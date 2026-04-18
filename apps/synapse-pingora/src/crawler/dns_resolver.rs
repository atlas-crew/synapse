//! Async DNS resolution for crawler verification.
//!
//! ## Security
//! - Rate limiting via semaphore prevents resource exhaustion at scale
//! - Timeout enforcement prevents slow DNS servers from blocking requests
//! - IP round-trip verification prevents DNS rebinding attacks

use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Semaphore;

/// DNS resolution errors.
#[derive(Debug, Error, Clone)]
pub enum DnsError {
    #[error("DNS resolver creation failed: {0}")]
    ResolverCreation(String),
    #[error("DNS lookup failed: {0}")]
    LookupFailed(String),
    #[error("DNS timeout after {0}ms")]
    Timeout(u64),
    #[error("DNS rate limit exceeded, try again later")]
    RateLimited,
    #[error(
        "DNS verification failed: IP not in forward lookup results (possible rebinding attack)"
    )]
    IpMismatch,
}

impl From<hickory_resolver::ResolveError> for DnsError {
    fn from(e: hickory_resolver::ResolveError) -> Self {
        DnsError::ResolverCreation(e.to_string())
    }
}

/// Async DNS resolver for crawler verification with rate limiting.
#[derive(Debug)]
pub struct DnsResolver {
    resolver: Resolver<TokioConnectionProvider>,
    timeout: Duration,
    /// Semaphore to limit concurrent DNS lookups
    semaphore: Arc<Semaphore>,
    /// Maximum concurrent lookups (for logging/metrics)
    max_concurrent: usize,
}

impl DnsResolver {
    /// Create a new DNS resolver with rate limiting.
    ///
    /// # Arguments
    /// * `timeout_ms` - DNS lookup timeout in milliseconds
    /// * `max_concurrent` - Maximum concurrent DNS lookups (semaphore permits)
    pub async fn new(timeout_ms: u64, max_concurrent: usize) -> Result<Self, DnsError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .with_options({
            let mut opts = hickory_resolver::config::ResolverOpts::default();
            opts.timeout = Duration::from_millis(timeout_ms);
            opts.attempts = 2;
            opts
        })
        .build();

        Ok(Self {
            resolver,
            timeout: Duration::from_millis(timeout_ms),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        })
    }

    /// Get current number of available permits (for metrics)
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Get maximum concurrent lookups configured
    pub fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Acquire a permit for DNS lookup, with non-blocking try.
    /// Returns None if rate limit is exceeded.
    async fn acquire_permit(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        // Try to acquire without blocking - if we can't get a permit immediately,
        // we're at capacity and should return a rate limit error
        match self.semaphore.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                tracing::warn!(
                    "DNS rate limit reached: {}/{} permits in use",
                    self.max_concurrent - self.semaphore.available_permits(),
                    self.max_concurrent
                );
                None
            }
        }
    }

    /// Reverse DNS lookup: IP -> hostname.
    ///
    /// Rate-limited via semaphore to prevent resource exhaustion.
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Result<Option<String>, DnsError> {
        let _permit = self.acquire_permit().await.ok_or(DnsError::RateLimited)?;

        match tokio::time::timeout(self.timeout, self.resolver.reverse_lookup(ip)).await {
            Ok(Ok(response)) => {
                // Get first PTR record
                if let Some(record) = response.iter().next() {
                    Ok(Some(record.to_string().trim_end_matches('.').to_string()))
                } else {
                    Ok(None)
                }
            }
            Ok(Err(e)) => {
                // No PTR record is common, not an error
                tracing::debug!("Reverse DNS lookup for {} failed: {}", ip, e);
                Ok(None)
            }
            Err(_) => {
                tracing::debug!(
                    "Reverse DNS lookup for {} timed out after {}ms",
                    ip,
                    self.timeout.as_millis()
                );
                Err(DnsError::Timeout(self.timeout.as_millis() as u64))
            }
        }
    }

    /// Forward DNS lookup: hostname -> IPs.
    ///
    /// Rate-limited via semaphore to prevent resource exhaustion.
    pub async fn forward_lookup(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
        let _permit = self.acquire_permit().await.ok_or(DnsError::RateLimited)?;

        match tokio::time::timeout(self.timeout, self.resolver.lookup_ip(hostname)).await {
            Ok(Ok(response)) => Ok(response.iter().collect()),
            Ok(Err(e)) => {
                tracing::debug!("Forward DNS lookup for {} failed: {}", hostname, e);
                Err(DnsError::LookupFailed(e.to_string()))
            }
            Err(_) => {
                tracing::debug!(
                    "Forward DNS lookup for {} timed out after {}ms",
                    hostname,
                    self.timeout.as_millis()
                );
                Err(DnsError::Timeout(self.timeout.as_millis() as u64))
            }
        }
    }

    /// Verify IP via reverse+forward DNS lookup.
    ///
    /// Returns (verified, hostname) where verified is true only if:
    /// 1. Reverse lookup (IP -> hostname) succeeds
    /// 2. Forward lookup (hostname -> IPs) succeeds
    /// 3. Original IP is contained in the forward lookup results
    ///
    /// This prevents DNS rebinding attacks where an attacker controls a domain
    /// that initially resolves to a legitimate IP, then changes after verification.
    ///
    /// ## Security
    /// The IP round-trip check is critical: we verify that the hostname
    /// the IP claims to be actually resolves back to that IP.
    pub async fn verify_ip(&self, ip: IpAddr) -> Result<(bool, Option<String>), DnsError> {
        // Step 1: Reverse lookup IP -> hostname
        let hostname = match self.reverse_lookup(ip).await? {
            Some(h) => h,
            None => return Ok((false, None)),
        };

        // Step 2: Forward lookup hostname -> IPs
        let resolved_ips = match self.forward_lookup(&hostname).await {
            Ok(ips) => ips,
            Err(DnsError::RateLimited) => return Err(DnsError::RateLimited),
            Err(_) => return Ok((false, Some(hostname))),
        };

        // Step 3: CRITICAL - Verify original IP is in the resolved IPs
        // This prevents DNS rebinding attacks
        let verified = resolved_ips.contains(&ip);

        if !verified {
            tracing::warn!(
                ip = %ip,
                hostname = %hostname,
                resolved_ips = ?resolved_ips,
                "DNS rebinding check failed: requesting IP not in forward lookup results"
            );
        }

        Ok((verified, Some(hostname)))
    }

    /// Verify IP with explicit rebinding protection.
    ///
    /// Same as `verify_ip` but returns a specific error on IP mismatch
    /// instead of just returning (false, hostname).
    pub async fn verify_ip_strict(&self, ip: IpAddr) -> Result<String, DnsError> {
        // Step 1: Reverse lookup IP -> hostname
        let hostname = match self.reverse_lookup(ip).await? {
            Some(h) => h,
            None => return Err(DnsError::LookupFailed("No PTR record".to_string())),
        };

        // Step 2: Forward lookup hostname -> IPs
        let resolved_ips = self.forward_lookup(&hostname).await?;

        // Step 3: CRITICAL - Verify original IP is in the resolved IPs
        if !resolved_ips.contains(&ip) {
            tracing::warn!(
                ip = %ip,
                hostname = %hostname,
                resolved_ips = ?resolved_ips,
                "DNS rebinding attack detected: IP not in forward lookup results"
            );
            return Err(DnsError::IpMismatch);
        }

        Ok(hostname)
    }
}
