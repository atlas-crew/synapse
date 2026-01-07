//! Per-site rate limiting with token bucket algorithm.
//!
//! Provides hostname-aware rate limiting with configurable limits,
//! burst capacity, and sliding window tracking.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use tracing::{debug, warn};

/// Rate limit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Request is allowed
    Allow,
    /// Request is rate limited
    Limited,
}

/// Rate limit configuration for a site.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Requests per second limit
    pub rps: u32,
    /// Burst capacity (tokens available for bursts)
    pub burst: u32,
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Window duration for sliding window
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rps: 1000,
            burst: 2000,
            enabled: true,
            window_secs: 1,
        }
    }
}

impl RateLimitConfig {
    /// Creates a new rate limit config with specified RPS.
    pub fn new(rps: u32) -> Self {
        Self {
            rps,
            burst: rps * 2,
            enabled: true,
            window_secs: 1,
        }
    }

    /// Sets the burst capacity.
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst = burst;
        self
    }

    /// Disables rate limiting.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Token bucket rate limiter.
#[derive(Debug)]
pub struct TokenBucket {
    /// Available tokens
    tokens: AtomicU64,
    /// Maximum tokens (burst capacity)
    max_tokens: u64,
    /// Tokens added per second
    refill_rate: u64,
    /// Last refill timestamp (nanos since start)
    last_refill: AtomicU64,
    /// Start time for timestamp calculation
    start_time: Instant,
}

impl TokenBucket {
    /// Creates a new token bucket.
    pub fn new(rps: u32, burst: u32) -> Self {
        let max_tokens = burst as u64;
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            refill_rate: rps as u64,
            last_refill: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Tries to acquire a token, returning true if successful.
    pub fn try_acquire(&self) -> bool {
        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Refills tokens based on elapsed time.
    fn refill(&self) {
        let now_nanos = self.start_time.elapsed().as_nanos() as u64;
        let last = self.last_refill.load(Ordering::Relaxed);

        if now_nanos <= last {
            return;
        }

        let elapsed_nanos = now_nanos - last;
        let elapsed_secs = elapsed_nanos as f64 / 1_000_000_000.0;
        let tokens_to_add = (elapsed_secs * self.refill_rate as f64) as u64;

        if tokens_to_add > 0 {
            // Try to update last_refill
            if self.last_refill.compare_exchange_weak(
                last,
                now_nanos,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ).is_ok() {
                // Add tokens up to max
                loop {
                    let current = self.tokens.load(Ordering::Relaxed);
                    let new_tokens = (current + tokens_to_add).min(self.max_tokens);
                    if self.tokens.compare_exchange_weak(
                        current,
                        new_tokens,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ).is_ok() {
                        break;
                    }
                }
            }
        }
    }

    /// Returns the current number of available tokens.
    pub fn available_tokens(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Relaxed)
    }
}

/// Per-key rate limiter (e.g., by IP address).
#[derive(Debug)]
pub struct KeyedRateLimiter {
    /// Key -> token bucket mapping
    buckets: RwLock<HashMap<String, Arc<TokenBucket>>>,
    /// Configuration
    config: RateLimitConfig,
    /// Maximum number of tracked keys (to prevent memory exhaustion)
    max_keys: usize,
}

impl KeyedRateLimiter {
    /// Creates a new keyed rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            config,
            max_keys: 100_000, // Default max tracked keys
        }
    }

    /// Sets the maximum number of tracked keys.
    pub fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    /// Checks if a request for the given key is allowed.
    pub fn check(&self, key: &str) -> RateLimitDecision {
        if !self.config.enabled {
            return RateLimitDecision::Allow;
        }

        // Try to get existing bucket
        {
            let buckets = self.buckets.read();
            if let Some(bucket) = buckets.get(key) {
                return if bucket.try_acquire() {
                    RateLimitDecision::Allow
                } else {
                    debug!("Rate limited key: {}", key);
                    RateLimitDecision::Limited
                };
            }
        }

        // Create new bucket
        {
            let mut buckets = self.buckets.write();

            // Evict old entries if over limit
            if buckets.len() >= self.max_keys {
                warn!("Rate limiter at capacity, evicting old entries");
                // Simple eviction: remove first 10% of entries
                let to_remove: Vec<_> = buckets.keys().take(self.max_keys / 10).cloned().collect();
                for k in to_remove {
                    buckets.remove(&k);
                }
            }

            let bucket = Arc::new(TokenBucket::new(self.config.rps, self.config.burst));
            let allowed = bucket.try_acquire();
            buckets.insert(key.to_string(), bucket);

            if allowed {
                RateLimitDecision::Allow
            } else {
                RateLimitDecision::Limited
            }
        }
    }

    /// Returns the number of tracked keys.
    pub fn key_count(&self) -> usize {
        self.buckets.read().len()
    }

    /// Clears all tracked keys.
    pub fn clear(&self) {
        self.buckets.write().clear();
    }
}

/// Per-site rate limit manager.
#[derive(Debug)]
pub struct RateLimitManager {
    /// Site hostname -> keyed limiter mapping
    site_limiters: RwLock<HashMap<String, Arc<KeyedRateLimiter>>>,
    /// Global limiter (applied to all sites)
    global_limiter: Option<Arc<KeyedRateLimiter>>,
    /// Default config for new sites
    default_config: RateLimitConfig,
}

impl RateLimitManager {
    /// Creates a new rate limit manager.
    pub fn new() -> Self {
        Self {
            site_limiters: RwLock::new(HashMap::new()),
            global_limiter: None,
            default_config: RateLimitConfig::default(),
        }
    }

    /// Creates a manager with a global rate limit.
    pub fn with_global(config: RateLimitConfig) -> Self {
        Self {
            site_limiters: RwLock::new(HashMap::new()),
            global_limiter: Some(Arc::new(KeyedRateLimiter::new(config.clone()))),
            default_config: config,
        }
    }

    /// Sets the default configuration for new sites.
    pub fn set_default_config(&mut self, config: RateLimitConfig) {
        self.default_config = config;
    }

    /// Adds a site-specific rate limiter.
    pub fn add_site(&self, hostname: &str, config: RateLimitConfig) {
        let limiter = Arc::new(KeyedRateLimiter::new(config));
        self.site_limiters
            .write()
            .insert(hostname.to_lowercase(), limiter);
    }

    /// Removes a site-specific rate limiter.
    pub fn remove_site(&self, hostname: &str) {
        self.site_limiters
            .write()
            .remove(&hostname.to_lowercase());
    }

    /// Checks if a request is allowed.
    ///
    /// # Arguments
    /// * `hostname` - The site hostname
    /// * `key` - The rate limit key (usually client IP)
    pub fn check(&self, hostname: &str, key: &str) -> RateLimitDecision {
        // Check global limiter first
        if let Some(global) = &self.global_limiter {
            if matches!(global.check(key), RateLimitDecision::Limited) {
                return RateLimitDecision::Limited;
            }
        }

        // Check site-specific limiter
        let normalized = hostname.to_lowercase();
        let limiters = self.site_limiters.read();

        if let Some(limiter) = limiters.get(&normalized) {
            return limiter.check(key);
        }

        // No site-specific limiter, allow
        RateLimitDecision::Allow
    }

    /// Returns true if the request is allowed.
    pub fn is_allowed(&self, hostname: &str, key: &str) -> bool {
        matches!(self.check(hostname, key), RateLimitDecision::Allow)
    }

    /// Returns rate limit statistics.
    pub fn stats(&self) -> RateLimitStats {
        let limiters = self.site_limiters.read();
        let total_keys: usize = limiters.values().map(|l| l.key_count()).sum();
        let global_keys = self.global_limiter.as_ref().map(|l| l.key_count()).unwrap_or(0);

        RateLimitStats {
            site_count: limiters.len(),
            total_tracked_keys: total_keys + global_keys,
            global_enabled: self.global_limiter.is_some(),
        }
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limit statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStats {
    /// Number of sites with rate limiting
    pub site_count: usize,
    /// Total number of tracked keys across all limiters
    pub total_tracked_keys: usize,
    /// Whether global rate limiting is enabled
    pub global_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_token_bucket_basic() {
        let bucket = TokenBucket::new(10, 10); // 10 RPS, 10 burst

        // Should allow 10 requests immediately
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // 11th should fail
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(1000, 10); // 1000 RPS, 10 burst

        // Drain the bucket
        for _ in 0..10 {
            bucket.try_acquire();
        }

        // Wait a bit for refill
        thread::sleep(Duration::from_millis(20));

        // Should have some tokens now
        assert!(bucket.try_acquire());
    }

    #[test]
    fn test_rate_limit_config() {
        let config = RateLimitConfig::new(100).with_burst(200);
        assert_eq!(config.rps, 100);
        assert_eq!(config.burst, 200);
        assert!(config.enabled);
    }

    #[test]
    fn test_rate_limit_disabled() {
        let config = RateLimitConfig::disabled();
        let limiter = KeyedRateLimiter::new(config);

        // Should always allow when disabled
        for _ in 0..1000 {
            assert!(matches!(limiter.check("key"), RateLimitDecision::Allow));
        }
    }

    #[test]
    fn test_keyed_rate_limiter() {
        let config = RateLimitConfig::new(5).with_burst(5);
        let limiter = KeyedRateLimiter::new(config);

        // Different keys have separate buckets
        for _ in 0..5 {
            assert!(matches!(limiter.check("key1"), RateLimitDecision::Allow));
            assert!(matches!(limiter.check("key2"), RateLimitDecision::Allow));
        }

        // Both should now be limited
        assert!(matches!(limiter.check("key1"), RateLimitDecision::Limited));
        assert!(matches!(limiter.check("key2"), RateLimitDecision::Limited));
    }

    #[test]
    fn test_keyed_limiter_key_count() {
        let config = RateLimitConfig::new(10);
        let limiter = KeyedRateLimiter::new(config);

        limiter.check("key1");
        limiter.check("key2");
        limiter.check("key3");

        assert_eq!(limiter.key_count(), 3);
    }

    #[test]
    fn test_rate_limit_manager() {
        let manager = RateLimitManager::new();

        // Add site-specific limiter
        manager.add_site("api.example.com", RateLimitConfig::new(2).with_burst(2));

        // Should limit api.example.com
        assert!(manager.is_allowed("api.example.com", "client1"));
        assert!(manager.is_allowed("api.example.com", "client1"));
        assert!(!manager.is_allowed("api.example.com", "client1"));

        // Other sites should be allowed (no limiter)
        assert!(manager.is_allowed("other.example.com", "client1"));
    }

    #[test]
    fn test_global_rate_limit() {
        let manager = RateLimitManager::with_global(RateLimitConfig::new(3).with_burst(3));

        // Global limit applies to all
        assert!(manager.is_allowed("any.com", "client1"));
        assert!(manager.is_allowed("any.com", "client1"));
        assert!(manager.is_allowed("any.com", "client1"));
        assert!(!manager.is_allowed("any.com", "client1"));
    }

    #[test]
    fn test_manager_case_insensitive() {
        let manager = RateLimitManager::new();
        manager.add_site("Example.COM", RateLimitConfig::new(1).with_burst(1));

        assert!(manager.is_allowed("example.com", "client"));
        assert!(!manager.is_allowed("EXAMPLE.COM", "client"));
    }

    #[test]
    fn test_keyed_limiter_clear() {
        let config = RateLimitConfig::new(10);
        let limiter = KeyedRateLimiter::new(config);

        limiter.check("key1");
        limiter.check("key2");
        assert_eq!(limiter.key_count(), 2);

        limiter.clear();
        assert_eq!(limiter.key_count(), 0);
    }

    #[test]
    fn test_stats() {
        let manager = RateLimitManager::with_global(RateLimitConfig::new(100));
        manager.add_site("site1.com", RateLimitConfig::new(50));
        manager.add_site("site2.com", RateLimitConfig::new(50));

        // Generate some traffic
        manager.check("site1.com", "ip1");
        manager.check("site2.com", "ip2");

        let stats = manager.stats();
        assert_eq!(stats.site_count, 2);
        assert!(stats.global_enabled);
    }

    #[test]
    fn test_available_tokens() {
        let bucket = TokenBucket::new(100, 50);
        assert_eq!(bucket.available_tokens(), 50); // Starts at burst capacity
    }
}
