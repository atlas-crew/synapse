//! Shadow Mirroring Module
//!
//! Provides zero-latency traffic mirroring for suspicious actors to honeypot endpoints.
//!
//! # Architecture
//!
//! ```text
//! Request → Detection → Risk Score → Decision Point
//!                          │
//!                          ├── risk < min: Pass through (no mirror)
//!                          ├── min ≤ risk < max: SHADOW MIRROR + Pass
//!                          └── risk ≥ max: Block (no mirror needed)
//!                                  │
//!                                  ▼
//!                          tokio::spawn() ──► Async HTTP POST to Honeypot
//!                          (fire & forget)
//! ```
//!
//! # Key Features
//!
//! - **Zero production latency**: Fire-and-forget async mirroring
//! - **Per-IP rate limiting**: Prevents honeypot flooding
//! - **Configurable thresholds**: Risk score window for mirroring
//! - **HMAC signing**: Optional payload authentication
//! - **Sampling**: Configurable percentage of eligible traffic

mod client;
mod config;
mod protocol;
mod rate_limiter;

pub use client::{ShadowClientStats, ShadowMirrorClient, ShadowMirrorError};
pub use config::{ShadowConfigError, ShadowMirrorConfig};
pub use protocol::{is_sensitive_header, MirrorPayload};
pub use rate_limiter::{RateLimiter, RateLimiterStats};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Default maximum concurrent mirror operations
const DEFAULT_MAX_CONCURRENT_MIRRORS: usize = 100;

/// Manager for shadow mirroring operations.
///
/// Coordinates mirror decisions, rate limiting, and async delivery to honeypots.
/// Uses a bounded queue (semaphore) to prevent memory exhaustion from slow honeypots.
pub struct ShadowMirrorManager {
    /// Shadow mirroring configuration
    config: ShadowMirrorConfig,
    /// Per-IP rate limiter
    rate_limiter: Arc<RateLimiter>,
    /// HTTP client for honeypot delivery
    client: Arc<ShadowMirrorClient>,
    /// Sensor ID for payload attribution
    sensor_id: String,
    /// Semaphore to bound concurrent mirror operations
    mirror_semaphore: Arc<Semaphore>,
    /// Maximum concurrent mirror operations
    max_concurrent: usize,
    /// Total mirror attempts
    attempts: AtomicU64,
    /// Mirrors skipped due to risk score
    skipped_risk: AtomicU64,
    /// Mirrors skipped due to sampling
    skipped_sampling: AtomicU64,
    /// Mirrors skipped due to rate limiting
    skipped_rate_limit: AtomicU64,
    /// Mirrors dropped due to queue full (backpressure)
    dropped_queue_full: AtomicU64,
    /// Mirrors sent successfully
    sent: AtomicU64,
}

impl ShadowMirrorManager {
    /// Creates a new shadow mirror manager with default concurrency limit.
    ///
    /// # Errors
    /// Returns `ShadowMirrorError::ClientCreation` if the HTTP client cannot be created.
    pub fn new(config: ShadowMirrorConfig, sensor_id: String) -> Result<Self, ShadowMirrorError> {
        Self::with_max_concurrent(config, sensor_id, DEFAULT_MAX_CONCURRENT_MIRRORS)
    }

    /// Creates a new shadow mirror manager with a custom concurrency limit.
    ///
    /// # Arguments
    /// * `config` - Shadow mirror configuration
    /// * `sensor_id` - Sensor ID for payload attribution
    /// * `max_concurrent` - Maximum concurrent mirror operations (prevents memory exhaustion)
    ///
    /// # Errors
    /// Returns `ShadowMirrorError::ClientCreation` if the HTTP client cannot be created.
    pub fn with_max_concurrent(
        config: ShadowMirrorConfig,
        sensor_id: String,
        max_concurrent: usize,
    ) -> Result<Self, ShadowMirrorError> {
        let rate_limiter = Arc::new(RateLimiter::new(config.per_ip_rate_limit));
        let client = Arc::new(ShadowMirrorClient::new(
            config.hmac_secret.clone(),
            config.timeout(),
        )?);
        let mirror_semaphore = Arc::new(Semaphore::new(max_concurrent));

        info!(
            enabled = config.enabled,
            min_risk = config.min_risk_score,
            max_risk = config.max_risk_score,
            sampling = config.sampling_rate,
            per_ip_limit = config.per_ip_rate_limit,
            honeypots = config.honeypot_urls.len(),
            max_concurrent = max_concurrent,
            "Shadow mirror manager initialized with bounded queue"
        );

        Ok(Self {
            config,
            rate_limiter,
            client,
            sensor_id,
            mirror_semaphore,
            max_concurrent,
            attempts: AtomicU64::new(0),
            skipped_risk: AtomicU64::new(0),
            skipped_sampling: AtomicU64::new(0),
            skipped_rate_limit: AtomicU64::new(0),
            dropped_queue_full: AtomicU64::new(0),
            sent: AtomicU64::new(0),
        })
    }

    /// Determines if a request should be mirrored based on detection result.
    ///
    /// # Arguments
    /// * `risk_score` - Risk score from detection (0-100)
    /// * `client_ip` - Source IP address
    ///
    /// # Returns
    /// `true` if the request should be mirrored, `false` otherwise.
    pub fn should_mirror(&self, risk_score: f32, client_ip: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        self.attempts.fetch_add(1, Ordering::Relaxed);

        // Check risk score window
        if risk_score < self.config.min_risk_score {
            self.skipped_risk.fetch_add(1, Ordering::Relaxed);
            debug!(
                risk = risk_score,
                min = self.config.min_risk_score,
                "Skipping mirror: risk below threshold"
            );
            return false;
        }

        if risk_score >= self.config.max_risk_score {
            self.skipped_risk.fetch_add(1, Ordering::Relaxed);
            debug!(
                risk = risk_score,
                max = self.config.max_risk_score,
                "Skipping mirror: risk above threshold (will be blocked)"
            );
            return false;
        }

        // Check sampling rate
        if self.config.sampling_rate < 1.0 {
            if fastrand::f32() > self.config.sampling_rate {
                self.skipped_sampling.fetch_add(1, Ordering::Relaxed);
                debug!(
                    sampling = self.config.sampling_rate,
                    "Skipping mirror: not selected by sampling"
                );
                return false;
            }
        }

        // Check per-IP rate limit
        if !self.rate_limiter.check_and_increment(client_ip) {
            self.skipped_rate_limit.fetch_add(1, Ordering::Relaxed);
            debug!(
                ip = client_ip,
                limit = self.config.per_ip_rate_limit,
                "Skipping mirror: per-IP rate limit exceeded"
            );
            return false;
        }

        true
    }

    /// Sends a mirror payload asynchronously (fire-and-forget) with bounded concurrency.
    ///
    /// Returns immediately without waiting for delivery to complete.
    /// Uses a semaphore to limit concurrent operations and prevent memory exhaustion
    /// when honeypots are slow or unresponsive. If the queue is full, the request
    /// is dropped (backpressure) rather than blocking or causing unbounded growth.
    ///
    /// # Returns
    /// `true` if the payload was queued for delivery, `false` if dropped due to backpressure.
    pub fn mirror_async(&self, payload: MirrorPayload) -> bool {
        // Try to acquire semaphore permit without blocking
        let permit = match self.mirror_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Queue is full - apply backpressure by dropping this request
                self.dropped_queue_full.fetch_add(1, Ordering::Relaxed);
                debug!(
                    request_id = %payload.request_id,
                    max_concurrent = self.max_concurrent,
                    "Shadow mirror dropped: queue full (backpressure)"
                );
                return false;
            }
        };

        let client = Arc::clone(&self.client);
        let urls = self.config.honeypot_urls.clone();
        let timeout = self.config.timeout();
        let request_id = payload.request_id.clone();

        self.sent.fetch_add(1, Ordering::Relaxed);

        // Fire and forget - permit is released when task completes
        tokio::spawn(async move {
            // Permit is held for the duration of this async block
            let _permit = permit;

            if let Err(e) = client.send_to_honeypot(&urls, payload, timeout).await {
                // Log but don't fail - this is best-effort
                warn!(
                    request_id = %request_id,
                    error = %e,
                    "Shadow mirror delivery failed"
                );
            }
            // Permit is dropped here, releasing the semaphore slot
        });

        true
    }

    /// Creates a mirror payload from request context.
    ///
    /// # Arguments
    /// * `request_id` - Unique request identifier
    /// * `source_ip` - Client IP address
    /// * `method` - HTTP method
    /// * `uri` - Request URI
    /// * `site_name` - Site/vhost name
    /// * `risk_score` - Calculated risk score
    /// * `matched_rules` - IDs of rules that matched
    /// * `ja4` - Optional JA4 TLS fingerprint
    /// * `ja4h` - Optional JA4H HTTP fingerprint
    /// * `campaign_id` - Optional campaign correlation ID
    /// * `headers` - Request headers to include
    /// * `body` - Optional request body
    #[allow(clippy::too_many_arguments)]
    pub fn create_payload(
        &self,
        request_id: String,
        source_ip: String,
        method: String,
        uri: String,
        site_name: String,
        risk_score: f32,
        matched_rules: Vec<String>,
        ja4: Option<String>,
        ja4h: Option<String>,
        campaign_id: Option<String>,
        headers: HashMap<String, String>,
        body: Option<String>,
    ) -> MirrorPayload {
        // Filter headers based on config
        let filtered_headers: HashMap<String, String> = headers
            .into_iter()
            .filter(|(k, _)| {
                self.config
                    .include_headers
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(k))
            })
            .collect();

        // Truncate body if too large
        let body = if self.config.include_body {
            body.map(|b| {
                if b.len() > self.config.max_body_size {
                    b[..self.config.max_body_size].to_string()
                } else {
                    b
                }
            })
        } else {
            None
        };

        MirrorPayload::new(
            request_id,
            source_ip,
            risk_score,
            method,
            uri,
            site_name,
            self.sensor_id.clone(),
        )
        .with_ja4(ja4)
        .with_ja4h(ja4h)
        .with_rules(matched_rules)
        .with_campaign(campaign_id)
        .with_headers(filtered_headers)
        .with_body(body)
    }

    /// Runs periodic cleanup of the rate limiter.
    ///
    /// Call this from a background task at regular intervals (e.g., every 60s).
    pub fn cleanup(&self) {
        self.rate_limiter.cleanup();
    }

    /// Returns statistics about shadow mirroring.
    pub fn stats(&self) -> ShadowMirrorStats {
        let client_stats = self.client.stats();
        let rate_limiter_stats = self.rate_limiter.stats();

        ShadowMirrorStats {
            enabled: self.config.enabled,
            attempts: self.attempts.load(Ordering::Relaxed),
            skipped_risk: self.skipped_risk.load(Ordering::Relaxed),
            skipped_sampling: self.skipped_sampling.load(Ordering::Relaxed),
            skipped_rate_limit: self.skipped_rate_limit.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            delivery_successes: client_stats.successes,
            delivery_failures: client_stats.failures,
            bytes_sent: client_stats.bytes_sent,
            tracked_ips: rate_limiter_stats.tracked_ips,
            max_concurrent: self.max_concurrent,
            queue_available: self.mirror_semaphore.available_permits(),
            min_risk_score: self.config.min_risk_score,
            max_risk_score: self.config.max_risk_score,
            sampling_rate: self.config.sampling_rate,
            per_ip_rate_limit: self.config.per_ip_rate_limit,
            honeypot_count: self.config.honeypot_urls.len(),
        }
    }

    /// Resets all statistics.
    pub fn reset_stats(&self) {
        self.attempts.store(0, Ordering::Relaxed);
        self.skipped_risk.store(0, Ordering::Relaxed);
        self.skipped_sampling.store(0, Ordering::Relaxed);
        self.skipped_rate_limit.store(0, Ordering::Relaxed);
        self.dropped_queue_full.store(0, Ordering::Relaxed);
        self.sent.store(0, Ordering::Relaxed);
        self.client.reset_stats();
        self.rate_limiter.reset();
    }

    /// Returns whether shadow mirroring is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns the configuration.
    pub fn config(&self) -> &ShadowMirrorConfig {
        &self.config
    }
}

/// Statistics about shadow mirroring operations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShadowMirrorStats {
    /// Whether shadow mirroring is enabled
    pub enabled: bool,
    /// Total mirror attempts (requests that could be mirrored)
    pub attempts: u64,
    /// Skipped due to risk score outside window
    pub skipped_risk: u64,
    /// Skipped due to sampling
    pub skipped_sampling: u64,
    /// Skipped due to per-IP rate limiting
    pub skipped_rate_limit: u64,
    /// Dropped due to queue being full (backpressure)
    pub dropped_queue_full: u64,
    /// Successfully queued for sending
    pub sent: u64,
    /// Successfully delivered to honeypot
    pub delivery_successes: u64,
    /// Failed to deliver to honeypot
    pub delivery_failures: u64,
    /// Total bytes sent to honeypots
    pub bytes_sent: u64,
    /// Number of IPs being rate-tracked
    pub tracked_ips: usize,
    /// Maximum concurrent mirror operations allowed
    pub max_concurrent: usize,
    /// Current available slots in the queue
    pub queue_available: usize,
    /// Configured minimum risk score
    pub min_risk_score: f32,
    /// Configured maximum risk score
    pub max_risk_score: f32,
    /// Configured sampling rate
    pub sampling_rate: f32,
    /// Configured per-IP rate limit
    pub per_ip_rate_limit: u32,
    /// Number of configured honeypot URLs
    pub honeypot_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ShadowMirrorConfig {
        ShadowMirrorConfig {
            enabled: true,
            min_risk_score: 40.0,
            max_risk_score: 70.0,
            honeypot_urls: vec!["http://localhost:8888/mirror".to_string()],
            sampling_rate: 1.0,
            per_ip_rate_limit: 10,
            timeout_secs: 5,
            hmac_secret: None,
            include_body: true,
            max_body_size: 1024,
            include_headers: vec!["User-Agent".to_string()],
        }
    }

    fn create_test_manager() -> ShadowMirrorManager {
        ShadowMirrorManager::new(create_test_config(), "sensor-01".to_string())
            .expect("test manager creation should succeed")
    }

    #[test]
    fn test_should_mirror_in_risk_window() {
        let manager = create_test_manager();

        // Risk in window should mirror
        assert!(manager.should_mirror(45.0, "192.168.1.1"));
        assert!(manager.should_mirror(50.0, "192.168.1.2"));
        assert!(manager.should_mirror(69.9, "192.168.1.3"));
    }

    #[test]
    fn test_should_not_mirror_below_min() {
        let manager = create_test_manager();

        assert!(!manager.should_mirror(10.0, "192.168.1.1"));
        assert!(!manager.should_mirror(39.9, "192.168.1.2"));
    }

    #[test]
    fn test_should_not_mirror_above_max() {
        let manager = create_test_manager();

        assert!(!manager.should_mirror(70.0, "192.168.1.1"));
        assert!(!manager.should_mirror(85.0, "192.168.1.2"));
        assert!(!manager.should_mirror(100.0, "192.168.1.3"));
    }

    #[test]
    fn test_should_not_mirror_when_disabled() {
        let mut config = create_test_config();
        config.enabled = false;
        let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
            .expect("manager creation should succeed");

        assert!(!manager.should_mirror(50.0, "192.168.1.1"));
    }

    #[test]
    fn test_rate_limiting() {
        let mut config = create_test_config();
        config.per_ip_rate_limit = 3;
        let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
            .expect("manager creation should succeed");

        let ip = "10.0.0.1";
        assert!(manager.should_mirror(50.0, ip));
        assert!(manager.should_mirror(50.0, ip));
        assert!(manager.should_mirror(50.0, ip));
        // Fourth request should be rate limited
        assert!(!manager.should_mirror(50.0, ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let mut config = create_test_config();
        config.per_ip_rate_limit = 2;
        let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
            .expect("manager creation should succeed");

        assert!(manager.should_mirror(50.0, "ip1"));
        assert!(manager.should_mirror(50.0, "ip1"));
        assert!(!manager.should_mirror(50.0, "ip1")); // Limited

        // Different IP should be independent
        assert!(manager.should_mirror(50.0, "ip2"));
        assert!(manager.should_mirror(50.0, "ip2"));
    }

    #[test]
    fn test_sampling_rate() {
        let mut config = create_test_config();
        config.sampling_rate = 0.0; // 0% sampling - should never mirror
        let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
            .expect("manager creation should succeed");

        // With 0% sampling, should never mirror
        for i in 0..100 {
            assert!(!manager.should_mirror(50.0, &format!("ip{}", i)));
        }
    }

    #[test]
    fn test_create_payload() {
        let manager = create_test_manager();

        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), "test-agent".to_string());
        headers.insert("X-Custom".to_string(), "should-be-filtered".to_string());

        let payload = manager.create_payload(
            "req-123".to_string(),
            "10.0.0.1".to_string(),
            "POST".to_string(),
            "/api/login".to_string(),
            "example.com".to_string(),
            55.0,
            vec!["sqli-001".to_string()],
            Some("ja4-fingerprint".to_string()),
            None,
            Some("campaign-123".to_string()),
            headers,
            Some("request body".to_string()),
        );

        assert_eq!(payload.request_id, "req-123");
        assert_eq!(payload.source_ip, "10.0.0.1");
        assert_eq!(payload.risk_score, 55.0);
        assert_eq!(payload.sensor_id, "sensor-01");
        assert!(payload.headers.contains_key("User-Agent"));
        assert!(!payload.headers.contains_key("X-Custom")); // Filtered out
    }

    #[test]
    fn test_body_truncation() {
        let mut config = create_test_config();
        config.max_body_size = 10;
        let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
            .expect("manager creation should succeed");

        let payload = manager.create_payload(
            "req-123".to_string(),
            "10.0.0.1".to_string(),
            "POST".to_string(),
            "/api".to_string(),
            "site".to_string(),
            50.0,
            vec![],
            None,
            None,
            None,
            HashMap::new(),
            Some("this is a very long body that should be truncated".to_string()),
        );

        assert_eq!(payload.body.unwrap().len(), 10);
    }

    #[test]
    fn test_stats() {
        let manager = create_test_manager();

        manager.should_mirror(50.0, "ip1");
        manager.should_mirror(50.0, "ip2");
        manager.should_mirror(10.0, "ip3"); // Below threshold

        let stats = manager.stats();
        assert!(stats.enabled);
        assert_eq!(stats.attempts, 3);
        assert_eq!(stats.skipped_risk, 1);
        assert_eq!(stats.min_risk_score, 40.0);
        assert_eq!(stats.max_risk_score, 70.0);
    }

    #[test]
    fn test_reset_stats() {
        let manager = create_test_manager();

        manager.should_mirror(50.0, "ip1");
        manager.should_mirror(50.0, "ip2");

        manager.reset_stats();

        let stats = manager.stats();
        assert_eq!(stats.attempts, 0);
        assert_eq!(stats.sent, 0);
    }

    #[test]
    fn test_bounded_queue_default_concurrency() {
        let manager = create_test_manager();

        let stats = manager.stats();
        assert_eq!(stats.max_concurrent, DEFAULT_MAX_CONCURRENT_MIRRORS);
        assert_eq!(stats.queue_available, DEFAULT_MAX_CONCURRENT_MIRRORS);
    }

    #[test]
    fn test_bounded_queue_custom_concurrency() {
        let config = create_test_config();
        let manager = ShadowMirrorManager::with_max_concurrent(config, "sensor-01".to_string(), 50)
            .expect("manager creation should succeed");

        let stats = manager.stats();
        assert_eq!(stats.max_concurrent, 50);
        assert_eq!(stats.queue_available, 50);
    }

    #[tokio::test]
    async fn test_bounded_queue_backpressure() {
        let config = create_test_config();
        // Create manager with very small queue to test backpressure
        let manager = ShadowMirrorManager::with_max_concurrent(config, "sensor-01".to_string(), 2)
            .expect("manager creation should succeed");

        // Create test payloads
        let payload1 = manager.create_payload(
            "req-1".to_string(),
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
            "site".to_string(),
            50.0,
            vec![],
            None,
            None,
            None,
            HashMap::new(),
            None,
        );
        let payload2 = manager.create_payload(
            "req-2".to_string(),
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
            "site".to_string(),
            50.0,
            vec![],
            None,
            None,
            None,
            HashMap::new(),
            None,
        );
        let payload3 = manager.create_payload(
            "req-3".to_string(),
            "10.0.0.1".to_string(),
            "GET".to_string(),
            "/test".to_string(),
            "site".to_string(),
            50.0,
            vec![],
            None,
            None,
            None,
            HashMap::new(),
            None,
        );

        // First two should succeed (queue size = 2)
        assert!(manager.mirror_async(payload1));
        assert!(manager.mirror_async(payload2));

        // Third should be dropped (backpressure)
        assert!(!manager.mirror_async(payload3));

        let stats = manager.stats();
        assert_eq!(stats.sent, 2);
        assert_eq!(stats.dropped_queue_full, 1);
    }

    #[test]
    fn test_stats_includes_queue_metrics() {
        let config = create_test_config();
        let manager = ShadowMirrorManager::with_max_concurrent(config, "sensor-01".to_string(), 25)
            .expect("manager creation should succeed");

        let stats = manager.stats();
        assert_eq!(stats.max_concurrent, 25);
        assert_eq!(stats.queue_available, 25);
        assert_eq!(stats.dropped_queue_full, 0);
    }
}
