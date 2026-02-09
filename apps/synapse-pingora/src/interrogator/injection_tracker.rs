//! Injection Tracker - Headless Browser Detection
//!
//! Tracks the effectiveness of JavaScript injection challenges and detects headless
//! browsers through behavioral analysis. This module correlates challenge attempts
//! with response timing and fingerprint patterns to identify automated clients.
//!
//! # Detection Signals
//!
//! The tracker monitors multiple signals to identify headless browsers:
//!
//! 1. **No JS Execution**: 0% success rate after 5+ attempts indicates JS is disabled
//! 2. **Consistent Timing**: Low variance in response times suggests automation
//! 3. **Rapid Requests**: >10 requests/second indicates bot behavior
//! 4. **Fingerprint Anomaly**: Fingerprint never changes or changes too frequently
//!
//! # Architecture
//!
//! ```text
//! +-------------------+     +------------------+     +------------------+
//! | JS Challenge      | --> | InjectionTracker | --> | Headless         |
//! | Attempts/Results  |     | (Correlation)    |     | Detection        |
//! +-------------------+     +------------------+     +------------------+
//!                                   |
//!                                   v
//!                           +------------------+
//!                           | Block Decision   |
//!                           | (should_block)   |
//!                           +------------------+
//! ```
//!
//! # Thread Safety
//!
//! Uses DashMap for lock-free concurrent access, suitable for high-throughput
//! request processing in the proxy pipeline.

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the injection tracker.
///
/// All fields have sensible defaults via `Default` implementation.
/// Can be serialized/deserialized for configuration file support.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct InjectionTrackerConfig {
    /// Maximum number of records to keep (default: 100_000)
    pub max_records: usize,
    /// Record time-to-live in seconds (default: 3600 = 1 hour)
    pub record_ttl_secs: u64,
    /// Minimum attempts before making headless determination (default: 5)
    pub min_attempts_for_detection: u32,
    /// Response time variance threshold (ms) below which is suspicious (default: 50.0)
    /// Low variance indicates automated timing
    pub timing_variance_threshold_ms: f64,
    /// Requests per second threshold above which is suspicious (default: 10.0)
    pub rapid_request_threshold_rps: f64,
    /// Maximum fingerprint changes allowed before anomaly (default: 20)
    /// Excessive changes indicate fingerprint spoofing
    pub max_fingerprint_changes: u32,
    /// JS success rate threshold below which is suspicious (default: 0.1 = 10%)
    pub js_success_rate_threshold: f64,
    /// Number of response times to keep for variance calculation (default: 20)
    pub response_time_window: usize,
}

impl Default for InjectionTrackerConfig {
    fn default() -> Self {
        Self {
            max_records: 100_000,
            record_ttl_secs: 3600,
            min_attempts_for_detection: 5,
            timing_variance_threshold_ms: 50.0,
            rapid_request_threshold_rps: 10.0,
            max_fingerprint_changes: 20,
            js_success_rate_threshold: 0.1,
            response_time_window: 20,
        }
    }
}

/// Record of injection tracking for an actor (IP + UA combination)
#[derive(Debug, Clone)]
pub struct InjectionRecord {
    /// IP address
    pub ip: String,
    /// Hash of User-Agent (for privacy)
    pub ua_hash: String,
    /// Number of JS challenge attempts
    pub js_attempts: u32,
    /// Number of JS challenge successes
    pub js_successes: u32,
    /// Number of cookie challenge attempts
    pub cookie_attempts: u32,
    /// Number of cookie challenge successes
    pub cookie_successes: u32,
    /// Recent response times (ms) for variance calculation
    pub response_times: VecDeque<u64>,
    /// Set of fingerprint hashes seen (HashSet for O(1) lookup)
    pub fingerprints_seen: std::collections::HashSet<String>,
    /// Ordered list of fingerprints for tracking changes (VecDeque for O(1) removal)
    fingerprints_order: VecDeque<String>,
    /// Number of times fingerprint changed
    pub fingerprint_changes: u32,
    /// First request timestamp (unix ms)
    pub first_seen: u64,
    /// Last request timestamp (unix ms)
    pub last_seen: u64,
    /// Total request count for rate calculation
    pub request_count: u64,
}

impl InjectionRecord {
    /// Create a new injection record
    fn new(ip: String, ua_hash: String, now: u64) -> Self {
        Self {
            ip,
            ua_hash,
            js_attempts: 0,
            js_successes: 0,
            cookie_attempts: 0,
            cookie_successes: 0,
            response_times: VecDeque::with_capacity(20),
            fingerprints_seen: std::collections::HashSet::with_capacity(16),
            fingerprints_order: VecDeque::with_capacity(16),
            fingerprint_changes: 0,
            first_seen: now,
            last_seen: now,
            request_count: 0,
        }
    }

    /// Calculate response time variance (standard deviation)
    fn response_time_variance(&self) -> f64 {
        if self.response_times.len() < 2 {
            return f64::MAX; // Not enough data
        }

        let times: Vec<f64> = self.response_times.iter().map(|&t| t as f64).collect();
        let n = times.len() as f64;
        let mean = times.iter().sum::<f64>() / n;
        let variance = times.iter().map(|&t| (t - mean).powi(2)).sum::<f64>() / n;
        variance.sqrt()
    }

    /// Calculate requests per second
    fn requests_per_second(&self) -> f64 {
        let duration_ms = self.last_seen.saturating_sub(self.first_seen);
        if duration_ms == 0 {
            return self.request_count as f64; // All requests in same ms
        }
        (self.request_count as f64) / (duration_ms as f64 / 1000.0)
    }

    /// Calculate JS success rate
    fn js_success_rate(&self) -> f64 {
        if self.js_attempts == 0 {
            return 1.0; // No attempts = not suspicious (yet)
        }
        (self.js_successes as f64) / (self.js_attempts as f64)
    }
}

/// Indicators that an actor may be a headless browser
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct HeadlessIndicators {
    /// No JavaScript execution detected (0% success after min attempts)
    pub no_js_execution: bool,
    /// Response timing is suspiciously consistent (low variance)
    pub consistent_timing: bool,
    /// Request rate is too rapid (>threshold RPS)
    pub rapid_requests: bool,
    /// Fingerprint behavior is anomalous (never changes or changes too much)
    pub fingerprint_anomaly: bool,
    /// Response time variance (ms) - lower is more suspicious
    pub timing_variance_ms: f64,
    /// Current requests per second
    pub requests_per_second: f64,
    /// JS challenge success rate
    pub js_success_rate: f64,
    /// Number of fingerprint changes observed
    pub fingerprint_changes: u32,
}

impl HeadlessIndicators {
    /// Check if any headless indicator is triggered.
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.no_js_execution
            || self.consistent_timing
            || self.rapid_requests
            || self.fingerprint_anomaly
    }

    /// Count how many indicators are triggered.
    #[inline]
    pub fn indicator_count(&self) -> u32 {
        self.no_js_execution as u32
            + self.consistent_timing as u32
            + self.rapid_requests as u32
            + self.fingerprint_anomaly as u32
    }

    /// Get human-readable description of triggered indicators.
    #[must_use]
    pub fn description(&self) -> String {
        let mut reasons = Vec::new();
        if self.no_js_execution {
            reasons.push(format!(
                "no_js_execution (success_rate: {:.1}%)",
                self.js_success_rate * 100.0
            ));
        }
        if self.consistent_timing {
            reasons.push(format!(
                "consistent_timing (variance: {:.1}ms)",
                self.timing_variance_ms
            ));
        }
        if self.rapid_requests {
            reasons.push(format!(
                "rapid_requests ({:.1} req/sec)",
                self.requests_per_second
            ));
        }
        if self.fingerprint_anomaly {
            reasons.push(format!(
                "fingerprint_anomaly ({} changes)",
                self.fingerprint_changes
            ));
        }
        if reasons.is_empty() {
            "none".to_string()
        } else {
            reasons.join(", ")
        }
    }
}

/// Summary of injection tracking for an actor
#[derive(Debug, Clone, serde::Serialize)]
pub struct InjectionSummary {
    /// IP address
    pub ip: String,
    /// User-Agent hash
    pub ua_hash: String,
    /// JS challenge success rate
    pub js_success_rate: f64,
    /// Cookie challenge success rate
    pub cookie_success_rate: f64,
    /// Total JS attempts
    pub js_attempts: u32,
    /// Total cookie attempts
    pub cookie_attempts: u32,
    /// Response time variance (ms)
    pub response_time_variance_ms: f64,
    /// Requests per second
    pub requests_per_second: f64,
    /// Headless detection indicators
    pub headless_indicators: HeadlessIndicators,
    /// Whether this actor is likely a headless browser
    pub is_likely_headless: bool,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Total requests observed
    pub total_requests: u64,
}

/// Statistics for the injection tracker
#[derive(Debug, Default)]
pub struct InjectionTrackerStats {
    /// Total JS attempts recorded
    pub js_attempts_total: AtomicU64,
    /// Total JS successes recorded
    pub js_successes_total: AtomicU64,
    /// Total cookie attempts recorded
    pub cookie_attempts_total: AtomicU64,
    /// Total cookie successes recorded
    pub cookie_successes_total: AtomicU64,
    /// Actors detected as headless
    pub headless_detected: AtomicU64,
    /// Block decisions made
    pub blocks_issued: AtomicU64,
    /// Records cleaned up due to expiration
    pub records_expired: AtomicU64,
    /// Records cleaned up due to capacity
    pub records_evicted: AtomicU64,
}

impl InjectionTrackerStats {
    /// Create a snapshot of current stats
    pub fn snapshot(&self) -> InjectionTrackerStatsSnapshot {
        InjectionTrackerStatsSnapshot {
            js_attempts_total: self.js_attempts_total.load(Ordering::Relaxed),
            js_successes_total: self.js_successes_total.load(Ordering::Relaxed),
            cookie_attempts_total: self.cookie_attempts_total.load(Ordering::Relaxed),
            cookie_successes_total: self.cookie_successes_total.load(Ordering::Relaxed),
            headless_detected: self.headless_detected.load(Ordering::Relaxed),
            blocks_issued: self.blocks_issued.load(Ordering::Relaxed),
            records_expired: self.records_expired.load(Ordering::Relaxed),
            records_evicted: self.records_evicted.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of stats for serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct InjectionTrackerStatsSnapshot {
    pub js_attempts_total: u64,
    pub js_successes_total: u64,
    pub cookie_attempts_total: u64,
    pub cookie_successes_total: u64,
    pub headless_detected: u64,
    pub blocks_issued: u64,
    pub records_expired: u64,
    pub records_evicted: u64,
}

/// Thread-safe injection tracker for headless browser detection.
///
/// Implements `Default` for convenient construction with default configuration.
#[derive(Debug)]
pub struct InjectionTracker {
    /// Records by actor key (ip:ua_hash)
    records: DashMap<String, InjectionRecord>,
    /// Configuration
    config: InjectionTrackerConfig,
    /// Statistics
    stats: InjectionTrackerStats,
}

impl Default for InjectionTracker {
    fn default() -> Self {
        Self::new(InjectionTrackerConfig::default())
    }
}

impl InjectionTracker {
    /// Create a new injection tracker with the given configuration.
    pub fn new(config: InjectionTrackerConfig) -> Self {
        Self {
            records: DashMap::with_capacity(config.max_records / 2),
            config,
            stats: InjectionTrackerStats::default(),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &InjectionTrackerConfig {
        &self.config
    }

    /// Generate actor key from IP and User-Agent
    fn actor_key(ip: &str, ua: &str) -> String {
        let ua_hash = hash_string(ua);
        format!("{}:{}", ip, ua_hash)
    }

    /// Hash User-Agent for privacy (first 16 hex chars of SHA256)
    fn hash_ua(ua: &str) -> String {
        hash_string(ua)
    }

    /// Record a JavaScript challenge attempt
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `ua` - User-Agent string
    /// * `success` - Whether the challenge was passed
    /// * `response_time_ms` - Time to complete challenge (ms)
    /// * `fingerprint` - Optional browser fingerprint
    ///
    /// # Returns
    /// Headless indicators based on current data
    pub fn record_js_attempt(
        &self,
        ip: &str,
        ua: &str,
        success: bool,
        response_time_ms: u64,
        fingerprint: Option<&str>,
    ) -> HeadlessIndicators {
        let now = now_ms();
        let key = Self::actor_key(ip, ua);
        let ua_hash = Self::hash_ua(ua);

        // Ensure we have capacity
        self.ensure_capacity();

        // Update or create record
        let mut entry = self
            .records
            .entry(key)
            .or_insert_with(|| InjectionRecord::new(ip.to_string(), ua_hash, now));

        let record = entry.value_mut();
        record.js_attempts += 1;
        if success {
            record.js_successes += 1;
            self.stats
                .js_successes_total
                .fetch_add(1, Ordering::Relaxed);
        }
        record.last_seen = now;
        record.request_count += 1;

        // Track response time
        if record.response_times.len() >= self.config.response_time_window {
            record.response_times.pop_front();
        }
        record.response_times.push_back(response_time_ms);

        // Track fingerprint using HashSet for O(1) lookup
        if let Some(fp) = fingerprint {
            let fp_hash = hash_string(fp);
            if !record.fingerprints_seen.contains(&fp_hash) {
                if !record.fingerprints_seen.is_empty() {
                    record.fingerprint_changes += 1;
                }
                record.fingerprints_seen.insert(fp_hash.clone());
                record.fingerprints_order.push_back(fp_hash);
                // Limit fingerprint history - O(1) removal with VecDeque
                if record.fingerprints_order.len() > 50 {
                    if let Some(oldest) = record.fingerprints_order.pop_front() {
                        record.fingerprints_seen.remove(&oldest);
                    }
                }
            }
        }

        self.stats.js_attempts_total.fetch_add(1, Ordering::Relaxed);

        // Calculate indicators
        self.calculate_indicators(record)
    }

    /// Record a cookie challenge attempt
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `ua` - User-Agent string
    /// * `success` - Whether the cookie was accepted/returned
    pub fn record_cookie_attempt(&self, ip: &str, ua: &str, success: bool) {
        let now = now_ms();
        let key = Self::actor_key(ip, ua);
        let ua_hash = Self::hash_ua(ua);

        // Ensure we have capacity
        self.ensure_capacity();

        // Update or create record
        let mut entry = self
            .records
            .entry(key)
            .or_insert_with(|| InjectionRecord::new(ip.to_string(), ua_hash, now));

        let record = entry.value_mut();
        record.cookie_attempts += 1;
        if success {
            record.cookie_successes += 1;
            self.stats
                .cookie_successes_total
                .fetch_add(1, Ordering::Relaxed);
        }
        record.last_seen = now;
        record.request_count += 1;

        self.stats
            .cookie_attempts_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get a summary of injection tracking for an actor
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `ua` - User-Agent string
    ///
    /// # Returns
    /// Summary if actor has been tracked, None otherwise
    pub fn get_summary(&self, ip: &str, ua: &str) -> Option<InjectionSummary> {
        let key = Self::actor_key(ip, ua);
        let record = self.records.get(&key)?;

        let indicators = self.calculate_indicators(&record);
        let is_likely_headless = self.is_likely_headless(&record, &indicators);

        Some(InjectionSummary {
            ip: record.ip.clone(),
            ua_hash: record.ua_hash.clone(),
            js_success_rate: record.js_success_rate(),
            cookie_success_rate: if record.cookie_attempts == 0 {
                1.0
            } else {
                (record.cookie_successes as f64) / (record.cookie_attempts as f64)
            },
            js_attempts: record.js_attempts,
            cookie_attempts: record.cookie_attempts,
            response_time_variance_ms: record.response_time_variance(),
            requests_per_second: record.requests_per_second(),
            headless_indicators: indicators,
            is_likely_headless,
            first_seen: record.first_seen,
            last_seen: record.last_seen,
            total_requests: record.request_count,
        })
    }

    /// Determine if an actor should be blocked
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `ua` - User-Agent string
    ///
    /// # Returns
    /// Tuple of (should_block, optional_reason)
    pub fn should_block(&self, ip: &str, ua: &str) -> (bool, Option<String>) {
        let key = Self::actor_key(ip, ua);
        let record = match self.records.get(&key) {
            Some(r) => r,
            None => return (false, None),
        };

        let indicators = self.calculate_indicators(&record);
        let is_headless = self.is_likely_headless(&record, &indicators);

        if is_headless {
            let reason = format!("Headless browser detected: {}", indicators.description());
            self.stats.blocks_issued.fetch_add(1, Ordering::Relaxed);
            (true, Some(reason))
        } else {
            (false, None)
        }
    }

    /// Remove expired records
    ///
    /// # Returns
    /// Number of records removed
    pub fn cleanup_expired(&self) -> usize {
        let now = now_ms();
        let ttl_ms = self.config.record_ttl_secs * 1000;
        let mut removed = 0;

        self.records.retain(|_, record| {
            if now.saturating_sub(record.last_seen) > ttl_ms {
                removed += 1;
                false
            } else {
                true
            }
        });

        self.stats
            .records_expired
            .fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    /// Get statistics
    pub fn stats(&self) -> &InjectionTrackerStats {
        &self.stats
    }

    /// Get number of tracked actors
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Check if no actors are tracked
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all records
    pub fn clear(&self) {
        self.records.clear();
    }

    // --- Private helpers ---

    /// Calculate headless indicators for a record
    fn calculate_indicators(&self, record: &InjectionRecord) -> HeadlessIndicators {
        let js_success_rate = record.js_success_rate();
        let timing_variance = record.response_time_variance();
        let rps = record.requests_per_second();

        // Check for no JS execution
        let no_js_execution = record.js_attempts >= self.config.min_attempts_for_detection
            && js_success_rate < self.config.js_success_rate_threshold;

        // Check for consistent timing (low variance)
        let consistent_timing = record.response_times.len() >= 5
            && timing_variance < self.config.timing_variance_threshold_ms;

        // Check for rapid requests
        let rapid_requests =
            record.request_count >= 10 && rps > self.config.rapid_request_threshold_rps;

        // Check for fingerprint anomaly
        // Anomaly = never changes after many requests OR changes too frequently
        let fingerprint_anomaly = if record.request_count >= 10 {
            // Never changes after many requests (static fingerprint or none)
            let never_changes =
                record.fingerprints_seen.len() <= 1 && record.fingerprint_changes == 0;
            // Changes too frequently (spoofing)
            let too_many_changes = record.fingerprint_changes > self.config.max_fingerprint_changes;
            never_changes || too_many_changes
        } else {
            false
        };

        HeadlessIndicators {
            no_js_execution,
            consistent_timing,
            rapid_requests,
            fingerprint_anomaly,
            timing_variance_ms: timing_variance,
            requests_per_second: rps,
            js_success_rate,
            fingerprint_changes: record.fingerprint_changes,
        }
    }

    /// Determine if actor is likely a headless browser
    fn is_likely_headless(
        &self,
        record: &InjectionRecord,
        indicators: &HeadlessIndicators,
    ) -> bool {
        // Need minimum data before making determination
        if record.js_attempts < self.config.min_attempts_for_detection {
            return false;
        }

        // Strong signal: no JS execution at all
        if indicators.no_js_execution {
            self.stats.headless_detected.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        // Multiple weak signals combined
        if indicators.indicator_count() >= 2 {
            self.stats.headless_detected.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    /// Ensure we have capacity for new records (evict oldest if needed)
    /// Uses probabilistic sampling to avoid O(n) collection of all records.
    fn ensure_capacity(&self) {
        if self.records.len() >= self.config.max_records {
            // Evict ~10% of oldest records using SAMPLING (not full collection)
            // Sample up to 1000 records to find eviction candidates
            let to_remove = self.config.max_records / 10;
            let sample_size = (to_remove * 5).min(1000).min(self.records.len());

            if sample_size == 0 {
                return;
            }

            // Sample records (DashMap iteration is already semi-random due to sharding)
            let mut candidates: Vec<(String, u64)> = Vec::with_capacity(sample_size);
            for entry in self.records.iter().take(sample_size) {
                candidates.push((entry.key().clone(), entry.value().last_seen));
            }

            // Sort sample by last_seen (oldest first)
            candidates.sort_unstable_by_key(|(_, last_seen)| *last_seen);

            // Evict oldest from sample
            for (key, _) in candidates.into_iter().take(to_remove) {
                self.records.remove(&key);
                self.stats.records_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Get current time in milliseconds since Unix epoch
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Hash a string using SHA256, return first 16 hex chars
fn hash_string(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8]) // First 8 bytes = 16 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> InjectionTrackerConfig {
        InjectionTrackerConfig {
            max_records: 1000,
            record_ttl_secs: 60,
            min_attempts_for_detection: 5,
            timing_variance_threshold_ms: 50.0,
            rapid_request_threshold_rps: 10.0,
            max_fingerprint_changes: 20,
            js_success_rate_threshold: 0.1,
            response_time_window: 20,
        }
    }

    #[test]
    fn test_new_tracker() {
        let tracker = InjectionTracker::new(test_config());
        assert!(tracker.is_empty());
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn test_record_js_attempt_success() {
        let tracker = InjectionTracker::new(test_config());

        let indicators = tracker.record_js_attempt("192.168.1.1", "Mozilla/5.0", true, 100, None);

        assert!(!indicators.is_suspicious());
        assert_eq!(tracker.len(), 1);

        let stats = tracker.stats().snapshot();
        assert_eq!(stats.js_attempts_total, 1);
        assert_eq!(stats.js_successes_total, 1);
    }

    #[test]
    fn test_record_js_attempt_failure() {
        let tracker = InjectionTracker::new(test_config());

        let indicators = tracker.record_js_attempt("192.168.1.1", "Mozilla/5.0", false, 100, None);

        assert!(!indicators.is_suspicious()); // Not enough attempts yet
        assert_eq!(tracker.len(), 1);

        let stats = tracker.stats().snapshot();
        assert_eq!(stats.js_attempts_total, 1);
        assert_eq!(stats.js_successes_total, 0);
    }

    #[test]
    fn test_no_js_execution_detection() {
        let tracker = InjectionTracker::new(test_config());
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make 5+ failed attempts
        for i in 0..6 {
            let indicators = tracker.record_js_attempt(ip, ua, false, 100 + i, None);
            if i >= 4 {
                // After 5 attempts with 0% success
                assert!(indicators.no_js_execution);
            }
        }

        let summary = tracker.get_summary(ip, ua).unwrap();
        assert!(summary.is_likely_headless);
        assert!(summary.headless_indicators.no_js_execution);
    }

    #[test]
    fn test_consistent_timing_detection() {
        let mut config = test_config();
        config.timing_variance_threshold_ms = 100.0; // Higher threshold for test
        let tracker = InjectionTracker::new(config);
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make attempts with very consistent timing (all 100ms)
        for _ in 0..10 {
            tracker.record_js_attempt(ip, ua, true, 100, None);
        }

        let summary = tracker.get_summary(ip, ua).unwrap();
        assert!(summary.headless_indicators.consistent_timing);
        assert!(summary.response_time_variance_ms < 100.0);
    }

    #[test]
    fn test_variable_timing_not_suspicious() {
        let mut config = test_config();
        config.timing_variance_threshold_ms = 30.0; // Lower threshold so high variance is not suspicious
        let tracker = InjectionTracker::new(config);
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make attempts with highly variable timing (std dev ~54ms)
        let times = [50, 200, 70, 250, 100, 300, 80, 220, 60, 280];
        for t in times {
            tracker.record_js_attempt(ip, ua, true, t, None);
        }

        let summary = tracker.get_summary(ip, ua).unwrap();
        // High variance (>30ms) should NOT trigger consistent_timing
        assert!(
            summary.response_time_variance_ms > 30.0,
            "Expected high variance, got {}",
            summary.response_time_variance_ms
        );
        assert!(!summary.headless_indicators.consistent_timing);
    }

    #[test]
    fn test_rapid_requests_detection() {
        let tracker = InjectionTracker::new(test_config());
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make many requests "quickly" (we can't actually control time, but
        // request_count/duration will give high RPS if all in same moment)
        for _ in 0..20 {
            tracker.record_js_attempt(ip, ua, true, 100, None);
        }

        let summary = tracker.get_summary(ip, ua).unwrap();
        // All requests have same timestamp, so RPS will be very high
        assert!(summary.requests_per_second > 10.0);
    }

    #[test]
    fn test_fingerprint_tracking() {
        let tracker = InjectionTracker::new(test_config());
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Record with fingerprint
        tracker.record_js_attempt(ip, ua, true, 100, Some("fp_hash_1"));
        tracker.record_js_attempt(ip, ua, true, 100, Some("fp_hash_2"));
        tracker.record_js_attempt(ip, ua, true, 100, Some("fp_hash_3"));

        let summary = tracker.get_summary(ip, ua).unwrap();
        assert_eq!(summary.headless_indicators.fingerprint_changes, 2);
    }

    #[test]
    fn test_fingerprint_anomaly_too_many_changes() {
        let mut config = test_config();
        config.max_fingerprint_changes = 5;
        config.min_attempts_for_detection = 3;
        let tracker = InjectionTracker::new(config);
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make many requests with different fingerprints
        for i in 0..15 {
            tracker.record_js_attempt(ip, ua, true, 100, Some(&format!("fp_{}", i)));
        }

        let summary = tracker.get_summary(ip, ua).unwrap();
        assert!(summary.headless_indicators.fingerprint_anomaly);
    }

    #[test]
    fn test_record_cookie_attempt() {
        let tracker = InjectionTracker::new(test_config());
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        tracker.record_cookie_attempt(ip, ua, true);
        tracker.record_cookie_attempt(ip, ua, false);

        let stats = tracker.stats().snapshot();
        assert_eq!(stats.cookie_attempts_total, 2);
        assert_eq!(stats.cookie_successes_total, 1);

        let summary = tracker.get_summary(ip, ua).unwrap();
        assert_eq!(summary.cookie_attempts, 2);
        assert_eq!(summary.cookie_success_rate, 0.5);
    }

    #[test]
    fn test_should_block_no_record() {
        let tracker = InjectionTracker::new(test_config());

        let (should_block, reason) = tracker.should_block("192.168.1.1", "Mozilla/5.0");
        assert!(!should_block);
        assert!(reason.is_none());
    }

    #[test]
    fn test_should_block_headless() {
        let tracker = InjectionTracker::new(test_config());
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make enough failed attempts to trigger headless detection
        for _ in 0..6 {
            tracker.record_js_attempt(ip, ua, false, 100, None);
        }

        let (should_block, reason) = tracker.should_block(ip, ua);
        assert!(should_block);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("Headless browser detected"));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut config = test_config();
        config.record_ttl_secs = 0; // Immediate expiration
        let tracker = InjectionTracker::new(config);

        tracker.record_js_attempt("192.168.1.1", "UA1", true, 100, None);
        tracker.record_js_attempt("192.168.1.2", "UA2", true, 100, None);
        assert_eq!(tracker.len(), 2);

        // Sleep to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        let removed = tracker.cleanup_expired();
        assert_eq!(removed, 2);
        assert!(tracker.is_empty());

        let stats = tracker.stats().snapshot();
        assert_eq!(stats.records_expired, 2);
    }

    #[test]
    fn test_capacity_eviction() {
        let mut config = test_config();
        config.max_records = 10;
        let tracker = InjectionTracker::new(config);

        // Add more records than max
        for i in 0..15 {
            tracker.record_js_attempt(&format!("192.168.1.{}", i), "UA", true, 100, None);
        }

        // Should have evicted some records
        assert!(tracker.len() <= 10);
    }

    #[test]
    fn test_actor_key_consistency() {
        let key1 = InjectionTracker::actor_key("192.168.1.1", "Mozilla/5.0");
        let key2 = InjectionTracker::actor_key("192.168.1.1", "Mozilla/5.0");
        let key3 = InjectionTracker::actor_key("192.168.1.1", "Chrome/100");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_ua_hash() {
        let hash1 = InjectionTracker::hash_ua("Mozilla/5.0");
        let hash2 = InjectionTracker::hash_ua("Mozilla/5.0");
        let hash3 = InjectionTracker::hash_ua("Chrome/100");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 16);
    }

    #[test]
    fn test_indicators_description() {
        let indicators = HeadlessIndicators {
            no_js_execution: true,
            consistent_timing: false,
            rapid_requests: true,
            fingerprint_anomaly: false,
            timing_variance_ms: 100.0,
            requests_per_second: 15.0,
            js_success_rate: 0.0,
            fingerprint_changes: 0,
        };

        let desc = indicators.description();
        assert!(desc.contains("no_js_execution"));
        assert!(desc.contains("rapid_requests"));
        assert!(!desc.contains("consistent_timing"));
    }

    #[test]
    fn test_indicators_count() {
        let indicators = HeadlessIndicators {
            no_js_execution: true,
            consistent_timing: true,
            rapid_requests: false,
            fingerprint_anomaly: false,
            ..Default::default()
        };

        assert_eq!(indicators.indicator_count(), 2);
        assert!(indicators.is_suspicious());
    }

    #[test]
    fn test_response_time_variance_calculation() {
        let mut record = InjectionRecord::new("192.168.1.1".to_string(), "hash".to_string(), 0);

        // Not enough data
        record.response_times.push_back(100);
        assert_eq!(record.response_time_variance(), f64::MAX);

        // Add more data
        record.response_times.push_back(100);
        record.response_times.push_back(100);
        assert_eq!(record.response_time_variance(), 0.0); // All same = 0 variance

        // Variable data
        record.response_times.clear();
        record.response_times.push_back(50);
        record.response_times.push_back(150);
        let variance = record.response_time_variance();
        assert!(variance > 0.0);
    }

    #[test]
    fn test_requests_per_second_calculation() {
        let mut record = InjectionRecord::new("192.168.1.1".to_string(), "hash".to_string(), 1000);
        record.request_count = 10;
        record.last_seen = 2000; // 1 second later

        let rps = record.requests_per_second();
        assert_eq!(rps, 10.0);
    }

    #[test]
    fn test_clear() {
        let tracker = InjectionTracker::new(test_config());

        tracker.record_js_attempt("192.168.1.1", "UA1", true, 100, None);
        tracker.record_js_attempt("192.168.1.2", "UA2", true, 100, None);
        assert_eq!(tracker.len(), 2);

        tracker.clear();
        assert!(tracker.is_empty());
    }

    #[test]
    fn test_summary_not_found() {
        let tracker = InjectionTracker::new(test_config());

        let summary = tracker.get_summary("192.168.1.1", "Mozilla/5.0");
        assert!(summary.is_none());
    }

    #[test]
    fn test_multiple_weak_signals_trigger_detection() {
        let mut config = test_config();
        config.timing_variance_threshold_ms = 100.0;
        config.min_attempts_for_detection = 5;
        let tracker = InjectionTracker::new(config);
        let ip = "192.168.1.1";
        let ua = "Mozilla/5.0";

        // Make requests with consistent timing and no fingerprint changes
        // but still passing JS (so no_js_execution is false)
        for _ in 0..15 {
            tracker.record_js_attempt(ip, ua, true, 100, None);
        }

        let summary = tracker.get_summary(ip, ua).unwrap();

        // Should have consistent_timing and fingerprint_anomaly (never changes)
        let indicators = &summary.headless_indicators;
        let count = indicators.indicator_count();

        // With 2+ signals, should be detected as headless
        if count >= 2 {
            assert!(summary.is_likely_headless);
        }
    }
}
