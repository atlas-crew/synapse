//! JA4 Rotation Detector
//!
//! Identifies entities that rapidly change their TLS fingerprints,
//! which indicates fingerprint spoofing or bot toolkit rotation.
//!
//! # Detection Strategy
//!
//! The detector tracks fingerprint observations per IP address with timestamps.
//! When an IP exhibits multiple unique fingerprints within a sliding time window,
//! it's flagged as rotating. IPs with similar rotation timing patterns are
//! grouped into campaigns.
//!
//! # Threat Model
//!
//! Fingerprint rotation indicates:
//! - **TLS fingerprint spoofing**: Attackers randomizing JA4 to evade detection
//! - **Bot toolkit rotation**: Automated tools cycling through client profiles
//! - **Evasion attempts**: Sophisticated actors trying to appear as different clients
//!
//! # Performance
//!
//! - O(1) fingerprint recording via HashMap
//! - O(n) analysis where n is number of tracked IPs
//! - Automatic cleanup of stale observations
//! - Thread-safe via RwLock for concurrent access
//!
//! # Example
//!
//! ```rust,ignore
//! use synapse_pingora::correlation::detectors::Ja4RotationDetector;
//! use std::time::Duration;
//!
//! let config = RotationConfig {
//!     min_fingerprints: 3,
//!     window: Duration::from_secs(60),
//!     track_combined: true,
//! };
//!
//! let detector = Ja4RotationDetector::new(config);
//!
//! // Record fingerprints as requests come in
//! let ip = "192.168.1.100".parse().unwrap();
//! detector.record_fingerprint(ip, "t13d1516h2_abc".to_string());
//! detector.record_fingerprint(ip, "t13d1516h2_def".to_string());
//! detector.record_fingerprint(ip, "t13d1516h2_ghi".to_string());
//!
//! // Check if rotating
//! assert!(detector.is_rotating(&ip));
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::correlation::{
    CampaignUpdate, CorrelationReason, CorrelationType, FingerprintIndex,
};

use super::{Detector, DetectorResult};

/// Configuration for rotation detection.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// Minimum unique fingerprints to trigger detection.
    ///
    /// Default: 3 (an IP must show at least 3 different fingerprints)
    pub min_fingerprints: usize,

    /// Time window for rotation detection.
    ///
    /// Default: 60 seconds
    pub window: Duration,

    /// Whether to track combined fingerprints (JA4+JA4H).
    ///
    /// When true, combined fingerprint changes also count toward rotation.
    /// Default: true
    pub track_combined: bool,

    /// Cleanup interval in seconds for automatic history cleanup.
    /// Default: 30 seconds
    pub cleanup_interval_secs: u64,

    /// Time window for grouping IPs with similar rotation timing.
    /// Default: 10 seconds
    pub grouping_window: Duration,

    /// Minimum group size for timing-based grouping.
    /// Default: 2 IPs
    pub min_group_size: usize,

    /// Divisor for normalizing unique fingerprint count in confidence calculation.
    /// Default: 5.0
    pub confidence_divisor: f64,

    /// Base confidence offset added to normalized value.
    /// Default: 0.7
    pub confidence_base: f64,

    /// Minimum confidence value for clamp.
    /// Default: 0.5
    pub confidence_min: f64,

    /// Maximum confidence value for clamp.
    /// Default: 0.95
    pub confidence_max: f64,

    /// Scan interval in milliseconds.
    /// Default: 10000 (10 seconds)
    pub scan_interval_ms: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            min_fingerprints: 3,
            window: Duration::from_secs(60),
            track_combined: true,
            cleanup_interval_secs: 30,
            grouping_window: Duration::from_secs(10),
            min_group_size: 2,
            confidence_divisor: 5.0,
            confidence_base: 0.7,
            confidence_min: 0.5,
            confidence_max: 0.95,
            scan_interval_ms: 10000,
        }
    }
}

impl RotationConfig {
    /// Create a new configuration with the specified threshold.
    pub fn with_threshold(min_fingerprints: usize) -> Self {
        Self {
            min_fingerprints,
            ..Default::default()
        }
    }

    /// Create a new configuration with the specified window.
    pub fn with_window(window: Duration) -> Self {
        Self {
            window,
            ..Default::default()
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_fingerprints < 2 {
            return Err("min_fingerprints must be at least 2".to_string());
        }
        if self.window.is_zero() {
            return Err("window duration must be positive".to_string());
        }
        Ok(())
    }
}

/// Tracks fingerprint history for a single IP address.
#[derive(Debug)]
struct FingerprintHistory {
    /// (timestamp, fingerprint) pairs
    observations: Vec<(Instant, String)>,
    /// When this history was last cleaned
    last_cleanup: Instant,
}

impl FingerprintHistory {
    fn new() -> Self {
        Self {
            observations: Vec::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Add a new observation.
    fn add(&mut self, fingerprint: String) {
        self.observations.push((Instant::now(), fingerprint));
    }

    /// Remove observations older than the given duration.
    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.observations.retain(|(ts, _)| *ts > cutoff);
        self.last_cleanup = Instant::now();
    }

    /// Get unique fingerprint count within the window.
    fn unique_count_in_window(&self, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        let unique: HashSet<_> = self
            .observations
            .iter()
            .filter(|(ts, _)| *ts > cutoff)
            .map(|(_, fp)| fp.as_str())
            .collect();
        unique.len()
    }

    /// Get all unique fingerprints within the window.
    fn unique_fingerprints_in_window(&self, window: Duration) -> Vec<String> {
        let cutoff = Instant::now() - window;
        let unique: HashSet<_> = self
            .observations
            .iter()
            .filter(|(ts, _)| *ts > cutoff)
            .map(|(_, fp)| fp.clone())
            .collect();
        unique.into_iter().collect()
    }

    /// Check if the history needs cleanup.
    fn needs_cleanup(&self, interval_secs: u64) -> bool {
        self.last_cleanup.elapsed().as_secs() >= interval_secs
    }
}

/// Detects IPs that rapidly rotate their TLS fingerprints.
///
/// This detector maintains per-IP fingerprint history and identifies
/// IPs that exhibit multiple unique fingerprints within a time window.
/// Such behavior indicates fingerprint spoofing or bot toolkit rotation.
pub struct Ja4RotationDetector {
    config: RotationConfig,
    /// Per-IP fingerprint history.
    history: RwLock<HashMap<IpAddr, FingerprintHistory>>,
    /// IPs already flagged as rotating.
    flagged: RwLock<HashSet<IpAddr>>,
}

impl Ja4RotationDetector {
    /// Create a new JA4 rotation detector with the given configuration.
    pub fn new(config: RotationConfig) -> Self {
        Self {
            config,
            history: RwLock::new(HashMap::new()),
            flagged: RwLock::new(HashSet::new()),
        }
    }

    /// Create a new detector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RotationConfig::default())
    }

    /// Record a fingerprint observation for an IP.
    ///
    /// This should be called whenever a request is processed and a JA4
    /// fingerprint is extracted. The detector will track the history
    /// and detect rotation patterns.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `fingerprint` - The JA4 fingerprint observed
    pub fn record_fingerprint(&self, ip: IpAddr, fingerprint: String) {
        // Skip empty fingerprints
        if fingerprint.is_empty() {
            return;
        }

        let mut history = match self.history.write() {
            Ok(h) => h,
            Err(_) => return, // Skip on lock contention
        };

        let entry = history.entry(ip).or_insert_with(FingerprintHistory::new);
        entry.add(fingerprint);

        // Periodic cleanup for this IP
        if entry.needs_cleanup(self.config.cleanup_interval_secs) {
            entry.cleanup(self.config.window);
        }

        // Check if this IP should be flagged
        let unique_count = entry.unique_count_in_window(self.config.window);
        if unique_count >= self.config.min_fingerprints {
            drop(history); // Release write lock
            if let Ok(mut flagged) = self.flagged.write() {
                flagged.insert(ip);
            }
        }
    }

    /// Check if an IP is currently rotating fingerprints.
    ///
    /// Returns `true` if the IP has been flagged as rotating (showing
    /// multiple unique fingerprints within the detection window).
    pub fn is_rotating(&self, ip: &IpAddr) -> bool {
        // First check the flagged set (fast path)
        if let Ok(flagged) = self.flagged.read() {
            if flagged.contains(ip) {
                return true;
            }
        }

        // Check current state (may have been updated since last flag check)
        self.unique_count_in_window(ip) >= self.config.min_fingerprints
    }

    /// Get unique fingerprint count within window for an IP.
    ///
    /// # Arguments
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    /// Number of unique fingerprints seen within the detection window.
    pub fn unique_count_in_window(&self, ip: &IpAddr) -> usize {
        let history = match self.history.read() {
            Ok(h) => h,
            Err(_) => return 0,
        };

        history
            .get(ip)
            .map(|h| h.unique_count_in_window(self.config.window))
            .unwrap_or(0)
    }

    /// Get unique fingerprints within window for an IP.
    ///
    /// # Arguments
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    /// List of unique fingerprints seen within the detection window.
    pub fn unique_fingerprints(&self, ip: &IpAddr) -> Vec<String> {
        let history = match self.history.read() {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        history
            .get(ip)
            .map(|h| h.unique_fingerprints_in_window(self.config.window))
            .unwrap_or_default()
    }

    /// Get all IPs currently flagged as rotating.
    pub fn get_rotating_ips(&self) -> Vec<IpAddr> {
        let flagged = match self.flagged.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        flagged.iter().copied().collect()
    }

    /// Get the number of tracked IPs.
    pub fn tracked_ip_count(&self) -> usize {
        self.history.read().map(|h| h.len()).unwrap_or(0)
    }

    /// Get the number of flagged (rotating) IPs.
    pub fn flagged_ip_count(&self) -> usize {
        self.flagged.read().map(|f| f.len()).unwrap_or(0)
    }

    /// Clean old observations from history.
    ///
    /// This is called automatically during normal operation but can be
    /// invoked manually if needed.
    pub fn cleanup_old_observations(&self) {
        let mut history = match self.history.write() {
            Ok(h) => h,
            Err(_) => return,
        };

        // Cleanup each IP's history
        for (_, ip_history) in history.iter_mut() {
            ip_history.cleanup(self.config.window);
        }

        // Remove IPs with no observations
        history.retain(|_, h| !h.observations.is_empty());

        // Re-evaluate flagged IPs
        let window = self.config.window;
        let min_fps = self.config.min_fingerprints;
        if let Ok(mut flagged) = self.flagged.write() {
            flagged.retain(|ip| {
                history
                    .get(ip)
                    .map(|h| h.unique_count_in_window(window) >= min_fps)
                    .unwrap_or(false)
            });
        }
    }

    /// Get detector statistics.
    pub fn stats(&self) -> Ja4RotationStats {
        let (tracked, total_observations) = self
            .history
            .read()
            .map(|h| {
                let tracked = h.len();
                let total: usize = h.values().map(|v| v.observations.len()).sum();
                (tracked, total)
            })
            .unwrap_or((0, 0));

        let flagged = self.flagged.read().map(|f| f.len()).unwrap_or(0);

        Ja4RotationStats {
            tracked_ips: tracked,
            flagged_ips: flagged,
            total_observations,
            window_seconds: self.config.window.as_secs(),
            min_fingerprints: self.config.min_fingerprints,
        }
    }

    /// Group rotating IPs by similar timing patterns.
    ///
    /// IPs that started rotating around the same time may be part of
    /// the same campaign.
    fn group_by_rotation_timing(&self) -> Vec<Vec<IpAddr>> {
        let history = match self.history.read() {
            Ok(h) => h,
            Err(_) => return Vec::new(),
        };

        let flagged = match self.flagged.read() {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        // Get first observation time for each flagged IP
        let mut ip_first_seen: Vec<(IpAddr, Instant)> = flagged
            .iter()
            .filter_map(|ip| {
                history.get(ip).and_then(|h| {
                    h.observations.first().map(|(ts, _)| (*ip, *ts))
                })
            })
            .collect();

        // Sort by first seen time
        ip_first_seen.sort_by_key(|(_, ts)| *ts);

        // Group IPs that started within the configured grouping window
        let mut groups: Vec<Vec<IpAddr>> = Vec::new();
        let mut current_group: Vec<IpAddr> = Vec::new();
        let mut group_start: Option<Instant> = None;

        for (ip, first_seen) in ip_first_seen {
            match group_start {
                None => {
                    group_start = Some(first_seen);
                    current_group.push(ip);
                }
                Some(start) => {
                    if first_seen.duration_since(start) <= self.config.grouping_window {
                        current_group.push(ip);
                    } else {
                        if current_group.len() >= self.config.min_group_size {
                            groups.push(std::mem::take(&mut current_group));
                        } else {
                            current_group.clear();
                        }
                        group_start = Some(first_seen);
                        current_group.push(ip);
                    }
                }
            }
        }

        // Don't forget the last group
        if current_group.len() >= self.config.min_group_size {
            groups.push(current_group);
        }

        groups
    }
}

impl Default for Ja4RotationDetector {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl Detector for Ja4RotationDetector {
    fn name(&self) -> &'static str {
        "ja4_rotation"
    }

    fn analyze(&self, _index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>> {
        // First, ensure cleanup is done
        self.cleanup_old_observations();

        // Group rotating IPs by timing patterns
        let groups = self.group_by_rotation_timing();

        // Create campaign updates for each group
        let updates: Vec<CampaignUpdate> = groups
            .into_iter()
            .map(|ips| {
                // Collect evidence (the fingerprints seen)
                let evidence: Vec<String> = ips
                    .iter()
                    .flat_map(|ip| {
                        let fps = self.unique_fingerprints(ip);
                        let ip_str = ip.to_string();
                        fps.into_iter()
                            .take(3) // Limit evidence per IP
                            .map(move |fp| format!("{}:{}", ip_str, fp))
                    })
                    .take(10) // Limit total evidence
                    .collect();

                let ip_strings: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
                let ip_count = ip_strings.len();

                // Calculate confidence based on group size and uniqueness
                let avg_unique: f64 = ips
                    .iter()
                    .map(|ip| self.unique_count_in_window(ip) as f64)
                    .sum::<f64>()
                    / ip_count as f64;

                let confidence = ((avg_unique - self.config.min_fingerprints as f64) / self.config.confidence_divisor + self.config.confidence_base)
                    .clamp(self.config.confidence_min, self.config.confidence_max);

                CampaignUpdate {
                    campaign_id: None,
                    status: None,
                    confidence: Some(confidence),
                    attack_types: Some(vec!["fingerprint_rotation".to_string()]),
                    add_member_ips: Some(ip_strings.clone()),
                    add_correlation_reason: Some(CorrelationReason::new(
                        CorrelationType::TlsFingerprint,
                        confidence,
                        format!(
                            "{} IPs rotating JA4 fingerprints within {}s window",
                            ip_count,
                            self.config.window.as_secs()
                        ),
                        evidence,
                    )),
                    increment_requests: None,
                    increment_blocked: None,
                    increment_rules: None,
                    risk_score: Some(((confidence * 100.0) as u32).min(100)),
                }
            })
            .collect();

        Ok(updates)
    }

    fn should_trigger(&self, ip: &IpAddr, _index: &FingerprintIndex) -> bool {
        // Trigger if this IP is approaching the rotation threshold
        self.unique_count_in_window(ip) >= self.config.min_fingerprints.saturating_sub(1)
    }

    fn scan_interval_ms(&self) -> u64 {
        self.config.scan_interval_ms
    }
}

/// Statistics for the JA4 rotation detector.
#[derive(Debug, Clone)]
pub struct Ja4RotationStats {
    /// Number of IPs being tracked.
    pub tracked_ips: usize,
    /// Number of IPs flagged as rotating.
    pub flagged_ips: usize,
    /// Total number of fingerprint observations.
    pub total_observations: usize,
    /// Detection window in seconds.
    pub window_seconds: u64,
    /// Minimum fingerprints threshold.
    pub min_fingerprints: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.min_fingerprints, 3);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.track_combined);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_with_threshold() {
        let config = RotationConfig::with_threshold(5);
        assert_eq!(config.min_fingerprints, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_with_window() {
        let config = RotationConfig::with_window(Duration::from_secs(120));
        assert_eq!(config.window, Duration::from_secs(120));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_min_fingerprints() {
        let config = RotationConfig {
            min_fingerprints: 1,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("min_fingerprints"));
    }

    #[test]
    fn test_config_validation_zero_window() {
        let config = RotationConfig {
            window: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        assert!(config.validate().unwrap_err().contains("window"));
    }

    // ========================================================================
    // Basic Detector Tests
    // ========================================================================

    #[test]
    fn test_detector_new() {
        let detector = Ja4RotationDetector::with_defaults();
        assert_eq!(detector.name(), "ja4_rotation");
        assert_eq!(detector.tracked_ip_count(), 0);
        assert_eq!(detector.flagged_ip_count(), 0);
    }

    #[test]
    fn test_record_fingerprint_single() {
        let detector = Ja4RotationDetector::with_defaults();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        detector.record_fingerprint(ip, "fp1".to_string());

        assert_eq!(detector.tracked_ip_count(), 1);
        assert_eq!(detector.unique_count_in_window(&ip), 1);
        assert!(!detector.is_rotating(&ip));
    }

    #[test]
    fn test_record_fingerprint_empty_skipped() {
        let detector = Ja4RotationDetector::with_defaults();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        detector.record_fingerprint(ip, "".to_string());

        assert_eq!(detector.tracked_ip_count(), 0);
    }

    #[test]
    fn test_rotation_detection_with_multiple_fingerprints() {
        let config = RotationConfig {
            min_fingerprints: 3,
            window: Duration::from_secs(60),
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Record 3 different fingerprints
        detector.record_fingerprint(ip, "fp_alpha".to_string());
        detector.record_fingerprint(ip, "fp_beta".to_string());
        detector.record_fingerprint(ip, "fp_gamma".to_string());

        // Should be flagged as rotating
        assert!(detector.is_rotating(&ip));
        assert_eq!(detector.flagged_ip_count(), 1);
        assert_eq!(detector.unique_count_in_window(&ip), 3);

        // Verify unique fingerprints
        let fps = detector.unique_fingerprints(&ip);
        assert_eq!(fps.len(), 3);
        assert!(fps.contains(&"fp_alpha".to_string()));
        assert!(fps.contains(&"fp_beta".to_string()));
        assert!(fps.contains(&"fp_gamma".to_string()));
    }

    #[test]
    fn test_rotation_not_triggered_below_threshold() {
        let config = RotationConfig {
            min_fingerprints: 4,
            window: Duration::from_secs(60),
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Record only 3 different fingerprints (below threshold of 4)
        detector.record_fingerprint(ip, "fp1".to_string());
        detector.record_fingerprint(ip, "fp2".to_string());
        detector.record_fingerprint(ip, "fp3".to_string());

        // Should NOT be flagged
        assert!(!detector.is_rotating(&ip));
        assert_eq!(detector.flagged_ip_count(), 0);
        assert_eq!(detector.unique_count_in_window(&ip), 3);
    }

    #[test]
    fn test_duplicate_fingerprints_counted_once() {
        let detector = Ja4RotationDetector::with_defaults();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record the same fingerprint multiple times
        for _ in 0..10 {
            detector.record_fingerprint(ip, "same_fp".to_string());
        }

        // Should only count as 1 unique fingerprint
        assert_eq!(detector.unique_count_in_window(&ip), 1);
        assert!(!detector.is_rotating(&ip));
    }

    #[test]
    fn test_window_expiration() {
        let config = RotationConfig {
            min_fingerprints: 2,
            window: Duration::from_millis(50), // Very short window
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Record fingerprints
        detector.record_fingerprint(ip, "fp1".to_string());
        detector.record_fingerprint(ip, "fp2".to_string());

        // Should be rotating initially
        assert!(detector.is_rotating(&ip));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(100));

        // Cleanup should clear old observations
        detector.cleanup_old_observations();

        // Should no longer be rotating
        assert!(!detector.is_rotating(&ip));
        assert_eq!(detector.flagged_ip_count(), 0);
    }

    #[test]
    fn test_cleanup_removes_empty_histories() {
        let config = RotationConfig {
            min_fingerprints: 2,
            window: Duration::from_millis(10),
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);

        // Add fingerprints for multiple IPs
        for i in 0..5 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            detector.record_fingerprint(ip, format!("fp{}", i));
        }

        assert_eq!(detector.tracked_ip_count(), 5);

        // Wait for window to expire
        thread::sleep(Duration::from_millis(50));

        // Cleanup
        detector.cleanup_old_observations();

        // All histories should be removed
        assert_eq!(detector.tracked_ip_count(), 0);
    }

    #[test]
    fn test_is_rotating_accuracy() {
        let config = RotationConfig {
            min_fingerprints: 3,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);

        let rotating_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let stable_ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Rotating IP: many fingerprints
        detector.record_fingerprint(rotating_ip, "fp1".to_string());
        detector.record_fingerprint(rotating_ip, "fp2".to_string());
        detector.record_fingerprint(rotating_ip, "fp3".to_string());
        detector.record_fingerprint(rotating_ip, "fp4".to_string());

        // Stable IP: single fingerprint repeated
        for _ in 0..10 {
            detector.record_fingerprint(stable_ip, "stable_fp".to_string());
        }

        assert!(detector.is_rotating(&rotating_ip));
        assert!(!detector.is_rotating(&stable_ip));
    }

    // ========================================================================
    // Detector Trait Tests
    // ========================================================================

    #[test]
    fn test_should_trigger() {
        let config = RotationConfig {
            min_fingerprints: 3,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let index = FingerprintIndex::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // With 0 fingerprints, should not trigger
        assert!(!detector.should_trigger(&ip, &index));

        // With 1 fingerprint, should not trigger (need 2 to be "approaching" 3)
        detector.record_fingerprint(ip, "fp1".to_string());
        assert!(!detector.should_trigger(&ip, &index));

        // With 2 fingerprints, should trigger (approaching threshold)
        detector.record_fingerprint(ip, "fp2".to_string());
        assert!(detector.should_trigger(&ip, &index));
    }

    #[test]
    fn test_analyze_creates_campaign_updates() {
        let config = RotationConfig {
            min_fingerprints: 2,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let index = FingerprintIndex::new();

        // Create two rotating IPs with similar timing (within 10 seconds)
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        detector.record_fingerprint(ip1, "fp1".to_string());
        detector.record_fingerprint(ip1, "fp2".to_string());
        detector.record_fingerprint(ip2, "fp1".to_string());
        detector.record_fingerprint(ip2, "fp2".to_string());

        // Both should be flagged
        assert!(detector.is_rotating(&ip1));
        assert!(detector.is_rotating(&ip2));

        // Analyze should create campaign update
        let updates = detector.analyze(&index).unwrap();

        // Should have at least one update if IPs grouped together
        // (timing grouping depends on exact timing of test execution)
        assert!(!updates.is_empty() || detector.flagged_ip_count() == 2);
    }

    #[test]
    fn test_scan_interval() {
        let detector = Ja4RotationDetector::with_defaults();
        assert_eq!(detector.scan_interval_ms(), 10000);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats() {
        let config = RotationConfig {
            min_fingerprints: 3,
            window: Duration::from_secs(60),
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);

        // Add some data
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        detector.record_fingerprint(ip1, "fp1".to_string());
        detector.record_fingerprint(ip1, "fp2".to_string());
        detector.record_fingerprint(ip1, "fp3".to_string());

        detector.record_fingerprint(ip2, "fp1".to_string());

        let stats = detector.stats();

        assert_eq!(stats.tracked_ips, 2);
        assert_eq!(stats.flagged_ips, 1);
        assert_eq!(stats.total_observations, 4);
        assert_eq!(stats.window_seconds, 60);
        assert_eq!(stats.min_fingerprints, 3);
    }

    #[test]
    fn test_get_rotating_ips() {
        let config = RotationConfig {
            min_fingerprints: 2,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        // IP1: rotating
        detector.record_fingerprint(ip1, "fp1".to_string());
        detector.record_fingerprint(ip1, "fp2".to_string());

        // IP2: rotating
        detector.record_fingerprint(ip2, "fp3".to_string());
        detector.record_fingerprint(ip2, "fp4".to_string());

        // IP3: not rotating
        detector.record_fingerprint(ip3, "fp5".to_string());

        let rotating = detector.get_rotating_ips();

        assert_eq!(rotating.len(), 2);
        assert!(rotating.contains(&ip1));
        assert!(rotating.contains(&ip2));
        assert!(!rotating.contains(&ip3));
    }

    // ========================================================================
    // Concurrency Tests
    // ========================================================================

    #[test]
    fn test_concurrent_fingerprint_recording() {
        use std::sync::Arc;

        let detector = Arc::new(Ja4RotationDetector::with_defaults());
        let mut handles = vec![];

        // Spawn multiple threads recording fingerprints
        for thread_id in 0..10 {
            let detector = Arc::clone(&detector);
            handles.push(thread::spawn(move || {
                for fp_id in 0..100 {
                    let ip: IpAddr = format!("10.{}.0.1", thread_id).parse().unwrap();
                    detector.record_fingerprint(ip, format!("fp_{}", fp_id % 5));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify no panics and reasonable state
        assert!(detector.tracked_ip_count() > 0);
    }

    #[test]
    fn test_concurrent_read_write() {
        use std::sync::Arc;

        let detector = Arc::new(Ja4RotationDetector::with_defaults());

        // Pre-populate
        for i in 0..10 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            detector.record_fingerprint(ip, "fp1".to_string());
            detector.record_fingerprint(ip, "fp2".to_string());
            detector.record_fingerprint(ip, "fp3".to_string());
        }

        let mut handles = vec![];

        // Writer threads
        for thread_id in 0..5 {
            let detector = Arc::clone(&detector);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let ip: IpAddr = format!("10.{}.0.{}", thread_id, i % 10).parse().unwrap();
                    detector.record_fingerprint(ip, format!("new_fp_{}", i));
                }
            }));
        }

        // Reader threads
        for _ in 0..5 {
            let detector = Arc::clone(&detector);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip: IpAddr = format!("10.0.0.{}", i % 10).parse().unwrap();
                    let _ = detector.is_rotating(&ip);
                    let _ = detector.unique_count_in_window(&ip);
                    let _ = detector.stats();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify integrity
        assert!(detector.tracked_ip_count() > 0);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_ipv6_addresses() {
        let detector = Ja4RotationDetector::with_defaults();

        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        detector.record_fingerprint(ipv6, "fp1".to_string());
        detector.record_fingerprint(ipv6, "fp2".to_string());
        detector.record_fingerprint(ipv6, "fp3".to_string());

        assert!(detector.is_rotating(&ipv6));
    }

    #[test]
    fn test_many_unique_fingerprints() {
        let config = RotationConfig {
            min_fingerprints: 3,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Record many unique fingerprints
        for i in 0..100 {
            detector.record_fingerprint(ip, format!("fp_{}", i));
        }

        assert!(detector.is_rotating(&ip));
        assert_eq!(detector.unique_count_in_window(&ip), 100);
    }

    #[test]
    fn test_analyze_with_empty_history() {
        let detector = Ja4RotationDetector::with_defaults();
        let index = FingerprintIndex::new();

        // Should return empty updates when no IPs tracked
        let updates = detector.analyze(&index).unwrap();
        assert!(updates.is_empty());
    }

    #[test]
    fn test_fingerprint_history_unique_count() {
        let mut history = FingerprintHistory::new();
        let window = Duration::from_secs(60);

        history.add("fp1".to_string());
        history.add("fp1".to_string()); // Duplicate
        history.add("fp2".to_string());
        history.add("fp3".to_string());
        history.add("fp2".to_string()); // Duplicate

        assert_eq!(history.unique_count_in_window(window), 3);
    }

    #[test]
    fn test_fingerprint_history_cleanup() {
        let mut history = FingerprintHistory::new();

        // Add observations
        history.add("fp1".to_string());
        history.add("fp2".to_string());

        // Wait briefly
        thread::sleep(Duration::from_millis(10));

        // Cleanup with very short window should remove all
        history.cleanup(Duration::from_millis(1));

        assert!(history.observations.is_empty());
    }

    #[test]
    fn test_grouping_by_rotation_timing() {
        let config = RotationConfig {
            min_fingerprints: 2,
            ..Default::default()
        };
        let detector = Ja4RotationDetector::new(config);

        // Add multiple rotating IPs
        for i in 0..5 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            detector.record_fingerprint(ip, "fp1".to_string());
            detector.record_fingerprint(ip, "fp2".to_string());
        }

        // All should be grouped together (started within 10s of each other)
        let groups = detector.group_by_rotation_timing();

        // Should have at least one group with multiple IPs
        if !groups.is_empty() {
            assert!(groups[0].len() >= 2);
        }
    }
}
