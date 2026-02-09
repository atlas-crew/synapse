//! Shared Fingerprint Detection Strategy
//!
//! This detector identifies campaigns where multiple IP addresses share the same
//! JA4 TLS fingerprint or combined fingerprint hash (JA4+JA4H). Shared fingerprints
//! are a strong indicator of coordinated attack tooling.
//!
//! # Detection Logic
//!
//! When 3+ IPs share an identical fingerprint, this strongly suggests:
//! - Same attack tooling (bot framework, scanner, etc.)
//! - Coordinated campaign from distributed infrastructure
//! - Potential botnet or proxy rotation
//!
//! # Example
//!
//! ```rust
//! use synapse_pingora::correlation::FingerprintIndex;
//! use synapse_pingora::correlation::detectors::{SharedFingerprintDetector, Detector};
//!
//! let index = FingerprintIndex::new();
//!
//! // Simulate 3 IPs sharing same fingerprint
//! index.update_entity("192.168.1.1", Some("t13d1516h2_abc123"), None);
//! index.update_entity("192.168.1.2", Some("t13d1516h2_abc123"), None);
//! index.update_entity("192.168.1.3", Some("t13d1516h2_abc123"), None);
//!
//! let detector = SharedFingerprintDetector::new(3);
//! let updates = detector.analyze(&index).unwrap();
//!
//! // Should detect a campaign with these 3 IPs
//! assert!(!updates.is_empty());
//! ```

use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::IpAddr;

use crate::correlation::{
    Campaign, CampaignUpdate, CorrelationReason, CorrelationType, FingerprintGroup,
    FingerprintIndex, FingerprintType,
};

use super::{Detector, DetectorResult};

/// Configuration for shared fingerprint detection
#[derive(Debug, Clone)]
pub struct SharedFingerprintConfig {
    /// Minimum number of IPs required to form a campaign
    pub threshold: usize,
    /// Base confidence score for detections (0.0-1.0)
    pub base_confidence: f64,
    /// Confidence bonus for combined fingerprints (JA4+JA4H)
    pub combined_type_bonus: f64,
    /// Confidence bonus per IP above threshold
    pub size_bonus_per_ip: f64,
    /// Maximum size bonus
    pub max_size_bonus: f64,
    /// Scan interval in milliseconds
    pub scan_interval_ms: u64,
}

impl Default for SharedFingerprintConfig {
    fn default() -> Self {
        Self {
            threshold: 3,
            base_confidence: 0.85,
            combined_type_bonus: 0.1,
            size_bonus_per_ip: 0.02,
            max_size_bonus: 0.05,
            scan_interval_ms: 5000,
        }
    }
}

/// Detector for campaigns based on shared fingerprints.
///
/// Identifies groups of IPs that share the same JA4 or combined fingerprint,
/// which indicates coordinated attack tooling.
pub struct SharedFingerprintDetector {
    /// Configuration for detection
    config: SharedFingerprintConfig,

    /// Fingerprints that have already been processed into campaigns
    /// Prevents duplicate campaign creation for the same fingerprint group
    processed_fingerprints: RwLock<HashSet<String>>,
}

impl SharedFingerprintDetector {
    /// Create a new detector with the specified threshold.
    ///
    /// # Arguments
    /// * `threshold` - Minimum IPs sharing a fingerprint to trigger campaign creation
    ///
    /// # Panics
    /// Panics if threshold is less than 2 (correlation requires at least 2 IPs).
    pub fn new(threshold: usize) -> Self {
        assert!(
            threshold >= 2,
            "Threshold must be at least 2 for correlation"
        );
        Self {
            config: SharedFingerprintConfig {
                threshold,
                ..Default::default()
            },
            processed_fingerprints: RwLock::new(HashSet::new()),
        }
    }

    /// Create a detector with custom configuration.
    ///
    /// # Arguments
    /// * `threshold` - Minimum IPs sharing a fingerprint
    /// * `base_confidence` - Confidence score for detections (0.0-1.0)
    /// * `scan_interval_ms` - Milliseconds between full scans
    pub fn with_config(threshold: usize, base_confidence: f64, scan_interval_ms: u64) -> Self {
        assert!(
            threshold >= 2,
            "Threshold must be at least 2 for correlation"
        );
        Self {
            config: SharedFingerprintConfig {
                threshold,
                base_confidence: base_confidence.clamp(0.0, 1.0),
                scan_interval_ms,
                ..Default::default()
            },
            processed_fingerprints: RwLock::new(HashSet::new()),
        }
    }

    /// Create a detector with full configuration.
    pub fn from_config(config: SharedFingerprintConfig) -> Self {
        assert!(
            config.threshold >= 2,
            "Threshold must be at least 2 for correlation"
        );
        Self {
            config,
            processed_fingerprints: RwLock::new(HashSet::new()),
        }
    }

    /// Check if a fingerprint has already been processed into a campaign.
    fn is_processed(&self, fingerprint: &str) -> bool {
        self.processed_fingerprints.read().contains(fingerprint)
    }

    /// Mark a fingerprint as processed.
    fn mark_processed(&self, fingerprint: &str) {
        self.processed_fingerprints
            .write()
            .insert(fingerprint.to_string());
    }

    /// Clear processed fingerprints (e.g., when resetting detector state).
    pub fn clear_processed(&self) {
        self.processed_fingerprints.write().clear();
    }

    /// Get the number of processed fingerprints.
    pub fn processed_count(&self) -> usize {
        self.processed_fingerprints.read().len()
    }

    /// Calculate confidence score based on fingerprint type and group size.
    ///
    /// Combined fingerprints (JA4+JA4H) get higher confidence than JA4 alone.
    /// Larger groups also increase confidence.
    fn calculate_confidence(&self, fp_type: FingerprintType, group_size: usize) -> f64 {
        let type_bonus = match fp_type {
            FingerprintType::Ja4 => 0.0,
            FingerprintType::Combined => self.config.combined_type_bonus,
        };

        // Size bonus: configurable per IP above threshold, capped at configurable max
        let size_bonus = ((group_size.saturating_sub(self.config.threshold)) as f64
            * self.config.size_bonus_per_ip)
            .min(self.config.max_size_bonus);

        (self.config.base_confidence + type_bonus + size_bonus).min(1.0)
    }

    /// Create a campaign update for a new fingerprint group.
    fn create_campaign_update(&self, group: &FingerprintGroup) -> CampaignUpdate {
        let confidence = self.calculate_confidence(group.fingerprint_type, group.size);

        let description = format!(
            "{} fingerprint '{}' shared by {} IPs",
            group.fingerprint_type, group.fingerprint, group.size
        );

        let reason = CorrelationReason::new(
            CorrelationType::HttpFingerprint,
            confidence,
            description,
            group.ips.clone(),
        );

        // Create a new campaign
        let campaign = Campaign::new(Campaign::generate_id(), group.ips.clone(), confidence);

        // Build update with correlation reason
        CampaignUpdate {
            campaign_id: Some(campaign.id.clone()),
            status: Some(campaign.status),
            confidence: Some(confidence),
            attack_types: None,
            add_member_ips: Some(group.ips.clone()),
            add_correlation_reason: Some(reason),
            increment_requests: None,
            increment_blocked: None,
            increment_rules: None,
            risk_score: None,
        }
    }

    /// Analyze a fingerprint group and return campaign update if new.
    fn process_group(&self, group: &FingerprintGroup) -> Option<CampaignUpdate> {
        // Skip if already processed
        if self.is_processed(&group.fingerprint) {
            return None;
        }

        // Skip if below threshold
        if group.size < self.config.threshold {
            return None;
        }

        // Mark as processed and create update
        self.mark_processed(&group.fingerprint);
        Some(self.create_campaign_update(group))
    }
}

impl Detector for SharedFingerprintDetector {
    fn name(&self) -> &'static str {
        "shared_fingerprint"
    }

    fn analyze(&self, index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>> {
        // Get all groups above threshold
        let groups = index.get_groups_above_threshold(self.config.threshold);

        if groups.is_empty() {
            return Ok(Vec::new());
        }

        // Process each group
        let updates: Vec<CampaignUpdate> = groups
            .iter()
            .filter_map(|group| self.process_group(group))
            .collect();

        Ok(updates)
    }

    fn should_trigger(&self, ip: &IpAddr, index: &FingerprintIndex) -> bool {
        let ip_str = ip.to_string();

        // Get fingerprints for this IP
        let fingerprints = match index.get_ip_fingerprints(&ip_str) {
            Some(fps) => fps,
            None => return false,
        };

        // Check if JA4 fingerprint group is at threshold
        if let Some(ref ja4) = fingerprints.0 {
            if !self.is_processed(ja4) {
                let count = index.count_ips_by_ja4(ja4);
                if count >= self.config.threshold {
                    return true;
                }
            }
        }

        // Check if combined fingerprint group is at threshold
        if let Some(ref combined) = fingerprints.1 {
            if !self.is_processed(combined) {
                let count = index.count_ips_by_combined(combined);
                if count >= self.config.threshold {
                    return true;
                }
            }
        }

        false
    }

    fn scan_interval_ms(&self) -> u64 {
        self.config.scan_interval_ms
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a test index with IPs sharing a JA4 fingerprint.
    fn create_test_index_ja4(fingerprint: &str, ip_count: usize) -> FingerprintIndex {
        let index = FingerprintIndex::new();
        for i in 0..ip_count {
            let ip = format!("192.168.1.{}", i + 1);
            index.update_entity(&ip, Some(fingerprint), None);
        }
        index
    }

    /// Create a test index with IPs sharing a combined fingerprint.
    fn create_test_index_combined(fingerprint: &str, ip_count: usize) -> FingerprintIndex {
        let index = FingerprintIndex::new();
        for i in 0..ip_count {
            let ip = format!("10.0.0.{}", i + 1);
            index.update_entity(&ip, None, Some(fingerprint));
        }
        index
    }

    /// Create a test index with mixed fingerprint types.
    fn create_mixed_test_index() -> FingerprintIndex {
        let index = FingerprintIndex::new();

        // JA4 group of 4 IPs
        for i in 0..4 {
            index.update_entity(&format!("192.168.1.{}", i + 1), Some("ja4_shared"), None);
        }

        // Combined group of 3 IPs
        for i in 0..3 {
            index.update_entity(&format!("10.0.0.{}", i + 1), None, Some("combined_shared"));
        }

        // Single IP with unique fingerprint
        index.update_entity("172.16.0.1", Some("ja4_unique"), Some("combined_unique"));

        index
    }

    // ========================================================================
    // Constructor Tests
    // ========================================================================

    #[test]
    fn test_new_detector() {
        let detector = SharedFingerprintDetector::new(3);
        assert_eq!(detector.config.threshold, 3);
        assert!((detector.config.base_confidence - 0.85).abs() < 0.001);
        assert_eq!(detector.config.scan_interval_ms, 5000);
        assert_eq!(detector.processed_count(), 0);
    }

    #[test]
    fn test_detector_with_config() {
        let detector = SharedFingerprintDetector::with_config(5, 0.9, 10000);
        assert_eq!(detector.config.threshold, 5);
        assert!((detector.config.base_confidence - 0.9).abs() < 0.001);
        assert_eq!(detector.config.scan_interval_ms, 10000);
    }

    #[test]
    fn test_confidence_clamping() {
        let detector = SharedFingerprintDetector::with_config(2, 1.5, 1000);
        assert!((detector.config.base_confidence - 1.0).abs() < 0.001);

        let detector = SharedFingerprintDetector::with_config(2, -0.5, 1000);
        assert!(detector.config.base_confidence >= 0.0);
    }

    #[test]
    #[should_panic(expected = "Threshold must be at least 2")]
    fn test_threshold_too_low() {
        SharedFingerprintDetector::new(1);
    }

    // ========================================================================
    // Detection Tests - JA4 Fingerprints
    // ========================================================================

    #[test]
    fn test_detect_ja4_group_at_threshold() {
        let index = create_test_index_ja4("shared_ja4", 3);
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);
        assert!(updates[0].add_correlation_reason.is_some());

        let reason = updates[0].add_correlation_reason.as_ref().unwrap();
        assert_eq!(reason.correlation_type, CorrelationType::HttpFingerprint);
        assert_eq!(reason.evidence.len(), 3);
    }

    #[test]
    fn test_detect_ja4_group_above_threshold() {
        let index = create_test_index_ja4("large_group", 10);
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);

        let reason = updates[0].add_correlation_reason.as_ref().unwrap();
        assert_eq!(reason.evidence.len(), 10);
        // Larger group should have higher confidence
        assert!(reason.confidence > 0.85);
    }

    #[test]
    fn test_no_detection_below_threshold() {
        let index = create_test_index_ja4("small_group", 2);
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();

        assert!(updates.is_empty());
    }

    // ========================================================================
    // Detection Tests - Combined Fingerprints
    // ========================================================================

    #[test]
    fn test_detect_combined_group() {
        let index = create_test_index_combined("combined_fp", 4);
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);

        let reason = updates[0].add_correlation_reason.as_ref().unwrap();
        // Combined fingerprints should have higher confidence than JA4 alone
        assert!(reason.confidence > 0.9);
    }

    #[test]
    fn test_detect_mixed_groups() {
        let index = create_mixed_test_index();
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();

        // Should detect both JA4 group (4 IPs) and combined group (3 IPs)
        assert_eq!(updates.len(), 2);
    }

    // ========================================================================
    // Duplicate Prevention Tests
    // ========================================================================

    #[test]
    fn test_no_duplicate_campaigns() {
        let index = create_test_index_ja4("repeated_fp", 5);
        let detector = SharedFingerprintDetector::new(3);

        // First analysis should detect
        let updates1 = detector.analyze(&index).unwrap();
        assert_eq!(updates1.len(), 1);

        // Second analysis should not duplicate
        let updates2 = detector.analyze(&index).unwrap();
        assert!(updates2.is_empty());

        assert_eq!(detector.processed_count(), 1);
    }

    #[test]
    fn test_clear_processed() {
        let index = create_test_index_ja4("clearable_fp", 3);
        let detector = SharedFingerprintDetector::new(3);

        // First detection
        let updates1 = detector.analyze(&index).unwrap();
        assert_eq!(updates1.len(), 1);

        // Clear processed
        detector.clear_processed();
        assert_eq!(detector.processed_count(), 0);

        // Should detect again
        let updates2 = detector.analyze(&index).unwrap();
        assert_eq!(updates2.len(), 1);
    }

    // ========================================================================
    // Trigger Tests
    // ========================================================================

    #[test]
    fn test_should_trigger_at_threshold() {
        let index = create_test_index_ja4("trigger_fp", 3);
        let detector = SharedFingerprintDetector::new(3);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should trigger - group has reached threshold
        assert!(detector.should_trigger(&ip, &index));
    }

    #[test]
    fn test_should_not_trigger_below_threshold() {
        let index = create_test_index_ja4("small_fp", 2);
        let detector = SharedFingerprintDetector::new(3);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should not trigger - below threshold
        assert!(!detector.should_trigger(&ip, &index));
    }

    #[test]
    fn test_should_not_trigger_already_processed() {
        let index = create_test_index_ja4("processed_fp", 5);
        let detector = SharedFingerprintDetector::new(3);

        // Process first
        detector.analyze(&index).unwrap();

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should not trigger - already processed
        assert!(!detector.should_trigger(&ip, &index));
    }

    #[test]
    fn test_should_not_trigger_unknown_ip() {
        let index = create_test_index_ja4("known_fp", 3);
        let detector = SharedFingerprintDetector::new(3);

        // IP not in the index
        let ip: IpAddr = "10.10.10.10".parse().unwrap();

        assert!(!detector.should_trigger(&ip, &index));
    }

    // ========================================================================
    // Confidence Calculation Tests
    // ========================================================================

    #[test]
    fn test_confidence_ja4_only() {
        let detector = SharedFingerprintDetector::new(3);
        let confidence = detector.calculate_confidence(FingerprintType::Ja4, 3);

        // Base confidence for JA4
        assert!((confidence - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_confidence_combined_higher() {
        let detector = SharedFingerprintDetector::new(3);

        let ja4_conf = detector.calculate_confidence(FingerprintType::Ja4, 3);
        let combined_conf = detector.calculate_confidence(FingerprintType::Combined, 3);

        // Combined should have higher confidence
        assert!(combined_conf > ja4_conf);
        assert!((combined_conf - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_confidence_increases_with_size() {
        let detector = SharedFingerprintDetector::new(3);

        let conf_3 = detector.calculate_confidence(FingerprintType::Ja4, 3);
        let conf_5 = detector.calculate_confidence(FingerprintType::Ja4, 5);
        let conf_10 = detector.calculate_confidence(FingerprintType::Ja4, 10);

        // Confidence should increase with group size
        assert!(conf_5 > conf_3);
        assert!(conf_10 > conf_5);
    }

    #[test]
    fn test_confidence_capped_at_one() {
        let detector = SharedFingerprintDetector::with_config(3, 0.99, 1000);
        let confidence = detector.calculate_confidence(FingerprintType::Combined, 100);

        // Should be capped at 1.0
        assert!((confidence - 1.0).abs() < 0.001);
    }

    // ========================================================================
    // Trait Implementation Tests
    // ========================================================================

    #[test]
    fn test_detector_name() {
        let detector = SharedFingerprintDetector::new(3);
        assert_eq!(detector.name(), "shared_fingerprint");
    }

    #[test]
    fn test_detector_scan_interval() {
        let detector = SharedFingerprintDetector::with_config(3, 0.9, 7500);
        assert_eq!(detector.scan_interval_ms(), 7500);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_index() {
        let index = FingerprintIndex::new();
        let detector = SharedFingerprintDetector::new(3);

        let updates = detector.analyze(&index).unwrap();
        assert!(updates.is_empty());
    }

    #[test]
    fn test_all_unique_fingerprints() {
        let index = FingerprintIndex::new();

        // Each IP has unique fingerprint
        for i in 0..10 {
            index.update_entity(
                &format!("10.0.0.{}", i),
                Some(&format!("unique_fp_{}", i)),
                None,
            );
        }

        let detector = SharedFingerprintDetector::new(3);
        let updates = detector.analyze(&index).unwrap();

        assert!(updates.is_empty());
    }

    #[test]
    fn test_multiple_groups_different_sizes() {
        let index = FingerprintIndex::new();

        // Large group (5 IPs)
        for i in 0..5 {
            index.update_entity(&format!("192.168.1.{}", i), Some("large_group"), None);
        }

        // Medium group (3 IPs)
        for i in 0..3 {
            index.update_entity(&format!("10.0.0.{}", i), Some("medium_group"), None);
        }

        // Small group (2 IPs) - below threshold
        index.update_entity("172.16.0.1", Some("small_group"), None);
        index.update_entity("172.16.0.2", Some("small_group"), None);

        let detector = SharedFingerprintDetector::new(3);
        let updates = detector.analyze(&index).unwrap();

        // Should detect large and medium, but not small
        assert_eq!(updates.len(), 2);
    }

    #[test]
    fn test_ipv6_addresses() {
        let index = FingerprintIndex::new();

        index.update_entity("2001:db8::1", Some("ipv6_shared"), None);
        index.update_entity("2001:db8::2", Some("ipv6_shared"), None);
        index.update_entity("2001:db8::3", Some("ipv6_shared"), None);

        let detector = SharedFingerprintDetector::new(3);
        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);

        let reason = updates[0].add_correlation_reason.as_ref().unwrap();
        assert!(reason.evidence.contains(&"2001:db8::1".to_string()));
    }

    // ========================================================================
    // Thread Safety Tests
    // ========================================================================

    #[test]
    fn test_concurrent_analysis() {
        use std::sync::Arc;
        use std::thread;

        let index = Arc::new(create_test_index_ja4("concurrent_fp", 5));
        let detector = Arc::new(SharedFingerprintDetector::new(3));

        let mut handles = vec![];

        // Spawn multiple threads analyzing the same index
        for _ in 0..5 {
            let index = Arc::clone(&index);
            let detector = Arc::clone(&detector);

            handles.push(thread::spawn(move || detector.analyze(&index).unwrap()));
        }

        let mut total_updates = 0;
        for handle in handles {
            let updates = handle.join().unwrap();
            total_updates += updates.len();
        }

        // Only one thread should create the campaign
        assert_eq!(total_updates, 1);
        assert_eq!(detector.processed_count(), 1);
    }

    #[test]
    fn test_concurrent_trigger_checks() {
        use std::sync::Arc;
        use std::thread;

        let index = Arc::new(create_test_index_ja4("trigger_concurrent", 5));
        let detector = Arc::new(SharedFingerprintDetector::new(3));

        let mut handles = vec![];

        // Multiple threads checking should_trigger
        for i in 0..5 {
            let index = Arc::clone(&index);
            let detector = Arc::clone(&detector);
            let ip: IpAddr = format!("192.168.1.{}", i + 1).parse().unwrap();

            handles.push(thread::spawn(move || detector.should_trigger(&ip, &index)));
        }

        let mut triggered_count = 0;
        for handle in handles {
            if handle.join().unwrap() {
                triggered_count += 1;
            }
        }

        // All should return true since nothing is processed yet
        assert!(triggered_count > 0);
    }
}
