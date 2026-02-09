//! Attack Sequence Detector
//!
//! Identifies coordinated attacks where multiple IPs send identical
//! or highly similar attack payloads. Weight: 50 (highest signal).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashSet;

use super::common::TimeWindowedIndex;
use super::{Detector, DetectorResult};
use crate::correlation::{CampaignUpdate, CorrelationReason, CorrelationType, FingerprintIndex};

/// Configuration for attack sequence detection
#[derive(Debug, Clone)]
pub struct AttackSequenceConfig {
    /// Minimum IPs sharing same payload to trigger detection
    pub min_ips: usize,
    /// Time window for attack correlation
    pub window: Duration,
    /// Minimum payload similarity threshold (0.0 to 1.0)
    pub similarity_threshold: f64,
    /// Base confidence multiplier for confidence calculation (0.0 to 1.0)
    pub base_confidence: f64,
    /// Divisor for scaling confidence by IP count
    pub confidence_scale_divisor: f64,
    /// Maximum entries per payload hash (0 = unlimited)
    pub max_entries_per_hash: usize,
}

impl Default for AttackSequenceConfig {
    fn default() -> Self {
        Self {
            min_ips: 2,
            window: Duration::from_secs(300), // 5 minutes
            similarity_threshold: 0.95,
            base_confidence: 0.9,
            confidence_scale_divisor: 10.0,
            max_entries_per_hash: 1000,
        }
    }
}

/// Represents an observed attack payload
#[derive(Debug, Clone)]
pub struct AttackPayload {
    /// Hash of the normalized payload
    pub payload_hash: String,
    /// Attack classification (sqli, xss, path_traversal, etc.)
    pub attack_type: String,
    /// Target path
    pub target_path: String,
    /// When this was observed
    pub timestamp: Instant,
}

/// Detects campaigns based on shared attack payloads
pub struct AttackSequenceDetector {
    config: AttackSequenceConfig,
    /// Payload hash -> IPs (using common TimeWindowedIndex)
    payload_index: TimeWindowedIndex<String, IpAddr>,
    /// Already detected payload groups
    detected: DashSet<String>,
}

impl AttackSequenceDetector {
    pub fn new(config: AttackSequenceConfig) -> Self {
        let payload_index = TimeWindowedIndex::new(config.window, config.max_entries_per_hash);
        Self {
            config,
            payload_index,
            detected: DashSet::new(),
        }
    }

    /// Record an attack payload observation
    pub fn record_attack(&self, ip: IpAddr, payload: AttackPayload) {
        self.payload_index
            .insert_with_timestamp(payload.payload_hash, ip, payload.timestamp);
    }

    /// Get IPs sharing a specific payload
    pub fn get_ips_for_payload(&self, payload_hash: &str) -> Vec<IpAddr> {
        self.payload_index.get_unique(&payload_hash.to_string())
    }

    /// Get groups of IPs sharing payloads above threshold
    fn get_correlated_groups(&self) -> Vec<(String, Vec<IpAddr>)> {
        self.payload_index
            .get_groups_with_min_unique_count(self.config.min_ips)
            .into_iter()
            .filter(|(hash, _)| !self.detected.contains(hash))
            .collect()
    }
}

impl Detector for AttackSequenceDetector {
    fn name(&self) -> &'static str {
        "attack_sequence"
    }

    fn analyze(&self, _index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>> {
        let groups = self.get_correlated_groups();
        let mut updates = Vec::new();

        for (payload_hash, ips) in groups {
            let confidence = (ips.len() as f64 / self.config.confidence_scale_divisor).min(1.0)
                * self.config.base_confidence;

            updates.push(CampaignUpdate {
                campaign_id: Some(format!(
                    "attack-seq-{}",
                    &payload_hash[..8.min(payload_hash.len())]
                )),
                status: None,
                confidence: Some(confidence),
                attack_types: Some(vec!["attack_sequence".to_string()]),
                add_member_ips: Some(ips.iter().map(|ip| ip.to_string()).collect()),
                add_correlation_reason: Some(CorrelationReason::new(
                    CorrelationType::AttackSequence,
                    confidence,
                    format!("{} IPs sharing identical attack payload", ips.len()),
                    ips.iter().map(|ip| ip.to_string()).collect(),
                )),
                ..Default::default()
            });

            // Mark as detected
            self.detected.insert(payload_hash);
        }

        Ok(updates)
    }

    fn should_trigger(&self, ip: &IpAddr, _index: &FingerprintIndex) -> bool {
        // Check if this IP is part of any payload group that's close to threshold
        self.payload_index.any_key_has_value_with_min_count(
            |entry_ip| entry_ip == ip,
            self.config.min_ips.saturating_sub(1).max(1),
        )
    }

    fn scan_interval_ms(&self) -> u64 {
        3000
    } // 3 seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AttackSequenceConfig::default();
        assert_eq!(config.min_ips, 2);
        assert_eq!(config.window, Duration::from_secs(300));
    }

    #[test]
    fn test_record_attack() {
        let detector = AttackSequenceDetector::new(AttackSequenceConfig::default());
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        detector.record_attack(
            ip,
            AttackPayload {
                payload_hash: "hash123".to_string(),
                attack_type: "sqli".to_string(),
                target_path: "/api/login".to_string(),
                timestamp: Instant::now(),
            },
        );

        let ips = detector.get_ips_for_payload("hash123");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], ip);
    }

    #[test]
    fn test_detection_with_multiple_ips() {
        let detector = AttackSequenceDetector::new(AttackSequenceConfig::default());

        for i in 1..=3 {
            let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
            detector.record_attack(
                ip,
                AttackPayload {
                    payload_hash: "shared_payload".to_string(),
                    attack_type: "sqli".to_string(),
                    target_path: "/api".to_string(),
                    timestamp: Instant::now(),
                },
            );
        }

        let index = FingerprintIndex::new();
        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);
        assert!(updates[0].add_member_ips.as_ref().unwrap().len() == 3);
    }

    #[test]
    fn test_no_detection_below_threshold() {
        let detector = AttackSequenceDetector::new(AttackSequenceConfig {
            min_ips: 3,
            ..Default::default()
        });

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        detector.record_attack(
            ip,
            AttackPayload {
                payload_hash: "hash".to_string(),
                attack_type: "xss".to_string(),
                target_path: "/".to_string(),
                timestamp: Instant::now(),
            },
        );

        let index = FingerprintIndex::new();
        let updates = detector.analyze(&index).unwrap();
        assert!(updates.is_empty());
    }

    #[test]
    fn test_should_trigger() {
        let detector = AttackSequenceDetector::new(AttackSequenceConfig::default());
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        detector.record_attack(
            ip1,
            AttackPayload {
                payload_hash: "test".to_string(),
                attack_type: "sqli".to_string(),
                target_path: "/".to_string(),
                timestamp: Instant::now(),
            },
        );

        // Should trigger because one more IP would reach threshold
        let index = FingerprintIndex::new();
        assert!(detector.should_trigger(&ip1, &index));
    }
}
