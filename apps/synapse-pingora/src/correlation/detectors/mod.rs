//! Campaign Detection Strategies
//!
//! This module defines the Detector trait and implements concrete detectors
//! for identifying coordinated attack campaigns.

use crate::correlation::{CampaignUpdate, FingerprintIndex};
use std::net::IpAddr;

/// Result type for detector operations
pub type DetectorResult<T> = Result<T, DetectorError>;

/// Errors that can occur during detection
#[derive(Debug, Clone)]
pub enum DetectorError {
    /// Index not available or corrupted
    IndexUnavailable(String),
    /// Detection logic failure
    DetectionFailed(String),
    /// Rate limited to prevent CPU exhaustion
    RateLimited,
}

impl std::fmt::Display for DetectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectorError::IndexUnavailable(msg) => write!(f, "Index unavailable: {}", msg),
            DetectorError::DetectionFailed(msg) => write!(f, "Detection failed: {}", msg),
            DetectorError::RateLimited => write!(f, "Detection rate limited"),
        }
    }
}

impl std::error::Error for DetectorError {}

/// Trait for campaign detection strategies
///
/// Each detector analyzes the fingerprint index to identify patterns
/// that suggest coordinated attack campaigns.
pub trait Detector: Send + Sync {
    /// Unique identifier for this detector
    fn name(&self) -> &'static str;

    /// Run detection analysis on the current index state
    /// Returns campaign updates to be applied to the store
    fn analyze(&self, index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>>;

    /// Check if a specific IP should trigger immediate analysis
    /// Used for event-driven detection on new requests
    fn should_trigger(&self, ip: &IpAddr, index: &FingerprintIndex) -> bool;

    /// Minimum interval between full scans (milliseconds)
    fn scan_interval_ms(&self) -> u64 {
        5000 // Default: 5 seconds
    }
}

pub mod attack_sequence;
pub mod auth_token;
pub mod behavioral_similarity;
pub mod common;
pub mod graph;
pub mod ja4_rotation;
pub mod network_proximity;
pub mod shared_fingerprint;
pub mod timing_correlation;

pub use attack_sequence::{AttackPayload, AttackSequenceConfig, AttackSequenceDetector};
pub use auth_token::{AuthTokenConfig, AuthTokenDetector, TokenFingerprint};
pub use behavioral_similarity::{BehaviorPattern, BehavioralConfig, BehavioralSimilarityDetector};
pub use common::TimeWindowedIndex;
pub use graph::{GraphConfig, GraphDetector};
pub use ja4_rotation::{Ja4RotationDetector, Ja4RotationStats, RotationConfig};
pub use network_proximity::{NetworkProximityConfig, NetworkProximityDetector};
pub use shared_fingerprint::SharedFingerprintDetector;
pub use timing_correlation::{TimingConfig, TimingCorrelationDetector};
