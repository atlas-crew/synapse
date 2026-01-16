//! Campaign Correlation Module
//!
//! Provides fingerprint indexing and campaign detection for synapse-pingora.
//! This module enables efficient correlation of network entities based on
//! shared TLS/HTTP fingerprints, allowing detection of coordinated attack
//! campaigns that may originate from different IP addresses.
//!
//! # Architecture
//!
//! The correlation system uses inverted indexes for O(1) lookups:
//! - JA4 fingerprint -> Set of IPs
//! - Combined fingerprint hash (JA4+JA4H) -> Set of IPs
//! - Reverse lookup for cleanup: IP -> fingerprints
//!
//! # Phase 4 Module (Campaign Detection)
//!
//! ## Features
//! - Thread-safe concurrent access via DashMap
//! - O(1) fingerprint-to-IP lookups
//! - Automatic group threshold detection
//! - Memory-efficient reverse index for cleanup
//!
//! ## Related Modules
//! - [`crate::fingerprint`] - JA4/JA4H fingerprint generation
//! - [`crate::entity`] - Per-IP entity tracking with fingerprint storage

pub mod campaign_state;
pub mod fingerprint_index;
pub mod detectors;
pub mod manager;

#[cfg(test)]
mod integration_tests;

pub use campaign_state::{
    Campaign, CampaignError, CampaignStatus, CampaignStore, CampaignStoreStats,
    CampaignUpdate, CorrelationReason, CorrelationType,
};
pub use fingerprint_index::{FingerprintGroup, FingerprintIndex, FingerprintType, IndexStats};
pub use manager::{CampaignManager, ManagerConfig, ManagerStats};
