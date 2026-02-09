//! Payload Profiling subsystem for bandwidth tracking and anomaly detection.
//!
//! Features:
//! - Per-endpoint statistics with sliding windows
//! - Per-entity (IP) bandwidth tracking
//! - Anomaly detection: oversized payloads, bandwidth spikes, exfiltration patterns

pub mod anomaly;
pub mod config;
pub mod endpoint_stats;
pub mod entity_bandwidth;
pub mod manager;

pub use anomaly::{
    PayloadAnomaly, PayloadAnomalyMetadata, PayloadAnomalySeverity, PayloadAnomalyType,
};
pub use config::PayloadConfig;
pub use endpoint_stats::{
    EndpointPayloadStats, EndpointPayloadStatsSnapshot, PayloadWindow, SizeStats,
};
pub use entity_bandwidth::{BandwidthBucket, EntityBandwidth};
pub use manager::{EndpointSortBy, PayloadManager, PayloadSummary};
