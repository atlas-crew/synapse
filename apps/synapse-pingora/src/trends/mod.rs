//! Trends subsystem for signal tracking and anomaly detection.
//!
//! This module provides time-series signal storage and analysis for detecting
//! behavioral anomalies such as fingerprint changes, session sharing, velocity
//! spikes, and impossible travel patterns.
//!
//! # Architecture
//!
//! - [`config`] - Configuration for trends subsystem
//! - [`types`] - Signal, anomaly, and correlation type definitions
//! - [`time_store`] - Time-bucketed signal storage with LRU eviction
//! - [`signal_extractor`] - Extract signals from HTTP requests
//! - [`anomaly_detector`] - Detect behavioral anomalies
//! - [`correlation`] - Find correlations between signals/entities
//! - [`manager`] - High-level coordinator
//!
//! # Impossible Travel Detection
//!
//! The trends manager includes integrated impossible travel detection via
//! [`TrendsManager::record_login`]. This detects account takeover attempts
//! by tracking user logins across geographic locations and flagging when
//! sequential logins would require unrealistic travel speeds (>1000 km/h).
//!
//! ```ignore
//! // Record a login and check for impossible travel
//! let alert_generated = trends_manager.record_login(
//!     "user@example.com",
//!     chrono::Utc::now().timestamp_millis() as u64,
//!     "203.0.113.50",
//!     40.7128, -74.0060,  // NYC
//!     "United States", "US",
//!     Some("New York"),
//!     10,  // accuracy km
//!     Some("device-fingerprint-123"),
//! );
//! ```

mod anomaly_detector;
mod config;
mod correlation;
mod manager;
mod signal_extractor;
mod time_store;
mod types;

pub use anomaly_detector::{AnomalyDetector, AnomalyDetectorConfig};
pub use config::TrendsConfig;
pub use correlation::{Correlation, CorrelationEngine, CorrelationMetadata, CorrelationType};
pub use manager::{
    TrendsManager, TrendsManagerDependencies, TrendsManagerStats, TrendsReason, TrendsStats,
};
pub use signal_extractor::SignalExtractor;
pub use time_store::{SignalBucket, TimeStore, TimeStoreStats};
pub use types::{
    Anomaly, AnomalyMetadata, AnomalyQueryOptions, AnomalySeverity, AnomalyType, AuthTokenMetadata,
    BehavioralMetadata, BucketSummary, CategorySummary, DeviceMetadata, NetworkMetadata, Signal,
    SignalCategory, SignalMetadata, SignalTrend, SignalType, TimeRange, TopSignalType,
    TrendHistogramBucket, TrendQueryOptions, TrendsSummary,
};
