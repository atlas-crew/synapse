//! Signal intelligence aggregation for Synapse-Pingora.
//!
//! Provides categorized, time-bucketed signals for security events such as
//! attacks, anomalies, behavior changes, and external intelligence.

pub mod signal_manager;

pub use signal_manager::{
    Signal, SignalCategory, SignalManager, SignalManagerConfig, SignalQueryOptions, SignalSummary,
    TopSignalType,
};
