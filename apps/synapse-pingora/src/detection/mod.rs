//! Detection module for attack pattern recognition.
//!
//! This module provides detection engines for identifying attack patterns:
//! - Credential stuffing detection with per-entity auth failure tracking
//! - Distributed attack correlation via fingerprint
//! - Account takeover detection (success after failures)
//! - Low-and-slow pattern detection
//!
//! # Architecture
//!
//! - [`CredentialStuffingDetector`] - Main detection engine with concurrent access
//! - [`StuffingConfig`] - Configuration for detection thresholds
//! - [`StuffingVerdict`] - Detection verdict (allow/suspicious/block)
//!
//! # Example
//!
//! ```ignore
//! use synapse_pingora::detection::{
//!     CredentialStuffingDetector, AuthAttempt, AuthResult, StuffingConfig,
//! };
//!
//! let detector = CredentialStuffingDetector::new(StuffingConfig::default());
//!
//! // Check if this is an auth endpoint
//! if detector.is_auth_endpoint("/api/login") {
//!     // Record the attempt
//!     let attempt = AuthAttempt::new("192.168.1.1", "/api/login", now_ms());
//!     let verdict = detector.record_attempt(&attempt);
//!
//!     // Handle verdict
//!     if verdict.is_block() {
//!         // Block the request
//!     }
//! }
//! ```

mod credential_stuffing;
mod types;

pub use credential_stuffing::{CredentialStuffingDetector, StuffingState, StuffingStats};
pub use types::{
    AuthAttempt, AuthMetrics, AuthResult, DistributedAttack, EntityEndpointKey,
    GlobalVelocityTracker, StuffingConfig, StuffingEvent, StuffingSeverity, StuffingVerdict,
    TakeoverAlert, UsernameTargetedAttack,
};
