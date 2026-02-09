//! Session State Management Module
//!
//! Provides session tracking with 50K LRU capacity and hijacking detection via JA4 fingerprint binding
//! for the synapse-pingora WAF proxy.
//!
//! # Architecture
//!
//! The `SessionManager` coordinates three main data structures:
//! - **sessions**: Primary DashMap storing SessionState by token_hash
//! - **session_by_id**: O(1) lookup from session_id to token_hash
//! - **actor_sessions**: O(1) lookup from actor_id to session_ids
//!
//! # Hijack Detection Strategy
//!
//! When validating a session, the manager checks for potential hijacking:
//! 1. JA4 fingerprint mismatch detection (client fingerprint changed)
//! 2. IP address change detection (optional, for strict mode)
//! 3. Impossible travel detection (future enhancement)
//!
//! # Usage
//!
//! ```rust,ignore
//! use synapse_pingora::session::{SessionManager, SessionConfig, SessionDecision};
//! use std::sync::Arc;
//!
//! // Create manager with custom configuration
//! let config = SessionConfig {
//!     max_sessions: 50_000,
//!     session_ttl_secs: 3600,
//!     ..Default::default()
//! };
//! let manager = Arc::new(SessionManager::new(config));
//!
//! // Validate incoming request
//! let ip = "192.168.1.100".parse().unwrap();
//! let decision = manager.validate_request("token_hash_abc", ip, Some("t13d1516h2_abc123"));
//!
//! match decision {
//!     SessionDecision::Valid => { /* continue processing */ }
//!     SessionDecision::New => { /* new session created */ }
//!     SessionDecision::Suspicious(alert) => { /* potential hijack */ }
//!     SessionDecision::Expired => { /* session expired */ }
//!     SessionDecision::Invalid(reason) => { /* invalid session */ }
//! }
//!
//! // Start background cleanup tasks
//! Arc::clone(&manager).start_background_tasks();
//! ```

mod manager;

pub use manager::{
    HijackAlert, HijackType, SessionConfig, SessionDecision, SessionManager, SessionState,
    SessionStats, SessionStatsSnapshot,
};
