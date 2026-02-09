//! Actor State Management Module
//!
//! Provides per-actor state tracking with 100K LRU capacity for the synapse-pingora WAF proxy.
//! Actors represent persistent threat identities that may span multiple IP addresses and sessions.
//!
//! # Architecture
//!
//! The `ActorManager` coordinates three main data structures:
//! - **actors**: Primary DashMap storing ActorState by actor_id
//! - **ip_to_actor**: O(1) lookup from IP address to actor_id
//! - **fingerprint_to_actor**: O(1) lookup from fingerprint to actor_id
//!
//! # Correlation Strategy
//!
//! When processing a request, the manager attempts to correlate the request to an existing actor:
//! 1. Check if the IP is already mapped to an actor
//! 2. Check if the fingerprint is already mapped to an actor
//! 3. If both match different actors, prefer fingerprint (more stable identifier)
//! 4. If no match, create a new actor
//!
//! # Usage
//!
//! ```rust,ignore
//! use synapse_pingora::actor::{ActorManager, ActorConfig};
//! use std::sync::Arc;
//!
//! // Create manager with custom configuration
//! let config = ActorConfig {
//!     max_actors: 100_000,
//!     decay_interval_secs: 900,
//!     ..Default::default()
//! };
//! let manager = Arc::new(ActorManager::new(config));
//!
//! // Get or create actor for request
//! let ip = "192.168.1.100".parse().unwrap();
//! let actor_id = manager.get_or_create_actor(ip, Some("t13d1516h2_abc123"));
//!
//! // Record rule match
//! manager.record_rule_match(&actor_id, "sqli-001", 25.0, "sqli");
//!
//! // Start background tasks
//! Arc::clone(&manager).start_background_tasks();
//! ```

mod manager;

pub use manager::{
    ActorConfig, ActorManager, ActorState, ActorStats, ActorStatsSnapshot, RuleMatch,
};
