//! Entity Tracking Module for Per-IP Risk Accumulation
//!
//! This module provides thread-safe entity tracking for synapse-pingora,
//! enabling per-IP risk scoring, decay, and blocking decisions without
//! requiring a roundtrip to the Node.js risk-server.
//!
//! # Phase 2 Module (Feature Migration from risk-server)
//!
//! ## Features
//! - Thread-safe concurrent access via DashMap
//! - Risk accumulation with time-based decay
//! - LRU eviction for memory bounds (max 100K entities)
//! - Rule match history with repeat offender multipliers
//! - Anomaly tracking for behavioral analysis
//!
//! ## Feature Flags
//! - `USE_PINGORA_ENTITIES=true`: Enable Pingora entity tracking
//!
//! ## Dual-Running Mode
//! Both Pingora and risk-server track entities. Headers injected for comparison:
//! - `X-Entity-Risk-Pingora`: Risk score from Pingora
//! - `X-Entity-Risk-Node`: Risk score from risk-server
//! - `X-Entity-Blocked-Pingora`: Block decision from Pingora
//!
//! @see apps/risk-server/src/state.ts (TypeScript reference)
//! @see libsynapse/src/entity.rs (Rust reference)

mod store;

pub use store::{
    // Configuration
    EntityConfig,
    // State types
    EntityState,
    RuleMatchHistory,
    EntitySnapshot,
    EntityMetrics,
    // Manager
    EntityManager,
    // Decision types
    BlockDecision,
    RiskApplication,
};
