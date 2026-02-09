//! Tarpitting Module for Progressive Response Delays
//!
//! Implements slow-drip defense by progressively delaying responses to
//! suspicious actors without blocking them outright.
//!
//! # Phase 3 Module (Feature Migration from risk-server)
//!
//! ## Features
//! - Progressive delay calculation: base × 1.5^(level-1), max 30s
//! - Non-blocking delays using Tokio async sleep
//! - Per-IP state tracking with automatic decay
//! - LRU eviction for memory bounds (max 10K states)
//!
//! ## Feature Flags
//! - `ENABLE_PINGORA_TARPIT=true`: Enable Pingora tarpitting
//!
//! ## Dual-Running Mode
//! Headers injected for comparison:
//! - `X-Tarpit-Delay-Pingora-Ms`: Delay calculated by Pingora
//! - `X-Tarpit-Level-Pingora`: Current tarpit level
//!
//! @see apps/risk-server/src/interrogator/tarpit.ts (TypeScript reference)

mod manager;

pub use manager::{
    // Configuration
    TarpitConfig,
    // Result types
    TarpitDecision,
    // Manager
    TarpitManager,
    // State types
    TarpitState,
    TarpitStats,
};
