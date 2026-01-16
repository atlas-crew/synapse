//! Interrogator System - Progressive Challenge Escalation
//!
//! Implements a multi-level challenge system for suspicious actors:
//! 1. Cookie Challenge - Silent tracking cookie
//! 2. JS PoW Challenge - Proof-of-work computation
//! 3. CAPTCHA Challenge - Human verification (stub)
//! 4. Tarpit - Progressive delays (already implemented)
//! 5. Block - Hard block with custom page
//!
//! # Architecture
//!
//! The system uses a progressive escalation model where each failed challenge
//! or continued suspicious behavior moves the actor to a harder challenge level.
//! The ProgressionManager orchestrates the challenge selection based on actor
//! history and current risk score.
//!
//! ```text
//! +----------+     +-------------+     +---------+     +--------+     +-------+
//! | Cookie   | --> | JS PoW      | --> | CAPTCHA | --> | Tarpit | --> | Block |
//! | (silent) |     | (compute)   |     | (human) |     | (slow) |     | (hard)|
//! +----------+     +-------------+     +---------+     +--------+     +-------+
//!     Level 1         Level 2          Level 3        Level 4       Level 5
//! ```
//!
//! # Feature Flags
//!
//! - `ENABLE_COOKIE_CHALLENGE=true`: Enable cookie tracking
//! - `ENABLE_JS_CHALLENGE=true`: Enable JavaScript PoW challenges
//! - `ENABLE_CAPTCHA=false`: CAPTCHA is stubbed (future work)
//! - `ENABLE_TARPIT=true`: Enable progressive delays
//!
//! # Dual-Running Mode
//!
//! Headers injected for observability:
//! - `X-Challenge-Level`: Current challenge level for actor
//! - `X-Challenge-Type`: Type of challenge issued (cookie/js/captcha/tarpit/block)

pub mod cookie_manager;
pub mod js_challenge_manager;
pub mod progression_manager;

pub use cookie_manager::{CookieChallenge, CookieConfig, CookieError, CookieManager, CookieStats};
pub use js_challenge_manager::{JsChallenge, JsChallengeConfig, JsChallengeManager, JsChallengeStats};
pub use progression_manager::{
    ActorChallengeState, ChallengeLevel, ProgressionConfig, ProgressionManager, ProgressionStats,
};

/// Response to present to the actor
#[derive(Debug, Clone)]
pub enum ChallengeResponse {
    /// No challenge needed, allow request
    Allow,
    /// Set a tracking cookie
    Cookie {
        name: String,
        value: String,
        max_age: u64,
        http_only: bool,
        secure: bool,
    },
    /// Present JavaScript proof-of-work challenge
    JsChallenge {
        html: String,
        expected_solution: String,
        expires_at: u64,
    },
    /// Present CAPTCHA (stub - returns HTML placeholder)
    Captcha { html: String, session_id: String },
    /// Apply tarpit delay
    Tarpit { delay_ms: u64 },
    /// Block with custom page
    Block { html: String, status_code: u16 },
}

/// Result of validating a challenge response
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Invalid(String),
    Expired,
    NotFound,
}

/// Trait for challenge implementations
pub trait Interrogator: Send + Sync {
    /// Name of this interrogator
    fn name(&self) -> &'static str;

    /// Challenge level (1-5, lower = softer)
    fn challenge_level(&self) -> u8;

    /// Generate a challenge for the actor
    fn generate_challenge(&self, actor_id: &str) -> ChallengeResponse;

    /// Validate a challenge response
    fn validate_response(&self, actor_id: &str, response: &str) -> ValidationResult;

    /// Check if actor should escalate to next level
    fn should_escalate(&self, actor_id: &str) -> bool;
}
