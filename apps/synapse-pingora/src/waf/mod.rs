//! WAF Rule Engine module.
//!
//! High-performance WAF rule evaluation with regex caching,
//! index-based candidate selection, and SQL/XSS detection.
//!
//! # Features
//!
//! - Rule compilation with pre-compiled regex patterns (~30μs for 237 rules)
//! - Index-based candidate selection for O(1) rule filtering
//! - SQL injection pattern detection
//! - XSS pattern detection
//! - Stateful IP tracking with rate limiting
//! - Credential stuffing detection integration
//!
//! # Architecture
//!
//! - [`Engine`] - Main WAF rule engine
//! - [`WafRule`] - Rule definition with conditions
//! - [`RuleIndex`] - Index for fast rule candidate selection
//! - [`StateStore`] - Per-IP stateful tracking
//!
//! # Example
//!
//! ```ignore
//! use synapse_pingora::waf::{Engine, Request, Action};
//!
//! let mut engine = Engine::empty();
//! engine.load_rules(rules_json)?;
//!
//! let verdict = engine.analyze(&Request {
//!     method: "GET",
//!     path: "/api/users?id=1' OR '1'='1",
//!     ..Default::default()
//! });
//!
//! assert_eq!(verdict.action, Action::Block);
//! ```

mod engine;
mod index;
mod rule;
mod state;
mod synapse;
mod trace;
mod types;

pub use engine::Engine;
pub use index::{
    build_rule_index, get_candidate_rule_indices, method_to_mask, CandidateCache,
    CandidateCacheKey, IndexedRule, RuleIndex, RuleRequirements, UriAnchor, UriAnchorKind,
    UriTransform, METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT, REQ_ARGS,
    REQ_ARG_ENTRIES, REQ_BODY, REQ_JSON, REQ_MULTIPART, REQ_RESPONSE, REQ_RESPONSE_BODY,
};
pub use rule::{boolean_operands, MatchCondition, MatchValue, WafRule};
pub use state::{now_ms, StateStore};
pub use synapse::Synapse;
pub use trace::{TraceEvent, TraceSink, TraceState};
pub use types::{
    repeat_multiplier, Action, AnomalyContribution, AnomalySignal, AnomalySignalType, AnomalyType,
    ArgEntry, BlockingMode, EvalContext, Header, Request, RiskConfig, RiskContribution, Verdict,
};

/// Error type for WAF operations.
#[derive(Debug, Clone)]
pub enum WafError {
    /// Failed to parse rules JSON.
    ParseError(String),
    /// Invalid regex pattern in rules.
    RegexError(String),
}

impl std::fmt::Display for WafError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WafError::ParseError(msg) => write!(f, "parse error: {}", msg),
            WafError::RegexError(msg) => write!(f, "regex error: {}", msg),
        }
    }
}

impl std::error::Error for WafError {}
