//! Progression Manager - Challenge Escalation Orchestrator
//!
//! Orchestrates the progressive challenge escalation system. Based on actor
//! behavior, risk score, and challenge history, selects the appropriate
//! challenge level and manages escalation/de-escalation.
//!
//! # Challenge Levels
//!
//! 1. **Cookie (Level 1)**: Silent tracking, no user impact
//! 2. **JS PoW (Level 2)**: Computational challenge, ~1-5s delay
//! 3. **CAPTCHA (Level 3)**: Human verification, requires interaction
//! 4. **Tarpit (Level 4)**: Progressive delays, degrades experience
//! 5. **Block (Level 5)**: Hard block with custom page
//!
//! # Risk Score Mapping
//!
//! - 0.0-0.2: No challenge (Allow)
//! - 0.2-0.4: Cookie challenge
//! - 0.4-0.6: JS PoW challenge
//! - 0.6-0.8: CAPTCHA or Tarpit
//! - 0.8-1.0: Block
//!
//! # Escalation Rules
//!
//! - Failed challenge → increment failure count
//! - 3+ failures at level → escalate to next level
//! - 10+ total failures → skip to block
//! - 1 hour without incident → de-escalate one level
//!
//! # Integration
//!
//! The ProgressionManager integrates with:
//! - CookieManager: For level 1 challenges
//! - JsChallengeManager: For level 2 challenges
//! - TarpitManager: For level 4 challenges (from src/tarpit/)

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

use super::{
    CaptchaManager, ChallengeResponse, CookieManager, JsChallengeManager, ValidationResult,
};
use crate::tarpit::TarpitManager;

/// Challenge levels for progressive escalation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ChallengeLevel {
    None = 0,
    Cookie = 1,
    JsChallenge = 2,
    Captcha = 3,
    Tarpit = 4,
    Block = 5,
}

impl ChallengeLevel {
    /// Get level from numeric value
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => ChallengeLevel::None,
            1 => ChallengeLevel::Cookie,
            2 => ChallengeLevel::JsChallenge,
            3 => ChallengeLevel::Captcha,
            4 => ChallengeLevel::Tarpit,
            _ => ChallengeLevel::Block,
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            ChallengeLevel::None => "none",
            ChallengeLevel::Cookie => "cookie",
            ChallengeLevel::JsChallenge => "js_challenge",
            ChallengeLevel::Captcha => "captcha",
            ChallengeLevel::Tarpit => "tarpit",
            ChallengeLevel::Block => "block",
        }
    }
}

impl std::fmt::Display for ChallengeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Per-actor challenge state
#[derive(Debug, Clone)]
pub struct ActorChallengeState {
    /// Actor identifier
    pub actor_id: String,
    /// Current challenge level
    pub current_level: ChallengeLevel,
    /// Failures at current level
    pub failures_at_level: u32,
    /// Last challenge timestamp (ms since epoch)
    pub last_challenge_time: u64,
    /// Total failures across all levels
    pub total_failures: u32,
    /// History of escalations: (level, timestamp)
    pub escalation_history: Vec<(ChallengeLevel, u64)>,
    /// Last successful challenge completion (ms since epoch)
    pub last_success_time: Option<u64>,
}

impl ActorChallengeState {
    /// Create a new actor state
    pub fn new(actor_id: String) -> Self {
        Self {
            actor_id,
            current_level: ChallengeLevel::None,
            failures_at_level: 0,
            last_challenge_time: 0,
            total_failures: 0,
            escalation_history: Vec::new(),
            last_success_time: None,
        }
    }
}

/// Configuration for progression manager
#[derive(Debug, Clone)]
pub struct ProgressionConfig {
    /// Failures before escalating to next level (default: 3)
    pub failures_before_escalate: u32,
    /// Cooldown between escalations in seconds (default: 60)
    pub escalation_cooldown_secs: u64,
    /// Time without incident before de-escalating in seconds (default: 3600 = 1 hour)
    pub auto_de_escalate_secs: u64,
    /// Total failures that skip directly to block (default: 10)
    pub skip_to_block_threshold: u32,
    /// Enable cookie challenges (default: true)
    pub enable_cookie: bool,
    /// Enable JS PoW challenges (default: true)
    pub enable_js_challenge: bool,
    /// Enable CAPTCHA challenges (default: false - stub)
    pub enable_captcha: bool,
    /// Enable tarpit challenges (default: true)
    pub enable_tarpit: bool,
    /// Risk score threshold for cookie (default: 0.2)
    pub risk_threshold_cookie: f64,
    /// Risk score threshold for JS challenge (default: 0.4)
    pub risk_threshold_js: f64,
    /// Risk score threshold for CAPTCHA/tarpit (default: 0.6)
    pub risk_threshold_captcha: f64,
    /// Risk score threshold for block (default: 0.8)
    pub risk_threshold_block: f64,
    /// Block page HTML template
    pub block_page_html: String,
    /// Block status code (default: 403)
    pub block_status_code: u16,
    /// CAPTCHA page HTML template (stub)
    pub captcha_page_html: String,
    /// Background cleanup interval in seconds (default: 300)
    pub cleanup_interval_secs: u64,
    /// Max states to track (default: 100_000)
    pub max_states: usize,
    /// Max escalation history entries per actor (default: 100)
    /// Prevents unbounded memory growth from malicious actors
    pub max_escalation_history: usize,
}

impl Default for ProgressionConfig {
    fn default() -> Self {
        Self {
            failures_before_escalate: 3,
            escalation_cooldown_secs: 60,
            auto_de_escalate_secs: 3600, // 1 hour
            skip_to_block_threshold: 10,
            enable_cookie: true,
            enable_js_challenge: true,
            enable_captcha: false, // Stub
            enable_tarpit: true,
            risk_threshold_cookie: 0.2,
            risk_threshold_js: 0.4,
            risk_threshold_captcha: 0.6,
            risk_threshold_block: 0.8,
            block_page_html: DEFAULT_BLOCK_PAGE.to_string(),
            block_status_code: 403,
            captcha_page_html: DEFAULT_CAPTCHA_PAGE.to_string(),
            cleanup_interval_secs: 300,
            max_states: 100_000,
            max_escalation_history: 100, // Prevents memory exhaustion
        }
    }
}

/// Statistics for progression manager
#[derive(Debug, Default)]
pub struct ProgressionStats {
    /// Total actors tracked
    pub actors_tracked: AtomicU64,
    /// Total escalations
    pub escalations: AtomicU64,
    /// Total de-escalations
    pub de_escalations: AtomicU64,
    /// Direct blocks (skipped escalation)
    pub direct_blocks: AtomicU64,
    /// Total challenges issued
    pub challenges_issued: AtomicU64,
    /// Total challenge successes
    pub successes: AtomicU64,
    /// Total challenge failures
    pub failures: AtomicU64,
}

impl ProgressionStats {
    /// Create a snapshot of current stats
    pub fn snapshot(&self) -> ProgressionStatsSnapshot {
        ProgressionStatsSnapshot {
            actors_tracked: self.actors_tracked.load(Ordering::Relaxed),
            escalations: self.escalations.load(Ordering::Relaxed),
            de_escalations: self.de_escalations.load(Ordering::Relaxed),
            direct_blocks: self.direct_blocks.load(Ordering::Relaxed),
            challenges_issued: self.challenges_issued.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of progression stats for serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProgressionStatsSnapshot {
    pub actors_tracked: u64,
    pub escalations: u64,
    pub de_escalations: u64,
    pub direct_blocks: u64,
    pub challenges_issued: u64,
    pub successes: u64,
    pub failures: u64,
}

/// Progressive challenge escalation manager
pub struct ProgressionManager {
    /// Per-actor challenge states
    actor_states: DashMap<String, ActorChallengeState>,
    /// Cookie challenge manager
    cookie_manager: Arc<CookieManager>,
    /// JS challenge manager
    js_manager: Arc<JsChallengeManager>,
    /// CAPTCHA challenge manager
    captcha_manager: Arc<CaptchaManager>,
    /// Tarpit manager
    tarpit_manager: Arc<TarpitManager>,
    /// Configuration
    config: ProgressionConfig,
    /// Statistics
    stats: ProgressionStats,
    /// Shutdown signal for background tasks
    shutdown: Arc<Notify>,
    /// Shutdown flag to check if shutdown was requested
    shutdown_flag: Arc<AtomicBool>,
}

impl ProgressionManager {
    /// Create a new progression manager
    pub fn new(
        cookie_manager: Arc<CookieManager>,
        js_manager: Arc<JsChallengeManager>,
        captcha_manager: Arc<CaptchaManager>,
        tarpit_manager: Arc<TarpitManager>,
        config: ProgressionConfig,
    ) -> Self {
        Self {
            actor_states: DashMap::with_capacity(config.max_states.min(10_000)),
            cookie_manager,
            js_manager,
            captcha_manager,
            tarpit_manager,
            config,
            stats: ProgressionStats::default(),
            shutdown: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get configuration
    pub fn config(&self) -> &ProgressionConfig {
        &self.config
    }

    /// Push an entry to escalation history with bounds checking.
    /// If at capacity, removes oldest entry before adding new one.
    /// This prevents memory exhaustion from malicious actors.
    fn push_escalation_history(
        &self,
        state: &mut ActorChallengeState,
        level: ChallengeLevel,
        timestamp: u64,
    ) {
        // Remove oldest if at capacity
        if state.escalation_history.len() >= self.config.max_escalation_history {
            state.escalation_history.remove(0);
        }
        state.escalation_history.push((level, timestamp));
    }

    /// Get appropriate challenge for actor based on risk score and history
    pub fn get_challenge(&self, actor_id: &str, risk_score: f64) -> ChallengeResponse {
        let now = now_ms();

        // Get or create actor state
        let mut state = self.get_or_create_state(actor_id);

        // Check for auto de-escalation
        self.check_auto_de_escalate(&mut state, now);

        // Determine effective level based on risk score and current state
        let effective_level = self.determine_effective_level(&state, risk_score);

        // Update state
        state.last_challenge_time = now;
        state.current_level = effective_level;

        // Store updated state
        self.actor_states.insert(actor_id.to_string(), state);

        self.stats.challenges_issued.fetch_add(1, Ordering::Relaxed);

        // Generate challenge for level
        self.get_challenge_for_level(actor_id, effective_level)
    }

    /// Record a failed challenge attempt
    pub fn record_failure(&self, actor_id: &str) {
        let now = now_ms();

        let mut state = self.get_or_create_state(actor_id);
        state.failures_at_level += 1;
        state.total_failures += 1;
        state.last_challenge_time = now;

        self.stats.failures.fetch_add(1, Ordering::Relaxed);

        // Check if should escalate
        if state.total_failures >= self.config.skip_to_block_threshold {
            // Skip directly to block
            if state.current_level != ChallengeLevel::Block {
                self.push_escalation_history(&mut state, ChallengeLevel::Block, now);
                state.current_level = ChallengeLevel::Block;
                state.failures_at_level = 0;
                self.stats.direct_blocks.fetch_add(1, Ordering::Relaxed);
            }
        } else if state.failures_at_level >= self.config.failures_before_escalate {
            // Normal escalation
            let next_level = self.next_level(state.current_level);
            if next_level != state.current_level {
                self.push_escalation_history(&mut state, next_level, now);
                state.current_level = next_level;
                state.failures_at_level = 0;
                self.stats.escalations.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.actor_states.insert(actor_id.to_string(), state);
    }

    /// Record a successful challenge completion
    pub fn record_success(&self, actor_id: &str) {
        let now = now_ms();

        if let Some(mut entry) = self.actor_states.get_mut(actor_id) {
            entry.failures_at_level = 0;
            entry.last_success_time = Some(now);
            self.stats.successes.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Manually escalate an actor
    pub fn escalate(&self, actor_id: &str) -> ChallengeLevel {
        let now = now_ms();

        let mut state = self.get_or_create_state(actor_id);
        let next_level = self.next_level(state.current_level);

        if next_level != state.current_level {
            self.push_escalation_history(&mut state, next_level, now);
            state.current_level = next_level;
            state.failures_at_level = 0;
            self.stats.escalations.fetch_add(1, Ordering::Relaxed);
        }

        let level = state.current_level;
        self.actor_states.insert(actor_id.to_string(), state);
        level
    }

    /// Manually de-escalate an actor
    pub fn de_escalate(&self, actor_id: &str) -> ChallengeLevel {
        let now = now_ms();

        let mut state = self.get_or_create_state(actor_id);
        let prev_level = self.prev_level(state.current_level);

        if prev_level != state.current_level {
            self.push_escalation_history(&mut state, prev_level, now);
            state.current_level = prev_level;
            state.failures_at_level = 0;
            self.stats.de_escalations.fetch_add(1, Ordering::Relaxed);
        }

        let level = state.current_level;
        self.actor_states.insert(actor_id.to_string(), state);
        level
    }

    /// Reset actor to no challenge
    pub fn reset(&self, actor_id: &str) {
        self.actor_states.remove(actor_id);
    }

    /// Get current level for actor
    pub fn get_level(&self, actor_id: &str) -> ChallengeLevel {
        self.actor_states
            .get(actor_id)
            .map(|s| s.current_level)
            .unwrap_or(ChallengeLevel::None)
    }

    /// Get actor state
    pub fn get_actor_state(&self, actor_id: &str) -> Option<ActorChallengeState> {
        self.actor_states.get(actor_id).map(|s| s.clone())
    }

    /// List actors at a specific challenge level
    pub fn list_actors_at_level(&self, level: ChallengeLevel) -> Vec<ActorChallengeState> {
        self.actor_states
            .iter()
            .filter(|e| e.value().current_level == level)
            .map(|e| e.value().clone())
            .collect()
    }

    /// List all tracked actors
    pub fn list_all_actors(&self) -> Vec<ActorChallengeState> {
        self.actor_states
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    /// Start background tasks (de-escalation, cleanup)
    ///
    /// Spawns a background task that periodically runs maintenance.
    /// The task will exit cleanly when `shutdown()` is called.
    pub fn start_background_tasks(self: Arc<Self>) {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);
        let shutdown = self.shutdown.clone();
        let shutdown_flag = self.shutdown_flag.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Check shutdown flag before running maintenance
                        if shutdown_flag.load(Ordering::Relaxed) {
                            log::info!("Progression manager background tasks shutting down (flag)");
                            break;
                        }
                        manager.run_maintenance();
                    }
                    _ = shutdown.notified() => {
                        log::info!("Progression manager background tasks shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Signal shutdown for background tasks.
    ///
    /// This method signals the background maintenance task to stop.
    /// The task will exit after completing any in-progress work.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
    }

    /// Run maintenance tasks (de-escalation, cleanup)
    pub fn run_maintenance(&self) {
        let now = now_ms();

        // Auto de-escalate eligible actors
        let mut to_de_escalate = Vec::new();
        for entry in self.actor_states.iter() {
            let state = entry.value();
            let idle_time = now.saturating_sub(state.last_challenge_time);
            let de_escalate_threshold_ms = self.config.auto_de_escalate_secs * 1000;

            if idle_time > de_escalate_threshold_ms && state.current_level > ChallengeLevel::None {
                to_de_escalate.push(entry.key().clone());
            }
        }

        for actor_id in to_de_escalate {
            self.de_escalate(&actor_id);
        }

        // Cleanup old states if over capacity
        if self.actor_states.len() > self.config.max_states {
            // Find oldest states
            let mut actors: Vec<_> = self
                .actor_states
                .iter()
                .map(|e| (e.key().clone(), e.value().last_challenge_time))
                .collect();
            actors.sort_by_key(|(_, time)| *time);

            // Remove oldest 10%
            let to_remove = self.config.max_states / 10;
            for (actor_id, _) in actors.into_iter().take(to_remove) {
                self.actor_states.remove(&actor_id);
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &ProgressionStats {
        &self.stats
    }

    /// Get number of tracked actors
    pub fn len(&self) -> usize {
        self.actor_states.len()
    }

    /// Get cookie challenge name for validation.
    pub fn cookie_name(&self) -> &str {
        self.cookie_manager.config().cookie_name.as_str()
    }

    /// Check if no actors are tracked
    pub fn is_empty(&self) -> bool {
        self.actor_states.is_empty()
    }

    /// Clear all state
    pub fn clear(&self) {
        self.actor_states.clear();
    }

    /// Validate a challenge response for an actor
    pub fn validate_challenge(&self, actor_id: &str, response: &str) -> ValidationResult {
        let level = self.get_level(actor_id);

        let result = match level {
            ChallengeLevel::Cookie => self.cookie_manager.validate_cookie(actor_id, response),
            ChallengeLevel::JsChallenge => self.js_manager.validate_pow(actor_id, response),
            ChallengeLevel::Captcha => self.captcha_manager.validate_response(actor_id, response),
            _ => ValidationResult::NotFound,
        };

        match &result {
            ValidationResult::Valid => self.record_success(actor_id),
            ValidationResult::Invalid(_) | ValidationResult::Expired => {
                self.record_failure(actor_id)
            }
            ValidationResult::NotFound => {}
        }

        result
    }

    // --- Private helpers ---

    /// Get or create actor state atomically.
    ///
    /// Uses DashMap's entry API to avoid race conditions between checking
    /// for existence and creating a new state.
    fn get_or_create_state(&self, actor_id: &str) -> ActorChallengeState {
        // Use entry API for atomic get-or-insert to prevent race conditions
        let entry = self.actor_states.entry(actor_id.to_string());
        match entry {
            dashmap::mapref::entry::Entry::Occupied(occupied) => occupied.get().clone(),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                self.stats.actors_tracked.fetch_add(1, Ordering::Relaxed);
                let state = ActorChallengeState::new(actor_id.to_string());
                vacant.insert(state.clone());
                state
            }
        }
    }

    /// Check and apply auto de-escalation
    fn check_auto_de_escalate(&self, state: &mut ActorChallengeState, now: u64) {
        if state.current_level == ChallengeLevel::None {
            return;
        }

        let idle_time = now.saturating_sub(state.last_challenge_time);
        let de_escalate_threshold_ms = self.config.auto_de_escalate_secs * 1000;

        if idle_time > de_escalate_threshold_ms {
            let prev_level = self.prev_level(state.current_level);
            if prev_level != state.current_level {
                self.push_escalation_history(state, prev_level, now);
                state.current_level = prev_level;
                state.failures_at_level = 0;
                self.stats.de_escalations.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Determine effective level based on state and risk score
    fn determine_effective_level(
        &self,
        state: &ActorChallengeState,
        risk_score: f64,
    ) -> ChallengeLevel {
        // Determine level from risk score
        let risk_level = self.determine_initial_level(risk_score);

        // Use the higher of current level or risk-based level
        // (actors can be escalated above their risk score due to behavior)
        std::cmp::max(state.current_level, risk_level)
    }

    /// Determine initial level from risk score
    fn determine_initial_level(&self, risk_score: f64) -> ChallengeLevel {
        if risk_score >= self.config.risk_threshold_block {
            ChallengeLevel::Block
        } else if risk_score >= self.config.risk_threshold_captcha {
            if self.config.enable_captcha {
                ChallengeLevel::Captcha
            } else if self.config.enable_tarpit {
                ChallengeLevel::Tarpit
            } else {
                ChallengeLevel::JsChallenge
            }
        } else if risk_score >= self.config.risk_threshold_js {
            if self.config.enable_js_challenge {
                ChallengeLevel::JsChallenge
            } else if self.config.enable_cookie {
                ChallengeLevel::Cookie
            } else {
                ChallengeLevel::None
            }
        } else if risk_score >= self.config.risk_threshold_cookie {
            if self.config.enable_cookie {
                ChallengeLevel::Cookie
            } else {
                ChallengeLevel::None
            }
        } else {
            ChallengeLevel::None
        }
    }

    /// Get next level (escalate)
    fn next_level(&self, current: ChallengeLevel) -> ChallengeLevel {
        match current {
            ChallengeLevel::None => {
                if self.config.enable_cookie {
                    ChallengeLevel::Cookie
                } else if self.config.enable_js_challenge {
                    ChallengeLevel::JsChallenge
                } else if self.config.enable_captcha {
                    ChallengeLevel::Captcha
                } else if self.config.enable_tarpit {
                    ChallengeLevel::Tarpit
                } else {
                    ChallengeLevel::Block
                }
            }
            ChallengeLevel::Cookie => {
                if self.config.enable_js_challenge {
                    ChallengeLevel::JsChallenge
                } else if self.config.enable_captcha {
                    ChallengeLevel::Captcha
                } else if self.config.enable_tarpit {
                    ChallengeLevel::Tarpit
                } else {
                    ChallengeLevel::Block
                }
            }
            ChallengeLevel::JsChallenge => {
                if self.config.enable_captcha {
                    ChallengeLevel::Captcha
                } else if self.config.enable_tarpit {
                    ChallengeLevel::Tarpit
                } else {
                    ChallengeLevel::Block
                }
            }
            ChallengeLevel::Captcha => {
                if self.config.enable_tarpit {
                    ChallengeLevel::Tarpit
                } else {
                    ChallengeLevel::Block
                }
            }
            ChallengeLevel::Tarpit => ChallengeLevel::Block,
            ChallengeLevel::Block => ChallengeLevel::Block, // Can't escalate beyond block
        }
    }

    /// Get previous level (de-escalate)
    fn prev_level(&self, current: ChallengeLevel) -> ChallengeLevel {
        match current {
            ChallengeLevel::Block => {
                if self.config.enable_tarpit {
                    ChallengeLevel::Tarpit
                } else if self.config.enable_captcha {
                    ChallengeLevel::Captcha
                } else if self.config.enable_js_challenge {
                    ChallengeLevel::JsChallenge
                } else if self.config.enable_cookie {
                    ChallengeLevel::Cookie
                } else {
                    ChallengeLevel::None
                }
            }
            ChallengeLevel::Tarpit => {
                if self.config.enable_captcha {
                    ChallengeLevel::Captcha
                } else if self.config.enable_js_challenge {
                    ChallengeLevel::JsChallenge
                } else if self.config.enable_cookie {
                    ChallengeLevel::Cookie
                } else {
                    ChallengeLevel::None
                }
            }
            ChallengeLevel::Captcha => {
                if self.config.enable_js_challenge {
                    ChallengeLevel::JsChallenge
                } else if self.config.enable_cookie {
                    ChallengeLevel::Cookie
                } else {
                    ChallengeLevel::None
                }
            }
            ChallengeLevel::JsChallenge => {
                if self.config.enable_cookie {
                    ChallengeLevel::Cookie
                } else {
                    ChallengeLevel::None
                }
            }
            ChallengeLevel::Cookie => ChallengeLevel::None,
            ChallengeLevel::None => ChallengeLevel::None, // Can't de-escalate below none
        }
    }

    /// Get challenge response for a level
    fn get_challenge_for_level(&self, actor_id: &str, level: ChallengeLevel) -> ChallengeResponse {
        match level {
            ChallengeLevel::None => ChallengeResponse::Allow,

            ChallengeLevel::Cookie => {
                let challenge = self.cookie_manager.generate_tracking_cookie(actor_id);
                ChallengeResponse::Cookie {
                    name: challenge.cookie_name,
                    value: challenge.cookie_value,
                    max_age: self.cookie_manager.config().cookie_max_age_secs,
                    http_only: self.cookie_manager.config().http_only,
                    secure: self.cookie_manager.config().secure_only,
                }
            }

            ChallengeLevel::JsChallenge => {
                let challenge = self.js_manager.generate_pow_challenge(actor_id);
                let html = self.js_manager.generate_challenge_page(&challenge);
                ChallengeResponse::JsChallenge {
                    html,
                    expected_solution: challenge.expected_hash_prefix,
                    expires_at: challenge.expires_at,
                }
            }

            ChallengeLevel::Captcha => {
                let challenge = self.captcha_manager.issue_challenge(actor_id);
                ChallengeResponse::Captcha {
                    html: challenge.html,
                    session_id: challenge.session_id,
                }
            }

            ChallengeLevel::Tarpit => {
                let decision = self.tarpit_manager.tarpit(actor_id);
                ChallengeResponse::Tarpit {
                    delay_ms: decision.delay_ms,
                }
            }

            ChallengeLevel::Block => ChallengeResponse::Block {
                html: self.config.block_page_html.clone(),
                status_code: self.config.block_status_code,
            },
        }
    }
}

/// Get current time in milliseconds since Unix epoch
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Default block page HTML
const DEFAULT_BLOCK_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #e53e3e 0%, #9b2c2c 100%);
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
        }
        h1 { color: #e53e3e; margin-bottom: 1rem; }
        p { color: #666; }
        .icon {
            font-size: 4rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">&#128683;</div>
        <h1>Access Denied</h1>
        <p>Your request has been blocked due to suspicious activity.</p>
        <p>If you believe this is an error, please contact support.</p>
    </div>
</body>
</html>"#;

/// Default CAPTCHA page HTML (stub)
const DEFAULT_CAPTCHA_PAGE: &str = r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
        }
        h2 { color: #333; }
        p { color: #666; }
        .placeholder {
            background: #f0f0f0;
            padding: 2rem;
            margin: 1rem 0;
            border-radius: 4px;
            color: #999;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Human Verification Required</h2>
        <p>Please complete the verification below to continue.</p>
        <div class="placeholder">
            [CAPTCHA Placeholder - Integration Required]
        </div>
        <p><small>This is a stub implementation.</small></p>
    </div>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrogator::{CaptchaConfig, CookieConfig, JsChallengeConfig};
    use crate::tarpit::TarpitConfig;

    fn test_managers() -> (
        Arc<CookieManager>,
        Arc<JsChallengeManager>,
        Arc<CaptchaManager>,
        Arc<TarpitManager>,
    ) {
        let cookie_config = CookieConfig {
            cookie_name: "__test".to_string(),
            cookie_max_age_secs: 3600,
            secret_key: [0x01; 32],
            secure_only: true,
            http_only: true,
            same_site: "Strict".to_string(),
        };
        let js_config = JsChallengeConfig {
            difficulty: 1, // Low for fast tests
            ..Default::default()
        };
        let captcha_config = CaptchaConfig {
            secret: "test_captcha_secret".to_string(),
            expiry_secs: 300,
            max_challenges: 100,
            cleanup_interval_secs: 60,
        };
        let tarpit_config = TarpitConfig {
            base_delay_ms: 10, // Low for fast tests
            ..Default::default()
        };

        (
            Arc::new(CookieManager::new(cookie_config).expect("valid test config")),
            Arc::new(JsChallengeManager::new(js_config)),
            Arc::new(CaptchaManager::new(captcha_config)),
            Arc::new(TarpitManager::new(tarpit_config)),
        )
    }

    fn test_config() -> ProgressionConfig {
        ProgressionConfig {
            failures_before_escalate: 3,
            auto_de_escalate_secs: 1, // Fast for tests
            skip_to_block_threshold: 10,
            ..Default::default()
        }
    }

    #[test]
    fn test_level_from_risk_score() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Low risk -> None
        assert_eq!(manager.determine_initial_level(0.1), ChallengeLevel::None);

        // Medium-low risk -> Cookie
        assert_eq!(manager.determine_initial_level(0.3), ChallengeLevel::Cookie);

        // Medium risk -> JS Challenge
        assert_eq!(
            manager.determine_initial_level(0.5),
            ChallengeLevel::JsChallenge
        );

        // Medium-high risk -> Tarpit (CAPTCHA disabled by default)
        assert_eq!(manager.determine_initial_level(0.7), ChallengeLevel::Tarpit);

        // High risk -> Block
        assert_eq!(manager.determine_initial_level(0.9), ChallengeLevel::Block);
    }

    #[test]
    fn test_escalation() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::None);

        // Escalate through levels
        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Cookie);

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::JsChallenge);

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Tarpit); // CAPTCHA disabled

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Block);

        // Can't escalate beyond block
        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Block);
    }

    #[test]
    fn test_de_escalation() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Start at block
        for _ in 0..5 {
            manager.escalate("actor_123");
        }
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Block);

        // De-escalate through levels
        let level = manager.de_escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Tarpit);

        let level = manager.de_escalate("actor_123");
        assert_eq!(level, ChallengeLevel::JsChallenge);

        let level = manager.de_escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Cookie);

        let level = manager.de_escalate("actor_123");
        assert_eq!(level, ChallengeLevel::None);

        // Can't de-escalate below none
        let level = manager.de_escalate("actor_123");
        assert_eq!(level, ChallengeLevel::None);
    }

    #[test]
    fn test_failure_escalation() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Start a challenge to get state
        manager.get_challenge("actor_123", 0.3);
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Cookie);

        // Record failures - should escalate after 3
        manager.record_failure("actor_123");
        manager.record_failure("actor_123");
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Cookie);

        manager.record_failure("actor_123"); // 3rd failure
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::JsChallenge);
    }

    #[test]
    fn test_skip_to_block() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Start a challenge
        manager.get_challenge("actor_123", 0.3);

        // Record many failures - should skip to block after 10
        for _ in 0..10 {
            manager.record_failure("actor_123");
        }

        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Block);
    }

    #[test]
    fn test_get_challenge_response() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Low risk -> Allow
        let response = manager.get_challenge("actor_1", 0.1);
        assert!(matches!(response, ChallengeResponse::Allow));

        // Medium-low risk -> Cookie
        let response = manager.get_challenge("actor_2", 0.3);
        assert!(matches!(response, ChallengeResponse::Cookie { .. }));

        // Medium risk -> JS Challenge
        let response = manager.get_challenge("actor_3", 0.5);
        assert!(matches!(response, ChallengeResponse::JsChallenge { .. }));

        // High risk -> Block
        let response = manager.get_challenge("actor_4", 0.9);
        assert!(matches!(response, ChallengeResponse::Block { .. }));
    }

    #[test]
    fn test_actor_state_tracking() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_123", 0.5);

        let state = manager.get_actor_state("actor_123").unwrap();
        assert_eq!(state.actor_id, "actor_123");
        assert_eq!(state.current_level, ChallengeLevel::JsChallenge);
        assert_eq!(state.total_failures, 0);

        manager.record_failure("actor_123");
        let state = manager.get_actor_state("actor_123").unwrap();
        assert_eq!(state.total_failures, 1);
        assert_eq!(state.failures_at_level, 1);
    }

    #[test]
    fn test_list_actors_at_level() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_1", 0.3); // Cookie
        manager.get_challenge("actor_2", 0.5); // JS
        manager.get_challenge("actor_3", 0.5); // JS
        manager.get_challenge("actor_4", 0.9); // Block

        let cookie_actors = manager.list_actors_at_level(ChallengeLevel::Cookie);
        assert_eq!(cookie_actors.len(), 1);

        let js_actors = manager.list_actors_at_level(ChallengeLevel::JsChallenge);
        assert_eq!(js_actors.len(), 2);

        let block_actors = manager.list_actors_at_level(ChallengeLevel::Block);
        assert_eq!(block_actors.len(), 1);
    }

    #[test]
    fn test_reset() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_123", 0.5);
        assert!(manager.get_actor_state("actor_123").is_some());

        manager.reset("actor_123");
        assert!(manager.get_actor_state("actor_123").is_none());
    }

    #[test]
    fn test_stats_tracking() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_1", 0.5);
        manager.get_challenge("actor_2", 0.5);

        let stats = manager.stats().snapshot();
        assert_eq!(stats.actors_tracked, 2);
        assert_eq!(stats.challenges_issued, 2);

        manager.record_failure("actor_1");
        let stats = manager.stats().snapshot();
        assert_eq!(stats.failures, 1);

        manager.record_success("actor_1");
        let stats = manager.stats().snapshot();
        assert_eq!(stats.successes, 1);
    }

    #[test]
    fn test_challenge_level_display() {
        assert_eq!(ChallengeLevel::None.name(), "none");
        assert_eq!(ChallengeLevel::Cookie.name(), "cookie");
        assert_eq!(ChallengeLevel::JsChallenge.name(), "js_challenge");
        assert_eq!(ChallengeLevel::Captcha.name(), "captcha");
        assert_eq!(ChallengeLevel::Tarpit.name(), "tarpit");
        assert_eq!(ChallengeLevel::Block.name(), "block");

        assert_eq!(format!("{}", ChallengeLevel::Cookie), "cookie");
    }

    #[test]
    fn test_challenge_level_from_u8() {
        assert_eq!(ChallengeLevel::from_u8(0), ChallengeLevel::None);
        assert_eq!(ChallengeLevel::from_u8(1), ChallengeLevel::Cookie);
        assert_eq!(ChallengeLevel::from_u8(2), ChallengeLevel::JsChallenge);
        assert_eq!(ChallengeLevel::from_u8(3), ChallengeLevel::Captcha);
        assert_eq!(ChallengeLevel::from_u8(4), ChallengeLevel::Tarpit);
        assert_eq!(ChallengeLevel::from_u8(5), ChallengeLevel::Block);
        assert_eq!(ChallengeLevel::from_u8(100), ChallengeLevel::Block); // Out of range
    }

    #[test]
    fn test_risk_higher_than_current_level() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Start with cookie level
        manager.get_challenge("actor_123", 0.3);
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Cookie);

        // Higher risk should increase effective level
        let response = manager.get_challenge("actor_123", 0.9);
        assert!(matches!(response, ChallengeResponse::Block { .. }));
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Block);
    }

    #[test]
    fn test_behavior_escalates_above_risk() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Low risk, but manual escalation
        manager.get_challenge("actor_123", 0.1);
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::None);

        manager.escalate("actor_123");
        manager.escalate("actor_123");
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::JsChallenge);

        // Even with low risk, behavior-based level persists
        let response = manager.get_challenge("actor_123", 0.1);
        assert!(matches!(response, ChallengeResponse::JsChallenge { .. }));
    }

    #[test]
    fn test_escalation_history() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_123", 0.3);
        manager.escalate("actor_123");
        manager.escalate("actor_123");

        let state = manager.get_actor_state("actor_123").unwrap();
        assert_eq!(state.escalation_history.len(), 2);
        assert_eq!(state.escalation_history[0].0, ChallengeLevel::JsChallenge);
        assert_eq!(state.escalation_history[1].0, ChallengeLevel::Tarpit);
    }

    #[test]
    fn test_clear() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        manager.get_challenge("actor_1", 0.5);
        manager.get_challenge("actor_2", 0.5);
        assert_eq!(manager.len(), 2);

        manager.clear();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_disabled_levels_skipped() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let config = ProgressionConfig {
            enable_cookie: false,
            enable_js_challenge: false,
            enable_captcha: false,
            enable_tarpit: true,
            ..test_config()
        };
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, config);

        // Escalation should skip disabled levels
        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Tarpit);

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Block);
    }

    #[test]
    fn test_tarpit_challenge() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, test_config());

        // Get tarpit challenge
        let response = manager.get_challenge("actor_123", 0.7);
        assert!(matches!(response, ChallengeResponse::Tarpit { delay_ms } if delay_ms > 0));
    }

    #[test]
    fn test_captcha_challenge() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let config = ProgressionConfig {
            enable_captcha: true,
            ..test_config()
        };
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, config);

        // Get CAPTCHA challenge at medium-high risk
        let response = manager.get_challenge("actor_123", 0.65);
        match response {
            ChallengeResponse::Captcha { html, session_id } => {
                assert!(html.contains("Human Verification Required"));
                assert!(html.contains("What is"));
                assert!(!session_id.is_empty());
            }
            _ => panic!("Expected CAPTCHA challenge, got {:?}", response),
        }
    }

    #[test]
    fn test_captcha_validation() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let config = ProgressionConfig {
            enable_captcha: true,
            ..test_config()
        };
        let manager = ProgressionManager::new(cookie, js, captcha.clone(), tarpit, config);

        // Get CAPTCHA challenge
        let response = manager.get_challenge("actor_123", 0.65);
        let session_id = match response {
            ChallengeResponse::Captcha { session_id, .. } => session_id,
            _ => panic!("Expected CAPTCHA challenge"),
        };

        // Get the challenge details from the captcha manager to know the answer
        let challenge = captcha.issue_challenge("actor_123");
        // Parse the question to get the answer (e.g., "What is 5 + 3?")
        let parts: Vec<&str> = challenge.question.split_whitespace().collect();
        let a: i32 = parts[2].parse().unwrap();
        let b: i32 = parts[4].trim_end_matches('?').parse().unwrap();
        let answer = a + b;

        // Validate with correct answer
        let validation_response = format!("{}:{}", challenge.session_id, answer);
        let result = captcha.validate_response("actor_123", &validation_response);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_captcha_escalation_with_enabled() {
        let (cookie, js, captcha, tarpit) = test_managers();
        let config = ProgressionConfig {
            enable_captcha: true,
            ..test_config()
        };
        let manager = ProgressionManager::new(cookie, js, captcha, tarpit, config);

        // Start at Cookie
        manager.get_challenge("actor_123", 0.3);
        assert_eq!(manager.get_level("actor_123"), ChallengeLevel::Cookie);

        // Escalate through levels
        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::JsChallenge);

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Captcha); // Now enabled!

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Tarpit);

        let level = manager.escalate("actor_123");
        assert_eq!(level, ChallengeLevel::Block);
    }
}
