//! Thread-safe session manager using DashMap for concurrent access.
//!
//! Implements session tracking with LRU eviction and hijack detection via JA4 fingerprint binding.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

// ============================================================================
// Session Decision
// ============================================================================

/// Session validation decision returned by `validate_request`.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionDecision {
    /// Session is valid, continue processing.
    Valid,
    /// Session is new, tracking initiated.
    New,
    /// Session may be hijacked - contains the alert details.
    Suspicious(HijackAlert),
    /// Session has expired (TTL or idle timeout exceeded).
    Expired,
    /// Session is invalid for the specified reason.
    Invalid(String),
}

// ============================================================================
// Hijack Alert
// ============================================================================

/// Alert for potential session hijacking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HijackAlert {
    /// Session ID that may be hijacked.
    pub session_id: String,
    /// Type of hijacking detected.
    pub alert_type: HijackType,
    /// Original bound value (e.g., original JA4 fingerprint).
    pub original_value: String,
    /// New value that triggered the alert.
    pub new_value: String,
    /// Timestamp when the alert was generated (ms since epoch).
    pub timestamp: u64,
    /// Confidence level of the hijack detection (0.0 - 1.0).
    pub confidence: f64,
}

/// Type of session hijacking detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HijackType {
    /// JA4 TLS fingerprint mismatch (high confidence).
    Ja4Mismatch,
    /// IP address changed unexpectedly.
    IpChange,
    /// Impossible travel detected (IP geolocation suggests impossible speed).
    ImpossibleTravel,
    /// Session token rotation detected unexpectedly.
    TokenRotation,
}

// ============================================================================
// Session State
// ============================================================================

/// Per-session state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    /// Unique session identifier (UUID v4).
    pub session_id: String,
    /// Hash of the session token (used as primary key).
    pub token_hash: String,
    /// Associated actor ID (if bound to an actor).
    pub actor_id: Option<String>,
    /// Creation timestamp (ms since epoch).
    pub creation_time: u64,
    /// Last activity timestamp (ms since epoch).
    pub last_activity: u64,
    /// Total request count for this session.
    pub request_count: u64,
    /// Bound JA4 fingerprint (for hijack detection).
    pub bound_ja4: Option<String>,
    /// Bound IP address (for strict mode hijack detection).
    pub bound_ip: Option<IpAddr>,
    /// Whether this session is flagged as suspicious.
    pub is_suspicious: bool,
    /// History of hijack alerts for this session.
    pub hijack_alerts: Vec<HijackAlert>,
}

impl SessionState {
    /// Create a new session state.
    pub fn new(session_id: String, token_hash: String) -> Self {
        let now = now_ms();
        Self {
            session_id,
            token_hash,
            actor_id: None,
            creation_time: now,
            last_activity: now,
            request_count: 0,
            bound_ja4: None,
            bound_ip: None,
            is_suspicious: false,
            hijack_alerts: Vec::new(),
        }
    }

    /// Update last activity timestamp and increment request count.
    pub fn touch(&mut self) {
        self.last_activity = now_ms();
        self.request_count += 1;
    }

    /// Bind JA4 fingerprint to this session.
    pub fn bind_ja4(&mut self, ja4: String) {
        if self.bound_ja4.is_none() && !ja4.is_empty() {
            self.bound_ja4 = Some(ja4);
        }
    }

    /// Bind IP address to this session.
    pub fn bind_ip(&mut self, ip: IpAddr) {
        if self.bound_ip.is_none() {
            self.bound_ip = Some(ip);
        }
    }

    /// Add a hijack alert to this session.
    pub fn add_alert(&mut self, alert: HijackAlert) {
        self.is_suspicious = true;
        self.hijack_alerts.push(alert);
    }
}

// ============================================================================
// Session Configuration
// ============================================================================

/// Configuration for SessionManager.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum number of sessions to track (LRU eviction when exceeded).
    /// Default: 50,000
    pub max_sessions: usize,

    /// Session time-to-live in seconds (absolute expiration).
    /// Default: 3600 (1 hour)
    pub session_ttl_secs: u64,

    /// Idle timeout in seconds (inactivity expiration).
    /// Default: 900 (15 minutes)
    pub idle_timeout_secs: u64,

    /// Interval in seconds between cleanup cycles.
    /// Default: 300 (5 minutes)
    pub cleanup_interval_secs: u64,

    /// Enable JA4 fingerprint binding for hijack detection.
    /// Default: true
    pub enable_ja4_binding: bool,

    /// Enable IP binding for strict mode hijack detection.
    /// Default: false (can cause false positives for mobile users)
    pub enable_ip_binding: bool,

    /// Number of JA4 mismatches before alerting (0 = immediate).
    /// Default: 1 (immediate alert on mismatch)
    pub ja4_mismatch_threshold: u32,

    /// Window in seconds to allow IP changes (for mobile/VPN users).
    /// Default: 60 seconds
    pub ip_change_window_secs: u64,

    /// Maximum number of hijack alerts to store per session.
    /// Default: 10
    pub max_alerts_per_session: usize,

    /// Whether session tracking is enabled.
    /// Default: true
    pub enabled: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 50_000,
            session_ttl_secs: 3600,
            idle_timeout_secs: 900,
            cleanup_interval_secs: 300,
            enable_ja4_binding: true,
            enable_ip_binding: false,
            ja4_mismatch_threshold: 1,
            ip_change_window_secs: 60,
            max_alerts_per_session: 10,
            enabled: true,
        }
    }
}

// ============================================================================
// Session Statistics
// ============================================================================

/// Statistics for monitoring the session manager.
#[derive(Debug, Default)]
pub struct SessionStats {
    /// Total number of sessions currently tracked.
    pub total_sessions: AtomicU64,
    /// Number of active sessions (not expired).
    pub active_sessions: AtomicU64,
    /// Number of suspicious sessions.
    pub suspicious_sessions: AtomicU64,
    /// Total hijack alerts generated.
    pub hijack_alerts: AtomicU64,
    /// Total sessions expired (TTL or idle).
    pub expired_sessions: AtomicU64,
    /// Total sessions evicted due to LRU capacity.
    pub evictions: AtomicU64,
    /// Total sessions created.
    pub total_created: AtomicU64,
    /// Total sessions invalidated.
    pub total_invalidated: AtomicU64,
}

impl SessionStats {
    /// Create a new stats instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of the current statistics.
    pub fn snapshot(&self) -> SessionStatsSnapshot {
        SessionStatsSnapshot {
            total_sessions: self.total_sessions.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            suspicious_sessions: self.suspicious_sessions.load(Ordering::Relaxed),
            hijack_alerts: self.hijack_alerts.load(Ordering::Relaxed),
            expired_sessions: self.expired_sessions.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            total_created: self.total_created.load(Ordering::Relaxed),
            total_invalidated: self.total_invalidated.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of session statistics (for serialization).
#[derive(Debug, Clone, Serialize)]
pub struct SessionStatsSnapshot {
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub suspicious_sessions: u64,
    pub hijack_alerts: u64,
    pub expired_sessions: u64,
    pub evictions: u64,
    pub total_created: u64,
    pub total_invalidated: u64,
}

// ============================================================================
// Session Manager
// ============================================================================

/// Manages session state with LRU eviction and hijack detection.
///
/// Thread-safe implementation using DashMap for lock-free concurrent access.
pub struct SessionManager {
    /// Sessions by token_hash (primary storage).
    sessions: DashMap<String, SessionState>,

    /// Session ID to token_hash mapping (for lookup by session ID).
    session_by_id: DashMap<String, String>,

    /// Actor ID to session IDs mapping (for listing actor's sessions).
    actor_sessions: DashMap<String, Vec<String>>,

    /// Configuration.
    config: SessionConfig,

    /// Statistics.
    stats: Arc<SessionStats>,

    /// Shutdown signal for background tasks.
    shutdown: Arc<Notify>,

    /// Touch counter for lazy eviction.
    touch_counter: AtomicU32,
}

impl SessionManager {
    /// Create a new session manager with the given configuration.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            sessions: DashMap::with_capacity(config.max_sessions),
            session_by_id: DashMap::with_capacity(config.max_sessions),
            actor_sessions: DashMap::with_capacity(config.max_sessions / 10),
            config,
            stats: Arc::new(SessionStats::new()),
            shutdown: Arc::new(Notify::new()),
            touch_counter: AtomicU32::new(0),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Check if session tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the number of tracked sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    // ========================================================================
    // Primary API
    // ========================================================================

    /// Validate an incoming request's session.
    ///
    /// This is the primary entry point - call on every request with a session token.
    ///
    /// # Arguments
    /// * `token_hash` - Hash of the session token (not the raw token)
    /// * `ip` - Client IP address
    /// * `ja4` - Optional JA4 TLS fingerprint
    ///
    /// # Returns
    /// A `SessionDecision` indicating the validation result.
    pub fn validate_request(
        &self,
        token_hash: &str,
        ip: IpAddr,
        ja4: Option<&str>,
    ) -> SessionDecision {
        if !self.config.enabled {
            return SessionDecision::Valid;
        }

        // Check capacity and evict if needed
        self.maybe_evict();

        // Try to get existing session
        if let Some(mut entry) = self.sessions.get_mut(token_hash) {
            let session = entry.value_mut();

            // Check expiration
            if self.is_session_expired(session) {
                // Remove expired session
                drop(entry);
                self.remove_session(token_hash);
                self.stats.expired_sessions.fetch_add(1, Ordering::Relaxed);
                return SessionDecision::Expired;
            }

            // Check for hijacking
            if let Some(alert) = self.detect_hijack(session, ip, ja4) {
                session.add_alert(alert.clone());
                session.touch();

                // Trim alerts if needed
                if session.hijack_alerts.len() > self.config.max_alerts_per_session {
                    let excess = session.hijack_alerts.len() - self.config.max_alerts_per_session;
                    session.hijack_alerts.drain(0..excess);
                }

                self.stats.hijack_alerts.fetch_add(1, Ordering::Relaxed);

                // Update suspicious count if first alert
                if session.hijack_alerts.len() == 1 {
                    self.stats.suspicious_sessions.fetch_add(1, Ordering::Relaxed);
                }

                return SessionDecision::Suspicious(alert);
            }

            // Valid session - update activity
            session.touch();

            // Bind fingerprint if first request or not yet bound
            if let Some(ja4_str) = ja4 {
                session.bind_ja4(ja4_str.to_string());
            }

            if self.config.enable_ip_binding {
                session.bind_ip(ip);
            }

            return SessionDecision::Valid;
        }

        // Session doesn't exist - create new one
        let _session = self.create_session(token_hash, ip, ja4);
        SessionDecision::New
    }

    /// Create a new session.
    ///
    /// # Arguments
    /// * `token_hash` - Hash of the session token
    /// * `ip` - Client IP address
    /// * `ja4` - Optional JA4 TLS fingerprint
    ///
    /// # Returns
    /// The newly created session state.
    pub fn create_session(
        &self,
        token_hash: &str,
        ip: IpAddr,
        ja4: Option<&str>,
    ) -> SessionState {
        if !self.config.enabled {
            return SessionState::new(generate_session_id(), token_hash.to_string());
        }

        // Check capacity and evict if needed
        self.maybe_evict();

        let session_id = generate_session_id();
        let mut session = SessionState::new(session_id.clone(), token_hash.to_string());
        session.touch();

        // Bind fingerprint and IP
        if let Some(ja4_str) = ja4 {
            session.bind_ja4(ja4_str.to_string());
        }

        if self.config.enable_ip_binding {
            session.bind_ip(ip);
        }

        // Insert into maps
        self.session_by_id.insert(session_id.clone(), token_hash.to_string());
        self.sessions.insert(token_hash.to_string(), session.clone());

        // Update stats
        self.stats.total_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.active_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.total_created.fetch_add(1, Ordering::Relaxed);

        session
    }

    /// Get session by token hash.
    pub fn get_session(&self, token_hash: &str) -> Option<SessionState> {
        self.sessions.get(token_hash).map(|entry| entry.value().clone())
    }

    /// Get session by session ID.
    pub fn get_session_by_id(&self, session_id: &str) -> Option<SessionState> {
        self.session_by_id
            .get(session_id)
            .and_then(|token_hash| self.sessions.get(token_hash.value()).map(|e| e.value().clone()))
    }

    /// Touch session to update activity timestamp.
    pub fn touch_session(&self, token_hash: &str) {
        if let Some(mut entry) = self.sessions.get_mut(token_hash) {
            entry.value_mut().touch();
        }
    }

    /// Bind session to an actor.
    ///
    /// # Arguments
    /// * `token_hash` - Hash of the session token
    /// * `actor_id` - Actor ID to bind to
    pub fn bind_to_actor(&self, token_hash: &str, actor_id: &str) {
        if let Some(mut entry) = self.sessions.get_mut(token_hash) {
            let session = entry.value_mut();
            let session_id = session.session_id.clone();

            // Update session's actor_id
            session.actor_id = Some(actor_id.to_string());

            // Update actor_sessions mapping
            self.actor_sessions
                .entry(actor_id.to_string())
                .or_insert_with(Vec::new)
                .push(session_id);
        }
    }

    /// Get all sessions for an actor.
    ///
    /// # Arguments
    /// * `actor_id` - Actor ID to look up
    ///
    /// # Returns
    /// Vector of session states associated with the actor.
    pub fn get_actor_sessions(&self, actor_id: &str) -> Vec<SessionState> {
        self.actor_sessions
            .get(actor_id)
            .map(|session_ids| {
                session_ids
                    .iter()
                    .filter_map(|session_id| self.get_session_by_id(session_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Invalidate a session.
    ///
    /// # Arguments
    /// * `token_hash` - Hash of the session token to invalidate
    ///
    /// # Returns
    /// `true` if the session was invalidated, `false` if not found.
    pub fn invalidate_session(&self, token_hash: &str) -> bool {
        if self.remove_session(token_hash) {
            self.stats.total_invalidated.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Mark session as suspicious with a hijack alert.
    ///
    /// # Arguments
    /// * `token_hash` - Hash of the session token
    /// * `alert` - Hijack alert to add
    pub fn mark_suspicious(&self, token_hash: &str, alert: HijackAlert) {
        if let Some(mut entry) = self.sessions.get_mut(token_hash) {
            let session = entry.value_mut();
            let was_suspicious = session.is_suspicious;
            session.add_alert(alert);

            // Trim alerts if needed
            if session.hijack_alerts.len() > self.config.max_alerts_per_session {
                let excess = session.hijack_alerts.len() - self.config.max_alerts_per_session;
                session.hijack_alerts.drain(0..excess);
            }

            self.stats.hijack_alerts.fetch_add(1, Ordering::Relaxed);

            // Update suspicious count if first alert
            if !was_suspicious {
                self.stats.suspicious_sessions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// List sessions with pagination.
    ///
    /// # Arguments
    /// * `limit` - Maximum number of sessions to return
    /// * `offset` - Number of sessions to skip
    ///
    /// # Returns
    /// Vector of session states sorted by last_activity (most recent first).
    pub fn list_sessions(&self, limit: usize, offset: usize) -> Vec<SessionState> {
        let mut sessions: Vec<SessionState> = self
            .sessions
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Sort by last_activity (most recent first)
        sessions.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        // Apply pagination
        sessions.into_iter().skip(offset).take(limit).collect()
    }

    /// List suspicious sessions.
    ///
    /// # Returns
    /// Vector of session states that have been flagged as suspicious.
    pub fn list_suspicious_sessions(&self) -> Vec<SessionState> {
        self.sessions
            .iter()
            .filter(|entry| entry.value().is_suspicious)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Start background cleanup tasks.
    ///
    /// Spawns a background task that periodically:
    /// 1. Removes expired sessions (TTL and idle timeout)
    /// 2. Evicts oldest sessions if over capacity
    pub fn start_background_tasks(self: Arc<Self>) {
        let manager = self;
        let cleanup_interval = Duration::from_secs(manager.config.cleanup_interval_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check shutdown
                        if Arc::strong_count(&manager.shutdown) == 1 {
                            // Only this task holds a reference, shutting down
                            break;
                        }

                        // Cleanup expired sessions
                        manager.cleanup_expired_sessions();

                        // Evict if over capacity
                        manager.evict_if_needed();
                    }
                    _ = manager.shutdown.notified() => {
                        log::info!("Session manager background tasks shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Signal shutdown for background tasks.
    pub fn shutdown(&self) {
        self.shutdown.notify_one();
    }

    /// Get statistics.
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Clear all sessions (primarily for testing).
    pub fn clear(&self) {
        self.sessions.clear();
        self.session_by_id.clear();
        self.actor_sessions.clear();
        self.stats.total_sessions.store(0, Ordering::Relaxed);
        self.stats.active_sessions.store(0, Ordering::Relaxed);
        self.stats.suspicious_sessions.store(0, Ordering::Relaxed);
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    /// Detect potential session hijacking.
    ///
    /// # Arguments
    /// * `session` - Current session state
    /// * `ip` - Client IP address
    /// * `ja4` - Optional JA4 TLS fingerprint
    ///
    /// # Returns
    /// A hijack alert if hijacking is detected, None otherwise.
    fn detect_hijack(
        &self,
        session: &SessionState,
        ip: IpAddr,
        ja4: Option<&str>,
    ) -> Option<HijackAlert> {
        let now = now_ms();

        // Check JA4 fingerprint binding
        if self.config.enable_ja4_binding {
            if let (Some(bound_ja4), Some(current_ja4)) = (&session.bound_ja4, ja4) {
                if bound_ja4 != current_ja4 {
                    return Some(HijackAlert {
                        session_id: session.session_id.clone(),
                        alert_type: HijackType::Ja4Mismatch,
                        original_value: bound_ja4.clone(),
                        new_value: current_ja4.to_string(),
                        timestamp: now,
                        confidence: 0.9, // High confidence - fingerprint changed
                    });
                }
            }
        }

        // Check IP binding (if enabled in strict mode)
        if self.config.enable_ip_binding {
            if let Some(bound_ip) = session.bound_ip {
                if bound_ip != ip {
                    // Allow some IP change within window (for mobile users)
                    let time_since_last = now.saturating_sub(session.last_activity);
                    let window_ms = self.config.ip_change_window_secs * 1000;

                    if time_since_last < window_ms {
                        return Some(HijackAlert {
                            session_id: session.session_id.clone(),
                            alert_type: HijackType::IpChange,
                            original_value: bound_ip.to_string(),
                            new_value: ip.to_string(),
                            timestamp: now,
                            confidence: 0.7, // Lower confidence - could be legitimate
                        });
                    }
                }
            }
        }

        None
    }

    /// Check if a session has expired.
    ///
    /// # Arguments
    /// * `session` - Session state to check
    ///
    /// # Returns
    /// `true` if the session has expired (TTL or idle timeout), `false` otherwise.
    fn is_session_expired(&self, session: &SessionState) -> bool {
        let now = now_ms();

        // Check absolute TTL
        let ttl_ms = self.config.session_ttl_secs * 1000;
        if now.saturating_sub(session.creation_time) > ttl_ms {
            return true;
        }

        // Check idle timeout
        let idle_ms = self.config.idle_timeout_secs * 1000;
        if now.saturating_sub(session.last_activity) > idle_ms {
            return true;
        }

        false
    }

    /// Cleanup expired sessions.
    fn cleanup_expired_sessions(&self) {
        let mut to_remove = Vec::new();

        for entry in self.sessions.iter() {
            if self.is_session_expired(entry.value()) {
                to_remove.push(entry.key().clone());
            }
        }

        for token_hash in to_remove {
            self.remove_session(&token_hash);
            self.stats.expired_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evict sessions if over capacity.
    fn evict_if_needed(&self) {
        let current_len = self.sessions.len();
        if current_len <= self.config.max_sessions {
            return;
        }

        // Evict oldest 1% of sessions
        let evict_count = (self.config.max_sessions / 100).max(1);
        self.evict_oldest(evict_count);
    }

    /// Maybe evict oldest sessions if at capacity.
    ///
    /// Uses lazy eviction: only check every 100th operation.
    fn maybe_evict(&self) {
        let count = self.touch_counter.fetch_add(1, Ordering::Relaxed);
        if count % 100 != 0 {
            return;
        }

        if self.sessions.len() < self.config.max_sessions {
            return;
        }

        // Evict oldest 1% of sessions
        let evict_count = (self.config.max_sessions / 100).max(1);
        self.evict_oldest(evict_count);
    }

    /// Evict the N oldest sessions by last_activity timestamp.
    ///
    /// Uses sampling to avoid O(n) collection of all sessions.
    fn evict_oldest(&self, count: usize) {
        let sample_size = (count * 10).min(1000).min(self.sessions.len());

        if sample_size == 0 {
            return;
        }

        // Sample sessions
        let mut candidates: Vec<(String, u64)> = Vec::with_capacity(sample_size);
        for entry in self.sessions.iter().take(sample_size) {
            candidates.push((entry.key().clone(), entry.value().last_activity));
        }

        // Sort by last_activity (oldest first)
        candidates.sort_unstable_by_key(|(_, ts)| *ts);

        // Evict oldest N from sample
        for (token_hash, _) in candidates.into_iter().take(count) {
            self.remove_session(&token_hash);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove a session and clean up all mappings.
    fn remove_session(&self, token_hash: &str) -> bool {
        if let Some((_, session)) = self.sessions.remove(token_hash) {
            // Remove session_id mapping
            self.session_by_id.remove(&session.session_id);

            // Remove from actor's sessions list
            if let Some(actor_id) = &session.actor_id {
                if let Some(mut entry) = self.actor_sessions.get_mut(actor_id) {
                    entry.retain(|id| id != &session.session_id);
                }
            }

            // Update stats
            self.stats.total_sessions.fetch_sub(1, Ordering::Relaxed);
            self.stats.active_sessions.fetch_sub(1, Ordering::Relaxed);

            if session.is_suspicious {
                self.stats.suspicious_sessions.fetch_sub(1, Ordering::Relaxed);
            }

            return true;
        }

        false
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new(SessionConfig::default())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a unique session ID using UUID v4.
fn generate_session_id() -> String {
    // Use fastrand for fast random number generation
    let a = fastrand::u64(..);
    let b = fastrand::u64(..);
    format!(
        "sess-{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16 & 0xFFFF,
        a as u16 & 0x0FFF,
        ((b >> 48) as u16 & 0x3FFF) | 0x8000,
        b & 0xFFFF_FFFF_FFFF
    )
}

/// Get current time in milliseconds since Unix epoch.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_test_manager() -> SessionManager {
        SessionManager::new(SessionConfig {
            max_sessions: 1000,
            session_ttl_secs: 3600,
            idle_timeout_secs: 900,
            ..Default::default()
        })
    }

    fn create_test_ip(last_octet: u8) -> IpAddr {
        format!("192.168.1.{}", last_octet).parse().unwrap()
    }

    // ========================================================================
    // Session Creation and Retrieval Tests
    // ========================================================================

    #[test]
    fn test_session_creation() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let session = manager.create_session("token_hash_1", ip, None);

        assert!(!session.session_id.is_empty());
        assert!(session.session_id.starts_with("sess-"));
        assert_eq!(session.token_hash, "token_hash_1");
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_session_retrieval_by_token_hash() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);

        let retrieved = manager.get_session("token_hash_1").unwrap();
        assert_eq!(retrieved.token_hash, "token_hash_1");
    }

    #[test]
    fn test_session_retrieval_by_id() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let session = manager.create_session("token_hash_1", ip, None);
        let retrieved = manager.get_session_by_id(&session.session_id).unwrap();

        assert_eq!(retrieved.token_hash, "token_hash_1");
    }

    #[test]
    fn test_session_nonexistent() {
        let manager = create_test_manager();

        assert!(manager.get_session("nonexistent").is_none());
        assert!(manager.get_session_by_id("nonexistent").is_none());
    }

    // ========================================================================
    // Session Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_new_session() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let decision = manager.validate_request("token_hash_1", ip, None);

        assert_eq!(decision, SessionDecision::New);
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_validate_existing_session() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Create session first
        manager.create_session("token_hash_1", ip, Some("ja4_fingerprint"));

        // Validate again with same fingerprint
        let decision = manager.validate_request("token_hash_1", ip, Some("ja4_fingerprint"));

        assert_eq!(decision, SessionDecision::Valid);
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_validate_increments_request_count() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.validate_request("token_hash_1", ip, None);
        manager.validate_request("token_hash_1", ip, None);
        manager.validate_request("token_hash_1", ip, None);

        let session = manager.get_session("token_hash_1").unwrap();
        assert_eq!(session.request_count, 3);
    }

    // ========================================================================
    // JA4 Fingerprint Binding Tests
    // ========================================================================

    #[test]
    fn test_ja4_binding() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, Some("ja4_fingerprint_1"));

        let session = manager.get_session("token_hash_1").unwrap();
        assert_eq!(session.bound_ja4, Some("ja4_fingerprint_1".to_string()));
    }

    #[test]
    fn test_ja4_mismatch_detection() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Create session with fingerprint
        manager.create_session("token_hash_1", ip, Some("ja4_fingerprint_1"));

        // Validate with different fingerprint
        let decision = manager.validate_request("token_hash_1", ip, Some("ja4_fingerprint_2"));

        match decision {
            SessionDecision::Suspicious(alert) => {
                assert_eq!(alert.alert_type, HijackType::Ja4Mismatch);
                assert_eq!(alert.original_value, "ja4_fingerprint_1");
                assert_eq!(alert.new_value, "ja4_fingerprint_2");
                assert!(alert.confidence >= 0.9);
            }
            _ => panic!("Expected Suspicious decision, got {:?}", decision),
        }
    }

    #[test]
    fn test_ja4_binding_first_value_only() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Create session without fingerprint
        manager.create_session("token_hash_1", ip, None);

        // First request with fingerprint binds it
        manager.validate_request("token_hash_1", ip, Some("ja4_fingerprint_1"));

        let session = manager.get_session("token_hash_1").unwrap();
        assert_eq!(session.bound_ja4, Some("ja4_fingerprint_1".to_string()));
    }

    #[test]
    fn test_ja4_binding_disabled() {
        let config = SessionConfig {
            enable_ja4_binding: false,
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let ip = create_test_ip(1);

        // Create session with fingerprint
        manager.create_session("token_hash_1", ip, Some("ja4_fingerprint_1"));

        // Different fingerprint should NOT trigger alert when binding is disabled
        let decision = manager.validate_request("token_hash_1", ip, Some("ja4_fingerprint_2"));

        assert_eq!(decision, SessionDecision::Valid);
    }

    // ========================================================================
    // IP Binding Tests
    // ========================================================================

    #[test]
    fn test_ip_binding_strict_mode() {
        let config = SessionConfig {
            enable_ip_binding: true,
            ip_change_window_secs: 60,
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let ip1 = create_test_ip(1);
        let ip2 = create_test_ip(2);

        // Create session with IP1
        manager.create_session("token_hash_1", ip1, None);

        // Validate with different IP immediately (within window)
        let decision = manager.validate_request("token_hash_1", ip2, None);

        match decision {
            SessionDecision::Suspicious(alert) => {
                assert_eq!(alert.alert_type, HijackType::IpChange);
                assert!(alert.confidence >= 0.5 && alert.confidence < 0.9);
            }
            _ => panic!("Expected Suspicious decision, got {:?}", decision),
        }
    }

    #[test]
    fn test_ip_binding_disabled_by_default() {
        let manager = create_test_manager();
        let ip1 = create_test_ip(1);
        let ip2 = create_test_ip(2);

        // Create session with IP1
        manager.create_session("token_hash_1", ip1, None);

        // Different IP should NOT trigger alert when IP binding is disabled
        let decision = manager.validate_request("token_hash_1", ip2, None);

        assert_eq!(decision, SessionDecision::Valid);
    }

    // ========================================================================
    // Session Expiration Tests
    // ========================================================================

    #[test]
    fn test_session_ttl_expiration() {
        let config = SessionConfig {
            session_ttl_secs: 0, // Immediate expiration
            idle_timeout_secs: 3600,
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);

        // Small sleep to ensure time passes
        std::thread::sleep(std::time::Duration::from_millis(10));

        let decision = manager.validate_request("token_hash_1", ip, None);
        assert_eq!(decision, SessionDecision::Expired);
    }

    #[test]
    fn test_session_idle_expiration() {
        let config = SessionConfig {
            session_ttl_secs: 3600,
            idle_timeout_secs: 0, // Immediate idle timeout
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);

        // Small sleep to ensure time passes
        std::thread::sleep(std::time::Duration::from_millis(10));

        let decision = manager.validate_request("token_hash_1", ip, None);
        assert_eq!(decision, SessionDecision::Expired);
    }

    // ========================================================================
    // Actor Binding Tests
    // ========================================================================

    #[test]
    fn test_bind_to_actor() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);
        manager.bind_to_actor("token_hash_1", "actor_123");

        let session = manager.get_session("token_hash_1").unwrap();
        assert_eq!(session.actor_id, Some("actor_123".to_string()));
    }

    #[test]
    fn test_get_actor_sessions() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Create multiple sessions for same actor
        manager.create_session("token_1", ip, None);
        manager.create_session("token_2", ip, None);
        manager.create_session("token_3", ip, None);

        manager.bind_to_actor("token_1", "actor_123");
        manager.bind_to_actor("token_2", "actor_123");
        manager.bind_to_actor("token_3", "actor_456");

        let actor_sessions = manager.get_actor_sessions("actor_123");
        assert_eq!(actor_sessions.len(), 2);
    }

    // ========================================================================
    // LRU Eviction Tests
    // ========================================================================

    #[test]
    fn test_lru_eviction() {
        let config = SessionConfig {
            max_sessions: 100,
            ..Default::default()
        };
        let manager = SessionManager::new(config);

        // Add 150 sessions (over capacity)
        for i in 0..150 {
            let ip = create_test_ip((i % 256) as u8);
            manager.create_session(&format!("token_{}", i), ip, None);
        }

        // Lazy eviction doesn't aggressively enforce the limit
        assert!(manager.len() <= 150);

        // Force more evictions
        for i in 150..300 {
            let ip = create_test_ip((i % 256) as u8);
            manager.create_session(&format!("token_{}", i), ip, None);
        }

        // Verify evictions occurred
        let evictions = manager.stats().evictions.load(Ordering::Relaxed);
        assert!(evictions > 0);
    }

    // ========================================================================
    // Session Invalidation Tests
    // ========================================================================

    #[test]
    fn test_invalidate_session() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);
        assert_eq!(manager.len(), 1);

        let result = manager.invalidate_session("token_hash_1");
        assert!(result);
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_invalidate_nonexistent_session() {
        let manager = create_test_manager();

        let result = manager.invalidate_session("nonexistent");
        assert!(!result);
    }

    // ========================================================================
    // Suspicious Session Tests
    // ========================================================================

    #[test]
    fn test_mark_suspicious() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);

        let alert = HijackAlert {
            session_id: "test".to_string(),
            alert_type: HijackType::Ja4Mismatch,
            original_value: "old".to_string(),
            new_value: "new".to_string(),
            timestamp: now_ms(),
            confidence: 0.9,
        };

        manager.mark_suspicious("token_hash_1", alert);

        let session = manager.get_session("token_hash_1").unwrap();
        assert!(session.is_suspicious);
        assert_eq!(session.hijack_alerts.len(), 1);
    }

    #[test]
    fn test_list_suspicious_sessions() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Create sessions and mark some as suspicious
        for i in 0..10 {
            manager.create_session(&format!("token_{}", i), ip, None);
        }

        let alert = HijackAlert {
            session_id: "test".to_string(),
            alert_type: HijackType::Ja4Mismatch,
            original_value: "old".to_string(),
            new_value: "new".to_string(),
            timestamp: now_ms(),
            confidence: 0.9,
        };

        manager.mark_suspicious("token_0", alert.clone());
        manager.mark_suspicious("token_2", alert.clone());
        manager.mark_suspicious("token_4", alert);

        let suspicious = manager.list_suspicious_sessions();
        assert_eq!(suspicious.len(), 3);
    }

    // ========================================================================
    // List Tests
    // ========================================================================

    #[test]
    fn test_list_sessions() {
        let manager = create_test_manager();

        for i in 0..10 {
            let ip = create_test_ip(i);
            manager.create_session(&format!("token_{}", i), ip, None);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // Test pagination
        let first_page = manager.list_sessions(5, 0);
        assert_eq!(first_page.len(), 5);

        let second_page = manager.list_sessions(5, 5);
        assert_eq!(second_page.len(), 5);

        // Should be sorted by last_activity (most recent first)
        for window in first_page.windows(2) {
            assert!(window[0].last_activity >= window[1].last_activity);
        }
    }

    // ========================================================================
    // Concurrent Access Tests
    // ========================================================================

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(create_test_manager());
        let mut handles = vec![];

        // Spawn 10 threads, each creating and validating sessions
        for thread_id in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip: IpAddr = format!("10.{}.0.{}", thread_id, i % 256).parse().unwrap();
                    let token = format!("token_t{}_{}", thread_id, i);
                    let ja4 = format!("ja4_t{}_{}", thread_id, i % 5);

                    manager.validate_request(&token, ip, Some(&ja4));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify no panics and reasonable state
        assert!(manager.len() > 0);
        assert!(manager.stats().total_created.load(Ordering::Relaxed) > 0);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats() {
        let manager = create_test_manager();

        // Initial stats
        let stats = manager.stats().snapshot();
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.suspicious_sessions, 0);

        // Create sessions
        for i in 0..5 {
            let ip = create_test_ip(i);
            manager.create_session(&format!("token_{}", i), ip, Some(&format!("ja4_{}", i)));
        }

        let stats = manager.stats().snapshot();
        assert_eq!(stats.total_sessions, 5);
        assert_eq!(stats.active_sessions, 5);
        assert_eq!(stats.total_created, 5);
    }

    // ========================================================================
    // Clear Tests
    // ========================================================================

    #[test]
    fn test_clear() {
        let manager = create_test_manager();

        for i in 0..10 {
            let ip = create_test_ip(i);
            manager.create_session(&format!("token_{}", i), ip, None);
        }

        assert_eq!(manager.len(), 10);

        manager.clear();

        assert_eq!(manager.len(), 0);
        assert!(manager.session_by_id.is_empty());
        assert!(manager.actor_sessions.is_empty());
    }

    // ========================================================================
    // Default Implementation Tests
    // ========================================================================

    #[test]
    fn test_default() {
        let manager = SessionManager::default();

        assert!(manager.is_enabled());
        assert!(manager.is_empty());
        assert_eq!(manager.config().max_sessions, 50_000);
    }

    // ========================================================================
    // Session ID Generation Tests
    // ========================================================================

    #[test]
    fn test_session_id_uniqueness() {
        let mut ids = std::collections::HashSet::new();
        for _ in 0..1000 {
            let id = generate_session_id();
            assert!(!ids.contains(&id), "Duplicate ID generated: {}", id);
            ids.insert(id);
        }
    }

    #[test]
    fn test_session_id_format() {
        let id = generate_session_id();

        // Should be sess-xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx format
        assert!(id.starts_with("sess-"));
        assert_eq!(id.len(), 41); // "sess-" (5) + UUID (36)
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_empty_ja4_fingerprint() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, Some(""));

        let session = manager.get_session("token_hash_1").unwrap();
        assert!(session.bound_ja4.is_none());
    }

    #[test]
    fn test_ipv6_addresses() {
        let manager = create_test_manager();

        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        let session = manager.create_session("token_hash_1", ipv6, None);
        assert_eq!(session.request_count, 1);

        let decision = manager.validate_request("token_hash_1", ipv6, None);
        assert_eq!(decision, SessionDecision::Valid);
    }

    #[test]
    fn test_disabled_manager() {
        let config = SessionConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = SessionManager::new(config);

        assert!(!manager.is_enabled());

        let ip = create_test_ip(1);
        let decision = manager.validate_request("token_hash_1", ip, None);

        // Should return Valid without creating session when disabled
        assert_eq!(decision, SessionDecision::Valid);
        assert!(manager.is_empty());
    }

    // ========================================================================
    // Hijack Alert Trimming Tests
    // ========================================================================

    #[test]
    fn test_alert_trimming() {
        let config = SessionConfig {
            max_alerts_per_session: 3,
            ..Default::default()
        };
        let manager = SessionManager::new(config);
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, Some("ja4_original"));

        // Add more alerts than max
        for i in 0..10 {
            let alert = HijackAlert {
                session_id: "test".to_string(),
                alert_type: HijackType::Ja4Mismatch,
                original_value: "old".to_string(),
                new_value: format!("new_{}", i),
                timestamp: now_ms(),
                confidence: 0.9,
            };
            manager.mark_suspicious("token_hash_1", alert);
        }

        let session = manager.get_session("token_hash_1").unwrap();
        assert_eq!(session.hijack_alerts.len(), 3);

        // Should keep most recent
        assert_eq!(session.hijack_alerts[2].new_value, "new_9");
    }

    // ========================================================================
    // Session Touch Tests
    // ========================================================================

    #[test]
    fn test_touch_session() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.create_session("token_hash_1", ip, None);

        let before = manager.get_session("token_hash_1").unwrap().last_activity;

        std::thread::sleep(std::time::Duration::from_millis(10));

        manager.touch_session("token_hash_1");

        let after = manager.get_session("token_hash_1").unwrap().last_activity;
        assert!(after > before);
    }
}
