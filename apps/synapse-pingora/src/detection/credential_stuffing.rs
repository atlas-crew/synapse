//! Credential stuffing detection engine.
//!
//! Detects credential stuffing attacks with:
//! - Per-entity auth failure tracking with sliding windows
//! - Distributed attack correlation via fingerprint
//! - Account takeover detection (success after failures)
//! - Low-and-slow pattern detection
//!
//! Thread-safe with DashMap for concurrent access.
//! Performance target: <5μs per record_attempt/record_result.

use crate::detection::{
    AuthAttempt, AuthMetrics, AuthResult, DistributedAttack, EntityEndpointKey,
    GlobalVelocityTracker, StuffingConfig, StuffingEvent, StuffingSeverity, StuffingVerdict,
    TakeoverAlert, UsernameTargetedAttack,
};
use crossbeam_channel::{bounded, Receiver, Sender};
use serde::{Deserialize, Serialize};
use dashmap::DashMap;
use parking_lot::RwLock;
use regex::Regex;
use tracing::warn;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get current time in milliseconds since Unix epoch.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Credential stuffing detector with concurrent access.
///
/// SECURITY: Implements multi-dimensional detection to catch distributed attacks:
/// - Per-entity (IP) failure tracking
/// - Fingerprint-based distributed attack correlation
/// - Username-targeted attack detection (multiple IPs targeting same username)
/// - Global velocity monitoring for coordinated attacks
pub struct CredentialStuffingDetector {
    /// Per-entity auth metrics (entity+endpoint -> metrics)
    entity_auth: DashMap<EntityEndpointKey, AuthMetrics>,
    /// Distributed attack tracking (fingerprint+endpoint -> attack)
    distributed: DashMap<String, DistributedAttack>,
    /// Username-targeted attack tracking (username+endpoint -> attack)
    username_targeted: DashMap<String, UsernameTargetedAttack>,
    /// Global velocity tracker for overall failure rate
    global_velocity: RwLock<GlobalVelocityTracker>,
    /// Recent takeover alerts (bounded queue)
    takeovers: RwLock<VecDeque<TakeoverAlert>>,
    /// Recent events for alerting (bounded queue)
    events: RwLock<VecDeque<StuffingEvent>>,
    /// Compiled auth path regexes
    auth_patterns: Vec<Regex>,
    /// Configuration
    config: StuffingConfig,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Shutdown channel sender
    shutdown_tx: Sender<()>,
    /// Cleanup thread handle
    cleanup_handle: Option<JoinHandle<()>>,
}

impl CredentialStuffingDetector {
    /// Create a new detector with the given configuration.
    ///
    /// Configuration is validated and sanitized before use.
    pub fn new(config: StuffingConfig) -> Self {
        // Validate and sanitize config
        let config = config.validated();

        // Compile auth patterns with validation logging
        // SECURITY: Invalid patterns are logged and skipped rather than causing panics
        let auth_patterns: Vec<Regex> = config
            .auth_path_patterns
            .iter()
            .filter_map(|p| {
                match Regex::new(p) {
                    Ok(re) => Some(re),
                    Err(e) => {
                        warn!(
                            pattern = %p,
                            error = %e,
                            "Invalid auth_path_pattern in StuffingConfig - pattern will be skipped"
                        );
                        None
                    }
                }
            })
            .collect();

        let (shutdown_tx, shutdown_rx) = bounded(1);
        let shutdown = Arc::new(AtomicBool::new(false));

        let entity_auth = DashMap::with_capacity(config.max_entities.min(10_000));
        let distributed = DashMap::with_capacity(config.max_distributed_attacks.min(1_000));
        let username_targeted = DashMap::with_capacity(config.max_distributed_attacks.min(1_000));

        // Clone for cleanup thread
        let entity_auth_clone = entity_auth.clone();
        let distributed_clone = distributed.clone();
        let username_targeted_clone = username_targeted.clone();
        let shutdown_flag = shutdown.clone();
        let cleanup_interval = config.cleanup_interval_ms;
        let failure_window = config.failure_window_ms;
        let distributed_window = config.distributed_window_ms;
        let username_window = config.username_targeted_window_ms;

        let handle = thread::spawn(move || {
            Self::cleanup_loop(
                entity_auth_clone,
                distributed_clone,
                username_targeted_clone,
                shutdown_rx,
                shutdown_flag,
                cleanup_interval,
                failure_window,
                distributed_window,
                username_window,
            );
        });

        // Initialize global velocity tracker
        let global_velocity = GlobalVelocityTracker::new(
            config.global_velocity_max_track,
            config.global_velocity_window_ms,
        );

        Self {
            entity_auth,
            distributed,
            username_targeted,
            global_velocity: RwLock::new(global_velocity),
            takeovers: RwLock::new(VecDeque::with_capacity(config.max_takeover_alerts)),
            events: RwLock::new(VecDeque::with_capacity(1000)),
            auth_patterns,
            config,
            shutdown,
            shutdown_tx,
            cleanup_handle: Some(handle),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(StuffingConfig::default())
    }

    /// Background cleanup loop.
    fn cleanup_loop(
        entity_auth: DashMap<EntityEndpointKey, AuthMetrics>,
        distributed: DashMap<String, DistributedAttack>,
        username_targeted: DashMap<String, UsernameTargetedAttack>,
        shutdown_rx: Receiver<()>,
        shutdown: Arc<AtomicBool>,
        cleanup_interval_ms: u64,
        failure_window_ms: u64,
        distributed_window_ms: u64,
        username_window_ms: u64,
    ) {
        let cleanup_interval = std::time::Duration::from_millis(cleanup_interval_ms);

        loop {
            match shutdown_rx.recv_timeout(cleanup_interval) {
                Ok(()) | Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }

                    let now = now_ms();

                    // Clean expired entity auth records
                    let entity_threshold = now.saturating_sub(failure_window_ms * 2);
                    entity_auth.retain(|_, metrics| metrics.last_attempt >= entity_threshold);

                    // Clean expired distributed attacks
                    let distributed_threshold = now.saturating_sub(distributed_window_ms);
                    distributed.retain(|_, attack| attack.last_activity >= distributed_threshold);

                    // Clean expired username-targeted attacks
                    let username_threshold = now.saturating_sub(username_window_ms);
                    username_targeted.retain(|_, attack| attack.last_activity >= username_threshold);
                }
            }
        }
    }

    /// Check if an endpoint is an auth endpoint.
    pub fn is_auth_endpoint(&self, path: &str) -> bool {
        self.auth_patterns.iter().any(|re| re.is_match(path))
    }

    /// Record an auth attempt (request phase).
    ///
    /// Call this when a request hits an auth endpoint.
    /// Returns a verdict that may adjust risk or block.
    pub fn record_attempt(&self, attempt: &AuthAttempt) -> StuffingVerdict {
        let now = attempt.timestamp;
        let key = EntityEndpointKey::new(&attempt.entity_id, &attempt.endpoint);

        // Get or create metrics
        let mut metrics = self
            .entity_auth
            .entry(key.clone())
            .or_insert_with(|| AuthMetrics::new(attempt.entity_id.clone(), attempt.endpoint.clone(), now));

        // Check if window has expired and reset
        if now.saturating_sub(metrics.window_start) > self.config.failure_window_ms {
            metrics.reset_window(now);
        }

        metrics.last_attempt = now;

        // Check thresholds based on current failures (before this attempt's result)
        let failures = metrics.failures;
        drop(metrics); // Release lock before returning

        // Track distributed attack if fingerprint provided
        if let Some(ref fingerprint) = attempt.fingerprint {
            self.track_distributed_attempt(fingerprint, &attempt.endpoint, &attempt.entity_id, now);
        }

        // Track username-targeted attack if username provided
        if let Some(ref username) = attempt.username {
            self.track_username_targeted_attempt(username, &attempt.endpoint, &attempt.entity_id, now);
        }

        // Evaluate verdict based on failure history
        if failures >= self.config.failure_threshold_block {
            StuffingVerdict::block(format!(
                "Credential stuffing: {} failures in window",
                failures
            ))
        } else if failures >= self.config.failure_threshold_high {
            let event = StuffingEvent::SuspiciousFailureRate {
                entity_id: attempt.entity_id.clone(),
                endpoint: attempt.endpoint.clone(),
                failures,
                window_ms: self.config.failure_window_ms,
                severity: StuffingSeverity::High,
            };
            self.emit_event(event);

            StuffingVerdict::suspicious(
                format!("High failure rate: {} failures", failures),
                StuffingSeverity::High,
            )
        } else if failures >= self.config.failure_threshold_suspicious {
            let event = StuffingEvent::SuspiciousFailureRate {
                entity_id: attempt.entity_id.clone(),
                endpoint: attempt.endpoint.clone(),
                failures,
                window_ms: self.config.failure_window_ms,
                severity: StuffingSeverity::Medium,
            };
            self.emit_event(event);

            StuffingVerdict::suspicious(
                format!("Suspicious failure rate: {} failures", failures),
                StuffingSeverity::Medium,
            )
        } else {
            // Check for distributed attack (fingerprint-based)
            if let Some(ref fingerprint) = attempt.fingerprint {
                if let Some(verdict) = self.check_distributed_attack(fingerprint, &attempt.endpoint)
                {
                    return verdict;
                }
            }

            // Check for username-targeted attack
            if let Some(ref username) = attempt.username {
                if let Some(verdict) = self.check_username_targeted_attack(username, &attempt.endpoint)
                {
                    return verdict;
                }
            }

            // Check for global velocity spike
            if let Some(verdict) = self.check_global_velocity(now) {
                return verdict;
            }

            StuffingVerdict::Allow
        }
    }

    /// Record an auth result (response phase).
    ///
    /// Call this when auth response is known (success/failure).
    /// Checks for account takeover pattern.
    pub fn record_result(&self, result: &AuthResult) -> Option<TakeoverAlert> {
        let now = result.timestamp;
        let key = EntityEndpointKey::new(&result.entity_id, &result.endpoint);

        // Get or create metrics
        let mut entry = self.entity_auth.entry(key.clone()).or_insert_with(|| {
            AuthMetrics::new(result.entity_id.clone(), result.endpoint.clone(), now)
        });

        let metrics = entry.value_mut();

        if result.success {
            // Check for takeover pattern BEFORE updating metrics
            let prior_failures = metrics.failures;
            let failure_window = now.saturating_sub(metrics.window_start);

            metrics.record_success(now);

            // Takeover detection: success after many failures
            if prior_failures >= self.config.takeover_min_failures
                && failure_window <= self.config.takeover_window_ms
            {
                let alert = TakeoverAlert::new(
                    result.entity_id.clone(),
                    result.endpoint.clone(),
                    prior_failures,
                    failure_window,
                    now,
                );

                // Emit event
                let event = StuffingEvent::AccountTakeover {
                    entity_id: result.entity_id.clone(),
                    endpoint: result.endpoint.clone(),
                    prior_failures,
                    severity: StuffingSeverity::Critical,
                };
                self.emit_event(event);

                // Store alert
                self.store_takeover_alert(alert.clone());

                // Reset window after takeover (start fresh monitoring)
                metrics.reset_window(now);

                return Some(alert);
            }

            // Reset window on success (normal behavior)
            metrics.reset_window(now);
        } else {
            // Record failure
            metrics.record_failure(now);

            // Track global velocity
            drop(entry); // Release entry lock before acquiring global lock
            self.record_global_velocity_failure(now);

            // Track username-targeted failure if username provided
            if let Some(ref username) = result.username {
                self.record_username_targeted_failure(username, &result.endpoint, now);
            }

            // Re-acquire entry for low-and-slow check
            let entry = self.entity_auth.get(&key);
            if let Some(metrics) = entry {
                // Check for low-and-slow pattern
                if metrics.detect_low_and_slow(
                    self.config.low_slow_min_hours,
                    self.config.low_slow_min_per_hour,
                ) {
                    let event = StuffingEvent::LowAndSlow {
                        entity_id: result.entity_id.clone(),
                        endpoint: result.endpoint.clone(),
                        hours_active: self.config.low_slow_min_hours,
                        total_failures: metrics.total_failures,
                        severity: StuffingSeverity::Medium,
                    };
                    self.emit_event(event);
                }
            }
        }

        None
    }

    /// Track a distributed attack attempt.
    fn track_distributed_attempt(
        &self,
        fingerprint: &str,
        endpoint: &str,
        entity_id: &str,
        now: u64,
    ) {
        let key = format!("{}:{}", fingerprint, endpoint);

        let mut entry = self.distributed.entry(key).or_insert_with(|| {
            DistributedAttack::new(
                fingerprint.to_string(),
                endpoint.to_string(),
                entity_id.to_string(),
                now,
            )
        });

        let attack = entry.value_mut();
        attack.add_entity(entity_id.to_string(), now);
    }

    /// Check for distributed attack and return verdict if detected.
    fn check_distributed_attack(
        &self,
        fingerprint: &str,
        endpoint: &str,
    ) -> Option<StuffingVerdict> {
        let key = format!("{}:{}", fingerprint, endpoint);

        if let Some(attack) = self.distributed.get(&key) {
            if attack.entity_count() >= self.config.distributed_min_ips {
                let event = StuffingEvent::DistributedAttackDetected {
                    fingerprint: fingerprint.to_string(),
                    endpoint: endpoint.to_string(),
                    ip_count: attack.entity_count(),
                    total_failures: attack.total_failures,
                    severity: StuffingSeverity::High,
                };
                self.emit_event(event);

                return Some(StuffingVerdict::suspicious_with_risk(
                    format!(
                        "Distributed attack: {} IPs with same fingerprint",
                        attack.entity_count()
                    ),
                    StuffingSeverity::High,
                    30, // +30 risk as per spec
                ));
            }
        }

        None
    }

    /// Record a failure in distributed attack tracking.
    pub fn record_distributed_failure(&self, fingerprint: &str, endpoint: &str, now: u64) {
        let key = format!("{}:{}", fingerprint, endpoint);

        if let Some(mut entry) = self.distributed.get_mut(&key) {
            entry.value_mut().record_failure(now);
        }
    }

    /// Track a username-targeted attack attempt.
    ///
    /// SECURITY: Tracks multiple IPs attempting the same username to detect
    /// coordinated credential stuffing that evades per-IP rate limiting.
    fn track_username_targeted_attempt(
        &self,
        username: &str,
        endpoint: &str,
        entity_id: &str,
        now: u64,
    ) {
        let key = format!("{}:{}", username, endpoint);

        let mut entry = self.username_targeted.entry(key).or_insert_with(|| {
            UsernameTargetedAttack::new(
                username.to_string(),
                endpoint.to_string(),
                entity_id.to_string(),
                now,
            )
        });

        let attack = entry.value_mut();
        attack.add_ip(entity_id.to_string(), now);
    }

    /// Record a failure for username-targeted attack tracking.
    fn record_username_targeted_failure(&self, username: &str, endpoint: &str, now: u64) {
        let key = format!("{}:{}", username, endpoint);

        if let Some(mut entry) = self.username_targeted.get_mut(&key) {
            entry.value_mut().record_failure(now);
        }
    }

    /// Check for username-targeted attack and return verdict if detected.
    ///
    /// SECURITY: Detects when many IPs target the same username, indicating
    /// a botnet attack on a specific account (possibly from breach list).
    fn check_username_targeted_attack(
        &self,
        username: &str,
        endpoint: &str,
    ) -> Option<StuffingVerdict> {
        let key = format!("{}:{}", username, endpoint);

        if let Some(attack) = self.username_targeted.get(&key) {
            let ip_count = attack.ip_count();
            let failures = attack.total_failures;

            // Check if we exceed thresholds
            if ip_count >= self.config.username_targeted_min_ips
                && failures >= self.config.username_targeted_min_failures
            {
                let event = StuffingEvent::UsernameTargetedAttack {
                    username: username.to_string(),
                    endpoint: endpoint.to_string(),
                    ip_count,
                    total_failures: failures,
                    severity: StuffingSeverity::High,
                };
                self.emit_event(event);

                return Some(StuffingVerdict::suspicious_with_risk(
                    format!(
                        "Username-targeted attack: {} IPs targeting '{}'",
                        ip_count, username
                    ),
                    StuffingSeverity::High,
                    35, // Higher risk than distributed (+35 vs +30) since targeted
                ));
            }
        }

        None
    }

    /// Record a failure in global velocity tracking.
    fn record_global_velocity_failure(&self, now: u64) {
        let mut tracker = self.global_velocity.write();
        tracker.record_failure(now);
    }

    /// Check for global velocity spike and return verdict if detected.
    ///
    /// SECURITY: Detects sudden spikes in overall auth failure rate that
    /// may indicate a coordinated attack across many IPs/usernames.
    fn check_global_velocity(&self, now: u64) -> Option<StuffingVerdict> {
        let tracker = self.global_velocity.read();
        let rate = tracker.failure_rate(now);

        if rate >= self.config.global_velocity_threshold_rate {
            let count = tracker.failure_count(now);
            drop(tracker); // Release lock before emitting event

            let event = StuffingEvent::GlobalVelocitySpike {
                failure_rate: rate,
                failure_count: count,
                threshold_rate: self.config.global_velocity_threshold_rate,
                severity: StuffingSeverity::High,
            };
            self.emit_event(event);

            return Some(StuffingVerdict::suspicious_with_risk(
                format!(
                    "Global velocity spike: {:.1} failures/sec (threshold: {:.1})",
                    rate, self.config.global_velocity_threshold_rate
                ),
                StuffingSeverity::High,
                20, // Lower than targeted attacks since it affects everyone
            ));
        }

        None
    }

    /// Emit an event for alerting.
    fn emit_event(&self, event: StuffingEvent) {
        let mut events = self.events.write();
        if events.len() >= 1000 {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Store a takeover alert.
    fn store_takeover_alert(&self, alert: TakeoverAlert) {
        let mut takeovers = self.takeovers.write();
        if takeovers.len() >= self.config.max_takeover_alerts {
            takeovers.pop_front();
        }
        takeovers.push_back(alert);
    }

    // --- Query APIs ---

    /// Get entity's auth metrics.
    pub fn get_entity_metrics(&self, entity_id: &str, endpoint: &str) -> Option<AuthMetrics> {
        let key = EntityEndpointKey::new(entity_id, endpoint);
        self.entity_auth.get(&key).map(|e| e.clone())
    }

    /// Get all entity metrics.
    pub fn get_all_entity_metrics(&self) -> Vec<AuthMetrics> {
        self.entity_auth.iter().map(|e| e.value().clone()).collect()
    }

    /// Get active distributed attacks.
    pub fn get_distributed_attacks(&self) -> Vec<DistributedAttack> {
        self.distributed.iter().map(|e| e.value().clone()).collect()
    }

    /// Get recent takeover alerts.
    pub fn get_takeover_alerts(&self, since: u64) -> Vec<TakeoverAlert> {
        let takeovers = self.takeovers.read();
        takeovers
            .iter()
            .filter(|a| a.success_at >= since)
            .cloned()
            .collect()
    }

    /// Get all takeover alerts.
    pub fn get_all_takeover_alerts(&self) -> Vec<TakeoverAlert> {
        let takeovers = self.takeovers.read();
        takeovers.iter().cloned().collect()
    }

    /// Get recent events since timestamp.
    pub fn get_events(&self, since: u64) -> Vec<StuffingEvent> {
        let events = self.events.read();
        // Note: Events don't currently have timestamps - would need to add for proper filtering
        // For now, return all events (caller should drain_events() after processing)
        let _ = since; // Acknowledge param for future use
        events.iter().cloned().collect()
    }

    /// Get all events.
    pub fn drain_events(&self) -> Vec<StuffingEvent> {
        let mut events = self.events.write();
        events.drain(..).collect()
    }

    /// Get statistics.
    pub fn get_stats(&self) -> StuffingStats {
        let entity_count = self.entity_auth.len();
        let distributed_count = self.distributed.len();
        let takeover_count = self.takeovers.read().len();
        let event_count = self.events.read().len();

        // Calculate totals
        let mut total_failures: u64 = 0;
        let mut total_successes: u64 = 0;
        let mut suspicious_entities: usize = 0;

        for entry in self.entity_auth.iter() {
            let metrics = entry.value();
            total_failures += metrics.total_failures;
            total_successes += metrics.total_successes;
            if metrics.failures >= self.config.failure_threshold_suspicious {
                suspicious_entities += 1;
            }
        }

        StuffingStats {
            entity_count,
            distributed_attack_count: distributed_count,
            takeover_alert_count: takeover_count,
            event_count,
            total_failures,
            total_successes,
            suspicious_entities,
        }
    }

    /// Clear all data.
    pub fn clear(&self) {
        self.entity_auth.clear();
        self.distributed.clear();
        self.takeovers.write().clear();
        self.events.write().clear();
    }

    /// Get entity count.
    pub fn len(&self) -> usize {
        self.entity_auth.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entity_auth.is_empty()
    }

    /// Stop the detector (cleanup thread).
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
    }

    /// Export state for persistence.
    pub fn export(&self) -> StuffingState {
        StuffingState {
            entity_metrics: self.get_all_entity_metrics(),
            distributed_attacks: self.get_distributed_attacks(),
            takeover_alerts: self.get_all_takeover_alerts(),
        }
    }

    /// Import state from persistence.
    pub fn import(&self, state: StuffingState) {
        for metrics in state.entity_metrics {
            let key = EntityEndpointKey::new(&metrics.entity_id, &metrics.endpoint);
            self.entity_auth.insert(key, metrics);
        }

        for attack in state.distributed_attacks {
            let key = format!("{}:{}", attack.fingerprint, attack.endpoint);
            self.distributed.insert(key, attack);
        }

        let mut takeovers = self.takeovers.write();
        for alert in state.takeover_alerts {
            if takeovers.len() < self.config.max_takeover_alerts {
                takeovers.push_back(alert);
            }
        }
    }
}

impl Drop for CredentialStuffingDetector {
    fn drop(&mut self) {
        self.stop();
        if let Some(handle) = self.cleanup_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Detector statistics.
#[derive(Debug, Clone, Default)]
pub struct StuffingStats {
    /// Number of tracked entities
    pub entity_count: usize,
    /// Number of active distributed attacks
    pub distributed_attack_count: usize,
    /// Number of takeover alerts
    pub takeover_alert_count: usize,
    /// Number of events in queue
    pub event_count: usize,
    /// Total failures recorded
    pub total_failures: u64,
    /// Total successes recorded
    pub total_successes: u64,
    /// Entities above suspicious threshold
    pub suspicious_entities: usize,
}

/// Exportable state for persistence/HA sync.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StuffingState {
    pub entity_metrics: Vec<AuthMetrics>,
    pub distributed_attacks: Vec<DistributedAttack>,
    pub takeover_alerts: Vec<TakeoverAlert>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StuffingConfig {
        StuffingConfig {
            failure_window_ms: 60_000, // 1 minute for tests
            failure_threshold_suspicious: 3,
            failure_threshold_high: 5,
            failure_threshold_block: 10,
            distributed_min_ips: 3,
            distributed_window_ms: 60_000,
            takeover_window_ms: 60_000,
            takeover_min_failures: 3,
            low_slow_min_hours: 2,
            low_slow_min_per_hour: 1,
            cleanup_interval_ms: 60_000,
            ..Default::default()
        }
    }

    #[test]
    fn test_is_auth_endpoint() {
        let detector = CredentialStuffingDetector::with_defaults();

        assert!(detector.is_auth_endpoint("/api/login"));
        assert!(detector.is_auth_endpoint("/api/auth/token"));
        assert!(detector.is_auth_endpoint("/v1/signin"));
        assert!(detector.is_auth_endpoint("/oauth/authorize"));

        assert!(!detector.is_auth_endpoint("/api/users"));
        assert!(!detector.is_auth_endpoint("/api/products"));
    }

    #[test]
    fn test_invalid_patterns_are_skipped_gracefully() {
        // SECURITY: Invalid regex patterns should NOT cause panics
        // They should be logged and skipped
        let config = StuffingConfig {
            auth_path_patterns: vec![
                r"(?i)/valid-login".to_string(),
                r"[invalid(regex".to_string(),   // Invalid: unclosed bracket
                r"(?i)/another-valid".to_string(),
                r"*invalid*".to_string(),         // Invalid: nothing to repeat
            ],
            ..Default::default()
        };

        // This should NOT panic even with invalid patterns
        let detector = CredentialStuffingDetector::new(config);

        // Valid patterns should still work
        assert!(detector.is_auth_endpoint("/valid-login"));
        assert!(detector.is_auth_endpoint("/another-valid"));

        // Invalid patterns are skipped, not matched
        assert!(!detector.is_auth_endpoint("/something-else"));
    }

    #[test]
    fn test_record_attempt_allow() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        let attempt = AuthAttempt::new("1.2.3.4", "/login", now);
        let verdict = detector.record_attempt(&attempt);

        assert!(verdict.is_allow());
    }

    #[test]
    fn test_record_attempt_suspicious() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record 3 failures first
        for i in 0..3 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i);
            detector.record_result(&result);
        }

        // Now attempt should be suspicious
        let attempt = AuthAttempt::new("1.2.3.4", "/login", now + 100);
        let verdict = detector.record_attempt(&attempt);

        assert!(!verdict.is_allow());
        assert!(!verdict.is_block());
        assert!(verdict.risk_delta() > 0);
    }

    #[test]
    fn test_record_attempt_block() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record 10 failures
        for i in 0..10 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i);
            detector.record_result(&result);
        }

        // Now attempt should be blocked
        let attempt = AuthAttempt::new("1.2.3.4", "/login", now + 100);
        let verdict = detector.record_attempt(&attempt);

        assert!(verdict.is_block());
    }

    #[test]
    fn test_takeover_detection() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record 5 failures
        for i in 0..5 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i * 1000);
            detector.record_result(&result);
        }

        // Then success - should trigger takeover alert
        let result = AuthResult::new("1.2.3.4", "/login", true, now + 10000);
        let alert = detector.record_result(&result);

        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.entity_id, "1.2.3.4");
        assert_eq!(alert.prior_failures, 5);
        assert_eq!(alert.severity, StuffingSeverity::Critical);

        // Check alert stored
        let alerts = detector.get_takeover_alerts(now);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_distributed_attack_detection() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // 3 different IPs with same fingerprint
        let ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"];
        for ip in &ips {
            let attempt =
                AuthAttempt::new(*ip, "/login", now).with_fingerprint("same-fingerprint");
            detector.record_attempt(&attempt);
        }

        // Fourth IP should trigger distributed attack detection
        let attempt = AuthAttempt::new("4.4.4.4", "/login", now).with_fingerprint("same-fingerprint");
        let verdict = detector.record_attempt(&attempt);

        // Should be suspicious due to distributed attack
        assert!(!verdict.is_allow());
        assert_eq!(verdict.risk_delta(), 30);
    }

    #[test]
    fn test_window_reset() {
        let mut config = test_config();
        config.failure_window_ms = 100; // 100ms window for test
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // Record failures
        for i in 0..5 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i);
            detector.record_result(&result);
        }

        // Wait for window to expire
        std::thread::sleep(std::time::Duration::from_millis(150));
        let later = now_ms();

        // New attempt should reset window
        let attempt = AuthAttempt::new("1.2.3.4", "/login", later);
        let verdict = detector.record_attempt(&attempt);

        // Should be allowed since window reset
        assert!(verdict.is_allow());
    }

    #[test]
    fn test_success_resets_window() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record 4 failures (just below block threshold)
        for i in 0..4 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i * 1000);
            detector.record_result(&result);
        }

        // Successful login (without triggering takeover - need 3+ failures)
        let result = AuthResult::new("1.2.3.4", "/login", true, now + 5000);
        let alert = detector.record_result(&result);

        // Takeover detected (4 > 3 min failures)
        assert!(alert.is_some());

        // New attempt should be allowed (window reset after takeover)
        let attempt = AuthAttempt::new("1.2.3.4", "/login", now + 6000);
        let verdict = detector.record_attempt(&attempt);
        assert!(verdict.is_allow());
    }

    #[test]
    fn test_stats() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record some activity
        for i in 0..5 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i * 1000);
            detector.record_result(&result);
        }

        let result = AuthResult::new("5.6.7.8", "/login", true, now + 10000);
        detector.record_result(&result);

        let stats = detector.get_stats();
        assert_eq!(stats.entity_count, 2);
        assert_eq!(stats.total_failures, 5);
        assert_eq!(stats.total_successes, 1);
        assert!(stats.suspicious_entities >= 1);
    }

    #[test]
    fn test_clear() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Add some data
        let result = AuthResult::new("1.2.3.4", "/login", false, now);
        detector.record_result(&result);

        assert!(!detector.is_empty());

        detector.clear();

        assert!(detector.is_empty());
        assert_eq!(detector.get_stats().entity_count, 0);
    }

    #[test]
    fn test_export_import() {
        let detector1 = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record activity
        for i in 0..3 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i * 1000);
            detector1.record_result(&result);
        }

        // Export
        let state = detector1.export();
        assert!(!state.entity_metrics.is_empty());

        // Import into new detector
        let detector2 = CredentialStuffingDetector::new(test_config());
        detector2.import(state);

        assert_eq!(detector1.len(), detector2.len());
    }

    #[test]
    fn test_events_emitted() {
        let detector = CredentialStuffingDetector::new(test_config());
        let now = now_ms();

        // Record enough failures to trigger suspicious
        for i in 0..5 {
            let result = AuthResult::new("1.2.3.4", "/login", false, now + i * 1000);
            detector.record_result(&result);
        }

        // Attempt should emit event
        let attempt = AuthAttempt::new("1.2.3.4", "/login", now + 10000);
        detector.record_attempt(&attempt);

        let events = detector.drain_events();
        assert!(!events.is_empty());
    }

    #[test]
    fn test_username_targeted_attack_detection() {
        let mut config = test_config();
        config.username_targeted_min_ips = 3;
        config.username_targeted_min_failures = 5;
        config.username_targeted_window_ms = 60_000;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // 5 different IPs targeting same username "admin"
        let ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"];
        for (i, ip) in ips.iter().enumerate() {
            // Record attempt to track the IP
            let attempt = AuthAttempt::new(*ip, "/login", now + i as u64 * 100)
                .with_username("admin");
            detector.record_attempt(&attempt);

            // Record failure to increment failure count
            let result = AuthResult::new(*ip, "/login", false, now + i as u64 * 100 + 50)
                .with_username("admin");
            detector.record_result(&result);
        }

        // Next attempt from a 6th IP should detect username-targeted attack
        let attempt = AuthAttempt::new("6.6.6.6", "/login", now + 1000)
            .with_username("admin");
        let verdict = detector.record_attempt(&attempt);

        // Should be suspicious due to username-targeted attack
        assert!(!verdict.is_allow());
        assert_eq!(verdict.risk_delta(), 35); // Higher risk for targeted attacks

        // Check event was emitted
        let events = detector.drain_events();
        let has_username_targeted = events.iter().any(|e| {
            matches!(e, StuffingEvent::UsernameTargetedAttack { username, .. } if username == "admin")
        });
        assert!(has_username_targeted, "Expected UsernameTargetedAttack event");
    }

    #[test]
    fn test_username_targeted_different_usernames_isolated() {
        let mut config = test_config();
        config.username_targeted_min_ips = 3;
        config.username_targeted_min_failures = 5;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // 2 IPs targeting "admin" - not enough
        for (i, ip) in ["1.1.1.1", "2.2.2.2"].iter().enumerate() {
            let attempt = AuthAttempt::new(*ip, "/login", now + i as u64 * 100)
                .with_username("admin");
            detector.record_attempt(&attempt);
            let result = AuthResult::new(*ip, "/login", false, now + i as u64 * 100 + 50)
                .with_username("admin");
            detector.record_result(&result);
        }

        // 2 IPs targeting "user" - not enough
        for (i, ip) in ["3.3.3.3", "4.4.4.4"].iter().enumerate() {
            let attempt = AuthAttempt::new(*ip, "/login", now + i as u64 * 100)
                .with_username("user");
            detector.record_attempt(&attempt);
            let result = AuthResult::new(*ip, "/login", false, now + i as u64 * 100 + 50)
                .with_username("user");
            detector.record_result(&result);
        }

        // Neither username should trigger detection
        let attempt = AuthAttempt::new("5.5.5.5", "/login", now + 1000)
            .with_username("admin");
        let verdict = detector.record_attempt(&attempt);
        assert!(verdict.is_allow(), "Should not detect attack with only 3 IPs");
    }

    #[test]
    fn test_global_velocity_spike_detection() {
        let mut config = test_config();
        config.global_velocity_threshold_rate = 5.0; // 5 failures/sec
        config.global_velocity_window_ms = 1000;     // 1 second window
        config.global_velocity_max_track = 100;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // Record 10 failures in rapid succession (within 1 second = 10/sec rate)
        for i in 0..10 {
            let result = AuthResult::new(
                format!("10.0.0.{}", i),
                "/login",
                false,
                now + i as u64 * 50, // 50ms apart
            );
            detector.record_result(&result);
        }

        // New attempt should detect global velocity spike
        let attempt = AuthAttempt::new("11.11.11.11", "/login", now + 600);
        let verdict = detector.record_attempt(&attempt);

        // Should be suspicious due to global velocity spike
        assert!(!verdict.is_allow());
        assert_eq!(verdict.risk_delta(), 20); // Global velocity risk

        // Check event was emitted
        let events = detector.drain_events();
        let has_velocity_spike = events.iter().any(|e| {
            matches!(e, StuffingEvent::GlobalVelocitySpike { .. })
        });
        assert!(has_velocity_spike, "Expected GlobalVelocitySpike event");
    }

    #[test]
    fn test_global_velocity_below_threshold() {
        let mut config = test_config();
        config.global_velocity_threshold_rate = 100.0; // Very high threshold
        config.global_velocity_window_ms = 1000;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // Record a few failures
        for i in 0..3 {
            let result = AuthResult::new(format!("10.0.0.{}", i), "/login", false, now + i as u64 * 100);
            detector.record_result(&result);
        }

        // Should be allowed - not enough for velocity spike
        let attempt = AuthAttempt::new("11.11.11.11", "/login", now + 500);
        let verdict = detector.record_attempt(&attempt);

        assert!(verdict.is_allow());
    }

    #[test]
    fn test_distributed_vs_username_targeted_priority() {
        // Tests that fingerprint-based distributed detection takes priority
        let mut config = test_config();
        config.distributed_min_ips = 3;
        config.username_targeted_min_ips = 3;
        config.username_targeted_min_failures = 3;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // Set up both conditions: same fingerprint AND same username
        let ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"];
        for (i, ip) in ips.iter().enumerate() {
            let attempt = AuthAttempt::new(*ip, "/login", now + i as u64 * 100)
                .with_fingerprint("shared-fp")
                .with_username("admin");
            detector.record_attempt(&attempt);
            let result = AuthResult::new(*ip, "/login", false, now + i as u64 * 100 + 50)
                .with_username("admin");
            detector.record_result(&result);
        }

        // Next attempt should detect distributed attack first (fingerprint has priority)
        let attempt = AuthAttempt::new("5.5.5.5", "/login", now + 1000)
            .with_fingerprint("shared-fp")
            .with_username("admin");
        let verdict = detector.record_attempt(&attempt);

        // Should be detected - either distributed or username-targeted
        assert!(!verdict.is_allow());
        // Distributed gives +30, username-targeted gives +35
        // If distributed is checked first, we get +30
        assert_eq!(verdict.risk_delta(), 30, "Fingerprint-based detection should take priority");
    }

    #[test]
    fn test_username_tracking_across_results() {
        let mut config = test_config();
        config.username_targeted_min_ips = 2;
        config.username_targeted_min_failures = 3;
        let detector = CredentialStuffingDetector::new(config);
        let now = now_ms();

        // Two IPs, but need 3 failures
        let attempt1 = AuthAttempt::new("1.1.1.1", "/login", now)
            .with_username("victim");
        detector.record_attempt(&attempt1);
        let result1 = AuthResult::new("1.1.1.1", "/login", false, now + 10)
            .with_username("victim");
        detector.record_result(&result1);

        let attempt2 = AuthAttempt::new("2.2.2.2", "/login", now + 100)
            .with_username("victim");
        detector.record_attempt(&attempt2);
        let result2 = AuthResult::new("2.2.2.2", "/login", false, now + 110)
            .with_username("victim");
        detector.record_result(&result2);

        // 2 IPs, 2 failures - not enough failures yet
        let attempt3 = AuthAttempt::new("3.3.3.3", "/login", now + 200)
            .with_username("victim");
        let verdict = detector.record_attempt(&attempt3);
        assert!(verdict.is_allow(), "2 failures should not trigger (need 3)");

        // Third failure pushes over threshold
        let result3 = AuthResult::new("3.3.3.3", "/login", false, now + 210)
            .with_username("victim");
        detector.record_result(&result3);

        // Now should detect
        let attempt4 = AuthAttempt::new("4.4.4.4", "/login", now + 300)
            .with_username("victim");
        let verdict = detector.record_attempt(&attempt4);
        assert!(!verdict.is_allow(), "3 IPs and 3 failures should trigger");
    }
}
