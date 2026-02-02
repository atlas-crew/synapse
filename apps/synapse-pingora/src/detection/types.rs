//! Credential stuffing detection types and configuration.
//!
//! Provides types for detecting credential stuffing attacks:
//! - Per-entity auth failure tracking
//! - Distributed attack correlation via fingerprint
//! - Account takeover detection (success after failures)
//! - Low-and-slow pattern detection
//!
//! Not on hot path - runs per-auth-request, not every request.

use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};

/// Severity levels for credential stuffing events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum StuffingSeverity {
    /// Low severity - informational
    Low = 0,
    /// Medium severity - worth monitoring
    Medium = 1,
    /// High severity - likely attack
    High = 2,
    /// Critical severity - confirmed attack or takeover
    Critical = 3,
}

impl StuffingSeverity {
    /// Get string name for severity.
    pub const fn as_str(&self) -> &'static str {
        match self {
            StuffingSeverity::Low => "low",
            StuffingSeverity::Medium => "medium",
            StuffingSeverity::High => "high",
            StuffingSeverity::Critical => "critical",
        }
    }

    /// Default risk delta for each severity level.
    pub const fn default_risk_delta(&self) -> i32 {
        match self {
            StuffingSeverity::Low => 5,
            StuffingSeverity::Medium => 10,
            StuffingSeverity::High => 25,
            StuffingSeverity::Critical => 50,
        }
    }
}

impl Default for StuffingSeverity {
    fn default() -> Self {
        StuffingSeverity::Medium
    }
}

/// Verdict from credential stuffing analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StuffingVerdict {
    /// Allow the request
    Allow,
    /// Flag as suspicious with reason and risk adjustment
    Suspicious {
        reason: String,
        risk_delta: i32,
        severity: StuffingSeverity,
    },
    /// Block the request
    Block { reason: String },
}

impl StuffingVerdict {
    /// Create a suspicious verdict with default risk delta from severity.
    pub fn suspicious(reason: impl Into<String>, severity: StuffingSeverity) -> Self {
        StuffingVerdict::Suspicious {
            reason: reason.into(),
            risk_delta: severity.default_risk_delta(),
            severity,
        }
    }

    /// Create a suspicious verdict with custom risk delta.
    pub fn suspicious_with_risk(
        reason: impl Into<String>,
        severity: StuffingSeverity,
        risk_delta: i32,
    ) -> Self {
        StuffingVerdict::Suspicious {
            reason: reason.into(),
            risk_delta,
            severity,
        }
    }

    /// Create a block verdict.
    pub fn block(reason: impl Into<String>) -> Self {
        StuffingVerdict::Block {
            reason: reason.into(),
        }
    }

    /// Check if this verdict is Allow.
    pub fn is_allow(&self) -> bool {
        matches!(self, StuffingVerdict::Allow)
    }

    /// Check if this verdict is Block.
    pub fn is_block(&self) -> bool {
        matches!(self, StuffingVerdict::Block { .. })
    }

    /// Get the risk delta (0 for Allow/Block).
    pub fn risk_delta(&self) -> i32 {
        match self {
            StuffingVerdict::Suspicious { risk_delta, .. } => *risk_delta,
            _ => 0,
        }
    }
}

/// Per-entity authentication metrics.
///
/// Tracks auth attempts for a single entity (IP) against auth endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMetrics {
    /// Entity identifier (IP address)
    pub entity_id: String,
    /// Endpoint being tracked (e.g., "/api/login")
    pub endpoint: String,

    // Sliding window metrics
    /// Failed auth attempts in current window
    pub failures: u32,
    /// Successful auth attempts in current window
    pub successes: u32,
    /// Window start timestamp (ms since epoch)
    pub window_start: u64,
    /// Last attempt timestamp (ms since epoch)
    pub last_attempt: u64,

    // Historical totals
    /// Total failed attempts (lifetime)
    pub total_failures: u64,
    /// Total successful attempts (lifetime)
    pub total_successes: u64,

    // Low-and-slow detection
    /// Hourly failure buckets (24 hours)
    pub hourly_failures: [u32; 24],
    /// Current hour index (0-23)
    pub current_hour_index: u8,
    /// Last hour rotation timestamp
    pub last_hour_rotation: u64,
}

impl AuthMetrics {
    /// Create new auth metrics for an entity/endpoint pair.
    pub fn new(entity_id: String, endpoint: String, now: u64) -> Self {
        Self {
            entity_id,
            endpoint,
            failures: 0,
            successes: 0,
            window_start: now,
            last_attempt: now,
            total_failures: 0,
            total_successes: 0,
            hourly_failures: [0; 24],
            current_hour_index: 0,
            last_hour_rotation: now,
        }
    }

    /// Record a failed attempt.
    pub fn record_failure(&mut self, now: u64) {
        self.failures += 1;
        self.total_failures += 1;
        self.last_attempt = now;
        self.update_hourly(now, true);
    }

    /// Record a successful attempt.
    pub fn record_success(&mut self, now: u64) {
        self.successes += 1;
        self.total_successes += 1;
        self.last_attempt = now;
    }

    /// Reset sliding window.
    pub fn reset_window(&mut self, now: u64) {
        self.failures = 0;
        self.successes = 0;
        self.window_start = now;
    }

    /// Update hourly buckets for low-and-slow detection.
    fn update_hourly(&mut self, now: u64, is_failure: bool) {
        const HOUR_MS: u64 = 60 * 60 * 1000;

        let hours_elapsed = now.saturating_sub(self.last_hour_rotation) / HOUR_MS;

        if hours_elapsed > 0 {
            // Rotate buckets
            let rotations = hours_elapsed.min(24) as usize;
            for _ in 0..rotations {
                self.current_hour_index = (self.current_hour_index + 1) % 24;
                self.hourly_failures[self.current_hour_index as usize] = 0;
            }
            self.last_hour_rotation = now;
        }

        if is_failure {
            self.hourly_failures[self.current_hour_index as usize] += 1;
        }
    }

    /// Detect low-and-slow pattern (consistent failures over hours).
    ///
    /// Returns true if failures are spread evenly across multiple hours.
    pub fn detect_low_and_slow(&self, min_hours: usize, min_failures_per_hour: u32) -> bool {
        let active_hours: usize = self
            .hourly_failures
            .iter()
            .filter(|&&f| f >= min_failures_per_hour)
            .count();

        active_hours >= min_hours
    }

    /// Get failure rate (failures per second in current window).
    #[allow(dead_code)]
    pub fn failure_rate(&self, now: u64) -> f64 {
        let window_duration = now.saturating_sub(self.window_start);
        if window_duration == 0 {
            return 0.0;
        }
        (self.failures as f64) / (window_duration as f64 / 1000.0)
    }
}

/// Distributed attack tracking (same fingerprint, multiple IPs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedAttack {
    /// Fingerprint ID correlating the attack
    pub fingerprint: String,
    /// Target endpoint
    pub endpoint: String,
    /// Entity IDs (IPs) participating
    pub entities: HashSet<String>,
    /// Total failures across all entities
    pub total_failures: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Correlation confidence score (0.0-1.0)
    pub correlation_score: f32,
}

impl DistributedAttack {
    /// Create a new distributed attack record.
    pub fn new(fingerprint: String, endpoint: String, entity_id: String, now: u64) -> Self {
        let mut entities = HashSet::new();
        entities.insert(entity_id);
        Self {
            fingerprint,
            endpoint,
            entities,
            total_failures: 0,
            window_start: now,
            last_activity: now,
            correlation_score: 0.0,
        }
    }

    /// Add an entity to the attack.
    pub fn add_entity(&mut self, entity_id: String, now: u64) {
        self.entities.insert(entity_id);
        self.last_activity = now;
        self.update_correlation_score();
    }

    /// Record a failure.
    pub fn record_failure(&mut self, now: u64) {
        self.total_failures += 1;
        self.last_activity = now;
    }

    /// Get number of participating entities (IPs).
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Update correlation score based on entity count and failure rate.
    fn update_correlation_score(&mut self) {
        // Score increases with more entities
        let entity_factor = (self.entities.len() as f32 / 10.0).min(1.0);
        // Score increases with more failures
        let failure_factor = (self.total_failures as f32 / 100.0).min(1.0);
        self.correlation_score = (entity_factor + failure_factor) / 2.0;
    }
}

/// Account takeover alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverAlert {
    /// Entity ID (IP) that succeeded
    pub entity_id: String,
    /// Endpoint where takeover occurred
    pub endpoint: String,
    /// Number of failures before success
    pub prior_failures: u32,
    /// Window duration of failures (ms)
    pub failure_window_ms: u64,
    /// Success timestamp
    pub success_at: u64,
    /// Severity of the alert
    pub severity: StuffingSeverity,
}

impl TakeoverAlert {
    /// Create a new takeover alert.
    pub fn new(
        entity_id: String,
        endpoint: String,
        prior_failures: u32,
        failure_window_ms: u64,
        success_at: u64,
    ) -> Self {
        // Severity based on failure count
        let severity = if prior_failures >= 50 {
            StuffingSeverity::Critical
        } else if prior_failures >= 20 {
            StuffingSeverity::High
        } else {
            StuffingSeverity::Critical // Any takeover is critical
        };

        Self {
            entity_id,
            endpoint,
            prior_failures,
            failure_window_ms,
            success_at,
            severity,
        }
    }
}

/// Credential stuffing event types for alerting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StuffingEvent {
    /// Suspicious failure rate from single entity
    SuspiciousFailureRate {
        entity_id: String,
        endpoint: String,
        failures: u32,
        window_ms: u64,
        severity: StuffingSeverity,
    },
    /// Distributed attack detected (multiple IPs, same fingerprint)
    DistributedAttackDetected {
        fingerprint: String,
        endpoint: String,
        ip_count: usize,
        total_failures: u64,
        severity: StuffingSeverity,
    },
    /// Username-targeted attack detected (multiple IPs targeting same username)
    ///
    /// SECURITY: This indicates a botnet specifically targeting a username,
    /// possibly a high-value account or known credential from a breach.
    UsernameTargetedAttack {
        username: String,
        endpoint: String,
        ip_count: usize,
        total_failures: u64,
        severity: StuffingSeverity,
    },
    /// Global velocity spike detected (abnormal auth failure rate)
    ///
    /// SECURITY: A sudden spike in global auth failures may indicate
    /// a coordinated credential stuffing attack across many targets.
    GlobalVelocitySpike {
        failure_rate: f64,
        failure_count: usize,
        threshold_rate: f64,
        severity: StuffingSeverity,
    },
    /// Account takeover (success after many failures)
    AccountTakeover {
        entity_id: String,
        endpoint: String,
        prior_failures: u32,
        severity: StuffingSeverity,
    },
    /// Low-and-slow attack pattern detected
    LowAndSlow {
        entity_id: String,
        endpoint: String,
        hours_active: usize,
        total_failures: u64,
        severity: StuffingSeverity,
    },
}

impl StuffingEvent {
    /// Get the severity of this event.
    pub fn severity(&self) -> StuffingSeverity {
        match self {
            StuffingEvent::SuspiciousFailureRate { severity, .. } => *severity,
            StuffingEvent::DistributedAttackDetected { severity, .. } => *severity,
            StuffingEvent::UsernameTargetedAttack { severity, .. } => *severity,
            StuffingEvent::GlobalVelocitySpike { severity, .. } => *severity,
            StuffingEvent::AccountTakeover { severity, .. } => *severity,
            StuffingEvent::LowAndSlow { severity, .. } => *severity,
        }
    }

    /// Get the entity ID if applicable.
    pub fn entity_id(&self) -> Option<&str> {
        match self {
            StuffingEvent::SuspiciousFailureRate { entity_id, .. } => Some(entity_id),
            StuffingEvent::AccountTakeover { entity_id, .. } => Some(entity_id),
            StuffingEvent::LowAndSlow { entity_id, .. } => Some(entity_id),
            StuffingEvent::DistributedAttackDetected { .. } => None,
            StuffingEvent::UsernameTargetedAttack { .. } => None,
            StuffingEvent::GlobalVelocitySpike { .. } => None,
        }
    }
}

/// Configuration for credential stuffing detection.
#[derive(Debug, Clone)]
pub struct StuffingConfig {
    // Single IP thresholds
    /// Sliding window duration (ms) - default 5 minutes
    pub failure_window_ms: u64,
    /// Failures to flag as suspicious
    pub failure_threshold_suspicious: u32,
    /// Failures to flag as high risk
    pub failure_threshold_high: u32,
    /// Failures to trigger block
    pub failure_threshold_block: u32,

    // Distributed attack thresholds
    /// Minimum IPs for distributed attack (fingerprint-based)
    pub distributed_min_ips: usize,
    /// Window for distributed attack correlation (ms)
    pub distributed_window_ms: u64,

    // Username-targeted attack thresholds
    /// Minimum IPs targeting same username for alert
    pub username_targeted_min_ips: usize,
    /// Minimum failures against username for alert
    pub username_targeted_min_failures: u64,
    /// Window for username-targeted correlation (ms)
    pub username_targeted_window_ms: u64,

    // Global velocity thresholds
    /// Failure rate (per second) that triggers velocity alert
    pub global_velocity_threshold_rate: f64,
    /// Window for global velocity tracking (ms)
    pub global_velocity_window_ms: u64,
    /// Maximum failures to track in global velocity window
    pub global_velocity_max_track: usize,

    // Takeover detection
    /// Window to check failures before success (ms)
    pub takeover_window_ms: u64,
    /// Minimum failures before success to flag takeover
    pub takeover_min_failures: u32,

    // Low-and-slow detection
    /// Minimum hours with failures for low-and-slow
    pub low_slow_min_hours: usize,
    /// Minimum failures per hour for low-and-slow
    pub low_slow_min_per_hour: u32,

    // Auth endpoint patterns (regex strings)
    /// Path patterns that indicate auth endpoints
    pub auth_path_patterns: Vec<String>,

    // Limits
    /// Maximum entities to track
    pub max_entities: usize,
    /// Maximum distributed attacks to track
    pub max_distributed_attacks: usize,
    /// Maximum takeover alerts to retain
    pub max_takeover_alerts: usize,
    /// Cleanup interval (ms)
    pub cleanup_interval_ms: u64,
}

impl StuffingConfig {
    /// Validate configuration values and return a sanitized config.
    ///
    /// Ensures thresholds are in ascending order and within reasonable bounds.
    /// Windows under 100ms are allowed for testing purposes.
    pub fn validated(mut self) -> Self {
        // First, ensure block threshold has a minimum (highest threshold)
        self.failure_threshold_block = self.failure_threshold_block.max(3);

        // Then constrain high to be less than block
        if self.failure_threshold_high >= self.failure_threshold_block {
            self.failure_threshold_high = self.failure_threshold_block.saturating_sub(1);
        }
        self.failure_threshold_high = self.failure_threshold_high.max(2);

        // Finally constrain suspicious to be less than high
        if self.failure_threshold_suspicious >= self.failure_threshold_high {
            self.failure_threshold_suspicious = self.failure_threshold_high.saturating_sub(1);
        }
        self.failure_threshold_suspicious = self.failure_threshold_suspicious.max(1);

        // Ensure windows are reasonable (min 10ms for testing, typically much higher)
        self.failure_window_ms = self.failure_window_ms.max(10);
        self.distributed_window_ms = self.distributed_window_ms.max(10);
        self.takeover_window_ms = self.takeover_window_ms.max(10);
        self.cleanup_interval_ms = self.cleanup_interval_ms.max(10);

        // Ensure distributed attack needs at least 2 IPs
        self.distributed_min_ips = self.distributed_min_ips.max(2);

        // Ensure takeover needs at least 1 failure
        self.takeover_min_failures = self.takeover_min_failures.max(1);

        // Cap limits to prevent memory exhaustion
        self.max_entities = self.max_entities.min(10_000_000);
        self.max_distributed_attacks = self.max_distributed_attacks.min(100_000);
        self.max_takeover_alerts = self.max_takeover_alerts.min(100_000);

        self
    }
}

impl Default for StuffingConfig {
    fn default() -> Self {
        Self {
            // Single IP thresholds
            failure_window_ms: 5 * 60 * 1000, // 5 minutes
            failure_threshold_suspicious: 5,
            failure_threshold_high: 20,
            failure_threshold_block: 50,

            // Distributed attack (fingerprint-based)
            distributed_min_ips: 3,
            distributed_window_ms: 15 * 60 * 1000, // 15 minutes

            // Username-targeted attack detection
            username_targeted_min_ips: 5,           // 5 different IPs
            username_targeted_min_failures: 10,      // 10 failures total
            username_targeted_window_ms: 10 * 60 * 1000, // 10 minutes

            // Global velocity detection
            global_velocity_threshold_rate: 10.0,    // 10 failures/sec
            global_velocity_window_ms: 60 * 1000,    // 1 minute
            global_velocity_max_track: 5000,         // Track up to 5000 failures

            // Takeover detection
            takeover_window_ms: 5 * 60 * 1000, // 5 minutes
            takeover_min_failures: 5,

            // Low-and-slow
            low_slow_min_hours: 3,
            low_slow_min_per_hour: 2,

            // Default auth patterns
            auth_path_patterns: vec![
                r"(?i)/login".to_string(),
                r"(?i)/auth".to_string(),
                r"(?i)/signin".to_string(),
                r"(?i)/token".to_string(),
                r"(?i)/oauth".to_string(),
                r"(?i)/session".to_string(),
            ],

            // Limits
            max_entities: 100_000,
            max_distributed_attacks: 1_000,
            max_takeover_alerts: 1_000,
            cleanup_interval_ms: 5 * 60 * 1000, // 5 minutes
        }
    }
}

/// Auth attempt input for recording.
#[derive(Debug, Clone)]
pub struct AuthAttempt {
    /// Entity ID (IP address)
    pub entity_id: String,
    /// Endpoint path
    pub endpoint: String,
    /// Optional fingerprint for correlation
    pub fingerprint: Option<String>,
    /// Optional username for targeted attack detection
    pub username: Option<String>,
    /// Timestamp (ms since epoch)
    pub timestamp: u64,
}

impl AuthAttempt {
    /// Create a new auth attempt.
    pub fn new(entity_id: impl Into<String>, endpoint: impl Into<String>, now: u64) -> Self {
        Self {
            entity_id: entity_id.into(),
            endpoint: endpoint.into(),
            fingerprint: None,
            username: None,
            timestamp: now,
        }
    }

    /// Set fingerprint.
    pub fn with_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// Set username for targeted attack detection.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
}

/// Auth result input for recording success/failure.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// Entity ID (IP address)
    pub entity_id: String,
    /// Endpoint path
    pub endpoint: String,
    /// Whether auth succeeded
    pub success: bool,
    /// Optional username for targeted attack detection
    pub username: Option<String>,
    /// Timestamp (ms since epoch)
    pub timestamp: u64,
}

impl AuthResult {
    /// Create a new auth result.
    pub fn new(
        entity_id: impl Into<String>,
        endpoint: impl Into<String>,
        success: bool,
        now: u64,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            endpoint: endpoint.into(),
            success,
            username: None,
            timestamp: now,
        }
    }

    /// Set username for targeted attack detection.
    pub fn with_username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }
}

/// Username-targeted attack tracking (multiple IPs targeting same username).
///
/// SECURITY: Detects distributed credential stuffing where a botnet targets
/// the same username(s) from many different IPs to evade per-IP rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameTargetedAttack {
    /// Target username
    pub username: String,
    /// Endpoint being targeted
    pub endpoint: String,
    /// Entity IDs (IPs) attempting this username
    pub attacking_ips: HashSet<String>,
    /// Total failure count
    pub total_failures: u64,
    /// Window start timestamp
    pub window_start: u64,
    /// Last activity timestamp
    pub last_activity: u64,
}

impl UsernameTargetedAttack {
    /// Create a new username-targeted attack record.
    pub fn new(username: String, endpoint: String, entity_id: String, now: u64) -> Self {
        let mut attacking_ips = HashSet::new();
        attacking_ips.insert(entity_id);
        Self {
            username,
            endpoint,
            attacking_ips,
            total_failures: 0,
            window_start: now,
            last_activity: now,
        }
    }

    /// Add an IP attempting this username.
    pub fn add_ip(&mut self, entity_id: String, now: u64) {
        self.attacking_ips.insert(entity_id);
        self.last_activity = now;
    }

    /// Record a failure.
    pub fn record_failure(&mut self, now: u64) {
        self.total_failures += 1;
        self.last_activity = now;
    }

    /// Get number of unique IPs attacking this username.
    pub fn ip_count(&self) -> usize {
        self.attacking_ips.len()
    }
}

/// Global velocity tracking for overall auth failure rate.
///
/// SECURITY: Detects sudden spikes in global auth failure rate that may
/// indicate a coordinated attack across many IPs/usernames.
#[derive(Debug, Clone)]
pub struct GlobalVelocityTracker {
    /// Sliding window of failure timestamps (ring buffer)
    failure_times: VecDeque<u64>,
    /// Maximum window size
    max_window_size: usize,
    /// Window duration in milliseconds
    window_ms: u64,
}

impl Default for GlobalVelocityTracker {
    fn default() -> Self {
        Self::new(1000, 60_000) // 1000 failures, 60 second window
    }
}

impl GlobalVelocityTracker {
    /// Create a new global velocity tracker.
    pub fn new(max_window_size: usize, window_ms: u64) -> Self {
        Self {
            failure_times: VecDeque::with_capacity(max_window_size),
            max_window_size,
            window_ms,
        }
    }

    /// Record a failure.
    pub fn record_failure(&mut self, now: u64) {
        // Evict old entries
        let threshold = now.saturating_sub(self.window_ms);
        while let Some(&oldest) = self.failure_times.front() {
            if oldest < threshold {
                self.failure_times.pop_front();
            } else {
                break;
            }
        }

        // Add new entry (bounded)
        if self.failure_times.len() < self.max_window_size {
            self.failure_times.push_back(now);
        }
    }

    /// Get current failure rate (failures per second in window).
    pub fn failure_rate(&self, now: u64) -> f64 {
        let threshold = now.saturating_sub(self.window_ms);
        let recent_count = self
            .failure_times
            .iter()
            .filter(|&&t| t >= threshold)
            .count();

        if self.window_ms == 0 {
            return 0.0;
        }

        (recent_count as f64) / (self.window_ms as f64 / 1000.0)
    }

    /// Get failure count in window.
    pub fn failure_count(&self, now: u64) -> usize {
        let threshold = now.saturating_sub(self.window_ms);
        self.failure_times
            .iter()
            .filter(|&&t| t >= threshold)
            .count()
    }
}

/// Composite key for entity+endpoint tracking.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EntityEndpointKey {
    pub entity_id: String,
    pub endpoint: String,
}

impl EntityEndpointKey {
    pub fn new(entity_id: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            entity_id: entity_id.into(),
            endpoint: endpoint.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_default_risk() {
        assert_eq!(StuffingSeverity::Low.default_risk_delta(), 5);
        assert_eq!(StuffingSeverity::Medium.default_risk_delta(), 10);
        assert_eq!(StuffingSeverity::High.default_risk_delta(), 25);
        assert_eq!(StuffingSeverity::Critical.default_risk_delta(), 50);
    }

    #[test]
    fn test_verdict_creation() {
        let allow = StuffingVerdict::Allow;
        assert!(allow.is_allow());
        assert!(!allow.is_block());
        assert_eq!(allow.risk_delta(), 0);

        let suspicious = StuffingVerdict::suspicious("test", StuffingSeverity::High);
        assert!(!suspicious.is_allow());
        assert_eq!(suspicious.risk_delta(), 25);

        let block = StuffingVerdict::block("blocked");
        assert!(block.is_block());
    }

    #[test]
    fn test_auth_metrics_failure_recording() {
        let mut metrics = AuthMetrics::new("1.2.3.4".to_string(), "/login".to_string(), 1000);

        metrics.record_failure(1000);
        metrics.record_failure(2000);
        metrics.record_failure(3000);

        assert_eq!(metrics.failures, 3);
        assert_eq!(metrics.total_failures, 3);
        assert_eq!(metrics.successes, 0);
    }

    #[test]
    fn test_auth_metrics_window_reset() {
        let mut metrics = AuthMetrics::new("1.2.3.4".to_string(), "/login".to_string(), 1000);

        metrics.record_failure(1000);
        metrics.record_failure(2000);
        assert_eq!(metrics.failures, 2);

        metrics.reset_window(5000);
        assert_eq!(metrics.failures, 0);
        assert_eq!(metrics.total_failures, 2); // Total preserved
    }

    #[test]
    fn test_distributed_attack() {
        let mut attack = DistributedAttack::new(
            "fp123".to_string(),
            "/login".to_string(),
            "1.1.1.1".to_string(),
            1000,
        );

        attack.add_entity("2.2.2.2".to_string(), 2000);
        attack.add_entity("3.3.3.3".to_string(), 3000);
        attack.record_failure(3000);
        attack.record_failure(3000);

        assert_eq!(attack.entity_count(), 3);
        assert_eq!(attack.total_failures, 2);
        assert!(attack.correlation_score > 0.0);
    }

    #[test]
    fn test_takeover_alert_severity() {
        let alert = TakeoverAlert::new("1.2.3.4".to_string(), "/login".to_string(), 5, 60000, 1000);
        assert_eq!(alert.severity, StuffingSeverity::Critical);

        let high_alert =
            TakeoverAlert::new("1.2.3.4".to_string(), "/login".to_string(), 25, 60000, 1000);
        assert_eq!(high_alert.severity, StuffingSeverity::High);

        let critical_alert =
            TakeoverAlert::new("1.2.3.4".to_string(), "/login".to_string(), 100, 60000, 1000);
        assert_eq!(critical_alert.severity, StuffingSeverity::Critical);
    }

    #[test]
    fn test_stuffing_event_entity_id() {
        let event = StuffingEvent::SuspiciousFailureRate {
            entity_id: "1.2.3.4".to_string(),
            endpoint: "/login".to_string(),
            failures: 10,
            window_ms: 60000,
            severity: StuffingSeverity::Medium,
        };
        assert_eq!(event.entity_id(), Some("1.2.3.4"));

        let distributed = StuffingEvent::DistributedAttackDetected {
            fingerprint: "fp123".to_string(),
            endpoint: "/login".to_string(),
            ip_count: 5,
            total_failures: 100,
            severity: StuffingSeverity::High,
        };
        assert_eq!(distributed.entity_id(), None);
    }

    #[test]
    fn test_config_defaults() {
        let config = StuffingConfig::default();
        assert_eq!(config.failure_window_ms, 5 * 60 * 1000);
        assert_eq!(config.failure_threshold_suspicious, 5);
        assert_eq!(config.failure_threshold_high, 20);
        assert_eq!(config.failure_threshold_block, 50);
        assert_eq!(config.distributed_min_ips, 3);
        assert!(!config.auth_path_patterns.is_empty());
    }

    #[test]
    fn test_auth_attempt_builder() {
        let attempt = AuthAttempt::new("1.2.3.4", "/login", 1000).with_fingerprint("fp123");
        assert_eq!(attempt.entity_id, "1.2.3.4");
        assert_eq!(attempt.endpoint, "/login");
        assert_eq!(attempt.fingerprint, Some("fp123".to_string()));
    }

    #[test]
    fn test_config_validation_thresholds() {
        // Invalid: suspicious > high > block (inverted)
        let config = StuffingConfig {
            failure_threshold_suspicious: 100,
            failure_threshold_high: 50,
            failure_threshold_block: 10,
            ..Default::default()
        };

        let validated = config.validated();

        // Should be corrected to ascending order
        assert!(validated.failure_threshold_suspicious < validated.failure_threshold_high);
        assert!(validated.failure_threshold_high < validated.failure_threshold_block);
        assert!(validated.failure_threshold_suspicious >= 1);
    }

    #[test]
    fn test_config_validation_windows() {
        // Invalid: zero windows
        let config = StuffingConfig {
            failure_window_ms: 0,
            distributed_window_ms: 0,
            takeover_window_ms: 0,
            cleanup_interval_ms: 0,
            ..Default::default()
        };

        let validated = config.validated();

        // Should be at least 10ms (allows testing with small windows)
        assert!(validated.failure_window_ms >= 10);
        assert!(validated.distributed_window_ms >= 10);
        assert!(validated.takeover_window_ms >= 10);
        assert!(validated.cleanup_interval_ms >= 10);
    }

    #[test]
    fn test_config_validation_limits() {
        // Invalid: very large limits
        let config = StuffingConfig {
            max_entities: usize::MAX,
            max_distributed_attacks: usize::MAX,
            max_takeover_alerts: usize::MAX,
            ..Default::default()
        };

        let validated = config.validated();

        // Should be capped
        assert!(validated.max_entities <= 10_000_000);
        assert!(validated.max_distributed_attacks <= 100_000);
        assert!(validated.max_takeover_alerts <= 100_000);
    }
}
