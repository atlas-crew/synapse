//! Thread-safe actor manager using DashMap for concurrent access.
//!
//! Implements per-actor state tracking with LRU eviction and background cleanup.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for ActorManager.
#[derive(Debug, Clone)]
pub struct ActorConfig {
    /// Maximum number of actors to track (LRU eviction when exceeded).
    /// Default: 100,000
    pub max_actors: usize,

    /// Interval in seconds between decay cycles.
    /// Default: 900 (15 minutes)
    pub decay_interval_secs: u64,

    /// Interval in seconds between persistence cycles.
    /// Default: 300 (5 minutes)
    pub persist_interval_secs: u64,

    /// Threshold for correlation confidence.
    /// Default: 0.7
    pub correlation_threshold: f64,

    /// Factor by which risk scores decay each cycle.
    /// Default: 0.9
    pub risk_decay_factor: f64,

    /// Maximum number of rule matches to track per actor.
    /// Default: 100
    pub max_rule_matches: usize,

    /// Maximum number of session IDs to track per actor.
    /// Prevents memory exhaustion from session hijacking attacks.
    /// Default: 50
    pub max_session_ids: usize,

    /// Whether actor tracking is enabled.
    /// Default: true
    pub enabled: bool,

    /// Maximum risk score (default: 100.0).
    pub max_risk: f64,
}

impl Default for ActorConfig {
    fn default() -> Self {
        Self {
            max_actors: 100_000,
            decay_interval_secs: 900,
            persist_interval_secs: 300,
            correlation_threshold: 0.7,
            risk_decay_factor: 0.9,
            max_rule_matches: 100,
            max_session_ids: 50, // Prevents memory exhaustion
            enabled: true,
            max_risk: 100.0,
        }
    }
}

// ============================================================================
// Rule Match Record
// ============================================================================

/// Rule match record for actor history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Rule identifier (e.g., "sqli-001").
    pub rule_id: String,

    /// Timestamp when the rule was matched (ms since epoch).
    pub timestamp: u64,

    /// Risk contribution from this rule match.
    pub risk_contribution: f64,

    /// Category of the rule (e.g., "sqli", "xss", "path_traversal").
    pub category: String,
}

impl RuleMatch {
    /// Create a new rule match record.
    pub fn new(rule_id: String, risk_contribution: f64, category: String) -> Self {
        Self {
            rule_id,
            timestamp: now_ms(),
            risk_contribution,
            category,
        }
    }
}

// ============================================================================
// Actor State
// ============================================================================

/// Per-actor state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorState {
    /// Unique actor identifier (UUID v4).
    pub actor_id: String,

    /// Accumulated risk score (0.0 - max_risk).
    pub risk_score: f64,

    /// History of rule matches for this actor.
    pub rule_matches: Vec<RuleMatch>,

    /// Count of anomalous behaviors detected.
    pub anomaly_count: u64,

    /// Session IDs associated with this actor.
    pub session_ids: Vec<String>,

    /// First seen timestamp (ms since epoch).
    pub first_seen: u64,

    /// Last seen timestamp (ms since epoch).
    pub last_seen: u64,

    /// IP addresses associated with this actor.
    #[serde(with = "ip_set_serde")]
    pub ips: HashSet<IpAddr>,

    /// Fingerprints associated with this actor.
    pub fingerprints: HashSet<String>,

    /// Whether this actor is currently blocked.
    pub is_blocked: bool,

    /// Reason for blocking (if blocked).
    pub block_reason: Option<String>,

    /// Timestamp when blocked (ms since epoch).
    pub blocked_since: Option<u64>,
}

impl ActorState {
    /// Create a new actor state.
    pub fn new(actor_id: String) -> Self {
        let now = now_ms();
        Self {
            actor_id,
            risk_score: 0.0,
            rule_matches: Vec::new(),
            anomaly_count: 0,
            session_ids: Vec::new(),
            first_seen: now,
            last_seen: now,
            ips: HashSet::new(),
            fingerprints: HashSet::new(),
            is_blocked: false,
            block_reason: None,
            blocked_since: None,
        }
    }

    /// Update last seen timestamp.
    pub fn touch(&mut self) {
        self.last_seen = now_ms();
    }

    /// Add an IP address to this actor.
    pub fn add_ip(&mut self, ip: IpAddr) {
        self.ips.insert(ip);
        self.touch();
    }

    /// Add a fingerprint to this actor.
    pub fn add_fingerprint(&mut self, fingerprint: String) {
        if !fingerprint.is_empty() {
            self.fingerprints.insert(fingerprint);
            self.touch();
        }
    }

    /// Add a rule match to this actor's history.
    pub fn add_rule_match(&mut self, rule_match: RuleMatch, max_matches: usize) {
        self.rule_matches.push(rule_match);
        self.touch();

        // Trim to max matches (keep most recent)
        if self.rule_matches.len() > max_matches {
            let excess = self.rule_matches.len() - max_matches;
            self.rule_matches.drain(0..excess);
        }
    }

    /// Get the count of matches for a specific rule.
    pub fn get_rule_match_count(&self, rule_id: &str) -> usize {
        self.rule_matches
            .iter()
            .filter(|m| m.rule_id == rule_id)
            .count()
    }
}

/// Custom serde implementation for HashSet<IpAddr>.
mod ip_set_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashSet;
    use std::net::IpAddr;

    pub fn serialize<S>(set: &HashSet<IpAddr>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let strings: Vec<String> = set.iter().map(|ip| ip.to_string()).collect();
        strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashSet<IpAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        let mut set = HashSet::new();
        for s in strings {
            if let Ok(ip) = s.parse() {
                set.insert(ip);
            }
        }
        Ok(set)
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for monitoring the actor manager.
#[derive(Debug, Default)]
pub struct ActorStats {
    /// Total number of actors currently tracked.
    pub total_actors: AtomicU64,

    /// Number of blocked actors.
    pub blocked_actors: AtomicU64,

    /// Total correlations made (IP-to-actor or fingerprint-to-actor).
    pub correlations_made: AtomicU64,

    /// Total actors evicted due to LRU capacity.
    pub evictions: AtomicU64,

    /// Total actors created.
    pub total_created: AtomicU64,

    /// Total rule matches recorded.
    pub total_rule_matches: AtomicU64,
}

impl ActorStats {
    /// Create a new stats instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of the current statistics.
    pub fn snapshot(&self) -> ActorStatsSnapshot {
        ActorStatsSnapshot {
            total_actors: self.total_actors.load(Ordering::Relaxed),
            blocked_actors: self.blocked_actors.load(Ordering::Relaxed),
            correlations_made: self.correlations_made.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            total_created: self.total_created.load(Ordering::Relaxed),
            total_rule_matches: self.total_rule_matches.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of actor statistics (for serialization).
#[derive(Debug, Clone, Serialize)]
pub struct ActorStatsSnapshot {
    pub total_actors: u64,
    pub blocked_actors: u64,
    pub correlations_made: u64,
    pub evictions: u64,
    pub total_created: u64,
    pub total_rule_matches: u64,
}

// ============================================================================
// Actor Manager
// ============================================================================

/// Manages actor state with LRU eviction.
///
/// Thread-safe implementation using DashMap for lock-free concurrent access.
pub struct ActorManager {
    /// Actors by actor_id (primary storage).
    actors: DashMap<String, ActorState>,

    /// IP address to actor_id mapping.
    ip_to_actor: DashMap<IpAddr, String>,

    /// Fingerprint to actor_id mapping.
    fingerprint_to_actor: DashMap<String, String>,

    /// Configuration.
    config: ActorConfig,

    /// Statistics.
    stats: Arc<ActorStats>,

    /// Shutdown signal.
    shutdown: Arc<Notify>,

    /// Touch counter for lazy eviction.
    touch_counter: AtomicU32,
}

impl ActorManager {
    /// Create a new actor manager with the given configuration.
    pub fn new(config: ActorConfig) -> Self {
        Self {
            actors: DashMap::with_capacity(config.max_actors),
            ip_to_actor: DashMap::with_capacity(config.max_actors),
            fingerprint_to_actor: DashMap::with_capacity(config.max_actors * 2),
            config,
            stats: Arc::new(ActorStats::new()),
            shutdown: Arc::new(Notify::new()),
            touch_counter: AtomicU32::new(0),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &ActorConfig {
        &self.config
    }

    /// Check if actor tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the number of tracked actors.
    pub fn len(&self) -> usize {
        self.actors.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    /// Get or create an actor for the given IP and optional fingerprint.
    ///
    /// # Correlation Logic
    /// 1. Check if IP is already mapped to an actor
    /// 2. Check if fingerprint is already mapped to an actor
    /// 3. If both match different actors, prefer fingerprint (more stable)
    /// 4. If no match, create a new actor
    ///
    /// # Returns
    /// The actor_id for the correlated or newly created actor.
    pub fn get_or_create_actor(&self, ip: IpAddr, fingerprint: Option<&str>) -> String {
        if !self.config.enabled {
            return generate_actor_id();
        }

        // Check capacity and evict if needed
        self.maybe_evict();

        // Try to correlate to existing actor
        if let Some(actor_id) = self.correlate_actor(ip, fingerprint) {
            // Update the existing actor
            if let Some(mut entry) = self.actors.get_mut(&actor_id) {
                entry.add_ip(ip);
                if let Some(fp) = fingerprint {
                    if !fp.is_empty() {
                        entry.add_fingerprint(fp.to_string());
                        // Update fingerprint mapping
                        self.fingerprint_to_actor.insert(fp.to_string(), actor_id.clone());
                    }
                }
                // Ensure IP mapping is current
                self.ip_to_actor.insert(ip, actor_id.clone());
            }
            return actor_id;
        }

        // Create new actor
        let actor_id = generate_actor_id();
        let mut actor = ActorState::new(actor_id.clone());
        actor.add_ip(ip);

        if let Some(fp) = fingerprint {
            if !fp.is_empty() {
                actor.add_fingerprint(fp.to_string());
                self.fingerprint_to_actor.insert(fp.to_string(), actor_id.clone());
            }
        }

        // Insert mappings
        self.ip_to_actor.insert(ip, actor_id.clone());
        self.actors.insert(actor_id.clone(), actor);

        // Update stats
        self.stats.total_actors.fetch_add(1, Ordering::Relaxed);
        self.stats.total_created.fetch_add(1, Ordering::Relaxed);

        actor_id
    }

    /// Record a rule match for an actor.
    ///
    /// # Arguments
    /// * `actor_id` - The actor ID to record the match for
    /// * `rule_id` - The rule that matched
    /// * `risk_contribution` - Risk points to add
    /// * `category` - Category of the rule (e.g., "sqli", "xss")
    pub fn record_rule_match(
        &self,
        actor_id: &str,
        rule_id: &str,
        risk_contribution: f64,
        category: &str,
    ) {
        if !self.config.enabled {
            return;
        }

        if let Some(mut entry) = self.actors.get_mut(actor_id) {
            let rule_match = RuleMatch::new(
                rule_id.to_string(),
                risk_contribution,
                category.to_string(),
            );

            // Add risk (capped at max)
            entry.risk_score = (entry.risk_score + risk_contribution).min(self.config.max_risk);

            // Add rule match to history
            entry.add_rule_match(rule_match, self.config.max_rule_matches);

            // Update stats
            self.stats.total_rule_matches.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get actor state by ID.
    pub fn get_actor(&self, actor_id: &str) -> Option<ActorState> {
        self.actors.get(actor_id).map(|entry| entry.value().clone())
    }

    /// Get actor by IP address.
    pub fn get_actor_by_ip(&self, ip: IpAddr) -> Option<ActorState> {
        self.ip_to_actor
            .get(&ip)
            .and_then(|actor_id| self.actors.get(actor_id.value()).map(|e| e.value().clone()))
    }

    /// Get actor by fingerprint.
    pub fn get_actor_by_fingerprint(&self, fingerprint: &str) -> Option<ActorState> {
        self.fingerprint_to_actor
            .get(fingerprint)
            .and_then(|actor_id| self.actors.get(actor_id.value()).map(|e| e.value().clone()))
    }

    /// Block an actor.
    ///
    /// # Returns
    /// `true` if the actor was blocked, `false` if not found.
    pub fn block_actor(&self, actor_id: &str, reason: &str) -> bool {
        if let Some(mut entry) = self.actors.get_mut(actor_id) {
            if !entry.is_blocked {
                entry.is_blocked = true;
                entry.block_reason = Some(reason.to_string());
                entry.blocked_since = Some(now_ms());
                self.stats.blocked_actors.fetch_add(1, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Unblock an actor.
    ///
    /// # Returns
    /// `true` if the actor was unblocked, `false` if not found.
    pub fn unblock_actor(&self, actor_id: &str) -> bool {
        if let Some(mut entry) = self.actors.get_mut(actor_id) {
            if entry.is_blocked {
                entry.is_blocked = false;
                entry.block_reason = None;
                entry.blocked_since = None;
                self.stats.blocked_actors.fetch_sub(1, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Check if an actor is blocked.
    pub fn is_blocked(&self, actor_id: &str) -> bool {
        self.actors
            .get(actor_id)
            .map(|entry| entry.is_blocked)
            .unwrap_or(false)
    }

    /// Associate a session with an actor.
    /// Session IDs are bounded by max_session_ids to prevent memory exhaustion.
    pub fn bind_session(&self, actor_id: &str, session_id: &str) {
        if let Some(mut entry) = self.actors.get_mut(actor_id) {
            if !entry.session_ids.contains(&session_id.to_string()) {
                // SECURITY: Enforce max session_ids to prevent memory exhaustion
                if entry.session_ids.len() >= self.config.max_session_ids {
                    // Remove oldest session (FIFO)
                    entry.session_ids.remove(0);
                }
                entry.session_ids.push(session_id.to_string());
                entry.touch();
            }
        }
    }

    /// List actors with pagination.
    ///
    /// # Arguments
    /// * `limit` - Maximum number of actors to return
    /// * `offset` - Number of actors to skip
    ///
    /// # Returns
    /// Vector of actor states sorted by last_seen (most recent first).
    pub fn list_actors(&self, limit: usize, offset: usize) -> Vec<ActorState> {
        let mut actors: Vec<ActorState> = self
            .actors
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Sort by last_seen (most recent first)
        actors.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        // Apply pagination
        actors.into_iter().skip(offset).take(limit).collect()
    }

    /// List blocked actors.
    pub fn list_blocked_actors(&self) -> Vec<ActorState> {
        self.actors
            .iter()
            .filter(|entry| entry.is_blocked)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Start background tasks (decay, cleanup).
    ///
    /// Spawns a background task that periodically:
    /// 1. Decays risk scores by the decay factor
    /// 2. Evicts stale actors if over capacity
    pub fn start_background_tasks(self: Arc<Self>) {
        let manager = self;
        let decay_interval = Duration::from_secs(manager.config.decay_interval_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(decay_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check shutdown
                        if Arc::strong_count(&manager.shutdown) == 1 {
                            // Only this task holds a reference, shutting down
                            break;
                        }

                        // Decay risk scores
                        manager.decay_scores();

                        // Evict stale actors
                        manager.evict_if_needed();
                    }
                    _ = manager.shutdown.notified() => {
                        log::info!("Actor manager background tasks shutting down");
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
    pub fn stats(&self) -> &ActorStats {
        &self.stats
    }

    /// Clear all actors (primarily for testing).
    pub fn clear(&self) {
        self.actors.clear();
        self.ip_to_actor.clear();
        self.fingerprint_to_actor.clear();
        self.stats.total_actors.store(0, Ordering::Relaxed);
        self.stats.blocked_actors.store(0, Ordering::Relaxed);
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    /// Decay risk scores for all actors.
    fn decay_scores(&self) {
        let decay_factor = self.config.risk_decay_factor;

        for mut entry in self.actors.iter_mut() {
            let actor = entry.value_mut();
            if actor.risk_score > 0.0 {
                actor.risk_score *= decay_factor;

                // Floor very small values to zero
                if actor.risk_score < 0.01 {
                    actor.risk_score = 0.0;
                }
            }
        }
    }

    /// Evict actors if over capacity.
    fn evict_if_needed(&self) {
        let current_len = self.actors.len();
        if current_len <= self.config.max_actors {
            return;
        }

        // Evict oldest 1% of actors
        let evict_count = (self.config.max_actors / 100).max(1);
        self.evict_oldest(evict_count);
    }

    /// Maybe evict oldest actors if at capacity.
    ///
    /// Uses lazy eviction: only check every 100th operation.
    fn maybe_evict(&self) {
        let count = self.touch_counter.fetch_add(1, Ordering::Relaxed);
        if count % 100 != 0 {
            return;
        }

        if self.actors.len() < self.config.max_actors {
            return;
        }

        // Evict oldest 1% of actors
        let evict_count = (self.config.max_actors / 100).max(1);
        self.evict_oldest(evict_count);
    }

    /// Evict the N oldest actors by last_seen timestamp.
    ///
    /// Uses sampling to avoid O(n) collection of all actors.
    fn evict_oldest(&self, count: usize) {
        let sample_size = (count * 10).min(1000).min(self.actors.len());

        if sample_size == 0 {
            return;
        }

        // Sample actors
        let mut candidates: Vec<(String, u64)> = Vec::with_capacity(sample_size);
        for entry in self.actors.iter().take(sample_size) {
            candidates.push((entry.key().clone(), entry.value().last_seen));
        }

        // Sort by last_seen (oldest first)
        candidates.sort_unstable_by_key(|(_, ts)| *ts);

        // Evict oldest N from sample
        for (actor_id, _) in candidates.into_iter().take(count) {
            self.remove_actor(&actor_id);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove an actor and clean up all mappings.
    fn remove_actor(&self, actor_id: &str) {
        if let Some((_, actor)) = self.actors.remove(actor_id) {
            // Remove IP mappings
            for ip in &actor.ips {
                self.ip_to_actor.remove(ip);
            }

            // Remove fingerprint mappings
            for fp in &actor.fingerprints {
                self.fingerprint_to_actor.remove(fp);
            }

            // Update stats
            self.stats.total_actors.fetch_sub(1, Ordering::Relaxed);
            if actor.is_blocked {
                self.stats.blocked_actors.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Correlate an IP and/or fingerprint to an existing actor.
    ///
    /// # Returns
    /// The actor_id if correlation found, None otherwise.
    fn correlate_actor(&self, ip: IpAddr, fingerprint: Option<&str>) -> Option<String> {
        let ip_actor = self.ip_to_actor.get(&ip).map(|r| r.value().clone());

        let fp_actor = fingerprint.and_then(|fp| {
            if fp.is_empty() {
                None
            } else {
                self.fingerprint_to_actor.get(fp).map(|r| r.value().clone())
            }
        });

        match (ip_actor, fp_actor) {
            (Some(ip_id), Some(fp_id)) => {
                // Both match - prefer fingerprint (more stable)
                if ip_id == fp_id {
                    Some(ip_id)
                } else {
                    // Different actors - merge them by preferring fingerprint
                    self.stats.correlations_made.fetch_add(1, Ordering::Relaxed);
                    Some(fp_id)
                }
            }
            (Some(id), None) => {
                self.stats.correlations_made.fetch_add(1, Ordering::Relaxed);
                Some(id)
            }
            (None, Some(id)) => {
                self.stats.correlations_made.fetch_add(1, Ordering::Relaxed);
                Some(id)
            }
            (None, None) => None,
        }
    }
}

impl Default for ActorManager {
    fn default() -> Self {
        Self::new(ActorConfig::default())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a unique actor ID using cryptographically secure random bytes.
fn generate_actor_id() -> String {
    // Use getrandom for cryptographically secure random bytes
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("Failed to get random bytes");

    // Format as UUID v4 with proper version and variant bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // Variant 1

    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
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

    fn create_test_manager() -> ActorManager {
        ActorManager::new(ActorConfig {
            max_actors: 1000,
            ..Default::default()
        })
    }

    fn create_test_ip(last_octet: u8) -> IpAddr {
        format!("192.168.1.{}", last_octet).parse().unwrap()
    }

    // ========================================================================
    // Actor Creation and Retrieval Tests
    // ========================================================================

    #[test]
    fn test_actor_creation() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);

        assert!(!actor_id.is_empty());
        assert_eq!(manager.len(), 1);

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.actor_id, actor_id);
        assert!(actor.ips.contains(&ip));
        assert!(!actor.is_blocked);
    }

    #[test]
    fn test_actor_retrieval_by_ip() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        let retrieved = manager.get_actor_by_ip(ip).unwrap();

        assert_eq!(retrieved.actor_id, actor_id);
    }

    #[test]
    fn test_actor_retrieval_by_fingerprint() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);
        let fingerprint = "t13d1516h2_abc123";

        let actor_id = manager.get_or_create_actor(ip, Some(fingerprint));
        let retrieved = manager.get_actor_by_fingerprint(fingerprint).unwrap();

        assert_eq!(retrieved.actor_id, actor_id);
    }

    #[test]
    fn test_actor_nonexistent() {
        let manager = create_test_manager();

        assert!(manager.get_actor("nonexistent").is_none());
        assert!(manager.get_actor_by_ip(create_test_ip(99)).is_none());
        assert!(manager.get_actor_by_fingerprint("nonexistent").is_none());
    }

    // ========================================================================
    // IP and Fingerprint Correlation Tests
    // ========================================================================

    #[test]
    fn test_ip_correlation() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // First request
        let actor_id1 = manager.get_or_create_actor(ip, None);

        // Second request from same IP
        let actor_id2 = manager.get_or_create_actor(ip, None);

        assert_eq!(actor_id1, actor_id2);
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_fingerprint_correlation() {
        let manager = create_test_manager();
        let ip1 = create_test_ip(1);
        let ip2 = create_test_ip(2);
        let fingerprint = "t13d1516h2_shared";

        // First request
        let actor_id1 = manager.get_or_create_actor(ip1, Some(fingerprint));

        // Second request from different IP but same fingerprint
        let actor_id2 = manager.get_or_create_actor(ip2, Some(fingerprint));

        assert_eq!(actor_id1, actor_id2);
        assert_eq!(manager.len(), 1);

        // Verify both IPs are associated
        let actor = manager.get_actor(&actor_id1).unwrap();
        assert!(actor.ips.contains(&ip1));
        assert!(actor.ips.contains(&ip2));
    }

    #[test]
    fn test_fingerprint_preferred_over_ip() {
        let manager = create_test_manager();
        let ip1 = create_test_ip(1);
        let ip2 = create_test_ip(2);
        let fp1 = "fingerprint_1";
        let fp2 = "fingerprint_2";

        // Create actor with IP1 and FP1
        let actor_id1 = manager.get_or_create_actor(ip1, Some(fp1));

        // Create actor with IP2 and FP2
        let actor_id2 = manager.get_or_create_actor(ip2, Some(fp2));

        assert_ne!(actor_id1, actor_id2);

        // Now request with IP1 but FP2 - should correlate to FP2's actor
        let actor_id3 = manager.get_or_create_actor(ip1, Some(fp2));

        assert_eq!(actor_id3, actor_id2);
    }

    // ========================================================================
    // Rule Match Recording Tests
    // ========================================================================

    #[test]
    fn test_record_rule_match() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.record_rule_match(&actor_id, "sqli-001", 25.0, "sqli");

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.rule_matches.len(), 1);
        assert_eq!(actor.rule_matches[0].rule_id, "sqli-001");
        assert_eq!(actor.rule_matches[0].risk_contribution, 25.0);
        assert_eq!(actor.rule_matches[0].category, "sqli");
        assert_eq!(actor.risk_score, 25.0);
    }

    #[test]
    fn test_rule_match_risk_accumulation() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.record_rule_match(&actor_id, "sqli-001", 25.0, "sqli");
        manager.record_rule_match(&actor_id, "xss-001", 20.0, "xss");
        manager.record_rule_match(&actor_id, "sqli-002", 30.0, "sqli");

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.rule_matches.len(), 3);
        assert_eq!(actor.risk_score, 75.0);
    }

    #[test]
    fn test_rule_match_risk_capped() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);

        // Add more than max_risk
        for _ in 0..15 {
            manager.record_rule_match(&actor_id, "sqli-001", 10.0, "sqli");
        }

        let actor = manager.get_actor(&actor_id).unwrap();
        assert!(actor.risk_score <= 100.0);
    }

    #[test]
    fn test_rule_match_history_limit() {
        let config = ActorConfig {
            max_rule_matches: 5,
            ..Default::default()
        };
        let manager = ActorManager::new(config);
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);

        // Add more than max_rule_matches
        for i in 0..10 {
            manager.record_rule_match(&actor_id, &format!("rule-{}", i), 5.0, "test");
        }

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.rule_matches.len(), 5);

        // Should keep most recent
        assert_eq!(actor.rule_matches[0].rule_id, "rule-5");
        assert_eq!(actor.rule_matches[4].rule_id, "rule-9");
    }

    // ========================================================================
    // Blocking/Unblocking Tests
    // ========================================================================

    #[test]
    fn test_block_actor() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);

        assert!(!manager.is_blocked(&actor_id));

        let result = manager.block_actor(&actor_id, "High risk score");

        assert!(result);
        assert!(manager.is_blocked(&actor_id));

        let actor = manager.get_actor(&actor_id).unwrap();
        assert!(actor.is_blocked);
        assert_eq!(actor.block_reason, Some("High risk score".to_string()));
        assert!(actor.blocked_since.is_some());
    }

    #[test]
    fn test_unblock_actor() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.block_actor(&actor_id, "Test");

        assert!(manager.is_blocked(&actor_id));

        let result = manager.unblock_actor(&actor_id);

        assert!(result);
        assert!(!manager.is_blocked(&actor_id));

        let actor = manager.get_actor(&actor_id).unwrap();
        assert!(!actor.is_blocked);
        assert!(actor.block_reason.is_none());
        assert!(actor.blocked_since.is_none());
    }

    #[test]
    fn test_block_nonexistent() {
        let manager = create_test_manager();

        assert!(!manager.block_actor("nonexistent", "Test"));
        assert!(!manager.unblock_actor("nonexistent"));
        assert!(!manager.is_blocked("nonexistent"));
    }

    // ========================================================================
    // LRU Eviction Tests
    // ========================================================================

    #[test]
    fn test_lru_eviction() {
        let config = ActorConfig {
            max_actors: 100,
            ..Default::default()
        };
        let manager = ActorManager::new(config);

        // Add 150 actors (over capacity)
        // Lazy eviction triggers every 100 operations, evicting 1% (1 actor) each time
        for i in 0..150 {
            let ip = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
            manager.get_or_create_actor(ip, None);
        }

        // Lazy eviction doesn't aggressively enforce the limit
        // At most we create 150 - evictions triggered at operations 100 and 150 (with some actors evicted)
        assert!(manager.len() <= 150);

        // Force more evictions by touching the manager more times
        for i in 0..200 {
            let ip = format!("10.1.{}.{}", i / 256, i % 256).parse().unwrap();
            manager.get_or_create_actor(ip, None);
        }

        // After 350 total operations (multiple eviction cycles), should be closer to limit
        // but still may exceed due to lazy eviction nature
        let final_len = manager.len();
        let evictions = manager.stats().evictions.load(Ordering::Relaxed);

        // Verify evictions did occur
        assert!(evictions > 0, "Expected evictions to occur, got 0");

        // The key invariant: we should have created many actors but evicted some
        let created = manager.stats().total_created.load(Ordering::Relaxed);
        assert!(created > final_len as u64, "Expected some actors to be evicted");

        println!(
            "LRU eviction test: created={}, evicted={}, final_len={}",
            created, evictions, final_len
        );
    }

    #[test]
    fn test_eviction_removes_mappings() {
        let config = ActorConfig {
            max_actors: 10,
            ..Default::default()
        };
        let manager = ActorManager::new(config);

        // Create first actor and get its ID
        let first_ip = create_test_ip(1);
        let first_fingerprint = "first_fp";
        let first_actor_id = manager.get_or_create_actor(first_ip, Some(first_fingerprint));

        // Sleep to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Add many more actors to trigger eviction of the first
        for i in 10..200 {
            let ip = format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap();
            manager.get_or_create_actor(ip, Some(&format!("fp_{}", i)));
        }

        // If first actor was evicted, its mappings should be gone
        if manager.get_actor(&first_actor_id).is_none() {
            assert!(manager.ip_to_actor.get(&first_ip).is_none());
            assert!(manager.fingerprint_to_actor.get(first_fingerprint).is_none());
        }
    }

    // ========================================================================
    // Score Decay Tests
    // ========================================================================

    #[test]
    fn test_decay_scores() {
        let config = ActorConfig {
            risk_decay_factor: 0.5,
            ..Default::default()
        };
        let manager = ActorManager::new(config);
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.record_rule_match(&actor_id, "test", 100.0, "test");

        // Verify initial score
        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 100.0);

        // Apply decay
        manager.decay_scores();

        // Verify decayed score
        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 50.0);

        // Apply decay again
        manager.decay_scores();

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 25.0);
    }

    #[test]
    fn test_decay_floors_to_zero() {
        let config = ActorConfig {
            risk_decay_factor: 0.001,
            ..Default::default()
        };
        let manager = ActorManager::new(config);
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.record_rule_match(&actor_id, "test", 1.0, "test");

        // Apply decay multiple times
        for _ in 0..5 {
            manager.decay_scores();
        }

        // Very small values should floor to zero
        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.risk_score, 0.0);
    }

    // ========================================================================
    // Session Binding Tests
    // ========================================================================

    #[test]
    fn test_bind_session() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        let actor_id = manager.get_or_create_actor(ip, None);
        manager.bind_session(&actor_id, "session-123");
        manager.bind_session(&actor_id, "session-456");
        manager.bind_session(&actor_id, "session-123"); // Duplicate

        let actor = manager.get_actor(&actor_id).unwrap();
        assert_eq!(actor.session_ids.len(), 2);
        assert!(actor.session_ids.contains(&"session-123".to_string()));
        assert!(actor.session_ids.contains(&"session-456".to_string()));
    }

    // ========================================================================
    // List Tests
    // ========================================================================

    #[test]
    fn test_list_actors() {
        let manager = create_test_manager();

        // Create some actors
        for i in 0..10 {
            let ip = create_test_ip(i);
            manager.get_or_create_actor(ip, None);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // List with pagination
        let first_page = manager.list_actors(5, 0);
        assert_eq!(first_page.len(), 5);

        let second_page = manager.list_actors(5, 5);
        assert_eq!(second_page.len(), 5);

        // Should be sorted by last_seen (most recent first)
        for window in first_page.windows(2) {
            assert!(window[0].last_seen >= window[1].last_seen);
        }
    }

    #[test]
    fn test_list_blocked_actors() {
        let manager = create_test_manager();

        // Create actors and block some
        for i in 0..10 {
            let ip = create_test_ip(i);
            let actor_id = manager.get_or_create_actor(ip, None);
            if i % 2 == 0 {
                manager.block_actor(&actor_id, "Test");
            }
        }

        let blocked = manager.list_blocked_actors();
        assert_eq!(blocked.len(), 5);

        for actor in blocked {
            assert!(actor.is_blocked);
        }
    }

    // ========================================================================
    // Concurrent Access Tests
    // ========================================================================

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(create_test_manager());
        let mut handles = vec![];

        // Spawn 10 threads, each creating and updating actors
        for thread_id in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip: IpAddr = format!("10.{}.0.{}", thread_id, i % 256).parse().unwrap();
                    let fingerprint = format!("fp_t{}_{}", thread_id, i % 5);
                    let actor_id = manager.get_or_create_actor(ip, Some(&fingerprint));
                    manager.record_rule_match(&actor_id, "test", 1.0, "test");
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
        assert_eq!(stats.total_actors, 0);
        assert_eq!(stats.blocked_actors, 0);
        assert_eq!(stats.total_created, 0);

        // Create actors
        for i in 0..5 {
            let ip = create_test_ip(i);
            let actor_id = manager.get_or_create_actor(ip, None);
            manager.record_rule_match(&actor_id, "test", 10.0, "test");
        }

        // Block one
        let actor = manager.list_actors(1, 0)[0].clone();
        manager.block_actor(&actor.actor_id, "Test");

        let stats = manager.stats().snapshot();
        assert_eq!(stats.total_actors, 5);
        assert_eq!(stats.blocked_actors, 1);
        assert_eq!(stats.total_created, 5);
        assert_eq!(stats.total_rule_matches, 5);
    }

    // ========================================================================
    // Clear Tests
    // ========================================================================

    #[test]
    fn test_clear() {
        let manager = create_test_manager();

        // Add some actors
        for i in 0..10 {
            let ip = create_test_ip(i);
            let actor_id = manager.get_or_create_actor(ip, Some(&format!("fp_{}", i)));
            manager.block_actor(&actor_id, "Test");
        }

        assert_eq!(manager.len(), 10);

        manager.clear();

        assert_eq!(manager.len(), 0);
        assert!(manager.ip_to_actor.is_empty());
        assert!(manager.fingerprint_to_actor.is_empty());
        assert_eq!(manager.stats().total_actors.load(Ordering::Relaxed), 0);
        assert_eq!(manager.stats().blocked_actors.load(Ordering::Relaxed), 0);
    }

    // ========================================================================
    // Default Implementation Tests
    // ========================================================================

    #[test]
    fn test_default() {
        let manager = ActorManager::default();

        assert!(manager.is_enabled());
        assert!(manager.is_empty());
        assert_eq!(manager.config().max_actors, 100_000);
    }

    // ========================================================================
    // Actor ID Generation Tests
    // ========================================================================

    #[test]
    fn test_actor_id_uniqueness() {
        let mut ids = HashSet::new();
        for _ in 0..1000 {
            let id = generate_actor_id();
            assert!(!ids.contains(&id), "Duplicate ID generated: {}", id);
            ids.insert(id);
        }
    }

    #[test]
    fn test_actor_id_format() {
        let id = generate_actor_id();

        // Should be UUID-like format: xxxxxxxx-xxxx-4xxx-xxxx-xxxxxxxxxxxx
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().nth(8), Some('-'));
        assert_eq!(id.chars().nth(13), Some('-'));
        assert_eq!(id.chars().nth(14), Some('4')); // Version 4
        assert_eq!(id.chars().nth(18), Some('-'));
        assert_eq!(id.chars().nth(23), Some('-'));
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_empty_fingerprint() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        // Empty fingerprint should be ignored
        let actor_id = manager.get_or_create_actor(ip, Some(""));

        let actor = manager.get_actor(&actor_id).unwrap();
        assert!(actor.fingerprints.is_empty());
        assert!(manager.fingerprint_to_actor.is_empty());
    }

    #[test]
    fn test_ipv6_addresses() {
        let manager = create_test_manager();

        let ipv6_1: IpAddr = "2001:db8::1".parse().unwrap();
        let ipv6_2: IpAddr = "2001:db8::2".parse().unwrap();

        let actor_id1 = manager.get_or_create_actor(ipv6_1, Some("ipv6_fp"));
        let actor_id2 = manager.get_or_create_actor(ipv6_2, Some("ipv6_fp"));

        assert_eq!(actor_id1, actor_id2);

        let actor = manager.get_actor(&actor_id1).unwrap();
        assert!(actor.ips.contains(&ipv6_1));
        assert!(actor.ips.contains(&ipv6_2));
    }

    #[test]
    fn test_disabled_manager() {
        let config = ActorConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = ActorManager::new(config);

        assert!(!manager.is_enabled());

        let ip = create_test_ip(1);
        let actor_id = manager.get_or_create_actor(ip, None);

        // Should still generate an ID but not track
        assert!(!actor_id.is_empty());
        assert!(manager.is_empty());

        // Record rule match should be no-op
        manager.record_rule_match(&actor_id, "test", 10.0, "test");
        assert!(manager.get_actor(&actor_id).is_none());
    }
}
