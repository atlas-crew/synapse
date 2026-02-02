//! Thread-safe entity store using DashMap for concurrent access.
//!
//! Provides lock-free entity tracking for high-RPS WAF scenarios.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

/// Configuration for entity tracking.
#[derive(Debug, Clone)]
pub struct EntityConfig {
    /// Maximum number of entities to track (LRU eviction when exceeded).
    pub max_entities: usize,
    /// Maximum entities per site/tenant (prevents single tenant from filling global pool).
    ///
    /// SECURITY: This limit ensures fair-share allocation across tenants. A single
    /// tenant generating many unique actors (intentional attack or misconfigured
    /// client) cannot fill the global pool and degrade security for other tenants.
    ///
    /// Default: 10% of max_entities (10,000 for default 100,000 max)
    /// Set to 0 to disable per-site limits.
    pub max_entities_per_site: usize,
    /// Risk half-life in minutes (time for risk to decay to 50% of current value).
    ///
    /// SECURITY: Using exponential decay prevents attackers from predicting when
    /// their risk score will drop below threshold. With linear decay (deprecated),
    /// attackers could time attacks to occur right after score drops below threshold.
    ///
    /// Formula: new_risk = old_risk * 0.5^(elapsed_minutes / half_life_minutes)
    ///
    /// Default: 5 minutes (score decays to 50% every 5 minutes)
    /// - After 5 min: 50% of original
    /// - After 10 min: 25% of original
    /// - After 20 min: 6.25% of original
    pub risk_half_life_minutes: f64,
    /// Minimum half-life for repeat offenders (multiplied from base).
    ///
    /// Entities with many rule matches decay slower as punishment.
    /// Applied as: effective_half_life = base_half_life * repeat_offender_factor
    ///
    /// Default factor range: 1.0 (first offense) to 3.0 (heavy offender)
    pub repeat_offender_max_factor: f64,
    /// Risk threshold for automatic blocking.
    pub block_threshold: f64,
    /// Maximum number of rule matches to track per entity.
    pub max_rules_per_entity: usize,
    /// Whether entity tracking is enabled.
    pub enabled: bool,
    /// Maximum risk score (default: 100.0, extended: 1000.0).
    pub max_risk: f64,
    /// Maximum number of anomaly entries to track per entity.
    pub max_anomalies_per_entity: usize,
}

impl Default for EntityConfig {
    fn default() -> Self {
        Self {
            max_entities: 100_000,  // 100K for production
            max_entities_per_site: 10_000, // 10% of max - fair share per tenant
            risk_half_life_minutes: 5.0, // 50% decay every 5 minutes
            repeat_offender_max_factor: 3.0, // Up to 3x longer half-life for repeat offenders
            block_threshold: 70.0,
            max_rules_per_entity: 50,
            enabled: true,
            max_risk: 100.0,
            max_anomalies_per_entity: 100,
        }
    }
}

/// Per-IP entity state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    /// IP address (primary key).
    pub entity_id: String,
    /// Site/tenant ID this entity is associated with (for multi-tenant isolation).
    #[serde(default)]
    pub site_id: Option<String>,
    /// Accumulated risk score (0.0-max_risk).
    pub risk: f64,
    /// First seen timestamp (ms).
    pub first_seen_at: u64,
    /// Last seen timestamp (ms).
    pub last_seen_at: u64,
    /// Last decay timestamp (ms).
    pub last_decay_at: u64,
    /// Total request count.
    pub request_count: u64,
    /// Whether this entity is blocked.
    pub blocked: bool,
    /// Reason for blocking.
    pub blocked_reason: Option<String>,
    /// Timestamp when blocked (ms).
    pub blocked_since: Option<u64>,
    /// Rule match history (rule_id -> history).
    pub matches: HashMap<u32, RuleMatchHistory>,
    /// JA4 fingerprint (if available).
    pub ja4_fingerprint: Option<String>,
    /// Combined fingerprint hash (for correlation).
    pub combined_fingerprint: Option<String>,
    /// Previous JA4 fingerprint (for change detection).
    pub previous_ja4: Option<String>,
    /// Count of JA4 changes within the tracking window.
    pub ja4_change_count: u32,
    /// Timestamp of last JA4 change (milliseconds).
    pub last_ja4_change_ms: Option<u64>,
}

impl EntityState {
    /// Create a new entity state for the given IP.
    pub fn new(entity_id: String, now: u64) -> Self {
        Self {
            entity_id,
            site_id: None,
            risk: 0.0,
            first_seen_at: now,
            last_seen_at: now,
            last_decay_at: now,
            request_count: 0, // touch will increment to 1
            blocked: false,
            blocked_reason: None,
            blocked_since: None,
            matches: HashMap::new(),
            ja4_fingerprint: None,
            combined_fingerprint: None,
            previous_ja4: None,
            ja4_change_count: 0,
            last_ja4_change_ms: None,
        }
    }

    /// Create a new entity state with a site ID.
    pub fn with_site(entity_id: String, site_id: String, now: u64) -> Self {
        Self {
            entity_id,
            site_id: Some(site_id),
            risk: 0.0,
            first_seen_at: now,
            last_seen_at: now,
            last_decay_at: now,
            request_count: 0,
            blocked: false,
            blocked_reason: None,
            blocked_since: None,
            matches: HashMap::new(),
            ja4_fingerprint: None,
            combined_fingerprint: None,
            previous_ja4: None,
            ja4_change_count: 0,
            last_ja4_change_ms: None,
        }
    }

    /// Get the repeat offender multiplier for a rule.
    ///
    /// Returns 1.0 if rule hasn't been matched before.
    /// Multiplier tiers: 1→1.0, 2→1.25, 6→1.5, 11→2.0
    #[inline]
    pub fn get_match_multiplier(&self, rule_id: u32) -> f64 {
        self.matches
            .get(&rule_id)
            .map(|h| repeat_multiplier(h.count))
            .unwrap_or(1.0)
    }

    /// Get match count for a rule (0 if not matched).
    #[inline]
    pub fn get_match_count(&self, rule_id: u32) -> u32 {
        self.matches.get(&rule_id).map(|h| h.count).unwrap_or(0)
    }
}

/// Rule match history for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchHistory {
    /// Rule ID.
    pub rule_id: u32,
    /// First match timestamp (ms).
    pub first_matched_at: u64,
    /// Last match timestamp (ms).
    pub last_matched_at: u64,
    /// Match count.
    pub count: u32,
}

impl RuleMatchHistory {
    /// Create a new rule match history.
    pub fn new(rule_id: u32, now: u64) -> Self {
        Self {
            rule_id,
            first_matched_at: now,
            last_matched_at: now,
            count: 1,
        }
    }
}

/// Calculate repeat offender multiplier based on match count.
///
/// Tiered multiplier system:
/// - 1 match: 1.0x
/// - 2-5 matches: 1.25x
/// - 6-10 matches: 1.5x
/// - 11+ matches: 2.0x
#[inline]
pub fn repeat_multiplier(count: u32) -> f64 {
    match count {
        0..=1 => 1.0,
        2..=5 => 1.25,
        6..=10 => 1.5,
        _ => 2.0,
    }
}

/// Block decision result.
#[derive(Debug, Clone)]
pub struct BlockDecision {
    /// Whether the entity is blocked.
    pub blocked: bool,
    /// Current risk score.
    pub risk: f64,
    /// Reason for blocking (if blocked).
    pub reason: Option<String>,
    /// Timestamp when blocked (if blocked).
    pub blocked_since: Option<u64>,
}

/// Risk application result.
#[derive(Debug, Clone)]
pub struct RiskApplication {
    /// New risk score after application.
    pub new_risk: f64,
    /// Base risk that was applied.
    pub base_risk: f64,
    /// Multiplier used (1.0 if disabled).
    pub multiplier: f64,
    /// Final risk added (base * multiplier).
    pub final_risk: f64,
    /// Current match count for the rule.
    pub match_count: u32,
}

/// Result of JA4 reputation check.
#[derive(Debug, Clone)]
pub struct Ja4ReputationResult {
    /// Whether rapid fingerprint changes were detected.
    pub rapid_changes: bool,
    /// Number of changes in the tracking window.
    pub change_count: u32,
}

/// Thread-safe entity manager using DashMap.
///
/// Provides lock-free concurrent access to entity state for high-RPS WAF scenarios.
/// Uses timestamp-based LRU eviction instead of ordered list for better concurrency.
///
/// SECURITY: Implements per-site entity quotas to prevent a single tenant from
/// filling the global pool and degrading security for all tenants.
pub struct EntityManager {
    /// Entities by IP address (lock-free concurrent map).
    entities: DashMap<String, EntityState>,
    /// Per-site entity counts for fair-share allocation.
    site_counts: DashMap<String, AtomicU64>,
    /// Configuration (immutable after creation).
    config: EntityConfig,
    /// Total entities ever created (for metrics).
    total_created: AtomicU64,
    /// Total entities evicted (for metrics).
    total_evicted: AtomicU64,
    /// Touch counter for lazy operations.
    touch_counter: AtomicU32,
}

impl Default for EntityManager {
    fn default() -> Self {
        Self::new(EntityConfig::default())
    }
}

impl EntityManager {
    /// Create a new entity manager with the given configuration.
    pub fn new(config: EntityConfig) -> Self {
        Self {
            entities: DashMap::with_capacity(config.max_entities),
            site_counts: DashMap::new(),
            config,
            total_created: AtomicU64::new(0),
            total_evicted: AtomicU64::new(0),
            touch_counter: AtomicU32::new(0),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &EntityConfig {
        &self.config
    }

    /// Check if entity tracking is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the number of tracked entities.
    pub fn len(&self) -> usize {
        self.entities.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    /// Get metrics about the entity store.
    pub fn metrics(&self) -> EntityMetrics {
        EntityMetrics {
            current_entities: self.entities.len(),
            max_entities: self.config.max_entities,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_evicted: self.total_evicted.load(Ordering::Relaxed),
        }
    }

    /// Touch an entity (update last_seen, apply decay, increment request_count).
    ///
    /// Creates the entity if it doesn't exist.
    /// Returns a snapshot of the entity state.
    pub fn touch_entity(&self, ip: &str) -> EntitySnapshot {
        let now = now_ms();

        // Check capacity and evict if needed (before inserting)
        self.maybe_evict();

        // Use entry API for atomic get-or-insert
        let mut entry = self.entities.entry(ip.to_string()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            EntityState::new(ip.to_string(), now)
        });

        let entity = entry.value_mut();

        // Apply decay
        self.apply_decay(entity, now);

        // Update timestamps and count
        entity.last_seen_at = now;
        entity.request_count += 1;

        // Return snapshot
        EntitySnapshot {
            entity_id: entity.entity_id.clone(),
            risk: entity.risk,
            request_count: entity.request_count,
            blocked: entity.blocked,
            blocked_reason: entity.blocked_reason.clone(),
        }
    }

    /// Touch an entity and associate fingerprint.
    pub fn touch_entity_with_fingerprint(
        &self,
        ip: &str,
        ja4: Option<&str>,
        combined: Option<&str>,
    ) -> EntitySnapshot {
        let now = now_ms();
        self.maybe_evict();

        let mut entry = self.entities.entry(ip.to_string()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            EntityState::new(ip.to_string(), now)
        });

        let entity = entry.value_mut();
        self.apply_decay(entity, now);

        entity.last_seen_at = now;
        entity.request_count += 1;

        // Update fingerprints if provided
        if let Some(ja4) = ja4 {
            entity.ja4_fingerprint = Some(ja4.to_string());
        }
        if let Some(combined) = combined {
            entity.combined_fingerprint = Some(combined.to_string());
        }

        EntitySnapshot {
            entity_id: entity.entity_id.clone(),
            risk: entity.risk,
            request_count: entity.request_count,
            blocked: entity.blocked,
            blocked_reason: entity.blocked_reason.clone(),
        }
    }

    /// Touch an entity for a specific site/tenant.
    ///
    /// SECURITY: Enforces per-site entity limits to prevent a single tenant from
    /// exhausting the global entity pool and degrading security for all tenants.
    ///
    /// Returns None if the site has exceeded its quota and the entity doesn't exist.
    pub fn touch_entity_for_site(&self, ip: &str, site_id: &str) -> Option<EntitySnapshot> {
        let now = now_ms();

        // Check if entity already exists (allows updates even if at quota)
        if let Some(mut entry) = self.entities.get_mut(ip) {
            let entity = entry.value_mut();
            self.apply_decay(entity, now);
            entity.last_seen_at = now;
            entity.request_count += 1;
            // Update site_id if not set
            if entity.site_id.is_none() {
                entity.site_id = Some(site_id.to_string());
            }
            return Some(EntitySnapshot {
                entity_id: entity.entity_id.clone(),
                risk: entity.risk,
                request_count: entity.request_count,
                blocked: entity.blocked,
                blocked_reason: entity.blocked_reason.clone(),
            });
        }

        // Entity doesn't exist - check per-site quota before creating
        if self.config.max_entities_per_site > 0 {
            let site_count = self.get_site_count(site_id);
            if site_count >= self.config.max_entities_per_site as u64 {
                // Site at quota - try to evict some old entries for this site
                self.evict_oldest_for_site(site_id, 10);
                // Check again after eviction
                let new_count = self.get_site_count(site_id);
                if new_count >= self.config.max_entities_per_site as u64 {
                    tracing::warn!(
                        site_id = %site_id,
                        count = site_count,
                        max = self.config.max_entities_per_site,
                        "Site entity quota exceeded, rejecting new entity"
                    );
                    return None;
                }
            }
        }

        // Check global capacity
        self.maybe_evict();

        // Create new entity with site_id
        let mut entry = self.entities.entry(ip.to_string()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            self.increment_site_count(site_id);
            EntityState::with_site(ip.to_string(), site_id.to_string(), now)
        });

        let entity = entry.value_mut();
        self.apply_decay(entity, now);
        entity.last_seen_at = now;
        entity.request_count += 1;

        Some(EntitySnapshot {
            entity_id: entity.entity_id.clone(),
            risk: entity.risk,
            request_count: entity.request_count,
            blocked: entity.blocked,
            blocked_reason: entity.blocked_reason.clone(),
        })
    }

    /// Get the current entity count for a site.
    pub fn get_site_count(&self, site_id: &str) -> u64 {
        self.site_counts
            .get(site_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Increment the entity count for a site.
    fn increment_site_count(&self, site_id: &str) {
        self.site_counts
            .entry(site_id.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the entity count for a site.
    fn decrement_site_count(&self, site_id: &str) {
        if let Some(counter) = self.site_counts.get(site_id) {
            // Use saturating sub to avoid underflow
            let current = counter.load(Ordering::Relaxed);
            if current > 0 {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Get site metrics for monitoring.
    pub fn site_metrics(&self) -> Vec<SiteMetrics> {
        self.site_counts
            .iter()
            .map(|entry| SiteMetrics {
                site_id: entry.key().clone(),
                entity_count: entry.value().load(Ordering::Relaxed),
                max_entities: self.config.max_entities_per_site as u64,
            })
            .collect()
    }

    /// Get an entity snapshot (read-only).
    pub fn get_entity(&self, ip: &str) -> Option<EntitySnapshot> {
        self.entities.get(ip).map(|entry| {
            let entity = entry.value();
            EntitySnapshot {
                entity_id: entity.entity_id.clone(),
                risk: entity.risk,
                request_count: entity.request_count,
                blocked: entity.blocked,
                blocked_reason: entity.blocked_reason.clone(),
            }
        })
    }

    /// Apply risk from a matched rule.
    ///
    /// Returns the risk application result, or None if entity doesn't exist.
    pub fn apply_rule_risk(
        &self,
        ip: &str,
        rule_id: u32,
        base_risk: f64,
        enable_multiplier: bool,
    ) -> Option<RiskApplication> {
        let now = now_ms();
        let max_risk = self.config.max_risk;
        let max_rules = self.config.max_rules_per_entity;

        self.entities.get_mut(ip).map(|mut entry| {
            let entity = entry.value_mut();

            // Apply decay first
            self.apply_decay(entity, now);

            // Calculate multiplier based on current count (before incrementing)
            let current_count = entity.get_match_count(rule_id);
            let multiplier = if enable_multiplier {
                repeat_multiplier(current_count + 1)
            } else {
                1.0
            };

            let final_risk = base_risk * multiplier;

            // Add risk (clamped to max_risk)
            entity.risk = (entity.risk + final_risk.max(0.0)).min(max_risk);

            // Update rule match history
            if let Some(history) = entity.matches.get_mut(&rule_id) {
                history.last_matched_at = now;
                history.count += 1;
            } else {
                entity.matches.insert(rule_id, RuleMatchHistory::new(rule_id, now));
            }

            // Trim rule history if needed
            if entity.matches.len() > max_rules {
                Self::trim_rule_history(&mut entity.matches, max_rules);
            }

            RiskApplication {
                new_risk: entity.risk,
                base_risk,
                multiplier,
                final_risk,
                match_count: current_count + 1,
            }
        })
    }

    /// Apply external risk (e.g., from anomaly detection).
    ///
    /// Creates the entity if it doesn't exist.
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `risk` - Risk points to add (will be clamped to max_risk)
    /// * `reason` - Reason for risk application (logged at debug level)
    pub fn apply_external_risk(&self, ip: &str, risk: f64, reason: &str) -> f64 {
        let now = now_ms();
        let max_risk = self.config.max_risk;
        self.maybe_evict();

        let mut entry = self.entities.entry(ip.to_string()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            EntityState::new(ip.to_string(), now)
        });

        let entity = entry.value_mut();
        self.apply_decay(entity, now);

        entity.last_seen_at = now;
        entity.request_count += 1;
        let old_risk = entity.risk;
        entity.risk = (entity.risk + risk.max(0.0)).min(max_risk);

        // Log risk application for debugging and audit
        if risk > 0.0 && !reason.is_empty() {
            tracing::debug!(
                ip = %ip,
                old_risk = old_risk,
                added_risk = risk,
                new_risk = entity.risk,
                reason = %reason,
                "Applied external risk"
            );
        }

        entity.risk
    }

    /// Apply anomaly-based risk to an entity.
    ///
    /// Used for behavioral anomalies like honeypot hits, rapid fingerprint changes, etc.
    /// Creates the entity if it doesn't exist.
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `anomaly_type` - Type of anomaly detected (e.g., "honeypot_hit", "ja4_rapid_change")
    /// * `risk` - Risk points to add
    /// * `details` - Optional details about the anomaly
    pub fn apply_anomaly_risk(
        &self,
        ip: &str,
        anomaly_type: &str,
        risk: f64,
        details: Option<&str>,
    ) -> f64 {
        let reason = match details {
            Some(d) => format!("{}: {}", anomaly_type, d),
            None => anomaly_type.to_string(),
        };
        self.apply_external_risk(ip, risk, &reason)
    }

    /// Check if an entity should be blocked based on risk threshold.
    ///
    /// Returns the block decision.
    pub fn check_block(&self, ip: &str) -> BlockDecision {
        let now = now_ms();
        let threshold = self.config.block_threshold;

        match self.entities.get_mut(ip) {
            Some(mut entry) => {
                let entity = entry.value_mut();
                self.apply_decay(entity, now);

                if entity.risk >= threshold {
                    if !entity.blocked {
                        entity.blocked = true;
                        entity.blocked_since = Some(now);
                    }
                    entity.blocked_reason = Some(format!(
                        "Risk {:.1} >= threshold {:.1}",
                        entity.risk, threshold
                    ));
                    BlockDecision {
                        blocked: true,
                        risk: entity.risk,
                        reason: entity.blocked_reason.clone(),
                        blocked_since: entity.blocked_since,
                    }
                } else {
                    // Below threshold - clear block status
                    entity.blocked = false;
                    entity.blocked_reason = None;
                    entity.blocked_since = None;
                    BlockDecision {
                        blocked: false,
                        risk: entity.risk,
                        reason: None,
                        blocked_since: None,
                    }
                }
            }
            None => BlockDecision {
                blocked: false,
                risk: 0.0,
                reason: None,
                blocked_since: None,
            },
        }
    }

    /// Manually block an entity.
    pub fn manual_block(&self, ip: &str, reason: &str) -> bool {
        let now = now_ms();
        match self.entities.get_mut(ip) {
            Some(mut entry) => {
                let entity = entry.value_mut();
                entity.blocked = true;
                entity.blocked_reason = Some(reason.to_string());
                if entity.blocked_since.is_none() {
                    entity.blocked_since = Some(now);
                }
                true
            }
            None => false,
        }
    }

    /// Release an entity (reset risk and unblock).
    pub fn release_entity(&self, ip: &str) -> bool {
        match self.entities.get_mut(ip) {
            Some(mut entry) => {
                let entity = entry.value_mut();
                entity.risk = 0.0;
                entity.blocked = false;
                entity.blocked_reason = None;
                entity.blocked_since = None;
                entity.matches.clear();
                true
            }
            None => false,
        }
    }

    /// Release all entities (reset risk and unblock all).
    ///
    /// Returns the number of entities released.
    pub fn release_all(&self) -> usize {
        let mut count = 0;
        for mut entry in self.entities.iter_mut() {
            let entity = entry.value_mut();
            if entity.blocked || entity.risk > 0.0 {
                entity.risk = 0.0;
                entity.blocked = false;
                entity.blocked_reason = None;
                entity.blocked_since = None;
                entity.matches.clear();
                count += 1;
            }
        }
        count
    }

    /// List all entity IDs.
    pub fn list_entity_ids(&self) -> Vec<String> {
        self.entities.iter().map(|e| e.key().clone()).collect()
    }

    /// Returns top N entities sorted by risk score (highest first)
    pub fn list_top_risk(&self, limit: usize) -> Vec<EntitySnapshot> {
        let mut entities: Vec<_> = self.entities.iter()
            .map(|entry| {
                let state = entry.value();
                EntitySnapshot {
                    entity_id: state.entity_id.clone(),
                    risk: state.risk,
                    request_count: state.request_count,
                    blocked: state.blocked,
                    blocked_reason: state.blocked_reason.clone(),
                }
            })
            .collect();

        entities.sort_by(|a, b| {
            b.risk.partial_cmp(&a.risk).unwrap_or(std::cmp::Ordering::Equal)
        });
        entities.truncate(limit);
        entities
    }

    /// Check JA4 reputation for an IP address.
    /// Detects rapid fingerprint changes that indicate bot behavior.
    ///
    /// # Arguments
    /// * `ip` - Client IP address
    /// * `current_ja4` - Current JA4 fingerprint
    /// * `now_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// Reputation result if entity exists, None otherwise
    pub fn check_ja4_reputation(
        &self,
        ip: &str,
        current_ja4: &str,
        now_ms: u64,
    ) -> Option<Ja4ReputationResult> {
        let mut entry = self.entities.get_mut(ip)?;

        const RAPID_CHANGE_WINDOW_MS: u64 = 60_000; // 1 minute
        const RAPID_CHANGE_THRESHOLD: u32 = 3;

        let mut rapid_changes = false;

        if let Some(ref prev_ja4) = entry.previous_ja4 {
            if prev_ja4 != current_ja4 {
                // Fingerprint changed!
                let within_window = entry
                    .last_ja4_change_ms
                    .map(|t| now_ms.saturating_sub(t) < RAPID_CHANGE_WINDOW_MS)
                    .unwrap_or(false);

                if within_window {
                    entry.ja4_change_count += 1;
                    if entry.ja4_change_count >= RAPID_CHANGE_THRESHOLD {
                        rapid_changes = true;
                    }
                } else {
                    // Outside window - reset counter
                    entry.ja4_change_count = 1;
                }

                entry.previous_ja4 = Some(current_ja4.to_string());
                entry.last_ja4_change_ms = Some(now_ms);
            }
            // If fingerprint is same, don't update anything
        } else {
            // First fingerprint seen for this IP
            entry.previous_ja4 = Some(current_ja4.to_string());
            entry.last_ja4_change_ms = Some(now_ms);
            entry.ja4_change_count = 0;
        }

        Some(Ja4ReputationResult {
            rapid_changes,
            change_count: entry.ja4_change_count,
        })
    }

    // Internal helpers

    /// Apply exponential decay to an entity based on elapsed time.
    ///
    /// SECURITY: Uses exponential decay (half-life model) instead of linear decay
    /// to prevent attackers from predicting when their risk score will drop below
    /// threshold. With linear decay, attackers could precisely calculate wait times.
    ///
    /// Formula: new_risk = old_risk * 0.5^(elapsed_minutes / effective_half_life)
    ///
    /// Repeat offenders decay slower (longer half-life) as punishment.
    fn apply_decay(&self, entity: &mut EntityState, now: u64) {
        // Early exit if no risk to decay
        if entity.risk <= 0.0 {
            entity.last_decay_at = now;
            return;
        }

        let elapsed_ms = now.saturating_sub(entity.last_decay_at);
        // Skip decay for short intervals (< 1 second) - optimization
        if elapsed_ms < 1000 {
            return;
        }

        // Calculate repeat offender factor based on total rule match history
        // More matches = slower decay (longer half-life) as punishment
        let total_matches: u32 = entity.matches.values().map(|h| h.count).sum();
        let repeat_factor = self.calculate_repeat_offender_factor(total_matches);

        // Effective half-life increases with repeat offenses
        let effective_half_life_minutes = self.config.risk_half_life_minutes * repeat_factor;

        // Convert elapsed time to minutes
        let elapsed_minutes = elapsed_ms as f64 / 60_000.0;

        // Exponential decay: risk = risk * 0.5^(elapsed / half_life)
        // Using natural log: risk = risk * e^(-ln(2) * elapsed / half_life)
        let decay_exponent = -0.693147 * elapsed_minutes / effective_half_life_minutes;
        let decay_factor = decay_exponent.exp();

        // Apply decay
        entity.risk = (entity.risk * decay_factor).max(0.0);

        // Clamp very small values to zero (floating point cleanup)
        if entity.risk < 0.01 {
            entity.risk = 0.0;
        }

        entity.last_decay_at = now;
    }

    /// Calculate the repeat offender factor for decay slowdown.
    ///
    /// Returns a multiplier (1.0 to max_factor) based on total rule match count.
    /// Higher match counts result in slower decay (longer half-life).
    ///
    /// Tiers:
    /// - 0-2 matches: 1.0x (normal decay)
    /// - 3-5 matches: 1.25x slower
    /// - 6-10 matches: 1.5x slower
    /// - 11-20 matches: 2.0x slower
    /// - 21+ matches: max_factor (default 3.0x slower)
    fn calculate_repeat_offender_factor(&self, total_matches: u32) -> f64 {
        let factor = match total_matches {
            0..=2 => 1.0,
            3..=5 => 1.25,
            6..=10 => 1.5,
            11..=20 => 2.0,
            _ => self.config.repeat_offender_max_factor,
        };

        // Clamp to configured maximum
        factor.min(self.config.repeat_offender_max_factor)
    }

    /// Maybe evict oldest entities if at capacity.
    ///
    /// Uses lazy eviction: only check every 100th touch to avoid overhead.
    fn maybe_evict(&self) {
        // Lazy check - only evaluate every 100th operation
        let count = self.touch_counter.fetch_add(1, Ordering::Relaxed);
        if count % 100 != 0 {
            return;
        }

        // Check if we need to evict
        if self.entities.len() < self.config.max_entities {
            return;
        }

        // Evict oldest 1% of entities (batch eviction for efficiency)
        let evict_count = (self.config.max_entities / 100).max(1);
        self.evict_oldest(evict_count);
    }

    /// Evict the N oldest entities by last_seen_at timestamp.
    ///
    /// Uses sampling to avoid O(n) collection of all entities.
    /// Samples up to 10x the eviction count, then evicts the oldest from the sample.
    /// This provides probabilistically good eviction while maintaining O(sample_size) complexity.
    fn evict_oldest(&self, count: usize) {
        // Sample size: 10x eviction count, capped at 1000 to avoid excessive memory
        let sample_size = (count * 10).min(1000).min(self.entities.len());

        if sample_size == 0 {
            return;
        }

        // Sample entities - DashMap iter() provides reasonable distribution
        let mut candidates: Vec<(String, Option<String>, u64)> = Vec::with_capacity(sample_size);
        for entry in self.entities.iter().take(sample_size) {
            candidates.push((
                entry.key().clone(),
                entry.value().site_id.clone(),
                entry.value().last_seen_at,
            ));
        }

        // Sort sampled candidates by last_seen_at (oldest first)
        candidates.sort_unstable_by_key(|(_, _, ts)| *ts);

        // Evict oldest N from sample
        for (ip, site_id, _) in candidates.into_iter().take(count) {
            if self.entities.remove(&ip).is_some() {
                self.total_evicted.fetch_add(1, Ordering::Relaxed);
                // Decrement site count if entity had a site_id
                if let Some(ref site) = site_id {
                    self.decrement_site_count(site);
                }
            }
        }
    }

    /// Evict oldest entities for a specific site.
    ///
    /// SECURITY: Used when a site exceeds its quota to make room for new entities.
    /// Only evicts entities belonging to the specified site.
    fn evict_oldest_for_site(&self, site_id: &str, count: usize) {
        // Sample entities belonging to this site
        let sample_size = (count * 10).min(500);
        let mut candidates: Vec<(String, u64)> = Vec::with_capacity(sample_size);

        for entry in self.entities.iter() {
            if entry.value().site_id.as_deref() == Some(site_id) {
                candidates.push((entry.key().clone(), entry.value().last_seen_at));
                if candidates.len() >= sample_size {
                    break;
                }
            }
        }

        if candidates.is_empty() {
            return;
        }

        // Sort by last_seen_at (oldest first)
        candidates.sort_unstable_by_key(|(_, ts)| *ts);

        // Evict oldest N
        let mut evicted = 0;
        for (ip, _) in candidates.into_iter().take(count) {
            if self.entities.remove(&ip).is_some() {
                self.total_evicted.fetch_add(1, Ordering::Relaxed);
                self.decrement_site_count(site_id);
                evicted += 1;
            }
        }

        if evicted > 0 {
            tracing::debug!(
                site_id = %site_id,
                evicted = evicted,
                "Evicted oldest entities for site to make room"
            );
        }
    }

    /// Trim rule history to max size, keeping most recent.
    fn trim_rule_history(matches: &mut HashMap<u32, RuleMatchHistory>, max_rules: usize) {
        if matches.len() <= max_rules {
            return;
        }

        // Find oldest entries to remove
        let mut entries: Vec<_> = matches.iter().collect();
        entries.sort_by_key(|(_, h)| h.last_matched_at);

        let to_remove = matches.len() - max_rules;
        let remove_ids: Vec<u32> = entries
            .iter()
            .take(to_remove)
            .map(|(id, _)| **id)
            .collect();

        for id in remove_ids {
            matches.remove(&id);
        }
    }

    // ========== Testing Methods ==========

    /// Simulate time-based decay for testing purposes.
    ///
    /// This method allows tests to verify decay behavior without waiting for real time to pass.
    /// It sets the entity's last_decay_at to a past time, then applies decay based on elapsed time.
    #[cfg(test)]
    pub fn test_decay(&self, ip: &str, elapsed_ms: u64) -> Option<f64> {
        let now = now_ms();
        if let Some(mut entry) = self.entities.get_mut(ip) {
            // Set last_decay_at to simulate elapsed time
            entry.last_decay_at = now.saturating_sub(elapsed_ms);
            self.apply_decay(&mut entry, now);
            Some(entry.risk)
        } else {
            None
        }
    }

    /// Get the full entity state for testing (exposes internal fields).
    #[cfg(test)]
    pub fn test_get_entity_state(&self, ip: &str) -> Option<EntityState> {
        self.entities.get(ip).map(|e| e.value().clone())
    }

    // ========== Persistence Methods ==========

    /// Create a snapshot of all entity states for persistence.
    ///
    /// Returns a Vec of cloned EntityState suitable for serialization.
    pub fn snapshot(&self) -> Vec<EntityState> {
        self.entities.iter().map(|e| e.value().clone()).collect()
    }

    /// Restore entity states from a persisted snapshot.
    ///
    /// Clears existing entities and inserts the restored ones.
    /// Updates total_created counter to reflect restored count.
    /// Rebuilds site_counts from restored entity site_id fields.
    pub fn restore(&self, entities: Vec<EntityState>) {
        self.entities.clear();
        self.site_counts.clear();

        let count = entities.len() as u64;
        for entity in entities {
            // Rebuild site counts
            if let Some(ref site_id) = entity.site_id {
                self.increment_site_count(site_id);
            }
            self.entities.insert(entity.entity_id.clone(), entity);
        }
        self.total_created.store(count, Ordering::Relaxed);
        self.total_evicted.store(0, Ordering::Relaxed);
    }

    /// Merge restored entities with existing ones (additive restore).
    ///
    /// Only inserts entities that don't already exist.
    /// Useful for partial recovery scenarios.
    /// Updates site_counts for newly merged entities.
    pub fn merge_restore(&self, entities: Vec<EntityState>) -> usize {
        let mut merged = 0;
        for entity in entities {
            let site_id = entity.site_id.clone();
            if self.entities.insert(entity.entity_id.clone(), entity).is_none() {
                merged += 1;
                // Update site count for new entity
                if let Some(ref site) = site_id {
                    self.increment_site_count(site);
                }
            }
        }
        self.total_created.fetch_add(merged as u64, Ordering::Relaxed);
        merged
    }

    /// Clear the entity store and all site counts.
    pub fn clear(&self) {
        self.entities.clear();
        self.site_counts.clear();
    }
}

/// Snapshot of entity state (for returning across lock boundaries).
#[derive(Debug, Clone, Serialize)]
pub struct EntitySnapshot {
    pub entity_id: String,
    pub risk: f64,
    pub request_count: u64,
    pub blocked: bool,
    pub blocked_reason: Option<String>,
}

/// Entity store metrics.
#[derive(Debug, Clone)]
pub struct EntityMetrics {
    pub current_entities: usize,
    pub max_entities: usize,
    pub total_created: u64,
    pub total_evicted: u64,
}

/// Per-site entity metrics for monitoring multi-tenant fairness.
#[derive(Debug, Clone)]
pub struct SiteMetrics {
    pub site_id: String,
    pub entity_count: u64,
    pub max_entities: u64,
}

/// Get current time in milliseconds since Unix epoch.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_entity_creation() {
        let manager = EntityManager::default();
        let snapshot = manager.touch_entity("192.168.1.1");

        assert_eq!(snapshot.entity_id, "192.168.1.1");
        assert_eq!(snapshot.risk, 0.0);
        assert_eq!(snapshot.request_count, 1);
        assert!(!snapshot.blocked);
    }

    #[test]
    fn test_entity_touch_increments_count() {
        let manager = EntityManager::default();
        manager.touch_entity("192.168.1.1");
        manager.touch_entity("192.168.1.1");
        let snapshot = manager.touch_entity("192.168.1.1");

        assert_eq!(snapshot.request_count, 3);
    }

    #[test]
    fn test_apply_rule_risk() {
        let manager = EntityManager::default();
        manager.touch_entity("192.168.1.1");

        let result = manager.apply_rule_risk("192.168.1.1", 100, 10.0, false);
        assert!(result.is_some());

        let result = result.unwrap();
        assert!(result.new_risk >= 10.0);
        assert_eq!(result.base_risk, 10.0);
        assert_eq!(result.multiplier, 1.0);
        assert_eq!(result.match_count, 1);
    }

    #[test]
    fn test_apply_rule_risk_with_multiplier() {
        let manager = EntityManager::default();
        manager.touch_entity("192.168.1.1");

        // First match: 1.0x
        let r1 = manager.apply_rule_risk("192.168.1.1", 100, 10.0, true).unwrap();
        assert_eq!(r1.multiplier, 1.0);
        assert_eq!(r1.match_count, 1);

        // Second match: 1.25x
        let r2 = manager.apply_rule_risk("192.168.1.1", 100, 10.0, true).unwrap();
        assert_eq!(r2.multiplier, 1.25);
        assert_eq!(r2.match_count, 2);

        // After 6 matches: 1.5x
        for _ in 0..4 {
            manager.apply_rule_risk("192.168.1.1", 100, 10.0, true);
        }
        let r6 = manager.apply_rule_risk("192.168.1.1", 100, 10.0, true).unwrap();
        assert_eq!(r6.multiplier, 1.5);

        // After 11 matches: 2.0x
        for _ in 0..4 {
            manager.apply_rule_risk("192.168.1.1", 100, 10.0, true);
        }
        let r11 = manager.apply_rule_risk("192.168.1.1", 100, 10.0, true).unwrap();
        assert_eq!(r11.multiplier, 2.0);
    }

    #[test]
    fn test_risk_capping() {
        let manager = EntityManager::default();
        manager.touch_entity("192.168.1.1");

        // Apply more than 100 risk
        for _ in 0..15 {
            manager.apply_rule_risk("192.168.1.1", 100, 10.0, false);
        }

        let snapshot = manager.get_entity("192.168.1.1").unwrap();
        assert!(snapshot.risk <= 100.0);
    }

    #[test]
    fn test_risk_blocking() {
        let config = EntityConfig {
            block_threshold: 50.0,
            ..Default::default()
        };
        let manager = EntityManager::new(config);
        manager.touch_entity("192.168.1.1");

        // Apply 60 risk
        manager.apply_rule_risk("192.168.1.1", 100, 60.0, false);

        let decision = manager.check_block("192.168.1.1");
        assert!(decision.blocked);
        assert!(decision.reason.is_some());
        assert!(decision.reason.unwrap().contains("60.0"));
    }

    #[test]
    fn test_release_entity() {
        let manager = EntityManager::default();
        manager.touch_entity("192.168.1.1");
        manager.apply_rule_risk("192.168.1.1", 100, 50.0, false);
        manager.manual_block("192.168.1.1", "test");

        let snapshot = manager.get_entity("192.168.1.1").unwrap();
        assert!(snapshot.blocked);
        assert!(snapshot.risk > 0.0);

        manager.release_entity("192.168.1.1");

        let snapshot = manager.get_entity("192.168.1.1").unwrap();
        assert!(!snapshot.blocked);
        assert_eq!(snapshot.risk, 0.0);
    }

    #[test]
    fn test_lru_eviction() {
        // Use max_entities=1000 to test eviction behavior
        // Eviction happens every 100 touches, evicting 1% (10 entities) each time
        let config = EntityConfig {
            max_entities: 1000,
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        // Add 1500 unique entities
        // Eviction starts after touch 1000 when we exceed capacity
        // With 500 over-capacity touches, we get ~5 eviction cycles (at 1001, 1101, 1201, 1301, 1401)
        // Each cycle evicts 10 entities, so ~50 total evicted
        for i in 0..1500 {
            manager.touch_entity(&format!("{}.{}.{}.{}", i, i, i, i));
        }

        let after_loading = manager.len();

        // Expected: 1500 created - ~50 evicted = ~1450 remaining
        // Lazy eviction doesn't aggressively enforce the limit - it slowly brings it down
        assert!(
            after_loading <= 1500,
            "Should not have more than created: {}",
            after_loading
        );

        // Verify some eviction occurred (should be around 50)
        let metrics = manager.metrics();
        assert!(
            metrics.total_evicted > 0,
            "Should have evicted some entities: {}",
            metrics.total_evicted
        );

        // Now force more eviction cycles to get closer to max_entities
        // Each 100 touches triggers an eviction check
        for _ in 0..500 {
            manager.touch_entity("force.eviction");
        }

        let after_force = manager.len();

        // After 500 more touches (5 more eviction cycles), should be closer to limit
        assert!(
            after_force < after_loading,
            "Additional touches should trigger more eviction: before={}, after={}",
            after_loading, after_force
        );

        println!(
            "LRU eviction test: created={}, evicted={}, after_load={}, after_force={}",
            metrics.total_created, manager.metrics().total_evicted, after_loading, after_force
        );
    }

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(EntityManager::default());
        let mut handles = vec![];

        // Spawn 10 threads, each touching entities 100 times
        for thread_id in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip = format!("192.168.{}.{}", thread_id, i % 10);
                    manager.touch_entity(&ip);
                    manager.apply_rule_risk(&ip, 100, 1.0, true);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify no panics and reasonable state
        assert!(manager.len() > 0);
        assert!(manager.len() <= 100); // 10 threads * 10 unique IPs each
    }

    #[test]
    fn test_fingerprint_association() {
        let manager = EntityManager::default();

        manager.touch_entity_with_fingerprint(
            "192.168.1.1",
            Some("t13d1516h2_abc123_def456"),
            Some("combined_hash_xyz"),
        );

        // Fingerprints are stored but not in snapshot (kept internal)
        let snapshot = manager.get_entity("192.168.1.1").unwrap();
        assert_eq!(snapshot.entity_id, "192.168.1.1");
        assert_eq!(snapshot.request_count, 1);
    }

    #[test]
    fn test_release_all() {
        let manager = EntityManager::default();

        manager.touch_entity("1.1.1.1");
        manager.touch_entity("2.2.2.2");
        manager.apply_rule_risk("1.1.1.1", 100, 50.0, false);
        manager.apply_rule_risk("2.2.2.2", 100, 30.0, false);

        let count = manager.release_all();
        assert_eq!(count, 2);

        assert_eq!(manager.get_entity("1.1.1.1").unwrap().risk, 0.0);
        assert_eq!(manager.get_entity("2.2.2.2").unwrap().risk, 0.0);
    }

    #[test]
    fn test_metrics() {
        let manager = EntityManager::default();

        for i in 0..5 {
            manager.touch_entity(&format!("192.168.1.{}", i));
        }

        let metrics = manager.metrics();
        assert_eq!(metrics.current_entities, 5);
        assert_eq!(metrics.max_entities, 100_000);
        assert_eq!(metrics.total_created, 5);
        assert_eq!(metrics.total_evicted, 0);
    }

    #[test]
    fn test_repeat_multiplier() {
        assert_eq!(repeat_multiplier(0), 1.0);
        assert_eq!(repeat_multiplier(1), 1.0);
        assert_eq!(repeat_multiplier(2), 1.25);
        assert_eq!(repeat_multiplier(5), 1.25);
        assert_eq!(repeat_multiplier(6), 1.5);
        assert_eq!(repeat_multiplier(10), 1.5);
        assert_eq!(repeat_multiplier(11), 2.0);
        assert_eq!(repeat_multiplier(100), 2.0);
    }

    // ==================== JA4 Reputation Tests ====================

    #[test]
    fn test_ja4_first_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());

        // Touch entity first to create it
        manager.touch_entity("1.2.3.4");

        // First fingerprint - should not trigger rapid changes
        let result = manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 1000);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(!result.rapid_changes);
        assert_eq!(result.change_count, 0);
    }

    #[test]
    fn test_ja4_same_fingerprint_no_change() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Same fingerprint twice - no change
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 1000);
        let result = manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 2000);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(!result.rapid_changes);
        assert_eq!(result.change_count, 0);
    }

    #[test]
    fn test_ja4_rapid_changes_triggers() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // 3 different fingerprints within 60 seconds should trigger
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 1000);
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_2", 10000); // 10s later
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_3", 20000); // 20s later
        let result = manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_4", 30000); // 30s later

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.rapid_changes);
        assert!(result.change_count >= 3);
    }

    #[test]
    fn test_ja4_changes_outside_window_reset() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // First change
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 1000);
        manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_2", 10000);

        // Change outside window (> 60 seconds later)
        let result = manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_3", 100000);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(!result.rapid_changes);
        assert_eq!(result.change_count, 1); // Counter was reset
    }

    #[test]
    fn test_ja4_nonexistent_entity() {
        let manager = EntityManager::new(EntityConfig::default());

        // Entity doesn't exist - should return None
        let result = manager.check_ja4_reputation("1.2.3.4", "ja4_fingerprint_1", 1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_ja4_change_count_increments() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // First fingerprint
        let r1 = manager.check_ja4_reputation("1.2.3.4", "fp1", 1000).unwrap();
        assert_eq!(r1.change_count, 0);

        // Second fingerprint (change)
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp2", 2000).unwrap();
        assert_eq!(r2.change_count, 1);

        // Third fingerprint (change)
        let r3 = manager.check_ja4_reputation("1.2.3.4", "fp3", 3000).unwrap();
        assert_eq!(r3.change_count, 2);

        // Fourth fingerprint (change) - should trigger rapid_changes
        let r4 = manager.check_ja4_reputation("1.2.3.4", "fp4", 4000).unwrap();
        assert_eq!(r4.change_count, 3);
        assert!(r4.rapid_changes);
    }

    // ==================== JA4 Reputation Edge Case Tests ====================

    #[test]
    fn test_ja4_window_boundary_exactly_at_60s() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // First fingerprint at t=0
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);

        // Change at t=10s
        manager.check_ja4_reputation("1.2.3.4", "fp2", 10_000);

        // Change exactly at 60s boundary (should still be within window)
        let result = manager.check_ja4_reputation("1.2.3.4", "fp3", 70_000);
        assert!(result.is_some());
        let result = result.unwrap();
        // 70000 - 10000 = 60000ms exactly - this is NOT < 60000, so outside window
        // Counter should reset
        assert_eq!(result.change_count, 1);
        assert!(!result.rapid_changes);
    }

    #[test]
    fn test_ja4_window_boundary_just_inside() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // First fingerprint at t=0
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);

        // Change at t=10s
        manager.check_ja4_reputation("1.2.3.4", "fp2", 10_000);

        // Change at t=69.999s (just inside 60s window from last change)
        let result = manager.check_ja4_reputation("1.2.3.4", "fp3", 69_999);
        assert!(result.is_some());
        let result = result.unwrap();
        // 69999 - 10000 = 59999ms < 60000ms - still within window
        assert_eq!(result.change_count, 2);
    }

    #[test]
    fn test_ja4_window_boundary_just_outside() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // First fingerprint at t=0
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);

        // Change at t=10s
        manager.check_ja4_reputation("1.2.3.4", "fp2", 10_000);

        // Change at t=70.001s (just outside 60s window from last change)
        let result = manager.check_ja4_reputation("1.2.3.4", "fp3", 70_001);
        assert!(result.is_some());
        let result = result.unwrap();
        // 70001 - 10000 = 60001ms > 60000ms - outside window, counter resets
        assert_eq!(result.change_count, 1);
    }

    #[test]
    fn test_ja4_counter_reset_timing() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Build up to 2 changes within window
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);
        manager.check_ja4_reputation("1.2.3.4", "fp2", 10_000);
        let r1 = manager.check_ja4_reputation("1.2.3.4", "fp3", 20_000).unwrap();
        assert_eq!(r1.change_count, 2);

        // Long delay - counter should reset
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp4", 100_000).unwrap();
        assert_eq!(r2.change_count, 1); // Reset to 1

        // Continue from reset - need 2 more changes to trigger
        let r3 = manager.check_ja4_reputation("1.2.3.4", "fp5", 110_000).unwrap();
        assert_eq!(r3.change_count, 2);
        assert!(!r3.rapid_changes);

        let r4 = manager.check_ja4_reputation("1.2.3.4", "fp6", 120_000).unwrap();
        assert_eq!(r4.change_count, 3);
        assert!(r4.rapid_changes);
    }

    #[test]
    fn test_ja4_empty_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Empty fingerprint should be treated as valid (just an empty string)
        let r1 = manager.check_ja4_reputation("1.2.3.4", "", 1000);
        assert!(r1.is_some());

        // Change from empty to non-empty
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp1", 2000).unwrap();
        assert_eq!(r2.change_count, 1);

        // Change back to empty
        let r3 = manager.check_ja4_reputation("1.2.3.4", "", 3000).unwrap();
        assert_eq!(r3.change_count, 2);
    }

    #[test]
    fn test_ja4_whitespace_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Whitespace is a valid (though unusual) fingerprint
        manager.check_ja4_reputation("1.2.3.4", "   ", 1000);

        // Different whitespace is a change
        let r = manager.check_ja4_reputation("1.2.3.4", "\t", 2000).unwrap();
        assert_eq!(r.change_count, 1);
    }

    #[test]
    fn test_ja4_very_long_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Very long fingerprint
        let long_fp = "a".repeat(10000);
        let r1 = manager.check_ja4_reputation("1.2.3.4", &long_fp, 1000);
        assert!(r1.is_some());

        // Different long fingerprint
        let long_fp2 = "b".repeat(10000);
        let r2 = manager.check_ja4_reputation("1.2.3.4", &long_fp2, 2000).unwrap();
        assert_eq!(r2.change_count, 1);
    }

    #[test]
    fn test_ja4_unicode_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Unicode fingerprint (shouldn't happen in practice but should handle)
        let r1 = manager.check_ja4_reputation("1.2.3.4", "日本語", 1000);
        assert!(r1.is_some());

        // Different unicode
        let r2 = manager.check_ja4_reputation("1.2.3.4", "中文", 2000).unwrap();
        assert_eq!(r2.change_count, 1);

        // Emoji
        let r3 = manager.check_ja4_reputation("1.2.3.4", "🔒🔑", 3000).unwrap();
        assert_eq!(r3.change_count, 2);
    }

    #[test]
    fn test_ja4_case_sensitivity() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Fingerprints are case-sensitive
        manager.check_ja4_reputation("1.2.3.4", "ABC", 1000);

        // Different case = different fingerprint
        let r = manager.check_ja4_reputation("1.2.3.4", "abc", 2000).unwrap();
        assert_eq!(r.change_count, 1);

        // Back to original case
        let r2 = manager.check_ja4_reputation("1.2.3.4", "ABC", 3000).unwrap();
        assert_eq!(r2.change_count, 2);
    }

    #[test]
    fn test_ja4_timestamp_overflow_protection() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Set up fingerprint at very high timestamp
        manager.check_ja4_reputation("1.2.3.4", "fp1", u64::MAX - 1000);

        // Change with timestamp that would overflow if subtracted incorrectly
        let r = manager.check_ja4_reputation("1.2.3.4", "fp2", u64::MAX);
        assert!(r.is_some());
        let r = r.unwrap();
        // saturating_sub should prevent overflow
        assert_eq!(r.change_count, 1);
    }

    #[test]
    fn test_ja4_timestamp_zero() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Timestamp 0 should work
        let r1 = manager.check_ja4_reputation("1.2.3.4", "fp1", 0);
        assert!(r1.is_some());

        // Change with timestamp 0 (same time)
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp2", 0).unwrap();
        // 0 - 0 = 0 < 60000, so within window
        assert_eq!(r2.change_count, 1);
    }

    #[test]
    fn test_ja4_rapid_threshold_exactly_3() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Setup: First fingerprint
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);

        // 1 change
        let r1 = manager.check_ja4_reputation("1.2.3.4", "fp2", 1000).unwrap();
        assert_eq!(r1.change_count, 1);
        assert!(!r1.rapid_changes);

        // 2 changes
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp3", 2000).unwrap();
        assert_eq!(r2.change_count, 2);
        assert!(!r2.rapid_changes);

        // 3 changes - should trigger
        let r3 = manager.check_ja4_reputation("1.2.3.4", "fp4", 3000).unwrap();
        assert_eq!(r3.change_count, 3);
        assert!(r3.rapid_changes);
    }

    #[test]
    fn test_ja4_rapid_stays_triggered() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Build up to trigger threshold
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);
        manager.check_ja4_reputation("1.2.3.4", "fp2", 1000);
        manager.check_ja4_reputation("1.2.3.4", "fp3", 2000);
        let r = manager.check_ja4_reputation("1.2.3.4", "fp4", 3000).unwrap();
        assert!(r.rapid_changes);

        // Additional changes should keep triggering
        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp5", 4000).unwrap();
        assert!(r2.rapid_changes);
        assert_eq!(r2.change_count, 4);

        let r3 = manager.check_ja4_reputation("1.2.3.4", "fp6", 5000).unwrap();
        assert!(r3.rapid_changes);
        assert_eq!(r3.change_count, 5);
    }

    #[test]
    fn test_ja4_multiple_entities_isolated() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.1.1.1");
        manager.touch_entity("2.2.2.2");

        // Build up changes for entity 1
        manager.check_ja4_reputation("1.1.1.1", "fp1", 0);
        manager.check_ja4_reputation("1.1.1.1", "fp2", 1000);
        manager.check_ja4_reputation("1.1.1.1", "fp3", 2000);
        let r1 = manager.check_ja4_reputation("1.1.1.1", "fp4", 3000).unwrap();
        assert!(r1.rapid_changes);

        // Entity 2 should be unaffected
        let r2 = manager.check_ja4_reputation("2.2.2.2", "other_fp", 3000);
        assert!(r2.is_some());
        let r2 = r2.unwrap();
        assert!(!r2.rapid_changes);
        assert_eq!(r2.change_count, 0);
    }

    #[test]
    fn test_ja4_same_fingerprint_repeated_no_change() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Set initial fingerprint
        manager.check_ja4_reputation("1.2.3.4", "constant_fp", 0);

        // Repeatedly check same fingerprint - should not increment
        for i in 1..10 {
            let r = manager.check_ja4_reputation("1.2.3.4", "constant_fp", i * 1000).unwrap();
            assert_eq!(r.change_count, 0);
            assert!(!r.rapid_changes);
        }
    }

    #[test]
    fn test_ja4_alternating_fingerprints() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Alternating between two fingerprints should still count as changes
        manager.check_ja4_reputation("1.2.3.4", "fp_a", 0);
        let r1 = manager.check_ja4_reputation("1.2.3.4", "fp_b", 1000).unwrap();
        assert_eq!(r1.change_count, 1);

        let r2 = manager.check_ja4_reputation("1.2.3.4", "fp_a", 2000).unwrap();
        assert_eq!(r2.change_count, 2);

        let r3 = manager.check_ja4_reputation("1.2.3.4", "fp_b", 3000).unwrap();
        assert_eq!(r3.change_count, 3);
        assert!(r3.rapid_changes);
    }

    #[test]
    fn test_ja4_concurrent_checks() {
        use std::sync::Arc;
        use std::thread;

        let manager = Arc::new(EntityManager::new(EntityConfig::default()));
        manager.touch_entity("1.2.3.4");

        let mut handles = vec![];

        // Spawn multiple threads checking same entity
        for thread_id in 0..5 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..10 {
                    let fp = format!("fp_t{}_i{}", thread_id, i);
                    let ts = (thread_id * 10000 + i * 100) as u64;
                    let _ = manager.check_ja4_reputation("1.2.3.4", &fp, ts);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should complete without panics
        // Entity should still exist
        assert!(manager.get_entity("1.2.3.4").is_some());
    }

    #[test]
    fn test_ja4_with_fingerprint_association() {
        let manager = EntityManager::new(EntityConfig::default());

        // Create entity with fingerprint via touch
        manager.touch_entity_with_fingerprint(
            "1.2.3.4",
            Some("initial_ja4"),
            Some("combined_hash"),
        );

        // Check reputation should work
        let r = manager.check_ja4_reputation("1.2.3.4", "different_ja4", 1000);
        assert!(r.is_some());
        let r = r.unwrap();
        // First check sets previous_ja4, so no change counted
        // Wait, entity was touched with ja4, but check_ja4_reputation looks at previous_ja4 field
        // which is different from ja4_fingerprint field
        assert_eq!(r.change_count, 0); // First reputation check
    }

    #[test]
    fn test_entity_state_ja4_fields() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Check sequence of operations
        manager.check_ja4_reputation("1.2.3.4", "fp1", 1000);
        manager.check_ja4_reputation("1.2.3.4", "fp2", 2000);
        manager.check_ja4_reputation("1.2.3.4", "fp3", 3000);

        // Verify internal state through entry API
        let entry = manager.entities.get("1.2.3.4").unwrap();
        assert_eq!(entry.previous_ja4.as_deref(), Some("fp3"));
        assert_eq!(entry.ja4_change_count, 2);
        assert!(entry.last_ja4_change_ms.is_some());
    }

    #[test]
    fn test_ja4_after_entity_release() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Build up some changes
        manager.check_ja4_reputation("1.2.3.4", "fp1", 0);
        manager.check_ja4_reputation("1.2.3.4", "fp2", 1000);

        // Release entity - note: release_entity only resets risk, blocked, and matches
        // but does NOT reset JA4 tracking fields (previous_ja4, ja4_change_count, etc.)
        manager.release_entity("1.2.3.4");

        // Entity still exists with cleared risk but JA4 state preserved
        // Touch to update timestamps
        manager.touch_entity("1.2.3.4");

        // Check with a different fingerprint - since previous_ja4 is preserved ("fp2"),
        // this will count as another change
        let r = manager.check_ja4_reputation("1.2.3.4", "new_fp", 5000);
        assert!(r.is_some());
        let r = r.unwrap();
        // JA4 change count continues from where it was (1 change from fp1->fp2)
        // Now adding fp2->new_fp = 2 changes total
        // But timestamp 5000 vs 1000 = 4000ms which is within 60s window
        assert_eq!(r.change_count, 2);
        assert!(!r.rapid_changes); // Need 3+ for rapid_changes
    }

    #[test]
    fn test_ja4_special_characters_in_fingerprint() {
        let manager = EntityManager::new(EntityConfig::default());
        manager.touch_entity("1.2.3.4");

        // Fingerprints with special characters
        let special_fps = [
            "t13d1516h2_8daaf6152771_02713d6af862",  // Real JA4 format
            "fp-with-dashes",
            "fp_with_underscores",
            "fp.with.dots",
            "fp/with/slashes",
            "fp\\with\\backslashes",
            "fp:with:colons",
            "fp;with;semicolons",
        ];

        for (i, fp) in special_fps.iter().enumerate() {
            let r = manager.check_ja4_reputation("1.2.3.4", fp, (i * 1000) as u64);
            assert!(r.is_some(), "Failed for fingerprint: {}", fp);
        }
    }

    // ==================== Exponential Decay Tests ====================

    #[test]
    fn test_exponential_decay_basic() {
        // With 5 minute half-life, risk should decay to ~50% after 5 minutes
        let config = EntityConfig {
            risk_half_life_minutes: 5.0,
            repeat_offender_max_factor: 3.0,
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        // Create entity with risk
        manager.touch_entity("1.2.3.4");
        manager.apply_rule_risk("1.2.3.4", 100, 80.0, false);

        let initial = manager.get_entity("1.2.3.4").unwrap();
        assert!((initial.risk - 80.0).abs() < 0.1, "Initial risk should be ~80");

        // Simulate 5 minutes passing (half-life)
        let five_minutes_ms = 5 * 60 * 1000;
        let risk_after = manager.test_decay("1.2.3.4", five_minutes_ms).unwrap();

        // Risk should be approximately 50% (40.0)
        let ratio = risk_after / 80.0;
        assert!(
            (ratio - 0.5).abs() < 0.05,
            "After 1 half-life, risk should be ~50%: got ratio {}",
            ratio
        );
    }

    #[test]
    fn test_exponential_decay_two_half_lives() {
        let config = EntityConfig {
            risk_half_life_minutes: 5.0,
            repeat_offender_max_factor: 3.0,
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        manager.touch_entity("1.2.3.4");
        manager.apply_rule_risk("1.2.3.4", 100, 100.0, false);

        // Simulate 10 minutes passing (2 half-lives)
        let ten_minutes_ms = 10 * 60 * 1000;
        let risk_after = manager.test_decay("1.2.3.4", ten_minutes_ms).unwrap();

        // Risk should be approximately 25% (2 half-lives = 0.5^2 = 0.25)
        let ratio = risk_after / 100.0;
        assert!(
            (ratio - 0.25).abs() < 0.05,
            "After 2 half-lives, risk should be ~25%: got ratio {}",
            ratio
        );
    }

    #[test]
    fn test_repeat_offender_decay_slowdown() {
        let config = EntityConfig {
            risk_half_life_minutes: 5.0,
            repeat_offender_max_factor: 3.0,
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        // Create two entities: one first-time offender, one repeat offender
        manager.touch_entity("first.offender");
        manager.touch_entity("repeat.offender");

        // First offender: just one rule match
        manager.apply_rule_risk("first.offender", 100, 80.0, true);

        // Repeat offender: many rule matches (21+ matches = 3x factor)
        manager.apply_rule_risk("repeat.offender", 100, 80.0, true);
        for i in 2..=25 {
            manager.apply_rule_risk("repeat.offender", i, 0.0, true);
        }

        // Verify initial risk is similar
        let first_initial = manager.get_entity("first.offender").unwrap().risk;
        let repeat_initial = manager.test_get_entity_state("repeat.offender").unwrap().risk;
        assert!((first_initial - repeat_initial).abs() < 1.0, "Initial risk should be similar");

        // Simulate 5 minutes of decay
        let five_minutes_ms = 5 * 60 * 1000;
        let first_risk_after = manager.test_decay("first.offender", five_minutes_ms).unwrap();
        let repeat_risk_after = manager.test_decay("repeat.offender", five_minutes_ms).unwrap();

        // Repeat offender should have higher remaining risk (slower decay)
        assert!(
            repeat_risk_after > first_risk_after,
            "Repeat offender should decay slower: first={}, repeat={}",
            first_risk_after, repeat_risk_after
        );

        // First offender: 5 min = 1 half-life → ~50% remaining
        let first_ratio = first_risk_after / first_initial;
        assert!(
            (first_ratio - 0.5).abs() < 0.1,
            "First offender should be ~50%: got {}",
            first_ratio
        );

        // Repeat offender with 3x factor: 5 min = only ~1/3 half-life → ~79% remaining
        let repeat_ratio = repeat_risk_after / repeat_initial;
        assert!(
            repeat_ratio > 0.7,
            "Repeat offender should retain >70%: got {}",
            repeat_ratio
        );
    }

    #[test]
    fn test_calculate_repeat_offender_factor() {
        let manager = EntityManager::default();

        // Test all tiers
        assert_eq!(manager.calculate_repeat_offender_factor(0), 1.0);
        assert_eq!(manager.calculate_repeat_offender_factor(2), 1.0);
        assert_eq!(manager.calculate_repeat_offender_factor(3), 1.25);
        assert_eq!(manager.calculate_repeat_offender_factor(5), 1.25);
        assert_eq!(manager.calculate_repeat_offender_factor(6), 1.5);
        assert_eq!(manager.calculate_repeat_offender_factor(10), 1.5);
        assert_eq!(manager.calculate_repeat_offender_factor(11), 2.0);
        assert_eq!(manager.calculate_repeat_offender_factor(20), 2.0);
        assert_eq!(manager.calculate_repeat_offender_factor(21), 3.0); // max_factor
        assert_eq!(manager.calculate_repeat_offender_factor(100), 3.0);
    }

    #[test]
    fn test_decay_clamps_small_values_to_zero() {
        let config = EntityConfig {
            risk_half_life_minutes: 1.0, // Fast decay for testing
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        manager.touch_entity("1.2.3.4");
        manager.apply_rule_risk("1.2.3.4", 100, 0.005, false); // Very small risk

        // After significant decay, should clamp to exactly zero
        let sixty_minutes_ms = 60 * 60 * 1000; // 60 half-lives
        let risk_after = manager.test_decay("1.2.3.4", sixty_minutes_ms).unwrap();

        assert_eq!(risk_after, 0.0, "Very small risk should clamp to 0.0");
    }

    #[test]
    fn test_nonlinear_decay_prevents_timing_attacks() {
        // This test verifies that decay is non-linear (proportional to current risk),
        // making timing attacks harder than with linear decay
        let config = EntityConfig {
            risk_half_life_minutes: 5.0,
            ..Default::default()
        };
        let manager = EntityManager::new(config);

        // Test two entities with different starting risks
        manager.touch_entity("high.risk");
        manager.touch_entity("low.risk");
        manager.apply_rule_risk("high.risk", 100, 80.0, false);
        manager.apply_rule_risk("low.risk", 100, 40.0, false);

        // Decay both for 1 minute
        let one_minute_ms = 60 * 1000;
        let high_after = manager.test_decay("high.risk", one_minute_ms).unwrap();
        let low_after = manager.test_decay("low.risk", one_minute_ms).unwrap();

        // Calculate absolute drops
        let drop_from_80 = 80.0 - high_after;
        let drop_from_40 = 40.0 - low_after;

        // With exponential decay, the *amount* dropped is proportional to current level
        // 80 → drops more than 40 → in the same time period
        // Drop from 80 should be about 2x the drop from 40 (since risk is 2x higher)
        let drop_ratio = drop_from_80 / drop_from_40;
        assert!(
            (drop_ratio - 2.0).abs() < 0.1,
            "Exponential decay should be proportional to current risk: ratio={}",
            drop_ratio
        );
    }

}
