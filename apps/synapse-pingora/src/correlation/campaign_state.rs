//! Campaign state structures and storage for tracking correlated threat campaigns.
//!
//! This module provides the data model for campaigns detected by correlation engines.
//! Campaigns group related threat actors (IP addresses) that exhibit coordinated behavior
//! such as shared fingerprints, timing patterns, or behavioral similarities.
//!
//! # Architecture
//!
//! - `Campaign` - A detected threat campaign with actors, status, and metrics
//! - `CampaignStore` - Thread-safe storage using DashMap for concurrent access
//! - `CampaignStatus` - Lifecycle states from detection through resolution
//! - `CorrelationType` - Types of correlations that link actors together
//!
//! # Example
//!
//! ```rust
//! use synapse_pingora::correlation::campaign_state::{
//!     CampaignStore, Campaign, CampaignStatus, CorrelationType, CorrelationReason,
//! };
//! use chrono::Utc;
//!
//! let store = CampaignStore::new();
//!
//! // Create a new campaign
//! let campaign = Campaign {
//!     id: Campaign::generate_id(),
//!     status: CampaignStatus::Detected,
//!     actors: vec!["192.168.1.100".to_string(), "192.168.1.101".to_string()],
//!     actor_count: 2,
//!     confidence: 0.85,
//!     attack_types: vec!["SQLi".to_string()],
//!     correlation_reasons: vec![CorrelationReason {
//!         correlation_type: CorrelationType::SharedFingerprint,
//!         confidence: 0.9,
//!         description: "Identical JA4 fingerprint".to_string(),
//!         evidence: vec!["192.168.1.100".to_string(), "192.168.1.101".to_string()],
//!     }],
//!     first_seen: Utc::now(),
//!     last_activity: Utc::now(),
//!     total_requests: 50,
//!     blocked_requests: 12,
//!     rules_triggered: 8,
//!     risk_score: 75,
//!     resolved_at: None,
//!     resolved_reason: None,
//! };
//!
//! store.create_campaign(campaign).unwrap();
//! ```

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during campaign operations.
#[derive(Debug, Error)]
pub enum CampaignError {
    /// Campaign with the given ID was not found.
    #[error("Campaign not found: {0}")]
    NotFound(String),

    /// Campaign with the given ID already exists.
    #[error("Campaign already exists: {0}")]
    AlreadyExists(String),

    /// Actor (IP) is not part of the specified campaign.
    #[error("Actor not in campaign: {0}")]
    ActorNotInCampaign(String),

    /// Invalid campaign state transition or operation.
    #[error("Invalid campaign state: {0}")]
    InvalidState(String),
}

// ============================================================================
// Campaign Status and Types
// ============================================================================

/// Status of a detected campaign.
///
/// Campaigns progress through lifecycle states from initial detection
/// through resolution or dormancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum CampaignStatus {
    /// Newly detected, under observation.
    /// The system has identified potential correlation but is gathering more evidence.
    Detected,

    /// Confirmed active threat.
    /// The campaign has been validated and is actively generating malicious traffic.
    Active,

    /// Previously active, now quiet.
    /// No activity has been seen for a period, but the campaign hasn't been resolved.
    Dormant,

    /// Resolved/mitigated.
    /// The campaign has been addressed and is no longer a concern.
    Resolved,
}

impl Default for CampaignStatus {
    fn default() -> Self {
        Self::Detected
    }
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detected => write!(f, "detected"),
            Self::Active => write!(f, "active"),
            Self::Dormant => write!(f, "dormant"),
            Self::Resolved => write!(f, "resolved"),
        }
    }
}

/// Type of correlation that linked actors together.
///
/// Different correlation engines detect different types of relationships
/// between threat actors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// Actors share identical or highly similar fingerprints.
    /// This suggests the same client software or tooling.
    SharedFingerprint,

    /// Actors exhibit JA4 fingerprint rotation patterns.
    /// Rapid fingerprint changes indicate evasion attempts.
    Ja4Rotation,

    /// Actors show timing-based correlation.
    /// Request patterns arrive in coordinated bursts or sequences.
    TimingCorrelation,

    /// Actors exhibit similar attack behaviors.
    /// Same attack types, targets, or payloads suggest coordination.
    BehavioralSimilarity,

    /// Actors originate from related network segments.
    /// Same ASN, subnet, or geographic region increases correlation likelihood.
    NetworkProximity,
}

impl std::fmt::Display for CorrelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedFingerprint => write!(f, "shared_fingerprint"),
            Self::Ja4Rotation => write!(f, "ja4_rotation"),
            Self::TimingCorrelation => write!(f, "timing_correlation"),
            Self::BehavioralSimilarity => write!(f, "behavioral_similarity"),
            Self::NetworkProximity => write!(f, "network_proximity"),
        }
    }
}

// ============================================================================
// Correlation Reason
// ============================================================================

/// A reason why entities were correlated into a campaign.
///
/// Each correlation reason captures the type of correlation, confidence level,
/// and specific evidence that supports the correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReason {
    /// The type of correlation detected.
    pub correlation_type: CorrelationType,

    /// Confidence level for this correlation (0.0 to 1.0).
    /// Higher values indicate stronger evidence.
    pub confidence: f64,

    /// Human-readable description of the correlation.
    pub description: String,

    /// Evidence supporting the correlation (e.g., IP addresses, fingerprints).
    pub evidence: Vec<String>,
}

impl CorrelationReason {
    /// Create a new correlation reason with the given parameters.
    pub fn new(
        correlation_type: CorrelationType,
        confidence: f64,
        description: impl Into<String>,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            correlation_type,
            confidence: confidence.clamp(0.0, 1.0),
            description: description.into(),
            evidence,
        }
    }
}

// ============================================================================
// Campaign
// ============================================================================

/// A detected threat campaign.
///
/// Campaigns group related threat actors (IP addresses) that exhibit
/// coordinated behavior. They track activity metrics, confidence levels,
/// and the reasons for correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    /// Unique campaign identifier (e.g., "camp-18abc123def").
    pub id: String,

    /// Current status of the campaign.
    pub status: CampaignStatus,

    /// List of actor IP addresses in this campaign.
    pub actors: Vec<String>,

    /// Number of actors (cached for efficiency).
    pub actor_count: usize,

    /// Overall confidence score for the campaign (0.0 to 1.0).
    pub confidence: f64,

    /// Types of attacks observed from this campaign.
    pub attack_types: Vec<String>,

    /// Reasons why actors were correlated into this campaign.
    pub correlation_reasons: Vec<CorrelationReason>,

    /// When the campaign was first detected.
    pub first_seen: DateTime<Utc>,

    /// When the most recent activity was observed.
    pub last_activity: DateTime<Utc>,

    /// Total number of requests from all actors.
    pub total_requests: u64,

    /// Number of requests that were blocked.
    pub blocked_requests: u64,

    /// Number of WAF rules triggered by this campaign.
    pub rules_triggered: u64,

    /// Aggregate risk score for the campaign.
    pub risk_score: u32,

    /// When the campaign was resolved (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,

    /// Reason for resolution (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_reason: Option<String>,
}

impl Campaign {
    /// Generate a new unique campaign ID.
    ///
    /// Format: `camp-{timestamp_hex}` where timestamp is milliseconds since Unix epoch.
    pub fn generate_id() -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        format!("camp-{:x}", timestamp)
    }

    /// Create a new campaign with minimal required fields.
    ///
    /// Sets default values for metrics and timestamps.
    pub fn new(id: String, actors: Vec<String>, confidence: f64) -> Self {
        let now = Utc::now();
        let actor_count = actors.len();
        Self {
            id,
            status: CampaignStatus::Detected,
            actors,
            actor_count,
            confidence: confidence.clamp(0.0, 1.0),
            attack_types: Vec::new(),
            correlation_reasons: Vec::new(),
            first_seen: now,
            last_activity: now,
            total_requests: 0,
            blocked_requests: 0,
            rules_triggered: 0,
            risk_score: 0,
            resolved_at: None,
            resolved_reason: None,
        }
    }

    /// Check if the campaign is currently active (not resolved).
    #[inline]
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            CampaignStatus::Detected | CampaignStatus::Active
        )
    }

    /// Check if the campaign has been resolved.
    #[inline]
    pub fn is_resolved(&self) -> bool {
        self.status == CampaignStatus::Resolved
    }

    /// Get the duration since last activity.
    pub fn time_since_activity(&self) -> Duration {
        Utc::now().signed_duration_since(self.last_activity)
    }

    /// Calculate the block rate (blocked / total requests).
    pub fn block_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.blocked_requests as f64 / self.total_requests as f64
        }
    }
}

// ============================================================================
// Campaign Update
// ============================================================================

/// Update parameters for modifying an existing campaign.
///
/// All fields are optional; only non-None fields will be applied.
#[derive(Debug, Clone, Default)]
pub struct CampaignUpdate {
    /// New status for the campaign.
    pub status: Option<CampaignStatus>,

    /// New confidence level.
    pub confidence: Option<f64>,

    /// Replace attack types with this list.
    pub attack_types: Option<Vec<String>>,

    /// Add a new correlation reason.
    pub add_correlation_reason: Option<CorrelationReason>,

    /// Increment total requests by this amount.
    pub increment_requests: Option<u64>,

    /// Increment blocked requests by this amount.
    pub increment_blocked: Option<u64>,

    /// Increment rules triggered by this amount.
    pub increment_rules: Option<u64>,

    /// New risk score for the campaign.
    pub risk_score: Option<u32>,
}

impl CampaignUpdate {
    /// Create a new empty update.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method to set status.
    pub fn with_status(mut self, status: CampaignStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Builder method to set confidence.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Builder method to increment request counts.
    pub fn with_request_increment(mut self, total: u64, blocked: u64) -> Self {
        self.increment_requests = Some(total);
        self.increment_blocked = Some(blocked);
        self
    }
}

// ============================================================================
// Campaign Store Statistics
// ============================================================================

/// Statistics about the campaign store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CampaignStoreStats {
    /// Total number of campaigns in the store.
    pub total_campaigns: usize,

    /// Number of active campaigns.
    pub active_campaigns: usize,

    /// Number of detected (unconfirmed) campaigns.
    pub detected_campaigns: usize,

    /// Number of resolved campaigns.
    pub resolved_campaigns: usize,

    /// Total number of actors across all campaigns.
    pub total_actors: usize,
}

// ============================================================================
// Campaign Store
// ============================================================================

/// Thread-safe campaign storage using DashMap.
///
/// Provides concurrent access to campaigns with atomic operations.
/// Maintains a reverse index from IP addresses to campaign IDs for
/// efficient lookups.
pub struct CampaignStore {
    /// Primary storage: campaign_id -> Campaign.
    campaigns: DashMap<String, Campaign>,

    /// Reverse index: IP address -> campaign_id.
    /// Allows quick lookup of which campaign an IP belongs to.
    ip_to_campaign: DashMap<String, String>,
}

impl Default for CampaignStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CampaignStore {
    /// Create a new empty campaign store.
    pub fn new() -> Self {
        Self {
            campaigns: DashMap::new(),
            ip_to_campaign: DashMap::new(),
        }
    }

    /// Create a new campaign store with initial capacity hints.
    pub fn with_capacity(campaigns: usize, actors: usize) -> Self {
        Self {
            campaigns: DashMap::with_capacity(campaigns),
            ip_to_campaign: DashMap::with_capacity(actors),
        }
    }

    // ========================================================================
    // CRUD Operations
    // ========================================================================

    /// Create a new campaign in the store.
    ///
    /// Returns an error if a campaign with the same ID already exists.
    /// Also populates the IP-to-campaign reverse index.
    pub fn create_campaign(&self, campaign: Campaign) -> Result<(), CampaignError> {
        let id = campaign.id.clone();

        // Check for existing campaign
        if self.campaigns.contains_key(&id) {
            return Err(CampaignError::AlreadyExists(id));
        }

        // Add actors to reverse index
        for actor in &campaign.actors {
            self.ip_to_campaign.insert(actor.clone(), id.clone());
        }

        // Insert campaign
        self.campaigns.insert(id, campaign);

        Ok(())
    }

    /// Get a campaign by ID.
    ///
    /// Returns a cloned copy of the campaign for thread safety.
    pub fn get_campaign(&self, id: &str) -> Option<Campaign> {
        self.campaigns.get(id).map(|entry| entry.value().clone())
    }

    /// Get the campaign ID for an IP address.
    ///
    /// Uses the reverse index for O(1) lookup.
    pub fn get_campaign_for_ip(&self, ip: &str) -> Option<String> {
        self.ip_to_campaign.get(ip).map(|entry| entry.value().clone())
    }

    /// Update an existing campaign with the given update parameters.
    ///
    /// Returns an error if the campaign doesn't exist.
    pub fn update_campaign(&self, id: &str, update: CampaignUpdate) -> Result<(), CampaignError> {
        let mut entry = self
            .campaigns
            .get_mut(id)
            .ok_or_else(|| CampaignError::NotFound(id.to_string()))?;

        let campaign = entry.value_mut();

        // Apply updates
        if let Some(status) = update.status {
            campaign.status = status;
        }

        if let Some(confidence) = update.confidence {
            campaign.confidence = confidence.clamp(0.0, 1.0);
        }

        if let Some(attack_types) = update.attack_types {
            campaign.attack_types = attack_types;
        }

        if let Some(reason) = update.add_correlation_reason {
            campaign.correlation_reasons.push(reason);
        }

        if let Some(increment) = update.increment_requests {
            campaign.total_requests = campaign.total_requests.saturating_add(increment);
        }

        if let Some(increment) = update.increment_blocked {
            campaign.blocked_requests = campaign.blocked_requests.saturating_add(increment);
        }

        if let Some(increment) = update.increment_rules {
            campaign.rules_triggered = campaign.rules_triggered.saturating_add(increment);
        }

        if let Some(risk_score) = update.risk_score {
            campaign.risk_score = risk_score;
        }

        // Always update last_activity timestamp
        campaign.last_activity = Utc::now();

        Ok(())
    }

    // ========================================================================
    // Actor Management
    // ========================================================================

    /// Add an actor (IP address) to an existing campaign.
    ///
    /// Returns an error if the campaign doesn't exist.
    /// Skips if the actor is already in the campaign.
    pub fn add_actor_to_campaign(&self, campaign_id: &str, ip: &str) -> Result<(), CampaignError> {
        let mut entry = self
            .campaigns
            .get_mut(campaign_id)
            .ok_or_else(|| CampaignError::NotFound(campaign_id.to_string()))?;

        let campaign = entry.value_mut();

        // Check if actor already exists
        if !campaign.actors.contains(&ip.to_string()) {
            campaign.actors.push(ip.to_string());
            campaign.actor_count = campaign.actors.len();
            campaign.last_activity = Utc::now();

            // Update reverse index
            self.ip_to_campaign
                .insert(ip.to_string(), campaign_id.to_string());
        }

        Ok(())
    }

    /// Remove an actor (IP address) from a campaign.
    ///
    /// Returns an error if the campaign doesn't exist or the actor isn't in it.
    pub fn remove_actor_from_campaign(
        &self,
        campaign_id: &str,
        ip: &str,
    ) -> Result<(), CampaignError> {
        let mut entry = self
            .campaigns
            .get_mut(campaign_id)
            .ok_or_else(|| CampaignError::NotFound(campaign_id.to_string()))?;

        let campaign = entry.value_mut();

        // Find and remove the actor
        let original_len = campaign.actors.len();
        campaign.actors.retain(|actor| actor != ip);

        if campaign.actors.len() == original_len {
            return Err(CampaignError::ActorNotInCampaign(ip.to_string()));
        }

        campaign.actor_count = campaign.actors.len();
        campaign.last_activity = Utc::now();

        // Update reverse index
        self.ip_to_campaign.remove(ip);

        Ok(())
    }

    // ========================================================================
    // Listing and Querying
    // ========================================================================

    /// List all campaigns, optionally filtered by status.
    ///
    /// Returns a vector of cloned campaigns for thread safety.
    pub fn list_campaigns(&self, status_filter: Option<CampaignStatus>) -> Vec<Campaign> {
        self.campaigns
            .iter()
            .filter(|entry| {
                status_filter
                    .map(|status| entry.value().status == status)
                    .unwrap_or(true)
            })
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// List all active campaigns (Detected or Active status).
    ///
    /// Convenience method for common use case.
    pub fn list_active_campaigns(&self) -> Vec<Campaign> {
        self.campaigns
            .iter()
            .filter(|entry| entry.value().is_active())
            .map(|entry| entry.value().clone())
            .collect()
    }

    // ========================================================================
    // Lifecycle Management
    // ========================================================================

    /// Mark a campaign as resolved with the given reason.
    ///
    /// Sets status to Resolved and records the resolution timestamp.
    pub fn resolve_campaign(&self, id: &str, reason: &str) -> Result<(), CampaignError> {
        let mut entry = self
            .campaigns
            .get_mut(id)
            .ok_or_else(|| CampaignError::NotFound(id.to_string()))?;

        let campaign = entry.value_mut();

        // Check if already resolved
        if campaign.status == CampaignStatus::Resolved {
            return Err(CampaignError::InvalidState(format!(
                "Campaign {} is already resolved",
                id
            )));
        }

        campaign.status = CampaignStatus::Resolved;
        campaign.resolved_at = Some(Utc::now());
        campaign.resolved_reason = Some(reason.to_string());
        campaign.last_activity = Utc::now();

        Ok(())
    }

    /// Expire dormant campaigns that haven't had activity within max_age.
    ///
    /// Campaigns with no activity for longer than max_age are marked as Dormant.
    /// Returns the IDs of campaigns that were marked dormant.
    pub fn expire_dormant_campaigns(&self, max_age: Duration) -> Vec<String> {
        let now = Utc::now();
        let mut expired = Vec::new();

        for mut entry in self.campaigns.iter_mut() {
            let campaign = entry.value_mut();

            // Skip already resolved or dormant campaigns
            if matches!(
                campaign.status,
                CampaignStatus::Resolved | CampaignStatus::Dormant
            ) {
                continue;
            }

            // Check if campaign has exceeded max age
            let age = now.signed_duration_since(campaign.last_activity);
            if age > max_age {
                campaign.status = CampaignStatus::Dormant;
                expired.push(campaign.id.clone());
            }
        }

        expired
    }

    // ========================================================================
    // Statistics
    // ========================================================================

    /// Get statistics about the campaign store.
    pub fn stats(&self) -> CampaignStoreStats {
        let mut active = 0;
        let mut detected = 0;
        let mut resolved = 0;
        let mut total_actors = 0;

        for entry in self.campaigns.iter() {
            let campaign = entry.value();
            total_actors += campaign.actor_count;

            match campaign.status {
                CampaignStatus::Detected => {
                    detected += 1;
                    active += 1;
                }
                CampaignStatus::Active => active += 1,
                CampaignStatus::Resolved => resolved += 1,
                CampaignStatus::Dormant => {}
            }
        }

        CampaignStoreStats {
            total_campaigns: self.campaigns.len(),
            active_campaigns: active,
            detected_campaigns: detected,
            resolved_campaigns: resolved,
            total_actors,
        }
    }

    /// Get the number of campaigns in the store.
    #[inline]
    pub fn len(&self) -> usize {
        self.campaigns.len()
    }

    /// Check if the store is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.campaigns.is_empty()
    }

    /// Clear all campaigns from the store.
    ///
    /// Also clears the reverse index.
    pub fn clear(&self) {
        self.campaigns.clear();
        self.ip_to_campaign.clear();
    }

    /// Remove a campaign by ID.
    ///
    /// Also removes all associated actors from the reverse index.
    /// Returns the removed campaign if it existed.
    pub fn remove_campaign(&self, id: &str) -> Option<Campaign> {
        if let Some((_, campaign)) = self.campaigns.remove(id) {
            // Clean up reverse index
            for actor in &campaign.actors {
                self.ip_to_campaign.remove(actor);
            }
            Some(campaign)
        } else {
            None
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Campaign Tests
    // ========================================================================

    #[test]
    fn test_campaign_generate_id() {
        let id1 = Campaign::generate_id();
        let id2 = Campaign::generate_id();

        assert!(id1.starts_with("camp-"));
        assert!(id2.starts_with("camp-"));
        // IDs should be unique (different timestamps)
        // Note: They might be the same if generated too quickly
        assert!(id1.len() > 5); // "camp-" + at least some hex
    }

    #[test]
    fn test_campaign_new() {
        let actors = vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()];
        let campaign = Campaign::new("test-1".to_string(), actors.clone(), 0.85);

        assert_eq!(campaign.id, "test-1");
        assert_eq!(campaign.status, CampaignStatus::Detected);
        assert_eq!(campaign.actors, actors);
        assert_eq!(campaign.actor_count, 2);
        assert!((campaign.confidence - 0.85).abs() < 0.001);
        assert!(campaign.is_active());
        assert!(!campaign.is_resolved());
    }

    #[test]
    fn test_campaign_confidence_clamping() {
        let campaign = Campaign::new("test-1".to_string(), vec![], 1.5);
        assert!((campaign.confidence - 1.0).abs() < 0.001);

        let campaign = Campaign::new("test-2".to_string(), vec![], -0.5);
        assert!(campaign.confidence >= 0.0);
    }

    #[test]
    fn test_campaign_block_rate() {
        let mut campaign = Campaign::new("test-1".to_string(), vec![], 0.9);

        // No requests - should return 0
        assert!((campaign.block_rate() - 0.0).abs() < 0.001);

        // 50% block rate
        campaign.total_requests = 100;
        campaign.blocked_requests = 50;
        assert!((campaign.block_rate() - 0.5).abs() < 0.001);

        // 100% block rate
        campaign.blocked_requests = 100;
        assert!((campaign.block_rate() - 1.0).abs() < 0.001);
    }

    // ========================================================================
    // CampaignStore CRUD Tests
    // ========================================================================

    #[test]
    fn test_store_create_campaign() {
        let store = CampaignStore::new();
        let campaign = Campaign::new(
            "camp-1".to_string(),
            vec!["192.168.1.1".to_string()],
            0.9,
        );

        let result = store.create_campaign(campaign);
        assert!(result.is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_store_create_duplicate_fails() {
        let store = CampaignStore::new();

        let campaign1 = Campaign::new("camp-1".to_string(), vec![], 0.9);
        store.create_campaign(campaign1).unwrap();

        let campaign2 = Campaign::new("camp-1".to_string(), vec![], 0.8);
        let result = store.create_campaign(campaign2);

        assert!(matches!(result, Err(CampaignError::AlreadyExists(_))));
    }

    #[test]
    fn test_store_get_campaign() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec!["10.0.0.1".to_string()], 0.9);
        store.create_campaign(campaign).unwrap();

        let retrieved = store.get_campaign("camp-1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, "camp-1");

        let not_found = store.get_campaign("nonexistent");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_store_get_campaign_for_ip() {
        let store = CampaignStore::new();
        let campaign = Campaign::new(
            "camp-1".to_string(),
            vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
            0.9,
        );
        store.create_campaign(campaign).unwrap();

        // Both IPs should map to the campaign
        assert_eq!(
            store.get_campaign_for_ip("192.168.1.1"),
            Some("camp-1".to_string())
        );
        assert_eq!(
            store.get_campaign_for_ip("192.168.1.2"),
            Some("camp-1".to_string())
        );

        // Unknown IP should return None
        assert!(store.get_campaign_for_ip("10.0.0.1").is_none());
    }

    #[test]
    fn test_store_update_campaign() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec![], 0.5);
        store.create_campaign(campaign).unwrap();

        let update = CampaignUpdate::new()
            .with_status(CampaignStatus::Active)
            .with_confidence(0.95);

        let result = store.update_campaign("camp-1", update);
        assert!(result.is_ok());

        let updated = store.get_campaign("camp-1").unwrap();
        assert_eq!(updated.status, CampaignStatus::Active);
        assert!((updated.confidence - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_store_update_nonexistent_fails() {
        let store = CampaignStore::new();
        let update = CampaignUpdate::new().with_confidence(0.9);

        let result = store.update_campaign("nonexistent", update);
        assert!(matches!(result, Err(CampaignError::NotFound(_))));
    }

    #[test]
    fn test_store_update_increments() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec![], 0.9);
        store.create_campaign(campaign).unwrap();

        let update = CampaignUpdate {
            increment_requests: Some(100),
            increment_blocked: Some(25),
            increment_rules: Some(10),
            ..Default::default()
        };

        store.update_campaign("camp-1", update).unwrap();

        let updated = store.get_campaign("camp-1").unwrap();
        assert_eq!(updated.total_requests, 100);
        assert_eq!(updated.blocked_requests, 25);
        assert_eq!(updated.rules_triggered, 10);
    }

    // ========================================================================
    // Actor Management Tests
    // ========================================================================

    #[test]
    fn test_store_add_actor() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec!["10.0.0.1".to_string()], 0.9);
        store.create_campaign(campaign).unwrap();

        let result = store.add_actor_to_campaign("camp-1", "10.0.0.2");
        assert!(result.is_ok());

        let updated = store.get_campaign("camp-1").unwrap();
        assert_eq!(updated.actor_count, 2);
        assert!(updated.actors.contains(&"10.0.0.2".to_string()));

        // Reverse index should be updated
        assert_eq!(
            store.get_campaign_for_ip("10.0.0.2"),
            Some("camp-1".to_string())
        );
    }

    #[test]
    fn test_store_add_duplicate_actor_idempotent() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec!["10.0.0.1".to_string()], 0.9);
        store.create_campaign(campaign).unwrap();

        // Adding same actor twice should be idempotent
        store.add_actor_to_campaign("camp-1", "10.0.0.1").unwrap();
        store.add_actor_to_campaign("camp-1", "10.0.0.1").unwrap();

        let updated = store.get_campaign("camp-1").unwrap();
        assert_eq!(updated.actor_count, 1); // Still only 1 actor
    }

    #[test]
    fn test_store_remove_actor() {
        let store = CampaignStore::new();
        let campaign = Campaign::new(
            "camp-1".to_string(),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            0.9,
        );
        store.create_campaign(campaign).unwrap();

        let result = store.remove_actor_from_campaign("camp-1", "10.0.0.1");
        assert!(result.is_ok());

        let updated = store.get_campaign("camp-1").unwrap();
        assert_eq!(updated.actor_count, 1);
        assert!(!updated.actors.contains(&"10.0.0.1".to_string()));

        // Reverse index should be updated
        assert!(store.get_campaign_for_ip("10.0.0.1").is_none());
    }

    #[test]
    fn test_store_remove_nonexistent_actor_fails() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec!["10.0.0.1".to_string()], 0.9);
        store.create_campaign(campaign).unwrap();

        let result = store.remove_actor_from_campaign("camp-1", "10.0.0.2");
        assert!(matches!(result, Err(CampaignError::ActorNotInCampaign(_))));
    }

    // ========================================================================
    // Listing Tests
    // ========================================================================

    #[test]
    fn test_store_list_campaigns() {
        let store = CampaignStore::new();

        // Create campaigns with different statuses
        let mut c1 = Campaign::new("camp-1".to_string(), vec![], 0.9);
        c1.status = CampaignStatus::Detected;

        let mut c2 = Campaign::new("camp-2".to_string(), vec![], 0.8);
        c2.status = CampaignStatus::Active;

        let mut c3 = Campaign::new("camp-3".to_string(), vec![], 0.7);
        c3.status = CampaignStatus::Resolved;

        store.create_campaign(c1).unwrap();
        store.create_campaign(c2).unwrap();
        store.create_campaign(c3).unwrap();

        // List all
        let all = store.list_campaigns(None);
        assert_eq!(all.len(), 3);

        // Filter by status
        let detected = store.list_campaigns(Some(CampaignStatus::Detected));
        assert_eq!(detected.len(), 1);
        assert_eq!(detected[0].id, "camp-1");

        let resolved = store.list_campaigns(Some(CampaignStatus::Resolved));
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "camp-3");
    }

    #[test]
    fn test_store_list_active_campaigns() {
        let store = CampaignStore::new();

        let mut c1 = Campaign::new("camp-1".to_string(), vec![], 0.9);
        c1.status = CampaignStatus::Detected;

        let mut c2 = Campaign::new("camp-2".to_string(), vec![], 0.8);
        c2.status = CampaignStatus::Active;

        let mut c3 = Campaign::new("camp-3".to_string(), vec![], 0.7);
        c3.status = CampaignStatus::Resolved;

        let mut c4 = Campaign::new("camp-4".to_string(), vec![], 0.6);
        c4.status = CampaignStatus::Dormant;

        store.create_campaign(c1).unwrap();
        store.create_campaign(c2).unwrap();
        store.create_campaign(c3).unwrap();
        store.create_campaign(c4).unwrap();

        let active = store.list_active_campaigns();
        assert_eq!(active.len(), 2);
        assert!(active.iter().all(|c| c.is_active()));
    }

    // ========================================================================
    // Lifecycle Tests
    // ========================================================================

    #[test]
    fn test_store_resolve_campaign() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec![], 0.9);
        store.create_campaign(campaign).unwrap();

        let result = store.resolve_campaign("camp-1", "Threat mitigated");
        assert!(result.is_ok());

        let resolved = store.get_campaign("camp-1").unwrap();
        assert_eq!(resolved.status, CampaignStatus::Resolved);
        assert!(resolved.resolved_at.is_some());
        assert_eq!(resolved.resolved_reason, Some("Threat mitigated".to_string()));
    }

    #[test]
    fn test_store_resolve_already_resolved_fails() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec![], 0.9);
        store.create_campaign(campaign).unwrap();

        store.resolve_campaign("camp-1", "First resolution").unwrap();

        let result = store.resolve_campaign("camp-1", "Second resolution");
        assert!(matches!(result, Err(CampaignError::InvalidState(_))));
    }

    #[test]
    fn test_store_expire_dormant_campaigns() {
        let store = CampaignStore::new();

        // Create a campaign with old activity
        let mut old_campaign = Campaign::new("camp-old".to_string(), vec![], 0.9);
        old_campaign.last_activity = Utc::now() - Duration::hours(2);
        store.create_campaign(old_campaign).unwrap();

        // Create a recent campaign
        let recent_campaign = Campaign::new("camp-recent".to_string(), vec![], 0.9);
        store.create_campaign(recent_campaign).unwrap();

        // Create an already resolved campaign (should not be affected)
        let mut resolved_campaign = Campaign::new("camp-resolved".to_string(), vec![], 0.9);
        resolved_campaign.status = CampaignStatus::Resolved;
        resolved_campaign.last_activity = Utc::now() - Duration::hours(3);
        store.create_campaign(resolved_campaign).unwrap();

        // Expire campaigns older than 1 hour
        let expired = store.expire_dormant_campaigns(Duration::hours(1));

        assert_eq!(expired.len(), 1);
        assert!(expired.contains(&"camp-old".to_string()));

        // Verify statuses
        let old = store.get_campaign("camp-old").unwrap();
        assert_eq!(old.status, CampaignStatus::Dormant);

        let recent = store.get_campaign("camp-recent").unwrap();
        assert_eq!(recent.status, CampaignStatus::Detected); // Unchanged

        let resolved = store.get_campaign("camp-resolved").unwrap();
        assert_eq!(resolved.status, CampaignStatus::Resolved); // Unchanged
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_store_stats() {
        let store = CampaignStore::new();

        let mut c1 = Campaign::new(
            "camp-1".to_string(),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            0.9,
        );
        c1.status = CampaignStatus::Detected;

        let mut c2 = Campaign::new(
            "camp-2".to_string(),
            vec!["10.0.0.3".to_string()],
            0.8,
        );
        c2.status = CampaignStatus::Active;

        let mut c3 = Campaign::new(
            "camp-3".to_string(),
            vec!["10.0.0.4".to_string(), "10.0.0.5".to_string()],
            0.7,
        );
        c3.status = CampaignStatus::Resolved;

        store.create_campaign(c1).unwrap();
        store.create_campaign(c2).unwrap();
        store.create_campaign(c3).unwrap();

        let stats = store.stats();
        assert_eq!(stats.total_campaigns, 3);
        assert_eq!(stats.active_campaigns, 2); // Detected + Active
        assert_eq!(stats.detected_campaigns, 1);
        assert_eq!(stats.resolved_campaigns, 1);
        assert_eq!(stats.total_actors, 5);
    }

    // ========================================================================
    // Status Transition Tests
    // ========================================================================

    #[test]
    fn test_campaign_status_transitions() {
        let store = CampaignStore::new();
        let campaign = Campaign::new("camp-1".to_string(), vec![], 0.9);
        store.create_campaign(campaign).unwrap();

        // Detected -> Active
        let update = CampaignUpdate::new().with_status(CampaignStatus::Active);
        store.update_campaign("camp-1", update).unwrap();
        assert_eq!(
            store.get_campaign("camp-1").unwrap().status,
            CampaignStatus::Active
        );

        // Active -> Dormant
        let update = CampaignUpdate::new().with_status(CampaignStatus::Dormant);
        store.update_campaign("camp-1", update).unwrap();
        assert_eq!(
            store.get_campaign("camp-1").unwrap().status,
            CampaignStatus::Dormant
        );

        // Dormant -> Active (campaign resumes)
        let update = CampaignUpdate::new().with_status(CampaignStatus::Active);
        store.update_campaign("camp-1", update).unwrap();
        assert_eq!(
            store.get_campaign("camp-1").unwrap().status,
            CampaignStatus::Active
        );
    }

    #[test]
    fn test_campaign_status_display() {
        assert_eq!(format!("{}", CampaignStatus::Detected), "detected");
        assert_eq!(format!("{}", CampaignStatus::Active), "active");
        assert_eq!(format!("{}", CampaignStatus::Dormant), "dormant");
        assert_eq!(format!("{}", CampaignStatus::Resolved), "resolved");
    }

    // ========================================================================
    // Correlation Type Tests
    // ========================================================================

    #[test]
    fn test_correlation_type_display() {
        assert_eq!(
            format!("{}", CorrelationType::SharedFingerprint),
            "shared_fingerprint"
        );
        assert_eq!(format!("{}", CorrelationType::Ja4Rotation), "ja4_rotation");
        assert_eq!(
            format!("{}", CorrelationType::TimingCorrelation),
            "timing_correlation"
        );
        assert_eq!(
            format!("{}", CorrelationType::BehavioralSimilarity),
            "behavioral_similarity"
        );
        assert_eq!(
            format!("{}", CorrelationType::NetworkProximity),
            "network_proximity"
        );
    }

    #[test]
    fn test_correlation_reason_new() {
        let reason = CorrelationReason::new(
            CorrelationType::SharedFingerprint,
            0.95,
            "Identical JA4 fingerprint detected",
            vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
        );

        assert_eq!(reason.correlation_type, CorrelationType::SharedFingerprint);
        assert!((reason.confidence - 0.95).abs() < 0.001);
        assert_eq!(reason.description, "Identical JA4 fingerprint detected");
        assert_eq!(reason.evidence.len(), 2);
    }

    #[test]
    fn test_correlation_reason_confidence_clamping() {
        let reason = CorrelationReason::new(
            CorrelationType::TimingCorrelation,
            1.5, // Over 1.0
            "Test",
            vec![],
        );
        assert!((reason.confidence - 1.0).abs() < 0.001);

        let reason = CorrelationReason::new(
            CorrelationType::TimingCorrelation,
            -0.5, // Under 0.0
            "Test",
            vec![],
        );
        assert!(reason.confidence >= 0.0);
    }

    // ========================================================================
    // Edge Cases and Thread Safety Tests
    // ========================================================================

    #[test]
    fn test_store_remove_campaign() {
        let store = CampaignStore::new();
        let campaign = Campaign::new(
            "camp-1".to_string(),
            vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
            0.9,
        );
        store.create_campaign(campaign).unwrap();

        // Verify IP mappings exist
        assert!(store.get_campaign_for_ip("10.0.0.1").is_some());
        assert!(store.get_campaign_for_ip("10.0.0.2").is_some());

        // Remove campaign
        let removed = store.remove_campaign("camp-1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, "camp-1");

        // Campaign should be gone
        assert!(store.get_campaign("camp-1").is_none());

        // IP mappings should be cleaned up
        assert!(store.get_campaign_for_ip("10.0.0.1").is_none());
        assert!(store.get_campaign_for_ip("10.0.0.2").is_none());
    }

    #[test]
    fn test_store_clear() {
        let store = CampaignStore::new();

        for i in 0..5 {
            let campaign = Campaign::new(
                format!("camp-{}", i),
                vec![format!("10.0.0.{}", i)],
                0.9,
            );
            store.create_campaign(campaign).unwrap();
        }

        assert_eq!(store.len(), 5);

        store.clear();

        assert!(store.is_empty());
        assert!(store.get_campaign_for_ip("10.0.0.1").is_none());
    }

    #[test]
    fn test_store_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(CampaignStore::new());
        let mut handles = vec![];

        // Spawn threads that create campaigns
        for i in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let campaign = Campaign::new(
                    format!("camp-{}", i),
                    vec![format!("10.0.{}.1", i)],
                    0.9,
                );
                let _ = store.create_campaign(campaign);

                // Add some actors
                for j in 2..5 {
                    let _ = store.add_actor_to_campaign(&format!("camp-{}", i), &format!("10.0.{}.{}", i, j));
                }
            }));
        }

        // Spawn threads that read campaigns
        for _ in 0..5 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = store.list_campaigns(None);
                    let _ = store.stats();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify no panics and reasonable state
        assert!(store.len() > 0);
        let stats = store.stats();
        assert!(stats.total_actors >= store.len()); // At least 1 actor per campaign
    }

    #[test]
    fn test_campaign_time_since_activity() {
        let mut campaign = Campaign::new("test".to_string(), vec![], 0.9);

        // Set last_activity to 1 hour ago
        campaign.last_activity = Utc::now() - Duration::hours(1);

        let elapsed = campaign.time_since_activity();
        // Should be approximately 1 hour (allow some slack for test execution)
        assert!(elapsed.num_minutes() >= 59);
        assert!(elapsed.num_minutes() <= 61);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let campaign = Campaign {
            id: "camp-test".to_string(),
            status: CampaignStatus::Active,
            actors: vec!["10.0.0.1".to_string()],
            actor_count: 1,
            confidence: 0.85,
            attack_types: vec!["SQLi".to_string()],
            correlation_reasons: vec![CorrelationReason {
                correlation_type: CorrelationType::SharedFingerprint,
                confidence: 0.9,
                description: "Test correlation".to_string(),
                evidence: vec!["10.0.0.1".to_string()],
            }],
            first_seen: Utc::now(),
            last_activity: Utc::now(),
            total_requests: 100,
            blocked_requests: 25,
            rules_triggered: 10,
            risk_score: 75,
            resolved_at: None,
            resolved_reason: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&campaign).unwrap();

        // Deserialize back
        let deserialized: Campaign = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.id, campaign.id);
        assert_eq!(deserialized.status, campaign.status);
        assert_eq!(deserialized.actor_count, campaign.actor_count);
        assert!((deserialized.confidence - campaign.confidence).abs() < 0.001);
    }

    #[test]
    fn test_serialization_skip_none_fields() {
        let campaign = Campaign::new("test".to_string(), vec![], 0.9);

        let json = serde_json::to_string(&campaign).unwrap();

        // resolved_at and resolved_reason should be omitted when None
        assert!(!json.contains("resolved_at"));
        assert!(!json.contains("resolved_reason"));
    }
}
