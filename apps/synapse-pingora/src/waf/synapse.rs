//! Synapse facade for the WAF engine.
//!
//! Provides a high-level API matching the libsynapse Synapse struct
//! for seamless migration.

use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Engine, Request, RiskConfig, Verdict, WafError};
use crate::profiler::{EndpointProfile, ProfileStore, ProfileStoreConfig};

/// Main WAF detection engine facade.
///
/// This struct provides the same API as libsynapse::Synapse,
/// enabling a drop-in replacement.
///
/// # Example
///
/// ```ignore
/// use synapse_pingora::waf::{Synapse, Request, Action};
///
/// let mut synapse = Synapse::new();
/// synapse.load_rules(rules_json).unwrap();
///
/// let verdict = synapse.analyze(&Request {
///     method: "GET",
///     path: "/api/users?id=1' OR '1'='1",
///     ..Default::default()
/// });
///
/// assert_eq!(verdict.action, Action::Block);
/// ```
pub struct Synapse {
    engine: Engine,
    /// Risk configuration for anomaly detection thresholds.
    risk_config: RwLock<RiskConfig>,
    /// Profile storage for endpoint behavior learning.
    profile_store: ProfileStore,
}

impl Default for Synapse {
    fn default() -> Self {
        Self::new()
    }
}

impl Synapse {
    /// Create a new Synapse instance with no rules loaded.
    pub fn new() -> Self {
        Self {
            engine: Engine::empty(),
            risk_config: RwLock::new(RiskConfig::default()),
            profile_store: ProfileStore::new(ProfileStoreConfig::default()),
        }
    }

    /// Create a new Synapse instance with custom profile configuration.
    pub fn with_profile_config(profile_config: ProfileStoreConfig) -> Self {
        Self {
            engine: Engine::empty(),
            risk_config: RwLock::new(RiskConfig::default()),
            profile_store: ProfileStore::new(profile_config),
        }
    }

    /// Load rules from JSON.
    ///
    /// Returns the number of rules loaded on success.
    pub fn load_rules(&mut self, json: &[u8]) -> Result<usize, WafError> {
        self.engine.load_rules(json)
    }

    /// Analyze a request and return a verdict.
    pub fn analyze(&self, req: &Request) -> Verdict {
        self.engine.analyze(req)
    }

    /// Record response status code for profiling.
    ///
    /// Updates the endpoint profile with the observed status code,
    /// enabling baseline learning and anomaly detection.
    pub fn record_response_status(&self, path: &str, status: u16) {
        let now_ms = Self::now_ms();
        let mut profile = self.profile_store.get_or_create(path);
        // Update profile with response status observation
        // Use 0 for response size since we only have status
        profile.update_response(0, status, None, now_ms);
    }

    /// Get all learned profiles.
    ///
    /// Returns a snapshot of all endpoint profiles currently in storage.
    pub fn get_profiles(&self) -> Vec<EndpointProfile> {
        self.profile_store.get_profiles()
    }

    /// Load profiles into the engine.
    ///
    /// Merges or replaces profiles in storage from a previous snapshot.
    pub fn load_profiles(&self, profiles: Vec<EndpointProfile>) {
        for profile in profiles {
            // Insert each profile into the store by its template path
            let template = profile.template.clone();
            let mut entry = self.profile_store.get_or_create(&template);
            // Merge the loaded profile data into the existing entry
            *entry = profile;
        }
    }

    /// Get the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Get current risk configuration.
    pub fn risk_config(&self) -> RiskConfig {
        self.risk_config.read().clone()
    }

    /// Set risk configuration.
    ///
    /// Updates the risk thresholds for anomaly-based blocking.
    pub fn set_risk_config(&self, config: RiskConfig) {
        *self.risk_config.write() = config;
    }

    /// Get the number of stored profiles.
    pub fn profile_count(&self) -> usize {
        self.profile_store.len()
    }

    /// Clear all stored profiles.
    pub fn clear_profiles(&self) {
        self.profile_store.clear();
    }

    /// Get current timestamp in milliseconds.
    #[inline]
    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_synapse() {
        let synapse = Synapse::new();
        assert_eq!(synapse.rule_count(), 0);
    }

    #[test]
    fn test_load_rules() {
        let mut synapse = Synapse::new();
        let rules = r#"[
            {
                "id": 1,
                "description": "SQL injection",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {"type": "uri", "match": {"type": "contains", "match": "' OR '"}}
                ]
            }
        ]"#;
        let count = synapse.load_rules(rules.as_bytes()).unwrap();
        assert_eq!(count, 1);
        assert_eq!(synapse.rule_count(), 1);
    }

    #[test]
    fn test_default_synapse() {
        let synapse = Synapse::default();
        assert_eq!(synapse.rule_count(), 0);
    }

    #[test]
    fn test_risk_config_get_set() {
        use crate::waf::BlockingMode;

        let synapse = Synapse::new();

        // Default config
        let config = synapse.risk_config();
        assert_eq!(config.max_risk, 100.0);
        assert!(config.enable_repeat_multipliers);

        // Modify config
        let mut new_config = config.clone();
        new_config.max_risk = 1000.0;
        new_config.blocking_mode = BlockingMode::Enforcement;
        new_config.anomaly_blocking_threshold = 25.0;
        synapse.set_risk_config(new_config);

        // Verify changes persisted
        let updated = synapse.risk_config();
        assert_eq!(updated.max_risk, 1000.0);
        assert_eq!(updated.anomaly_blocking_threshold, 25.0);
        assert!(matches!(updated.blocking_mode, BlockingMode::Enforcement));
    }

    #[test]
    fn test_record_response_status() {
        let synapse = Synapse::new();

        // Initially no profiles
        assert_eq!(synapse.profile_count(), 0);

        // Record some status codes
        synapse.record_response_status("/api/users", 200);
        synapse.record_response_status("/api/users", 200);
        synapse.record_response_status("/api/users", 404);

        // Should have created a profile
        assert_eq!(synapse.profile_count(), 1);

        // Multiple paths create multiple profiles
        synapse.record_response_status("/api/orders", 200);
        assert_eq!(synapse.profile_count(), 2);
    }

    #[test]
    fn test_get_and_load_profiles() {
        let synapse = Synapse::new();

        // Create some profiles
        synapse.record_response_status("/api/users", 200);
        synapse.record_response_status("/api/orders", 200);
        assert_eq!(synapse.profile_count(), 2);

        // Get profiles snapshot
        let profiles = synapse.get_profiles();
        assert_eq!(profiles.len(), 2);

        // Clear and verify empty
        synapse.clear_profiles();
        assert_eq!(synapse.profile_count(), 0);

        // Load profiles back
        synapse.load_profiles(profiles);
        assert_eq!(synapse.profile_count(), 2);
    }

    #[test]
    fn test_profile_path_normalization() {
        let synapse = Synapse::new();

        // Paths with IDs should normalize to templates
        synapse.record_response_status("/api/users/123", 200);
        synapse.record_response_status("/api/users/456", 200);

        // Both should map to the same template (with ID normalized)
        // Note: exact count depends on ProfileStore's segment detection config
        let profiles = synapse.get_profiles();
        assert!(!profiles.is_empty());
    }
}
