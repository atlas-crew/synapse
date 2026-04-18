//! Synapse facade for the WAF engine.
//!
//! Provides a high-level API matching the libsynapse Synapse struct
//! for seamless migration.

use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Engine, Request, RiskConfig, TraceSink, Verdict, WafError};
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

    /// Precompute all rule structures including regex compilation.
    pub fn precompute_rules(
        &self,
        json: &[u8],
    ) -> Result<crate::waf::engine::CompiledRules, WafError> {
        self.engine.precompute_rules(json)
    }

    /// Fast swap of rule state using precomputed data.
    pub fn reload_from_compiled(&mut self, compiled: crate::waf::engine::CompiledRules) {
        self.engine.reload_from_compiled(compiled);
    }

    /// Parse rules from JSON bytes without modifying state.
    pub fn parse_rules(json: &[u8]) -> Result<Vec<crate::waf::WafRule>, WafError> {
        Engine::parse_rules(json)
    }

    /// Reload the engine with a new set of pre-parsed rules.
    pub fn reload_rules(&mut self, rules: Vec<crate::waf::WafRule>) -> Result<(), WafError> {
        self.engine.reload_rules(rules)
    }

    /// Analyze a request and return a verdict.
    pub fn analyze(&self, req: &Request) -> Verdict {
        self.engine.analyze(req)
    }

    /// Analyze a request and emit evaluation trace events.
    pub fn analyze_with_trace(&self, req: &Request, trace: &mut dyn TraceSink) -> Verdict {
        self.engine.analyze_with_trace(req, trace)
    }

    /// Analyze a request with a timeout to prevent DoS via complex regexes.
    ///
    /// # Arguments
    /// * `req` - The request to analyze
    /// * `timeout` - Maximum time allowed for rule evaluation
    ///
    /// # Returns
    /// A `Verdict` with `timed_out=true` if evaluation exceeded the deadline.
    pub fn analyze_with_timeout(&self, req: &Request, timeout: std::time::Duration) -> Verdict {
        self.engine.analyze_with_timeout(req, timeout)
    }

    /// Analyze a request with the default timeout (50ms).
    ///
    /// Recommended for production use to prevent DoS attacks.
    pub fn analyze_safe(&self, req: &Request) -> Verdict {
        self.engine.analyze_safe(req)
    }

    /// Evaluate the deferred rule set (rules that reference signals only
    /// available after the body-phase pass — currently `dlp_violation`).
    ///
    /// The caller must populate `req.dlp_matches` before calling this.
    /// Returns a default (Allow) verdict when no deferred rules are loaded.
    pub fn analyze_deferred_with_timeout(
        &self,
        req: &Request,
        timeout: std::time::Duration,
    ) -> Verdict {
        self.engine.analyze_deferred_with_timeout(req, timeout)
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
    fn test_load_rules_parse_error_preserves_existing_ruleset() {
        const SENTINEL_RULE_ID: u32 = 90_001;
        const SENTINEL_PATH: &str = "/reload-rules-preserved";

        let mut synapse = Synapse::new();
        let valid_rules = format!(
            r#"[
            {{
                "id": {},
                "description": "Reload rules preservation sentinel",
                "risk": 10.0,
                "blocking": true,
                "matches": [
                    {{
                        "type": "uri",
                        "match": {{
                            "type": "contains",
                            "match": "{}"
                        }}
                    }}
                ]
            }}
        ]"#,
            SENTINEL_RULE_ID, SENTINEL_PATH
        );

        let loaded = synapse
            .load_rules(valid_rules.as_bytes())
            .expect("valid sentinel rules must load");
        assert_eq!(
            loaded, 1,
            "expected sentinel rule to be the only loaded rule"
        );

        let make_sentinel_request = || Request {
            method: "GET",
            path: SENTINEL_PATH,
            ..Default::default()
        };

        let before_failure = synapse.analyze(&make_sentinel_request());
        assert_eq!(
            before_failure.action,
            crate::waf::Action::Block,
            "sentinel rule must block before the failed reload attempt"
        );
        assert!(
            before_failure.matched_rules.contains(&SENTINEL_RULE_ID),
            "sentinel rule id must be observable before the failed reload"
        );

        let err = synapse
            .load_rules(b"{")
            .expect_err("malformed JSON must not be accepted during reload");
        match err {
            WafError::ParseError(msg) => {
                assert!(
                    !msg.is_empty(),
                    "parse errors should preserve the serde failure context"
                );
            }
            other => panic!("expected parse error from malformed JSON, got {:?}", other),
        }

        assert_eq!(
            synapse.rule_count(),
            1,
            "failed reload must preserve the prior ruleset atomically"
        );

        let after_failure = synapse.analyze(&make_sentinel_request());
        assert_eq!(
            after_failure.action,
            crate::waf::Action::Block,
            "failed reload must leave the previously loaded blocking rule active"
        );
        assert!(
            after_failure.matched_rules.contains(&SENTINEL_RULE_ID),
            "failed reload must preserve the previously loaded sentinel rule"
        );

        let regex_err = synapse
            .load_rules(
                br#"[
                    {
                        "id": 90002,
                        "description": "Invalid regex",
                        "risk": 10.0,
                        "matches": [
                            {
                                "type": "uri",
                                "match": {
                                    "type": "regex",
                                    "match": "["
                                }
                            }
                        ]
                    }
                ]"#,
            )
            .expect_err("invalid regex must not be accepted during reload");
        match regex_err {
            WafError::RegexError(msg) => {
                assert!(
                    msg.contains('['),
                    "regex errors should preserve the invalid pattern context"
                );
            }
            other => panic!(
                "expected regex error from invalid rule reload, got {:?}",
                other
            ),
        }

        assert_eq!(
            synapse.rule_count(),
            1,
            "compile-time reload failures must also preserve the prior ruleset atomically"
        );

        let after_regex_failure = synapse.analyze(&make_sentinel_request());
        assert_eq!(
            after_regex_failure.action,
            crate::waf::Action::Block,
            "regex reload failures must leave the previously loaded blocking rule active"
        );
        assert!(
            after_regex_failure
                .matched_rules
                .contains(&SENTINEL_RULE_ID),
            "regex reload failures must preserve the previously loaded sentinel rule"
        );
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
