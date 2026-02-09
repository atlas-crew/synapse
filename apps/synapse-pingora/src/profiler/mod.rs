//! API Endpoint Profiler Module
//!
//! This module provides behavioral profiling for API endpoints, including:
//! - Statistical baseline learning (payload sizes, parameters, content types)
//! - Anomaly detection based on deviations from baseline
//! - Schema learning and validation (JSON body schema inference)
//! - Rate tracking and burst detection
//! - Pattern detection (UUID, email, JWT, etc.)
//!
//! ## Architecture
//!
//! ### Core Components
//! - `EndpointProfile` - Per-endpoint statistical baseline
//! - `Distribution` - Statistical distribution tracker (Welford's algorithm)
//! - `PercentilesTracker` - P-square streaming percentiles
//! - `RateTracker` - Time-windowed request rate tracking
//! - `AnomalySignal` - Individual anomaly signal with severity
//! - `AnomalyResult` - Aggregated detection results for a request
//!
//! ### Parameter Schema (local)
//! - `ParameterSchema` - Expected parameters, content types, and payload sizes
//!
//! ### JSON Schema Learning (Ported from libsynapse)
//! - `SchemaLearner` - Thread-safe JSON schema learning engine
//! - `FieldSchema` - Per-field type and constraint tracking
//! - `JsonEndpointSchema` - Full schema for request/response JSON bodies
//! - `ValidationResult` - Schema violation detection
//!
//! **Note**: Schema learning only processes JSON object bodies. Array-root bodies
//! (e.g., `[{...}, {...}]`) are silently skipped. APIs using arrays as the root
//! element will not benefit from schema learning or validation.
//!
//! ### Storage
//! - `ProfileStore` - Thread-safe storage with LRU eviction
//! - `SegmentCardinality` - Dynamic path segment detection
//!
//! ## Memory Budget
//!
//! - Distribution: ~130 bytes
//! - RateTracker: ~520 bytes
//! - EndpointProfile: ~2KB
//! - SchemaLearner: ~5KB per endpoint
//! - ProfileStore: 10,000 profiles * 2KB = ~20MB default

// Core modules
mod distribution;
mod endpoint_profile;
mod rate_tracker;
mod signals;

// Header profiling modules (W4.1 HeaderProfiler)
pub mod entropy;
pub mod header_profiler;
pub mod header_types;

// Schema learning modules (ported from libsynapse)
pub mod patterns;
pub mod profile_store;
pub mod schema_learner;
pub mod schema_types;

// Template path interning for allocation reduction
pub mod template_intern;

#[cfg(test)]
mod value_analysis_tests;

// Core re-exports
pub use distribution::{Distribution, PercentilesTracker};
pub use endpoint_profile::{is_likely_pii, redact_value, EndpointProfile, ParamStats};
pub use rate_tracker::RateTracker;
pub use signals::{AnomalyResult, AnomalySignal, AnomalySignalType};

// Header profiler re-exports
pub use entropy::{entropy_z_score, is_entropy_anomaly, normalized_entropy, shannon_entropy};
pub use header_profiler::{HeaderProfiler, HeaderProfilerStats};
pub use header_types::{HeaderAnomaly, HeaderAnomalyResult, HeaderBaseline, ValueStats};

// Schema learning re-exports
pub use patterns::{detect_pattern, matches_pattern};
pub use profile_store::{
    ProfileStore, ProfileStoreConfig, ProfileStoreMetrics, SegmentCardinality,
};
pub use schema_learner::{SchemaLearner, SchemaLearnerConfig, SchemaLearnerStats};
pub use schema_types::{
    EndpointSchema as JsonEndpointSchema, FieldSchema, FieldType, PatternType, SchemaViolation,
    ValidationResult, ViolationSeverity, ViolationType,
};

// Template interning re-exports
pub use template_intern::{
    cache_stats as template_cache_stats, intern_template, normalize_and_intern,
};

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::ProfilerConfig;

/// Profiler manager for endpoint behavior learning and anomaly detection.
#[derive(Debug)]
pub struct Profiler {
    /// Configuration
    config: ProfilerConfig,
    /// Endpoint profiles (template -> profile)
    profiles: Arc<RwLock<HashMap<String, EndpointProfile>>>,
    /// Learned schemas (template -> schema definition)
    schemas: Arc<RwLock<HashMap<String, ParameterSchema>>>,
}

/// Learned parameter schema for an endpoint.
///
/// This tracks expected parameters, content types, and payload sizes for an endpoint.
/// For JSON body schema learning (field types, constraints), see `JsonEndpointSchema`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParameterSchema {
    /// Path template
    pub template: String,
    /// Expected content types
    pub expected_content_types: Vec<String>,
    /// Required parameters
    pub required_params: Vec<String>,
    /// Optional parameters
    pub optional_params: Vec<String>,
    /// Parameter statistics (value analysis)
    pub param_stats: HashMap<String, ParamStats>,
    /// Minimum payload size
    pub min_payload_size: usize,
    /// Maximum payload size
    pub max_payload_size: usize,
    /// Sample count used to build schema
    pub sample_count: u32,
    /// Last updated timestamp (ms)
    pub last_updated_ms: u64,
}

impl ParameterSchema {
    /// Create a new schema from an endpoint profile.
    pub fn from_profile(profile: &EndpointProfile, param_threshold: f64) -> Self {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Extract expected content types (seen in >10% of requests)
        let expected_content_types: Vec<String> = profile
            .content_types
            .iter()
            .filter(|(_, &count)| count as f64 / profile.sample_count as f64 > 0.1)
            .map(|(ct, _)| ct.clone())
            .collect();

        // Separate required (>80% frequency) vs optional params
        let mut required_params = Vec::new();
        let mut optional_params = Vec::new();
        let mut param_stats = HashMap::new();

        for (param, stats) in &profile.expected_params {
            // Clone stats for schema
            param_stats.insert(param.clone(), stats.clone());

            if profile.param_frequency(param) >= param_threshold {
                required_params.push(param.clone());
            } else {
                optional_params.push(param.clone());
            }
        }

        Self {
            template: profile.template.clone(),
            expected_content_types,
            required_params,
            optional_params,
            param_stats,
            min_payload_size: profile.payload_size.min() as usize,
            max_payload_size: profile.payload_size.max() as usize,
            sample_count: profile.sample_count,
            last_updated_ms: now_ms,
        }
    }
}

impl Profiler {
    /// Create a new profiler with the given configuration.
    pub fn new(config: ProfilerConfig) -> Self {
        Self {
            config,
            profiles: Arc::new(RwLock::new(HashMap::new())),
            schemas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if profiling is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get or create an endpoint profile.
    pub fn get_or_create_profile(&self, template: &str) -> Option<EndpointProfile> {
        if !self.config.enabled {
            return None;
        }

        let mut profiles = self.profiles.write();

        // Check capacity limit
        if !profiles.contains_key(template) && profiles.len() >= self.config.max_profiles {
            return None; // At capacity, don't create new profile
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Some(
            profiles
                .entry(template.to_string())
                .or_insert_with(|| EndpointProfile::new(template.to_string(), now_ms))
                .clone(),
        )
    }

    /// Update an endpoint profile with request data.
    ///
    /// Respects the `freeze_after_samples` setting to prevent model poisoning.
    /// If a profile has reached the freeze threshold, updates are silently ignored.
    pub fn update_profile(
        &self,
        template: &str,
        payload_size: usize,
        params: &[(&str, &str)],
        content_type: Option<&str>,
    ) {
        if !self.config.enabled {
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut profiles = self.profiles.write();

        if let Some(profile) = profiles.get_mut(template) {
            // Check if profile is frozen (anti-poisoning measure)
            if self.config.freeze_after_samples > 0
                && profile.sample_count >= self.config.freeze_after_samples
            {
                return; // Profile frozen, reject updates
            }
            profile.update(payload_size, params, content_type, now_ms);
        } else if profiles.len() < self.config.max_profiles {
            let mut profile = EndpointProfile::new(template.to_string(), now_ms);
            profile.update(payload_size, params, content_type, now_ms);
            profiles.insert(template.to_string(), profile);
        }
    }

    /// Update an endpoint profile with response data.
    ///
    /// Respects the `freeze_after_samples` setting to prevent model poisoning.
    pub fn update_response_profile(
        &self,
        template: &str,
        response_size: usize,
        status_code: u16,
        content_type: Option<&str>,
    ) {
        if !self.config.enabled {
            return;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut profiles = self.profiles.write();

        if let Some(profile) = profiles.get_mut(template) {
            // Check if profile is frozen (anti-poisoning measure)
            if self.config.freeze_after_samples > 0
                && profile.sample_count >= self.config.freeze_after_samples
            {
                return; // Profile frozen, reject updates
            }
            profile.update_response(response_size, status_code, content_type, now_ms);
        }
    }

    /// Get all profiles.
    pub fn get_profiles(&self) -> Vec<EndpointProfile> {
        let profiles = self.profiles.read();
        profiles.values().cloned().collect()
    }

    /// Get a specific profile by template.
    pub fn get_profile(&self, template: &str) -> Option<EndpointProfile> {
        let profiles = self.profiles.read();
        profiles.get(template).cloned()
    }

    /// Get the number of profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.read().len()
    }

    /// Learn schema from a profile if it has enough samples.
    pub fn learn_schema(&self, template: &str) {
        if !self.config.enabled {
            return;
        }

        let profiles = self.profiles.read();
        if let Some(profile) = profiles.get(template) {
            if profile.is_mature(self.config.min_samples_for_validation) {
                drop(profiles); // Release read lock before taking write lock

                let mut schemas = self.schemas.write();
                if schemas.len() < self.config.max_schemas {
                    let profiles = self.profiles.read();
                    if let Some(profile) = profiles.get(template) {
                        let schema = ParameterSchema::from_profile(profile, 0.8);
                        schemas.insert(template.to_string(), schema);
                    }
                }
            }
        }
    }

    /// Get all learned schemas.
    pub fn get_schemas(&self) -> Vec<ParameterSchema> {
        let schemas = self.schemas.read();
        schemas.values().cloned().collect()
    }

    /// Get a specific schema by template.
    pub fn get_schema(&self, template: &str) -> Option<ParameterSchema> {
        let schemas = self.schemas.read();
        schemas.get(template).cloned()
    }

    /// Get the number of schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.read().len()
    }

    /// Reset all profiles (for testing).
    pub fn reset_profiles(&self) {
        self.profiles.write().clear();
    }

    /// Reset all schemas (for testing).
    pub fn reset_schemas(&self) {
        self.schemas.write().clear();
    }

    /// Analyze a request against the learned profile.
    ///
    /// Uses configurable thresholds for anomaly detection and optional PII redaction.
    pub fn analyze_request(
        &self,
        template: &str,
        payload_size: usize,
        params: &[(&str, &str)],
        content_type: Option<&str>,
    ) -> AnomalyResult {
        if !self.config.enabled {
            return AnomalyResult::none();
        }

        let profiles = self.profiles.read();
        let profile = match profiles.get(template) {
            Some(p) if p.is_mature(self.config.min_samples_for_validation) => p,
            _ => return AnomalyResult::none(), // No mature profile yet
        };

        let mut result = AnomalyResult::new();

        // Check payload size anomaly using configurable threshold
        let z_score = profile.payload_size.z_score(payload_size as f64);
        if z_score > self.config.payload_z_threshold {
            result.add(
                AnomalySignalType::PayloadSizeHigh,
                (z_score.min(10.0) as u8).max(1),
                format!(
                    "Payload size {} is {:.1} std devs above mean",
                    payload_size, z_score
                ),
            );
        } else if z_score < -self.config.payload_z_threshold {
            result.add(
                AnomalySignalType::PayloadSizeLow,
                2,
                format!(
                    "Payload size {} is {:.1} std devs below mean",
                    payload_size,
                    z_score.abs()
                ),
            );
        }

        // Check for unexpected parameters and value anomalies
        for &(param, value) in params {
            if profile.param_frequency(param) < 0.01 {
                // Redact value if PII protection is enabled
                let display_value = if self.config.redact_pii && is_likely_pii(value) {
                    redact_value(value)
                } else {
                    value.to_string()
                };
                result.add(
                    AnomalySignalType::UnexpectedParam,
                    3,
                    format!("Unexpected parameter: {} (value: {})", param, display_value),
                );
            } else if let Some(stats) = profile.expected_params.get(param) {
                // Value length analysis using configurable threshold
                let len_z = stats.length_dist.z_score(value.len() as f64);
                if len_z > self.config.param_z_threshold {
                    // Redact value if PII protection is enabled
                    let display_value = if self.config.redact_pii && is_likely_pii(value) {
                        redact_value(value)
                    } else if self.config.redact_pii && value.len() > 20 {
                        // Redact long values that might contain sensitive data
                        redact_value(value)
                    } else {
                        value.to_string()
                    };
                    result.add(
                        AnomalySignalType::ParamValueAnomaly,
                        (len_z.min(10.0) as u8).max(1),
                        format!(
                            "Parameter {} length {} is anomalous (z={:.1}, value: {})",
                            param,
                            value.len(),
                            len_z,
                            display_value
                        ),
                    );
                }

                // Type check (if numeric is dominant)
                // FIX: Prevent division by zero when stats.count is 0
                if stats.count > 0 {
                    let numeric_ratio =
                        *stats.type_counts.get("numeric").unwrap_or(&0) as f64 / stats.count as f64;
                    if numeric_ratio > self.config.type_ratio_threshold {
                        if value.parse::<f64>().is_err() {
                            result.add(
                                AnomalySignalType::ParamValueAnomaly,
                                5,
                                format!("Parameter {} expected numeric, got string", param),
                            );
                        }
                    }
                }
            }
        }

        // Check content type mismatch
        if let Some(ct) = content_type {
            if let Some(dominant) = profile.dominant_content_type() {
                if ct != dominant && !profile.content_types.contains_key(ct) {
                    result.add(
                        AnomalySignalType::ContentTypeMismatch,
                        5,
                        format!(
                            "Content-Type {} not seen before (expected {})",
                            ct, dominant
                        ),
                    );
                }
            }
        }

        result.normalize();
        result
    }

    /// Analyze a response against the learned profile.
    ///
    /// Uses configurable thresholds for response size anomaly detection.
    pub fn analyze_response(
        &self,
        template: &str,
        response_size: usize,
        status_code: u16,
        content_type: Option<&str>,
    ) -> AnomalyResult {
        if !self.config.enabled {
            return AnomalyResult::none();
        }

        let profiles = self.profiles.read();
        let profile = match profiles.get(template) {
            Some(p) if p.is_mature(self.config.min_samples_for_validation) => p,
            _ => return AnomalyResult::none(),
        };

        let mut result = AnomalyResult::new();

        // Check response size anomaly (potential data leak) using configurable threshold
        let size_z = profile.response_size.z_score(response_size as f64);
        if size_z > self.config.response_z_threshold {
            result.add(
                AnomalySignalType::PayloadSizeHigh, // Re-using PayloadSizeHigh for response too
                (size_z.min(10.0) as u8).max(1),
                format!(
                    "Response size {} is {:.1} std devs above mean (possible leak)",
                    response_size, size_z
                ),
            );
        }

        // Check status code anomaly (error spike)
        if status_code >= 500 {
            let error_rate = profile.error_rate();
            if error_rate < 0.05 {
                // Normally stable endpoint
                result.add(
                    AnomalySignalType::AbnormalErrorRate,
                    5,
                    format!(
                        "Unexpected 5xx error (usual rate: {:.1}%)",
                        error_rate * 100.0
                    ),
                );
            }
        }

        // Check content type mismatch
        if let Some(ct) = content_type {
            if let Some(dominant) = profile.dominant_response_content_type() {
                if ct != dominant && !profile.response_content_types.contains_key(ct) {
                    result.add(
                        AnomalySignalType::ContentTypeMismatch,
                        3,
                        format!(
                            "Response Content-Type {} not seen before (expected {})",
                            ct, dominant
                        ),
                    );
                }
            }
        }

        result.normalize();
        result
    }

    /// Check if a profile is frozen (no longer accepts updates).
    ///
    /// Frozen baselines help prevent model poisoning attacks where attackers
    /// gradually shift the baseline to make malicious patterns appear normal.
    pub fn is_profile_frozen(&self, template: &str) -> bool {
        if self.config.freeze_after_samples == 0 {
            return false; // Freezing disabled
        }
        let profiles = self.profiles.read();
        profiles
            .get(template)
            .map(|p| p.sample_count >= self.config.freeze_after_samples)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ProfilerConfig {
        ProfilerConfig {
            enabled: true,
            max_profiles: 100,
            max_schemas: 50,
            min_samples_for_validation: 10,
            ..Default::default()
        }
    }

    #[test]
    fn test_profiler_new() {
        let profiler = Profiler::new(default_config());
        assert!(profiler.is_enabled());
        assert_eq!(profiler.profile_count(), 0);
        assert_eq!(profiler.schema_count(), 0);
    }

    #[test]
    fn test_profiler_update_and_get_profile() {
        let profiler = Profiler::new(default_config());

        profiler.update_profile(
            "/api/users",
            100,
            &[("name", "alice"), ("email", "a@example.com")],
            Some("application/json"),
        );

        assert_eq!(profiler.profile_count(), 1);

        let profile = profiler.get_profile("/api/users").unwrap();
        assert_eq!(profile.sample_count, 1);
    }

    #[test]
    fn test_profiler_disabled() {
        let config = ProfilerConfig {
            enabled: false,
            ..default_config()
        };
        let profiler = Profiler::new(config);

        profiler.update_profile("/api/users", 100, &[], None);

        assert_eq!(profiler.profile_count(), 0);
    }

    #[test]
    fn test_profiler_max_profiles() {
        let config = ProfilerConfig {
            max_profiles: 2,
            ..default_config()
        };
        let profiler = Profiler::new(config);

        profiler.update_profile("/api/a", 100, &[], None);
        profiler.update_profile("/api/b", 100, &[], None);
        profiler.update_profile("/api/c", 100, &[], None);

        // Should not exceed max_profiles
        assert_eq!(profiler.profile_count(), 2);
    }

    #[test]
    fn test_profiler_learn_schema() {
        let config = ProfilerConfig {
            min_samples_for_validation: 5,
            ..default_config()
        };
        let profiler = Profiler::new(config);

        // Add samples
        for i in 0..10 {
            profiler.update_profile(
                "/api/users",
                100 + i,
                &[("name", "alice")],
                Some("application/json"),
            );
        }

        profiler.learn_schema("/api/users");

        assert_eq!(profiler.schema_count(), 1);
        let schema = profiler.get_schema("/api/users").unwrap();
        assert_eq!(schema.template, "/api/users");
    }

    #[test]
    fn test_profiler_reset() {
        let profiler = Profiler::new(default_config());

        profiler.update_profile("/api/a", 100, &[], None);
        profiler.update_profile("/api/b", 100, &[], None);

        assert_eq!(profiler.profile_count(), 2);

        profiler.reset_profiles();

        assert_eq!(profiler.profile_count(), 0);
    }
}
