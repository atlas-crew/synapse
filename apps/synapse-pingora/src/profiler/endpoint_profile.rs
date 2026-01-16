//! Per-endpoint statistical profile.
//!
//! Tracks baseline behavior for individual API endpoints including:
//! - Payload size distribution
//! - Expected parameters and their frequencies
//! - Content types observed
//! - Response status code distribution
//! - Request rate patterns
//!
//! ## Memory Budget
//! ~2KB per endpoint profile

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::profiler::distribution::Distribution;
use crate::profiler::rate_tracker::RateTracker;

// ============================================================================
// Constants
// ============================================================================

/// Maximum number of content types to track per endpoint.
/// Prevents memory exhaustion from attackers sending many unique Content-Type headers.
const MAX_CONTENT_TYPES: usize = 20;

/// Maximum number of parameters to track per endpoint.
const MAX_PARAMS: usize = 50;

// ============================================================================
// EndpointProfile - Per-endpoint baseline
// ============================================================================

/// Statistical profile for a single API endpoint.
///
/// Memory budget: ~2KB per endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointProfile {
    /// Path template (e.g., "/api/users/{id}")
    pub template: String,

    /// Payload size distribution (bytes)
    pub payload_size: Distribution,

    /// Expected query parameters (name -> frequency count)
    /// Capped at MAX_PARAMS parameters
    pub expected_params: HashMap<String, u32>,

    /// Expected content types (type -> frequency count)
    pub content_types: HashMap<String, u32>,

    /// HTTP status codes (code -> count)
    pub status_codes: HashMap<u16, u32>,

    /// Request rate tracker (60-second window)
    pub request_rate: RateTracker,

    /// Aggregate endpoint risk score (0.0-100.0)
    /// Computed from attack density and vulnerability indicators
    pub endpoint_risk: f32,

    /// Total sample count
    pub sample_count: u32,

    /// First seen timestamp (ms)
    pub first_seen_ms: u64,

    /// Last updated timestamp (ms)
    pub last_updated_ms: u64,
}

impl EndpointProfile {
    /// Create a new profile for an endpoint template.
    pub fn new(template: String, now_ms: u64) -> Self {
        Self {
            template,
            payload_size: Distribution::new(),
            expected_params: HashMap::with_capacity(16),
            content_types: HashMap::with_capacity(4),
            status_codes: HashMap::with_capacity(8),
            request_rate: RateTracker::new(),
            endpoint_risk: 0.0,
            sample_count: 0,
            first_seen_ms: now_ms,
            last_updated_ms: now_ms,
        }
    }

    /// Update profile with request data.
    ///
    /// Uses `&[&str]` to avoid allocation overhead on the hot path.
    /// Only clones param keys when inserting new entries into the HashMap.
    pub fn update(
        &mut self,
        payload_size: usize,
        params: &[&str],
        content_type: Option<&str>,
        now_ms: u64,
    ) {
        // Update payload size distribution
        self.payload_size.update(payload_size as f64);

        // Update request rate
        self.request_rate.record(now_ms);

        // Update parameter frequencies (only clone on insert)
        for &param in params {
            if let Some(count) = self.expected_params.get_mut(param) {
                *count += 1;
            } else if self.expected_params.len() < MAX_PARAMS {
                self.expected_params.insert(param.to_string(), 1);
            }
        }

        // Cap params at MAX_PARAMS (memory protection)
        if self.expected_params.len() > MAX_PARAMS {
            Self::evict_least_frequent(&mut self.expected_params, MAX_PARAMS);
        }

        // Update content type (bounded to prevent memory exhaustion)
        if let Some(ct) = content_type {
            // Only track if we haven't hit the limit, or if this type is already tracked
            if self.content_types.len() < MAX_CONTENT_TYPES || self.content_types.contains_key(ct) {
                *self.content_types.entry(ct.to_string()).or_insert(0) += 1;
            }
            // If at limit and new type, just ignore (don't pollute with attacker-generated types)
        }

        self.sample_count += 1;
        self.last_updated_ms = now_ms;
    }

    /// Record response status code.
    pub fn record_status(&mut self, status_code: u16) {
        *self.status_codes.entry(status_code).or_insert(0) += 1;
    }

    /// Get the dominant content type (most frequent).
    pub fn dominant_content_type(&self) -> Option<&str> {
        self.content_types
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(ct, _)| ct.as_str())
    }

    /// Get parameter frequency (0.0-1.0).
    pub fn param_frequency(&self, param: &str) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }
        self.expected_params
            .get(param)
            .map(|&count| count as f64 / self.sample_count as f64)
            .unwrap_or(0.0)
    }

    /// Check if a parameter is "expected" (seen in > threshold of requests).
    pub fn is_expected_param(&self, param: &str, threshold: f64) -> bool {
        self.param_frequency(param) >= threshold
    }

    /// Get status code frequency (0.0-1.0).
    pub fn status_frequency(&self, status_code: u16) -> f64 {
        let total: u32 = self.status_codes.values().sum();
        if total == 0 {
            return 0.0;
        }
        self.status_codes
            .get(&status_code)
            .map(|&count| count as f64 / total as f64)
            .unwrap_or(0.0)
    }

    /// Get the error rate (4xx + 5xx responses).
    pub fn error_rate(&self) -> f64 {
        let total: u32 = self.status_codes.values().sum();
        if total == 0 {
            return 0.0;
        }
        let errors: u32 = self
            .status_codes
            .iter()
            .filter(|(&code, _)| code >= 400)
            .map(|(_, &count)| count)
            .sum();
        errors as f64 / total as f64
    }

    /// Calculate baseline request rate (requests per minute over lifetime).
    pub fn baseline_rate(&self, now_ms: u64) -> f64 {
        let lifetime_ms = now_ms.saturating_sub(self.first_seen_ms).max(1);
        let lifetime_minutes = lifetime_ms as f64 / 60_000.0;
        self.sample_count as f64 / lifetime_minutes.max(1.0)
    }

    /// Evict least frequent entries from a HashMap.
    fn evict_least_frequent(map: &mut HashMap<String, u32>, target_size: usize) {
        if map.len() <= target_size {
            return;
        }

        // Find minimum frequency to keep
        let mut frequencies: Vec<u32> = map.values().copied().collect();
        frequencies.sort_unstable();
        let to_remove = map.len() - target_size;
        let min_keep = frequencies.get(to_remove).copied().unwrap_or(0);

        // Remove entries below threshold
        map.retain(|_, &mut count| count >= min_keep);
    }

    /// Check if profile has enough samples for anomaly detection.
    pub fn is_mature(&self, min_samples: u32) -> bool {
        self.sample_count >= min_samples
    }

    /// Get the age of this profile in milliseconds.
    pub fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.first_seen_ms)
    }

    /// Get time since last update in milliseconds.
    pub fn idle_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.last_updated_ms)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_profile_new() {
        let profile = EndpointProfile::new("/api/users".to_string(), 1000);
        assert_eq!(profile.template, "/api/users");
        assert_eq!(profile.sample_count, 0);
        assert_eq!(profile.first_seen_ms, 1000);
        assert_eq!(profile.last_updated_ms, 1000);
    }

    #[test]
    fn test_endpoint_profile_update() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &["name", "email"], Some("application/json"), 2000);

        assert_eq!(profile.sample_count, 1);
        assert_eq!(profile.last_updated_ms, 2000);
        assert!(profile.expected_params.contains_key("name"));
        assert!(profile.expected_params.contains_key("email"));
        assert!(profile.content_types.contains_key("application/json"));
    }

    #[test]
    fn test_endpoint_profile_param_frequency() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        // Update with "name" in all requests, "email" in half
        for i in 0..10 {
            let params = if i % 2 == 0 {
                vec!["name", "email"]
            } else {
                vec!["name"]
            };
            profile.update(100, &params, None, 1000 + i * 100);
        }

        assert!((profile.param_frequency("name") - 1.0).abs() < 0.01);
        assert!((profile.param_frequency("email") - 0.5).abs() < 0.01);
        assert_eq!(profile.param_frequency("unknown"), 0.0);
    }

    #[test]
    fn test_endpoint_profile_is_expected_param() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        // "name" in 9/10 requests, "optional" in 2/10
        for i in 0..10 {
            let params = if i == 0 {
                vec!["optional"]
            } else if i < 3 {
                vec!["name", "optional"]
            } else {
                vec!["name"]
            };
            profile.update(100, &params, None, 1000 + i * 100);
        }

        assert!(profile.is_expected_param("name", 0.8)); // 90% > 80%
        assert!(!profile.is_expected_param("optional", 0.8)); // 20% < 80%
    }

    #[test]
    fn test_endpoint_profile_content_type_bounds() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add MAX_CONTENT_TYPES unique content types
        for i in 0..MAX_CONTENT_TYPES {
            profile.update(100, &[], Some(&format!("application/type-{}", i)), 1000 + i as u64);
        }
        assert_eq!(profile.content_types.len(), MAX_CONTENT_TYPES);

        // Try to add more unique content types - should be ignored
        for i in 0..10 {
            profile.update(100, &[], Some(&format!("application/extra-{}", i)), 2000 + i as u64);
        }
        // Should still be at MAX_CONTENT_TYPES, not growing
        assert_eq!(profile.content_types.len(), MAX_CONTENT_TYPES);

        // But existing content types should still be updated
        let initial_count = *profile.content_types.get("application/type-0").unwrap();
        profile.update(100, &[], Some("application/type-0"), 3000);
        let updated_count = *profile.content_types.get("application/type-0").unwrap();
        assert_eq!(updated_count, initial_count + 1);
    }

    #[test]
    fn test_endpoint_profile_dominant_content_type() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // JSON 5 times, XML 2 times
        for _ in 0..5 {
            profile.update(100, &[], Some("application/json"), 1000);
        }
        for _ in 0..2 {
            profile.update(100, &[], Some("application/xml"), 1000);
        }

        assert_eq!(profile.dominant_content_type(), Some("application/json"));
    }

    #[test]
    fn test_endpoint_profile_status_codes() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // 80% success, 20% errors
        for _ in 0..8 {
            profile.record_status(200);
        }
        for _ in 0..2 {
            profile.record_status(500);
        }

        assert!((profile.status_frequency(200) - 0.8).abs() < 0.01);
        assert!((profile.status_frequency(500) - 0.2).abs() < 0.01);
        assert!((profile.error_rate() - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_endpoint_profile_baseline_rate() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 0);

        // 60 requests over 1 minute = 60 req/min
        for i in 0..60 {
            profile.update(100, &[], None, i * 1000);
        }

        let rate = profile.baseline_rate(60_000);
        assert!((rate - 60.0).abs() < 1.0);
    }

    #[test]
    fn test_endpoint_profile_is_mature() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        assert!(!profile.is_mature(10));

        for i in 0..10 {
            profile.update(100, &[], None, 1000 + i * 100);
        }

        assert!(profile.is_mature(10));
        assert!(!profile.is_mature(20));
    }

    #[test]
    fn test_endpoint_profile_age_and_idle() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);

        assert_eq!(profile.age_ms(2000), 1000);
        assert_eq!(profile.idle_ms(2000), 1000);
    }

    #[test]
    fn test_evict_least_frequent() {
        let mut map: HashMap<String, u32> = HashMap::new();
        map.insert("a".to_string(), 10);
        map.insert("b".to_string(), 5);
        map.insert("c".to_string(), 1);
        map.insert("d".to_string(), 8);

        EndpointProfile::evict_least_frequent(&mut map, 2);

        // Should keep "a" (10) and "d" (8)
        assert!(map.len() <= 2);
        assert!(map.contains_key("a"));
    }

    #[test]
    fn test_endpoint_profile_param_cap() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add more than MAX_PARAMS parameters
        for i in 0..(MAX_PARAMS + 10) {
            profile.update(100, &[&format!("param_{}", i)], None, 1000 + i as u64);
        }

        // Should not exceed MAX_PARAMS
        assert!(profile.expected_params.len() <= MAX_PARAMS);
    }
}
