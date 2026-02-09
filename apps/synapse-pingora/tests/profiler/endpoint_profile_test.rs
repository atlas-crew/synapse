//! Tests for EndpointProfile.
//!
//! Coverage targets:
//! - new, update, record_status
//! - dominant_content_type, param_frequency, is_expected_param
//! - status_frequency, error_rate, baseline_rate
//! - is_mature, age_ms, idle_ms
//!
//! Edge cases:
//! - Empty profile
//! - Content type bounds (MAX_CONTENT_TYPES)
//! - Parameter bounds (MAX_PARAMS)
//! - LRU eviction of least frequent parameters

use synapse_pingora::profiler::EndpointProfile;

// ============================================================================
// Construction and Basic Operations
// ============================================================================

mod construction {
    use super::*;

    #[test]
    fn test_new_profile() {
        let profile = EndpointProfile::new("/api/users".to_string(), 1000);

        assert_eq!(profile.template, "/api/users");
        assert_eq!(profile.sample_count, 0);
        assert_eq!(profile.first_seen_ms, 1000);
        assert_eq!(profile.last_updated_ms, 1000);
        assert_eq!(profile.endpoint_risk, 0.0);
    }

    #[test]
    fn test_new_profile_empty_collections() {
        let profile = EndpointProfile::new("/api/test".to_string(), 0);

        assert!(profile.expected_params.is_empty());
        assert!(profile.content_types.is_empty());
        assert!(profile.status_codes.is_empty());
    }

    #[test]
    fn test_new_profile_distribution_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 0);

        assert_eq!(profile.payload_size.count(), 0);
        assert_eq!(profile.request_rate.request_count(), 0);
    }
}

// ============================================================================
// Update Operations
// ============================================================================

mod update {
    use super::*;

    #[test]
    fn test_update_increments_sample_count() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[("name", "John")], Some("application/json"), 2000);

        assert_eq!(profile.sample_count, 1);
    }

    #[test]
    fn test_update_updates_timestamps() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[], None, 2000);

        assert_eq!(profile.first_seen_ms, 1000); // Unchanged
        assert_eq!(profile.last_updated_ms, 2000); // Updated
    }

    #[test]
    fn test_update_tracks_params() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(
            100,
            &[("name", "John"), ("email", "john@test.com")],
            Some("application/json"),
            2000,
        );

        assert!(profile.expected_params.contains_key("name"));
        assert!(profile.expected_params.contains_key("email"));
        assert_eq!(
            profile.expected_params.get("name").map(|s| s.count),
            Some(1)
        );
        assert_eq!(
            profile.expected_params.get("email").map(|s| s.count),
            Some(1)
        );
    }

    #[test]
    fn test_update_increments_param_frequency() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[("name", "John")], None, 1000);
        profile.update(100, &[("name", "Jane")], None, 1001);
        profile.update(100, &[("name", "Bob")], None, 1002);

        assert_eq!(
            profile.expected_params.get("name").map(|s| s.count),
            Some(3)
        );
    }

    #[test]
    fn test_update_tracks_content_type() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[], Some("application/json"), 2000);

        assert!(profile.content_types.contains_key("application/json"));
        assert_eq!(profile.content_types.get("application/json"), Some(&1));
    }

    #[test]
    fn test_update_tracks_multiple_content_types() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        for _ in 0..5 {
            profile.update(100, &[], Some("application/json"), 1000);
        }
        for _ in 0..2 {
            profile.update(100, &[], Some("application/xml"), 1000);
        }

        assert_eq!(profile.content_types.get("application/json"), Some(&5));
        assert_eq!(profile.content_types.get("application/xml"), Some(&2));
    }

    #[test]
    fn test_update_without_content_type() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[], None, 2000);

        assert!(profile.content_types.is_empty());
    }

    #[test]
    fn test_update_payload_size_distribution() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        for i in 1..=10 {
            profile.update(i * 100, &[], None, 1000 + i as u64);
        }

        assert_eq!(profile.payload_size.count(), 10);
        assert!(profile.payload_size.mean() > 0.0);
    }

    #[test]
    fn test_update_request_rate() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        for i in 0..5 {
            profile.update(100, &[], None, 1000 + i * 100);
        }

        assert_eq!(profile.request_rate.request_count(), 5);
    }
}

// ============================================================================
// Content Type Bounds
// ============================================================================

mod content_type_bounds {
    use super::*;

    const MAX_CONTENT_TYPES: usize = 20;

    #[test]
    fn test_content_type_at_limit() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add MAX_CONTENT_TYPES unique content types
        for i in 0..MAX_CONTENT_TYPES {
            profile.update(
                100,
                &[],
                Some(&format!("application/type-{}", i)),
                1000 + i as u64,
            );
        }

        assert_eq!(profile.content_types.len(), MAX_CONTENT_TYPES);
    }

    #[test]
    fn test_content_type_ignores_new_after_limit() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Fill to limit
        for i in 0..MAX_CONTENT_TYPES {
            profile.update(
                100,
                &[],
                Some(&format!("application/type-{}", i)),
                1000 + i as u64,
            );
        }

        // Try to add more
        for i in 0..10 {
            profile.update(
                100,
                &[],
                Some(&format!("application/extra-{}", i)),
                2000 + i as u64,
            );
        }

        // Should still be at limit
        assert_eq!(profile.content_types.len(), MAX_CONTENT_TYPES);
    }

    #[test]
    fn test_content_type_updates_existing_after_limit() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Fill to limit
        for i in 0..MAX_CONTENT_TYPES {
            profile.update(100, &[], Some(&format!("application/type-{}", i)), 1000);
        }

        let initial_count = *profile.content_types.get("application/type-0").unwrap();

        // Update existing type
        profile.update(100, &[], Some("application/type-0"), 2000);

        let updated_count = *profile.content_types.get("application/type-0").unwrap();
        assert_eq!(updated_count, initial_count + 1);
    }
}

// ============================================================================
// Parameter Bounds
// ============================================================================

mod param_bounds {
    use super::*;

    const MAX_PARAMS: usize = 50;

    #[test]
    fn test_params_at_limit() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add MAX_PARAMS unique parameters
        for i in 0..MAX_PARAMS {
            let param_name = format!("param_{}", i);
            profile.update(100, &[(&param_name, "value")], None, 1000 + i as u64);
        }

        assert!(profile.expected_params.len() <= MAX_PARAMS);
    }

    #[test]
    fn test_params_eviction_after_limit() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add more than MAX_PARAMS
        for i in 0..(MAX_PARAMS + 20) {
            let param_name = format!("param_{}", i);
            profile.update(100, &[(&param_name, "value")], None, 1000 + i as u64);
        }

        // Should not exceed MAX_PARAMS
        assert!(profile.expected_params.len() <= MAX_PARAMS);
    }

    #[test]
    fn test_params_evicts_least_frequent() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add a frequently used param
        for _ in 0..100 {
            profile.update(100, &[("frequent_param", "value")], None, 1000);
        }

        // Add many infrequent params
        for i in 0..(MAX_PARAMS + 10) {
            let param_name = format!("rare_param_{}", i);
            profile.update(100, &[(&param_name, "value")], None, 1000);
        }

        // Frequent param should still exist
        assert!(profile.expected_params.contains_key("frequent_param"));
    }
}

// ============================================================================
// Content Type Analysis
// ============================================================================

mod content_type_analysis {
    use super::*;

    #[test]
    fn test_dominant_content_type_single() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        profile.update(100, &[], Some("application/json"), 1000);

        assert_eq!(profile.dominant_content_type(), Some("application/json"));
    }

    #[test]
    fn test_dominant_content_type_multiple() {
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
    fn test_dominant_content_type_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert!(profile.dominant_content_type().is_none());
    }

    #[test]
    fn test_dominant_content_type_tie() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Equal counts
        for _ in 0..5 {
            profile.update(100, &[], Some("application/json"), 1000);
        }
        for _ in 0..5 {
            profile.update(100, &[], Some("application/xml"), 1000);
        }

        // Should return one of them (implementation-dependent)
        let dominant = profile.dominant_content_type();
        assert!(dominant == Some("application/json") || dominant == Some("application/xml"));
    }
}

// ============================================================================
// Parameter Frequency
// ============================================================================

mod param_frequency {
    use super::*;

    #[test]
    fn test_param_frequency_all_requests() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        for i in 0..10 {
            profile.update(100, &[("name", "John")], None, 1000 + i);
        }

        assert!((profile.param_frequency("name") - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_param_frequency_half_requests() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        for i in 0..10 {
            let params: Vec<(&str, &str)> = if i % 2 == 0 {
                vec![("name", "John"), ("email", "john@test.com")]
            } else {
                vec![("name", "John")]
            };
            profile.update(100, &params, None, 1000 + i);
        }

        assert!((profile.param_frequency("name") - 1.0).abs() < 0.01);
        assert!((profile.param_frequency("email") - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_param_frequency_unknown_param() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        profile.update(100, &[("name", "John")], None, 1000);

        assert_eq!(profile.param_frequency("unknown"), 0.0);
    }

    #[test]
    fn test_param_frequency_empty_profile() {
        let profile = EndpointProfile::new("/api/users".to_string(), 1000);
        assert_eq!(profile.param_frequency("name"), 0.0);
    }

    #[test]
    fn test_is_expected_param_above_threshold() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        // "name" in 9/10 requests
        for i in 0..10 {
            let params: Vec<(&str, &str)> = if i < 9 {
                vec![("name", "John")]
            } else {
                vec![]
            };
            profile.update(100, &params, None, 1000 + i);
        }

        assert!(profile.is_expected_param("name", 0.8)); // 90% > 80%
    }

    #[test]
    fn test_is_expected_param_below_threshold() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        // "optional" in 2/10 requests
        for i in 0..10 {
            let params: Vec<(&str, &str)> = if i < 2 {
                vec![("optional", "value")]
            } else {
                vec![]
            };
            profile.update(100, &params, None, 1000 + i);
        }

        assert!(!profile.is_expected_param("optional", 0.8)); // 20% < 80%
    }

    #[test]
    fn test_is_expected_param_at_threshold() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);

        // "param" in 8/10 requests
        for i in 0..10 {
            let params: Vec<(&str, &str)> = if i < 8 {
                vec![("param", "value")]
            } else {
                vec![]
            };
            profile.update(100, &params, None, 1000 + i);
        }

        assert!(profile.is_expected_param("param", 0.8)); // 80% >= 80%
    }
}

// ============================================================================
// Status Code Tracking
// ============================================================================

mod status_codes {
    use super::*;

    #[test]
    fn test_record_status() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        profile.record_status(200);
        profile.record_status(200);
        profile.record_status(404);

        assert_eq!(profile.status_codes.get(&200), Some(&2));
        assert_eq!(profile.status_codes.get(&404), Some(&1));
    }

    #[test]
    fn test_status_frequency() {
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
    }

    #[test]
    fn test_status_frequency_unknown() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        profile.record_status(200);

        assert_eq!(profile.status_frequency(404), 0.0);
    }

    #[test]
    fn test_status_frequency_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert_eq!(profile.status_frequency(200), 0.0);
    }

    #[test]
    fn test_error_rate() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // 70% success, 20% client errors, 10% server errors
        for _ in 0..7 {
            profile.record_status(200);
        }
        for _ in 0..2 {
            profile.record_status(404);
        }
        profile.record_status(500);

        // Error rate = (2 + 1) / 10 = 0.3
        assert!((profile.error_rate() - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_error_rate_all_success() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        for _ in 0..10 {
            profile.record_status(200);
        }

        assert_eq!(profile.error_rate(), 0.0);
    }

    #[test]
    fn test_error_rate_all_errors() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        for _ in 0..5 {
            profile.record_status(400);
        }
        for _ in 0..5 {
            profile.record_status(500);
        }

        assert_eq!(profile.error_rate(), 1.0);
    }

    #[test]
    fn test_error_rate_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert_eq!(profile.error_rate(), 0.0);
    }

    #[test]
    fn test_error_rate_includes_4xx() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        profile.record_status(200);
        profile.record_status(400); // Bad Request
        profile.record_status(401); // Unauthorized
        profile.record_status(403); // Forbidden
        profile.record_status(404); // Not Found

        // 4 errors out of 5 = 80%
        assert!((profile.error_rate() - 0.8).abs() < 0.01);
    }
}

// ============================================================================
// Rate Analysis
// ============================================================================

mod rate_analysis {
    use super::*;

    #[test]
    fn test_baseline_rate() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 0);

        // 60 requests over 1 minute
        for i in 0..60 {
            profile.update(100, &[], None, i * 1000);
        }

        let rate = profile.baseline_rate(60_000);
        assert!((rate - 60.0).abs() < 1.0);
    }

    #[test]
    fn test_baseline_rate_2_minutes() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 0);

        // 60 requests over 2 minutes
        for i in 0..60 {
            profile.update(100, &[], None, i * 2000);
        }

        let rate = profile.baseline_rate(120_000);
        assert!((rate - 30.0).abs() < 1.0); // 30 req/min
    }

    #[test]
    fn test_baseline_rate_short_lifetime() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        profile.update(100, &[], None, 1001);

        // Very short lifetime should still work
        let rate = profile.baseline_rate(1001);
        assert!(rate > 0.0);
    }

    #[test]
    fn test_baseline_rate_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 0);
        let rate = profile.baseline_rate(60_000);
        assert_eq!(rate, 0.0);
    }
}

// ============================================================================
// Profile Maturity
// ============================================================================

mod maturity {
    use super::*;

    #[test]
    fn test_is_mature_false() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        for i in 0..9 {
            profile.update(100, &[], None, 1000 + i);
        }

        assert!(!profile.is_mature(10));
    }

    #[test]
    fn test_is_mature_at_threshold() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        for i in 0..10 {
            profile.update(100, &[], None, 1000 + i);
        }

        assert!(profile.is_mature(10));
    }

    #[test]
    fn test_is_mature_above_threshold() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        for i in 0..100 {
            profile.update(100, &[], None, 1000 + i);
        }

        assert!(profile.is_mature(10));
        assert!(profile.is_mature(50));
        assert!(profile.is_mature(100));
        assert!(!profile.is_mature(101));
    }

    #[test]
    fn test_is_mature_empty() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert!(!profile.is_mature(1));
    }
}

// ============================================================================
// Time Tracking
// ============================================================================

mod time_tracking {
    use super::*;

    #[test]
    fn test_age_ms() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert_eq!(profile.age_ms(2000), 1000);
        assert_eq!(profile.age_ms(5000), 4000);
    }

    #[test]
    fn test_age_ms_at_creation() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        assert_eq!(profile.age_ms(1000), 0);
    }

    #[test]
    fn test_age_ms_saturating() {
        let profile = EndpointProfile::new("/api/test".to_string(), 1000);
        // Time before creation should saturate to 0
        assert_eq!(profile.age_ms(500), 0);
    }

    #[test]
    fn test_idle_ms() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);
        profile.update(100, &[], None, 2000);

        assert_eq!(profile.idle_ms(3000), 1000);
        assert_eq!(profile.idle_ms(5000), 3000);
    }

    #[test]
    fn test_idle_ms_just_updated() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);
        profile.update(100, &[], None, 2000);

        assert_eq!(profile.idle_ms(2000), 0);
    }

    #[test]
    fn test_idle_ms_saturating() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);
        profile.update(100, &[], None, 2000);

        // Time before last update should saturate to 0
        assert_eq!(profile.idle_ms(1500), 0);
    }
}

// ============================================================================
// Serialization
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);
        profile.update(
            100,
            &[("name", "John"), ("email", "john@test.com")],
            Some("application/json"),
            2000,
        );
        profile.record_status(200);

        let serialized = serde_json::to_string(&profile).expect("Failed to serialize");
        let deserialized: EndpointProfile =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(profile.template, deserialized.template);
        assert_eq!(profile.sample_count, deserialized.sample_count);
        assert_eq!(profile.first_seen_ms, deserialized.first_seen_ms);
        assert_eq!(profile.last_updated_ms, deserialized.last_updated_ms);
    }

    #[test]
    fn test_clone() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);
        profile.update(100, &[("param", "value")], Some("application/json"), 2000);

        let cloned = profile.clone();

        assert_eq!(profile.template, cloned.template);
        assert_eq!(profile.sample_count, cloned.sample_count);
        // Note: expected_params contains ParamStats which doesn't impl PartialEq
        assert_eq!(profile.expected_params.len(), cloned.expected_params.len());
    }
}
