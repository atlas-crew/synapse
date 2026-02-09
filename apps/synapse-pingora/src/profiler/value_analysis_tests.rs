#[cfg(test)]
mod tests {
    use crate::config::ProfilerConfig;
    use crate::profiler::{is_likely_pii, redact_value, AnomalySignalType, Profiler};

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
    fn test_value_length_anomaly() {
        let profiler = Profiler::new(default_config());
        let template = "/api/test";

        // Train with varied short strings (length ~3-8) to establish variance
        let training_values = ["hi", "hey", "hello", "short", "testing", "goodbye"];
        for i in 0..50 {
            let value = training_values[i % training_values.len()];
            profiler.update_profile(template, 100, &[("param", value)], None);
        }

        // Test with very long string (100 chars vs ~5 average)
        let long_string = "a".repeat(100);
        let result = profiler.analyze_request(template, 100, &[("param", &long_string)], None);

        assert!(result
            .signals
            .iter()
            .any(|s| s.signal_type == AnomalySignalType::ParamValueAnomaly));
    }

    #[test]
    fn test_value_type_anomaly() {
        let profiler = Profiler::new(default_config());
        let template = "/api/test";

        // Train with numeric strings
        for i in 0..50 {
            profiler.update_profile(template, 100, &[("id", &i.to_string())], None);
        }

        // Test with non-numeric string
        let result = profiler.analyze_request(template, 100, &[("id", "not_a_number")], None);

        assert!(result
            .signals
            .iter()
            .any(|s| s.signal_type == AnomalySignalType::ParamValueAnomaly));
    }

    #[test]
    fn test_email_detection() {
        let profiler = Profiler::new(default_config());
        let template = "/api/users";

        profiler.update_profile(template, 100, &[("email", "test@example.com")], None);

        let profile = profiler.get_profile(template).unwrap();
        let stats = profile.expected_params.get("email").unwrap();

        assert_eq!(*stats.type_counts.get("email").unwrap_or(&0), 1);
    }

    #[test]
    fn test_uuid_detection() {
        let profiler = Profiler::new(default_config());
        let template = "/api/items";
        let uuid = "123e4567-e89b-12d3-a456-426614174000";

        profiler.update_profile(template, 100, &[("id", uuid)], None);

        let profile = profiler.get_profile(template).unwrap();
        let stats = profile.expected_params.get("id").unwrap();

        assert_eq!(*stats.type_counts.get("uuid").unwrap_or(&0), 1);
    }

    // ========================================================================
    // PII Redaction Tests
    // ========================================================================

    #[test]
    fn test_redact_value_email() {
        let email = "user@example.com";
        let redacted = redact_value(email);
        // Should show first 2 and last 2 chars
        assert!(redacted.starts_with("us"));
        assert!(redacted.ends_with("om"));
        assert!(redacted.contains("*"));
        // Original value should not appear
        assert!(!redacted.contains("@example"));
    }

    #[test]
    fn test_redact_value_short() {
        let short = "abc";
        let redacted = redact_value(short);
        // Short values are fully redacted
        assert_eq!(redacted, "***");
    }

    #[test]
    fn test_redact_value_uuid() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let redacted = redact_value(uuid);
        assert!(redacted.starts_with("12"));
        assert!(redacted.ends_with("00"));
        assert!(redacted.contains("*"));
    }

    #[test]
    fn test_is_likely_pii_email() {
        assert!(is_likely_pii("test@example.com"));
        assert!(is_likely_pii("user.name@company.org"));
        assert!(!is_likely_pii("not-an-email"));
    }

    #[test]
    fn test_is_likely_pii_uuid() {
        assert!(is_likely_pii("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!is_likely_pii("not-a-uuid"));
    }

    #[test]
    fn test_is_likely_pii_long_token() {
        // Long alphanumeric strings (API keys, tokens) are flagged as PII
        assert!(is_likely_pii("abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!is_likely_pii("short"));
    }

    // ========================================================================
    // Frozen Baseline Tests (Anti-Poisoning)
    // ========================================================================

    #[test]
    fn test_frozen_baseline_prevents_updates() {
        let config = ProfilerConfig {
            enabled: true,
            max_profiles: 100,
            max_schemas: 50,
            min_samples_for_validation: 5,
            freeze_after_samples: 10,
            ..Default::default()
        };
        let profiler = Profiler::new(config);
        let template = "/api/frozen";

        // Add 10 samples to reach freeze threshold
        for i in 0..10 {
            profiler.update_profile(template, 100, &[("val", &i.to_string())], None);
        }

        assert!(profiler.is_profile_frozen(template));

        // Get sample count before attempting more updates
        let count_before = profiler.get_profile(template).unwrap().sample_count;

        // Try to add more samples - should be rejected
        for i in 10..20 {
            profiler.update_profile(template, 100, &[("val", &i.to_string())], None);
        }

        // Sample count should not have changed
        let count_after = profiler.get_profile(template).unwrap().sample_count;
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn test_unfrozen_profile_accepts_updates() {
        let config = ProfilerConfig {
            enabled: true,
            max_profiles: 100,
            max_schemas: 50,
            min_samples_for_validation: 5,
            freeze_after_samples: 0, // Disabled
            ..Default::default()
        };
        let profiler = Profiler::new(config);
        let template = "/api/unfrozen";

        // Add samples
        for i in 0..20 {
            profiler.update_profile(template, 100, &[("val", &i.to_string())], None);
        }

        assert!(!profiler.is_profile_frozen(template));
        assert_eq!(profiler.get_profile(template).unwrap().sample_count, 20);
    }

    // ========================================================================
    // Type Count Bounds Tests
    // ========================================================================

    #[test]
    fn test_type_counts_bounded() {
        use crate::profiler::ParamStats;

        let mut stats = ParamStats::new();

        // Try to add many different type-like values
        // The type_counts map should stay bounded
        for _ in 0..100 {
            stats.update("12345"); // numeric
            stats.update("hello"); // string
            stats.update("test@example.com"); // email
            stats.update("123e4567-e89b-12d3-a456-426614174000"); // uuid
        }

        // Type counts should not exceed the default limit (10 types)
        // Standard types: numeric, string, email, uuid = 4
        assert!(stats.type_counts.len() <= 10);
    }

    // ========================================================================
    // Division by Zero Protection Tests
    // ========================================================================

    #[test]
    fn test_no_division_by_zero_empty_stats() {
        let profiler = Profiler::new(default_config());
        let template = "/api/divzero";

        // Create profile with minimal training
        for _ in 0..10 {
            profiler.update_profile(template, 100, &[], None);
        }

        // Analyze with parameter that has no stats (would cause div/0 if unprotected)
        let result = profiler.analyze_request(template, 100, &[("new_param", "value")], None);

        // Should not panic, should flag as unexpected param
        assert!(result
            .signals
            .iter()
            .any(|s| s.signal_type == AnomalySignalType::UnexpectedParam));
    }

    // ========================================================================
    // Configurable Threshold Tests
    // ========================================================================

    #[test]
    fn test_configurable_z_threshold() {
        // Use a higher threshold that won't flag our test case
        let config = ProfilerConfig {
            enabled: true,
            max_profiles: 100,
            max_schemas: 50,
            min_samples_for_validation: 10,
            payload_z_threshold: 10.0, // Very high threshold
            ..Default::default()
        };
        let profiler = Profiler::new(config);
        let template = "/api/threshold";

        // Train with payload size ~100
        for _ in 0..50 {
            profiler.update_profile(template, 100, &[], None);
        }

        // Test with slightly larger payload - should NOT trigger with high threshold
        let result = profiler.analyze_request(template, 200, &[], None);

        // With z-threshold of 10.0, a 2x payload shouldn't trigger
        assert!(!result
            .signals
            .iter()
            .any(|s| s.signal_type == AnomalySignalType::PayloadSizeHigh));
    }
}
