//! Tests for AnomalySignalType, AnomalySignal, and AnomalyResult.
//!
//! Coverage targets:
//! - AnomalySignalType: as_str, default_severity
//! - AnomalySignal: new, with_default_severity
//! - AnomalyResult: none, new, add, add_signal, has_anomalies, signal_count, normalize, max_severity, signal_types, merge

use synapse_pingora::profiler::{AnomalyResult, AnomalySignal, AnomalySignalType};

// ============================================================================
// AnomalySignalType Tests
// ============================================================================

mod signal_type {
    use super::*;

    #[test]
    fn test_all_types_have_as_str() {
        let types = [
            (AnomalySignalType::PayloadSizeHigh, "payload_size_high"),
            (AnomalySignalType::PayloadSizeLow, "payload_size_low"),
            (AnomalySignalType::UnexpectedParam, "unexpected_param"),
            (
                AnomalySignalType::MissingExpectedParam,
                "missing_expected_param",
            ),
            (AnomalySignalType::ParamValueAnomaly, "param_value_anomaly"),
            (
                AnomalySignalType::ContentTypeMismatch,
                "content_type_mismatch",
            ),
            (AnomalySignalType::RateBurst, "rate_burst"),
            (AnomalySignalType::ParamCountAnomaly, "param_count_anomaly"),
        ];

        for (signal_type, expected_str) in types {
            assert_eq!(signal_type.as_str(), expected_str);
        }
    }

    #[test]
    fn test_all_types_have_default_severity() {
        let types = [
            (AnomalySignalType::PayloadSizeHigh, 5),
            (AnomalySignalType::PayloadSizeLow, 2),
            (AnomalySignalType::UnexpectedParam, 3),
            (AnomalySignalType::MissingExpectedParam, 2),
            (AnomalySignalType::ParamValueAnomaly, 4),
            (AnomalySignalType::ContentTypeMismatch, 5),
            (AnomalySignalType::RateBurst, 6),
            (AnomalySignalType::ParamCountAnomaly, 3),
        ];

        for (signal_type, expected_severity) in types {
            assert_eq!(signal_type.default_severity(), expected_severity);
        }
    }

    #[test]
    fn test_signal_type_equality() {
        assert_eq!(
            AnomalySignalType::PayloadSizeHigh,
            AnomalySignalType::PayloadSizeHigh
        );
        assert_ne!(
            AnomalySignalType::PayloadSizeHigh,
            AnomalySignalType::PayloadSizeLow
        );
    }

    #[test]
    fn test_signal_type_clone() {
        let original = AnomalySignalType::RateBurst;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_signal_type_copy() {
        let original = AnomalySignalType::UnexpectedParam;
        let copied = original; // Copy, not move
        assert_eq!(original, copied);
    }

    #[test]
    fn test_signal_type_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(AnomalySignalType::PayloadSizeHigh);
        set.insert(AnomalySignalType::RateBurst);
        set.insert(AnomalySignalType::PayloadSizeHigh); // Duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&AnomalySignalType::PayloadSizeHigh));
        assert!(set.contains(&AnomalySignalType::RateBurst));
    }

    #[test]
    fn test_signal_type_serialize() {
        let signal_type = AnomalySignalType::RateBurst;
        let serialized = serde_json::to_string(&signal_type).expect("Failed to serialize");
        assert_eq!(serialized, "\"rate_burst\"");
    }

    #[test]
    fn test_signal_type_deserialize() {
        let deserialized: AnomalySignalType =
            serde_json::from_str("\"content_type_mismatch\"").expect("Failed to deserialize");
        assert_eq!(deserialized, AnomalySignalType::ContentTypeMismatch);
    }
}

// ============================================================================
// AnomalySignal Tests
// ============================================================================

mod signal {
    use super::*;

    #[test]
    fn test_new_signal() {
        let signal = AnomalySignal::new(
            AnomalySignalType::PayloadSizeHigh,
            7,
            "Large payload detected".to_string(),
        );

        assert_eq!(signal.signal_type, AnomalySignalType::PayloadSizeHigh);
        assert_eq!(signal.severity, 7);
        assert_eq!(signal.detail, "Large payload detected");
    }

    #[test]
    fn test_severity_clamped_to_max() {
        let signal = AnomalySignal::new(
            AnomalySignalType::RateBurst,
            15, // Over max
            "Test".to_string(),
        );

        assert_eq!(signal.severity, 10); // Clamped to 10
    }

    #[test]
    fn test_severity_at_max() {
        let signal = AnomalySignal::new(AnomalySignalType::RateBurst, 10, "Test".to_string());

        assert_eq!(signal.severity, 10);
    }

    #[test]
    fn test_severity_zero() {
        let signal = AnomalySignal::new(AnomalySignalType::PayloadSizeLow, 0, "Test".to_string());

        assert_eq!(signal.severity, 0);
    }

    #[test]
    fn test_with_default_severity() {
        let signal = AnomalySignal::with_default_severity(
            AnomalySignalType::RateBurst,
            "Rate burst detected".to_string(),
        );

        assert_eq!(signal.severity, 6); // Default for RateBurst
        assert_eq!(signal.signal_type, AnomalySignalType::RateBurst);
    }

    #[test]
    fn test_with_default_severity_all_types() {
        let types = [
            AnomalySignalType::PayloadSizeHigh,
            AnomalySignalType::PayloadSizeLow,
            AnomalySignalType::UnexpectedParam,
            AnomalySignalType::MissingExpectedParam,
            AnomalySignalType::ParamValueAnomaly,
            AnomalySignalType::ContentTypeMismatch,
            AnomalySignalType::RateBurst,
            AnomalySignalType::ParamCountAnomaly,
        ];

        for signal_type in types {
            let signal = AnomalySignal::with_default_severity(signal_type, "Test".to_string());
            assert_eq!(signal.severity, signal_type.default_severity());
        }
    }

    #[test]
    fn test_signal_clone() {
        let original = AnomalySignal::new(
            AnomalySignalType::UnexpectedParam,
            5,
            "Unexpected param".to_string(),
        );

        let cloned = original.clone();

        assert_eq!(original.signal_type, cloned.signal_type);
        assert_eq!(original.severity, cloned.severity);
        assert_eq!(original.detail, cloned.detail);
    }

    #[test]
    fn test_signal_serialize() {
        let signal = AnomalySignal::new(
            AnomalySignalType::PayloadSizeHigh,
            7,
            "Large payload".to_string(),
        );

        let serialized = serde_json::to_string(&signal).expect("Failed to serialize");
        assert!(serialized.contains("payload_size_high"));
        assert!(serialized.contains("7"));
        assert!(serialized.contains("Large payload"));
    }

    #[test]
    fn test_signal_deserialize() {
        let json = r#"{"signal_type":"rate_burst","severity":6,"detail":"High rate"}"#;
        let signal: AnomalySignal = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(signal.signal_type, AnomalySignalType::RateBurst);
        assert_eq!(signal.severity, 6);
        assert_eq!(signal.detail, "High rate");
    }
}

// ============================================================================
// AnomalyResult Tests
// ============================================================================

mod result {
    use super::*;

    #[test]
    fn test_none_result() {
        let result = AnomalyResult::none();

        assert!(!result.has_anomalies());
        assert_eq!(result.total_score, 0.0);
        assert_eq!(result.signal_count(), 0);
        assert!(result.signals.is_empty());
    }

    #[test]
    fn test_new_result() {
        let result = AnomalyResult::new();

        assert!(!result.has_anomalies());
        assert_eq!(result.total_score, 0.0);
        assert_eq!(result.signal_count(), 0);
    }

    #[test]
    fn test_default_trait() {
        let result = AnomalyResult::default();

        assert!(!result.has_anomalies());
        assert_eq!(result.total_score, 0.0);
    }

    #[test]
    fn test_add_single_signal() {
        let mut result = AnomalyResult::new();
        result.add(
            AnomalySignalType::UnexpectedParam,
            3,
            "New param".to_string(),
        );

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 1);
        assert_eq!(result.total_score, 3.0);
    }

    #[test]
    fn test_add_multiple_signals() {
        let mut result = AnomalyResult::new();
        result.add(
            AnomalySignalType::UnexpectedParam,
            3,
            "New param".to_string(),
        );
        result.add(AnomalySignalType::RateBurst, 6, "High rate".to_string());

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 2);
        assert_eq!(result.total_score, 9.0);
    }

    #[test]
    fn test_add_signal() {
        let mut result = AnomalyResult::new();
        let signal = AnomalySignal::new(AnomalySignalType::PayloadSizeHigh, 5, "Large".to_string());
        result.add_signal(signal);

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 1);
        assert_eq!(result.total_score, 5.0);
    }

    #[test]
    fn test_normalize_under_limit() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::UnexpectedParam, 3, "Test".to_string());

        result.normalize();

        assert_eq!(result.total_score, 3.0); // Unchanged
    }

    #[test]
    fn test_normalize_clamps_high() {
        let mut result = AnomalyResult::new();
        // Add many signals to exceed +10
        for _ in 0..5 {
            result.add(AnomalySignalType::RateBurst, 6, "Test".to_string());
        }

        assert_eq!(result.total_score, 30.0);

        result.normalize();

        assert_eq!(result.total_score, 10.0);
    }

    #[test]
    fn test_normalize_at_boundary() {
        let mut result = AnomalyResult::new();
        result.total_score = 10.0;

        result.normalize();

        assert_eq!(result.total_score, 10.0);
    }

    #[test]
    fn test_normalize_negative_score() {
        let mut result = AnomalyResult::new();
        result.total_score = -15.0;

        result.normalize();

        assert_eq!(result.total_score, -10.0);
    }

    #[test]
    fn test_max_severity_single() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::UnexpectedParam, 5, "Test".to_string());

        assert_eq!(result.max_severity(), 5);
    }

    #[test]
    fn test_max_severity_multiple() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::PayloadSizeLow, 2, "Small".to_string());
        result.add(AnomalySignalType::RateBurst, 8, "Burst".to_string());
        result.add(AnomalySignalType::UnexpectedParam, 3, "Param".to_string());

        assert_eq!(result.max_severity(), 8);
    }

    #[test]
    fn test_max_severity_empty() {
        let result = AnomalyResult::none();
        assert_eq!(result.max_severity(), 0);
    }

    #[test]
    fn test_signal_types() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::PayloadSizeHigh, 5, "Test".to_string());
        result.add(AnomalySignalType::RateBurst, 6, "Test".to_string());

        let types = result.signal_types();

        assert_eq!(types.len(), 2);
        assert!(types.contains(&AnomalySignalType::PayloadSizeHigh));
        assert!(types.contains(&AnomalySignalType::RateBurst));
    }

    #[test]
    fn test_signal_types_empty() {
        let result = AnomalyResult::none();
        assert!(result.signal_types().is_empty());
    }

    #[test]
    fn test_signal_types_duplicates() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::RateBurst, 6, "First".to_string());
        result.add(AnomalySignalType::RateBurst, 6, "Second".to_string());

        let types = result.signal_types();

        // Should include duplicates
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn test_merge_two_results() {
        let mut result1 = AnomalyResult::new();
        result1.add(AnomalySignalType::PayloadSizeHigh, 5, "Test1".to_string());

        let mut result2 = AnomalyResult::new();
        result2.add(AnomalySignalType::RateBurst, 6, "Test2".to_string());

        result1.merge(result2);

        assert_eq!(result1.signal_count(), 2);
        assert_eq!(result1.total_score, 11.0);
    }

    #[test]
    fn test_merge_with_empty() {
        let mut result1 = AnomalyResult::new();
        result1.add(AnomalySignalType::PayloadSizeHigh, 5, "Test".to_string());

        let result2 = AnomalyResult::none();

        result1.merge(result2);

        assert_eq!(result1.signal_count(), 1);
        assert_eq!(result1.total_score, 5.0);
    }

    #[test]
    fn test_merge_empty_with_populated() {
        let mut result1 = AnomalyResult::none();

        let mut result2 = AnomalyResult::new();
        result2.add(AnomalySignalType::RateBurst, 6, "Test".to_string());

        result1.merge(result2);

        assert_eq!(result1.signal_count(), 1);
        assert_eq!(result1.total_score, 6.0);
    }

    #[test]
    fn test_has_anomalies_after_merge() {
        let mut result1 = AnomalyResult::none();
        let mut result2 = AnomalyResult::new();
        result2.add(AnomalySignalType::UnexpectedParam, 3, "Test".to_string());

        assert!(!result1.has_anomalies());

        result1.merge(result2);

        assert!(result1.has_anomalies());
    }

    #[test]
    fn test_result_clone() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::PayloadSizeHigh, 5, "Test".to_string());
        result.add(AnomalySignalType::RateBurst, 6, "Test".to_string());

        let cloned = result.clone();

        assert_eq!(result.total_score, cloned.total_score);
        assert_eq!(result.signal_count(), cloned.signal_count());
    }

    #[test]
    fn test_result_serialize() {
        let mut result = AnomalyResult::new();
        result.add(
            AnomalySignalType::UnexpectedParam,
            3,
            "Test param".to_string(),
        );

        let serialized = serde_json::to_string(&result).expect("Failed to serialize");

        assert!(serialized.contains("total_score"));
        assert!(serialized.contains("signals"));
        assert!(serialized.contains("unexpected_param"));
    }

    #[test]
    fn test_result_deserialize() {
        let json = r#"{"total_score":3.0,"signals":[{"signal_type":"unexpected_param","severity":3,"detail":"Test"}]}"#;
        let result: AnomalyResult = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(result.total_score, 3.0);
        assert_eq!(result.signal_count(), 1);
        assert!(result.has_anomalies());
    }
}

// ============================================================================
// Integration Scenarios
// ============================================================================

mod scenarios {
    use super::*;

    #[test]
    fn test_anomaly_detection_workflow() {
        // Simulate a typical anomaly detection workflow
        let mut result = AnomalyResult::new();

        // Detect payload size anomaly
        let payload_size = 10000;
        let mean_size = 1000;
        if payload_size > mean_size * 5 {
            result.add(
                AnomalySignalType::PayloadSizeHigh,
                5,
                format!("Payload {}B vs mean {}B", payload_size, mean_size),
            );
        }

        // Detect unexpected parameter
        let unexpected_params = vec!["malicious_param"];
        if !unexpected_params.is_empty() {
            result.add(
                AnomalySignalType::UnexpectedParam,
                3,
                format!("{} unexpected parameters", unexpected_params.len()),
            );
        }

        result.normalize();

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 2);
        assert!(result.total_score <= 10.0);
    }

    #[test]
    fn test_multi_signal_attack_pattern() {
        let mut result = AnomalyResult::new();

        // Multiple signals indicating attack
        result.add(
            AnomalySignalType::PayloadSizeHigh,
            7,
            "Oversized payload".to_string(),
        );
        result.add(
            AnomalySignalType::UnexpectedParam,
            4,
            "SQL injection attempt".to_string(),
        );
        result.add(AnomalySignalType::RateBurst, 6, "Rate spike".to_string());
        result.add(
            AnomalySignalType::ContentTypeMismatch,
            5,
            "Wrong content type".to_string(),
        );

        result.normalize();

        // Total should be clamped to 10
        assert_eq!(result.total_score, 10.0);
        assert_eq!(result.signal_count(), 4);
        assert_eq!(result.max_severity(), 7);
    }
}
