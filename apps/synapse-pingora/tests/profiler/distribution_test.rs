//! Tests for Distribution and PercentilesTracker.
//!
//! Coverage targets:
//! - PercentilesTracker: new, update, get, min, max, is_initialized
//! - Distribution: new, update, count, mean, stddev, variance, z_score, percentiles, min, max, is_valid
//!
//! Edge cases:
//! - Empty distributions
//! - Single value
//! - Negative values
//! - Large values / overflow scenarios
//! - Insufficient samples for percentiles

use synapse_pingora::profiler::{Distribution, PercentilesTracker};

// ============================================================================
// PercentilesTracker Tests
// ============================================================================

mod percentiles_tracker {
    use super::*;

    #[test]
    fn test_new_tracker_not_initialized() {
        let pt = PercentilesTracker::new();
        assert!(!pt.is_initialized());
        assert_eq!(pt.min(), 0.0);
        assert_eq!(pt.max(), 0.0);
        let (p50, p95, p99) = pt.get();
        assert_eq!(p50, 0.0);
        assert_eq!(p95, 0.0);
        assert_eq!(p99, 0.0);
    }

    #[test]
    fn test_tracker_becomes_initialized_after_5_samples() {
        let mut pt = PercentilesTracker::new();

        for i in 1..=4 {
            pt.update(i as f64);
            assert!(
                !pt.is_initialized(),
                "Should not be initialized after {} samples",
                i
            );
        }

        pt.update(5.0);
        assert!(pt.is_initialized(), "Should be initialized after 5 samples");
    }

    #[test]
    fn test_percentiles_sorted_initialization() {
        let mut pt = PercentilesTracker::new();

        // Add unsorted values
        pt.update(5.0);
        pt.update(1.0);
        pt.update(4.0);
        pt.update(2.0);
        pt.update(3.0);

        assert!(pt.is_initialized());
        assert_eq!(pt.min(), 1.0);
        assert_eq!(pt.max(), 5.0);
    }

    #[test]
    fn test_percentiles_with_100_samples() {
        let mut pt = PercentilesTracker::new();

        // Add 1 to 100
        for i in 1..=100 {
            pt.update(i as f64);
        }

        let (p50, p95, p99) = pt.get();

        // p50 should be around 50 (allow for P-square approximation)
        assert!((p50 - 50.0).abs() < 10.0, "p50 was {}, expected ~50", p50);
        // p95 should be around 95
        assert!((p95 - 95.0).abs() < 10.0, "p95 was {}, expected ~95", p95);
        // p99 should be around 99
        assert!((p99 - 99.0).abs() < 5.0, "p99 was {}, expected ~99", p99);
    }

    #[test]
    fn test_percentiles_min_max_tracking() {
        let mut pt = PercentilesTracker::new();

        for i in 1..=10 {
            pt.update(i as f64);
        }

        assert_eq!(pt.min(), 1.0);
        assert_eq!(pt.max(), 10.0);
    }

    #[test]
    fn test_percentiles_with_new_minimum() {
        let mut pt = PercentilesTracker::new();

        // Initial samples
        for i in 5..=10 {
            pt.update(i as f64);
        }

        // Add a new minimum
        pt.update(1.0);

        assert_eq!(pt.min(), 1.0);
    }

    #[test]
    fn test_percentiles_with_new_maximum() {
        let mut pt = PercentilesTracker::new();

        // Initial samples
        for i in 1..=10 {
            pt.update(i as f64);
        }

        // Add a new maximum
        pt.update(100.0);

        assert_eq!(pt.max(), 100.0);
    }

    #[test]
    fn test_percentiles_all_same_values() {
        let mut pt = PercentilesTracker::new();

        for _ in 0..20 {
            pt.update(42.0);
        }

        let (p50, p95, p99) = pt.get();

        // All percentiles should be ~42 when values are identical
        assert!((p50 - 42.0).abs() < 1.0);
        assert!((p95 - 42.0).abs() < 1.0);
        assert!((p99 - 42.0).abs() < 1.0);
    }

    #[test]
    fn test_percentiles_bimodal_distribution() {
        let mut pt = PercentilesTracker::new();

        // 50 values at 10, 50 values at 100
        for _ in 0..50 {
            pt.update(10.0);
        }
        for _ in 0..50 {
            pt.update(100.0);
        }

        let (p50, p95, _) = pt.get();

        // p50 should be somewhere between 10 and 100
        assert!(p50 >= 10.0 && p50 <= 100.0);
        // p95 should be closer to 100
        assert!(p95 >= 50.0);
    }

    #[test]
    fn test_percentiles_with_outliers() {
        let mut pt = PercentilesTracker::new();

        // 95 normal values, 5 outliers
        for i in 1..=95 {
            pt.update(i as f64);
        }
        for _ in 0..5 {
            pt.update(1000.0);
        }

        let (p50, _, _) = pt.get();

        // p50 should still be around 50 (median is robust to outliers)
        assert!((p50 - 50.0).abs() < 20.0, "p50 was {}, expected ~50", p50);
    }

    #[test]
    fn test_percentiles_negative_values() {
        let mut pt = PercentilesTracker::new();

        for i in -10..=10 {
            pt.update(i as f64);
        }

        assert_eq!(pt.min(), -10.0);
        assert_eq!(pt.max(), 10.0);
    }

    #[test]
    fn test_percentiles_floating_point() {
        let mut pt = PercentilesTracker::new();

        pt.update(0.1);
        pt.update(0.2);
        pt.update(0.3);
        pt.update(0.4);
        pt.update(0.5);

        assert!(pt.is_initialized());
        assert!((pt.min() - 0.1).abs() < 0.001);
        assert!((pt.max() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_percentiles_large_values() {
        let mut pt = PercentilesTracker::new();

        for i in 1..=10 {
            pt.update(i as f64 * 1_000_000_000.0);
        }

        assert_eq!(pt.min(), 1_000_000_000.0);
        assert_eq!(pt.max(), 10_000_000_000.0);
    }

    #[test]
    fn test_percentiles_default_trait() {
        let pt = PercentilesTracker::default();
        assert!(!pt.is_initialized());
    }

    #[test]
    fn test_percentiles_clone() {
        let mut pt = PercentilesTracker::new();
        for i in 1..=10 {
            pt.update(i as f64);
        }

        let cloned = pt.clone();
        assert_eq!(pt.min(), cloned.min());
        assert_eq!(pt.max(), cloned.max());
        assert_eq!(pt.get(), cloned.get());
    }
}

// ============================================================================
// Distribution Tests
// ============================================================================

mod distribution {
    use super::*;

    #[test]
    fn test_new_distribution_empty() {
        let d = Distribution::new();
        assert_eq!(d.count(), 0);
        assert_eq!(d.mean(), 0.0);
        assert_eq!(d.stddev(), 0.0);
        assert_eq!(d.variance(), 0.0);
        assert!(!d.is_valid());
    }

    #[test]
    fn test_distribution_default_trait() {
        let d = Distribution::default();
        assert_eq!(d.count(), 0);
        assert!(!d.is_valid());
    }

    #[test]
    fn test_distribution_single_value() {
        let mut d = Distribution::new();
        d.update(42.0);

        assert_eq!(d.count(), 1);
        assert_eq!(d.mean(), 42.0);
        assert_eq!(d.stddev(), 0.0); // Need 2+ samples for stddev
        assert_eq!(d.variance(), 0.0);
        assert!(!d.is_valid()); // Need 5+ samples
    }

    #[test]
    fn test_distribution_two_values() {
        let mut d = Distribution::new();
        d.update(10.0);
        d.update(20.0);

        assert_eq!(d.count(), 2);
        assert_eq!(d.mean(), 15.0);
        assert!(d.stddev() > 0.0);
        assert!(d.variance() > 0.0);
    }

    #[test]
    fn test_distribution_welford_basic() {
        let mut d = Distribution::new();
        for v in [10.0, 20.0, 30.0, 40.0, 50.0] {
            d.update(v);
        }

        assert_eq!(d.count(), 5);
        assert!((d.mean() - 30.0).abs() < 0.01);
        // Population stddev of [10,20,30,40,50] is ~14.14
        assert!((d.stddev() - 14.14).abs() < 0.5);
        assert!(d.is_valid());
    }

    #[test]
    fn test_distribution_welford_accuracy() {
        let mut d = Distribution::new();

        // Use known values: [2, 4, 4, 4, 5, 5, 7, 9]
        // Mean = 5, Population Variance = 4, Population StdDev = 2
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            d.update(v);
        }

        assert_eq!(d.count(), 8);
        assert!((d.mean() - 5.0).abs() < 0.01);
        // Our implementation uses population variance
        assert!((d.variance() - 4.0).abs() < 0.1);
        assert!((d.stddev() - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_distribution_z_score_at_mean() {
        let mut d = Distribution::new();
        for v in [90.0, 95.0, 100.0, 105.0, 110.0] {
            d.update(v);
        }

        // Z-score at mean should be ~0
        assert!(d.z_score(100.0).abs() < 0.1);
    }

    #[test]
    fn test_distribution_z_score_above_mean() {
        let mut d = Distribution::new();
        for v in [90.0, 95.0, 100.0, 105.0, 110.0] {
            d.update(v);
        }

        let stddev = d.stddev();
        let z = d.z_score(100.0 + 2.0 * stddev);

        // Value 2 stddev above mean should have z-score ~2
        assert!((z - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_distribution_z_score_below_mean() {
        let mut d = Distribution::new();
        for v in [90.0, 95.0, 100.0, 105.0, 110.0] {
            d.update(v);
        }

        let stddev = d.stddev();
        let z = d.z_score(100.0 - 2.0 * stddev);

        // Value 2 stddev below mean should have z-score ~-2
        assert!((z - (-2.0)).abs() < 0.1);
    }

    #[test]
    fn test_distribution_z_score_zero_stddev() {
        let mut d = Distribution::new();

        // All same values - stddev is 0
        for _ in 0..10 {
            d.update(50.0);
        }

        // Z-score should be 0 when stddev is 0 (avoids division by zero)
        assert_eq!(d.z_score(100.0), 0.0);
        assert_eq!(d.z_score(0.0), 0.0);
    }

    #[test]
    fn test_distribution_z_score_very_small_stddev() {
        let mut d = Distribution::new();

        // Very close values - stddev approaches 0
        for _ in 0..10 {
            d.update(50.0);
        }
        d.update(50.001); // Tiny variance

        // Should still return 0 due to threshold check
        let z = d.z_score(100.0);
        assert!(z.abs() < 0.1 || z == 0.0);
    }

    #[test]
    fn test_distribution_negative_values() {
        let mut d = Distribution::new();
        for v in [-10.0, -5.0, 0.0, 5.0, 10.0] {
            d.update(v);
        }

        assert!((d.mean() - 0.0).abs() < 0.01);
        assert!(d.stddev() > 0.0);
        assert!(d.is_valid());
    }

    #[test]
    fn test_distribution_large_values() {
        let mut d = Distribution::new();
        for v in [1e9, 1e9 + 1.0, 1e9 + 2.0, 1e9 + 3.0, 1e9 + 4.0] {
            d.update(v);
        }

        assert!((d.mean() - (1e9 + 2.0)).abs() < 0.01);
        assert!(d.is_valid());
    }

    #[test]
    fn test_distribution_very_small_values() {
        let mut d = Distribution::new();
        for v in [1e-9, 2e-9, 3e-9, 4e-9, 5e-9] {
            d.update(v);
        }

        assert!((d.mean() - 3e-9).abs() < 1e-10);
        assert!(d.is_valid());
    }

    #[test]
    fn test_distribution_percentiles() {
        let mut d = Distribution::new();
        for i in 1..=100 {
            d.update(i as f64);
        }

        let (p50, p95, p99) = d.percentiles();

        assert!((p50 - 50.0).abs() < 10.0);
        assert!((p95 - 95.0).abs() < 10.0);
        assert!((p99 - 99.0).abs() < 5.0);
    }

    #[test]
    fn test_distribution_min_max() {
        let mut d = Distribution::new();
        for i in 1..=10 {
            d.update(i as f64);
        }

        assert_eq!(d.min(), 1.0);
        assert_eq!(d.max(), 10.0);
    }

    #[test]
    fn test_distribution_min_max_empty() {
        let d = Distribution::new();
        assert_eq!(d.min(), 0.0);
        assert_eq!(d.max(), 0.0);
    }

    #[test]
    fn test_distribution_is_valid_threshold() {
        let mut d = Distribution::new();

        for i in 1..5 {
            d.update(i as f64);
            assert!(!d.is_valid(), "Should not be valid after {} samples", i);
        }

        d.update(5.0);
        assert!(d.is_valid(), "Should be valid after 5 samples");
    }

    #[test]
    fn test_distribution_variance_calculation() {
        let mut d = Distribution::new();
        // Uniform distribution from 0 to 10: variance ≈ 8.33
        for v in [0.0, 2.0, 4.0, 6.0, 8.0, 10.0] {
            d.update(v);
        }

        assert!((d.mean() - 5.0).abs() < 0.01);
        assert!(d.variance() > 0.0);
        assert!((d.stddev() - d.variance().sqrt()).abs() < 0.001);
    }

    #[test]
    fn test_distribution_clone() {
        let mut d = Distribution::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            d.update(v);
        }

        let cloned = d.clone();

        assert_eq!(d.count(), cloned.count());
        assert_eq!(d.mean(), cloned.mean());
        assert_eq!(d.stddev(), cloned.stddev());
        assert_eq!(d.variance(), cloned.variance());
    }

    #[test]
    fn test_distribution_high_sample_count() {
        let mut d = Distribution::new();

        // Add 10000 samples
        for i in 1..=10000 {
            d.update(i as f64);
        }

        assert_eq!(d.count(), 10000);
        assert!((d.mean() - 5000.5).abs() < 1.0);
        assert!(d.is_valid());
    }

    #[test]
    fn test_distribution_incremental_accuracy() {
        // Test that incremental updates match batch calculation
        let values = vec![1.0, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0, 35.0, 40.0, 45.0];

        let mut d = Distribution::new();
        for &v in &values {
            d.update(v);
        }

        // Calculate expected mean
        let sum: f64 = values.iter().sum();
        let expected_mean = sum / values.len() as f64;

        assert!((d.mean() - expected_mean).abs() < 0.001);
    }
}

// ============================================================================
// Serialization Tests
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_distribution_serialize_deserialize() {
        let mut d = Distribution::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            d.update(v);
        }

        let serialized = serde_json::to_string(&d).expect("Failed to serialize");
        let deserialized: Distribution =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(d.count(), deserialized.count());
        assert_eq!(d.mean(), deserialized.mean());
    }

    #[test]
    fn test_percentiles_tracker_serialize_deserialize() {
        let mut pt = PercentilesTracker::new();
        for i in 1..=10 {
            pt.update(i as f64);
        }

        let serialized = serde_json::to_string(&pt).expect("Failed to serialize");
        let deserialized: PercentilesTracker =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        assert_eq!(pt.get(), deserialized.get());
        assert_eq!(pt.min(), deserialized.min());
        assert_eq!(pt.max(), deserialized.max());
    }
}
