//! Tests for RateTracker.
//!
//! Coverage targets:
//! - new, record, current_rate, rate_in_window
//! - request_count, last_request_time, clear, is_burst
//!
//! Edge cases:
//! - Empty tracker
//! - Single request
//! - Buffer wraparound (>64 requests)
//! - Window boundary conditions
//! - Zero baseline for burst detection

use synapse_pingora::profiler::RateTracker;

// ============================================================================
// Basic Operations
// ============================================================================

mod basic_operations {
    use super::*;

    #[test]
    fn test_new_tracker_empty() {
        let rt = RateTracker::new();
        assert_eq!(rt.request_count(), 0);
        assert_eq!(rt.current_rate(1000000), 0.0);
        assert!(rt.last_request_time().is_none());
    }

    #[test]
    fn test_default_trait() {
        let rt = RateTracker::default();
        assert_eq!(rt.request_count(), 0);
    }

    #[test]
    fn test_single_record() {
        let mut rt = RateTracker::new();
        let rate = rt.record(1000);

        assert_eq!(rt.request_count(), 1);
        assert!(rate > 0.0);
        assert_eq!(rt.last_request_time(), Some(1000));
    }

    #[test]
    fn test_multiple_records() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        for i in 0..10 {
            rt.record(base_time + i * 100);
        }

        assert_eq!(rt.request_count(), 10);
        assert_eq!(rt.last_request_time(), Some(base_time + 900));
    }

    #[test]
    fn test_record_returns_current_rate() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        for i in 0..5 {
            let rate = rt.record(base_time + i * 100);
            assert_eq!(rate, (i + 1) as f64);
        }
    }
}

// ============================================================================
// Rate Calculation
// ============================================================================

mod rate_calculation {
    use super::*;

    #[test]
    fn test_current_rate_within_window() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 10 requests in 1 second
        for i in 0..10 {
            rt.record(base_time + i * 100);
        }

        // Rate should be 10 req/min (all within 60s window)
        let rate = rt.current_rate(base_time + 1000);
        assert!((rate - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_current_rate_partial_window() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 5 requests
        for i in 0..5 {
            rt.record(base_time + i * 100);
        }

        // Rate at base_time + 500ms
        let rate = rt.current_rate(base_time + 500);
        assert_eq!(rate, 5.0);
    }

    #[test]
    fn test_current_rate_outside_window() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record requests
        for i in 0..5 {
            rt.record(base_time + i * 100);
        }

        // Check rate 61 seconds later - all old requests should be outside window
        let rate = rt.current_rate(base_time + 61_000);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_current_rate_at_window_boundary() {
        let mut rt = RateTracker::new();

        // Record at timestamp 1 (not 0, to avoid edge case with cutoff comparison)
        rt.record(1);

        // At 60001ms, the request at 1 should be outside the window
        // (cutoff = 60001 - 60000 = 1, filter is ts > cutoff, so ts > 1)
        let rate = rt.current_rate(60_001);
        assert_eq!(rate, 0.0);

        // At 60000ms, the request at 1 should still be in window
        // (cutoff = 60000 - 60000 = 0, filter is ts > 0, so 1 > 0 = true)
        let rate_earlier = rt.current_rate(60_000);
        assert_eq!(rate_earlier, 1.0);
    }

    #[test]
    fn test_current_rate_empty_tracker() {
        let rt = RateTracker::new();
        assert_eq!(rt.current_rate(1_000_000), 0.0);
    }
}

// ============================================================================
// Custom Window Rate
// ============================================================================

mod custom_window {
    use super::*;

    #[test]
    fn test_rate_in_window_10_seconds() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 10 requests over 10 seconds
        // Timestamps: base_time, base_time+1000, ..., base_time+9000
        for i in 0..10 {
            rt.record(base_time + i * 1000);
        }

        // Rate in 10-second window (10 requests)
        // At base_time + 9999, cutoff = base_time - 1, all 10 requests are > cutoff
        // Normalized to per-minute: 10 * (60000 / 10000) = 60
        let rate = rt.rate_in_window(base_time + 9999, 10_000);
        assert!((rate - 60.0).abs() < 1.0);
    }

    #[test]
    fn test_rate_in_window_5_seconds() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 10 requests over 10 seconds
        for i in 0..10 {
            rt.record(base_time + i * 1000);
        }

        // Rate in 5-second window from end
        // Should include requests at 5000, 6000, 7000, 8000, 9000 = 5 requests
        // Normalized: 5 * (60000 / 5000) = 60 req/min
        let rate = rt.rate_in_window(base_time + 10000, 5_000);
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_in_window_zero_window() {
        let mut rt = RateTracker::new();
        rt.record(1000);

        assert_eq!(rt.rate_in_window(1000, 0), 0.0);
    }

    #[test]
    fn test_rate_in_window_empty_tracker() {
        let rt = RateTracker::new();
        assert_eq!(rt.rate_in_window(1000, 10000), 0.0);
    }

    #[test]
    fn test_rate_in_window_large_window() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        for i in 0..10 {
            rt.record(base_time + i * 100);
        }

        // Use a 120 second window (2 minutes)
        let rate = rt.rate_in_window(base_time + 1000, 120_000);
        // 10 requests / 2 min window * 60 = 5 req/min
        assert!((rate - 5.0).abs() < 0.5);
    }
}

// ============================================================================
// Buffer Wraparound
// ============================================================================

mod buffer_wraparound {
    use super::*;

    #[test]
    fn test_buffer_exactly_64() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        for i in 0..64 {
            rt.record(base_time + i * 100);
        }

        assert_eq!(rt.request_count(), 64);
    }

    #[test]
    fn test_buffer_over_64() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 100 requests
        for i in 0..100 {
            rt.record(base_time + i * 100);
        }

        // Should max out at 64
        assert_eq!(rt.request_count(), 64);
    }

    #[test]
    fn test_buffer_wraparound_last_request_time() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Fill and overflow buffer
        for i in 0..100 {
            rt.record(base_time + i * 100);
        }

        // Last request should be the most recent
        assert_eq!(rt.last_request_time(), Some(base_time + 99 * 100));
    }

    #[test]
    fn test_buffer_wraparound_rate_calculation() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 100 requests quickly
        for i in 0..100 {
            rt.record(base_time + i * 10); // 10ms apart
        }

        // Rate should be based on the 64 most recent requests
        let rate = rt.current_rate(base_time + 1000);
        assert!(rate > 0.0);
        assert!(rate <= 64.0); // Can't exceed buffer size
    }
}

// ============================================================================
// Last Request Time
// ============================================================================

mod last_request_time {
    use super::*;

    #[test]
    fn test_last_request_time_empty() {
        let rt = RateTracker::new();
        assert!(rt.last_request_time().is_none());
    }

    #[test]
    fn test_last_request_time_single() {
        let mut rt = RateTracker::new();
        rt.record(1000);
        assert_eq!(rt.last_request_time(), Some(1000));
    }

    #[test]
    fn test_last_request_time_multiple() {
        let mut rt = RateTracker::new();
        rt.record(1000);
        rt.record(2000);
        rt.record(3000);
        assert_eq!(rt.last_request_time(), Some(3000));
    }

    #[test]
    fn test_last_request_time_at_buffer_boundary() {
        let mut rt = RateTracker::new();

        // Fill exactly to buffer boundary
        for i in 0..64 {
            rt.record(i as u64 * 100);
        }

        assert_eq!(rt.last_request_time(), Some(63 * 100));
    }

    #[test]
    fn test_last_request_time_after_wraparound() {
        let mut rt = RateTracker::new();

        for i in 0..65 {
            rt.record(i as u64 * 100);
        }

        // After one wraparound
        assert_eq!(rt.last_request_time(), Some(64 * 100));
    }
}

// ============================================================================
// Clear
// ============================================================================

mod clear {
    use super::*;

    #[test]
    fn test_clear_resets_count() {
        let mut rt = RateTracker::new();

        for i in 0..10 {
            rt.record(1000 + i * 100);
        }
        assert_eq!(rt.request_count(), 10);

        rt.clear();
        assert_eq!(rt.request_count(), 0);
    }

    #[test]
    fn test_clear_resets_last_request_time() {
        let mut rt = RateTracker::new();
        rt.record(1000);

        rt.clear();
        assert!(rt.last_request_time().is_none());
    }

    #[test]
    fn test_clear_resets_rate() {
        let mut rt = RateTracker::new();

        for i in 0..10 {
            rt.record(i * 100);
        }
        assert!(rt.current_rate(1000) > 0.0);

        rt.clear();
        assert_eq!(rt.current_rate(1000), 0.0);
    }

    #[test]
    fn test_clear_allows_reuse() {
        let mut rt = RateTracker::new();

        // First use
        for i in 0..5 {
            rt.record(i * 100);
        }

        rt.clear();

        // Second use
        for i in 0..3 {
            rt.record(1000 + i * 100);
        }

        assert_eq!(rt.request_count(), 3);
        assert_eq!(rt.last_request_time(), Some(1200));
    }
}

// ============================================================================
// Burst Detection
// ============================================================================

mod burst_detection {
    use super::*;

    #[test]
    fn test_is_burst_true() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 20 requests
        for i in 0..20 {
            rt.record(base_time + i * 100);
        }

        // Baseline of 5 req/min, current is 20 req/min
        // 20 > 5 * 3 = 15, so should be burst
        assert!(rt.is_burst(base_time + 2000, 5.0, 3.0));
    }

    #[test]
    fn test_is_burst_false() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 20 requests
        for i in 0..20 {
            rt.record(base_time + i * 100);
        }

        // Baseline of 5 req/min, multiplier 5
        // 20 > 5 * 5 = 25? No
        assert!(!rt.is_burst(base_time + 2000, 5.0, 5.0));
    }

    #[test]
    fn test_is_burst_zero_baseline() {
        let mut rt = RateTracker::new();
        rt.record(1000);

        // Zero baseline should not trigger burst
        assert!(!rt.is_burst(1000, 0.0, 2.0));
    }

    #[test]
    fn test_is_burst_negative_baseline() {
        let mut rt = RateTracker::new();
        rt.record(1000);

        // Negative baseline should not trigger burst
        assert!(!rt.is_burst(1000, -5.0, 2.0));
    }

    #[test]
    fn test_is_burst_exact_threshold() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 10 requests
        for i in 0..10 {
            rt.record(base_time + i * 100);
        }

        // Current rate is 10, baseline * multiplier = 5 * 2 = 10
        // 10 > 10 is false (not strictly greater)
        assert!(!rt.is_burst(base_time + 1000, 5.0, 2.0));
    }

    #[test]
    fn test_is_burst_empty_tracker() {
        let rt = RateTracker::new();
        // Empty tracker should not be a burst
        assert!(!rt.is_burst(1000, 5.0, 2.0));
    }

    #[test]
    fn test_is_burst_high_multiplier() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record 50 requests
        for i in 0..50 {
            rt.record(base_time + i * 100);
        }

        // With high multiplier, even high rate shouldn't trigger
        assert!(!rt.is_burst(base_time + 5000, 1.0, 100.0));
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_timestamps_far_in_future() {
        let mut rt = RateTracker::new();

        // Record at time 0
        rt.record(0);

        // Check rate way in the future
        let rate = rt.current_rate(u64::MAX / 2);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_saturating_subtraction() {
        let mut rt = RateTracker::new();

        // Record at time 1 (avoid 0 due to strict > comparison with cutoff)
        rt.record(1);

        // Current rate at time 1 shouldn't panic
        // cutoff = 1 - 60000 saturates to 0, and 1 > 0 is true
        let rate = rt.current_rate(1);
        assert_eq!(rate, 1.0);
    }

    #[test]
    fn test_rapid_succession() {
        let mut rt = RateTracker::new();
        let base_time = 1_000_000u64;

        // Record all at same timestamp
        for _ in 0..10 {
            rt.record(base_time);
        }

        let rate = rt.current_rate(base_time);
        assert_eq!(rate, 10.0);
    }

    #[test]
    fn test_clone() {
        let mut rt = RateTracker::new();
        rt.record(1000);
        rt.record(2000);

        let cloned = rt.clone();

        assert_eq!(rt.request_count(), cloned.request_count());
        assert_eq!(rt.last_request_time(), cloned.last_request_time());
    }
}

// ============================================================================
// Serialization (Note: timestamps are skipped in serde)
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let mut rt = RateTracker::new();
        for i in 0..10 {
            rt.record(1000 + i * 100);
        }

        let serialized = serde_json::to_string(&rt).expect("Failed to serialize");
        let deserialized: RateTracker =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // Timestamps are skipped, so deserialized will have reset timestamps
        // but write_idx and valid_count are preserved
        assert_eq!(rt.request_count(), deserialized.request_count());
    }

    #[test]
    fn test_serialized_timestamps_are_zeroed() {
        let mut rt = RateTracker::new();
        rt.record(1000);
        rt.record(2000);

        let serialized = serde_json::to_string(&rt).expect("Failed to serialize");
        let deserialized: RateTracker =
            serde_json::from_str(&serialized).expect("Failed to deserialize");

        // After deserialization, timestamps are zeroed but count is preserved
        // Rate calculation will return 0 because all timestamps are 0
        let rate = deserialized.current_rate(1_000_000);
        assert_eq!(rate, 0.0);
    }
}
