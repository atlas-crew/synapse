//! Sliding window request rate tracking.
//!
//! Uses a circular buffer to track request timestamps for rate calculation
//! within a configurable time window.
//!
//! ## Performance
//! - Record: O(1)
//! - Current rate: O(n) where n = buffer size (64)
//! - Memory: ~520 bytes

use serde::{Deserialize, Serialize};

// ============================================================================
// RateTracker - Sliding window request rate
// ============================================================================

/// Circular buffer for tracking requests per minute.
///
/// Uses 60-second sliding window for rate burst detection.
/// Memory: ~520 bytes (64 timestamps)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateTracker {
    /// Circular buffer of request timestamps (ms)
    /// Skip serde: rebuilt at runtime, arrays > 32 lack default serde support
    #[serde(skip, default = "default_timestamps")]
    timestamps: [u64; 64],
    /// Write index (wraps at 64)
    write_idx: u8,
    /// Number of valid entries
    valid_count: u8,
}

fn default_timestamps() -> [u64; 64] {
    [0u64; 64]
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RateTracker {
    /// Create a new rate tracker.
    pub fn new() -> Self {
        Self {
            timestamps: [0; 64],
            write_idx: 0,
            valid_count: 0,
        }
    }

    /// Record a request and return current rate (requests per minute).
    #[inline]
    pub fn record(&mut self, now_ms: u64) -> f64 {
        self.timestamps[self.write_idx as usize] = now_ms;
        self.write_idx = (self.write_idx + 1) % 64;
        if self.valid_count < 64 {
            self.valid_count += 1;
        }

        self.current_rate(now_ms)
    }

    /// Get current rate without recording (requests per minute).
    #[inline]
    pub fn current_rate(&self, now_ms: u64) -> f64 {
        if self.valid_count == 0 {
            return 0.0;
        }

        let window_ms: u64 = 60_000; // 60 seconds
        let cutoff = now_ms.saturating_sub(window_ms);

        let count = self
            .timestamps
            .iter()
            .take(self.valid_count as usize)
            .filter(|&&ts| ts > cutoff)
            .count();

        count as f64 // requests per minute (60s window)
    }

    /// Get rate for a custom window (in milliseconds).
    #[inline]
    pub fn rate_in_window(&self, now_ms: u64, window_ms: u64) -> f64 {
        if self.valid_count == 0 || window_ms == 0 {
            return 0.0;
        }

        let cutoff = now_ms.saturating_sub(window_ms);

        let count = self
            .timestamps
            .iter()
            .take(self.valid_count as usize)
            .filter(|&&ts| ts > cutoff)
            .count();

        // Normalize to requests per minute
        (count as f64 * 60_000.0) / window_ms as f64
    }

    /// Get the number of requests recorded (up to buffer size).
    #[inline]
    pub fn request_count(&self) -> u8 {
        self.valid_count
    }

    /// Get the most recent timestamp.
    #[inline]
    pub fn last_request_time(&self) -> Option<u64> {
        if self.valid_count == 0 {
            return None;
        }
        // Write index points to next slot, so previous is most recent
        let last_idx = if self.write_idx == 0 {
            (self.valid_count - 1) as usize
        } else {
            (self.write_idx - 1) as usize
        };
        Some(self.timestamps[last_idx])
    }

    /// Clear all recorded timestamps.
    pub fn clear(&mut self) {
        self.timestamps = [0; 64];
        self.write_idx = 0;
        self.valid_count = 0;
    }

    /// Check if there's a burst (rate exceeds multiplier * baseline).
    #[inline]
    pub fn is_burst(&self, now_ms: u64, baseline_rate: f64, multiplier: f64) -> bool {
        if baseline_rate <= 0.0 {
            return false;
        }
        let current = self.current_rate(now_ms);
        current > baseline_rate * multiplier
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_tracker_new() {
        let rt = RateTracker::new();
        assert_eq!(rt.request_count(), 0);
        assert_eq!(rt.current_rate(1000000), 0.0);
    }

    #[test]
    fn test_rate_tracker_record() {
        let mut rt = RateTracker::new();
        let base_time = 1000000u64;

        // Record 10 requests in 1 second
        for i in 0..10 {
            rt.record(base_time + i * 100);
        }

        // Rate should be 10 req/min (all within 60s window)
        let rate = rt.current_rate(base_time + 1000);
        assert!((rate - 10.0).abs() < 0.1);
    }

    #[test]
    fn test_rate_tracker_sliding_window() {
        let mut rt = RateTracker::new();
        let base_time = 1000000u64;

        // Record 5 requests at base time
        for i in 0..5 {
            rt.record(base_time + i * 100);
        }

        // Check rate at base time + 500ms
        let rate = rt.current_rate(base_time + 500);
        assert_eq!(rate, 5.0);

        // Check rate 61 seconds later - all old requests should be outside window
        let rate_later = rt.current_rate(base_time + 61_000);
        assert_eq!(rate_later, 0.0);
    }

    #[test]
    fn test_rate_tracker_buffer_wraparound() {
        let mut rt = RateTracker::new();
        let base_time = 1000000u64;

        // Record 100 requests (exceeds buffer size of 64)
        for i in 0..100 {
            rt.record(base_time + i * 100);
        }

        // Should have max 64 entries
        assert_eq!(rt.request_count(), 64);

        // Rate should count requests in window
        let rate = rt.current_rate(base_time + 10000);
        assert!(rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_last_request_time() {
        let mut rt = RateTracker::new();

        assert!(rt.last_request_time().is_none());

        rt.record(1000);
        assert_eq!(rt.last_request_time(), Some(1000));

        rt.record(2000);
        assert_eq!(rt.last_request_time(), Some(2000));

        rt.record(3000);
        assert_eq!(rt.last_request_time(), Some(3000));
    }

    #[test]
    fn test_rate_tracker_clear() {
        let mut rt = RateTracker::new();

        for i in 0..10 {
            rt.record(1000 + i * 100);
        }
        assert_eq!(rt.request_count(), 10);

        rt.clear();
        assert_eq!(rt.request_count(), 0);
        assert!(rt.last_request_time().is_none());
    }

    #[test]
    fn test_rate_tracker_is_burst() {
        let mut rt = RateTracker::new();
        let base_time = 1000000u64;

        // Record 20 requests
        for i in 0..20 {
            rt.record(base_time + i * 100);
        }

        // Baseline of 5 req/min, current is 20 req/min
        // 20 > 5 * 3 = 15, so should be burst
        assert!(rt.is_burst(base_time + 2000, 5.0, 3.0));

        // 20 > 5 * 5 = 25? No
        assert!(!rt.is_burst(base_time + 2000, 5.0, 5.0));
    }

    #[test]
    fn test_rate_tracker_is_burst_zero_baseline() {
        let mut rt = RateTracker::new();
        rt.record(1000);

        // Zero baseline should not trigger burst
        assert!(!rt.is_burst(1000, 0.0, 2.0));
    }

    #[test]
    fn test_rate_in_window() {
        let mut rt = RateTracker::new();
        let base_time = 1000000u64;

        // Record 10 requests over 10 seconds (at 0s, 1s, 2s, ..., 9s)
        for i in 0..10 {
            rt.record(base_time + i * 1000);
        }

        // Rate in 10-second window at now=base+10000
        // cutoff = 10000 - 10000 = 0, filter is ts > 0
        // Requests at 1s, 2s, ..., 9s = 9 requests (ts=0 excluded)
        // Rate = 9 * 60000 / 10000 = 54 req/min
        let rate = rt.rate_in_window(base_time + 10000, 10_000);
        assert!((rate - 54.0).abs() < 1.0);

        // Rate in 5-second window (requests at 5s, 6s, 7s, 8s, 9s = 5 requests)
        // cutoff = 10000 - 5000 = 5000, filter is ts > 5000
        // Requests at 6s, 7s, 8s, 9s = 4 requests
        let rate_5s = rt.rate_in_window(base_time + 10000, 5_000);
        // 4 requests * 60000 / 5000 = 48 req/min
        assert!(rate_5s > 0.0);
    }

    #[test]
    fn test_rate_in_window_zero() {
        let rt = RateTracker::new();
        assert_eq!(rt.rate_in_window(1000, 0), 0.0);
        assert_eq!(rt.rate_in_window(1000, 10000), 0.0);
    }

    #[test]
    fn test_rate_tracker_timestamps_outside_window() {
        let mut rt = RateTracker::new();

        // Record requests at time 0
        for i in 0..5 {
            rt.record(i * 100);
        }

        // Check rate way in the future - all timestamps should be outside window
        let rate = rt.current_rate(120_000); // 2 minutes later
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_rate_tracker_exact_boundary() {
        let mut rt = RateTracker::new();

        // Record at exactly 60 seconds ago
        rt.record(0);

        // At exactly 60000ms, the request at 0 should be outside the window
        // (cutoff = 60000 - 60000 = 0, filter is ts > cutoff, so ts > 0)
        let rate = rt.current_rate(60_000);
        assert_eq!(rate, 0.0);

        // At 59999ms with saturating_sub:
        // cutoff = 59999 - 60000 = 0 (saturates to 0)
        // filter is ts > 0, so request at ts=0 is excluded
        let rate_earlier = rt.current_rate(59_999);
        assert_eq!(rate_earlier, 0.0);

        // Test with a request actually inside the window
        rt.record(1); // request at ts=1
                      // At 60000ms, cutoff = 0, ts=1 > 0 is true
        let rate_with_in_window = rt.current_rate(60_000);
        assert_eq!(rate_with_in_window, 1.0);
    }
}
