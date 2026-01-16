//! Online statistics using Welford's algorithm and P-square percentiles.
//!
//! Provides streaming statistical analysis without storing all samples:
//! - Mean and variance tracking via Welford's algorithm
//! - Approximate percentiles (p50, p95, p99) via P-square algorithm
//!
//! ## Performance
//! - Update: O(1) time and space
//! - Z-score calculation: O(1)
//! - Memory: ~130 bytes per Distribution

use serde::{Deserialize, Serialize};

// ============================================================================
// PercentilesTracker - P-square algorithm for streaming percentiles
// ============================================================================

/// P-square algorithm for dynamic percentile estimation.
///
/// Maintains 5 markers for min, p50, p95, p99, max with O(1) updates.
/// Memory: ~56 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PercentilesTracker {
    /// Marker heights (actual values)
    q: [f64; 5],
    /// Marker positions (counts)
    n: [f64; 5],
    /// Desired marker positions
    n_prime: [f64; 5],
    /// Initialization buffer (first 5 samples)
    init_count: u8,
    init_buffer: [f64; 5],
}

impl Default for PercentilesTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PercentilesTracker {
    /// Create a new tracker for p50, p95, p99.
    ///
    /// Increments for desired positions are constants: 0, 0.5, 0.95, 0.99, 1.0
    /// These are used inline in the update method rather than stored.
    pub fn new() -> Self {
        Self {
            q: [0.0; 5],
            n: [1.0, 2.0, 3.0, 4.0, 5.0],
            // Desired positions for min, p50, p95, p99, max
            n_prime: [1.0, 2.0, 3.0, 4.0, 5.0],
            init_count: 0,
            init_buffer: [0.0; 5],
        }
    }

    /// Update with a new sample.
    #[inline]
    pub fn update(&mut self, value: f64) {
        // Initialization phase: collect first 5 samples
        if self.init_count < 5 {
            self.init_buffer[self.init_count as usize] = value;
            self.init_count += 1;
            if self.init_count == 5 {
                // Sort and initialize markers
                self.init_buffer.sort_by(|a, b| a.partial_cmp(b).unwrap());
                self.q = self.init_buffer;
            }
            return;
        }

        // Find cell k where value belongs
        let k = if value < self.q[0] {
            self.q[0] = value;
            0
        } else if value < self.q[1] {
            0
        } else if value < self.q[2] {
            1
        } else if value < self.q[3] {
            2
        } else if value < self.q[4] {
            3
        } else {
            self.q[4] = value;
            3
        };

        // Increment positions for markers > k
        for i in (k + 1)..5 {
            self.n[i] += 1.0;
        }

        // Update desired positions
        let total = self.n[4];
        self.n_prime[1] = 1.0 + 0.5 * total;
        self.n_prime[2] = 1.0 + 0.95 * total;
        self.n_prime[3] = 1.0 + 0.99 * total;
        self.n_prime[4] = total;

        // Adjust marker heights if needed (P-square adjustment)
        for i in 1..4 {
            let d = self.n_prime[i] - self.n[i];
            if (d >= 1.0 && self.n[i + 1] - self.n[i] > 1.0)
                || (d <= -1.0 && self.n[i - 1] - self.n[i] < -1.0)
            {
                let d_sign = if d >= 0.0 { 1.0 } else { -1.0 };
                // Parabolic adjustment
                let qi = self.q[i];
                let qip1 = self.q[i + 1];
                let qim1 = self.q[i - 1];
                let ni = self.n[i];
                let nip1 = self.n[i + 1];
                let nim1 = self.n[i - 1];

                let q_new = qi
                    + d_sign / (nip1 - nim1)
                        * ((ni - nim1 + d_sign) * (qip1 - qi) / (nip1 - ni)
                            + (nip1 - ni - d_sign) * (qi - qim1) / (ni - nim1));

                // Check bounds and use linear if parabolic fails
                if qim1 < q_new && q_new < qip1 {
                    self.q[i] = q_new;
                } else {
                    // Linear adjustment
                    let idx = if d_sign >= 0.0 { i + 1 } else { i - 1 };
                    self.q[i] = qi + d_sign * (self.q[idx] - qi) / (self.n[idx] - ni);
                }
                self.n[i] += d_sign;
            }
        }
    }

    /// Get percentiles (p50, p95, p99).
    #[inline]
    pub fn get(&self) -> (f64, f64, f64) {
        if self.init_count < 5 {
            // Not enough data
            return (0.0, 0.0, 0.0);
        }
        (self.q[1], self.q[2], self.q[3])
    }

    /// Get minimum value seen.
    #[inline]
    pub fn min(&self) -> f64 {
        if self.init_count < 5 {
            return 0.0;
        }
        self.q[0]
    }

    /// Get maximum value seen.
    #[inline]
    pub fn max(&self) -> f64 {
        if self.init_count < 5 {
            return 0.0;
        }
        self.q[4]
    }

    /// Check if tracker has enough data for meaningful percentiles.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.init_count >= 5
    }
}

// ============================================================================
// Distribution - Online statistics with Welford's algorithm
// ============================================================================

/// Online statistics calculator using Welford's algorithm.
///
/// Tracks mean, variance, and approximate percentiles without storing all samples.
/// Memory: ~130 bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Distribution {
    /// Sample count
    count: u32,
    /// Running mean
    mean: f64,
    /// Running M2 (sum of squared differences from mean)
    /// Variance = M2 / count
    m2: f64,
    /// Approximate percentiles using P-square algorithm
    percentiles: PercentilesTracker,
}

impl Default for Distribution {
    fn default() -> Self {
        Self::new()
    }
}

impl Distribution {
    /// Create a new empty distribution.
    #[inline]
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
            percentiles: PercentilesTracker::new(),
        }
    }

    /// Add a sample using Welford's online algorithm.
    /// O(1) time and space.
    #[inline]
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        self.percentiles.update(value);
    }

    /// Get sample count.
    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Get the mean.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Compute standard deviation.
    #[inline]
    pub fn stddev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / self.count as f64).sqrt()
    }

    /// Compute variance.
    #[inline]
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        self.m2 / self.count as f64
    }

    /// Calculate z-score for a value.
    /// Returns how many standard deviations from the mean.
    #[inline]
    pub fn z_score(&self, value: f64) -> f64 {
        let std = self.stddev();
        if std < 0.01 {
            // Avoid division by zero or near-zero
            return 0.0;
        }
        (value - self.mean) / std
    }

    /// Get approximate percentiles (p50, p95, p99).
    #[inline]
    pub fn percentiles(&self) -> (f64, f64, f64) {
        self.percentiles.get()
    }

    /// Get minimum value seen.
    #[inline]
    pub fn min(&self) -> f64 {
        self.percentiles.min()
    }

    /// Get maximum value seen.
    #[inline]
    pub fn max(&self) -> f64 {
        self.percentiles.max()
    }

    /// Check if distribution has enough data for statistical analysis.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.count >= 5
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distribution_welford() {
        let mut d = Distribution::new();
        for v in [10.0, 20.0, 30.0, 40.0, 50.0] {
            d.update(v);
        }
        assert!((d.mean() - 30.0).abs() < 0.01);
        // Population stddev of [10,20,30,40,50] is ~14.14
        assert!((d.stddev() - 14.14).abs() < 0.5);
    }

    #[test]
    fn test_distribution_z_score() {
        let mut d = Distribution::new();
        // Create distribution with mean=100, stddev≈10
        for v in [90.0, 95.0, 100.0, 105.0, 110.0] {
            d.update(v);
        }

        // Value at mean should have z-score ~0
        assert!(d.z_score(100.0).abs() < 0.1);

        // Value 2 stddev above mean
        let z = d.z_score(100.0 + 2.0 * d.stddev());
        assert!((z - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_distribution_empty() {
        let d = Distribution::new();
        assert_eq!(d.count(), 0);
        assert_eq!(d.mean(), 0.0);
        assert_eq!(d.stddev(), 0.0);
        assert_eq!(d.variance(), 0.0);
        assert!(!d.is_valid());
    }

    #[test]
    fn test_distribution_single_value() {
        let mut d = Distribution::new();
        d.update(42.0);
        assert_eq!(d.count(), 1);
        assert_eq!(d.mean(), 42.0);
        assert_eq!(d.stddev(), 0.0); // Need 2+ samples for stddev
    }

    #[test]
    fn test_distribution_variance() {
        let mut d = Distribution::new();
        // Uniform distribution from 0 to 10: variance = (10-0)^2 / 12 ≈ 8.33
        for v in [0.0, 2.0, 4.0, 6.0, 8.0, 10.0] {
            d.update(v);
        }
        // Mean should be 5.0
        assert!((d.mean() - 5.0).abs() < 0.01);
        // Variance should be roughly 11.67 (sample variance)
        assert!(d.variance() > 0.0);
    }

    #[test]
    fn test_percentiles_tracker() {
        let mut pt = PercentilesTracker::new();

        // Add 100 samples (1 to 100)
        for i in 1..=100 {
            pt.update(i as f64);
        }

        let (p50, p95, p99) = pt.get();

        // p50 should be around 50
        assert!((p50 - 50.0).abs() < 5.0);
        // p95 should be around 95
        assert!((p95 - 95.0).abs() < 5.0);
        // p99 should be around 99
        assert!((p99 - 99.0).abs() < 3.0);
    }

    #[test]
    fn test_percentiles_tracker_not_initialized() {
        let mut pt = PercentilesTracker::new();
        assert!(!pt.is_initialized());

        pt.update(1.0);
        pt.update(2.0);
        assert!(!pt.is_initialized());

        let (p50, p95, p99) = pt.get();
        assert_eq!(p50, 0.0);
        assert_eq!(p95, 0.0);
        assert_eq!(p99, 0.0);
    }

    #[test]
    fn test_percentiles_tracker_min_max() {
        let mut pt = PercentilesTracker::new();
        for i in 1..=10 {
            pt.update(i as f64);
        }

        assert_eq!(pt.min(), 1.0);
        assert_eq!(pt.max(), 10.0);
    }

    #[test]
    fn test_distribution_z_score_edge_cases() {
        let mut d = Distribution::new();
        // All same values - stddev is 0
        for _ in 0..10 {
            d.update(50.0);
        }

        // Z-score should be 0 when stddev is 0 (avoids division by zero)
        assert_eq!(d.z_score(100.0), 0.0);
    }

    #[test]
    fn test_distribution_negative_values() {
        let mut d = Distribution::new();
        for v in [-10.0, -5.0, 0.0, 5.0, 10.0] {
            d.update(v);
        }
        assert!((d.mean() - 0.0).abs() < 0.01);
        assert!(d.stddev() > 0.0);
    }

    #[test]
    fn test_distribution_large_values() {
        let mut d = Distribution::new();
        for v in [1e9, 1e9 + 1.0, 1e9 + 2.0, 1e9 + 3.0, 1e9 + 4.0] {
            d.update(v);
        }
        assert!((d.mean() - (1e9 + 2.0)).abs() < 0.01);
    }

    #[test]
    fn test_percentiles_with_outliers() {
        let mut pt = PercentilesTracker::new();

        // Add normal values
        for i in 1..=95 {
            pt.update(i as f64);
        }
        // Add outliers
        for _ in 0..5 {
            pt.update(1000.0);
        }

        let (p50, p95, p99) = pt.get();

        // p50 should still be around 50 (median is robust to outliers)
        assert!((p50 - 50.0).abs() < 10.0);
    }
}
