//! Header anomaly types and results.
//!
//! Provides types for header-based anomaly detection:
//! - Anomaly types for different header deviations
//! - Value statistics for learning baseline patterns
//! - Per-endpoint header baselines
//!
//! ## Memory Budget
//! - HeaderBaseline: ~1-2KB per endpoint (depends on header count)
//! - ValueStats: ~48 bytes per header

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ============================================================================
// HeaderAnomaly - Types of header anomalies
// ============================================================================

/// Type of header anomaly detected in a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HeaderAnomaly {
    /// A required header (seen in >95% of baseline) is missing
    MissingRequired {
        /// The missing header name
        header: String,
    },

    /// An unexpected header not seen in baseline is present
    UnexpectedHeader {
        /// The unexpected header name
        header: String,
    },

    /// Header value is anomalous (unusual pattern)
    AnomalousValue {
        /// The header name
        header: String,
        /// The anomalous value
        value: String,
        /// Reason for flagging as anomalous
        reason: String,
    },

    /// Header value entropy is anomalous (too high or too low)
    EntropyAnomaly {
        /// The header name
        header: String,
        /// The observed entropy
        entropy: f64,
        /// The expected mean entropy
        expected_mean: f64,
    },

    /// Header value length is outside expected range
    LengthAnomaly {
        /// The header name
        header: String,
        /// The observed length
        length: usize,
        /// The expected (min, max) range
        expected_range: (usize, usize),
    },
}

impl HeaderAnomaly {
    /// Get the header name associated with this anomaly.
    pub fn header(&self) -> &str {
        match self {
            Self::MissingRequired { header } => header,
            Self::UnexpectedHeader { header } => header,
            Self::AnomalousValue { header, .. } => header,
            Self::EntropyAnomaly { header, .. } => header,
            Self::LengthAnomaly { header, .. } => header,
        }
    }

    /// Get the base risk score for this anomaly type.
    pub fn base_risk(&self) -> u16 {
        match self {
            Self::MissingRequired { .. } => 10,
            Self::UnexpectedHeader { .. } => 5,
            Self::AnomalousValue { .. } => 15,
            Self::EntropyAnomaly { .. } => 20,
            Self::LengthAnomaly { .. } => 10,
        }
    }

    /// Get a human-readable description of this anomaly.
    pub fn description(&self) -> String {
        match self {
            Self::MissingRequired { header } => {
                format!("Required header '{}' is missing", header)
            }
            Self::UnexpectedHeader { header } => {
                format!("Unexpected header '{}' not seen in baseline", header)
            }
            Self::AnomalousValue { header, reason, .. } => {
                format!("Header '{}' has anomalous value: {}", header, reason)
            }
            Self::EntropyAnomaly {
                header,
                entropy,
                expected_mean,
            } => {
                format!(
                    "Header '{}' entropy {:.2} deviates from expected {:.2}",
                    header, entropy, expected_mean
                )
            }
            Self::LengthAnomaly {
                header,
                length,
                expected_range,
            } => {
                format!(
                    "Header '{}' length {} outside expected range [{}, {}]",
                    header, length, expected_range.0, expected_range.1
                )
            }
        }
    }
}

// ============================================================================
// HeaderAnomalyResult - Aggregated anomaly detection result
// ============================================================================

/// Result of header anomaly analysis for a request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeaderAnomalyResult {
    /// List of detected anomalies
    pub anomalies: Vec<HeaderAnomaly>,

    /// Total additional risk score contribution (0-50)
    pub risk_contribution: u16,
}

impl HeaderAnomalyResult {
    /// Create an empty result (no anomalies).
    #[inline]
    pub fn none() -> Self {
        Self {
            anomalies: Vec::new(),
            risk_contribution: 0,
        }
    }

    /// Create a new result with pre-allocated capacity.
    #[inline]
    pub fn new() -> Self {
        Self {
            anomalies: Vec::with_capacity(4),
            risk_contribution: 0,
        }
    }

    /// Add an anomaly and update risk score.
    #[inline]
    pub fn add(&mut self, anomaly: HeaderAnomaly) {
        self.risk_contribution = self
            .risk_contribution
            .saturating_add(anomaly.base_risk())
            .min(50);
        self.anomalies.push(anomaly);
    }

    /// Check if any anomalies were detected.
    #[inline]
    pub fn has_anomalies(&self) -> bool {
        !self.anomalies.is_empty()
    }

    /// Get the number of anomalies.
    #[inline]
    pub fn count(&self) -> usize {
        self.anomalies.len()
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: HeaderAnomalyResult) {
        for anomaly in other.anomalies {
            self.add(anomaly);
        }
    }
}

// ============================================================================
// ValueStats - Per-header value statistics
// ============================================================================

/// Statistics for a single header's values.
///
/// Uses Welford's algorithm for online mean/variance calculation.
/// Memory: ~48 bytes per header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueStats {
    /// Minimum value length seen
    pub min_length: usize,

    /// Maximum value length seen
    pub max_length: usize,

    /// Running mean of Shannon entropy
    pub entropy_mean: f64,

    /// Running variance of Shannon entropy (using Welford's algorithm)
    pub entropy_variance: f64,

    /// Running M2 for Welford's algorithm (sum of squared differences)
    entropy_m2: f64,

    /// Total samples seen for this header
    pub total_samples: u64,
}

impl ValueStats {
    /// Create new empty value statistics.
    pub fn new() -> Self {
        Self {
            min_length: usize::MAX,
            max_length: 0,
            entropy_mean: 0.0,
            entropy_variance: 0.0,
            entropy_m2: 0.0,
            total_samples: 0,
        }
    }

    /// Update statistics with a new value.
    ///
    /// # Arguments
    /// * `length` - The length of the value
    /// * `entropy` - The Shannon entropy of the value
    #[inline]
    pub fn update(&mut self, length: usize, entropy: f64) {
        // Update length bounds
        self.min_length = self.min_length.min(length);
        self.max_length = self.max_length.max(length);

        // Update entropy statistics using Welford's algorithm
        self.total_samples += 1;
        let delta = entropy - self.entropy_mean;
        self.entropy_mean += delta / self.total_samples as f64;
        let delta2 = entropy - self.entropy_mean;
        self.entropy_m2 += delta * delta2;

        // Recalculate variance
        if self.total_samples >= 2 {
            self.entropy_variance = self.entropy_m2 / self.total_samples as f64;
        }
    }

    /// Get the standard deviation of entropy.
    #[inline]
    pub fn entropy_stddev(&self) -> f64 {
        self.entropy_variance.sqrt()
    }

    /// Check if statistics have enough samples for anomaly detection.
    #[inline]
    pub fn is_mature(&self, min_samples: u64) -> bool {
        self.total_samples >= min_samples
    }

    /// Check if a length is within the expected range (with some tolerance).
    ///
    /// # Arguments
    /// * `length` - The length to check
    /// * `tolerance_factor` - How much to extend the range (e.g., 1.5 = 50% tolerance)
    #[inline]
    pub fn is_length_in_range(&self, length: usize, tolerance_factor: f64) -> bool {
        if self.total_samples == 0 {
            return true; // No baseline yet
        }

        let range = (self.max_length - self.min_length) as f64;
        let tolerance = (range * tolerance_factor).max(10.0) as usize;

        length >= self.min_length.saturating_sub(tolerance)
            && length <= self.max_length.saturating_add(tolerance)
    }

    /// Calculate z-score for an entropy value.
    #[inline]
    pub fn entropy_z_score(&self, entropy: f64) -> f64 {
        if self.entropy_variance <= 0.001 || self.total_samples < 5 {
            return 0.0;
        }
        (entropy - self.entropy_mean) / self.entropy_stddev()
    }
}

impl Default for ValueStats {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// HeaderBaseline - Per-endpoint header baseline
// ============================================================================

/// Learned baseline for headers on a specific endpoint.
///
/// Tracks which headers are required/optional and their value patterns.
/// Memory: ~1-2KB per endpoint (varies with header count)
#[derive(Debug, Clone)]
pub struct HeaderBaseline {
    /// The endpoint path/template
    pub endpoint: String,

    /// Headers seen in >95% of requests (considered required)
    pub required_headers: HashSet<String>,

    /// Headers seen in <95% of requests (considered optional)
    pub optional_headers: HashSet<String>,

    /// Value statistics per header
    pub header_value_stats: HashMap<String, ValueStats>,

    /// Total sample count for this endpoint
    pub sample_count: u64,

    /// Last time this baseline was updated
    pub last_updated: Instant,
}

impl HeaderBaseline {
    /// Create a new empty baseline for an endpoint.
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            required_headers: HashSet::with_capacity(16),
            optional_headers: HashSet::with_capacity(16),
            header_value_stats: HashMap::with_capacity(16),
            sample_count: 0,
            last_updated: Instant::now(),
        }
    }

    /// Check if baseline has enough samples for anomaly detection.
    #[inline]
    pub fn is_mature(&self, min_samples: u64) -> bool {
        self.sample_count >= min_samples
    }

    /// Get value stats for a header, if available.
    #[inline]
    pub fn get_stats(&self, header: &str) -> Option<&ValueStats> {
        self.header_value_stats.get(header)
    }

    /// Check if a header is considered required (>95% frequency).
    #[inline]
    pub fn is_required(&self, header: &str) -> bool {
        self.required_headers.contains(header)
    }

    /// Check if a header has been seen before (required or optional).
    #[inline]
    pub fn is_known(&self, header: &str) -> bool {
        self.required_headers.contains(header) || self.optional_headers.contains(header)
    }

    /// Get the frequency of a header (0.0 to 1.0).
    pub fn header_frequency(&self, header: &str) -> f64 {
        if self.sample_count == 0 {
            return 0.0;
        }

        self.header_value_stats
            .get(header)
            .map(|stats| stats.total_samples as f64 / self.sample_count as f64)
            .unwrap_or(0.0)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // HeaderAnomaly tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_header_anomaly_header() {
        let missing = HeaderAnomaly::MissingRequired {
            header: "Authorization".to_string(),
        };
        assert_eq!(missing.header(), "Authorization");

        let unexpected = HeaderAnomaly::UnexpectedHeader {
            header: "X-Evil".to_string(),
        };
        assert_eq!(unexpected.header(), "X-Evil");
    }

    #[test]
    fn test_header_anomaly_base_risk() {
        assert_eq!(
            HeaderAnomaly::MissingRequired {
                header: "Auth".to_string()
            }
            .base_risk(),
            10
        );
        assert_eq!(
            HeaderAnomaly::UnexpectedHeader {
                header: "X".to_string()
            }
            .base_risk(),
            5
        );
        assert_eq!(
            HeaderAnomaly::AnomalousValue {
                header: "X".to_string(),
                value: "bad".to_string(),
                reason: "test".to_string()
            }
            .base_risk(),
            15
        );
        assert_eq!(
            HeaderAnomaly::EntropyAnomaly {
                header: "X".to_string(),
                entropy: 7.5,
                expected_mean: 4.0
            }
            .base_risk(),
            20
        );
        assert_eq!(
            HeaderAnomaly::LengthAnomaly {
                header: "X".to_string(),
                length: 1000,
                expected_range: (10, 50)
            }
            .base_risk(),
            10
        );
    }

    #[test]
    fn test_header_anomaly_description() {
        let anomaly = HeaderAnomaly::MissingRequired {
            header: "Content-Type".to_string(),
        };
        let desc = anomaly.description();
        assert!(desc.contains("Content-Type"));
        assert!(desc.contains("missing"));
    }

    // ------------------------------------------------------------------------
    // HeaderAnomalyResult tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_anomaly_result_empty() {
        let result = HeaderAnomalyResult::none();
        assert!(!result.has_anomalies());
        assert_eq!(result.count(), 0);
        assert_eq!(result.risk_contribution, 0);
    }

    #[test]
    fn test_anomaly_result_add() {
        let mut result = HeaderAnomalyResult::new();

        result.add(HeaderAnomaly::MissingRequired {
            header: "Auth".to_string(),
        });
        assert_eq!(result.count(), 1);
        assert_eq!(result.risk_contribution, 10);

        result.add(HeaderAnomaly::EntropyAnomaly {
            header: "Token".to_string(),
            entropy: 7.5,
            expected_mean: 4.0,
        });
        assert_eq!(result.count(), 2);
        assert_eq!(result.risk_contribution, 30);
    }

    #[test]
    fn test_anomaly_result_risk_capped() {
        let mut result = HeaderAnomalyResult::new();

        // Add many high-risk anomalies
        for i in 0..10 {
            result.add(HeaderAnomaly::EntropyAnomaly {
                header: format!("Header-{}", i),
                entropy: 7.5,
                expected_mean: 4.0,
            });
        }

        // Risk should be capped at 50
        assert_eq!(result.risk_contribution, 50);
    }

    #[test]
    fn test_anomaly_result_merge() {
        let mut result1 = HeaderAnomalyResult::new();
        result1.add(HeaderAnomaly::MissingRequired {
            header: "A".to_string(),
        });

        let mut result2 = HeaderAnomalyResult::new();
        result2.add(HeaderAnomaly::UnexpectedHeader {
            header: "B".to_string(),
        });

        result1.merge(result2);
        assert_eq!(result1.count(), 2);
        assert_eq!(result1.risk_contribution, 15); // 10 + 5
    }

    // ------------------------------------------------------------------------
    // ValueStats tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_value_stats_new() {
        let stats = ValueStats::new();
        assert_eq!(stats.min_length, usize::MAX);
        assert_eq!(stats.max_length, 0);
        assert_eq!(stats.entropy_mean, 0.0);
        assert_eq!(stats.total_samples, 0);
    }

    #[test]
    fn test_value_stats_update() {
        let mut stats = ValueStats::new();

        stats.update(10, 4.0);
        assert_eq!(stats.min_length, 10);
        assert_eq!(stats.max_length, 10);
        assert_eq!(stats.total_samples, 1);
        assert!((stats.entropy_mean - 4.0).abs() < 0.001);

        stats.update(20, 5.0);
        assert_eq!(stats.min_length, 10);
        assert_eq!(stats.max_length, 20);
        assert_eq!(stats.total_samples, 2);
        assert!((stats.entropy_mean - 4.5).abs() < 0.001);
    }

    #[test]
    fn test_value_stats_is_mature() {
        let mut stats = ValueStats::new();
        assert!(!stats.is_mature(10));

        for _ in 0..10 {
            stats.update(10, 4.0);
        }
        assert!(stats.is_mature(10));
        assert!(!stats.is_mature(20));
    }

    #[test]
    fn test_value_stats_is_length_in_range() {
        let mut stats = ValueStats::new();

        // No samples yet - everything is in range
        assert!(stats.is_length_in_range(100, 1.5));

        // Add samples with lengths 10-50
        for len in [10, 20, 30, 40, 50] {
            stats.update(len, 4.0);
        }

        // Within range
        assert!(stats.is_length_in_range(30, 1.5));

        // Within tolerance
        assert!(stats.is_length_in_range(5, 1.5));
        assert!(stats.is_length_in_range(60, 1.5));

        // Outside tolerance (assuming tolerance is ~30 with 1.5 factor)
        // Actually with max 10 tolerance, 0 might still be out
    }

    #[test]
    fn test_value_stats_entropy_z_score() {
        let mut stats = ValueStats::new();

        // Not enough samples
        assert_eq!(stats.entropy_z_score(7.0), 0.0);

        // Add samples with varying entropy
        for entropy in [3.5, 4.0, 4.5, 4.0, 4.0] {
            stats.update(10, entropy);
        }

        // At mean should be ~0
        let z = stats.entropy_z_score(stats.entropy_mean);
        assert!(z.abs() < 0.1);

        // Above mean should be positive
        let z = stats.entropy_z_score(stats.entropy_mean + stats.entropy_stddev());
        assert!(z > 0.9 && z < 1.1);
    }

    // ------------------------------------------------------------------------
    // HeaderBaseline tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_header_baseline_new() {
        let baseline = HeaderBaseline::new("/api/users".to_string());
        assert_eq!(baseline.endpoint, "/api/users");
        assert_eq!(baseline.sample_count, 0);
        assert!(baseline.required_headers.is_empty());
        assert!(baseline.optional_headers.is_empty());
    }

    #[test]
    fn test_header_baseline_is_mature() {
        let mut baseline = HeaderBaseline::new("/test".to_string());
        assert!(!baseline.is_mature(10));

        baseline.sample_count = 10;
        assert!(baseline.is_mature(10));
    }

    #[test]
    fn test_header_baseline_is_known() {
        let mut baseline = HeaderBaseline::new("/test".to_string());

        baseline.required_headers.insert("Content-Type".to_string());
        baseline.optional_headers.insert("X-Request-ID".to_string());

        assert!(baseline.is_required("Content-Type"));
        assert!(!baseline.is_required("X-Request-ID"));

        assert!(baseline.is_known("Content-Type"));
        assert!(baseline.is_known("X-Request-ID"));
        assert!(!baseline.is_known("X-Unknown"));
    }

    #[test]
    fn test_header_baseline_header_frequency() {
        let mut baseline = HeaderBaseline::new("/test".to_string());
        baseline.sample_count = 100;

        let mut stats = ValueStats::new();
        for _ in 0..95 {
            stats.update(10, 4.0);
        }
        baseline
            .header_value_stats
            .insert("Content-Type".to_string(), stats);

        let freq = baseline.header_frequency("Content-Type");
        assert!((freq - 0.95).abs() < 0.01);

        // Unknown header
        assert_eq!(baseline.header_frequency("Unknown"), 0.0);
    }
}
