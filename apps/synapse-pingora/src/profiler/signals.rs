//! Anomaly signal types and results.
//!
//! Provides types for anomaly detection in request profiling:
//! - Signal types for different anomaly categories
//! - Signal containers with severity and details
//! - Aggregated results for request analysis
//!
//! ## Performance
//! - Signal creation: <100ns
//! - Result aggregation: O(n) where n = number of signals

use serde::{Deserialize, Serialize};

// ============================================================================
// AnomalySignalType - Types of anomalies detected
// ============================================================================

/// Type of anomaly detected in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySignalType {
    /// Payload size significantly above baseline (z-score > 3)
    PayloadSizeHigh,
    /// Payload size suspiciously small for endpoint
    PayloadSizeLow,
    /// Query parameter not seen in baseline
    UnexpectedParam,
    /// Usually-present parameter missing
    MissingExpectedParam,
    /// Parameter value outside learned range
    ParamValueAnomaly,
    /// Content-Type doesn't match baseline
    ContentTypeMismatch,
    /// Request rate burst from this entity
    RateBurst,
    /// Too many parameters
    ParamCountAnomaly,
}

impl AnomalySignalType {
    /// Get the signal type as a string for logging/metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PayloadSizeHigh => "payload_size_high",
            Self::PayloadSizeLow => "payload_size_low",
            Self::UnexpectedParam => "unexpected_param",
            Self::MissingExpectedParam => "missing_expected_param",
            Self::ParamValueAnomaly => "param_value_anomaly",
            Self::ContentTypeMismatch => "content_type_mismatch",
            Self::RateBurst => "rate_burst",
            Self::ParamCountAnomaly => "param_count_anomaly",
        }
    }

    /// Get the default severity for this signal type.
    pub fn default_severity(&self) -> u8 {
        match self {
            Self::PayloadSizeHigh => 5,
            Self::PayloadSizeLow => 2,
            Self::UnexpectedParam => 3,
            Self::MissingExpectedParam => 2,
            Self::ParamValueAnomaly => 4,
            Self::ContentTypeMismatch => 5,
            Self::RateBurst => 6,
            Self::ParamCountAnomaly => 3,
        }
    }
}

// ============================================================================
// AnomalySignal - Individual anomaly signal
// ============================================================================

/// Individual anomaly signal with severity and detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalySignal {
    /// Type of anomaly
    pub signal_type: AnomalySignalType,
    /// Severity (1-10)
    pub severity: u8,
    /// Human-readable detail
    pub detail: String,
}

impl AnomalySignal {
    /// Create a new anomaly signal.
    #[inline]
    pub fn new(signal_type: AnomalySignalType, severity: u8, detail: String) -> Self {
        Self {
            signal_type,
            severity: severity.min(10),
            detail,
        }
    }

    /// Create a signal with default severity for the type.
    #[inline]
    pub fn with_default_severity(signal_type: AnomalySignalType, detail: String) -> Self {
        Self::new(signal_type, signal_type.default_severity(), detail)
    }
}

// ============================================================================
// AnomalyResult - Detection result for a single request
// ============================================================================

/// Result of anomaly detection for a single request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Total anomaly score (-10 to +10, positive = more suspicious)
    pub total_score: f64,
    /// Detected anomaly signals
    pub signals: Vec<AnomalySignal>,
}

impl AnomalyResult {
    /// Create empty result (no anomalies).
    #[inline]
    pub fn none() -> Self {
        Self {
            total_score: 0.0,
            signals: Vec::new(),
        }
    }

    /// Create new result with pre-allocated capacity.
    #[inline]
    pub fn new() -> Self {
        Self {
            total_score: 0.0,
            signals: Vec::with_capacity(4), // Typical max signals
        }
    }

    /// Add an anomaly signal.
    #[inline]
    pub fn add(&mut self, signal_type: AnomalySignalType, severity: u8, detail: String) {
        self.total_score += severity as f64;
        self.signals
            .push(AnomalySignal::new(signal_type, severity, detail));
    }

    /// Add a signal with computed severity.
    #[inline]
    pub fn add_signal(&mut self, signal: AnomalySignal) {
        self.total_score += signal.severity as f64;
        self.signals.push(signal);
    }

    /// Check if any anomalies were detected.
    #[inline]
    pub fn has_anomalies(&self) -> bool {
        !self.signals.is_empty()
    }

    /// Get the number of signals.
    #[inline]
    pub fn signal_count(&self) -> usize {
        self.signals.len()
    }

    /// Clamp and normalize the total score to -10..+10 range.
    pub fn normalize(&mut self) {
        self.total_score = self.total_score.clamp(-10.0, 10.0);
    }

    /// Get the maximum severity among all signals.
    pub fn max_severity(&self) -> u8 {
        self.signals.iter().map(|s| s.severity).max().unwrap_or(0)
    }

    /// Get all signal types present.
    pub fn signal_types(&self) -> Vec<AnomalySignalType> {
        self.signals.iter().map(|s| s.signal_type).collect()
    }

    /// Merge another result into this one.
    pub fn merge(&mut self, other: AnomalyResult) {
        self.total_score += other.total_score;
        self.signals.extend(other.signals);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_signal_type_as_str() {
        assert_eq!(AnomalySignalType::PayloadSizeHigh.as_str(), "payload_size_high");
        assert_eq!(AnomalySignalType::RateBurst.as_str(), "rate_burst");
    }

    #[test]
    fn test_anomaly_signal_creation() {
        let signal = AnomalySignal::new(
            AnomalySignalType::PayloadSizeHigh,
            7,
            "Large payload detected".to_string(),
        );
        assert_eq!(signal.signal_type, AnomalySignalType::PayloadSizeHigh);
        assert_eq!(signal.severity, 7);
    }

    #[test]
    fn test_anomaly_signal_severity_clamped() {
        let signal = AnomalySignal::new(
            AnomalySignalType::RateBurst,
            15, // Over max
            "Test".to_string(),
        );
        assert_eq!(signal.severity, 10); // Clamped to 10
    }

    #[test]
    fn test_anomaly_result_empty() {
        let result = AnomalyResult::none();
        assert!(!result.has_anomalies());
        assert_eq!(result.total_score, 0.0);
        assert_eq!(result.signal_count(), 0);
    }

    #[test]
    fn test_anomaly_result_add() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::UnexpectedParam, 3, "New param".to_string());
        result.add(AnomalySignalType::RateBurst, 6, "High rate".to_string());

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 2);
        assert_eq!(result.total_score, 9.0);
    }

    #[test]
    fn test_anomaly_result_normalize() {
        let mut result = AnomalyResult::new();
        for _ in 0..5 {
            result.add(AnomalySignalType::RateBurst, 6, "Test".to_string());
        }
        assert_eq!(result.total_score, 30.0);

        result.normalize();
        assert_eq!(result.total_score, 10.0);
    }

    #[test]
    fn test_anomaly_result_max_severity() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::PayloadSizeLow, 2, "Small".to_string());
        result.add(AnomalySignalType::RateBurst, 8, "Burst".to_string());
        result.add(AnomalySignalType::UnexpectedParam, 3, "Param".to_string());

        assert_eq!(result.max_severity(), 8);
    }

    #[test]
    fn test_anomaly_result_signal_types() {
        let mut result = AnomalyResult::new();
        result.add(AnomalySignalType::PayloadSizeHigh, 5, "Test".to_string());
        result.add(AnomalySignalType::RateBurst, 6, "Test".to_string());

        let types = result.signal_types();
        assert!(types.contains(&AnomalySignalType::PayloadSizeHigh));
        assert!(types.contains(&AnomalySignalType::RateBurst));
    }

    #[test]
    fn test_anomaly_result_merge() {
        let mut result1 = AnomalyResult::new();
        result1.add(AnomalySignalType::PayloadSizeHigh, 5, "Test1".to_string());

        let mut result2 = AnomalyResult::new();
        result2.add(AnomalySignalType::RateBurst, 6, "Test2".to_string());

        result1.merge(result2);

        assert_eq!(result1.signal_count(), 2);
        assert_eq!(result1.total_score, 11.0);
    }

    #[test]
    fn test_default_severity() {
        assert_eq!(AnomalySignalType::PayloadSizeHigh.default_severity(), 5);
        assert_eq!(AnomalySignalType::RateBurst.default_severity(), 6);
        assert_eq!(AnomalySignalType::PayloadSizeLow.default_severity(), 2);
    }

    #[test]
    fn test_signal_with_default_severity() {
        let signal = AnomalySignal::with_default_severity(
            AnomalySignalType::RateBurst,
            "Test burst".to_string(),
        );
        assert_eq!(signal.severity, 6);
    }
}
