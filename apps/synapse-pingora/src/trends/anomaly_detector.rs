//! Anomaly detection for signal patterns.

use std::collections::{HashMap, HashSet};

use super::time_store::SignalBucket;
use super::types::{
    Anomaly, AnomalyMetadata, AnomalySeverity, AnomalyType, Signal, SignalCategory, SignalType,
};

/// Configuration for anomaly detection.
#[derive(Debug, Clone)]
pub struct AnomalyDetectorConfig {
    /// Minimum IP count for session sharing detection
    pub session_sharing_min_ips: usize,
    /// Velocity spike threshold multiplier
    pub velocity_spike_threshold: f64,
    /// Minimum unique values for rotation detection
    pub rotation_min_changes: usize,
    /// Time window for timing anomaly (ms)
    pub timing_anomaly_window_ms: i64,
    /// Minimum requests for timing analysis
    pub timing_anomaly_min_requests: usize,
}

impl Default for AnomalyDetectorConfig {
    fn default() -> Self {
        Self {
            session_sharing_min_ips: 3,
            velocity_spike_threshold: 3.0,
            rotation_min_changes: 5,
            timing_anomaly_window_ms: 60_000,
            timing_anomaly_min_requests: 10,
        }
    }
}

/// Anomaly detector for signal patterns.
pub struct AnomalyDetector {
    config: AnomalyDetectorConfig,
    risk_scores: HashMap<AnomalyType, u32>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector.
    pub fn new(risk_scores: HashMap<AnomalyType, u32>) -> Self {
        Self {
            config: AnomalyDetectorConfig::default(),
            risk_scores,
        }
    }

    /// Create with custom configuration.
    pub fn with_config(
        config: AnomalyDetectorConfig,
        risk_scores: HashMap<AnomalyType, u32>,
    ) -> Self {
        Self {
            config,
            risk_scores,
        }
    }

    /// Check a single signal for anomalies against recent history.
    pub fn check_signal(&self, signal: &Signal, recent_signals: &[Signal]) -> Option<Anomaly> {
        match signal.category {
            SignalCategory::AuthToken => self.check_auth_anomaly(signal, recent_signals),
            SignalCategory::Network => self.check_network_anomaly(signal, recent_signals),
            SignalCategory::Device => self.check_device_anomaly(signal, recent_signals),
            SignalCategory::Behavioral => self.check_behavioral_anomaly(signal, recent_signals),
        }
    }

    /// Detect batch anomalies across buckets.
    pub fn detect_batch_anomalies(
        &self,
        current: &SignalBucket,
        historical: &[&SignalBucket],
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Velocity spike detection
        if let Some(anomaly) = self.detect_velocity_spike(current, historical) {
            anomalies.push(anomaly);
        }

        // Session sharing detection
        anomalies.extend(self.detect_session_sharing(&current.signals));

        // JA4 cluster detection
        anomalies.extend(self.detect_ja4_clusters(&current.signals));

        // Rotation pattern detection
        anomalies.extend(self.detect_rotation_patterns(&current.signals, historical));

        anomalies
    }

    /// Check for auth token anomalies.
    fn check_auth_anomaly(&self, signal: &Signal, recent: &[Signal]) -> Option<Anomaly> {
        // Check for token reuse with different fingerprints
        let same_token_signals: Vec<_> = recent
            .iter()
            .filter(|s| s.signal_type == signal.signal_type && s.value == signal.value)
            .collect();

        if same_token_signals.len() >= 2 {
            let entities: HashSet<String> = same_token_signals
                .iter()
                .map(|s| s.entity_id.clone())
                .collect();
            let entity_count = entities.len();
            if entity_count >= self.config.session_sharing_min_ips {
                return Some(self.create_anomaly(
                    AnomalyType::SessionSharing,
                    AnomalySeverity::High,
                    format!("Auth token used from {} different IPs", entity_count),
                    signal.category,
                    same_token_signals.into_iter().cloned().collect(),
                    entities.into_iter().collect(),
                    AnomalyMetadata {
                        ip_count: Some(entity_count),
                        ..Default::default()
                    },
                ));
            }
        }

        None
    }

    /// Check for network anomalies.
    fn check_network_anomaly(&self, signal: &Signal, recent: &[Signal]) -> Option<Anomaly> {
        // Check for JA4 fingerprint change
        if signal.signal_type == SignalType::Ja4 {
            let previous_ja4: Vec<_> = recent
                .iter()
                .filter(|s| {
                    s.signal_type == SignalType::Ja4
                        && s.entity_id == signal.entity_id
                        && s.value != signal.value
                })
                .collect();

            if !previous_ja4.is_empty() {
                let prev = previous_ja4[0];
                return Some(self.create_anomaly(
                    AnomalyType::Ja4hChange,
                    AnomalySeverity::Medium,
                    format!(
                        "JA4 fingerprint changed from {} to {}",
                        &prev.value[..8.min(prev.value.len())],
                        &signal.value[..8.min(signal.value.len())]
                    ),
                    SignalCategory::Network,
                    vec![prev.clone(), signal.clone()],
                    vec![signal.entity_id.clone()],
                    AnomalyMetadata {
                        previous_value: Some(prev.value.clone()),
                        new_value: Some(signal.value.clone()),
                        ..Default::default()
                    },
                ));
            }
        }

        None
    }

    /// Check for device anomalies.
    fn check_device_anomaly(&self, signal: &Signal, recent: &[Signal]) -> Option<Anomaly> {
        // Check for fingerprint change within session
        if let Some(ref session_id) = signal.session_id {
            let session_fingerprints: Vec<_> = recent
                .iter()
                .filter(|s| {
                    s.session_id.as_ref() == Some(session_id)
                        && s.signal_type == SignalType::HttpFingerprint
                })
                .collect();

            let unique_fps: HashSet<_> = session_fingerprints.iter().map(|s| &s.value).collect();

            if unique_fps.len() >= 2 {
                return Some(self.create_anomaly(
                    AnomalyType::FingerprintChange,
                    AnomalySeverity::Medium,
                    format!(
                        "HTTP fingerprint changed within session (now {} variants)",
                        unique_fps.len()
                    ),
                    SignalCategory::Device,
                    session_fingerprints.into_iter().cloned().collect(),
                    vec![signal.entity_id.clone()],
                    AnomalyMetadata {
                        change_count: Some(unique_fps.len()),
                        ..Default::default()
                    },
                ));
            }
        }

        None
    }

    /// Check for behavioral anomalies.
    fn check_behavioral_anomaly(&self, signal: &Signal, recent: &[Signal]) -> Option<Anomaly> {
        if signal.signal_type != SignalType::Timing {
            return None;
        }

        // Check for timing anomalies (suspiciously regular intervals)
        let timing_signals: Vec<_> = recent
            .iter()
            .filter(|s| s.signal_type == SignalType::Timing && s.entity_id == signal.entity_id)
            .collect();

        if timing_signals.len() < self.config.timing_anomaly_min_requests {
            return None;
        }

        // Calculate variance in timing
        // (simplified check - real implementation would be more sophisticated)
        let mut intervals = Vec::new();
        for i in 1..timing_signals.len() {
            let delta = timing_signals[i].timestamp - timing_signals[i - 1].timestamp;
            intervals.push(delta);
        }

        if intervals.is_empty() {
            return None;
        }

        let mean = intervals.iter().sum::<i64>() as f64 / intervals.len() as f64;
        let variance = intervals
            .iter()
            .map(|&i| (i as f64 - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;

        // Very low variance indicates bot-like regular intervals
        if variance < 100.0 && mean < 1000.0 {
            return Some(self.create_anomaly(
                AnomalyType::TimingAnomaly,
                AnomalySeverity::Low,
                format!(
                    "Suspiciously regular request timing (mean: {:.0}ms, variance: {:.0})",
                    mean, variance
                ),
                SignalCategory::Behavioral,
                timing_signals.into_iter().cloned().collect(),
                vec![signal.entity_id.clone()],
                AnomalyMetadata {
                    threshold: Some(100.0),
                    actual: Some(variance),
                    ..Default::default()
                },
            ));
        }

        None
    }

    /// Detect velocity spikes.
    fn detect_velocity_spike(
        &self,
        current: &SignalBucket,
        historical: &[&SignalBucket],
    ) -> Option<Anomaly> {
        if historical.is_empty() {
            return None;
        }

        let current_count = current.summary.total_count;
        let historical_avg: f64 = historical
            .iter()
            .map(|b| b.summary.total_count as f64)
            .sum::<f64>()
            / historical.len() as f64;

        if historical_avg == 0.0 {
            return None;
        }

        let spike_ratio = current_count as f64 / historical_avg;

        if spike_ratio >= self.config.velocity_spike_threshold {
            return Some(self.create_anomaly(
                AnomalyType::VelocitySpike,
                AnomalySeverity::Medium,
                format!(
                    "Signal velocity spike: {:.1}x baseline ({} vs avg {:.0})",
                    spike_ratio, current_count, historical_avg
                ),
                SignalCategory::Behavioral,
                Vec::new(),
                Vec::new(),
                AnomalyMetadata {
                    threshold: Some(self.config.velocity_spike_threshold),
                    actual: Some(spike_ratio),
                    ..Default::default()
                },
            ));
        }

        None
    }

    /// Detect session sharing patterns.
    fn detect_session_sharing(&self, signals: &[Signal]) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Group auth tokens by value
        let mut token_ips: HashMap<String, HashSet<String>> = HashMap::new();
        for signal in signals {
            if signal.category == SignalCategory::AuthToken {
                token_ips
                    .entry(signal.value.clone())
                    .or_insert_with(HashSet::new)
                    .insert(signal.entity_id.clone());
            }
        }

        for (token_hash, ips) in token_ips {
            if ips.len() >= self.config.session_sharing_min_ips {
                anomalies.push(self.create_anomaly(
                    AnomalyType::SessionSharing,
                    AnomalySeverity::High,
                    format!(
                        "Auth token shared across {} IPs: {}...",
                        ips.len(),
                        &token_hash[..8.min(token_hash.len())]
                    ),
                    SignalCategory::AuthToken,
                    Vec::new(),
                    ips.into_iter().collect(),
                    AnomalyMetadata {
                        token_hash_prefix: Some(token_hash[..16.min(token_hash.len())].to_string()),
                        ..Default::default()
                    },
                ));
            }
        }

        anomalies
    }

    /// Detect JA4 fingerprint clusters.
    fn detect_ja4_clusters(&self, signals: &[Signal]) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Group JA4 fingerprints by value
        let mut ja4_ips: HashMap<String, HashSet<String>> = HashMap::new();
        for signal in signals {
            if signal.signal_type == SignalType::Ja4 {
                ja4_ips
                    .entry(signal.value.clone())
                    .or_insert_with(HashSet::new)
                    .insert(signal.entity_id.clone());
            }
        }

        for (ja4, ips) in ja4_ips {
            let ip_count = ips.len();
            if ip_count >= 10 {
                // Large cluster threshold
                anomalies.push(self.create_anomaly(
                    AnomalyType::Ja4IpCluster,
                    AnomalySeverity::Medium,
                    format!(
                        "JA4 fingerprint {} seen from {} IPs (potential bot farm)",
                        &ja4[..12.min(ja4.len())],
                        ip_count
                    ),
                    SignalCategory::Network,
                    Vec::new(),
                    ips.into_iter().collect(),
                    AnomalyMetadata {
                        ip_count: Some(ip_count),
                        ..Default::default()
                    },
                ));
            }
        }

        anomalies
    }

    /// Detect rotation patterns.
    fn detect_rotation_patterns(
        &self,
        current_signals: &[Signal],
        _historical: &[&SignalBucket],
    ) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();

        // Group by entity and signal type
        let mut entity_values: HashMap<(String, SignalType), HashSet<String>> = HashMap::new();

        for signal in current_signals {
            if matches!(
                signal.signal_type,
                SignalType::Ja4 | SignalType::HttpFingerprint
            ) {
                entity_values
                    .entry((signal.entity_id.clone(), signal.signal_type))
                    .or_insert_with(HashSet::new)
                    .insert(signal.value.clone());
            }
        }

        for ((entity_id, signal_type), values) in entity_values {
            if values.len() >= self.config.rotation_min_changes {
                let anomaly_type = match signal_type {
                    SignalType::Ja4 => AnomalyType::Ja4RotationPattern,
                    _ => AnomalyType::RotationPattern,
                };

                anomalies.push(self.create_anomaly(
                    anomaly_type,
                    AnomalySeverity::High,
                    format!(
                        "Systematic {:?} rotation: {} unique values from {}",
                        signal_type,
                        values.len(),
                        entity_id
                    ),
                    signal_type.category(),
                    Vec::new(),
                    vec![entity_id],
                    AnomalyMetadata {
                        change_count: Some(values.len()),
                        ..Default::default()
                    },
                ));
            }
        }

        anomalies
    }

    /// Create an anomaly with standard fields.
    fn create_anomaly(
        &self,
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        description: String,
        category: SignalCategory,
        signals: Vec<Signal>,
        entities: Vec<String>,
        metadata: AnomalyMetadata,
    ) -> Anomaly {
        Anomaly {
            id: uuid::Uuid::new_v4().to_string(),
            detected_at: chrono::Utc::now().timestamp_millis(),
            category,
            anomaly_type,
            severity,
            description,
            signals,
            entities,
            metadata,
            risk_applied: self.risk_scores.get(&anomaly_type).copied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signal(
        entity_id: &str,
        signal_type: SignalType,
        value: &str,
        session_id: Option<&str>,
    ) -> Signal {
        Signal {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            category: signal_type.category(),
            signal_type,
            value: value.to_string(),
            entity_id: entity_id.to_string(),
            session_id: session_id.map(String::from),
            metadata: super::super::types::SignalMetadata::default(),
        }
    }

    #[test]
    fn test_session_sharing_detection() {
        let detector = AnomalyDetector::new(HashMap::new());

        let signals = vec![
            create_test_signal("ip-1", SignalType::Bearer, "token123", None),
            create_test_signal("ip-2", SignalType::Bearer, "token123", None),
            create_test_signal("ip-3", SignalType::Bearer, "token123", None),
        ];

        let anomalies = detector.detect_session_sharing(&signals);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::SessionSharing);
    }

    #[test]
    fn test_ja4_cluster_detection() {
        let detector = AnomalyDetector::new(HashMap::new());

        let mut signals = Vec::new();
        for i in 0..15 {
            signals.push(create_test_signal(
                &format!("ip-{}", i),
                SignalType::Ja4,
                "t13d1516h2_same_fingerprint",
                None,
            ));
        }

        let anomalies = detector.detect_ja4_clusters(&signals);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::Ja4IpCluster);
    }

    #[test]
    fn test_rotation_pattern_detection() {
        let mut config = AnomalyDetectorConfig::default();
        config.rotation_min_changes = 3;

        let detector = AnomalyDetector::with_config(config, HashMap::new());

        let signals = vec![
            create_test_signal("ip-1", SignalType::Ja4, "fingerprint-1", None),
            create_test_signal("ip-1", SignalType::Ja4, "fingerprint-2", None),
            create_test_signal("ip-1", SignalType::Ja4, "fingerprint-3", None),
        ];

        let anomalies = detector.detect_rotation_patterns(&signals, &[]);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::Ja4RotationPattern);
    }
}
