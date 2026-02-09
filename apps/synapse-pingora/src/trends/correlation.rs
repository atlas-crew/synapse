//! Correlation engine for finding relationships between signals.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::types::{Signal, SignalType};

/// Types of correlations we detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// Multiple IPs sharing signals
    EntityCluster,
    /// Sequence of related signals
    SignalChain,
    /// Signals occurring together in time
    TemporalCorrelation,
    /// Similar but not identical fingerprints
    FingerprintFamily,
}

/// A detected correlation between signals/entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub id: String,
    pub correlation_type: CorrelationType,
    /// Correlation strength (0-1)
    pub strength: f64,
    /// Involved entity IDs (IPs)
    pub entities: Vec<String>,
    /// Related signals
    pub signals: Vec<Signal>,
    pub description: String,
    pub detected_at: i64,
    pub metadata: CorrelationMetadata,
}

/// Correlation metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorrelationMetadata {
    pub shared_value: Option<String>,
    pub signal_count: Option<usize>,
    pub time_window: Option<i64>,
}

/// Query options for correlations.
#[derive(Debug, Clone, Default)]
pub struct CorrelationQueryOptions {
    pub correlation_type: Option<CorrelationType>,
    pub entity_id: Option<String>,
    pub signal_type: Option<SignalType>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub min_strength: Option<f64>,
    pub limit: Option<usize>,
}

/// Correlation engine for finding relationships.
pub struct CorrelationEngine {
    /// Minimum entities for a cluster
    min_cluster_size: usize,
    /// Time window for temporal correlation (ms)
    temporal_window_ms: i64,
    /// Minimum correlation strength threshold
    min_strength: f64,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationEngine {
    /// Create a new correlation engine.
    pub fn new() -> Self {
        Self {
            min_cluster_size: 3,
            temporal_window_ms: 60_000,
            min_strength: 0.5,
        }
    }

    /// Create with custom settings.
    pub fn with_settings(
        min_cluster_size: usize,
        temporal_window_ms: i64,
        min_strength: f64,
    ) -> Self {
        Self {
            min_cluster_size,
            temporal_window_ms,
            min_strength,
        }
    }

    /// Find correlations in a set of signals.
    pub fn find_correlations(
        &self,
        signals: &[Signal],
        options: &CorrelationQueryOptions,
    ) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        // Entity clusters
        if options.correlation_type.is_none()
            || options.correlation_type == Some(CorrelationType::EntityCluster)
        {
            correlations.extend(self.find_entity_clusters(signals));
        }

        // Temporal correlations
        if options.correlation_type.is_none()
            || options.correlation_type == Some(CorrelationType::TemporalCorrelation)
        {
            correlations.extend(self.find_temporal_correlations(signals));
        }

        // Fingerprint families
        if options.correlation_type.is_none()
            || options.correlation_type == Some(CorrelationType::FingerprintFamily)
        {
            correlations.extend(self.find_fingerprint_families(signals));
        }

        // Apply filters
        let mut filtered = correlations
            .into_iter()
            .filter(|c| {
                if let Some(ref entity_id) = options.entity_id {
                    if !c.entities.contains(entity_id) {
                        return false;
                    }
                }
                if let Some(min_str) = options.min_strength {
                    if c.strength < min_str {
                        return false;
                    }
                }
                if let Some(from) = options.from {
                    if c.detected_at < from {
                        return false;
                    }
                }
                if let Some(to) = options.to {
                    if c.detected_at > to {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<_>>();

        // Sort by strength (strongest first)
        filtered.sort_by(|a, b| {
            b.strength
                .partial_cmp(&a.strength)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Apply limit
        if let Some(limit) = options.limit {
            filtered.truncate(limit);
        }

        filtered
    }

    /// Find entity clusters (IPs sharing signals).
    fn find_entity_clusters(&self, signals: &[Signal]) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        // Group signals by value
        let mut value_entities: HashMap<String, HashSet<String>> = HashMap::new();
        for signal in signals {
            value_entities
                .entry(signal.value.clone())
                .or_insert_with(HashSet::new)
                .insert(signal.entity_id.clone());
        }

        for (value, entities) in value_entities {
            let entity_count = entities.len();
            if entity_count >= self.min_cluster_size {
                let strength = (entity_count as f64 - 2.0) / 10.0;
                let strength = strength.min(1.0).max(self.min_strength);

                correlations.push(Correlation {
                    id: uuid::Uuid::new_v4().to_string(),
                    correlation_type: CorrelationType::EntityCluster,
                    strength,
                    entities: entities.into_iter().collect(),
                    signals: signals
                        .iter()
                        .filter(|s| s.value == value)
                        .cloned()
                        .collect(),
                    description: format!("Entity cluster: {} IPs share signal value", entity_count),
                    detected_at: chrono::Utc::now().timestamp_millis(),
                    metadata: CorrelationMetadata {
                        shared_value: Some(value[..16.min(value.len())].to_string()),
                        signal_count: Some(signals.iter().filter(|s| s.value == value).count()),
                        ..Default::default()
                    },
                });
            }
        }

        correlations
    }

    /// Find temporal correlations (signals occurring together).
    fn find_temporal_correlations(&self, signals: &[Signal]) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        if signals.len() < 2 {
            return correlations;
        }

        // Sort by timestamp
        let mut sorted = signals.to_vec();
        sorted.sort_by_key(|s| s.timestamp);

        // Sliding window to find bursts
        let mut window_start = 0;
        for i in 0..sorted.len() {
            // Shrink window from left
            while sorted[i].timestamp - sorted[window_start].timestamp > self.temporal_window_ms {
                window_start += 1;
            }

            // Check if window has multiple entities
            let window = &sorted[window_start..=i];
            let entities: HashSet<_> = window.iter().map(|s| &s.entity_id).collect();

            let entity_count = entities.len();
            if entity_count >= self.min_cluster_size {
                // Found a temporal burst
                let strength = (entity_count as f64 - 2.0) / 8.0;
                let strength = strength.min(1.0).max(self.min_strength);

                correlations.push(Correlation {
                    id: uuid::Uuid::new_v4().to_string(),
                    correlation_type: CorrelationType::TemporalCorrelation,
                    strength,
                    entities: entities.into_iter().cloned().collect(),
                    signals: window.to_vec(),
                    description: format!(
                        "Temporal burst: {} entities active within {}ms",
                        entity_count, self.temporal_window_ms
                    ),
                    detected_at: chrono::Utc::now().timestamp_millis(),
                    metadata: CorrelationMetadata {
                        signal_count: Some(window.len()),
                        time_window: Some(self.temporal_window_ms),
                        ..Default::default()
                    },
                });
            }
        }

        // Deduplicate overlapping correlations
        self.deduplicate_correlations(correlations)
    }

    /// Find fingerprint families (similar fingerprints).
    fn find_fingerprint_families(&self, signals: &[Signal]) -> Vec<Correlation> {
        let mut correlations = Vec::new();

        // Get fingerprint signals
        let fingerprints: Vec<_> = signals
            .iter()
            .filter(|s| {
                matches!(
                    s.signal_type,
                    SignalType::Ja4 | SignalType::Ja4h | SignalType::HttpFingerprint
                )
            })
            .collect();

        // Group by prefix (first 8 chars)
        let mut prefix_groups: HashMap<String, Vec<&Signal>> = HashMap::new();
        for fp in &fingerprints {
            if fp.value.len() >= 8 {
                let prefix = fp.value[..8].to_string();
                prefix_groups
                    .entry(prefix)
                    .or_insert_with(Vec::new)
                    .push(fp);
            }
        }

        for (prefix, group) in prefix_groups {
            let unique_values: HashSet<_> = group.iter().map(|s| &s.value).collect();

            // Only if there are multiple similar but not identical fingerprints
            if unique_values.len() >= 2 {
                let entities: HashSet<_> = group.iter().map(|s| s.entity_id.clone()).collect();
                let strength = unique_values.len() as f64 / 10.0;
                let strength = strength.min(1.0).max(self.min_strength);

                correlations.push(Correlation {
                    id: uuid::Uuid::new_v4().to_string(),
                    correlation_type: CorrelationType::FingerprintFamily,
                    strength,
                    entities: entities.into_iter().collect(),
                    signals: group.into_iter().cloned().collect(),
                    description: format!(
                        "Fingerprint family: {} variants with prefix {}...",
                        unique_values.len(),
                        prefix
                    ),
                    detected_at: chrono::Utc::now().timestamp_millis(),
                    metadata: CorrelationMetadata {
                        shared_value: Some(prefix),
                        signal_count: Some(unique_values.len()),
                        ..Default::default()
                    },
                });
            }
        }

        correlations
    }

    /// Deduplicate overlapping correlations.
    fn deduplicate_correlations(&self, correlations: Vec<Correlation>) -> Vec<Correlation> {
        if correlations.is_empty() {
            return correlations;
        }

        let mut result = Vec::new();
        let mut seen_entities: HashSet<String> = HashSet::new();

        for corr in correlations {
            // Check if any entity in this correlation is already covered
            let entities_set: HashSet<_> = corr.entities.iter().cloned().collect();
            let overlap = entities_set.intersection(&seen_entities).count();

            // Only add if less than 50% overlap
            if overlap as f64 / entities_set.len() as f64 <= 0.5 {
                seen_entities.extend(corr.entities.iter().cloned());
                result.push(corr);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_signal(entity_id: &str, value: &str, timestamp: i64) -> Signal {
        Signal {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            category: super::super::types::SignalCategory::Network,
            signal_type: SignalType::Ja4,
            value: value.to_string(),
            entity_id: entity_id.to_string(),
            session_id: None,
            metadata: super::super::types::SignalMetadata::default(),
        }
    }

    #[test]
    fn test_entity_cluster_detection() {
        let engine = CorrelationEngine::new();

        let signals = vec![
            create_test_signal("ip-1", "shared_value", 1000),
            create_test_signal("ip-2", "shared_value", 2000),
            create_test_signal("ip-3", "shared_value", 3000),
        ];

        let correlations = engine.find_entity_clusters(&signals);
        assert!(!correlations.is_empty());
        assert_eq!(
            correlations[0].correlation_type,
            CorrelationType::EntityCluster
        );
    }

    #[test]
    fn test_temporal_correlation() {
        let engine = CorrelationEngine::with_settings(2, 10_000, 0.3);

        let now = chrono::Utc::now().timestamp_millis();
        let signals = vec![
            create_test_signal("ip-1", "value-1", now),
            create_test_signal("ip-2", "value-2", now + 1000),
            create_test_signal("ip-3", "value-3", now + 2000),
        ];

        let correlations = engine.find_temporal_correlations(&signals);
        assert!(!correlations.is_empty());
        assert_eq!(
            correlations[0].correlation_type,
            CorrelationType::TemporalCorrelation
        );
    }

    #[test]
    fn test_fingerprint_family() {
        let engine = CorrelationEngine::new();

        let signals = vec![
            create_test_signal("ip-1", "t13d1516h2_variant1_abc", 1000),
            create_test_signal("ip-2", "t13d1516h2_variant2_def", 2000),
            create_test_signal("ip-3", "t13d1516h2_variant3_ghi", 3000),
        ];

        let correlations = engine.find_fingerprint_families(&signals);
        assert!(!correlations.is_empty());
        assert_eq!(
            correlations[0].correlation_type,
            CorrelationType::FingerprintFamily
        );
    }
}
