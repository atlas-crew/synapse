//! SignalManager - aggregates security signals into time buckets.
//!
//! Signals are categorized into high-level buckets:
//! - Attack
//! - Anomaly
//! - Behavior
//! - Intelligence
//!
//! This manager provides lightweight, in-memory storage optimized for
//! last-24-hour visibility and dashboard queries.

use std::collections::{HashMap, VecDeque};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Types
// ============================================================================

/// High-level signal categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalCategory {
    Attack,
    Anomaly,
    Behavior,
    Intelligence,
}

/// Security signal recorded by the sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// Unique signal ID.
    pub id: String,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Signal category.
    pub category: SignalCategory,
    /// Signal type identifier (string for extensibility).
    pub signal_type: String,
    /// Optional entity identifier (IP, actor ID, fingerprint).
    pub entity_id: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Arbitrary structured metadata.
    pub metadata: serde_json::Value,
}

impl Signal {
    pub fn new(
        category: SignalCategory,
        signal_type: impl Into<String>,
        entity_id: Option<String>,
        description: Option<String>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp_ms: now_ms(),
            category,
            signal_type: signal_type.into(),
            entity_id,
            description,
            metadata,
        }
    }
}

/// Query options for listing signals.
#[derive(Debug, Clone, Default)]
pub struct SignalQueryOptions {
    pub category: Option<SignalCategory>,
    pub limit: Option<usize>,
    pub since_ms: Option<u64>,
}

/// Summary of signals for dashboards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSummary {
    pub total_signals: usize,
    pub by_category: HashMap<SignalCategory, usize>,
    pub top_signal_types: Vec<TopSignalType>,
}

/// Top signal type counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopSignalType {
    pub signal_type: String,
    pub count: usize,
}

/// Signal manager configuration.
#[derive(Debug, Clone)]
pub struct SignalManagerConfig {
    /// Bucket size in milliseconds (default: 5 minutes).
    pub bucket_size_ms: u64,
    /// Total retention window in milliseconds (default: 24 hours).
    pub retention_ms: u64,
    /// Maximum stored signals per bucket (default: 1000).
    pub max_signals_per_bucket: usize,
    /// Maximum number of signals returned per query (default: 500).
    pub max_query_results: usize,
}

impl Default for SignalManagerConfig {
    fn default() -> Self {
        Self {
            bucket_size_ms: 5 * 60 * 1000,
            retention_ms: 24 * 60 * 60 * 1000,
            max_signals_per_bucket: 1000,
            max_query_results: 500,
        }
    }
}

// ============================================================================
// Internal Structures
// ============================================================================

#[derive(Debug, Clone)]
struct SignalBucket {
    timestamp_ms: u64,
    end_timestamp_ms: u64,
    signals: Vec<Signal>,
    by_category: HashMap<SignalCategory, usize>,
    by_type: HashMap<String, usize>,
}

impl SignalBucket {
    fn new(timestamp_ms: u64, bucket_size_ms: u64) -> Self {
        Self {
            timestamp_ms,
            end_timestamp_ms: timestamp_ms + bucket_size_ms,
            signals: Vec::new(),
            by_category: HashMap::new(),
            by_type: HashMap::new(),
        }
    }

    fn add_signal(&mut self, signal: Signal, max_signals: usize) {
        *self.by_category.entry(signal.category).or_insert(0) += 1;
        *self.by_type.entry(signal.signal_type.clone()).or_insert(0) += 1;

        if self.signals.len() < max_signals {
            self.signals.push(signal);
        }
    }
}

#[derive(Debug, Default)]
struct SignalStore {
    buckets: VecDeque<SignalBucket>,
}

// ============================================================================
// Signal Manager
// ============================================================================

/// In-memory signal aggregation manager.
pub struct SignalManager {
    config: SignalManagerConfig,
    store: RwLock<SignalStore>,
}

impl SignalManager {
    pub fn new(config: SignalManagerConfig) -> Self {
        Self {
            config,
            store: RwLock::new(SignalStore::default()),
        }
    }

    /// Record a signal into the time store.
    pub fn record(&self, signal: Signal) {
        let mut store = self.store.write();
        let bucket_ts = bucket_timestamp(signal.timestamp_ms, self.config.bucket_size_ms);

        let bucket = match store.buckets.back_mut() {
            Some(last) if last.timestamp_ms == bucket_ts => last,
            Some(last) if bucket_ts > last.timestamp_ms => {
                // Add buckets until we reach the target (handles gaps).
                let mut ts = last.timestamp_ms + self.config.bucket_size_ms;
                while ts <= bucket_ts {
                    store
                        .buckets
                        .push_back(SignalBucket::new(ts, self.config.bucket_size_ms));
                    ts += self.config.bucket_size_ms;
                }
                store.buckets.back_mut().expect("bucket just added")
            }
            _ => {
                // Either empty or out-of-order; add a fresh bucket.
                store
                    .buckets
                    .push_back(SignalBucket::new(bucket_ts, self.config.bucket_size_ms));
                store.buckets.back_mut().expect("bucket just added")
            }
        };

        bucket.add_signal(signal, self.config.max_signals_per_bucket);
        self.evict_old_buckets(&mut store);
    }

    /// Convenience method to build and record a signal.
    pub fn record_event(
        &self,
        category: SignalCategory,
        signal_type: impl Into<String>,
        entity_id: Option<String>,
        description: Option<String>,
        metadata: serde_json::Value,
    ) {
        self.record(Signal::new(
            category,
            signal_type,
            entity_id,
            description,
            metadata,
        ));
    }

    /// List recent signals with optional filtering.
    pub fn list_signals(&self, options: SignalQueryOptions) -> Vec<Signal> {
        let store = self.store.read();
        let limit = options
            .limit
            .unwrap_or(self.config.max_query_results)
            .min(self.config.max_query_results);

        let mut results = Vec::with_capacity(limit);
        for bucket in store.buckets.iter().rev() {
            for signal in bucket.signals.iter().rev() {
                if let Some(category) = options.category {
                    if signal.category != category {
                        continue;
                    }
                }
                if let Some(since_ms) = options.since_ms {
                    if signal.timestamp_ms < since_ms {
                        continue;
                    }
                }
                results.push(signal.clone());
                if results.len() >= limit {
                    return results;
                }
            }
        }
        results
    }

    /// Build a summary of signals for dashboards.
    pub fn summary(&self) -> SignalSummary {
        let store = self.store.read();
        let mut by_category: HashMap<SignalCategory, usize> = HashMap::new();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut total = 0usize;

        for bucket in store.buckets.iter() {
            total += bucket.signals.len();
            for (category, count) in &bucket.by_category {
                *by_category.entry(*category).or_insert(0) += count;
            }
            for (signal_type, count) in &bucket.by_type {
                *by_type.entry(signal_type.clone()).or_insert(0) += count;
            }
        }

        let mut top_signal_types: Vec<TopSignalType> = by_type
            .into_iter()
            .map(|(signal_type, count)| TopSignalType { signal_type, count })
            .collect();
        top_signal_types.sort_by(|a, b| b.count.cmp(&a.count));
        top_signal_types.truncate(10);

        SignalSummary {
            total_signals: total,
            by_category,
            top_signal_types,
        }
    }

    fn evict_old_buckets(&self, store: &mut SignalStore) {
        let max_buckets = (self.config.retention_ms / self.config.bucket_size_ms).max(1) as usize;
        while store.buckets.len() > max_buckets {
            store.buckets.pop_front();
        }
    }
}

#[inline]
fn bucket_timestamp(timestamp_ms: u64, bucket_size_ms: u64) -> u64 {
    timestamp_ms - (timestamp_ms % bucket_size_ms)
}

#[inline]
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SignalManagerConfig {
        SignalManagerConfig {
            bucket_size_ms: 1000, // 1 second buckets for testing
            retention_ms: 10_000, // 10 seconds
            max_signals_per_bucket: 100,
            max_query_results: 50,
        }
    }

    // ========================================================================
    // Signal Creation Tests
    // ========================================================================

    #[test]
    fn test_signal_new_creates_unique_id() {
        let s1 = Signal::new(
            SignalCategory::Attack,
            "sql_injection",
            None,
            None,
            serde_json::json!({}),
        );
        let s2 = Signal::new(
            SignalCategory::Attack,
            "sql_injection",
            None,
            None,
            serde_json::json!({}),
        );

        assert_ne!(s1.id, s2.id, "Each signal should have unique ID");
    }

    #[test]
    fn test_signal_new_sets_timestamp() {
        let before = now_ms();
        let signal = Signal::new(
            SignalCategory::Anomaly,
            "rate_spike",
            Some("192.168.1.1".to_string()),
            Some("Unusual request rate".to_string()),
            serde_json::json!({"rate": 1000}),
        );
        let after = now_ms();

        assert!(signal.timestamp_ms >= before);
        assert!(signal.timestamp_ms <= after);
    }

    #[test]
    fn test_signal_fields_populated() {
        let signal = Signal::new(
            SignalCategory::Behavior,
            "crawler_detected",
            Some("10.0.0.1".to_string()),
            Some("Bot behavior".to_string()),
            serde_json::json!({"bot_name": "test_bot"}),
        );

        assert_eq!(signal.category, SignalCategory::Behavior);
        assert_eq!(signal.signal_type, "crawler_detected");
        assert_eq!(signal.entity_id, Some("10.0.0.1".to_string()));
        assert_eq!(signal.description, Some("Bot behavior".to_string()));
        assert_eq!(signal.metadata["bot_name"], "test_bot");
    }

    // ========================================================================
    // Signal Manager Recording Tests
    // ========================================================================

    #[test]
    fn test_record_signal() {
        let manager = SignalManager::new(test_config());

        manager.record_event(
            SignalCategory::Attack,
            "xss",
            Some("1.2.3.4".to_string()),
            Some("XSS attempt".to_string()),
            serde_json::json!({}),
        );

        let signals = manager.list_signals(SignalQueryOptions::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, SignalCategory::Attack);
        assert_eq!(signals[0].signal_type, "xss");
    }

    #[test]
    fn test_record_multiple_signals() {
        let manager = SignalManager::new(test_config());

        for i in 0..5 {
            manager.record_event(
                SignalCategory::Attack,
                format!("attack_{}", i),
                None,
                None,
                serde_json::json!({"index": i}),
            );
        }

        let signals = manager.list_signals(SignalQueryOptions::default());
        assert_eq!(signals.len(), 5);
    }

    #[test]
    fn test_record_different_categories() {
        let manager = SignalManager::new(test_config());

        manager.record_event(SignalCategory::Attack, "sqli", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Anomaly, "rate_spike", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Behavior, "crawler", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Intelligence, "blocklist_hit", None, None, serde_json::json!({}));

        let summary = manager.summary();
        assert_eq!(summary.total_signals, 4);
        assert_eq!(summary.by_category.get(&SignalCategory::Attack), Some(&1));
        assert_eq!(summary.by_category.get(&SignalCategory::Anomaly), Some(&1));
        assert_eq!(summary.by_category.get(&SignalCategory::Behavior), Some(&1));
        assert_eq!(summary.by_category.get(&SignalCategory::Intelligence), Some(&1));
    }

    // ========================================================================
    // Query Filtering Tests
    // ========================================================================

    #[test]
    fn test_list_signals_filter_by_category() {
        let manager = SignalManager::new(test_config());

        manager.record_event(SignalCategory::Attack, "sqli", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Attack, "xss", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Anomaly, "rate_spike", None, None, serde_json::json!({}));

        let attacks = manager.list_signals(SignalQueryOptions {
            category: Some(SignalCategory::Attack),
            ..Default::default()
        });
        assert_eq!(attacks.len(), 2);

        let anomalies = manager.list_signals(SignalQueryOptions {
            category: Some(SignalCategory::Anomaly),
            ..Default::default()
        });
        assert_eq!(anomalies.len(), 1);
    }

    #[test]
    fn test_list_signals_limit() {
        let manager = SignalManager::new(test_config());

        for i in 0..20 {
            manager.record_event(
                SignalCategory::Attack,
                format!("attack_{}", i),
                None,
                None,
                serde_json::json!({}),
            );
        }

        let limited = manager.list_signals(SignalQueryOptions {
            limit: Some(5),
            ..Default::default()
        });
        assert_eq!(limited.len(), 5);
    }

    #[test]
    fn test_list_signals_respects_max_query_results() {
        let config = SignalManagerConfig {
            max_query_results: 10,
            ..test_config()
        };
        let manager = SignalManager::new(config);

        for i in 0..20 {
            manager.record_event(
                SignalCategory::Attack,
                format!("attack_{}", i),
                None,
                None,
                serde_json::json!({}),
            );
        }

        // Request more than max_query_results
        let signals = manager.list_signals(SignalQueryOptions {
            limit: Some(100),
            ..Default::default()
        });
        assert_eq!(signals.len(), 10);
    }

    #[test]
    fn test_list_signals_returns_most_recent_first() {
        let manager = SignalManager::new(test_config());

        manager.record_event(SignalCategory::Attack, "first", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Attack, "second", None, None, serde_json::json!({}));
        manager.record_event(SignalCategory::Attack, "third", None, None, serde_json::json!({}));

        let signals = manager.list_signals(SignalQueryOptions::default());
        assert_eq!(signals[0].signal_type, "third");
        assert_eq!(signals[1].signal_type, "second");
        assert_eq!(signals[2].signal_type, "first");
    }

    // ========================================================================
    // Summary Tests
    // ========================================================================

    #[test]
    fn test_summary_empty() {
        let manager = SignalManager::new(test_config());
        let summary = manager.summary();

        assert_eq!(summary.total_signals, 0);
        assert!(summary.by_category.is_empty());
        assert!(summary.top_signal_types.is_empty());
    }

    #[test]
    fn test_summary_counts_by_category() {
        let manager = SignalManager::new(test_config());

        for _ in 0..3 {
            manager.record_event(SignalCategory::Attack, "sqli", None, None, serde_json::json!({}));
        }
        for _ in 0..2 {
            manager.record_event(SignalCategory::Anomaly, "rate", None, None, serde_json::json!({}));
        }

        let summary = manager.summary();
        assert_eq!(summary.total_signals, 5);
        assert_eq!(summary.by_category.get(&SignalCategory::Attack), Some(&3));
        assert_eq!(summary.by_category.get(&SignalCategory::Anomaly), Some(&2));
    }

    #[test]
    fn test_summary_top_signal_types() {
        let manager = SignalManager::new(test_config());

        for _ in 0..5 {
            manager.record_event(SignalCategory::Attack, "sqli", None, None, serde_json::json!({}));
        }
        for _ in 0..3 {
            manager.record_event(SignalCategory::Attack, "xss", None, None, serde_json::json!({}));
        }
        for _ in 0..1 {
            manager.record_event(SignalCategory::Attack, "rce", None, None, serde_json::json!({}));
        }

        let summary = manager.summary();
        assert_eq!(summary.top_signal_types.len(), 3);
        assert_eq!(summary.top_signal_types[0].signal_type, "sqli");
        assert_eq!(summary.top_signal_types[0].count, 5);
        assert_eq!(summary.top_signal_types[1].signal_type, "xss");
        assert_eq!(summary.top_signal_types[1].count, 3);
        assert_eq!(summary.top_signal_types[2].signal_type, "rce");
        assert_eq!(summary.top_signal_types[2].count, 1);
    }

    #[test]
    fn test_summary_top_signal_types_limited_to_10() {
        let manager = SignalManager::new(test_config());

        for i in 0..15 {
            manager.record_event(
                SignalCategory::Attack,
                format!("attack_type_{}", i),
                None,
                None,
                serde_json::json!({}),
            );
        }

        let summary = manager.summary();
        assert_eq!(summary.top_signal_types.len(), 10);
    }

    // ========================================================================
    // Time Bucket Tests
    // ========================================================================

    #[test]
    fn test_bucket_timestamp_calculation() {
        // With 1000ms buckets:
        // 1500ms should go to bucket 1000
        // 2500ms should go to bucket 2000
        assert_eq!(bucket_timestamp(1500, 1000), 1000);
        assert_eq!(bucket_timestamp(2500, 1000), 2000);
        assert_eq!(bucket_timestamp(3000, 1000), 3000);
    }

    #[test]
    fn test_max_signals_per_bucket() {
        let config = SignalManagerConfig {
            max_signals_per_bucket: 3,
            ..test_config()
        };
        let manager = SignalManager::new(config);

        // Record more than max_signals_per_bucket
        for i in 0..10 {
            manager.record_event(
                SignalCategory::Attack,
                format!("attack_{}", i),
                None,
                None,
                serde_json::json!({}),
            );
        }

        // Summary should count all signals (via counters)
        let summary = manager.summary();
        assert_eq!(summary.by_category.get(&SignalCategory::Attack), Some(&10));

        // But list should only return stored signals
        let signals = manager.list_signals(SignalQueryOptions::default());
        assert_eq!(signals.len(), 3);
    }

    // ========================================================================
    // Bucket Eviction Tests
    // ========================================================================

    #[test]
    fn test_bucket_eviction_respects_retention() {
        let config = SignalManagerConfig {
            bucket_size_ms: 1000,
            retention_ms: 3000, // Only 3 buckets retained
            max_signals_per_bucket: 100,
            max_query_results: 500,
        };
        let manager = SignalManager::new(config);

        // Create signals with manually set timestamps to simulate time passing
        // Note: This tests internal eviction logic indirectly
        let store = &manager.store;

        {
            let mut store_lock = store.write();
            // Add 5 buckets manually
            for i in 0..5 {
                let mut bucket = SignalBucket::new(i * 1000, 1000);
                bucket.add_signal(
                    Signal {
                        id: format!("sig_{}", i),
                        timestamp_ms: i * 1000,
                        category: SignalCategory::Attack,
                        signal_type: format!("attack_{}", i),
                        entity_id: None,
                        description: None,
                        metadata: serde_json::json!({}),
                    },
                    100,
                );
                store_lock.buckets.push_back(bucket);
            }
        }

        // After eviction, only 3 buckets should remain
        manager.record_event(SignalCategory::Attack, "trigger_eviction", None, None, serde_json::json!({}));

        let summary = manager.summary();
        // Should have signals from retained buckets plus the new one
        assert!(summary.total_signals <= 4);
    }

    // ========================================================================
    // SignalCategory Tests
    // ========================================================================

    #[test]
    fn test_signal_category_equality() {
        assert_eq!(SignalCategory::Attack, SignalCategory::Attack);
        assert_ne!(SignalCategory::Attack, SignalCategory::Anomaly);
    }

    #[test]
    fn test_signal_category_serialization() {
        let category = SignalCategory::Intelligence;
        let serialized = serde_json::to_string(&category).unwrap();
        assert_eq!(serialized, "\"intelligence\"");

        let deserialized: SignalCategory = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, SignalCategory::Intelligence);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_empty_signal_query() {
        let manager = SignalManager::new(test_config());
        let signals = manager.list_signals(SignalQueryOptions::default());
        assert!(signals.is_empty());
    }

    #[test]
    fn test_filter_nonexistent_category() {
        let manager = SignalManager::new(test_config());

        manager.record_event(SignalCategory::Attack, "test", None, None, serde_json::json!({}));

        let signals = manager.list_signals(SignalQueryOptions {
            category: Some(SignalCategory::Anomaly),
            ..Default::default()
        });
        assert!(signals.is_empty());
    }

    #[test]
    fn test_signal_with_complex_metadata() {
        let manager = SignalManager::new(test_config());

        manager.record_event(
            SignalCategory::Attack,
            "complex_attack",
            Some("attacker-ip".to_string()),
            Some("Complex attack detected".to_string()),
            serde_json::json!({
                "rules": [1001, 1002, 1003],
                "risk_score": 85,
                "headers": {
                    "user-agent": "malicious-bot",
                    "x-forwarded-for": "1.2.3.4"
                },
                "nested": {
                    "deep": {
                        "value": true
                    }
                }
            }),
        );

        let signals = manager.list_signals(SignalQueryOptions::default());
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].metadata["rules"].as_array().unwrap().len(), 3);
        assert_eq!(signals[0].metadata["risk_score"], 85);
        assert_eq!(signals[0].metadata["nested"]["deep"]["value"], true);
    }
}
