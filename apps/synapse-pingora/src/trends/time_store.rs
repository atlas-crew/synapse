//! Time-bucketed signal storage with LRU eviction.

use std::collections::{HashMap, VecDeque};

use super::config::TrendsConfig;
use super::types::{
    BucketSummary, CategorySummary, CategoryTrendSummary, Signal, SignalBucketData, SignalTrend,
    SignalType, TimeRange, TopSignalType, TrendHistogramBucket, TrendQueryOptions, TrendsSummary,
};

/// A time bucket for signal aggregation.
#[derive(Debug, Clone)]
pub struct SignalBucket {
    /// Bucket start time (Unix ms)
    pub timestamp: i64,
    /// Bucket end time (Unix ms)
    pub end_timestamp: i64,
    /// Signals in this bucket
    pub signals: Vec<Signal>,
    /// Summary statistics
    pub summary: BucketSummary,
}

impl SignalBucket {
    /// Create a new bucket for the given timestamp.
    pub fn new(timestamp: i64, bucket_size_ms: u64) -> Self {
        Self {
            timestamp,
            end_timestamp: timestamp + bucket_size_ms as i64,
            signals: Vec::new(),
            summary: BucketSummary::default(),
        }
    }

    /// Add a signal to the bucket.
    pub fn add_signal(&mut self, signal: Signal, max_signals: usize) {
        // Update summary
        self.summary.total_count += 1;

        let category_summary = self
            .summary
            .by_category
            .entry(signal.category)
            .or_insert_with(CategorySummary::default);

        category_summary.count += 1;
        category_summary.unique_values.insert(signal.value.clone());
        category_summary
            .unique_entities
            .insert(signal.entity_id.clone());
        *category_summary
            .by_type
            .entry(signal.signal_type)
            .or_insert(0) += 1;

        // Only store signals up to max
        if self.signals.len() < max_signals {
            self.signals.push(signal);
        }
    }

    /// Convert to serializable format.
    pub fn to_data(&self) -> SignalBucketData {
        SignalBucketData {
            timestamp: self.timestamp,
            end_timestamp: self.end_timestamp,
            signals: self.signals.clone(),
            summary: self.summary.clone(),
        }
    }
}

/// Time-series signal store with ring buffer.
pub struct TimeStore {
    config: TrendsConfig,
    /// Ring buffer of time buckets
    buckets: VecDeque<SignalBucket>,
    /// Index from entity ID to bucket indices
    entity_index: HashMap<String, Vec<usize>>,
    /// Current bucket (most recent)
    current_bucket_idx: Option<usize>,
}

impl TimeStore {
    /// Create a new time store.
    pub fn new(config: &TrendsConfig) -> Self {
        Self {
            config: config.clone(),
            buckets: VecDeque::with_capacity(config.bucket_count()),
            entity_index: HashMap::new(),
            current_bucket_idx: None,
        }
    }

    /// Record a signal.
    pub fn record(&mut self, signal: Signal) {
        let bucket_timestamp = self.bucket_timestamp(signal.timestamp);

        // Get or create the bucket
        let bucket_idx = self.get_or_create_bucket(bucket_timestamp);

        // Add signal to bucket
        if let Some(bucket) = self.buckets.get_mut(bucket_idx) {
            bucket.add_signal(signal.clone(), self.config.max_signals_per_bucket);

            // Update entity index
            self.entity_index
                .entry(signal.entity_id)
                .or_insert_with(Vec::new)
                .push(bucket_idx);
        }

        self.current_bucket_idx = Some(bucket_idx);
    }

    /// Get the bucket timestamp for a given time.
    fn bucket_timestamp(&self, timestamp: i64) -> i64 {
        let bucket_size = self.config.bucket_size_ms as i64;
        (timestamp / bucket_size) * bucket_size
    }

    /// Get or create a bucket for the given timestamp.
    fn get_or_create_bucket(&mut self, timestamp: i64) -> usize {
        // Check if we already have this bucket
        for (idx, bucket) in self.buckets.iter().enumerate() {
            if bucket.timestamp == timestamp {
                return idx;
            }
        }

        // Create new bucket
        let bucket = SignalBucket::new(timestamp, self.config.bucket_size_ms);

        // Evict old buckets if necessary
        let max_buckets = self.config.bucket_count();
        while self.buckets.len() >= max_buckets {
            self.buckets.pop_front();
            // Rebuild entity index (indices shifted)
            self.rebuild_entity_index();
        }

        self.buckets.push_back(bucket);
        self.buckets.len() - 1
    }

    /// Rebuild the entity index after eviction.
    fn rebuild_entity_index(&mut self) {
        self.entity_index.clear();
        for (bucket_idx, bucket) in self.buckets.iter().enumerate() {
            for signal in &bucket.signals {
                self.entity_index
                    .entry(signal.entity_id.clone())
                    .or_insert_with(Vec::new)
                    .push(bucket_idx);
            }
        }
    }

    /// Get recent buckets (most recent first).
    pub fn get_recent_buckets(&self, count: usize) -> Vec<&SignalBucket> {
        self.buckets.iter().rev().take(count).collect()
    }

    /// Get signals for an entity.
    pub fn get_signals_for_entity(
        &self,
        entity_id: &str,
        options: &TrendQueryOptions,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();

        let bucket_indices = match self.entity_index.get(entity_id) {
            Some(indices) => indices.clone(),
            None => return signals,
        };

        // Deduplicate bucket indices (same bucket may be added multiple times for different signals)
        let unique_indices: std::collections::HashSet<usize> = bucket_indices.into_iter().collect();

        for idx in unique_indices {
            if let Some(bucket) = self.buckets.get(idx) {
                // Apply time filters
                if let Some(from) = options.from {
                    if bucket.end_timestamp < from {
                        continue;
                    }
                }
                if let Some(to) = options.to {
                    if bucket.timestamp > to {
                        continue;
                    }
                }

                for signal in &bucket.signals {
                    if signal.entity_id != entity_id {
                        continue;
                    }

                    // Apply type/category filters
                    if let Some(cat) = options.category {
                        if signal.category != cat {
                            continue;
                        }
                    }
                    if let Some(st) = options.signal_type {
                        if signal.signal_type != st {
                            continue;
                        }
                    }

                    signals.push(signal.clone());
                }
            }
        }

        // Apply limit
        if let Some(limit) = options.limit {
            signals.truncate(limit);
        }

        signals
    }

    /// Get all signals matching criteria.
    pub fn get_signals(&self, options: &TrendQueryOptions) -> Vec<Signal> {
        let mut signals = Vec::new();

        for bucket in &self.buckets {
            // Apply time filters
            if let Some(from) = options.from {
                if bucket.end_timestamp < from {
                    continue;
                }
            }
            if let Some(to) = options.to {
                if bucket.timestamp > to {
                    continue;
                }
            }

            for signal in &bucket.signals {
                // Apply entity filter
                if let Some(ref entity_id) = options.entity_id {
                    if &signal.entity_id != entity_id {
                        continue;
                    }
                }

                // Apply type/category filters
                if let Some(cat) = options.category {
                    if signal.category != cat {
                        continue;
                    }
                }
                if let Some(st) = options.signal_type {
                    if signal.signal_type != st {
                        continue;
                    }
                }

                signals.push(signal.clone());
            }
        }

        // Apply limit
        if let Some(limit) = options.limit {
            signals.truncate(limit);
        }

        signals
    }

    /// Get trends summary.
    pub fn get_summary(&self, options: &TrendQueryOptions) -> TrendsSummary {
        let mut summary = TrendsSummary::default();

        let now = chrono::Utc::now().timestamp_millis();
        summary.time_range = TimeRange {
            from: options.from.unwrap_or(now - 3_600_000), // 1 hour ago
            to: options.to.unwrap_or(now),
        };

        let mut type_counts: HashMap<SignalType, usize> = HashMap::new();

        for bucket in &self.buckets {
            // Apply time filters
            if bucket.timestamp < summary.time_range.from
                || bucket.timestamp > summary.time_range.to
            {
                continue;
            }

            summary.total_signals += bucket.summary.total_count;

            for (category, cat_summary) in &bucket.summary.by_category {
                let trend_summary = summary
                    .by_category
                    .entry(*category)
                    .or_insert_with(CategoryTrendSummary::default);

                trend_summary.count += cat_summary.count;
                trend_summary.unique_values += cat_summary.unique_values.len();
                trend_summary.unique_entities += cat_summary.unique_entities.len();

                for (signal_type, count) in &cat_summary.by_type {
                    *type_counts.entry(*signal_type).or_insert(0) += count;
                }
            }
        }

        // Build top signal types
        let mut sorted_types: Vec<_> = type_counts.into_iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(&a.1));

        summary.top_signal_types = sorted_types
            .into_iter()
            .take(10)
            .map(|(signal_type, count)| TopSignalType {
                signal_type,
                category: signal_type.category(),
                count,
            })
            .collect();

        summary
    }

    /// Get detailed trends by type.
    pub fn get_trends(&self, options: &TrendQueryOptions) -> Vec<SignalTrend> {
        let mut trends: HashMap<SignalType, SignalTrend> = HashMap::new();

        for bucket in &self.buckets {
            // Apply time filters
            if let Some(from) = options.from {
                if bucket.end_timestamp < from {
                    continue;
                }
            }
            if let Some(to) = options.to {
                if bucket.timestamp > to {
                    continue;
                }
            }

            for (category, cat_summary) in &bucket.summary.by_category {
                // Apply category filter
                if let Some(cat) = options.category {
                    if *category != cat {
                        continue;
                    }
                }

                for (signal_type, count) in &cat_summary.by_type {
                    // Apply type filter
                    if let Some(st) = options.signal_type {
                        if *signal_type != st {
                            continue;
                        }
                    }

                    let trend = trends.entry(*signal_type).or_insert_with(|| SignalTrend {
                        signal_type: *signal_type,
                        category: *category,
                        count: 0,
                        unique_values: 0,
                        unique_entities: 0,
                        first_seen: bucket.timestamp,
                        last_seen: bucket.timestamp,
                        histogram: Vec::new(),
                        change_rate: 0.0,
                    });

                    trend.count += count;
                    trend.unique_values += cat_summary.unique_values.len();
                    trend.unique_entities += cat_summary.unique_entities.len();
                    trend.first_seen = trend.first_seen.min(bucket.timestamp);
                    trend.last_seen = trend.last_seen.max(bucket.timestamp);

                    trend.histogram.push(TrendHistogramBucket {
                        timestamp: bucket.timestamp,
                        count: *count,
                        unique_values: cat_summary.unique_values.len(),
                        unique_entities: cat_summary.unique_entities.len(),
                    });
                }
            }
        }

        trends.into_values().collect()
    }

    /// Get statistics.
    pub fn get_stats(&self) -> TimeStoreStats {
        TimeStoreStats {
            bucket_count: self.buckets.len(),
            total_signals: self.buckets.iter().map(|b| b.summary.total_count).sum(),
            entity_count: self.entity_index.len(),
            oldest_bucket: self.buckets.front().map(|b| b.timestamp),
            newest_bucket: self.buckets.back().map(|b| b.timestamp),
        }
    }

    /// Export buckets for persistence.
    pub fn export(&self) -> Vec<SignalBucketData> {
        self.buckets.iter().map(|b| b.to_data()).collect()
    }

    /// Import buckets from persistence.
    pub fn import(&mut self, buckets: Vec<SignalBucketData>) {
        self.clear();

        for data in buckets {
            let mut bucket = SignalBucket::new(data.timestamp, self.config.bucket_size_ms);
            bucket.end_timestamp = data.end_timestamp;
            bucket.signals = data.signals;
            bucket.summary = data.summary;
            self.buckets.push_back(bucket);
        }

        self.rebuild_entity_index();
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.buckets.clear();
        self.entity_index.clear();
        self.current_bucket_idx = None;
    }

    /// Cleanup old data.
    pub fn cleanup(&mut self) {
        let cutoff = chrono::Utc::now().timestamp_millis()
            - (self.config.retention_hours as i64 * 60 * 60 * 1000);

        while let Some(bucket) = self.buckets.front() {
            if bucket.end_timestamp < cutoff {
                self.buckets.pop_front();
            } else {
                break;
            }
        }

        self.rebuild_entity_index();
    }

    /// Destroy the store.
    pub fn destroy(&mut self) {
        self.clear();
    }
}

/// Statistics for the time store.
#[derive(Debug, Clone, Default)]
pub struct TimeStoreStats {
    pub bucket_count: usize,
    pub total_signals: usize,
    pub entity_count: usize,
    pub oldest_bucket: Option<i64>,
    pub newest_bucket: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::super::types::SignalCategory;
    use super::*;

    fn create_test_signal(entity_id: &str, timestamp: i64) -> Signal {
        Signal {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            category: SignalCategory::Network,
            signal_type: SignalType::Ip,
            value: "192.168.1.1".to_string(),
            entity_id: entity_id.to_string(),
            session_id: None,
            metadata: super::super::types::SignalMetadata::default(),
        }
    }

    #[test]
    fn test_record_signal() {
        let config = TrendsConfig::default();
        let mut store = TimeStore::new(&config);

        let signal = create_test_signal("entity-1", chrono::Utc::now().timestamp_millis());
        store.record(signal);

        let stats = store.get_stats();
        assert_eq!(stats.total_signals, 1);
        assert_eq!(stats.entity_count, 1);
    }

    #[test]
    fn test_get_signals_for_entity() {
        let config = TrendsConfig::default();
        let mut store = TimeStore::new(&config);

        let now = chrono::Utc::now().timestamp_millis();
        store.record(create_test_signal("entity-1", now));
        store.record(create_test_signal("entity-1", now + 1000));
        store.record(create_test_signal("entity-2", now + 2000));

        let signals = store.get_signals_for_entity("entity-1", &TrendQueryOptions::default());
        assert_eq!(signals.len(), 2);
    }

    #[test]
    fn test_bucket_eviction() {
        let mut config = TrendsConfig::default();
        config.retention_hours = 1;
        config.bucket_size_ms = 60_000; // 1 minute

        let mut store = TimeStore::new(&config);

        // Add signals to fill buckets
        let now = chrono::Utc::now().timestamp_millis();
        for i in 0..100 {
            store.record(create_test_signal("entity-1", now + i * 60_000));
        }

        // Should have at most 60 buckets (1 hour / 1 minute)
        let stats = store.get_stats();
        assert!(stats.bucket_count <= 60);
    }
}
