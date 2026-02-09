//! Common utilities for campaign correlation detectors
//!
//! This module provides reusable abstractions for time-windowed indexing patterns
//! that are common across multiple detectors.

use std::collections::HashSet;
use std::hash::Hash;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Generic time-windowed index for tracking entries with expiration.
///
/// Many detectors need to track entries keyed by some identifier (e.g., payload hash,
/// token fingerprint, behavior pattern) with automatic expiration of old entries.
/// This struct provides a thread-safe, generic implementation of that pattern.
///
/// # Type Parameters
///
/// * `K` - The key type (e.g., String for hashes, u64 for time buckets)
/// * `V` - The value type (e.g., IpAddr for tracking which IPs match a key)
///
/// # Example
///
/// ```ignore
/// use std::net::IpAddr;
/// use std::time::Duration;
///
/// let index: TimeWindowedIndex<String, IpAddr> = TimeWindowedIndex::new(
///     Duration::from_secs(300),  // 5 minute window
///     1000,                      // max 1000 entries per key
/// );
///
/// let ip: IpAddr = "192.168.1.1".parse().unwrap();
/// index.insert("payload_hash_123".to_string(), ip);
///
/// let ips = index.get(&"payload_hash_123".to_string());
/// ```
pub struct TimeWindowedIndex<K, V>
where
    K: Eq + Hash + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    entries: DashMap<K, Vec<(V, Instant)>>,
    window: Duration,
    max_entries_per_key: usize,
}

impl<K, V> TimeWindowedIndex<K, V>
where
    K: Eq + Hash + Clone + Send + Sync,
    V: Clone + Send + Sync,
{
    /// Create a new time-windowed index.
    ///
    /// # Arguments
    ///
    /// * `window` - Duration after which entries expire
    /// * `max_entries_per_key` - Maximum entries to retain per key (0 = unlimited)
    pub fn new(window: Duration, max_entries_per_key: usize) -> Self {
        Self {
            entries: DashMap::new(),
            window,
            max_entries_per_key,
        }
    }

    /// Add an entry with the current timestamp.
    ///
    /// This method is thread-safe and will automatically clean up expired entries
    /// for the given key during insertion.
    pub fn insert(&self, key: K, value: V) {
        let now = Instant::now();
        let cutoff = now - self.window;
        let max_entries = self.max_entries_per_key;

        self.entries
            .entry(key)
            .and_modify(|entry| {
                // Remove expired entries
                entry.retain(|(_, ts)| *ts > cutoff);

                // Add new entry
                entry.push((value.clone(), now));

                // Enforce max entries limit (keep most recent)
                if max_entries > 0 && entry.len() > max_entries {
                    // Sort by timestamp descending and truncate
                    entry.sort_by(|a, b| b.1.cmp(&a.1));
                    entry.truncate(max_entries);
                }
            })
            .or_insert_with(|| vec![(value, now)]);
    }

    /// Add an entry with a specific timestamp.
    ///
    /// Useful when recording events that occurred in the past.
    pub fn insert_with_timestamp(&self, key: K, value: V, timestamp: Instant) {
        let cutoff = Instant::now() - self.window;
        let max_entries = self.max_entries_per_key;

        self.entries
            .entry(key)
            .and_modify(|entry| {
                // Remove expired entries
                entry.retain(|(_, ts)| *ts > cutoff);

                // Add new entry
                entry.push((value.clone(), timestamp));

                // Enforce max entries limit
                if max_entries > 0 && entry.len() > max_entries {
                    entry.sort_by(|a, b| b.1.cmp(&a.1));
                    entry.truncate(max_entries);
                }
            })
            .or_insert_with(|| vec![(value, timestamp)]);
    }

    /// Get all non-expired entries for a key.
    ///
    /// Returns values without their timestamps.
    pub fn get(&self, key: &K) -> Vec<V> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(v, _)| v.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all non-expired entries for a key with their timestamps.
    pub fn get_with_timestamps(&self, key: &K) -> Vec<(V, Instant)> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the count of non-expired entries for a key.
    pub fn count(&self, key: &K) -> usize {
        let cutoff = Instant::now() - self.window;

        self.entries
            .get(key)
            .map(|entries| entries.iter().filter(|(_, ts)| *ts > cutoff).count())
            .unwrap_or(0)
    }

    /// Get all keys that have at least `min_count` non-expired entries.
    pub fn get_keys_with_min_count(&self, min_count: usize) -> Vec<K> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .iter()
            .filter_map(|entry| {
                let valid_count = entry.value().iter().filter(|(_, ts)| *ts > cutoff).count();

                if valid_count >= min_count {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Remove expired entries from all keys.
    ///
    /// Also removes keys that have no remaining entries after cleanup.
    pub fn cleanup(&self) {
        let cutoff = Instant::now() - self.window;

        // First, clean up entries within each key
        for mut entry in self.entries.iter_mut() {
            entry.value_mut().retain(|(_, ts)| *ts > cutoff);
        }

        // Then, remove empty keys
        self.entries.retain(|_, v| !v.is_empty());
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Get the total number of keys in the index.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the configured window duration.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Check if a key exists with at least one non-expired entry.
    pub fn contains_key(&self, key: &K) -> bool {
        self.count(key) > 0
    }

    /// Iterate over all keys.
    ///
    /// Note: This includes keys that may have only expired entries.
    /// Use `get_keys_with_min_count(1)` for only active keys.
    pub fn keys(&self) -> Vec<K> {
        self.entries
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if any key has the given value and meets a minimum count threshold.
    ///
    /// This is useful for determining if adding one more entry would trigger
    /// a detection threshold.
    pub fn any_key_has_value_with_min_count<F>(&self, predicate: F, min_count: usize) -> bool
    where
        F: Fn(&V) -> bool,
    {
        let cutoff = Instant::now() - self.window;

        self.entries.iter().any(|entry| {
            let entries = entry.value();
            let has_match = entries
                .iter()
                .filter(|(_, ts)| *ts > cutoff)
                .any(|(v, _)| predicate(v));

            let count = entries.iter().filter(|(_, ts)| *ts > cutoff).count();

            has_match && count >= min_count
        })
    }
}

/// Extension for `TimeWindowedIndex` when values are hashable (e.g., IpAddr).
///
/// Provides methods for getting unique values, which is common when tracking
/// which IPs have been associated with a key.
impl<K, V> TimeWindowedIndex<K, V>
where
    K: Eq + Hash + Clone + Send + Sync,
    V: Clone + Eq + Hash + Send + Sync,
{
    /// Get unique non-expired values for a key.
    ///
    /// Useful when you want to know which distinct IPs have matched a pattern,
    /// without duplicates from multiple requests from the same IP.
    pub fn get_unique(&self, key: &K) -> Vec<V> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(v, _)| v.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the count of unique non-expired values for a key.
    pub fn count_unique(&self, key: &K) -> usize {
        let cutoff = Instant::now() - self.window;

        self.entries
            .get(key)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(v, _)| v)
                    .collect::<HashSet<_>>()
                    .len()
            })
            .unwrap_or(0)
    }

    /// Get all keys that have at least `min_count` unique non-expired values.
    pub fn get_keys_with_min_unique_count(&self, min_count: usize) -> Vec<K> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .iter()
            .filter_map(|entry| {
                let unique_count = entry
                    .value()
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(v, _)| v)
                    .collect::<HashSet<_>>()
                    .len();

                if unique_count >= min_count {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get groups of keys with their unique values, filtered by minimum count.
    ///
    /// This is a common operation for campaign detection: find all keys (e.g., payload hashes)
    /// that have at least N unique values (e.g., IPs), and return those groups.
    pub fn get_groups_with_min_unique_count(&self, min_count: usize) -> Vec<(K, Vec<V>)> {
        let cutoff = Instant::now() - self.window;

        self.entries
            .iter()
            .filter_map(|entry| {
                let unique_values: HashSet<V> = entry
                    .value()
                    .iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(v, _)| v.clone())
                    .collect();

                if unique_values.len() >= min_count {
                    Some((entry.key().clone(), unique_values.into_iter().collect()))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::thread;

    #[test]
    fn test_new() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.window(), Duration::from_secs(300));
    }

    #[test]
    fn test_insert_and_get() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        index.insert("key1".to_string(), ip1);
        index.insert("key1".to_string(), ip2);
        index.insert("key2".to_string(), ip1);

        let values = index.get(&"key1".to_string());
        assert_eq!(values.len(), 2);
        assert!(values.contains(&ip1));
        assert!(values.contains(&ip2));

        let values = index.get(&"key2".to_string());
        assert_eq!(values.len(), 1);
        assert!(values.contains(&ip1));

        assert_eq!(index.len(), 2);
    }

    #[test]
    fn test_get_nonexistent_key() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let values = index.get(&"nonexistent".to_string());
        assert!(values.is_empty());
    }

    #[test]
    fn test_expiration() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_millis(50), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key".to_string(), ip);

        // Should be present initially
        assert_eq!(index.get(&"key".to_string()).len(), 1);

        // Wait for expiration
        thread::sleep(Duration::from_millis(60));

        // Should be expired now
        assert_eq!(index.get(&"key".to_string()).len(), 0);
    }

    #[test]
    fn test_count() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        index.insert("key".to_string(), ip1);
        index.insert("key".to_string(), ip2);

        assert_eq!(index.count(&"key".to_string()), 2);
        assert_eq!(index.count(&"nonexistent".to_string()), 0);
    }

    #[test]
    fn test_get_unique() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();

        // Insert same IP multiple times
        index.insert("key".to_string(), ip1);
        index.insert("key".to_string(), ip1);
        index.insert("key".to_string(), ip1);

        // Raw count includes duplicates
        assert_eq!(index.count(&"key".to_string()), 3);

        // Unique count should be 1
        let unique = index.get_unique(&"key".to_string());
        assert_eq!(unique.len(), 1);
        assert_eq!(index.count_unique(&"key".to_string()), 1);
    }

    #[test]
    fn test_get_keys_with_min_count() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        // key1 has 3 entries
        index.insert("key1".to_string(), ip1);
        index.insert("key1".to_string(), ip2);
        index.insert("key1".to_string(), ip3);

        // key2 has 1 entry
        index.insert("key2".to_string(), ip1);

        let keys = index.get_keys_with_min_count(2);
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"key1".to_string()));

        let keys = index.get_keys_with_min_count(1);
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_get_keys_with_min_unique_count() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // key1 has 2 unique IPs
        index.insert("key1".to_string(), ip1);
        index.insert("key1".to_string(), ip2);

        // key2 has 1 unique IP (same IP twice)
        index.insert("key2".to_string(), ip1);
        index.insert("key2".to_string(), ip1);

        let keys = index.get_keys_with_min_unique_count(2);
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"key1".to_string()));
    }

    #[test]
    fn test_get_groups_with_min_unique_count() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        // key1 has 3 unique IPs
        index.insert("key1".to_string(), ip1);
        index.insert("key1".to_string(), ip2);
        index.insert("key1".to_string(), ip3);

        // key2 has only 1 unique IP
        index.insert("key2".to_string(), ip1);

        let groups = index.get_groups_with_min_unique_count(2);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0, "key1");
        assert_eq!(groups[0].1.len(), 3);
    }

    #[test]
    fn test_cleanup() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_millis(50), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key".to_string(), ip);

        assert_eq!(index.len(), 1);

        // Wait for expiration
        thread::sleep(Duration::from_millis(60));

        // Cleanup should remove expired entries and empty keys
        index.cleanup();

        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
    }

    #[test]
    fn test_clear() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key1".to_string(), ip);
        index.insert("key2".to_string(), ip);

        assert_eq!(index.len(), 2);

        index.clear();

        assert_eq!(index.len(), 0);
        assert!(index.is_empty());
    }

    #[test]
    fn test_contains_key() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key".to_string(), ip);

        assert!(index.contains_key(&"key".to_string()));
        assert!(!index.contains_key(&"nonexistent".to_string()));
    }

    #[test]
    fn test_max_entries_limit() {
        let index: TimeWindowedIndex<String, u32> =
            TimeWindowedIndex::new(Duration::from_secs(300), 3);

        // Insert 5 entries
        for i in 0..5 {
            index.insert("key".to_string(), i);
        }

        // Should only keep 3 most recent
        let values = index.get(&"key".to_string());
        assert_eq!(values.len(), 3);

        // Most recent values should be kept (2, 3, 4)
        assert!(values.contains(&2));
        assert!(values.contains(&3));
        assert!(values.contains(&4));
    }

    #[test]
    fn test_keys() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key1".to_string(), ip);
        index.insert("key2".to_string(), ip);
        index.insert("key3".to_string(), ip);

        let keys = index.keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_get_with_timestamps() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        index.insert("key".to_string(), ip);

        let entries = index.get_with_timestamps(&"key".to_string());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, ip);
    }

    #[test]
    fn test_insert_with_timestamp() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let past = Instant::now() - Duration::from_secs(10);

        index.insert_with_timestamp("key".to_string(), ip, past);

        let entries = index.get_with_timestamps(&"key".to_string());
        assert_eq!(entries.len(), 1);
        // The timestamp should be the one we provided
        assert!(entries[0].1 <= Instant::now() - Duration::from_secs(9));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;

        let index: Arc<TimeWindowedIndex<String, u32>> =
            Arc::new(TimeWindowedIndex::new(Duration::from_secs(300), 1000));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let idx = Arc::clone(&index);
                thread::spawn(move || {
                    for j in 0..100 {
                        idx.insert(format!("key{}", i), j);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 10 keys
        assert_eq!(index.len(), 10);

        // Each key should have entries
        for i in 0..10 {
            assert!(index.count(&format!("key{}", i)) > 0);
        }
    }

    #[test]
    fn test_any_key_has_value_with_min_count() {
        let index: TimeWindowedIndex<String, IpAddr> =
            TimeWindowedIndex::new(Duration::from_secs(300), 100);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        // Add ip1 to key1 with 2 other IPs
        index.insert("key1".to_string(), ip1);
        index.insert("key1".to_string(), ip2);
        index.insert("key1".to_string(), ip3);

        // Add ip2 to key2 alone
        index.insert("key2".to_string(), ip2);

        // ip1 is in key1 which has 3 entries - should pass min_count of 2
        assert!(index.any_key_has_value_with_min_count(|ip| *ip == ip1, 2));

        // ip1 is in key1 which has 3 entries - should pass min_count of 3
        assert!(index.any_key_has_value_with_min_count(|ip| *ip == ip1, 3));

        // ip1 is in key1 which has 3 entries - should fail min_count of 4
        assert!(!index.any_key_has_value_with_min_count(|ip| *ip == ip1, 4));

        // ip2 is in both keys, key1 has 3 entries so should pass min_count of 2
        assert!(index.any_key_has_value_with_min_count(|ip| *ip == ip2, 2));

        // Nonexistent IP should fail
        let ip_nonexistent: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!index.any_key_has_value_with_min_count(|ip| *ip == ip_nonexistent, 1));
    }
}
