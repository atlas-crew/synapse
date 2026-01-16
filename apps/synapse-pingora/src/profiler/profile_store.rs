//! Thread-safe profile storage with LRU eviction.
//!
//! Provides concurrent access to endpoint profiles using DashMap.
//! Includes dynamic path segment detection for template normalization.
//!
//! ## Memory Budget
//! Default: 10,000 profiles * ~2KB = ~20MB

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::profiler::endpoint_profile::EndpointProfile;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for profile storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStoreConfig {
    /// Maximum number of endpoint profiles to store.
    pub max_profiles: usize,
    /// Minimum samples before profile is used for anomaly detection.
    pub min_samples_for_detection: u32,
    /// Profile idle timeout (ms) - profiles not seen for this long are eviction candidates.
    pub idle_timeout_ms: u64,
    /// Enable dynamic path segment detection.
    pub enable_segment_detection: bool,
    /// Cardinality threshold for path segment to be considered dynamic.
    pub dynamic_segment_threshold: usize,
}

impl Default for ProfileStoreConfig {
    fn default() -> Self {
        Self {
            max_profiles: 10_000,
            min_samples_for_detection: 100,
            idle_timeout_ms: 24 * 60 * 60 * 1000, // 24 hours
            enable_segment_detection: true,
            dynamic_segment_threshold: 10,
        }
    }
}

// ============================================================================
// SegmentCardinality - Dynamic path segment detection
// ============================================================================

/// Tracks unique values for each path segment position to detect dynamic segments.
///
/// Example: If position 2 in "/api/users/{id}" sees 100+ unique values,
/// that segment is marked as dynamic (variable).
#[derive(Debug, Default)]
pub struct SegmentCardinality {
    /// Position -> Set of unique values seen
    /// Uses HashSet with capacity limit for memory protection
    segments: DashMap<usize, HashSet<String>>,
    /// Maximum unique values to track per position
    max_values: usize,
}

impl SegmentCardinality {
    /// Create a new cardinality tracker.
    pub fn new(max_values: usize) -> Self {
        Self {
            segments: DashMap::new(),
            max_values,
        }
    }

    /// Record a path segment value at a position.
    /// Returns true if the segment appears to be dynamic (high cardinality).
    pub fn record(&self, position: usize, value: &str, threshold: usize) -> bool {
        let mut entry = self.segments.entry(position).or_insert_with(HashSet::new);
        let values = entry.value_mut();

        // Don't track beyond max_values (memory protection)
        if values.len() < self.max_values {
            values.insert(value.to_string());
        }

        values.len() >= threshold
    }

    /// Check if a position appears dynamic (has high cardinality).
    pub fn is_dynamic(&self, position: usize, threshold: usize) -> bool {
        self.segments
            .get(&position)
            .map(|v| v.len() >= threshold)
            .unwrap_or(false)
    }

    /// Get cardinality at a position.
    pub fn cardinality(&self, position: usize) -> usize {
        self.segments.get(&position).map(|v| v.len()).unwrap_or(0)
    }

    /// Clear all tracked data.
    pub fn clear(&self) {
        self.segments.clear();
    }
}

// ============================================================================
// ProfileStore - Thread-safe storage
// ============================================================================

/// Thread-safe storage for endpoint profiles.
///
/// Uses DashMap for lock-free concurrent access.
pub struct ProfileStore {
    /// Profiles by template path.
    profiles: DashMap<String, EndpointProfile>,
    /// Configuration.
    config: ProfileStoreConfig,
    /// Segment cardinality tracker for dynamic path detection.
    segment_cardinality: SegmentCardinality,
    /// Total profiles created (lifetime).
    total_created: AtomicU64,
    /// Total profiles evicted (lifetime).
    total_evicted: AtomicU64,
    /// Last eviction timestamp (ms).
    last_eviction_ms: AtomicU64,
}

impl Default for ProfileStore {
    fn default() -> Self {
        Self::new(ProfileStoreConfig::default())
    }
}

impl ProfileStore {
    /// Create a new profile store with configuration.
    pub fn new(config: ProfileStoreConfig) -> Self {
        let max_segment_values = config.dynamic_segment_threshold * 2;
        Self {
            profiles: DashMap::with_capacity(config.max_profiles / 2),
            config,
            segment_cardinality: SegmentCardinality::new(max_segment_values),
            total_created: AtomicU64::new(0),
            total_evicted: AtomicU64::new(0),
            last_eviction_ms: AtomicU64::new(0),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &ProfileStoreConfig {
        &self.config
    }

    /// Get or create a profile for a path.
    ///
    /// Normalizes the path to a template if dynamic segment detection is enabled.
    pub fn get_or_create(&self, path: &str) -> dashmap::mapref::one::RefMut<String, EndpointProfile> {
        let template = if self.config.enable_segment_detection {
            self.normalize_path(path)
        } else {
            path.to_string()
        };

        let now_ms = now_ms();

        // Check capacity and evict if needed
        self.maybe_evict(now_ms);

        self.profiles.entry(template.clone()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            EndpointProfile::new(template, now_ms)
        })
    }

    /// Get an existing profile (read-only).
    pub fn get(&self, template: &str) -> Option<dashmap::mapref::one::Ref<String, EndpointProfile>> {
        self.profiles.get(template)
    }

    /// Check if a profile exists.
    pub fn contains(&self, template: &str) -> bool {
        self.profiles.contains_key(template)
    }

    /// Get number of stored profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Check if store is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// Normalize a path to a template by replacing dynamic segments.
    ///
    /// Example: "/api/users/12345/orders" -> "/api/users/{id}/orders"
    fn normalize_path(&self, path: &str) -> String {
        let segments: Vec<&str> = path.split('/').collect();
        let threshold = self.config.dynamic_segment_threshold;

        let normalized: Vec<String> = segments
            .iter()
            .enumerate()
            .map(|(pos, segment)| {
                if segment.is_empty() {
                    return String::new();
                }

                // Check if this looks like an ID (numeric, UUID-like, etc.)
                let looks_dynamic = Self::looks_like_id(segment);

                // Record cardinality
                let is_high_cardinality = self.segment_cardinality.record(pos, segment, threshold);

                if looks_dynamic || is_high_cardinality {
                    "{id}".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect();

        normalized.join("/")
    }

    /// Check if a segment looks like an ID (numeric, UUID, hex hash, etc.).
    fn looks_like_id(segment: &str) -> bool {
        // Empty segments are not IDs
        if segment.is_empty() {
            return false;
        }

        // Pure numeric (user IDs, etc.)
        if segment.chars().all(|c| c.is_ascii_digit()) {
            return segment.len() >= 1 && segment.len() <= 20; // Reasonable ID length
        }

        // UUID format: 8-4-4-4-12 hex
        if segment.len() == 36
            && segment
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-')
        {
            return true;
        }

        // Hex string (16+ chars, common for hashes/tokens)
        if segment.len() >= 16 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        // MongoDB ObjectId (24 hex chars)
        if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }

        false
    }

    /// Evict profiles if at capacity.
    fn maybe_evict(&self, now_ms: u64) {
        // Only check eviction periodically (every 1000ms)
        let last = self.last_eviction_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 1000 {
            return;
        }

        if self.profiles.len() < self.config.max_profiles {
            return;
        }

        self.last_eviction_ms.store(now_ms, Ordering::Relaxed);
        self.evict_stale(now_ms);
    }

    /// Evict stale profiles (not seen within idle timeout).
    fn evict_stale(&self, now_ms: u64) {
        let idle_timeout = self.config.idle_timeout_ms;
        let cutoff = now_ms.saturating_sub(idle_timeout);

        // Collect keys to remove (to avoid holding refs during iteration)
        let stale_keys: Vec<String> = self
            .profiles
            .iter()
            .filter(|entry| entry.value().last_updated_ms < cutoff)
            .map(|entry| entry.key().clone())
            .take(100) // Batch size
            .collect();

        for key in stale_keys {
            if self.profiles.remove(&key).is_some() {
                self.total_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Clear all profiles.
    pub fn clear(&self) {
        self.profiles.clear();
        self.segment_cardinality.clear();
    }

    /// Get store metrics.
    pub fn metrics(&self) -> ProfileStoreMetrics {
        ProfileStoreMetrics {
            current_profiles: self.profiles.len(),
            max_profiles: self.config.max_profiles,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_evicted: self.total_evicted.load(Ordering::Relaxed),
        }
    }

    /// List all profile templates.
    pub fn list_templates(&self) -> Vec<String> {
        self.profiles.iter().map(|e| e.key().clone()).collect()
    }

    /// Get mature profiles (those with enough samples for detection).
    pub fn mature_profiles(&self) -> Vec<String> {
        let min = self.config.min_samples_for_detection;
        self.profiles
            .iter()
            .filter(|e| e.value().is_mature(min))
            .map(|e| e.key().clone())
            .collect()
    }
}

/// Profile store metrics.
#[derive(Debug, Clone, Serialize)]
pub struct ProfileStoreMetrics {
    pub current_profiles: usize,
    pub max_profiles: usize,
    pub total_created: u64,
    pub total_evicted: u64,
}

/// Get current time in milliseconds.
#[inline]
fn now_ms() -> u64 {
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

    #[test]
    fn test_segment_cardinality_basic() {
        let sc = SegmentCardinality::new(100);

        // Add values to position 0
        for i in 0..5 {
            sc.record(0, &format!("value_{}", i), 10);
        }

        assert_eq!(sc.cardinality(0), 5);
        assert!(!sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_segment_cardinality_threshold() {
        let sc = SegmentCardinality::new(100);

        // Add 10 values
        for i in 0..10 {
            let is_dynamic = sc.record(0, &format!("value_{}", i), 10);
            if i < 9 {
                assert!(!is_dynamic);
            } else {
                assert!(is_dynamic);
            }
        }

        assert!(sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_profile_store_basic() {
        let store = ProfileStore::default();

        {
            let mut profile = store.get_or_create("/api/users");
            profile.update(100, &["name"], Some("application/json"), now_ms());
        }

        assert_eq!(store.len(), 1);
        assert!(store.contains("/api/users"));
    }

    #[test]
    fn test_profile_store_path_normalization() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            dynamic_segment_threshold: 2,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Access paths with numeric IDs
        store.get_or_create("/api/users/123/orders");
        store.get_or_create("/api/users/456/orders");

        // Both should normalize to the same template
        assert_eq!(store.len(), 1);

        let templates = store.list_templates();
        assert!(templates[0].contains("{id}"));
    }

    #[test]
    fn test_looks_like_id() {
        // Numeric IDs
        assert!(ProfileStore::looks_like_id("123"));
        assert!(ProfileStore::looks_like_id("12345678901234567890"));
        assert!(!ProfileStore::looks_like_id("123456789012345678901")); // Too long

        // UUIDs
        assert!(ProfileStore::looks_like_id(
            "550e8400-e29b-41d4-a716-446655440000"
        ));

        // Hex hashes
        assert!(ProfileStore::looks_like_id("abcdef1234567890"));
        assert!(!ProfileStore::looks_like_id("abcdef12345")); // Too short

        // MongoDB ObjectId
        assert!(ProfileStore::looks_like_id("507f1f77bcf86cd799439011"));

        // Non-IDs
        assert!(!ProfileStore::looks_like_id("users"));
        assert!(!ProfileStore::looks_like_id("api"));
        assert!(!ProfileStore::looks_like_id(""));
    }

    #[test]
    fn test_profile_store_without_normalization() {
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/users/123");
        store.get_or_create("/api/users/456");

        // Without normalization, these should be separate
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_profile_store_metrics() {
        let store = ProfileStore::default();

        for i in 0..5 {
            store.get_or_create(&format!("/api/endpoint_{}", i));
        }

        let metrics = store.metrics();
        assert_eq!(metrics.current_profiles, 5);
        assert_eq!(metrics.total_created, 5);
        assert_eq!(metrics.total_evicted, 0);
    }

    #[test]
    fn test_profile_store_clear() {
        let store = ProfileStore::default();

        for i in 0..5 {
            store.get_or_create(&format!("/api/endpoint_{}", i));
        }
        assert_eq!(store.len(), 5);

        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_profile_store_mature_profiles() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Create one mature and one immature profile
        {
            let mut p1 = store.get_or_create("/api/mature");
            for _ in 0..15 {
                p1.update(100, &[], None, now_ms());
            }
        }
        {
            let mut p2 = store.get_or_create("/api/immature");
            for _ in 0..5 {
                p2.update(100, &[], None, now_ms());
            }
        }

        let mature = store.mature_profiles();
        assert_eq!(mature.len(), 1);
        assert!(mature.contains(&"/api/mature".to_string()));
    }

    #[test]
    fn test_segment_cardinality_clear() {
        let sc = SegmentCardinality::new(100);

        for i in 0..10 {
            sc.record(0, &format!("value_{}", i), 20);
        }
        assert_eq!(sc.cardinality(0), 10);

        sc.clear();
        assert_eq!(sc.cardinality(0), 0);
    }

    #[test]
    fn test_segment_cardinality_max_values() {
        let sc = SegmentCardinality::new(5); // Max 5 values

        // Try to add 10 values
        for i in 0..10 {
            sc.record(0, &format!("value_{}", i), 100);
        }

        // Should cap at 5
        assert_eq!(sc.cardinality(0), 5);
    }
}
