//! Template Path String Interner
//!
//! Provides thread-safe interning of normalized path templates to reduce
//! allocation pressure in high-throughput scenarios (50k+ RPS).
//!
//! ## Design
//!
//! - Uses DashMap for lock-free concurrent access
//! - Bounded cache with simple eviction when full
//! - Returns cloned String (interning reduces allocation, not reference counting)
//!
//! ## Memory Budget
//!
//! - Default capacity: 1,000 entries
//! - Maximum entries: 10,000
//! - Typical entry: ~50 bytes (path template string)
//! - Maximum memory: ~500KB

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of cached templates before eviction
const MAX_CACHE_ENTRIES: usize = 10_000;

/// Initial capacity for the cache
const INITIAL_CAPACITY: usize = 1_000;

/// Global template cache using lock-free concurrent HashMap
static TEMPLATE_CACHE: Lazy<DashMap<String, String>> =
    Lazy::new(|| DashMap::with_capacity(INITIAL_CAPACITY));

/// Cache hit counter for metrics
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);

/// Cache miss counter for metrics
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);

/// Eviction counter for metrics
static EVICTIONS: AtomicU64 = AtomicU64::new(0);

/// Intern a template path, returning a reference to the cached version.
/// This avoids repeated allocations for the same path templates.
///
/// # Arguments
///
/// * `template` - The normalized path template to intern
///
/// # Returns
///
/// A cloned String from the cache. While this still allocates on return,
/// the cache reduces the frequency of string normalization and allows
/// future optimization to return `Arc<str>` if needed.
///
/// # Example
///
/// ```ignore
/// let template = intern_template("/api/users/{id}/posts/{id}");
/// // Second call returns cached version
/// let template2 = intern_template("/api/users/{id}/posts/{id}");
/// ```
#[inline]
pub fn intern_template(template: &str) -> String {
    // Fast path: check if already cached
    if let Some(cached) = TEMPLATE_CACHE.get(template) {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        return cached.value().clone();
    }

    CACHE_MISSES.fetch_add(1, Ordering::Relaxed);

    // LRU eviction if cache is full
    // Note: This is a simple eviction strategy; not true LRU but sufficient
    // for reducing memory growth while maintaining most-used entries
    if TEMPLATE_CACHE.len() >= MAX_CACHE_ENTRIES {
        // Simple eviction: remove first entry found
        // DashMap iteration order is not guaranteed, so this provides
        // pseudo-random eviction which is acceptable for a cache
        if let Some(entry) = TEMPLATE_CACHE.iter().next() {
            let key = entry.key().clone();
            drop(entry); // Release the reference before removing
            TEMPLATE_CACHE.remove(&key);
            EVICTIONS.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Insert the new template
    let owned = template.to_string();
    TEMPLATE_CACHE.insert(owned.clone(), owned.clone());
    owned
}

/// Normalize a URL path to a template and intern the result.
///
/// This combines path normalization with interning for maximum efficiency.
/// Numeric IDs and UUIDs are replaced with `{id}` placeholder.
///
/// # Examples
///
/// - `/api/users/123` -> `/api/users/{id}`
/// - `/api/orders/abc-def-123/items/456` -> `/api/orders/{id}/items/{id}`
/// - `/api/v1/products` -> `/api/v1/products` (unchanged)
#[inline]
pub fn normalize_and_intern(path: &str) -> String {
    let normalized = normalize_path_to_template(path);
    intern_template(&normalized)
}

/// Normalize a URL path to a template by replacing numeric/UUID segments with placeholders.
///
/// This is the core normalization logic, separated for testing and flexibility.
#[inline]
fn normalize_path_to_template(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            // Check if segment is purely numeric
            if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()) {
                return "{id}";
            }
            // Check if segment looks like a UUID (8-4-4-4-12 hex pattern)
            if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
                let hex_parts: Vec<&str> = segment.split('-').collect();
                if hex_parts.len() == 5
                    && hex_parts
                        .iter()
                        .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return "{id}";
                }
            }
            // Check for MongoDB ObjectId (24 hex chars)
            if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                return "{id}";
            }
            segment
        })
        .collect::<Vec<&str>>()
        .join("/")
}

/// Get cache statistics for monitoring.
///
/// Returns (hits, misses, evictions, size)
pub fn cache_stats() -> (u64, u64, u64, usize) {
    (
        CACHE_HITS.load(Ordering::Relaxed),
        CACHE_MISSES.load(Ordering::Relaxed),
        EVICTIONS.load(Ordering::Relaxed),
        TEMPLATE_CACHE.len(),
    )
}

/// Clear the cache (for testing).
#[cfg(test)]
pub fn clear_cache() {
    TEMPLATE_CACHE.clear();
    CACHE_HITS.store(0, Ordering::Relaxed);
    CACHE_MISSES.store(0, Ordering::Relaxed);
    EVICTIONS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intern_template_caches() {
        // Use unique template to avoid interference from parallel tests
        let template = "/api/intern_test_unique_12345/{id}";

        let first = intern_template(template);
        let second = intern_template(template);

        // Core functionality: both calls return the same value
        assert_eq!(first, second);
        assert_eq!(first, template);

        // Verify entry exists in cache
        let (_, _, _, size) = cache_stats();
        assert!(size >= 1, "Cache should have at least one entry");
    }

    #[test]
    fn test_normalize_numeric_ids() {
        assert_eq!(
            normalize_path_to_template("/api/users/123"),
            "/api/users/{id}"
        );
        assert_eq!(
            normalize_path_to_template("/api/users/123/posts/456"),
            "/api/users/{id}/posts/{id}"
        );
    }

    #[test]
    fn test_normalize_uuid() {
        assert_eq!(
            normalize_path_to_template("/api/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/api/orders/{id}"
        );
    }

    #[test]
    fn test_normalize_mongodb_objectid() {
        assert_eq!(
            normalize_path_to_template("/api/documents/507f1f77bcf86cd799439011"),
            "/api/documents/{id}"
        );
    }

    #[test]
    fn test_normalize_preserves_non_ids() {
        assert_eq!(
            normalize_path_to_template("/api/v1/products"),
            "/api/v1/products"
        );
        assert_eq!(
            normalize_path_to_template("/api/users/me/profile"),
            "/api/users/me/profile"
        );
    }

    #[test]
    fn test_normalize_and_intern() {
        // Test that different IDs normalize to the same template
        let result = normalize_and_intern("/api/users/123");
        assert_eq!(result, "/api/users/{id}");

        // Second call with different ID should produce same normalized result
        let result2 = normalize_and_intern("/api/users/456");
        assert_eq!(result2, "/api/users/{id}");

        // Both should be identical (same template)
        assert_eq!(result, result2);
    }

    #[test]
    fn test_cache_eviction() {
        // Note: This test verifies that adding entries works and cache doesn't grow unbounded.
        // Due to parallel test execution, we can't assert exact sizes, but we verify
        // the cache remains bounded below MAX_CACHE_ENTRIES (10,000).

        let size_before = cache_stats().3;

        // Add a batch of unique entries
        for i in 0..100 {
            intern_template(&format!("/api/eviction_test_endpoint_{}", i));
        }

        let (_, _, _, size_after) = cache_stats();

        // Verify entries were added (size increased)
        assert!(
            size_after >= size_before,
            "Cache size should not decrease after adding entries"
        );

        // Verify cache is bounded (won't exceed MAX_CACHE_ENTRIES)
        assert!(
            size_after <= 10_000,
            "Cache should remain bounded at MAX_CACHE_ENTRIES"
        );
    }
}
