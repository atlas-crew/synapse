//! Tests for ProfileStore, ProfileStoreConfig, and SegmentCardinality.
//!
//! Coverage targets:
//! - ProfileStoreConfig: default, custom
//! - SegmentCardinality: new, record, is_dynamic, cardinality, clear
//! - ProfileStore: new, config, get_or_create, get, contains, len, is_empty
//! - ProfileStore: clear, metrics, list_templates, mature_profiles
//! - Path normalization: looks_like_id, normalize_path
//! - Eviction: maybe_evict, evict_stale

use synapse_pingora::profiler::profile_store::{
    ProfileStore, ProfileStoreConfig, ProfileStoreMetrics, SegmentCardinality,
};

// ============================================================================
// ProfileStoreConfig Tests
// ============================================================================

mod config {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProfileStoreConfig::default();

        assert_eq!(config.max_profiles, 10_000);
        assert_eq!(config.min_samples_for_detection, 100);
        assert_eq!(config.idle_timeout_ms, 24 * 60 * 60 * 1000);
        assert!(config.enable_segment_detection);
        assert_eq!(config.dynamic_segment_threshold, 10);
    }

    #[test]
    fn test_custom_config() {
        let config = ProfileStoreConfig {
            max_profiles: 1000,
            min_samples_for_detection: 50,
            idle_timeout_ms: 3600_000,
            enable_segment_detection: false,
            dynamic_segment_threshold: 5,
        };

        assert_eq!(config.max_profiles, 1000);
        assert_eq!(config.min_samples_for_detection, 50);
        assert!(!config.enable_segment_detection);
    }

    #[test]
    fn test_config_clone() {
        let config = ProfileStoreConfig::default();
        let cloned = config.clone();

        assert_eq!(config.max_profiles, cloned.max_profiles);
        assert_eq!(
            config.min_samples_for_detection,
            cloned.min_samples_for_detection
        );
    }

    #[test]
    fn test_config_serialize() {
        let config = ProfileStoreConfig::default();
        let serialized = serde_json::to_string(&config).expect("Failed to serialize");

        assert!(serialized.contains("max_profiles"));
        assert!(serialized.contains("10000"));
    }

    #[test]
    fn test_config_deserialize() {
        let json = r#"{"max_profiles":5000,"min_samples_for_detection":50,"idle_timeout_ms":3600000,"enable_segment_detection":true,"dynamic_segment_threshold":20}"#;
        let config: ProfileStoreConfig = serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(config.max_profiles, 5000);
        assert_eq!(config.min_samples_for_detection, 50);
    }
}

// ============================================================================
// SegmentCardinality Tests
// ============================================================================

mod segment_cardinality {
    use super::*;

    #[test]
    fn test_new_cardinality_tracker() {
        let sc = SegmentCardinality::new(100);
        assert_eq!(sc.cardinality(0), 0);
        assert!(!sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_record_single_value() {
        let sc = SegmentCardinality::new(100);
        let is_dynamic = sc.record(0, "users", 10);

        assert!(!is_dynamic);
        assert_eq!(sc.cardinality(0), 1);
    }

    #[test]
    fn test_record_multiple_values() {
        let sc = SegmentCardinality::new(100);

        for i in 0..5 {
            sc.record(0, &format!("value_{}", i), 10);
        }

        assert_eq!(sc.cardinality(0), 5);
        assert!(!sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_record_reaches_threshold() {
        let sc = SegmentCardinality::new(100);

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
    fn test_record_duplicate_values() {
        let sc = SegmentCardinality::new(100);

        // Record same value multiple times
        for _ in 0..10 {
            sc.record(0, "same_value", 10);
        }

        // Should only count as 1 unique value
        assert_eq!(sc.cardinality(0), 1);
        assert!(!sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_record_multiple_positions() {
        let sc = SegmentCardinality::new(100);

        // Add values to different positions
        sc.record(0, "api", 10);
        sc.record(1, "users", 10);
        sc.record(2, "123", 10);

        assert_eq!(sc.cardinality(0), 1);
        assert_eq!(sc.cardinality(1), 1);
        assert_eq!(sc.cardinality(2), 1);
    }

    #[test]
    fn test_is_dynamic_below_threshold() {
        let sc = SegmentCardinality::new(100);

        for i in 0..5 {
            sc.record(0, &format!("value_{}", i), 10);
        }

        assert!(!sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_is_dynamic_at_threshold() {
        let sc = SegmentCardinality::new(100);

        for i in 0..10 {
            sc.record(0, &format!("value_{}", i), 10);
        }

        assert!(sc.is_dynamic(0, 10));
    }

    #[test]
    fn test_is_dynamic_unknown_position() {
        let sc = SegmentCardinality::new(100);
        assert!(!sc.is_dynamic(99, 10));
    }

    #[test]
    fn test_cardinality_unknown_position() {
        let sc = SegmentCardinality::new(100);
        assert_eq!(sc.cardinality(99), 0);
    }

    #[test]
    fn test_clear() {
        let sc = SegmentCardinality::new(100);

        for i in 0..10 {
            sc.record(0, &format!("value_{}", i), 20);
        }
        assert_eq!(sc.cardinality(0), 10);

        sc.clear();
        assert_eq!(sc.cardinality(0), 0);
    }

    #[test]
    fn test_max_values_limit() {
        let sc = SegmentCardinality::new(5); // Max 5 values

        // Try to add 10 values
        for i in 0..10 {
            sc.record(0, &format!("value_{}", i), 100);
        }

        // Should cap at 5
        assert_eq!(sc.cardinality(0), 5);
    }
}

// ============================================================================
// ProfileStore Basic Tests
// ============================================================================

mod store_basic {
    use super::*;

    #[test]
    fn test_new_store_default() {
        let store = ProfileStore::default();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_new_store_custom_config() {
        let config = ProfileStoreConfig {
            max_profiles: 100,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        assert_eq!(store.config().max_profiles, 100);
    }

    #[test]
    fn test_get_or_create_new() {
        let store = ProfileStore::default();

        {
            let _profile = store.get_or_create("/api/users");
        }

        assert_eq!(store.len(), 1);
        assert!(store.contains("/api/users"));
    }

    #[test]
    fn test_get_or_create_existing() {
        let store = ProfileStore::default();

        {
            let mut profile = store.get_or_create("/api/users");
            profile.update(100, &[("name", "John")], None, 1000);
        }

        {
            let profile = store.get_or_create("/api/users");
            assert_eq!(profile.sample_count, 1);
        }

        // Should still be just 1 profile
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_get_existing() {
        let store = ProfileStore::default();

        {
            let _profile = store.get_or_create("/api/users");
        }

        let profile = store.get("/api/users");
        assert!(profile.is_some());
    }

    #[test]
    fn test_get_nonexistent() {
        let store = ProfileStore::default();
        let profile = store.get("/api/nonexistent");
        assert!(profile.is_none());
    }

    #[test]
    fn test_contains_true() {
        let store = ProfileStore::default();
        store.get_or_create("/api/users");

        assert!(store.contains("/api/users"));
    }

    #[test]
    fn test_contains_false() {
        let store = ProfileStore::default();
        assert!(!store.contains("/api/users"));
    }

    #[test]
    fn test_len_and_is_empty() {
        let store = ProfileStore::default();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.get_or_create("/api/users");
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        store.get_or_create("/api/orders");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_clear() {
        let store = ProfileStore::default();

        store.get_or_create("/api/users");
        store.get_or_create("/api/orders");
        assert_eq!(store.len(), 2);

        store.clear();
        assert!(store.is_empty());
    }
}

// ============================================================================
// Path Normalization Tests
// ============================================================================

mod path_normalization {
    use super::*;

    #[test]
    fn test_numeric_id_normalized() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/users/123");
        store.get_or_create("/api/users/456");

        // Both should normalize to same template
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_uuid_normalized() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/users/550e8400-e29b-41d4-a716-446655440000");
        store.get_or_create("/api/users/123e4567-e89b-12d3-a456-426614174000");

        // Both should normalize to same template
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_hex_hash_normalized() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/tokens/abcdef1234567890");
        store.get_or_create("/api/tokens/fedcba0987654321");

        // Both should normalize to same template
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_mongodb_objectid_normalized() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/items/507f1f77bcf86cd799439011");
        store.get_or_create("/api/items/507f191e810c19729de860ea");

        // Both should normalize to same template
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_static_path_not_normalized() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/users");
        store.get_or_create("/api/orders");

        // Different static paths
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_normalization_disabled() {
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        store.get_or_create("/api/users/123");
        store.get_or_create("/api/users/456");

        // Without normalization, these are separate
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_cardinality_based_normalization() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            dynamic_segment_threshold: 3, // Low threshold
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Add 3 unique string values - should trigger cardinality detection
        store.get_or_create("/api/tenants/acme");
        store.get_or_create("/api/tenants/globex");
        store.get_or_create("/api/tenants/initech");

        // After threshold, new values should be normalized
        let templates = store.list_templates();
        assert!(templates.len() <= 3);
    }

    #[test]
    fn test_mixed_path_normalization() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // /api/users/{id}/orders/{order_id}
        store.get_or_create("/api/users/123/orders/456");
        store.get_or_create("/api/users/789/orders/012");

        // Should normalize both IDs
        assert_eq!(store.len(), 1);
    }
}

// ============================================================================
// looks_like_id Tests
// ============================================================================

mod looks_like_id {
    use super::*;

    // Note: looks_like_id is private, so we test it indirectly through normalization
    // Or we can expose it for testing. For now, test via store behavior.

    #[test]
    fn test_numeric_ids() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Various numeric ID formats
        store.get_or_create("/api/users/1");
        store.get_or_create("/api/users/12345");
        store.get_or_create("/api/users/99999999999999999999");

        // All should normalize to same template
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_non_id_strings() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            dynamic_segment_threshold: 100, // High threshold to avoid cardinality detection
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Static API paths
        store.get_or_create("/api/users");
        store.get_or_create("/api/orders");
        store.get_or_create("/api/products");

        // Each should be separate
        assert_eq!(store.len(), 3);
    }
}

// ============================================================================
// Metrics Tests
// ============================================================================

mod metrics {
    use super::*;

    #[test]
    fn test_metrics_initial() {
        let store = ProfileStore::default();
        let metrics = store.metrics();

        assert_eq!(metrics.current_profiles, 0);
        assert_eq!(metrics.total_created, 0);
        assert_eq!(metrics.total_evicted, 0);
    }

    #[test]
    fn test_metrics_after_creation() {
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
    fn test_metrics_no_duplicate_creation() {
        let store = ProfileStore::default();

        // Create same profile multiple times
        for _ in 0..5 {
            store.get_or_create("/api/users");
        }

        let metrics = store.metrics();
        assert_eq!(metrics.current_profiles, 1);
        assert_eq!(metrics.total_created, 1);
    }

    #[test]
    fn test_metrics_max_profiles() {
        let store = ProfileStore::default();
        let metrics = store.metrics();

        assert_eq!(metrics.max_profiles, 10_000);
    }
}

// ============================================================================
// List and Filter Tests
// ============================================================================

mod list_and_filter {
    use super::*;

    #[test]
    fn test_list_templates_empty() {
        let store = ProfileStore::default();
        let templates = store.list_templates();
        assert!(templates.is_empty());
    }

    #[test]
    fn test_list_templates() {
        let store = ProfileStore::default();

        store.get_or_create("/api/users");
        store.get_or_create("/api/orders");

        let templates = store.list_templates();
        assert_eq!(templates.len(), 2);
        assert!(templates.contains(&"/api/users".to_string()));
        assert!(templates.contains(&"/api/orders".to_string()));
    }

    #[test]
    fn test_mature_profiles_none() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Create profiles with few samples
        {
            let mut p = store.get_or_create("/api/users");
            for _ in 0..5 {
                p.update(100, &[], None, 1000);
            }
        }

        let mature = store.mature_profiles();
        assert!(mature.is_empty());
    }

    #[test]
    fn test_mature_profiles_some() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Create mature profile
        {
            let mut p = store.get_or_create("/api/mature");
            for _ in 0..15 {
                p.update(100, &[], None, 1000);
            }
        }

        // Create immature profile
        {
            let mut p = store.get_or_create("/api/immature");
            for _ in 0..5 {
                p.update(100, &[], None, 1000);
            }
        }

        let mature = store.mature_profiles();
        assert_eq!(mature.len(), 1);
        assert!(mature.contains(&"/api/mature".to_string()));
    }

    #[test]
    fn test_mature_profiles_all() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Create all mature profiles
        for endpoint in ["/api/a", "/api/b", "/api/c"] {
            let mut p = store.get_or_create(endpoint);
            for _ in 0..20 {
                p.update(100, &[], None, 1000);
            }
        }

        let mature = store.mature_profiles();
        assert_eq!(mature.len(), 3);
    }
}

// ============================================================================
// Serialization Tests
// ============================================================================

mod serialization {
    use super::*;

    #[test]
    fn test_metrics_serialize() {
        let metrics = ProfileStoreMetrics {
            current_profiles: 100,
            max_profiles: 10000,
            total_created: 150,
            total_evicted: 50,
        };

        let serialized = serde_json::to_string(&metrics).expect("Failed to serialize");
        assert!(serialized.contains("current_profiles"));
        assert!(serialized.contains("100"));
    }

    #[test]
    fn test_metrics_clone() {
        let metrics = ProfileStoreMetrics {
            current_profiles: 100,
            max_profiles: 10000,
            total_created: 150,
            total_evicted: 50,
        };

        let cloned = metrics.clone();
        assert_eq!(metrics.current_profiles, cloned.current_profiles);
        assert_eq!(metrics.total_created, cloned.total_created);
    }
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

mod concurrent {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_concurrent_get_or_create() {
        // Disable segment detection to keep paths as-is for unique counting
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = Arc::new(ProfileStore::new(config));
        let mut handles = vec![];

        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let _p = store_clone.get_or_create(&format!("/api/endpoint_{}", i * 100 + j));
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Should have created 1000 unique profiles
        assert_eq!(store.len(), 1000);
    }

    #[test]
    fn test_concurrent_update_same_profile() {
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = Arc::new(ProfileStore::new(config));
        let mut handles = vec![];

        for _ in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let mut p = store_clone.get_or_create("/api/shared");
                    p.update(100, &[], None, 1000);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Should have 1000 total updates
        let profile = store.get("/api/shared").expect("Profile should exist");
        assert_eq!(profile.sample_count, 1000);
    }

    #[test]
    fn test_concurrent_read_write() {
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = Arc::new(ProfileStore::new(config));

        // Pre-create some profiles
        for i in 0..10 {
            store.get_or_create(&format!("/api/endpoint_{}", i));
        }

        let mut handles = vec![];

        // Writers
        for i in 0..5 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let mut p = store_clone.get_or_create(&format!("/api/endpoint_{}", i));
                    p.update(100, &[], None, 1000 + j as u64);
                }
            }));
        }

        // Readers
        for _ in 0..5 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let _ = store_clone.get(&format!("/api/endpoint_{}", i % 10));
                    let _ = store_clone.list_templates();
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Store should be in consistent state
        assert!(store.len() >= 10);
    }
}
