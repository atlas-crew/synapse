//! Integration tests for the profiler module.
//!
//! Tests the interaction between components:
//! - ProfileStore + EndpointProfile
//! - Distribution + anomaly detection
//! - Full request profiling workflow
//!
//! Scenarios:
//! - API endpoint profiling workflow
//! - Anomaly detection based on learned baselines
//! - Memory bounds and eviction
//! - Concurrent profiling

use std::sync::Arc;
use std::thread;

use synapse_pingora::profiler::{
    AnomalyResult, AnomalySignalType, Distribution, EndpointProfile, ProfileStore,
    ProfileStoreConfig, RateTracker,
};

// ============================================================================
// End-to-End Profiling Workflow
// ============================================================================

mod e2e_workflow {
    use super::*;

    #[test]
    fn test_basic_profiling_workflow() {
        // Simulate a complete profiling workflow for an API endpoint
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // 1. Learning phase: receive 20 normal requests
        for i in 0..20 {
            let mut profile = store.get_or_create("/api/users/123");
            profile.update(
                1000 + (i % 200) as usize, // Payload size ~1000 bytes with variance
                &[("name", "John"), ("email", "john@example.com")],
                Some("application/json"),
                1000 + i * 100,
            );
            profile.record_status(200);
        }

        // 2. Verify baseline was learned
        let profile = store.get("/api/users/{id}").expect("Profile should exist");
        assert!(profile.is_mature(10));
        assert!(profile.param_frequency("name") > 0.9);
        assert!(profile.param_frequency("email") > 0.9);
        assert_eq!(profile.dominant_content_type(), Some("application/json"));
    }

    #[test]
    fn test_anomaly_detection_workflow() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Learning phase - add variance to payload sizes for meaningful z-scores
        for i in 0..100 {
            let mut profile = store.get_or_create("/api/data");
            profile.update(
                900 + (i % 200) as usize, // Payload 900-1099, mean ~1000
                &[("query", "search term")],
                Some("application/json"),
                i * 100,
            );
        }

        // Get learned profile
        let profile = store.get("/api/data").unwrap();

        // Detect anomalies for an abnormal request
        let mut result = AnomalyResult::new();

        // Check payload size anomaly
        let test_payload = 50000; // 50KB vs 1KB baseline
        let z_score = profile.payload_size.z_score(test_payload as f64);
        if z_score > 3.0 {
            result.add(
                AnomalySignalType::PayloadSizeHigh,
                5,
                format!("Payload {}B, z-score {:.1}", test_payload, z_score),
            );
        }

        // Check unexpected parameter
        let unexpected_params: Vec<&str> = vec!["malicious_param"]
            .into_iter()
            .filter(|p| !profile.expected_params.contains_key(*p))
            .collect();
        if !unexpected_params.is_empty() {
            result.add(
                AnomalySignalType::UnexpectedParam,
                3,
                format!("{} unexpected params", unexpected_params.len()),
            );
        }

        // Should have detected anomalies
        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 2);
    }

    #[test]
    fn test_content_type_mismatch_detection() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Learn JSON content type
        for _ in 0..20 {
            let mut profile = store.get_or_create("/api/submit");
            profile.update(100, &[], Some("application/json"), 1000);
        }

        // Check for content type mismatch
        let profile = store.get("/api/submit").unwrap();
        let test_content_type = "text/xml";

        let mut result = AnomalyResult::new();
        if !profile.content_types.contains_key(test_content_type) {
            result.add(
                AnomalySignalType::ContentTypeMismatch,
                5,
                format!("Unexpected content type: {}", test_content_type),
            );
        }

        assert!(result.has_anomalies());
        assert!(result
            .signal_types()
            .contains(&AnomalySignalType::ContentTypeMismatch));
    }
}

// ============================================================================
// Distribution + Anomaly Detection
// ============================================================================

mod distribution_anomalies {
    use super::*;

    #[test]
    fn test_payload_size_distribution_anomaly() {
        let mut dist = Distribution::new();

        // Learn baseline: ~1000 bytes with some variance (950-1049, mean ~1000)
        for i in 0..100 {
            dist.update(950.0 + i as f64);
        }

        // Normal request
        let normal_z = dist.z_score(1000.0);
        assert!(normal_z.abs() < 1.0);

        // Anomalous request (10x baseline)
        let anomalous_z = dist.z_score(10000.0);
        assert!(anomalous_z > 3.0);

        // Create anomaly result based on z-score
        let mut result = AnomalyResult::new();
        if anomalous_z > 3.0 {
            let severity = ((anomalous_z - 2.0) as u8).clamp(1, 8);
            result.add(
                AnomalySignalType::PayloadSizeHigh,
                severity,
                format!("z-score: {:.1}", anomalous_z),
            );
        }

        assert!(result.has_anomalies());
    }

    #[test]
    fn test_latency_distribution_percentiles() {
        let mut dist = Distribution::new();

        // Simulate response times: mostly fast, some slow
        for _ in 0..90 {
            dist.update(50.0); // 50ms fast responses
        }
        for _ in 0..10 {
            dist.update(500.0); // 500ms slow responses
        }

        let (p50, p95, p99) = dist.percentiles();

        // p50 should be around 50ms (fast)
        assert!(p50 < 100.0);
        // p95/p99 should capture slower responses
        assert!(p95 > 50.0);
    }
}

// ============================================================================
// Rate Tracking + Burst Detection
// ============================================================================

mod rate_detection {
    use super::*;

    #[test]
    fn test_rate_burst_detection() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 0);

        // Establish a sparse baseline: 1 req every 10 seconds over 300 seconds (6 req/min)
        // This keeps the buffer from being overwhelmed
        for i in 0..30 {
            profile.update(100, &[], None, i * 10_000);
        }

        // Now simulate a burst: 30 requests in 1 second
        // After the burst, buffer has 30 baseline + 30 burst = 60 entries
        let burst_start = 300_000u64;
        for i in 0..30 {
            profile.update(100, &[], None, burst_start + i * 33);
        }

        // Check if this is detected as a burst
        // At time burst_start + 1000, the 60-second window captures the burst
        let current_rate = profile.request_rate.current_rate(burst_start + 1000);
        let baseline = profile.baseline_rate(burst_start + 1000);

        // Current rate should be significantly higher than baseline
        // baseline = 60 / (5 min) = 12 req/min
        // current_rate should be ~30 (burst in last 60s window) or higher
        let is_burst = current_rate > baseline * 2.0;
        assert!(
            is_burst,
            "Current: {}, Baseline: {}",
            current_rate, baseline
        );
    }

    #[test]
    fn test_rate_tracker_integration() {
        let mut tracker = RateTracker::new();

        // Simulate normal traffic
        for i in 0..10 {
            tracker.record(i * 1000);
        }

        let normal_rate = tracker.current_rate(10_000);

        // Simulate burst
        for _ in 0..50 {
            tracker.record(11_000);
        }

        let burst_rate = tracker.current_rate(12_000);

        // Burst rate should be much higher
        assert!(burst_rate > normal_rate * 3.0);
    }
}

// ============================================================================
// Memory Bounds and Eviction
// ============================================================================

mod memory_bounds {
    use super::*;

    #[test]
    fn test_profile_memory_bounds() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Try to add more than max content types
        for i in 0..30 {
            profile.update(100, &[], Some(&format!("type-{}", i)), 1000);
        }

        // Should be bounded at MAX_CONTENT_TYPES (20)
        assert!(profile.content_types.len() <= 20);
    }

    #[test]
    fn test_store_path_normalization_prevents_explosion() {
        let config = ProfileStoreConfig {
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Simulate 1000 requests with unique IDs
        for i in 0..1000 {
            store.get_or_create(&format!("/api/users/{}/profile", i));
        }

        // Should normalize to a small number of templates
        assert!(store.len() < 100, "Store has {} profiles", store.len());
    }

    #[test]
    fn test_param_eviction_under_load() {
        let mut profile = EndpointProfile::new("/api/test".to_string(), 1000);

        // Add a frequently used param first
        for _ in 0..100 {
            profile.update(100, &[("important_param", "value")], None, 1000);
        }

        // Flood with unique params
        for i in 0..100 {
            let param_name = format!("spam_param_{}", i);
            profile.update(100, &[(&param_name, "value")], None, 1000);
        }

        // Important param should survive eviction
        assert!(profile.expected_params.contains_key("important_param"));
        assert!(profile.expected_params.len() <= 50);
    }
}

// ============================================================================
// Concurrent Profiling
// ============================================================================

mod concurrent_profiling {
    use super::*;

    #[test]
    fn test_concurrent_endpoint_profiling() {
        let config = ProfileStoreConfig {
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = Arc::new(ProfileStore::new(config));

        let mut handles = vec![];

        // Simulate 10 concurrent clients
        for client_id in 0..10 {
            let store_clone = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                // Each client makes 100 requests
                for req in 0..100 {
                    let endpoint = format!("/api/endpoint_{}", client_id % 5);
                    let mut profile = store_clone.get_or_create(&endpoint);
                    let client_id_str = client_id.to_string();
                    profile.update(
                        100 + client_id * 10,
                        &[("client_id", &client_id_str)],
                        Some("application/json"),
                        (client_id * 1000 + req) as u64,
                    );
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // Should have 5 endpoints (client_id % 5)
        assert_eq!(store.len(), 5);

        // Each endpoint should have 200 samples (2 clients per endpoint * 100 requests)
        for i in 0..5 {
            let profile = store.get(&format!("/api/endpoint_{}", i)).unwrap();
            assert_eq!(profile.sample_count, 200);
        }
    }

    #[test]
    fn test_concurrent_anomaly_tracking() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = Arc::new(ProfileStore::new(config));

        // Phase 1: Learning (sequential for determinism)
        // Add variance to payload sizes for meaningful z-scores
        for i in 0..100 {
            let mut profile = store.get_or_create("/api/monitored");
            profile.update(
                900 + (i % 200) as usize, // 900-1099, mean ~1000
                &[("normal_param", "value")],
                Some("application/json"),
                i,
            );
        }

        // Phase 2: Concurrent detection
        let store_ref = &store;
        let results: Vec<_> = (0..10)
            .map(|_| {
                let profile = store_ref.get("/api/monitored").unwrap();

                let mut result = AnomalyResult::new();

                // Check for anomaly
                let z_score = profile.payload_size.z_score(50000.0);
                if z_score > 3.0 {
                    result.add(
                        AnomalySignalType::PayloadSizeHigh,
                        5,
                        "Large payload".to_string(),
                    );
                }

                if !profile.expected_params.contains_key("attack_param") {
                    result.add(
                        AnomalySignalType::UnexpectedParam,
                        3,
                        "Unexpected".to_string(),
                    );
                }

                result
            })
            .collect();

        // All concurrent checks should detect the same anomalies
        for result in results {
            assert!(result.has_anomalies());
            assert_eq!(result.signal_count(), 2);
        }
    }
}

// ============================================================================
// Real-World Scenarios
// ============================================================================

mod scenarios {
    use super::*;

    #[test]
    fn test_api_fuzzing_detection() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 50,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Establish baseline
        for i in 0..100 {
            let mut profile = store.get_or_create("/api/search");
            profile.update(
                200,
                &[("q", "search"), ("page", "1"), ("limit", "10")],
                Some("application/json"),
                i * 100,
            );
        }

        // Simulate fuzzing attack with many unexpected params
        let profile = store.get("/api/search").unwrap();
        let attack_params = vec!["<script>", "OR 1=1", "../../etc/passwd", "{{template}}"];

        let mut result = AnomalyResult::new();
        let unexpected: Vec<_> = attack_params
            .iter()
            .filter(|&p| profile.expected_params.get::<str>(p).is_none())
            .collect();

        if !unexpected.is_empty() {
            result.add(
                AnomalySignalType::UnexpectedParam,
                (unexpected.len() as u8).min(10),
                format!("{} unexpected params detected", unexpected.len()),
            );
        }

        assert!(result.has_anomalies());
        assert_eq!(result.signal_count(), 1);
    }

    #[test]
    fn test_data_exfiltration_attempt() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 50,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Normal API responses are small (add variance for meaningful z-scores)
        for i in 0..100 {
            let mut profile = store.get_or_create("/api/user/profile");
            profile.update(
                400 + (i % 200) as usize, // 400-599, mean ~500
                &[("user_id", "123")],
                Some("application/json"),
                i * 100,
            );
            profile.record_status(200);
        }

        // Check for abnormally large response (data exfiltration)
        let profile = store.get("/api/user/profile").unwrap();

        let suspicious_payload = 500_000; // 500KB vs 500B baseline
        let z_score = profile.payload_size.z_score(suspicious_payload as f64);

        let mut result = AnomalyResult::new();
        if z_score > 3.0 {
            result.add(
                AnomalySignalType::PayloadSizeHigh,
                8,
                format!(
                    "Response {}B vs baseline mean {}B",
                    suspicious_payload,
                    profile.payload_size.mean() as usize
                ),
            );
        }

        assert!(result.has_anomalies());
        assert!(result.max_severity() >= 5);
    }

    #[test]
    fn test_credential_stuffing_pattern() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 20,
            enable_segment_detection: false,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Normal login patterns: sparse, mixed success/failure
        for i in 0..50 {
            let mut profile = store.get_or_create("/api/login");
            profile.update(
                100,
                &[("username", "user1"), ("password", "pass")],
                Some("application/json"),
                i * 10000,
            );
            // Mix of success and failure
            profile.record_status(if i % 3 == 0 { 401 } else { 200 });
        }

        // Simulate credential stuffing: rapid failures
        {
            let mut profile = store.get_or_create("/api/login");
            for i in 0..100 {
                profile.update(
                    100,
                    &[("username", "attacker"), ("password", "guess")],
                    Some("application/json"),
                    500_000 + i * 10,
                );
                profile.record_status(401); // All failures
            }
        }

        // Check for anomalies
        let profile = store.get("/api/login").unwrap();

        let mut result = AnomalyResult::new();

        // Check rate burst
        let current_rate = profile.request_rate.current_rate(501_000);
        let baseline = profile.baseline_rate(501_000);
        if current_rate > baseline * 5.0 {
            result.add(
                AnomalySignalType::RateBurst,
                7,
                "Rate spike detected".to_string(),
            );
        }

        // Check error rate
        let error_rate = profile.error_rate();
        if error_rate > 0.5 {
            // Custom signal for high error rate
            result.total_score += 5.0;
        }

        assert!(result.has_anomalies() || result.total_score > 0.0);
    }

    #[test]
    fn test_path_traversal_attempt() {
        let config = ProfileStoreConfig {
            min_samples_for_detection: 10,
            enable_segment_detection: true,
            ..Default::default()
        };
        let store = ProfileStore::new(config);

        // Normal file access
        for i in 0..20 {
            let mut profile = store.get_or_create(&format!("/api/files/{}", i));
            profile.update(
                1000,
                &[("filename", "file.txt")],
                Some("application/octet-stream"),
                i * 100,
            );
        }

        // Path traversal attempts should be normalized but detectable
        let suspicious_paths = [
            "/api/files/../../../etc/passwd",
            "/api/files/....//....//etc/shadow",
            "/api/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ];

        for path in suspicious_paths {
            let _profile = store.get_or_create(path);
        }

        // The store should handle these without creating explosion
        assert!(store.len() < 30);
    }
}
