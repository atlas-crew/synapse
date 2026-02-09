//! Integration tests for Phase 1 Profiler Integration in synapse-pingora.
//!
//! These tests verify the bandwidth API returns correct data after recording
//! and that the evaluate endpoint callback registration works correctly.

use std::sync::atomic::Ordering;
use std::sync::Arc;

// Use the library crate name (underscores, not hyphens)
use synapse_pingora::admin_server::{
    register_evaluate_callback, register_profiles_getter, register_schemas_getter, EvaluationResult,
};
use synapse_pingora::{MetricsRegistry, ProfilingMetrics};

// =============================================================================
// Integration Tests - Bandwidth API returns non-zero after recording
// =============================================================================

/// Test that bandwidth API returns non-zero values after recording request bytes.
#[test]
fn test_bandwidth_api_returns_nonzero_after_request_recording() {
    let registry = MetricsRegistry::new();

    // Initially all values should be zero
    let stats_before = registry.get_bandwidth_stats();
    assert_eq!(stats_before.total_bytes, 0);
    assert_eq!(stats_before.total_bytes_in, 0);
    assert_eq!(stats_before.request_count, 0);

    // Record some request bandwidth
    registry.record_request_bandwidth(1024);
    registry.record_request_bandwidth(2048);

    // Now values should be non-zero
    let stats_after = registry.get_bandwidth_stats();
    assert!(
        stats_after.total_bytes > 0,
        "total_bytes should be non-zero"
    );
    assert!(
        stats_after.total_bytes_in > 0,
        "total_bytes_in should be non-zero"
    );
    assert_eq!(stats_after.total_bytes_in, 3072);
    assert_eq!(stats_after.request_count, 2);
}

/// Test that bandwidth API returns non-zero values after recording response bytes.
#[test]
fn test_bandwidth_api_returns_nonzero_after_response_recording() {
    let registry = MetricsRegistry::new();

    // Initially all values should be zero
    let stats_before = registry.get_bandwidth_stats();
    assert_eq!(stats_before.total_bytes_out, 0);

    // Record some response bandwidth
    registry.record_response_bandwidth(4096);
    registry.record_response_bandwidth(8192);

    // Now values should be non-zero
    let stats_after = registry.get_bandwidth_stats();
    assert!(
        stats_after.total_bytes_out > 0,
        "total_bytes_out should be non-zero"
    );
    assert_eq!(stats_after.total_bytes_out, 12288);
    assert!(
        stats_after.total_bytes > 0,
        "total_bytes should be non-zero"
    );
}

/// Test that bandwidth stats correctly aggregate request and response data.
#[test]
fn test_bandwidth_api_aggregation() {
    let registry = MetricsRegistry::new();

    // Record interleaved request/response data
    registry.record_request_bandwidth(100);
    registry.record_response_bandwidth(500);
    registry.record_request_bandwidth(200);
    registry.record_response_bandwidth(1000);
    registry.record_request_bandwidth(300);
    registry.record_response_bandwidth(1500);

    let stats = registry.get_bandwidth_stats();

    // Verify aggregation
    assert_eq!(stats.total_bytes_in, 600);
    assert_eq!(stats.total_bytes_out, 3000);
    assert_eq!(stats.total_bytes, 3600);
    assert_eq!(stats.request_count, 3);
    assert_eq!(stats.avg_bytes_per_request, 1200); // 3600 / 3
}

/// Test that max sizes are tracked correctly through the API.
#[test]
fn test_bandwidth_api_max_size_tracking() {
    let registry = MetricsRegistry::new();

    // Record various sizes
    registry.record_request_bandwidth(100);
    registry.record_request_bandwidth(500);
    registry.record_request_bandwidth(250);

    registry.record_response_bandwidth(1000);
    registry.record_response_bandwidth(3000);
    registry.record_response_bandwidth(2000);

    let stats = registry.get_bandwidth_stats();

    assert_eq!(stats.max_request_size, 500);
    assert_eq!(stats.max_response_size, 3000);
}

/// Test bandwidth stats after reset.
#[test]
fn test_bandwidth_api_after_reset() {
    let registry = MetricsRegistry::new();

    // Record some data
    registry.record_request_bandwidth(1000);
    registry.record_response_bandwidth(2000);

    // Verify data exists
    let stats_before = registry.get_bandwidth_stats();
    assert!(stats_before.total_bytes > 0);

    // Reset doesn't reset bandwidth counters in current implementation
    // but we can verify the API still works after reset
    registry.reset();

    // After reset, endpoint_stats should be cleared
    let endpoint_stats = registry.get_endpoint_stats();
    assert!(endpoint_stats.is_empty());
}

/// Test concurrent bandwidth recording.
#[test]
fn test_bandwidth_api_concurrent_recording() {
    use std::thread;

    let registry = Arc::new(MetricsRegistry::new());

    let mut handles = vec![];

    // Spawn multiple threads recording bandwidth
    for i in 0..10 {
        let reg = Arc::clone(&registry);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                reg.record_request_bandwidth(i as u64 * 10 + 1);
                reg.record_response_bandwidth(i as u64 * 10 + 2);
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify all recordings were captured
    let stats = registry.get_bandwidth_stats();
    assert_eq!(stats.request_count, 1000); // 10 threads * 100 iterations
    assert!(stats.total_bytes_in > 0);
    assert!(stats.total_bytes_out > 0);
}

// =============================================================================
// Integration Tests - Endpoint profiling
// =============================================================================

/// Test that endpoint recording through registry works.
#[test]
fn test_endpoint_recording_integration() {
    let registry = MetricsRegistry::new();

    // Record various endpoints
    registry.record_endpoint("/api/users", "GET");
    registry.record_endpoint("/api/users", "POST");
    registry.record_endpoint("/api/products", "GET");
    registry.record_endpoint("/api/users/123", "GET");

    // Verify through the API
    let stats = registry.get_endpoint_stats();
    assert_eq!(stats.len(), 3); // 3 unique paths

    // Find specific stats
    let users_stat = stats
        .iter()
        .find(|(path, _)| path == "/api/users")
        .map(|(_, s)| s);

    assert!(users_stat.is_some());
    let users = users_stat.unwrap();
    assert_eq!(users.hit_count, 2);
    assert_eq!(users.methods.len(), 2);
}

/// Test that endpoint stats are cleared on reset.
#[test]
fn test_endpoint_stats_cleared_on_reset() {
    let registry = MetricsRegistry::new();

    registry.record_endpoint("/test/path", "GET");
    assert!(!registry.get_endpoint_stats().is_empty());

    registry.reset();

    assert!(registry.get_endpoint_stats().is_empty());
}

// =============================================================================
// Integration Tests - Evaluate endpoint callback registration
// =============================================================================

/// Test that evaluate callback can be registered.
#[test]
fn test_evaluate_callback_registration() {
    // Register a mock callback
    register_evaluate_callback(|_method, uri, _headers, _body, _client_ip| {
        // Simple mock that blocks SQL injection patterns
        let is_sqli = uri.contains("'") || uri.contains("OR") || uri.contains("--");
        EvaluationResult {
            blocked: is_sqli,
            risk_score: if is_sqli { 85 } else { 10 },
            matched_rules: if is_sqli { vec![942100] } else { vec![] },
            block_reason: if is_sqli {
                Some("SQL Injection detected".to_string())
            } else {
                None
            },
            detection_time_us: 100,
        }
    });

    // The callback is now registered - in the actual server it would be invoked
    // via the evaluate endpoint. We can't easily test the endpoint without
    // starting a full server, but we've verified registration doesn't panic.
}

/// Test that multiple callback registrations work (last one wins).
#[test]
fn test_evaluate_callback_reregistration() {
    // Register first callback
    register_evaluate_callback(
        |_method, _uri, _headers, _body, _client_ip| EvaluationResult {
            blocked: false,
            risk_score: 0,
            matched_rules: vec![],
            block_reason: None,
            detection_time_us: 50,
        },
    );

    // Register second callback (should replace first)
    register_evaluate_callback(
        |_method, _uri, _headers, _body, _client_ip| EvaluationResult {
            blocked: true,
            risk_score: 100,
            matched_rules: vec![999],
            block_reason: Some("Always block".to_string()),
            detection_time_us: 10,
        },
    );

    // No panic means registration worked
}

/// Test profiles getter registration.
#[test]
fn test_profiles_getter_registration() {
    register_profiles_getter(|| {
        // Return empty profiles for testing
        vec![]
    });

    // No panic means registration worked
}

/// Test schemas getter registration.
#[test]
fn test_schemas_getter_registration() {
    register_schemas_getter(|| {
        // Return empty schemas for testing
        vec![]
    });

    // No panic means registration worked
}

// =============================================================================
// Integration Tests - Full workflow simulation
// =============================================================================

/// Simulate a full profiling workflow: record bandwidth, endpoints, check stats.
#[test]
fn test_full_profiling_workflow() {
    let registry = MetricsRegistry::new();

    // Simulate several API requests
    let requests = vec![
        ("/api/users", "GET", 50, 1500),
        ("/api/users", "POST", 200, 50),
        ("/api/products", "GET", 30, 5000),
        ("/api/products/123", "GET", 20, 2000),
        ("/api/orders", "POST", 500, 100),
    ];

    for (path, method, req_bytes, resp_bytes) in &requests {
        registry.record_endpoint(path, method);
        registry.record_request_bandwidth(*req_bytes);
        registry.record_response_bandwidth(*resp_bytes);
    }

    // Verify endpoint stats
    let endpoint_stats = registry.get_endpoint_stats();
    assert_eq!(endpoint_stats.len(), 4); // 4 unique paths

    // Verify bandwidth stats
    let bw_stats = registry.get_bandwidth_stats();
    assert_eq!(bw_stats.request_count, 5);
    assert_eq!(bw_stats.total_bytes_in, 800); // 50+200+30+20+500
    assert_eq!(bw_stats.total_bytes_out, 8650); // 1500+50+5000+2000+100
    assert_eq!(bw_stats.max_request_size, 500);
    assert_eq!(bw_stats.max_response_size, 5000);
}

/// Test profiling metrics under simulated load.
#[test]
fn test_profiling_under_load() {
    let registry = MetricsRegistry::new();

    // Simulate 1000 requests to various endpoints
    for i in 0..1000 {
        let path = match i % 5 {
            0 => "/api/users",
            1 => "/api/products",
            2 => "/api/orders",
            3 => "/api/auth/login",
            _ => "/api/health",
        };
        let method = if i % 3 == 0 { "POST" } else { "GET" };

        registry.record_endpoint(path, method);
        registry.record_request_bandwidth((i % 100 + 1) as u64);
        registry.record_response_bandwidth((i % 500 + 1) as u64);
    }

    let endpoint_stats = registry.get_endpoint_stats();
    assert_eq!(endpoint_stats.len(), 5); // 5 unique endpoints

    let bw_stats = registry.get_bandwidth_stats();
    assert_eq!(bw_stats.request_count, 1000);
    assert!(bw_stats.total_bytes > 0);
    assert!(bw_stats.avg_bytes_per_request > 0);
}

// =============================================================================
// Integration Tests - ProfilingMetrics direct tests
// =============================================================================

/// Test ProfilingMetrics thread safety.
#[test]
fn test_profiling_metrics_thread_safety() {
    use std::thread;

    let metrics = Arc::new(ProfilingMetrics::default());

    let mut handles = vec![];

    // Thread 1: Record request bytes
    {
        let m = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            for i in 0..500 {
                m.record_request_bytes(i * 10);
            }
        }));
    }

    // Thread 2: Record response bytes
    {
        let m = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            for i in 0..500 {
                m.record_response_bytes(i * 20);
            }
        }));
    }

    // Thread 3: Record endpoints
    {
        let m = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            for i in 0..500 {
                let path = format!("/api/endpoint{}", i % 10);
                m.record_endpoint(&path, "GET");
            }
        }));
    }

    // Thread 4: Read stats
    {
        let m = Arc::clone(&metrics);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = m.get_bandwidth_stats();
                let _ = m.get_endpoint_stats();
            }
        }));
    }

    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }

    // Verify data was recorded
    assert_eq!(metrics.bandwidth_request_count.load(Ordering::Relaxed), 500);
    assert!(metrics.total_bytes_in.load(Ordering::Relaxed) > 0);
    assert!(metrics.total_bytes_out.load(Ordering::Relaxed) > 0);
}

/// Test that anomaly recording works through integration.
#[test]
fn test_anomaly_recording_integration() {
    let registry = MetricsRegistry::new();

    // Record some anomalies through the registry
    let anomalies = vec![
        ("sql_injection", 8.5),
        ("xss_attempt", 6.0),
        ("rate_limit_exceeded", 4.0),
        ("sql_injection", 9.0), // Repeat type
    ];

    registry.record_profile_metrics(
        10, // active profiles
        &anomalies
            .iter()
            .map(|(t, s)| (t.to_string(), *s))
            .collect::<Vec<_>>(),
    );

    // Verify via Prometheus output
    let prometheus = registry.render_prometheus();
    assert!(prometheus.contains("synapse_profiles_active_count 10"));
    assert!(prometheus.contains("synapse_anomalies_detected_total"));
}

// =============================================================================
// Integration Tests - Edge cases
// =============================================================================

/// Test handling of zero-byte requests.
#[test]
fn test_zero_byte_requests() {
    let registry = MetricsRegistry::new();

    registry.record_request_bandwidth(0);
    registry.record_response_bandwidth(0);

    let stats = registry.get_bandwidth_stats();
    assert_eq!(stats.total_bytes, 0);
    assert_eq!(stats.request_count, 1);
    assert_eq!(stats.avg_bytes_per_request, 0);
}

/// Test very large bandwidth values.
#[test]
fn test_large_bandwidth_values() {
    let registry = MetricsRegistry::new();

    // 1 GB request and response
    let one_gb = 1024 * 1024 * 1024u64;
    registry.record_request_bandwidth(one_gb);
    registry.record_response_bandwidth(one_gb);

    let stats = registry.get_bandwidth_stats();
    assert_eq!(stats.total_bytes_in, one_gb);
    assert_eq!(stats.total_bytes_out, one_gb);
    assert_eq!(stats.total_bytes, 2 * one_gb);
}

/// Test bandwidth stats with single request.
#[test]
fn test_single_request_stats() {
    let registry = MetricsRegistry::new();

    registry.record_request_bandwidth(100);
    registry.record_response_bandwidth(500);

    let stats = registry.get_bandwidth_stats();
    assert_eq!(stats.request_count, 1);
    assert_eq!(stats.total_bytes, 600);
    assert_eq!(stats.avg_bytes_per_request, 600);
}

/// Test endpoint path normalization through API.
#[test]
fn test_endpoint_path_handling() {
    let registry = MetricsRegistry::new();

    // Test various path formats
    registry.record_endpoint("/", "GET");
    registry.record_endpoint("/api", "GET");
    registry.record_endpoint("/api/", "GET"); // Different from /api
    registry.record_endpoint("/api/users/123/profile", "GET");
    registry.record_endpoint("/api/users?id=1", "GET");

    let stats = registry.get_endpoint_stats();
    assert_eq!(stats.len(), 5); // All unique paths
}
