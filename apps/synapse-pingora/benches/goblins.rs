//! "Goblins" Benchmark Suite - Testing potential performance bottlenecks
//!
//! Focus areas:
//! 1. DLP Response Scanning (Large payloads)
//! 2. JA4 Fingerprinting (Per-connection cost)
//! 3. EntityManager LRU Contention (Memory management cost)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
// NOTE: The `synapse` (libsynapse) crate was consolidated into synapse_pingora in Phase 10.
use serde_json;
use synapse_pingora::dlp::{DlpConfig, DlpScanner};
use synapse_pingora::fingerprint::{extract_client_fingerprint, HttpHeaders};
use synapse_pingora::horizon::{Severity, SignalType, ThreatSignal};
use synapse_pingora::{EntityConfig, EntityManager};

// ============================================================================
// 1. DLP Response Scanning
// ============================================================================

fn bench_dlp_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins/dlp_scanning");
    group.measurement_time(Duration::from_secs(10));

    let config = DlpConfig {
        max_body_inspection_bytes: 8 * 1024, // Default 8KB limit
        ..Default::default()
    };
    let scanner = DlpScanner::new(config);

    // Generate 50KB payload with mixed content
    let mut clean_payload = String::with_capacity(50 * 1024);
    for i in 0..1000 {
        clean_payload.push_str(&format!(
            "{{\"id\": {}, \"name\": \"Product {}\", \"desc\": \"Normal text\"}},",
            i, i
        ));
    }

    // BUG FIX: PII must appear WITHIN the inspection window (first 8KB), not appended
    // at the end where the scanner's max_body_inspection_bytes truncation skips it.
    let pii_block = concat!(
        "\"credit_card\": \"4532-0151-1283-0366\", ",
        "\"ssn\": \"123-45-6789\", ",
        "\"email\": \"leak@example.com\", ",
        "\"phone\": \"212-555-0199\", ",
    );
    // Interleave PII every ~500 bytes in the first 8KB of the payload
    let mut pii_payload = String::with_capacity(50 * 1024);
    for i in 0..1000 {
        if i % 5 == 0 && pii_payload.len() < 7 * 1024 {
            pii_payload.push_str(pii_block);
        }
        pii_payload.push_str(&format!(
            "{{\"id\": {}, \"name\": \"Product {}\", \"desc\": \"Normal text\"}},",
            i, i
        ));
    }

    group.bench_with_input(
        BenchmarkId::new("scan", "50kb_clean"),
        &clean_payload,
        |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
    );

    group.bench_with_input(
        BenchmarkId::new("scan", "50kb_with_pii"),
        &pii_payload,
        |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
    );

    group.finish();
}

// ============================================================================
// 2. JA4 Fingerprinting
// ============================================================================

fn bench_ja4_generation(c: &mut Criterion) {
    use http::{HeaderName, HeaderValue};

    let mut group = c.benchmark_group("goblins/ja4_fingerprint");

    let headers: Vec<(HeaderName, HeaderValue)> = vec![
        (
            HeaderName::from_static("host"),
            HeaderValue::from_static("api.example.com"),
        ),
        (
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ),
        (
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html,application/json"),
        ),
        (
            HeaderName::from_static("accept-language"),
            HeaderValue::from_static("en-US,en;q=0.9"),
        ),
        (
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=abc123456; preferences=dark"),
        ),
        (
            HeaderName::from_static("referer"),
            HeaderValue::from_static("https://google.com"),
        ),
    ];

    let req = HttpHeaders {
        headers: &headers,
        method: "GET",
        http_version: "1.1",
    };

    let ja4_header = Some("t13d1516h2_8daaf6152771_e5627efa2ab1");

    group.bench_function("full_fingerprint", |b| {
        b.iter(|| extract_client_fingerprint(black_box(ja4_header), black_box(&req)))
    });

    group.finish();
}

// ============================================================================
// 3. EntityManager LRU (Memory Goblin)
// ============================================================================

fn bench_entity_store_lru(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins/entity_lru");

    // Setup a full store
    let max_entities = 50_000;
    let config = EntityConfig {
        max_entities,
        ..Default::default()
    };
    let store = EntityManager::new(config);

    // BUG FIX: Generate valid IP addresses using all four octets
    // Previous code used format!("192.168.0.{}", i) with i up to 50000, producing
    // invalid IPs like "192.168.0.50000". Use proper octet decomposition instead.
    for i in 0..max_entities {
        let o3 = (i >> 8) & 0xFF;
        let o4 = i & 0xFF;
        store.touch_entity(&format!("10.{}.{}.{}", (i >> 16) & 0xFF, o3, o4));
    }

    // Benchmark touching an existing entity (triggers lazy LRU update)
    let oldest_ip = "10.0.0.0";

    group.bench_function("touch_existing_full_store", |b| {
        b.iter(|| black_box(store.touch_entity(black_box(oldest_ip))))
    });

    // Benchmark adding a NEW entity (triggers eviction of oldest)
    let mut next_id = max_entities;
    group.bench_function("add_new_evict_oldest", |b| {
        b.iter_batched(
            || {
                next_id += 1;
                let o3 = (next_id >> 8) & 0xFF;
                let o4 = next_id & 0xFF;
                format!("172.{}.{}.{}", (next_id >> 16) & 0xFF, o3, o4)
            },
            |ip| {
                black_box(store.touch_entity(&ip));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

// ============================================================================
// 4. Horizon Signal Serialization
// ============================================================================

fn bench_horizon_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins/horizon_serde");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // Minimal signal (only required fields)
    let minimal_signal =
        ThreatSignal::new(SignalType::IpThreat, Severity::High).with_confidence(0.85);

    // Full signal (all optional fields populated)
    let full_signal = ThreatSignal::new(SignalType::CampaignIndicator, Severity::Critical)
        .with_source_ip("203.0.113.42")
        .with_fingerprint("t13d1516h2_8daaf6152771_e5627efa2ab1")
        .with_confidence(0.95)
        .with_event_count(42)
        .with_metadata(serde_json::json!({
            "campaign_id": "CAMP-2024-001",
            "technique": "credential_stuffing",
            "targets": ["api.example.com", "login.example.com"],
            "iocs": {
                "ips": ["203.0.113.42", "198.51.100.23"],
                "user_agents": ["python-requests/2.28", "Go-http-client/1.1"]
            }
        }));

    // Serialization benchmarks
    group.bench_function("minimal_to_string", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&minimal_signal)).unwrap()))
    });

    group.bench_function("minimal_to_vec", |b| {
        b.iter(|| black_box(serde_json::to_vec(black_box(&minimal_signal)).unwrap()))
    });

    group.bench_function("full_to_string", |b| {
        b.iter(|| black_box(serde_json::to_string(black_box(&full_signal)).unwrap()))
    });

    group.bench_function("full_to_vec", |b| {
        b.iter(|| black_box(serde_json::to_vec(black_box(&full_signal)).unwrap()))
    });

    // Batch serialization (10 signals, simulating a telemetry flush)
    let batch: Vec<ThreatSignal> = (0..10)
        .map(|i| {
            ThreatSignal::new(SignalType::RateAnomaly, Severity::Medium)
                .with_source_ip(&format!("10.0.0.{}", i))
                .with_confidence(0.5 + (i as f64) * 0.05)
                .with_event_count(i as u32 + 1)
        })
        .collect();

    group.bench_function("batch_10_to_vec", |b| {
        b.iter(|| black_box(serde_json::to_vec(black_box(&batch)).unwrap()))
    });

    // Deserialization round-trip
    let full_json = serde_json::to_string(&full_signal).unwrap();

    group.bench_function("full_deserialize", |b| {
        b.iter(|| black_box(serde_json::from_str::<ThreatSignal>(black_box(&full_json)).unwrap()))
    });

    group.finish();
}

criterion_group!(
    goblins,
    bench_dlp_scanning,
    bench_ja4_generation,
    bench_entity_store_lru,
    bench_horizon_serialization,
);

criterion_main!(goblins);
