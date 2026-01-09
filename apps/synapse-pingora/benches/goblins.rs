//! "Goblins" Benchmark Suite - Testing potential performance bottlenecks
//!
//! Focus areas:
//! 1. DLP Response Scanning (Large payloads)
//! 2. JA4 Fingerprinting (Per-connection cost)
//! 3. EntityStore LRU Contention (Memory management cost)

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use synapse::{EntityStore, EntityConfig};
use synapse_pingora::dlp::{DlpScanner, DlpConfig};
use synapse_pingora::fingerprint::{extract_client_fingerprint, HttpHeaders};

// ============================================================================ 
// 1. DLP Response Scanning
// ============================================================================ 

fn bench_dlp_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins_dlp");
    group.measurement_time(Duration::from_secs(10));
    
    let config = DlpConfig {
        enabled: true,
        max_scan_size: 10 * 1024 * 1024,
        max_matches: 100,
        scan_text_only: true,
        max_body_inspection_bytes: 8 * 1024, // Default 8KB limit
    };
    let scanner = DlpScanner::new(config);

    // Generate 50KB payload with mixed content
    let mut clean_payload = String::with_capacity(50 * 1024);
    for i in 0..1000 {
        clean_payload.push_str(&format!("{{\"id\": {}, \"name\": \"Product {}\", \"desc\": \"Normal text\"}},", i, i));
    }
    
    let mut pii_payload = clean_payload.clone();
    // Inject PII every 500 chars
    for i in 0..10 {
        pii_payload.push_str(" \"credit_card\": \"4532-0151-1283-0366\", ");
    }

    group.bench_with_input(BenchmarkId::new("scan", "50kb_clean"), &clean_payload, |b, payload| {
        b.iter(|| scanner.scan(black_box(payload)))
    });

    group.bench_with_input(BenchmarkId::new("scan", "50kb_with_pii"), &pii_payload, |b, payload| {
        b.iter(|| scanner.scan(black_box(payload)))
    });

    group.finish();
}

// ============================================================================ 
// 2. JA4 Fingerprinting
// ============================================================================ 

fn bench_ja4_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins_ja4");
    
    let headers = vec![
        ("Host".to_string(), "api.example.com".to_string()),
        ("User-Agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string()),
        ("Accept".to_string(), "text/html,application/json".to_string()),
        ("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()),
        ("Cookie".to_string(), "session=abc123456; preferences=dark".to_string()),
        ("Referer".to_string(), "https://google.com".to_string()),
    ];
    
    let req = HttpHeaders {
        headers: &headers,
        method: "GET",
        http_version: "1.1",
    };
    
    let ja4_header = Some("t13d1516h2_8daaf6152771_e5627efa2ab1");

    group.bench_function("full_fingerprint", |b| {
        b.iter(|| {
            extract_client_fingerprint(black_box(ja4_header), black_box(&req))
        })
    });

    group.finish();
}

// ============================================================================ 
// 3. EntityStore LRU (Memory Goblin)
// ============================================================================ 

fn bench_entity_store_lru(c: &mut Criterion) {
    let mut group = c.benchmark_group("goblins_store");
    
    // Setup a full store
    let max_entities = 50_000;
    let config = EntityConfig {
        max_entities,
        ..Default::default()
    };
    let mut store = EntityStore::new(config);
    
    // Fill it up
    for i in 0..max_entities {
        store.touch_entity(&format!("192.168.0.{}", i));
    }

    // Benchmark touching an existing entity (triggers lazy LRU update)
    // We touch the *oldest* one to trigger `update_lru` moving it to end
    let oldest_ip = "192.168.0.0";
    
    group.bench_function("touch_existing_full_store", |b| {
        b.iter(|| {
            let _ = store.touch_entity(black_box(oldest_ip));
        })
    });

    // Benchmark adding a NEW entity (triggers eviction of oldest)
    // This is the expensive O(N) case: remove(0) from Vec
    let mut next_id = max_entities;
    group.bench_function("add_new_evict_oldest", |b| {
        b.iter_batched(
            || {
                next_id += 1;
                format!("10.0.0.{}", next_id)
            },
            |ip| { let _ = store.touch_entity(&ip); },
            criterion::BatchSize::SmallInput
        )
    });

    group.finish();
}

criterion_group!(
    goblins,
    bench_dlp_scanning,
    bench_ja4_generation,
    bench_entity_store_lru
);

criterion_main!(goblins);
