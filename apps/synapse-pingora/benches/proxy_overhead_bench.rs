//! Proxy overhead isolation benchmarks.
//!
//! Isolates and measures proxy-layer operations (vhost matching, entity lookup,
//! fingerprint extraction, config lock contention) separate from WAF analysis.
//!
//! Run with: `cargo bench --bench proxy_overhead_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use synapse_pingora::fingerprint::{generate_ja4h, parse_ja4_from_header, HttpHeaders};
use synapse_pingora::ratelimit::TokenBucket;
use synapse_pingora::{EntityConfig, EntityManager, SiteConfig, VhostMatcher};

// ============================================================================
// Helpers
// ============================================================================

/// Generate a pool of IP addresses for entity benchmarks.
fn generate_ip_pool(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let o2 = (i >> 16) & 0xFF;
            let o3 = (i >> 8) & 0xFF;
            let o4 = i & 0xFF;
            format!("10.{}.{}.{}", o2, o3, o4)
        })
        .collect()
}

/// Create N SiteConfig entries for VhostMatcher benchmarks.
fn make_sites(count: usize) -> Vec<SiteConfig> {
    (0..count)
        .map(|i| SiteConfig {
            hostname: format!("site{}.example.com", i),
            upstreams: vec![format!("127.0.0.1:{}", 8000 + i % 100)],
            ..Default::default()
        })
        .collect()
}

// ============================================================================
// 1. VhostMatcher — Hostname Lookup Scaling
// ============================================================================

fn bench_vhost_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/vhost_matching");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    for count in [10, 50, 200] {
        let sites = make_sites(count);
        let target_host = format!("site{}.example.com", count / 2); // mid-list hit
        let matcher = VhostMatcher::new(sites).expect("valid sites");

        group.bench_with_input(
            BenchmarkId::new("match_hit", count),
            &target_host,
            |b, host| {
                b.iter(|| {
                    let result = matcher.match_host(black_box(host));
                    black_box(result);
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("match_miss", count), &count, |b, _| {
            b.iter(|| {
                let result = matcher.match_host(black_box("unknown.example.org"));
                black_box(result);
            });
        });
    }

    group.finish();
}

// ============================================================================
// 2. Config Read Lock Contention
// ============================================================================

fn bench_config_read_lock(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/config_read_lock");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let sites = make_sites(50);
    let matcher = Arc::new(parking_lot::RwLock::new(
        VhostMatcher::new(sites).expect("valid sites"),
    ));

    for &threads in &[1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("rwlock_read", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for _ in 0..num_threads {
                            let matcher = Arc::clone(&matcher);
                            s.spawn(move || {
                                for i in 0..1000 {
                                    let host = format!("site{}.example.com", i % 50);
                                    let guard = matcher.read();
                                    let result = guard.match_host(black_box(&host));
                                    black_box(result);
                                }
                            });
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 3. Fingerprint Extraction
// ============================================================================

fn bench_fingerprint_extraction(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/fingerprint_extraction");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    group.bench_function("parse_ja4", |b| {
        b.iter(|| {
            let fp = parse_ja4_from_header(black_box(Some("t13d1516h2_8daaf6152771_e5627efa2ab1")));
            black_box(fp);
        });
    });

    let header_pairs: Vec<(HeaderName, HeaderValue)> = vec![
        (
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html,application/xhtml+xml"),
        ),
        (
            HeaderName::from_static("accept-encoding"),
            HeaderValue::from_static("gzip, deflate, br"),
        ),
        (
            HeaderName::from_static("accept-language"),
            HeaderValue::from_static("en-US,en;q=0.9"),
        ),
        (
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        ),
        (
            HeaderName::from_static("cookie"),
            HeaderValue::from_static("session=abc123"),
        ),
        (
            HeaderName::from_static("referer"),
            HeaderValue::from_static("https://example.com"),
        ),
    ];

    group.bench_function("generate_ja4h", |b| {
        let headers = HttpHeaders {
            headers: &header_pairs,
            method: "GET",
            http_version: "1.1",
        };
        b.iter(|| {
            let fp = generate_ja4h(black_box(&headers));
            black_box(fp);
        });
    });

    group.bench_function("extract_combined", |b| {
        let headers = HttpHeaders {
            headers: &header_pairs,
            method: "GET",
            http_version: "1.1",
        };
        b.iter(|| {
            let ja4 =
                parse_ja4_from_header(black_box(Some("t13d1516h2_8daaf6152771_e5627efa2ab1")));
            let ja4h = generate_ja4h(black_box(&headers));
            black_box((ja4, ja4h));
        });
    });

    group.finish();
}

// ============================================================================
// 4. Entity Lookup Pipeline
// ============================================================================

fn bench_entity_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/entity_lookup");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let ip_pool = generate_ip_pool(10_000);
    let config = EntityConfig {
        max_entities: 50_000,
        ..Default::default()
    };
    let manager = EntityManager::new(config);

    // Pre-populate with half the pool
    for ip in ip_pool.iter().take(5_000) {
        manager.touch_entity(ip);
    }

    group.bench_function("touch_entity", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = &ip_pool[idx % ip_pool.len()];
            let snapshot = manager.touch_entity(black_box(ip));
            black_box(snapshot);
            idx += 1;
        });
    });

    group.bench_function("get_entity_existing", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = &ip_pool[idx % 5_000]; // known entities
            let snapshot = manager.get_entity(black_box(ip));
            black_box(snapshot);
            idx += 1;
        });
    });

    group.bench_function("get_entity_unknown", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = format!("172.16.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            let snapshot = manager.get_entity(black_box(&ip));
            black_box(snapshot);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 5. Full Analysis Without WAF
// ============================================================================

fn bench_full_analysis_no_waf(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy/full_analysis_no_waf");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let entity_mgr = EntityManager::new(EntityConfig {
        max_entities: 50_000,
        ..Default::default()
    });
    let bucket = TokenBucket::new(100_000, 200_000);

    group.bench_function("entity_fingerprint_ratelimit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = format!("10.0.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);

            // Entity tracking
            let snapshot = entity_mgr.touch_entity(black_box(&ip));
            black_box(&snapshot);

            // Fingerprint parsing
            let fp = parse_ja4_from_header(black_box(Some("t13d1516h2_8daaf6152771_e5627efa2ab1")));
            black_box(fp);

            // Rate limiting
            let allowed = bucket.try_acquire();
            black_box(allowed);

            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    proxy_benches,
    bench_vhost_matching,
    bench_config_read_lock,
    bench_fingerprint_extraction,
    bench_entity_lookup,
    bench_full_analysis_no_waf,
);

criterion_main!(proxy_benches);
