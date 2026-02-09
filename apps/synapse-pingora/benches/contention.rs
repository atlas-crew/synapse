//! Multi-threaded contention benchmarks for lock-free and concurrent data structures.
//!
//! Tests how performance degrades under concurrent access — critical for
//! validating that DashMap, atomic, and LRU structures scale with core count.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;
use synapse_pingora::dlp::{DlpConfig, DlpScanner};
use synapse_pingora::ratelimit::TokenBucket;
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};
use synapse_pingora::{EntityConfig, EntityManager};

/// Pre-generate a pool of IP addresses to avoid allocation noise in hot loops.
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

// ============================================================================
// 1. Token Bucket — Atomic Contention
// ============================================================================

fn bench_token_bucket_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/token_bucket");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    for thread_count in [1, 2, 4, 8] {
        let bucket = Arc::new(TokenBucket::new(10_000_000, 20_000_000));

        group.bench_with_input(
            BenchmarkId::new("try_acquire", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|_| {
                                let bucket = Arc::clone(&bucket);
                                s.spawn(move || {
                                    for _ in 0..1000 {
                                        black_box(bucket.try_acquire());
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 2. EntityManager — DashMap Contention (Read-Heavy vs Write-Heavy)
// ============================================================================

fn bench_entity_manager_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/entity_manager");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let ip_pool = generate_ip_pool(10_000);

    // Read-heavy workload: 90% get_entity, 10% touch_entity
    for thread_count in [1, 2, 4, 8] {
        let config = EntityConfig {
            max_entities: 50_000,
            ..Default::default()
        };
        let store = Arc::new(EntityManager::new(config));

        // Pre-populate with half the IP pool
        for ip in ip_pool.iter().take(5_000) {
            store.touch_entity(ip);
        }

        group.bench_with_input(
            BenchmarkId::new("read_heavy_90_10", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let store = Arc::clone(&store);
                                let pool = &ip_pool;
                                s.spawn(move || {
                                    let offset = t * 1000;
                                    for i in 0..1000 {
                                        let ip = &pool[(offset + i) % pool.len()];
                                        if i % 10 == 0 {
                                            // 10% writes
                                            black_box(store.touch_entity(ip));
                                        } else {
                                            // 90% reads
                                            black_box(store.get_entity(ip));
                                        }
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    // Write-heavy workload: 50% get_entity, 50% touch_entity
    for thread_count in [1, 2, 4, 8] {
        let config = EntityConfig {
            max_entities: 50_000,
            ..Default::default()
        };
        let store = Arc::new(EntityManager::new(config));

        for ip in ip_pool.iter().take(5_000) {
            store.touch_entity(ip);
        }

        group.bench_with_input(
            BenchmarkId::new("write_heavy_50_50", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let store = Arc::clone(&store);
                                let pool = &ip_pool;
                                s.spawn(move || {
                                    let offset = t * 1000;
                                    for i in 0..1000 {
                                        let ip = &pool[(offset + i) % pool.len()];
                                        if i % 2 == 0 {
                                            // 50% writes
                                            black_box(store.touch_entity(ip));
                                        } else {
                                            // 50% reads
                                            black_box(store.get_entity(ip));
                                        }
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 3. TarpitManager — Concurrent Read/Write Contention
// ============================================================================

fn bench_tarpit_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/tarpit");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let ip_pool = generate_ip_pool(1_000);

    for thread_count in [1, 2, 4, 8] {
        let config = TarpitConfig::default();
        let manager = Arc::new(TarpitManager::new(config));

        // Pre-prime with 100 IPs at various tarpit levels
        for (i, ip) in ip_pool.iter().take(100).enumerate() {
            for _ in 0..i {
                manager.tarpit(ip);
            }
        }

        group.bench_with_input(
            BenchmarkId::new("mixed_read_write", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let mgr = Arc::clone(&manager);
                                let pool = &ip_pool;
                                s.spawn(move || {
                                    let offset = t * 100;
                                    for i in 0..500 {
                                        let ip = &pool[(offset + i) % pool.len()];
                                        if i % 5 == 0 {
                                            // 20% writes (tarpit escalation)
                                            black_box(mgr.tarpit(ip));
                                        } else {
                                            // 80% reads (delay check)
                                            black_box(mgr.peek_delay(ip));
                                        }
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 4. DLP Scanner — Concurrent Scan Contention
// ============================================================================

fn bench_dlp_scanner_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/dlp_scanner");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let scanner = Arc::new(DlpScanner::new(DlpConfig::default()));

    // Pre-generate content to scan (alternating clean and PII)
    let clean_content = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
    let pii_content = "Customer John Smith, card 4532-0151-1283-0366, SSN 123-45-6789, \
        email john@example.com, phone 212-555-0199";

    let contents: Vec<&str> = (0..100)
        .map(|i| {
            if i % 5 == 0 {
                pii_content
            } else {
                clean_content
            }
        })
        .collect();

    for thread_count in [1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("scan_mixed", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let scanner = Arc::clone(&scanner);
                                let contents = &contents;
                                s.spawn(move || {
                                    let offset = t * 20;
                                    for i in 0..100 {
                                        let content = contents[(offset + i) % contents.len()];
                                        black_box(scanner.scan(black_box(content)));
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    contention,
    bench_token_bucket_contention,
    bench_entity_manager_contention,
    bench_tarpit_contention,
    bench_dlp_scanner_contention,
);

criterion_main!(contention);
