//! Benchmarks for the campaign correlation subsystem.
//!
//! Covers: FingerprintIndex registration/lookup/group scanning,
//!         CampaignManager recording/scoring, and multi-threaded contention.
//!
//! Run with: `cargo bench --bench correlation`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::correlation::{
    Campaign, CampaignManager, CorrelationReason,
    CorrelationType, FingerprintIndex, ManagerConfig,
};

// ============================================================================
// Helpers
// ============================================================================

/// Generate a pool of unique IP address strings.
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

/// Generate a pool of synthetic JA4 fingerprint strings.
fn generate_fingerprint_pool(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| format!("t13d1516h2_bench{:06x}", i))
        .collect()
}

// ============================================================================
// 1. Fingerprint Registration
// ============================================================================

fn bench_fingerprint_registration(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation/fingerprint_register");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let ip_pool = generate_ip_pool(10_000);
    let fp_pool = generate_fingerprint_pool(1_000);

    // --- register_new_ip: update_entity with a brand-new IP each iteration ---
    group.bench_function("register_new_ip", |b| {
        let index = FingerprintIndex::new();
        let mut ip_idx = 0usize;
        let mut fp_idx = 0usize;
        b.iter(|| {
            let ip = &ip_pool[ip_idx % ip_pool.len()];
            let fp = &fp_pool[fp_idx % fp_pool.len()];
            black_box(index.update_entity(ip, Some(fp), None));
            ip_idx = ip_idx.wrapping_add(1);
            fp_idx = fp_idx.wrapping_add(1);
        });
    });

    // --- register_existing_ip: known IP, new fingerprint ---
    group.bench_function("register_existing_ip", |b| {
        let index = FingerprintIndex::new();
        // Pre-register all IPs with their first fingerprint
        for (i, ip) in ip_pool.iter().enumerate() {
            index.update_entity(ip, Some(&fp_pool[i % fp_pool.len()]), None);
        }
        let mut ip_idx = 0usize;
        let mut fp_idx = 500usize; // Start with a different fingerprint offset
        b.iter(|| {
            let ip = &ip_pool[ip_idx % ip_pool.len()];
            let fp = &fp_pool[fp_idx % fp_pool.len()];
            black_box(index.update_entity(ip, Some(fp), None));
            ip_idx = ip_idx.wrapping_add(1);
            fp_idx = fp_idx.wrapping_add(1);
        });
    });

    // --- register_same_pair: same IP + same JA4 (no-op fast path) ---
    group.bench_function("register_same_pair", |b| {
        let index = FingerprintIndex::new();
        let ip = &ip_pool[0];
        let fp = &fp_pool[0];
        index.update_entity(ip, Some(fp), None);
        b.iter(|| {
            black_box(index.update_entity(ip, Some(fp), None));
        });
    });

    group.finish();
}

// ============================================================================
// 2. Fingerprint Lookup
// ============================================================================

fn bench_fingerprint_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation/fingerprint_lookup");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let ip_pool = generate_ip_pool(5_000);
    let fp_pool = generate_fingerprint_pool(200);

    // Pre-populate: distribute 5000 IPs across 200 fingerprints
    let index = FingerprintIndex::new();
    for (i, ip) in ip_pool.iter().enumerate() {
        let fp = &fp_pool[i % fp_pool.len()];
        index.update_entity(ip, Some(fp), None);
    }

    // Pick a JA4 shared by exactly 5 IPs (group index 0..5 share fp_pool[0],
    // but with 5000/200 = 25 IPs per FP, so use a fresh index for the "small" case).
    let small_index = FingerprintIndex::new();
    let small_fp = "t13d1516h2_small_group";
    for ip in ip_pool.iter().take(5) {
        small_index.update_entity(ip, Some(small_fp), None);
    }
    // Also register a large-group FP
    let large_fp = "t13d1516h2_large_group";
    let large_index = FingerprintIndex::new();
    for ip in ip_pool.iter().take(100) {
        large_index.update_entity(ip, Some(large_fp), None);
    }

    group.bench_function("get_ips_by_ja4_small_group", |b| {
        b.iter(|| black_box(small_index.get_ips_by_ja4(small_fp)));
    });

    group.bench_function("get_ips_by_ja4_large_group", |b| {
        b.iter(|| black_box(large_index.get_ips_by_ja4(large_fp)));
    });

    group.bench_function("count_ips_by_ja4", |b| {
        // Use the main index with ~25 IPs per FP
        let fp = &fp_pool[0];
        b.iter(|| black_box(index.count_ips_by_ja4(fp)));
    });

    group.bench_function("get_ip_fingerprints", |b| {
        let ip = &ip_pool[0];
        b.iter(|| black_box(index.get_ip_fingerprints(ip)));
    });

    group.finish();
}

// ============================================================================
// 3. Fingerprint Group Scanning
// ============================================================================

fn bench_fingerprint_groups(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation/fingerprint_groups");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    // Build an index with varying group sizes:
    // - 50 fingerprints with 1 IP each  (below any threshold)
    // - 40 fingerprints with 3 IPs each
    // - 20 fingerprints with 6 IPs each
    // - 10 fingerprints with 15 IPs each
    let index = FingerprintIndex::new();
    let mut ip_counter = 0u32;
    let mut next_ip = || -> String {
        let o2 = (ip_counter >> 16) & 0xFF;
        let o3 = (ip_counter >> 8) & 0xFF;
        let o4 = ip_counter & 0xFF;
        ip_counter += 1;
        format!("10.{}.{}.{}", o2, o3, o4)
    };

    for f in 0..50 {
        let fp = format!("t13d_single_{:04}", f);
        index.update_entity(&next_ip(), Some(&fp), None);
    }
    for f in 0..40 {
        let fp = format!("t13d_trio_{:04}", f);
        for _ in 0..3 {
            index.update_entity(&next_ip(), Some(&fp), None);
        }
    }
    for f in 0..20 {
        let fp = format!("t13d_six_{:04}", f);
        for _ in 0..6 {
            index.update_entity(&next_ip(), Some(&fp), None);
        }
    }
    for f in 0..10 {
        let fp = format!("t13d_fifteen_{:04}", f);
        for _ in 0..15 {
            index.update_entity(&next_ip(), Some(&fp), None);
        }
    }

    for threshold in [2, 5, 10] {
        group.bench_with_input(
            BenchmarkId::new("get_groups_above_threshold", threshold),
            &threshold,
            |b, &thr| {
                b.iter(|| black_box(index.get_groups_above_threshold(thr)));
            },
        );
    }

    group.finish();
}

// ============================================================================
// 4. Campaign Manager Recording
// ============================================================================

fn bench_campaign_record(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation/campaign_record");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let ip_pool = generate_ip_pool(1_000);
    let fp_pool = generate_fingerprint_pool(100);

    let config = ManagerConfig {
        background_scanning: false,
        ..Default::default()
    };

    // --- register_ja4 ---
    group.bench_function("register_ja4", |b| {
        let manager = CampaignManager::with_config(config.clone());
        let mut idx = 0usize;
        b.iter(|| {
            let ip: IpAddr = ip_pool[idx % ip_pool.len()].parse().unwrap();
            let fp = fp_pool[idx % fp_pool.len()].clone();
            black_box(manager.register_ja4(ip, fp));
            idx = idx.wrapping_add(1);
        });
    });

    // --- record_attack ---
    group.bench_function("record_attack", |b| {
        let manager = CampaignManager::with_config(config.clone());
        let mut idx = 0usize;
        b.iter(|| {
            let ip: IpAddr = ip_pool[idx % ip_pool.len()].parse().unwrap();
            black_box(manager.record_attack(
                ip,
                format!("hash_{:06x}", idx),
                "sqli".to_string(),
                "/api/login".to_string(),
            ));
            idx = idx.wrapping_add(1);
        });
    });

    // --- record_request ---
    group.bench_function("record_request", |b| {
        let manager = CampaignManager::with_config(config.clone());
        let mut idx = 0usize;
        b.iter(|| {
            let ip: IpAddr = ip_pool[idx % ip_pool.len()].parse().unwrap();
            black_box(manager.record_request(ip, "GET", "/api/users"));
            idx = idx.wrapping_add(1);
        });
    });

    // --- record_request_full ---
    group.bench_function("record_request_full", |b| {
        let manager = CampaignManager::with_config(config.clone());
        let mut idx = 0usize;
        b.iter(|| {
            let ip: IpAddr = ip_pool[idx % ip_pool.len()].parse().unwrap();
            let fp = &fp_pool[idx % fp_pool.len()];
            black_box(manager.record_request_full(
                ip,
                "POST",
                "/api/data",
                Some(fp.as_str()),
                Some("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"),
            ));
            idx = idx.wrapping_add(1);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Campaign Scoring
// ============================================================================

fn bench_campaign_scoring(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation/campaign_scoring");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let config = ManagerConfig {
        background_scanning: false,
        ..Default::default()
    };
    let manager = CampaignManager::with_config(config);

    // Populate: 50 IPs sharing 5 fingerprints, with recorded attacks
    let ip_pool = generate_ip_pool(50);
    let fp_pool = generate_fingerprint_pool(5);

    for (i, ip_str) in ip_pool.iter().enumerate() {
        let ip: IpAddr = ip_str.parse().unwrap();
        let fp = fp_pool[i % fp_pool.len()].clone();
        manager.register_ja4(ip, fp);
        // Record some attacks
        for a in 0..2 {
            manager.record_attack(
                ip,
                format!("payload_hash_{}", a),
                "sqli".to_string(),
                "/target".to_string(),
            );
        }
    }

    // Create a campaign manually in the store so we can score it
    let actors: Vec<String> = ip_pool.iter().take(10).cloned().collect();
    let mut campaign = Campaign::new(
        Campaign::generate_id(),
        actors,
        0.85,
    );
    // Add multiple correlation reasons for realistic scoring
    campaign.correlation_reasons.push(CorrelationReason::new(
        CorrelationType::TlsFingerprint,
        0.90,
        "Shared JA4 fingerprint across 10 IPs",
        vec![],
    ));
    campaign.correlation_reasons.push(CorrelationReason::new(
        CorrelationType::AttackSequence,
        0.95,
        "Identical SQLi payloads",
        vec![],
    ));
    campaign.correlation_reasons.push(CorrelationReason::new(
        CorrelationType::BehavioralSimilarity,
        0.70,
        "Similar navigation patterns",
        vec![],
    ));
    campaign.correlation_reasons.push(CorrelationReason::new(
        CorrelationType::TimingCorrelation,
        0.65,
        "Synchronized request timing",
        vec![],
    ));

    // Store and retrieve for benchmarking
    let _ = manager.store().create_campaign(campaign.clone());

    group.bench_function("calculate_campaign_score", |b| {
        b.iter(|| black_box(manager.calculate_campaign_score(&campaign)));
    });

    group.finish();
}

// ============================================================================
// 6. FingerprintIndex Contention (Multi-Threaded)
// ============================================================================

fn bench_fingerprint_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/fingerprint_index");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let ip_pool = generate_ip_pool(10_000);
    let fp_pool = generate_fingerprint_pool(500);

    for thread_count in [1, 2, 4, 8] {
        // Pre-populate with half the IPs so reads have data
        let index = Arc::new(FingerprintIndex::new());
        for (i, ip) in ip_pool.iter().take(5_000).enumerate() {
            index.update_entity(ip, Some(&fp_pool[i % fp_pool.len()]), None);
        }

        group.bench_with_input(
            BenchmarkId::new("read80_write20", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                let index = Arc::clone(&index);
                let ip_pool = &ip_pool;
                let fp_pool = &fp_pool;
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let index = Arc::clone(&index);
                                s.spawn(move || {
                                    let ops = 1000;
                                    for i in 0..ops {
                                        let key = (t * ops + i) % ip_pool.len();
                                        if i % 5 == 0 {
                                            // 20% writes
                                            let fp = &fp_pool[key % fp_pool.len()];
                                            index.update_entity(
                                                &ip_pool[key],
                                                Some(fp),
                                                None,
                                            );
                                        } else {
                                            // 80% reads
                                            let fp = &fp_pool[key % fp_pool.len()];
                                            black_box(index.get_ips_by_ja4(fp));
                                        }
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 7. CampaignManager Contention (Multi-Threaded)
// ============================================================================

fn bench_campaign_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/campaign_manager");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let ip_pool = generate_ip_pool(5_000);
    let fp_pool = generate_fingerprint_pool(200);

    for thread_count in [1, 2, 4, 8] {
        let config = ManagerConfig {
            background_scanning: false,
            ..Default::default()
        };
        let manager = Arc::new(CampaignManager::with_config(config));

        // Pre-populate some fingerprints
        for (i, ip_str) in ip_pool.iter().take(1_000).enumerate() {
            let ip: IpAddr = ip_str.parse().unwrap();
            manager.register_ja4(ip, fp_pool[i % fp_pool.len()].clone());
        }

        group.bench_with_input(
            BenchmarkId::new("mixed_workload", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                let manager = Arc::clone(&manager);
                let ip_pool = &ip_pool;
                let fp_pool = &fp_pool;
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let manager = Arc::clone(&manager);
                                s.spawn(move || {
                                    let ops = 500;
                                    for i in 0..ops {
                                        let key = (t * ops + i) % ip_pool.len();
                                        let ip: IpAddr = ip_pool[key].parse().unwrap();
                                        match i % 3 {
                                            0 => {
                                                // register_ja4
                                                let fp = fp_pool[key % fp_pool.len()].clone();
                                                manager.register_ja4(ip, fp);
                                            }
                                            1 => {
                                                // record_attack
                                                manager.record_attack(
                                                    ip,
                                                    format!("hash_{}", i),
                                                    "xss".to_string(),
                                                    "/search".to_string(),
                                                );
                                            }
                                            _ => {
                                                // record_request
                                                manager.record_request(ip, "GET", "/api/status");
                                            }
                                        }
                                    }
                                })
                            })
                            .collect();
                        for h in handles {
                            h.join().unwrap();
                        }
                    });
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Entrypoint
// ============================================================================

criterion_group!(
    fingerprint_benches,
    bench_fingerprint_registration,
    bench_fingerprint_lookup,
    bench_fingerprint_groups,
);

criterion_group!(
    campaign_benches,
    bench_campaign_record,
    bench_campaign_scoring,
);

criterion_group!(
    contention_benches,
    bench_fingerprint_contention,
    bench_campaign_contention,
);

criterion_main!(fingerprint_benches, campaign_benches, contention_benches);
