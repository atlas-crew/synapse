//! Risk scoring, actor management, and blocklist benchmarks.
//!
//! Tests the per-request risk pipeline: entity risk application,
//! decay calculations, repeat offender multipliers, actor correlation,
//! and blocklist lookups.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use synapse_pingora::horizon::{BlocklistCache, BlocklistEntry, BlockType};
use synapse_pingora::{ActorConfig, ActorManager};
use synapse_pingora::{EntityConfig, EntityManager};

/// Pre-generate a pool of IP address strings to avoid allocation noise in hot loops.
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

/// Pre-generate a pool of parsed IpAddr values.
fn generate_ipaddr_pool(count: usize) -> Vec<IpAddr> {
    (0..count)
        .map(|i| {
            let o2 = ((i >> 16) & 0xFF) as u8;
            let o3 = ((i >> 8) & 0xFF) as u8;
            let o4 = (i & 0xFF) as u8;
            IpAddr::from([10, o2, o3, o4])
        })
        .collect()
}

/// Create an EntityManager with default config but a specified max_entities.
fn create_entity_manager(max_entities: usize) -> EntityManager {
    EntityManager::new(EntityConfig {
        max_entities,
        ..EntityConfig::default()
    })
}

// ============================================================================
// 1. Risk Application — apply_rule_risk
// ============================================================================

fn bench_risk_application(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk/apply_rule_risk");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);
    group.noise_threshold(0.02);

    let ip_pool = generate_ip_pool(1000);

    // --- first_hit: Entity with 0 prior matches ---
    {
        let em = create_entity_manager(50_000);
        // Pre-populate 1000 entities
        for ip in &ip_pool {
            em.touch_entity(ip);
        }

        group.bench_function("first_hit", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.apply_rule_risk(ip, 1001, 25.0, true))
            })
        });
    }

    // --- repeat_offender: Entity pre-loaded with 10 prior rule matches ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
        }
        // Pre-load 10 rule matches on every entity
        for ip in &ip_pool {
            for _ in 0..10 {
                em.apply_rule_risk(ip, 1001, 25.0, true);
            }
        }

        group.bench_function("repeat_offender", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.apply_rule_risk(ip, 1001, 25.0, true))
            })
        });
    }

    // --- high_risk_near_threshold: Entity pre-loaded to risk ~65 (near default 70.0 block threshold) ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
        }
        // Apply external risk to set each entity near threshold (~65)
        for ip in &ip_pool {
            em.apply_external_risk(ip, 65.0, "setup");
        }

        group.bench_function("high_risk_near_threshold", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.apply_rule_risk(ip, 1001, 25.0, true))
            })
        });
    }

    group.finish();
}

// ============================================================================
// 2. External Risk — apply_external_risk
// ============================================================================

fn bench_risk_external(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk/apply_external_risk");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let ip_pool = generate_ip_pool(1000);

    // --- cold_entity: New entity (not yet in the store) ---
    {
        let em = create_entity_manager(50_000);

        group.bench_function("cold_entity", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                // Use IPs beyond the pre-populated range so they're truly cold
                let ip = format!("172.16.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
                idx = idx.wrapping_add(1);
                black_box(em.apply_external_risk(&ip, 15.0, "threat_intel"))
            })
        });
    }

    // --- warm_entity: Entity with many prior touches ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
        }
        // Warm up with many touches
        for _ in 0..50 {
            for ip in &ip_pool {
                em.touch_entity(ip);
            }
        }

        group.bench_function("warm_entity", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.apply_external_risk(ip, 15.0, "threat_intel"))
            })
        });
    }

    group.finish();
}

// ============================================================================
// 3. Block Check — check_block
// ============================================================================

fn bench_block_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk/check_block");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    let ip_pool = generate_ip_pool(1000);

    // --- below_threshold: Entity at risk ~30 ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
            em.apply_external_risk(ip, 30.0, "setup");
        }

        group.bench_function("below_threshold", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.check_block(ip))
            })
        });
    }

    // --- above_threshold: Entity at risk ~90 ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
            em.apply_external_risk(ip, 90.0, "setup");
        }

        group.bench_function("above_threshold", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.check_block(ip))
            })
        });
    }

    // --- unknown_entity: IP not in store ---
    {
        let em = create_entity_manager(50_000);
        // Populate some entities, but we'll query IPs that don't exist
        for ip in &ip_pool {
            em.touch_entity(ip);
        }
        let unknown_ips: Vec<String> = (0..1000)
            .map(|i| format!("192.168.{}.{}", (i >> 8) & 0xFF, i & 0xFF))
            .collect();

        group.bench_function("unknown_entity", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &unknown_ips[idx % unknown_ips.len()];
                idx = idx.wrapping_add(1);
                black_box(em.check_block(ip))
            })
        });
    }

    group.finish();
}

// ============================================================================
// 4. Fingerprint Touch — touch_entity_with_fingerprint
// ============================================================================

fn bench_entity_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk/touch_with_fingerprint");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let ip_pool = generate_ip_pool(1000);

    // --- new_entity: IP not yet in store ---
    {
        let em = create_entity_manager(50_000);

        group.bench_function("new_entity", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = format!("172.16.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
                idx = idx.wrapping_add(1);
                black_box(em.touch_entity_with_fingerprint(
                    &ip,
                    Some("t13d1516h2_abc"),
                    Some("combined_fp_xyz"),
                ))
            })
        });
    }

    // --- existing_entity: IP already in store ---
    {
        let em = create_entity_manager(50_000);
        for ip in &ip_pool {
            em.touch_entity(ip);
        }

        group.bench_function("existing_entity", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = &ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(em.touch_entity_with_fingerprint(
                    ip,
                    Some("t13d1516h2_abc"),
                    Some("combined_fp_xyz"),
                ))
            })
        });
    }

    group.finish();
}

// ============================================================================
// 5. Risk Decay Under Load — decay calculation overhead
// ============================================================================

fn bench_risk_decay(c: &mut Criterion) {
    let mut group = c.benchmark_group("risk/decay_under_load");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    for entity_count in [100, 1000, 10_000] {
        let ip_pool = generate_ip_pool(entity_count);
        let em = create_entity_manager(50_000);

        // Populate entities and apply risk to all of them
        for ip in &ip_pool {
            em.touch_entity(ip);
            em.apply_external_risk(ip, 50.0, "setup");
        }

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::new("apply_rule_risk", entity_count),
            &entity_count,
            |b, _| {
                let mut idx = 0usize;
                b.iter(|| {
                    let ip = &ip_pool[idx % ip_pool.len()];
                    idx = idx.wrapping_add(1);
                    // apply_rule_risk triggers internal decay calculation
                    black_box(em.apply_rule_risk(ip, 1001, 25.0, true))
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// 6. Actor Management — get_or_create_actor
// ============================================================================

fn bench_actor_management(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/get_or_create");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let ip_pool = generate_ipaddr_pool(1000);

    // --- create_new: New IP that doesn't exist yet (cycles through IPs) ---
    {
        let am = ActorManager::new(ActorConfig::default());

        group.bench_function("create_new", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                // Generate IPs beyond pre-populated range for truly new actors
                let o2 = ((idx >> 16) & 0xFF) as u8;
                let o3 = ((idx >> 8) & 0xFF) as u8;
                let o4 = (idx & 0xFF) as u8;
                let ip = IpAddr::from([172, o2, o3, o4]);
                idx = idx.wrapping_add(1);
                black_box(am.get_or_create_actor(ip, None))
            })
        });
    }

    // --- get_existing: Known IP ---
    {
        let am = ActorManager::new(ActorConfig::default());
        // Pre-populate 1000 actors
        for ip in &ip_pool {
            am.get_or_create_actor(*ip, None);
        }

        group.bench_function("get_existing", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(am.get_or_create_actor(ip, None))
            })
        });
    }

    // --- with_fingerprint: IP + fingerprint correlation ---
    {
        let am = ActorManager::new(ActorConfig::default());
        // Pre-populate 1000 actors with fingerprints
        for ip in &ip_pool {
            am.get_or_create_actor(*ip, Some("ja4_fp_abc"));
        }

        group.bench_function("with_fingerprint", |b| {
            let mut idx = 0usize;
            b.iter(|| {
                let ip = ip_pool[idx % ip_pool.len()];
                idx = idx.wrapping_add(1);
                black_box(am.get_or_create_actor(ip, Some("ja4_fp_abc")))
            })
        });
    }

    group.finish();
}

// ============================================================================
// 7. Actor Rule Match — record_rule_match
// ============================================================================

fn bench_actor_rule_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/record_rule_match");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let ip_pool = generate_ipaddr_pool(1000);
    let am = ActorManager::new(ActorConfig::default());

    // Pre-create actors and collect their IDs
    let actor_ids: Vec<String> = ip_pool
        .iter()
        .map(|ip| am.get_or_create_actor(*ip, None))
        .collect();

    group.bench_function("record_match", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let actor_id = &actor_ids[idx % actor_ids.len()];
            idx = idx.wrapping_add(1);
            black_box(am.record_rule_match(actor_id, "rule_1001", 25.0, "sqli"))
        })
    });

    group.finish();
}

// ============================================================================
// 8. Blocklist Lookup — BlocklistCache
// ============================================================================

fn bench_blocklist_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("horizon/blocklist");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10_000);

    let cache = BlocklistCache::new();

    // Populate with 1000 IPs
    for i in 0..1000 {
        let ip = format!("10.0.{}.{}", (i >> 8) & 0xFF, i & 0xFF);
        cache.add(BlocklistEntry {
            block_type: BlockType::Ip,
            indicator: ip,
            expires_at: None,
            source: "bench".to_string(),
            reason: Some("benchmark setup".to_string()),
            created_at: None,
        });
    }

    // Populate with 500 fingerprints
    for i in 0..500 {
        cache.add(BlocklistEntry {
            block_type: BlockType::Fingerprint,
            indicator: format!("fp_blocked_{}", i),
            expires_at: None,
            source: "bench".to_string(),
            reason: Some("benchmark setup".to_string()),
            created_at: None,
        });
    }

    // --- is_ip_blocked_hit: IP that's in the blocklist ---
    group.bench_function("is_ip_blocked_hit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = format!("10.0.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            let ip = &ip[..]; // borrow as &str
            idx = (idx + 1) % 1000;
            black_box(cache.is_ip_blocked(ip))
        })
    });

    // --- is_ip_blocked_miss: IP not in blocklist ---
    group.bench_function("is_ip_blocked_miss", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = format!("192.168.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            idx = idx.wrapping_add(1);
            black_box(cache.is_ip_blocked(&ip))
        })
    });

    // --- is_fingerprint_blocked_hit: Fingerprint in blocklist ---
    group.bench_function("is_fingerprint_blocked_hit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let fp = format!("fp_blocked_{}", idx % 500);
            idx = idx.wrapping_add(1);
            black_box(cache.is_fingerprint_blocked(&fp))
        })
    });

    // --- is_fingerprint_blocked_miss: Not in blocklist ---
    group.bench_function("is_fingerprint_blocked_miss", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let fp = format!("fp_miss_{}", idx);
            idx = idx.wrapping_add(1);
            black_box(cache.is_fingerprint_blocked(&fp))
        })
    });

    // --- is_blocked_combined: Check both IP and fingerprint ---
    group.bench_function("is_blocked_combined", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = format!("10.0.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            let fp = format!("fp_blocked_{}", idx % 500);
            idx = (idx + 1) % 1000;
            black_box(cache.is_blocked(Some(&ip), Some(&fp)))
        })
    });

    group.finish();
}

// ============================================================================
// 9. Actor Contention — multi-threaded get_or_create + touch
// ============================================================================

fn bench_actor_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/actor_manager");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let ip_pool = generate_ipaddr_pool(10_000);

    for thread_count in [1, 2, 4, 8] {
        let am = Arc::new(ActorManager::new(ActorConfig::default()));

        // Pre-populate some actors so get_existing and touch paths are exercised
        for ip in ip_pool.iter().take(1000) {
            am.get_or_create_actor(*ip, None);
        }

        group.bench_with_input(
            BenchmarkId::new("get_or_create_and_touch", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let am = Arc::clone(&am);
                                let pool = &ip_pool;
                                s.spawn(move || {
                                    let offset = t * 1000;
                                    for i in 0..1000 {
                                        let ip = pool[(offset + i) % pool.len()];
                                        let actor_id =
                                            black_box(am.get_or_create_actor(ip, None));
                                        black_box(am.touch_actor(&actor_id));
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
// Criterion Groups
// ============================================================================

criterion_group!(
    risk_benches,
    bench_risk_application,
    bench_risk_external,
    bench_block_check,
    bench_entity_fingerprint,
    bench_risk_decay,
);

criterion_group!(
    actor_benches,
    bench_actor_management,
    bench_actor_rule_match,
);

criterion_group!(blocklist_benches, bench_blocklist_lookup,);

criterion_group!(contention_benches, bench_actor_contention,);

criterion_main!(risk_benches, actor_benches, blocklist_benches, contention_benches);
