//! Actor state management benchmarks.
//!
//! Measures actor creation, lookup by IP/fingerprint, block/unblock state
//! transitions, rule match recording, session binding, and concurrent
//! contention across the DashMap-backed ActorManager.
//!
//! Run with: `cargo bench --bench actor_session_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::{ActorConfig, ActorManager};

// ============================================================================
// Helpers
// ============================================================================

fn test_config() -> ActorConfig {
    ActorConfig {
        enabled: true,
        max_actors: 50_000,
        ..Default::default()
    }
}

fn test_ip(idx: u64) -> IpAddr {
    let o2 = ((idx >> 16) & 0xFF) as u8;
    let o3 = ((idx >> 8) & 0xFF) as u8;
    let o4 = (idx & 0xFF) as u8;
    IpAddr::from([10, o2, o3, o4])
}

// ============================================================================
// 1. Actor Creation & Lookup
// ============================================================================

fn bench_actor_create_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/create_lookup");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = ActorManager::new(test_config());

    group.bench_function("get_or_create_new", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let ip = test_ip(idx);
            let actor_id = manager.get_or_create_actor(black_box(ip), black_box(None));
            black_box(actor_id);
            idx += 1;
        });
    });

    // Pre-populate for existing lookups
    let pre_manager = ActorManager::new(test_config());
    let mut pre_ids = Vec::new();
    for i in 0..1000u64 {
        let id = pre_manager.get_or_create_actor(test_ip(i), None);
        pre_ids.push(id);
    }

    group.bench_function("get_or_create_existing", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ip = test_ip(idx as u64 % 1000);
            let actor_id = pre_manager.get_or_create_actor(black_box(ip), black_box(None));
            black_box(actor_id);
            idx += 1;
        });
    });

    group.bench_function("get_or_create_with_fingerprint", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let ip = test_ip(idx + 100_000);
            let fp = format!("t13d1516h2_bench_{}", idx % 500);
            let actor_id = pre_manager.get_or_create_actor(black_box(ip), black_box(Some(&fp)));
            black_box(actor_id);
            idx += 1;
        });
    });

    group.bench_function("get_actor_existing", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = &pre_ids[idx % pre_ids.len()];
            let state = pre_manager.get_actor(black_box(id));
            black_box(state);
            idx += 1;
        });
    });

    group.bench_function("get_actor_missing", |b| {
        b.iter(|| {
            let state = pre_manager.get_actor(black_box("nonexistent-actor-id"));
            black_box(state);
        });
    });

    group.finish();
}

// ============================================================================
// 2. Block / Unblock State Transitions
// ============================================================================

fn bench_actor_block_unblock(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/block_unblock");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    group.bench_function("block_then_check", |b| {
        let manager = ActorManager::new(test_config());
        // Pre-create actors
        let mut ids = Vec::new();
        for i in 0..500u64 {
            ids.push(manager.get_or_create_actor(test_ip(i), None));
        }

        let mut idx = 0usize;
        b.iter(|| {
            let id = &ids[idx % ids.len()];
            manager.block_actor(black_box(id), black_box("benchmark"));
            let blocked = manager.is_blocked(black_box(id));
            black_box(blocked);
            // Unblock for next iteration
            manager.unblock_actor(id);
            idx += 1;
        });
    });

    group.bench_function("is_blocked_check", |b| {
        let manager = ActorManager::new(test_config());
        let mut ids = Vec::new();
        for i in 0..1000u64 {
            let id = manager.get_or_create_actor(test_ip(i), None);
            // Block every other actor
            if i % 2 == 0 {
                manager.block_actor(&id, "bench-block");
            }
            ids.push(id);
        }

        let mut idx = 0usize;
        b.iter(|| {
            let id = &ids[idx % ids.len()];
            let blocked = manager.is_blocked(black_box(id));
            black_box(blocked);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 3. Rule Match Recording
// ============================================================================

fn bench_rule_match_recording(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/rule_match_recording");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = ActorManager::new(test_config());
    let mut ids = Vec::new();
    for i in 0..500u64 {
        ids.push(manager.get_or_create_actor(test_ip(i), None));
    }

    group.bench_function("record_rule_match", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = &ids[idx % ids.len()];
            manager.record_rule_match(
                black_box(id),
                black_box("rule-942100"),
                black_box(25.0),
                black_box("sqli"),
            );
            idx += 1;
        });
    });

    group.bench_function("touch_actor", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let id = &ids[idx % ids.len()];
            manager.touch_actor(black_box(id));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 4. Session Binding
// ============================================================================

fn bench_session_binding(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/session_binding");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = ActorManager::new(test_config());
    let mut ids = Vec::new();
    for i in 0..500u64 {
        ids.push(manager.get_or_create_actor(test_ip(i), None));
    }

    group.bench_function("bind_session", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let id = &ids[(idx as usize) % ids.len()];
            let session = format!("sess-{}", idx);
            manager.bind_session(black_box(id), black_box(&session));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 5. Concurrent Contention
// ============================================================================

fn bench_actor_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("actor/contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    for &threads in &[1, 2, 4, 8] {
        let manager = Arc::new(ActorManager::new(test_config()));

        // Pre-populate
        for i in 0..1000u64 {
            manager.get_or_create_actor(test_ip(i), None);
        }

        group.bench_with_input(
            BenchmarkId::new("mixed_operations", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let mgr = Arc::clone(&manager);
                            s.spawn(move || {
                                for i in 0..200u64 {
                                    let ip = test_ip(t as u64 * 1000 + i);
                                    let actor_id =
                                        mgr.get_or_create_actor(black_box(ip), black_box(None));
                                    match i % 5 {
                                        0 => {
                                            mgr.record_rule_match(
                                                black_box(&actor_id),
                                                black_box("rule-bench"),
                                                black_box(10.0),
                                                black_box("xss"),
                                            );
                                        }
                                        1 => {
                                            mgr.block_actor(
                                                black_box(&actor_id),
                                                black_box("contention-bench"),
                                            );
                                        }
                                        2 => {
                                            black_box(mgr.is_blocked(black_box(&actor_id)));
                                        }
                                        3 => {
                                            let sess = format!("sess-{}-{}", t, i);
                                            mgr.bind_session(
                                                black_box(&actor_id),
                                                black_box(&sess),
                                            );
                                        }
                                        _ => {
                                            mgr.touch_actor(black_box(&actor_id));
                                        }
                                    }
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
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    actor_session_benches,
    bench_actor_create_lookup,
    bench_actor_block_unblock,
    bench_rule_match_recording,
    bench_session_binding,
    bench_actor_contention,
);

criterion_main!(actor_session_benches);
