//! Benchmarks for the API profiler, distribution/percentile tracking, and payload manager.
//!
//! Groups:
//! - profiler/distribution    — Welford distribution update, z-score, percentiles
//! - profiler/percentiles     — P-square streaming percentiles
//! - profiler/update_profile  — Endpoint profile learning (various payload shapes)
//! - profiler/analyze_request — Anomaly detection against learned baselines
//! - profiler/response_profile — Response profiling and analysis
//! - payload/record_request   — Payload manager request recording + anomaly check
//! - payload/bandwidth_tracking — Per-entity bandwidth and top-entity queries
//! - contention/profiler      — Multi-threaded profiler contention

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::{Distribution, PercentilesTracker, Profiler, ProfilerConfig};
use synapse_pingora::{PayloadConfig, PayloadManager};

// ============================================================================
// Helpers
// ============================================================================

/// Create a Profiler with sensible benchmark defaults.
fn bench_profiler() -> Profiler {
    Profiler::new(ProfilerConfig {
        enabled: true,
        max_profiles: 1000,
        max_schemas: 500,
        min_samples_for_validation: 10,
        freeze_after_samples: 0, // never freeze during benchmarks
        ..Default::default()
    })
}

/// Warm a profiler with `n` updates for a given template.
fn warm_profiler(profiler: &Profiler, template: &str, n: usize) {
    for i in 0..n {
        let size = 200 + (i % 300); // varying payload sizes 200–499
        profiler.update_profile(
            template,
            size,
            &[("page", "1"), ("limit", "20")],
            Some("application/json"),
        );
        // Also feed response data so analyze_response has a baseline
        profiler.update_response_profile(template, 1024 + (i % 512), 200, Some("application/json"));
    }
}

// ============================================================================
// 1. Distribution — Welford online statistics
// ============================================================================

fn bench_distribution_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler/distribution");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    // cold_start — first 10 updates with no prior history
    group.bench_function("cold_start", |b| {
        b.iter(|| {
            let mut d = Distribution::new();
            for v in 0..10 {
                d.update(black_box(v as f64 * 100.0));
            }
            black_box(&d);
        })
    });

    // warm — add one update after 1000 existing samples
    group.bench_function("warm", |b| {
        let mut d = Distribution::new();
        for i in 0..1000 {
            d.update(i as f64);
        }
        b.iter(|| {
            let mut d = d.clone();
            d.update(black_box(500.0));
            black_box(&d);
        })
    });

    // z_score — compute z-score on a warmed distribution
    group.bench_function("z_score", |b| {
        let mut d = Distribution::new();
        for i in 0..1000 {
            d.update(i as f64);
        }
        b.iter(|| black_box(d.z_score(black_box(750.0))))
    });

    // percentiles — retrieve (p50, p95, p99)
    group.bench_function("percentiles", |b| {
        let mut d = Distribution::new();
        for i in 0..1000 {
            d.update(i as f64);
        }
        b.iter(|| black_box(d.percentiles()))
    });

    // mean_stddev — compute both mean and stddev
    group.bench_function("mean_stddev", |b| {
        let mut d = Distribution::new();
        for i in 0..1000 {
            d.update(i as f64);
        }
        b.iter(|| {
            let m = black_box(d.mean());
            let s = black_box(d.stddev());
            black_box((m, s));
        })
    });

    group.finish();
}

// ============================================================================
// 2. PercentilesTracker — P-square streaming percentiles
// ============================================================================

fn bench_percentiles_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler/percentiles");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    // update — single sample insertion
    group.bench_function("update", |b| {
        let mut pt = PercentilesTracker::new();
        // Initialise past the 5-sample bootstrap
        for i in 0..10 {
            pt.update(i as f64);
        }
        let mut counter = 10u64;
        b.iter(|| {
            counter += 1;
            pt.update(black_box(counter as f64));
        })
    });

    // get — retrieve (p50, p95, p99) after 1000 updates
    group.bench_function("get", |b| {
        let mut pt = PercentilesTracker::new();
        for i in 0..1000 {
            pt.update(i as f64);
        }
        b.iter(|| black_box(pt.get()))
    });

    group.finish();
}

// ============================================================================
// 3. Profiler — update_profile
// ============================================================================

fn bench_profiler_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler/update_profile");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let profiler = bench_profiler();
    // Pre-warm with 100 updates to /api/users
    warm_profiler(&profiler, "/api/users", 100);

    // simple_get — zero payload, no params, no content type
    group.bench_function("simple_get", |b| {
        b.iter(|| {
            profiler.update_profile(
                black_box("/api/users"),
                black_box(0),
                black_box(&[][..]),
                black_box(None),
            );
        })
    });

    // with_params — medium payload with query params and JSON content type
    group.bench_function("with_params", |b| {
        let params: &[(&str, &str)] = &[("q", "test"), ("page", "1"), ("limit", "20")];
        b.iter(|| {
            profiler.update_profile(
                black_box("/api/search"),
                black_box(256),
                black_box(params),
                black_box(Some("application/json")),
            );
        })
    });

    // large_post — 64 KiB multipart upload
    group.bench_function("large_post", |b| {
        b.iter(|| {
            profiler.update_profile(
                black_box("/api/upload"),
                black_box(65536),
                black_box(&[][..]),
                black_box(Some("multipart/form-data")),
            );
        })
    });

    group.finish();
}

// ============================================================================
// 4. Profiler — analyze_request (anomaly detection)
// ============================================================================

fn bench_profiler_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler/analyze_request");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let profiler = bench_profiler();
    // Pre-warm with 500 updates to establish a robust baseline
    warm_profiler(&profiler, "/api/users", 500);

    // normal_request — within learned baseline
    group.bench_function("normal_request", |b| {
        let params: &[(&str, &str)] = &[("page", "1"), ("limit", "20")];
        b.iter(|| {
            black_box(profiler.analyze_request(
                black_box("/api/users"),
                black_box(300),
                black_box(params),
                black_box(Some("application/json")),
            ));
        })
    });

    // anomalous_size — 10x the normal payload size
    group.bench_function("anomalous_size", |b| {
        let params: &[(&str, &str)] = &[("page", "1"), ("limit", "20")];
        b.iter(|| {
            black_box(profiler.analyze_request(
                black_box("/api/users"),
                black_box(3500), // ~10x the mean (~350)
                black_box(params),
                black_box(Some("application/json")),
            ));
        })
    });

    // new_params — parameters not seen during training
    group.bench_function("new_params", |b| {
        let params: &[(&str, &str)] = &[
            ("page", "1"),
            ("limit", "20"),
            ("debug", "true"),
            ("__proto__", "polluted"),
        ];
        b.iter(|| {
            black_box(profiler.analyze_request(
                black_box("/api/users"),
                black_box(300),
                black_box(params),
                black_box(Some("application/json")),
            ));
        })
    });

    // new_endpoint — template never profiled
    group.bench_function("new_endpoint", |b| {
        b.iter(|| {
            black_box(profiler.analyze_request(
                black_box("/api/never-seen"),
                black_box(512),
                black_box(&[("x", "y")][..]),
                black_box(Some("text/plain")),
            ));
        })
    });

    group.finish();
}

// ============================================================================
// 5. Profiler — response profiling and analysis
// ============================================================================

fn bench_profiler_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiler/response_profile");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let profiler = bench_profiler();
    warm_profiler(&profiler, "/api/items", 500);

    // update_response_profile — 200 OK
    group.bench_function("update_200", |b| {
        b.iter(|| {
            profiler.update_response_profile(
                black_box("/api/items"),
                black_box(1024),
                black_box(200),
                black_box(Some("application/json")),
            );
        })
    });

    // update_response_profile — 404 Not Found
    group.bench_function("update_404", |b| {
        b.iter(|| {
            profiler.update_response_profile(
                black_box("/api/items"),
                black_box(128),
                black_box(404),
                black_box(Some("application/json")),
            );
        })
    });

    // update_response_profile — 500 Internal Server Error
    group.bench_function("update_500", |b| {
        b.iter(|| {
            profiler.update_response_profile(
                black_box("/api/items"),
                black_box(256),
                black_box(500),
                black_box(Some("text/html")),
            );
        })
    });

    // analyze_response — 200 OK (normal)
    group.bench_function("analyze_200", |b| {
        b.iter(|| {
            black_box(profiler.analyze_response(
                black_box("/api/items"),
                black_box(1024),
                black_box(200),
                black_box(Some("application/json")),
            ));
        })
    });

    // analyze_response — 404 Not Found
    group.bench_function("analyze_404", |b| {
        b.iter(|| {
            black_box(profiler.analyze_response(
                black_box("/api/items"),
                black_box(128),
                black_box(404),
                black_box(Some("application/json")),
            ));
        })
    });

    // analyze_response — 500 Internal Server Error
    group.bench_function("analyze_500", |b| {
        b.iter(|| {
            black_box(profiler.analyze_response(
                black_box("/api/items"),
                black_box(256),
                black_box(500),
                black_box(Some("text/html")),
            ));
        })
    });

    group.finish();
}

// ============================================================================
// 6. PayloadManager — record_request + check_anomalies
// ============================================================================

fn bench_payload_manager(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload/record_request");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let manager = PayloadManager::new(PayloadConfig::default());

    // small_request — 256 B req, 1024 B resp
    group.bench_function("small_request", |b| {
        b.iter(|| {
            manager.record_request(
                black_box("/api/users"),
                black_box("10.0.0.1"),
                black_box(256),
                black_box(1024),
            );
        })
    });

    // large_request — 64 KiB req, 256 KiB resp
    group.bench_function("large_request", |b| {
        b.iter(|| {
            manager.record_request(
                black_box("/api/upload"),
                black_box("10.0.0.2"),
                black_box(65536),
                black_box(262144),
            );
        })
    });

    // check_anomalies after 1000 recorded requests
    group.bench_function("check_anomalies", |b| {
        let mgr = PayloadManager::new(PayloadConfig {
            warmup_requests: 50, // lower warmup so anomalies activate
            ..PayloadConfig::default()
        });
        for i in 0..1000 {
            let entity = format!("10.0.{}.{}", (i / 256) % 256, i % 256);
            mgr.record_request(
                "/api/data",
                &entity,
                512 + (i as u64 % 1024),
                2048 + (i as u64 % 4096),
            );
        }
        b.iter(|| black_box(mgr.check_anomalies()))
    });

    group.finish();
}

// ============================================================================
// 7. PayloadManager — bandwidth tracking
// ============================================================================

fn bench_payload_bandwidth(c: &mut Criterion) {
    let mut group = c.benchmark_group("payload/bandwidth_tracking");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    // Build up bandwidth data from 100 different entities
    let manager = PayloadManager::new(PayloadConfig::default());
    for i in 0..100 {
        let entity = format!("192.168.1.{}", i);
        for j in 0..50 {
            manager.record_request(
                &format!("/api/endpoint_{}", j % 10),
                &entity,
                256 + (j as u64 * 32),
                1024 + (j as u64 * 64),
            );
        }
    }

    // get_entity_bandwidth — single entity lookup
    group.bench_function("get_entity_bandwidth", |b| {
        b.iter(|| black_box(manager.get_entity_bandwidth(black_box("192.168.1.50"))))
    });

    // list_top_entities — top 10 by total bandwidth
    group.bench_function("list_top_entities_10", |b| {
        b.iter(|| black_box(manager.list_top_entities(black_box(10))))
    });

    group.finish();
}

// ============================================================================
// 8. Profiler — multi-threaded contention
// ============================================================================

fn bench_profiler_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/profiler");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    // Pre-generate endpoint templates to avoid allocation in the hot loop
    let templates: Vec<String> = (0..100).map(|i| format!("/api/endpoint_{}", i)).collect();

    for thread_count in [1, 2, 4, 8] {
        // Fresh profiler per thread configuration
        let profiler = Arc::new(bench_profiler());

        // Pre-warm all templates so analyze_request has baselines
        for tpl in &templates {
            warm_profiler(&profiler, tpl, 50);
        }

        group.bench_with_input(
            BenchmarkId::new("mixed_update_analyze", format!("{}t", thread_count)),
            &thread_count,
            |b, &threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        let handles: Vec<_> = (0..threads)
                            .map(|t| {
                                let profiler = Arc::clone(&profiler);
                                let templates = &templates;
                                s.spawn(move || {
                                    let offset = t * 100;
                                    for i in 0..500 {
                                        let tpl = &templates[(offset + i) % templates.len()];
                                        if i % 3 == 0 {
                                            // ~33% writes (update_profile)
                                            profiler.update_profile(
                                                tpl,
                                                black_box(256 + i),
                                                black_box(&[("k", "v")][..]),
                                                black_box(Some("application/json")),
                                            );
                                        } else {
                                            // ~67% reads (analyze_request)
                                            black_box(profiler.analyze_request(
                                                tpl,
                                                black_box(300 + i),
                                                black_box(&[("page", "1")][..]),
                                                black_box(Some("application/json")),
                                            ));
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
// Criterion harness
// ============================================================================

criterion_group!(
    profiler_benches,
    bench_distribution_update,
    bench_percentiles_tracker,
    bench_profiler_update,
    bench_profiler_analyze,
    bench_profiler_response,
    bench_payload_manager,
    bench_payload_bandwidth,
    bench_profiler_contention,
);

criterion_main!(profiler_benches);
