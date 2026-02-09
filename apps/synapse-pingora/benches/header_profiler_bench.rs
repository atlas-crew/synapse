//! Header behavioral profiling benchmarks.
//!
//! Measures per-request header learning, anomaly analysis after baseline
//! establishment, baseline lookup, and concurrent contention on the
//! DashMap-backed HeaderProfiler.
//!
//! Run with: `cargo bench --bench header_profiler_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::HeaderProfiler;

// ============================================================================
// Helpers
// ============================================================================

fn normal_headers() -> Vec<(String, String)> {
    vec![
        (
            "accept".into(),
            "text/html,application/xhtml+xml,application/xml;q=0.9".into(),
        ),
        ("accept-encoding".into(), "gzip, deflate, br".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        (
            "user-agent".into(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".into(),
        ),
        ("connection".into(), "keep-alive".into()),
        ("cache-control".into(), "max-age=0".into()),
    ]
}

fn anomalous_headers() -> Vec<(String, String)> {
    vec![
        ("accept".into(), "*/*".into()),
        ("user-agent".into(), "curl/7.68.0".into()),
        // Missing common headers like accept-encoding, accept-language
        (
            "x-custom-attack".into(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        ),
        ("x-unusual-1".into(), "val".into()),
        ("x-unusual-2".into(), "val".into()),
        ("x-unusual-3".into(), "val".into()),
        ("x-unusual-4".into(), "val".into()),
        ("x-unusual-5".into(), "val".into()),
    ]
}

/// Build a profiler with a warm baseline (min_samples satisfied).
fn warmed_profiler(endpoint: &str, samples: u64) -> HeaderProfiler {
    let profiler = HeaderProfiler::with_config(10_000, 10); // Low min_samples for bench
    let headers = normal_headers();
    for _ in 0..samples {
        profiler.learn(endpoint, &headers);
    }
    profiler
}

// ============================================================================
// 1. Learning — Per-Request Baseline Building
// ============================================================================

fn bench_header_learn(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/learn");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let profiler = HeaderProfiler::with_config(10_000, 50);
    let headers = normal_headers();

    group.bench_function("learn_new_endpoint", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let endpoint = format!("/api/endpoint/{}", idx);
            profiler.learn(black_box(&endpoint), black_box(&headers));
            idx += 1;
        });
    });

    group.bench_function("learn_existing_endpoint", |b| {
        // Pre-warm a single endpoint
        for _ in 0..100 {
            profiler.learn("/api/users", &headers);
        }
        b.iter(|| {
            profiler.learn(black_box("/api/users"), black_box(&headers));
        });
    });

    // Varying header counts
    for count in [3, 6, 12, 20] {
        let hdrs: Vec<(String, String)> = (0..count)
            .map(|i| (format!("x-header-{}", i), format!("value-{}", i)))
            .collect();
        group.bench_with_input(BenchmarkId::new("header_count", count), &hdrs, |b, hdrs| {
            b.iter(|| {
                profiler.learn(black_box("/api/sized"), black_box(hdrs));
            });
        });
    }

    group.finish();
}

// ============================================================================
// 2. Analysis — Anomaly Detection After Baseline
// ============================================================================

fn bench_header_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/analyze");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let profiler = warmed_profiler("/api/analyze", 100);
    let normal = normal_headers();
    let anomalous = anomalous_headers();

    group.bench_function("conforming_request", |b| {
        b.iter(|| {
            let result = profiler.analyze(black_box("/api/analyze"), black_box(&normal));
            black_box(result);
        });
    });

    group.bench_function("anomalous_request", |b| {
        b.iter(|| {
            let result = profiler.analyze(black_box("/api/analyze"), black_box(&anomalous));
            black_box(result);
        });
    });

    group.bench_function("unknown_endpoint", |b| {
        b.iter(|| {
            let result = profiler.analyze(black_box("/api/never-seen"), black_box(&normal));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Baseline Lookup
// ============================================================================

fn bench_header_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/baseline");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let profiler = HeaderProfiler::with_config(10_000, 10);
    let headers = normal_headers();

    // Populate 500 endpoints
    for i in 0..500 {
        let ep = format!("/api/ep/{}", i);
        for _ in 0..20 {
            profiler.learn(&ep, &headers);
        }
    }

    group.bench_function("get_baseline_hit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ep = format!("/api/ep/{}", idx % 500);
            let baseline = profiler.get_baseline(black_box(&ep));
            black_box(baseline);
            idx += 1;
        });
    });

    group.bench_function("get_baseline_miss", |b| {
        b.iter(|| {
            let baseline = profiler.get_baseline(black_box("/api/nonexistent"));
            black_box(baseline);
        });
    });

    group.bench_function("endpoint_count", |b| {
        b.iter(|| {
            let count = profiler.endpoint_count();
            black_box(count);
        });
    });

    group.bench_function("stats", |b| {
        b.iter(|| {
            let stats = profiler.stats();
            black_box(stats);
        });
    });

    group.finish();
}

// ============================================================================
// 4. Combined Learn + Analyze Pipeline
// ============================================================================

fn bench_learn_then_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/learn_then_analyze");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let profiler = warmed_profiler("/api/pipeline", 100);
    let normal = normal_headers();

    group.bench_function("learn_and_analyze_same_endpoint", |b| {
        b.iter(|| {
            profiler.learn(black_box("/api/pipeline"), black_box(&normal));
            let result = profiler.analyze(black_box("/api/pipeline"), black_box(&normal));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Concurrent Contention
// ============================================================================

fn bench_header_profiler_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let headers = normal_headers();
    let anomalous = anomalous_headers();

    for &threads in &[1, 2, 4, 8] {
        // Fresh profiler with some baseline
        let profiler = Arc::new(warmed_profiler("/api/shared", 50));

        group.bench_with_input(
            BenchmarkId::new("learn_and_analyze", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                let headers = headers.clone();
                let anomalous = anomalous.clone();
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let profiler = Arc::clone(&profiler);
                            let headers = headers.clone();
                            let anomalous = anomalous.clone();
                            s.spawn(move || {
                                for i in 0..100 {
                                    let ep = format!("/api/shared/{}", i % 20);
                                    if i % 4 == 0 {
                                        // 25% analysis
                                        let hdrs = if t % 2 == 0 { &headers } else { &anomalous };
                                        let result =
                                            profiler.analyze(black_box(&ep), black_box(hdrs));
                                        black_box(result);
                                    } else {
                                        // 75% learning
                                        profiler.learn(black_box(&ep), black_box(&headers));
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
// 6. LRU Eviction Under Capacity Pressure
// ============================================================================

fn bench_eviction_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_profiler/eviction");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let headers = normal_headers();

    // Small capacity to trigger eviction
    let profiler = HeaderProfiler::with_config(100, 10);
    // Fill to capacity
    for i in 0..100 {
        let ep = format!("/api/fill/{}", i);
        for _ in 0..15 {
            profiler.learn(&ep, &headers);
        }
    }

    group.bench_function("learn_past_capacity", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let ep = format!("/api/evict/{}", idx);
            profiler.learn(black_box(&ep), black_box(&headers));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    header_profiler_benches,
    bench_header_learn,
    bench_header_analyze,
    bench_header_baseline,
    bench_learn_then_analyze,
    bench_header_profiler_contention,
    bench_eviction_pressure,
);

criterion_main!(header_profiler_benches);
