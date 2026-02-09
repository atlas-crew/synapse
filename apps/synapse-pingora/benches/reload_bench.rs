//! Hot reload benchmarks.
//!
//! Measures config reload latency, concurrent read contention during reloads,
//! VhostMatcher reconstruction costs, and concurrent reload prevention.
//!
//! Run with: `cargo bench --bench reload_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::{ConfigReloader, SiteConfig, VhostMatcher};

// ============================================================================
// Helpers
// ============================================================================

/// Path to the benchmark fixture config.
const FIXTURE_PATH: &str = "benches/fixtures/bench_config.yaml";

/// Create a temporary config file by copying the fixture.
fn create_temp_config() -> tempfile::NamedTempFile {
    let fixture_content = std::fs::read_to_string(FIXTURE_PATH).expect("fixture config must exist");
    let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
    tmp.write_all(fixture_content.as_bytes())
        .expect("write temp config");
    tmp.flush().expect("flush temp config");
    tmp
}

/// Generate N SiteConfig entries.
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
// 1. Parse and Swap — Full Reload Cycle
// ============================================================================

fn bench_parse_and_swap(c: &mut Criterion) {
    let mut group = c.benchmark_group("reload/parse_and_swap");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let tmp = create_temp_config();
    let reloader = ConfigReloader::new(tmp.path()).expect("create reloader");

    group.bench_function("reload", |b| {
        b.iter(|| {
            let result = reloader.reload();
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 2. Concurrent Read During Reload
// ============================================================================

fn bench_concurrent_read_during_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("reload/concurrent_read_during_reload");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let tmp = create_temp_config();
    let reloader = Arc::new(ConfigReloader::new(tmp.path()).expect("create reloader"));

    group.bench_function("8_readers_1_writer", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                // 8 reader threads
                for _ in 0..8 {
                    let reloader = Arc::clone(&reloader);
                    s.spawn(move || {
                        for i in 0..100 {
                            let matcher = reloader.vhost_matcher();
                            let guard = matcher.read();
                            let host = format!("site{}.example.com", i % 20);
                            let result = guard.match_host(black_box(&host));
                            black_box(result);
                        }
                    });
                }
                // 1 writer thread
                let reloader = Arc::clone(&reloader);
                s.spawn(move || {
                    for _ in 0..10 {
                        let result = reloader.reload();
                        black_box(result);
                    }
                });
            });
        });
    });

    group.finish();
}

// ============================================================================
// 3. VhostMatcher Rebuild — Various Site Counts
// ============================================================================

fn bench_vhost_matcher_rebuild(c: &mut Criterion) {
    let mut group = c.benchmark_group("reload/vhost_matcher_rebuild");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    for count in [10, 50, 200] {
        let sites = make_sites(count);

        group.bench_with_input(BenchmarkId::new("build", count), &sites, |b, sites| {
            b.iter(|| {
                let matcher = VhostMatcher::new(black_box(sites.clone()));
                black_box(matcher);
            });
        });
    }

    group.finish();
}

// ============================================================================
// 4. Reload Prevention — Concurrent Reload Attempts
// ============================================================================

fn bench_reload_prevention(c: &mut Criterion) {
    let mut group = c.benchmark_group("reload/reload_prevention");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    let tmp = create_temp_config();
    let reloader = Arc::new(ConfigReloader::new(tmp.path()).expect("create reloader"));

    group.bench_function("2_concurrent_reloads", |b| {
        b.iter(|| {
            std::thread::scope(|s| {
                let r1 = Arc::clone(&reloader);
                let r2 = Arc::clone(&reloader);

                let h1 = s.spawn(move || {
                    let result = r1.reload();
                    black_box(result)
                });
                let h2 = s.spawn(move || {
                    let result = r2.reload();
                    black_box(result)
                });

                black_box(h1.join().unwrap());
                black_box(h2.join().unwrap());
            });
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    reload_benches,
    bench_parse_and_swap,
    bench_concurrent_read_during_reload,
    bench_vhost_matcher_rebuild,
    bench_reload_prevention,
);

criterion_main!(reload_benches);
