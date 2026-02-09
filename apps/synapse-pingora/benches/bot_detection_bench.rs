//! Bot detection benchmarks for the CrawlerDetector module.
//!
//! Measures per-request bot detection latency across the full 500+ signature
//! database, including sync pattern matching, async verification with caching,
//! multi-threaded contention, and realistic mixed-traffic throughput.
//!
//! Run with: `cargo bench --bench bot_detection_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::crawler::{CrawlerConfig, CrawlerDetector};

// ============================================================================
// Helpers
// ============================================================================

fn build_detector() -> CrawlerDetector {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for bench");

    rt.block_on(async {
        CrawlerDetector::new(CrawlerConfig::default())
            .await
            .unwrap_or_else(|_| CrawlerDetector::disabled())
    })
}

const NORMAL_BROWSER: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const BAD_BOT_EARLY: &str = "python-requests/2.28.0";
const BAD_BOT_LATE: &str = "Scrapy/2.11.0 (+https://scrapy.org)";
const GOOD_CRAWLER: &str = "Googlebot/2.1 (+http://www.google.com/bot.html)";

// ============================================================================
// 1. check_bad_bot — Sync Pattern Matching
// ============================================================================

fn bench_check_bad_bot(c: &mut Criterion) {
    let mut group = c.benchmark_group("bot/check_bad_bot");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    let detector = build_detector();

    group.bench_function("hit_early", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box(BAD_BOT_EARLY));
            black_box(result);
        });
    });

    group.bench_function("miss_normal_browser", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box(NORMAL_BROWSER));
            black_box(result);
        });
    });

    group.bench_function("hit_late", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box(BAD_BOT_LATE));
            black_box(result);
        });
    });

    group.bench_function("empty_ua", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box(""));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 2. verify — Async with Cache
// ============================================================================

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("bot/verify");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for bench");

    let detector = rt.block_on(async {
        CrawlerDetector::new(CrawlerConfig::default())
            .await
            .unwrap_or_else(|_| CrawlerDetector::disabled())
    });

    let test_ip: IpAddr = "93.184.216.34".parse().unwrap();

    // Pre-warm cache
    rt.block_on(async {
        let _ = detector.verify(GOOD_CRAWLER, test_ip).await;
    });

    group.bench_function("verify_cached", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = detector
                    .verify(black_box(GOOD_CRAWLER), black_box(test_ip))
                    .await;
                black_box(result);
            });
        });
    });

    group.bench_function("verify_cold", |b| {
        let mut idx = 0u32;
        b.iter(|| {
            let ip: IpAddr = format!(
                "10.{}.{}.{}",
                (idx >> 16) & 0xFF,
                (idx >> 8) & 0xFF,
                idx & 0xFF
            )
            .parse()
            .unwrap();
            rt.block_on(async {
                let result = detector
                    .verify(black_box(NORMAL_BROWSER), black_box(ip))
                    .await;
                black_box(result);
            });
            idx = idx.wrapping_add(1);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Contention — Multi-Threaded check_bad_bot
// ============================================================================

fn bench_bot_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("bot/contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let detector = Arc::new(build_detector());

    let user_agents = [NORMAL_BROWSER, BAD_BOT_EARLY, GOOD_CRAWLER, BAD_BOT_LATE];

    for &threads in &[1, 2, 4, 8] {
        group.bench_with_input(
            BenchmarkId::new("check_bad_bot", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let detector = Arc::clone(&detector);
                            s.spawn(move || {
                                for i in 0..500 {
                                    let ua = user_agents[(t * 500 + i) % user_agents.len()];
                                    let result = detector.check_bad_bot(black_box(ua));
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
// 4. Throughput — Realistic Mixed Traffic
// ============================================================================

fn bench_bot_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("bot/throughput");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);
    group.throughput(Throughput::Elements(1000));

    let detector = build_detector();

    // Pre-generate 1000 UAs: 900 normal, 80 bad bots, 20 good crawlers
    let mut user_agents: Vec<&str> = Vec::with_capacity(1000);
    for _ in 0..900 {
        user_agents.push(NORMAL_BROWSER);
    }
    for _ in 0..40 {
        user_agents.push(BAD_BOT_EARLY);
    }
    for _ in 0..40 {
        user_agents.push(BAD_BOT_LATE);
    }
    for _ in 0..20 {
        user_agents.push(GOOD_CRAWLER);
    }

    group.bench_function("mixed_traffic_1000", |b| {
        b.iter(|| {
            for ua in &user_agents {
                let result = detector.check_bad_bot(black_box(ua));
                black_box(result);
            }
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    bot_benches,
    bench_check_bad_bot,
    bench_verify,
    bench_bot_contention,
    bench_bot_throughput,
);

criterion_main!(bot_benches);
