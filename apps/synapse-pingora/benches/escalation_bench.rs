//! Challenge escalation path benchmarks.
//!
//! Benchmarks the full challenge progression state machine including cookie
//! generation/validation, PoW challenge generation/validation, injection
//! tracking, and multi-threaded contention on shared progression state.
//!
//! Run with: `cargo bench --bench escalation_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::interrogator::{
    CaptchaConfig, CaptchaManager, InjectionTracker, InjectionTrackerConfig,
};
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};
use synapse_pingora::{
    CookieConfig, CookieManager, JsChallengeConfig, JsChallengeManager, ProgressionConfig,
    ProgressionManager,
};

// ============================================================================
// Helpers
// ============================================================================

fn test_cookie_config() -> CookieConfig {
    CookieConfig {
        cookie_name: "__tx_bench".to_string(),
        cookie_max_age_secs: 86400,
        secret_key: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ],
        secure_only: true,
        http_only: true,
        same_site: "Strict".to_string(),
    }
}

fn build_progression_manager() -> ProgressionManager {
    let cookie_mgr = Arc::new(CookieManager::new(test_cookie_config()).expect("cookie manager"));
    let js_mgr = Arc::new(JsChallengeManager::new(JsChallengeConfig::default()));
    let captcha_mgr = Arc::new(CaptchaManager::new(CaptchaConfig::default()));
    let tarpit_mgr = Arc::new(TarpitManager::new(TarpitConfig::default()));

    ProgressionManager::new(
        cookie_mgr,
        js_mgr,
        captcha_mgr,
        tarpit_mgr,
        ProgressionConfig::default(),
    )
}

// ============================================================================
// 1. get_challenge at Various Risk Thresholds
// ============================================================================

fn bench_get_challenge_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/get_challenge_levels");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = build_progression_manager();

    for risk in [0.1, 0.3, 0.5, 0.7, 0.9] {
        group.bench_with_input(
            BenchmarkId::new("risk", format!("{:.1}", risk)),
            &risk,
            |b, &risk_score| {
                let mut idx = 0u64;
                b.iter(|| {
                    let actor = format!("risk-actor-{}", idx % 1000);
                    let response = manager.get_challenge(black_box(&actor), black_box(risk_score));
                    black_box(response);
                    idx += 1;
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 2. Cookie Generate + Validate Round-Trip
// ============================================================================

fn bench_cookie_generate_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/cookie_generate_validate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let manager = CookieManager::new(test_cookie_config()).expect("cookie manager");

    group.bench_function("generate", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("cookie-actor-{}", idx);
            let challenge = manager.generate_tracking_cookie(black_box(&actor));
            black_box(challenge);
            idx += 1;
        });
    });

    // Pre-generate a valid cookie
    let valid_cookie = manager.generate_tracking_cookie("bench-actor");

    group.bench_function("validate_valid", |b| {
        b.iter(|| {
            let result = manager.validate_cookie(
                black_box("bench-actor"),
                black_box(&valid_cookie.cookie_value),
            );
            black_box(result);
        });
    });

    group.bench_function("validate_invalid", |b| {
        b.iter(|| {
            let result = manager.validate_cookie(
                black_box("bench-actor"),
                black_box("garbage.invalid.data00000000000000"),
            );
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. PoW Challenge Generation
// ============================================================================

fn bench_pow_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/pow_generate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = JsChallengeManager::new(JsChallengeConfig::default());

    group.bench_function("generate_pow_challenge", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("pow-actor-{}", idx);
            let challenge = manager.generate_pow_challenge(black_box(&actor));
            black_box(challenge);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 4. PoW Validation
// ============================================================================

fn bench_pow_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/pow_validate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = JsChallengeManager::new(JsChallengeConfig::default());

    // Generate a challenge so validation has something to check
    let _challenge = manager.generate_pow_challenge("validate-actor");

    group.bench_function("validate_invalid_nonce", |b| {
        b.iter(|| {
            let result = manager.validate_pow(black_box("validate-actor"), black_box("0000000000"));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Full Escalation Path
// ============================================================================

fn bench_full_escalation_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/full_escalation_path");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let manager = build_progression_manager();

    group.bench_function("10_failures_escalation", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("escalation-actor-{}", idx);
            // Record 10 failures to escalate through levels
            for _ in 0..10 {
                manager.record_failure(black_box(&actor));
            }
            // Check final challenge level
            let response = manager.get_challenge(black_box(&actor), black_box(0.8));
            black_box(response);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 6. State Machine Contention
// ============================================================================

fn bench_state_machine_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/state_machine_contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    for &threads in &[1, 2, 4, 8] {
        let manager = Arc::new(build_progression_manager());

        group.bench_with_input(
            BenchmarkId::new("get_challenge_record_failure", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let mgr = Arc::clone(&manager);
                            s.spawn(move || {
                                for i in 0..100 {
                                    let actor = format!("contention-{}-{}", t, i % 20);
                                    if i % 3 == 0 {
                                        mgr.record_failure(black_box(&actor));
                                    } else {
                                        let response =
                                            mgr.get_challenge(black_box(&actor), black_box(0.5));
                                        black_box(response);
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
// 7. Injection Tracker
// ============================================================================

fn bench_injection_tracker(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/injection_tracker");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let tracker = InjectionTracker::new(InjectionTrackerConfig::default());

    group.bench_function("record_js_attempt", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let ip = format!("10.0.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            let indicators = tracker.record_js_attempt(
                black_box(&ip),
                black_box("Mozilla/5.0"),
                black_box(idx % 3 == 0), // 33% success
                black_box(150 + (idx % 50)),
                black_box(Some("t13d1516h2_bench")),
            );
            black_box(indicators);
            idx += 1;
        });
    });

    // Pre-populate for should_block
    for i in 0..100u64 {
        let ip = format!("172.16.0.{}", i);
        for _ in 0..10 {
            tracker.record_js_attempt(&ip, "Mozilla/5.0", false, 100, Some("fp_bench"));
        }
    }

    group.bench_function("should_block_check", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let ip = format!("172.16.0.{}", idx % 100);
            let (blocked, reason) = tracker.should_block(black_box(&ip), black_box("Mozilla/5.0"));
            black_box((blocked, reason));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    escalation_benches,
    bench_get_challenge_levels,
    bench_cookie_generate_validate,
    bench_pow_generate,
    bench_pow_validate,
    bench_full_escalation_path,
    bench_state_machine_contention,
    bench_injection_tracker,
);

criterion_main!(escalation_benches);
