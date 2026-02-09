//! CAPTCHA challenge generation and validation benchmarks.
//!
//! Measures challenge issuance, valid/invalid response validation,
//! concurrent issuance contention, and full round-trip latency.
//!
//! Run with: `cargo bench --bench captcha_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::interrogator::{CaptchaChallenge, CaptchaConfig, CaptchaManager};

// ============================================================================
// Helpers
// ============================================================================

fn test_captcha_config() -> CaptchaConfig {
    CaptchaConfig {
        expiry_secs: 300,
        max_challenges: 10_000,
        cleanup_interval_secs: 60,
        ..Default::default()
    }
}

/// Parse "What is A + B?" from the challenge question and compute the answer.
fn solve_challenge(challenge: &CaptchaChallenge) -> String {
    // question format: "What is {a} + {b}?"
    let q = &challenge.question;
    let parts: Vec<&str> = q.split_whitespace().collect();
    // ["What", "is", "{a}", "+", "{b}?"]
    let a: i32 = parts[2].parse().unwrap_or(0);
    let b_str = parts[4].trim_end_matches('?');
    let b: i32 = b_str.parse().unwrap_or(0);
    format!("{}:{}", challenge.session_id, a + b)
}

// ============================================================================
// 1. Challenge Issuance
// ============================================================================

fn bench_captcha_issue(c: &mut Criterion) {
    let mut group = c.benchmark_group("captcha/issue_challenge");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let manager = CaptchaManager::new(test_captcha_config());

    group.bench_function("unique_actors", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("actor-{}", idx);
            let challenge = manager.issue_challenge(black_box(&actor));
            black_box(challenge);
            idx += 1;
        });
    });

    group.bench_function("same_actor_repeated", |b| {
        b.iter(|| {
            let challenge = manager.issue_challenge(black_box("repeat-actor"));
            black_box(challenge);
        });
    });

    group.finish();
}

// ============================================================================
// 2. Response Validation
// ============================================================================

fn bench_captcha_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("captcha/validate_response");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let manager = CaptchaManager::new(test_captcha_config());

    // Issue a challenge and construct a valid response
    let challenge = manager.issue_challenge("validate-actor");
    let valid_response = solve_challenge(&challenge);

    group.bench_function("valid_response", |b| {
        b.iter(|| {
            let result =
                manager.validate_response(black_box("validate-actor"), black_box(&valid_response));
            black_box(result);
        });
    });

    group.bench_function("invalid_response", |b| {
        b.iter(|| {
            let result = manager
                .validate_response(black_box("validate-actor"), black_box("bad-session:9999"));
            black_box(result);
        });
    });

    group.bench_function("unknown_actor", |b| {
        b.iter(|| {
            let result = manager
                .validate_response(black_box("nonexistent-actor"), black_box("some-session:42"));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Full Round-Trip (Issue + Validate)
// ============================================================================

fn bench_captcha_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("captcha/round_trip");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = CaptchaManager::new(test_captcha_config());

    group.bench_function("issue_then_validate", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("rt-actor-{}", idx);
            let challenge = manager.issue_challenge(black_box(&actor));
            let response = solve_challenge(&challenge);
            let result = manager.validate_response(black_box(&actor), black_box(&response));
            black_box(result);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 4. Concurrent Issuance Contention
// ============================================================================

fn bench_captcha_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("captcha/contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    for &threads in &[1, 2, 4, 8] {
        let manager = Arc::new(CaptchaManager::new(test_captcha_config()));

        group.bench_with_input(
            BenchmarkId::new("issue_and_validate", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let mgr = Arc::clone(&manager);
                            s.spawn(move || {
                                for i in 0..200 {
                                    let actor = format!("contention-{}-{}", t, i);
                                    let challenge = mgr.issue_challenge(black_box(&actor));
                                    if i % 3 == 0 {
                                        // Validate every 3rd challenge
                                        let resp = solve_challenge(&challenge);
                                        let result = mgr
                                            .validate_response(black_box(&actor), black_box(&resp));
                                        black_box(result);
                                    }
                                    black_box(challenge);
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
    captcha_benches,
    bench_captcha_issue,
    bench_captcha_validate,
    bench_captcha_round_trip,
    bench_captcha_contention,
);

criterion_main!(captcha_benches);
