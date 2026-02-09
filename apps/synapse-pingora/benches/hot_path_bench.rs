//! Hot-path benchmarks for per-request subsystems.
//!
//! Covers SNI validation, body parsing/inspection, trap matching,
//! domain validation, and keyed rate limiting — all invoked on every
//! request in the proxy pipeline.
//!
//! Run with: `cargo bench --bench hot_path_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::body::{BodyConfig, BodyInspector, ContentType};
use synapse_pingora::ratelimit::{KeyedRateLimiter, RateLimitConfig, TokenBucket};
use synapse_pingora::{
    validate_domain_name, SniValidationConfig, SniValidationMode, SniValidator, TrapConfig,
    TrapMatcher,
};

// ============================================================================
// Helpers
// ============================================================================

fn default_sni_validator() -> SniValidator {
    SniValidator::new(SniValidationConfig {
        mode: SniValidationMode::Strict,
        ..Default::default()
    })
}

fn default_trap_matcher() -> TrapMatcher {
    TrapMatcher::new(TrapConfig::default()).expect("valid trap config")
}

// ============================================================================
// 1. SNI Validation
// ============================================================================

fn bench_sni_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path/sni_validation");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let validator = default_sni_validator();

    group.bench_function("match_tls", |b| {
        b.iter(|| {
            let result = validator.validate(
                black_box(Some("example.com")),
                black_box(Some("example.com")),
                black_box(true),
            );
            black_box(result);
        });
    });

    group.bench_function("mismatch_domain_fronting", |b| {
        b.iter(|| {
            let result = validator.validate(
                black_box(Some("legit.com")),
                black_box(Some("evil.com")),
                black_box(true),
            );
            black_box(result);
        });
    });

    group.bench_function("subdomain_allowed", |b| {
        let v = SniValidator::new(SniValidationConfig {
            mode: SniValidationMode::SubdomainAllowed,
            ..Default::default()
        });
        b.iter(|| {
            let result = v.validate(
                black_box(Some("example.com")),
                black_box(Some("www.example.com")),
                black_box(true),
            );
            black_box(result);
        });
    });

    group.bench_function("non_tls_skip", |b| {
        b.iter(|| {
            let result = validator.validate(
                black_box(None),
                black_box(Some("example.com")),
                black_box(false),
            );
            black_box(result);
        });
    });

    group.bench_function("validate_from_headers", |b| {
        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("x-forwarded-host".to_string(), "example.com".to_string()),
        ];
        b.iter(|| {
            let result = validator.validate_from_headers(black_box(&headers), black_box(true));
            black_box(result);
        });
    });

    for mode in [
        SniValidationMode::Strict,
        SniValidationMode::DomainOnly,
        SniValidationMode::LogOnly,
        SniValidationMode::Disabled,
    ] {
        let v = SniValidator::new(SniValidationConfig {
            mode,
            ..Default::default()
        });
        group.bench_with_input(
            BenchmarkId::new("mode", format!("{:?}", mode)),
            &(),
            |b, _| {
                b.iter(|| {
                    let result = v.validate(
                        black_box(Some("a.com")),
                        black_box(Some("b.com")),
                        black_box(true),
                    );
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 2. Body Inspection
// ============================================================================

fn bench_body_inspection(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path/body_inspection");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let inspector = BodyInspector::new(BodyConfig::default());

    // Content-Type detection (fast path)
    group.bench_function("content_type_from_header_json", |b| {
        b.iter(|| {
            let ct = ContentType::from_header(black_box("application/json; charset=utf-8"));
            black_box(ct);
        });
    });

    group.bench_function("content_type_from_header_html", |b| {
        b.iter(|| {
            let ct = ContentType::from_header(black_box("text/html"));
            black_box(ct);
        });
    });

    group.bench_function("content_type_detect_from_body", |b| {
        let body = b"{\"name\":\"test\",\"value\":42}";
        b.iter(|| {
            let ct = ContentType::detect_from_body(black_box(body));
            black_box(ct);
        });
    });

    // Small JSON body
    let small_json = br#"{"user":"admin","action":"login","ts":1234567890}"#;
    group.throughput(Throughput::Bytes(small_json.len() as u64));
    group.bench_function("inspect_small_json", |b| {
        b.iter(|| {
            let result =
                inspector.inspect(black_box(small_json), black_box(Some("application/json")));
            black_box(result);
        });
    });

    // Medium JSON body (~1KB)
    let medium_json = serde_json::json!({
        "users": (0..20).map(|i| serde_json::json!({
            "id": i,
            "name": format!("user_{}", i),
            "email": format!("user{}@example.com", i),
            "active": i % 2 == 0
        })).collect::<Vec<_>>()
    });
    let medium_bytes = serde_json::to_vec(&medium_json).unwrap();
    group.throughput(Throughput::Bytes(medium_bytes.len() as u64));
    group.bench_function("inspect_medium_json_1kb", |b| {
        b.iter(|| {
            let result = inspector.inspect(
                black_box(&medium_bytes),
                black_box(Some("application/json")),
            );
            black_box(result);
        });
    });

    // Form-encoded body
    let form_body = b"username=admin&password=secret123&remember=true&csrf=abc123def456";
    group.throughput(Throughput::Bytes(form_body.len() as u64));
    group.bench_function("inspect_form_urlencoded", |b| {
        b.iter(|| {
            let result = inspector.inspect(
                black_box(form_body),
                black_box(Some("application/x-www-form-urlencoded")),
            );
            black_box(result);
        });
    });

    // Binary body (skip path)
    let binary_body: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
    group.bench_function("inspect_binary_skip", |b| {
        b.iter(|| {
            let result = inspector.inspect(black_box(&binary_body), black_box(Some("image/png")));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Trap Matching
// ============================================================================

fn bench_trap_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path/trap_matching");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    let matcher = default_trap_matcher();

    group.bench_function("miss_normal_path", |b| {
        b.iter(|| {
            let hit = matcher.is_trap(black_box("/api/users/123"));
            black_box(hit);
        });
    });

    group.bench_function("hit_git", |b| {
        b.iter(|| {
            let hit = matcher.is_trap(black_box("/.git/config"));
            black_box(hit);
        });
    });

    group.bench_function("hit_env", |b| {
        b.iter(|| {
            let hit = matcher.is_trap(black_box("/.env"));
            black_box(hit);
        });
    });

    group.bench_function("hit_wp_admin", |b| {
        b.iter(|| {
            let hit = matcher.is_trap(black_box("/wp-admin/install.php"));
            black_box(hit);
        });
    });

    group.bench_function("miss_long_path", |b| {
        let path = format!("/api/v2/organizations/org-123/projects/proj-456/environments/prod/deployments/deploy-789");
        b.iter(|| {
            let hit = matcher.is_trap(black_box(&path));
            black_box(hit);
        });
    });

    group.bench_function("matched_pattern_on_hit", |b| {
        b.iter(|| {
            let pattern = matcher.matched_pattern(black_box("/.git/HEAD"));
            black_box(pattern);
        });
    });

    // Throughput: mixed traffic (95% normal, 5% trap)
    let paths: Vec<&str> = vec![
        "/api/users",
        "/api/products",
        "/api/orders",
        "/static/app.js",
        "/static/style.css",
        "/api/search?q=test",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/v2/dashboard",
        "/api/v2/settings",
        "/api/health",
        "/api/metrics",
        "/api/webhooks",
        "/api/events",
        "/api/notifications",
        "/api/reports",
        "/api/billing",
        "/api/teams",
        "/api/invites",
        "/.git/config", // 5% trap
    ];
    group.bench_function("mixed_traffic_95_5", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let path = paths[idx % paths.len()];
            let hit = matcher.is_trap(black_box(path));
            black_box(hit);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 4. Domain Validation
// ============================================================================

fn bench_domain_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path/domain_validation");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    group.bench_function("valid_simple", |b| {
        b.iter(|| {
            let result = validate_domain_name(black_box("example.com"));
            black_box(result);
        });
    });

    group.bench_function("valid_subdomain", |b| {
        b.iter(|| {
            let result = validate_domain_name(black_box("api.staging.example.com"));
            black_box(result);
        });
    });

    group.bench_function("invalid_too_long", |b| {
        let long = "a".repeat(64) + ".com";
        b.iter(|| {
            let result = validate_domain_name(black_box(&long));
            black_box(result);
        });
    });

    group.bench_function("invalid_homograph", |b| {
        // Cyrillic 'а' looks like Latin 'a'
        b.iter(|| {
            let result = validate_domain_name(black_box("exаmple.com")); // Cyrillic а
            black_box(result);
        });
    });

    group.bench_function("valid_hyphenated", |b| {
        b.iter(|| {
            let result = validate_domain_name(black_box("my-api-server.example.co.uk"));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Rate Limiting — Keyed
// ============================================================================

fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("hot_path/rate_limiting");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // TokenBucket — atomic CAS loop
    let bucket = TokenBucket::new(100_000, 200_000);
    group.bench_function("token_bucket_acquire", |b| {
        b.iter(|| {
            let allowed = bucket.try_acquire();
            black_box(allowed);
        });
    });

    // KeyedRateLimiter — per-key bucket lookup + acquire
    let limiter = KeyedRateLimiter::new(RateLimitConfig {
        rps: 1000,
        burst: 2000,
        ..Default::default()
    });

    // Pre-populate some keys
    for i in 0..100 {
        let key = format!("192.168.1.{}", i);
        limiter.check(&key);
    }

    group.bench_function("keyed_check_existing", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let key = format!("192.168.1.{}", idx % 100);
            let decision = limiter.check(black_box(&key));
            black_box(decision);
            idx += 1;
        });
    });

    group.bench_function("keyed_check_new_key", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let key = format!("10.0.{}.{}", (idx >> 8) & 0xFF, idx & 0xFF);
            let decision = limiter.check(black_box(&key));
            black_box(decision);
            idx += 1;
        });
    });

    // Contention
    for &threads in &[1, 2, 4, 8] {
        let limiter = Arc::new(KeyedRateLimiter::new(RateLimitConfig {
            rps: 100_000,
            burst: 200_000,
            ..Default::default()
        }));

        group.bench_with_input(
            BenchmarkId::new("keyed_contention", format!("{}t", threads)),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let limiter = Arc::clone(&limiter);
                            s.spawn(move || {
                                for i in 0..500 {
                                    let key = format!("10.{}.{}.{}", t, (i >> 8) & 0xFF, i & 0xFF);
                                    let decision = limiter.check(black_box(&key));
                                    black_box(decision);
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
    hot_path_benches,
    bench_sni_validation,
    bench_body_inspection,
    bench_trap_matching,
    bench_domain_validation,
    bench_rate_limiting,
);

criterion_main!(hot_path_benches);
