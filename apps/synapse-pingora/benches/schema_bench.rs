//! Schema learning and validation benchmarks.
//!
//! Verifies the ~5us schema learning claim and validates performance
//! across different JSON sizes, nesting depths, and contention levels.
//!
//! Run with: `cargo bench --bench schema_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::{SchemaLearner, SchemaLearnerConfig};

// ============================================================================
// Helpers
// ============================================================================

fn small_json() -> serde_json::Value {
    json!({
        "name": "John Smith",
        "age": 30,
        "email": "john@example.com",
        "active": true,
        "score": 95.5
    })
}

fn medium_json() -> serde_json::Value {
    json!({
        "name": "John Smith",
        "age": 30,
        "email": "john@example.com",
        "active": true,
        "score": 95.5,
        "address": "123 Main St",
        "city": "New York",
        "state": "NY",
        "zip": "10001",
        "phone": "212-555-0100",
        "company": "Acme Corp",
        "role": "engineer",
        "department": "security",
        "level": 3,
        "verified": true
    })
}

fn large_json() -> serde_json::Value {
    json!({
        "name": "John Smith",
        "age": 30,
        "email": "john@example.com",
        "active": true,
        "score": 95.5,
        "address": "123 Main St",
        "city": "New York",
        "state": "NY",
        "zip": "10001",
        "phone": "212-555-0100",
        "company": "Acme Corp",
        "role": "engineer",
        "department": "security",
        "level": 3,
        "verified": true,
        "bio": "Software engineer with 10 years experience",
        "website": "https://example.com",
        "github": "jsmith",
        "twitter": "@jsmith",
        "linkedin": "johnsmith",
        "timezone": "America/New_York",
        "locale": "en-US",
        "currency": "USD",
        "plan": "enterprise",
        "seats": 50,
        "storage_gb": 100,
        "api_calls": 1000000,
        "created_at": "2024-01-15T10:30:00Z",
        "updated_at": "2024-06-20T14:45:00Z"
    })
}

fn nested_json(depth: usize) -> serde_json::Value {
    let mut val = json!({"value": 42, "name": "leaf"});
    for _ in 0..depth {
        val = json!({"level": val, "count": 1});
    }
    val
}

fn violating_json() -> serde_json::Value {
    json!({
        "name": 12345,
        "age": "not_a_number",
        "email": true,
        "active": "yes",
        "score": "high"
    })
}

// ============================================================================
// 1. Schema Learning — Various JSON Sizes
// ============================================================================

fn bench_schema_learn(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/learn_request");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let learner = SchemaLearner::new();

    let small = small_json();
    let medium = medium_json();
    let large = large_json();

    group.bench_function("learn_small_json", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let template = format!("/api/small/{}", idx % 100);
            learner.learn_from_request(black_box(&template), black_box(&small));
            idx += 1;
        });
    });

    group.bench_function("learn_medium_json", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let template = format!("/api/medium/{}", idx % 100);
            learner.learn_from_request(black_box(&template), black_box(&medium));
            idx += 1;
        });
    });

    group.bench_function("learn_large_json", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let template = format!("/api/large/{}", idx % 100);
            learner.learn_from_request(black_box(&template), black_box(&large));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 2. Schema Validation
// ============================================================================

fn bench_schema_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/validate_request");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let learner = SchemaLearner::with_config(SchemaLearnerConfig {
        min_samples_for_validation: 10,
        ..Default::default()
    });

    // Pre-warm with 100 learns for /api/users
    let conforming = small_json();
    for _ in 0..100 {
        learner.learn_from_request("/api/users", &conforming);
    }

    let violating = violating_json();

    group.bench_function("validate_conforming", |b| {
        b.iter(|| {
            let result = learner.validate_request(black_box("/api/users"), black_box(&conforming));
            black_box(result);
        });
    });

    group.bench_function("validate_violating", |b| {
        b.iter(|| {
            let result = learner.validate_request(black_box("/api/users"), black_box(&violating));
            black_box(result);
        });
    });

    group.bench_function("validate_unknown_endpoint", |b| {
        b.iter(|| {
            let result =
                learner.validate_request(black_box("/api/never-seen"), black_box(&conforming));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Combined Learn + Validate Pipeline
// ============================================================================

fn bench_schema_learn_and_validate(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/learn_and_validate");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let learner = SchemaLearner::with_config(SchemaLearnerConfig {
        min_samples_for_validation: 5,
        ..Default::default()
    });

    // Pre-warm so validation has a baseline
    let body = small_json();
    for _ in 0..20 {
        learner.learn_from_request("/api/pipeline", &body);
    }

    group.bench_function("combined_pipeline", |b| {
        b.iter(|| {
            learner.learn_from_request(black_box("/api/pipeline"), black_box(&body));
            let result = learner.validate_request(black_box("/api/pipeline"), black_box(&body));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 4. Nested JSON — Depth-Bounded Traversal
// ============================================================================

fn bench_schema_nested(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/nested_json");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    for depth in [3, 5, 8] {
        let body = nested_json(depth);

        group.bench_with_input(BenchmarkId::new("learn_depth", depth), &body, |b, body| {
            let learner = SchemaLearner::new();
            let mut idx = 0u64;
            b.iter(|| {
                let template = format!("/api/nested/{}", idx % 50);
                learner.learn_from_request(black_box(&template), black_box(body));
                idx += 1;
            });
        });
    }

    group.finish();
}

// ============================================================================
// 5. Contention — Multi-Threaded
// ============================================================================

fn bench_schema_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/contention");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let body = small_json();

    for &threads in &[1, 2, 4, 8] {
        let learner = Arc::new(SchemaLearner::with_config(SchemaLearnerConfig {
            min_samples_for_validation: 5,
            ..Default::default()
        }));

        // Pre-warm shared templates
        for i in 0..20 {
            let template = format!("/api/shared/{}", i);
            for _ in 0..10 {
                learner.learn_from_request(&template, &body);
            }
        }

        group.bench_with_input(
            BenchmarkId::new("learn_validate_mixed", threads),
            &threads,
            |b, &num_threads| {
                b.iter(|| {
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let learner = Arc::clone(&learner);
                            let body = &body;
                            s.spawn(move || {
                                for i in 0..200 {
                                    let template = format!("/api/shared/{}", (t * 200 + i) % 20);
                                    if i % 2 == 0 {
                                        learner.learn_from_request(
                                            black_box(&template),
                                            black_box(body),
                                        );
                                    } else {
                                        let result = learner.validate_request(
                                            black_box(&template),
                                            black_box(body),
                                        );
                                        black_box(result);
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
// 6. LRU Eviction
// ============================================================================

fn bench_schema_lru_eviction(c: &mut Criterion) {
    let mut group = c.benchmark_group("schema/lru_eviction");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let learner = SchemaLearner::with_config(SchemaLearnerConfig {
        max_schemas: 100,
        ..Default::default()
    });

    let body = small_json();

    // Fill to capacity
    for i in 0..100 {
        let template = format!("/api/fill/{}", i);
        learner.learn_from_request(&template, &body);
    }

    group.bench_function("learn_with_eviction", |b| {
        let mut idx = 1000u64;
        b.iter(|| {
            let template = format!("/api/evict/{}", idx);
            learner.learn_from_request(black_box(&template), black_box(&body));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    schema_benches,
    bench_schema_learn,
    bench_schema_validate,
    bench_schema_learn_and_validate,
    bench_schema_nested,
    bench_schema_contention,
    bench_schema_lru_eviction,
);

criterion_main!(schema_benches);
