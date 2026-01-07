//! Performance benchmarks for the Synapse detection engine.
//!
//! Run with: `cargo bench`
//!
//! These benchmarks verify the sub-10μs detection target.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use once_cell::sync::Lazy;
use std::time::Duration;
use std::fs;
use std::path::Path;
use synapse::{Synapse, Request as SynapseRequest, Header as SynapseHeader, Action as SynapseAction, Verdict as SynapseVerdict};

// ============================================================================
// Detection Engine (Real libsynapse wrapper)
// ============================================================================

// Result struct to match the benchmark's expectations
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub blocked: bool,
    pub risk_score: u16,
}

impl From<SynapseVerdict> for DetectionResult {
    fn from(verdict: SynapseVerdict) -> Self {
        Self {
            blocked: verdict.action == SynapseAction::Block,
            risk_score: verdict.risk_score,
        }
    }
}

thread_local! {
    static SYNAPSE: std::cell::RefCell<Synapse> = std::cell::RefCell::new({
        let mut synapse = Synapse::new();
        
        // Try to load the real rules
        let rules_path = "../risk-server/libsynapse/rules.json";
        if Path::new(rules_path).exists() {
            match fs::read(rules_path) {
                Ok(rules_json) => {
                    if let Err(e) = synapse.load_rules(&rules_json) {
                        eprintln!("Failed to parse rules: {}", e);
                    } else {
                        // println!("Benchmark loaded real rules from {}", rules_path);
                    }
                }
                Err(e) => eprintln!("Failed to read rules: {}", e),
            }
        } else {
            eprintln!("WARNING: Rules file not found at {}, benchmarking empty engine!", rules_path);
        }

        synapse
    });
}

pub struct DetectionEngine;

impl DetectionEngine {
    #[inline]
    pub fn analyze(method: &str, uri: &str, headers: &[(String, String)]) -> DetectionResult {
        let synapse_headers: Vec<SynapseHeader> = headers
            .iter()
            .map(|(name, value)| SynapseHeader::new(name, value))
            .collect();

        // In a real scenario, we'd have the client IP. For bench, use dummy.
        let request = SynapseRequest {
            method,
            path: uri,
            query: None, // libsynapse parses this from path if None
            headers: synapse_headers,
            body: None,
            client_ip: "127.0.0.1",
            is_static: false,
        };

        let verdict = SYNAPSE.with(|s| s.borrow().analyze(&request));
        verdict.into()
    }

    pub fn ensure_init() {
        SYNAPSE.with(|s| { let _ = s.borrow(); });
    }
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_clean_requests(c: &mut Criterion) {
    // Ensure engine is initialized
    DetectionEngine::ensure_init();

    let clean_uris = vec![
        ("/api/users/123", "simple path"),
        ("/api/search?q=hello+world&page=1", "with query"),
        ("/api/products/list?category=electronics&sort=price", "complex query"),
        ("/assets/images/logo.png", "static asset"),
        ("/v1/oauth/token", "auth endpoint"),
    ];

    let mut group = c.benchmark_group("clean_requests");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    for (uri, name) in clean_uris {
        group.bench_with_input(
            BenchmarkId::new("detection", name),
            &uri,
            |b, uri| {
                b.iter(|| {
                    let result = DetectionEngine::analyze(
                        black_box("GET"),
                        black_box(uri),
                        black_box(&[]),
                    );
                    assert!(!result.blocked);
                    result
                })
            },
        );
    }
    group.finish();
}

fn bench_attack_detection(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let attacks = vec![
        ("/api/users?id=1' OR '1'='1", "sqli"),
        ("/search?q=<script>alert(1)</script>", "xss"),
        ("/files/../../../etc/passwd", "path_traversal"),
        ("/ping?host=127.0.0.1|cat /etc/passwd", "cmd_injection"),
    ];

    let mut group = c.benchmark_group("attack_detection");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    for (uri, name) in attacks {
        group.bench_with_input(
            BenchmarkId::new("detection", name),
            &uri,
            |b, uri| {
                b.iter(|| {
                    let result = DetectionEngine::analyze(
                        black_box("GET"),
                        black_box(uri),
                        black_box(&[]),
                    );
                    result
                })
            },
        );
    }
    group.finish();
}

fn bench_with_headers(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let headers = vec![
        ("user-agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        ("cookie".to_string(), "session=abc123; user=john".to_string()),
        ("referer".to_string(), "https://example.com/page".to_string()),
        ("x-forwarded-for".to_string(), "192.168.1.1, 10.0.0.1".to_string()),
    ];

    let mut group = c.benchmark_group("with_headers");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // Clean request with headers
    group.bench_function("clean_with_headers", |b| {
        b.iter(|| {
            DetectionEngine::analyze(
                black_box("GET"),
                black_box("/api/users/123"),
                black_box(&headers),
            )
        })
    });

    // Attack in header
    let attack_headers = vec![
        ("user-agent".to_string(), "<script>alert(1)</script>".to_string()),
    ];
    group.bench_function("xss_in_header", |b| {
        b.iter(|| {
            let result = DetectionEngine::analyze(
                black_box("GET"),
                black_box("/api/users/123"),
                black_box(&attack_headers),
            );
            result
        })
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    // Mixed workload simulating real traffic
    let requests: Vec<(&str, &str, bool)> = vec![
        ("GET", "/api/users/123", false),
        ("GET", "/api/search?q=hello", false),
        ("POST", "/api/login", false),
        ("GET", "/api/users?id=1' OR '1'='1", true),
        ("GET", "/static/main.js", false),
        ("GET", "/search?q=<script>alert(1)</script>", true),
        ("GET", "/api/products", false),
        ("GET", "/files/../../../etc/passwd", true),
        ("PUT", "/api/users/123", false),
        ("DELETE", "/api/users/123", false),
    ];

    let mut group = c.benchmark_group("throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    group.bench_function("mixed_workload_10_requests", |b| {
        b.iter(|| {
            for (method, uri, expected_block) in &requests {
                let _ = DetectionEngine::analyze(
                    black_box(method),
                    black_box(uri),
                    black_box(&[]),
                );
            }
        })
    });

    group.finish();
}

fn bench_sub_10us_verification(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let mut group = c.benchmark_group("sub_10us_target");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10000);

    // This is THE key benchmark
    group.bench_function("full_detection_cycle", |b| {
        b.iter(|| {
            DetectionEngine::analyze(
                black_box("GET"),
                black_box("/api/users?id=1' OR '1'='1&name=test&page=1"),
                black_box(&[
                    ("user-agent".to_string(), "Mozilla/5.0".to_string()),
                    ("cookie".to_string(), "session=abc".to_string()),
                ]),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_clean_requests,
    bench_attack_detection,
    bench_with_headers,
    bench_throughput,
    bench_sub_10us_verification,
);

criterion_main!(benches);
