//! Performance benchmarks for the Synapse detection engine.
//!
//! Run with: `cargo bench`
//!
//! These benchmarks verify the sub-10μs detection target.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::time::Duration;
// NOTE: The `synapse` (libsynapse) crate was consolidated into synapse_pingora in Phase 10.
// These types are re-exported from the waf module.
use synapse_pingora::waf::{
    Action as SynapseAction, Header as SynapseHeader, Request as SynapseRequest, Synapse,
    Verdict as SynapseVerdict,
};

// ============================================================================
// Data Loading
// ============================================================================

#[derive(Debug, Deserialize)]
struct PayloadData {
    attacks: AttackPayloads,
    normal: Vec<NormalPayload>,
}

#[derive(Debug, Deserialize)]
struct AttackPayloads {
    sqli: Vec<String>,
    xss: Vec<String>,
    #[serde(rename = "commandInjection")]
    command_injection: Vec<String>,
    #[serde(rename = "pathTraversal")]
    path_traversal: Vec<String>,
    #[serde(default)]
    xxe: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NormalPayload {
    #[serde(rename = "type")]
    _type: String,
    data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct HeavyPayloadData {
    complex_request: ComplexRequest,
}

#[derive(Debug, Deserialize)]
struct ComplexRequest {
    uri: String,
    headers: Vec<(String, String)>,
    body_json: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ScenarioRequest {
    name: String,
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body_json: serde_json::Value,
}

static PAYLOADS: Lazy<PayloadData> = Lazy::new(|| {
    let path = Path::new("benches/payloads.json");
    if !path.exists() {
        eprintln!("WARNING: benches/payloads.json not found. Run 'node apps/load-testing/scripts/extract_payloads.mjs' first.");
        // Return dummy data to avoid crash if file missing
        return PayloadData {
            attacks: AttackPayloads {
                sqli: vec!["' OR '1'='1".into()],
                xss: vec!["<script>alert(1)</script>".into()],
                xxe: vec![],
                command_injection: vec![],
                path_traversal: vec![],
            },
            normal: vec![],
        };
    }
    let content = fs::read_to_string(path).expect("Failed to read payloads.json");
    serde_json::from_str(&content).expect("Failed to parse payloads.json")
});

static HEAVY_PAYLOADS: Lazy<HeavyPayloadData> = Lazy::new(|| {
    let path = Path::new("benches/heavy_payloads.json");
    if !path.exists() {
        eprintln!("WARNING: benches/heavy_payloads.json not found.");
        panic!("Missing heavy_payloads.json");
    }
    let content = fs::read_to_string(path).expect("Failed to read heavy_payloads.json");
    serde_json::from_str(&content).expect("Failed to parse heavy_payloads.json")
});

static SCENARIOS: Lazy<Vec<ScenarioRequest>> = Lazy::new(|| {
    let path = Path::new("benches/scenarios.json");
    if !path.exists() {
        eprintln!("WARNING: benches/scenarios.json not found.");
        return vec![];
    }
    let content = fs::read_to_string(path).expect("Failed to read scenarios.json");
    serde_json::from_str(&content).expect("Failed to parse scenarios.json")
});

// ============================================================================
// Detection Engine (Synapse WAF)
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
        let rules_path = "data/rules.json";
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
    pub fn analyze(
        method: &str,
        uri: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> DetectionResult {
        let synapse_headers: Vec<SynapseHeader> = headers
            .iter()
            .map(|(name, value)| SynapseHeader::new(name, value))
            .collect();

        // In a real scenario, we'd have the client IP. For bench, use dummy.
        let request = SynapseRequest {
            method,
            path: uri,
            query: None, // Synapse parses this from path if None
            headers: synapse_headers,
            body,
            client_ip: "127.0.0.1",
            is_static: false,
        };

        let verdict = SYNAPSE.with(|s| s.borrow().analyze(&request));
        verdict.into()
    }

    pub fn ensure_init() {
        SYNAPSE.with(|s| {
            let _ = s.borrow();
        });
    }

    /// Validate engine correctness before benchmarking.
    /// Panics if a known attack is not detected — prevents benchmarking a no-op engine.
    pub fn validate_correctness() {
        // Try multiple known attack vectors — at least one should trigger a non-zero risk score
        let payloads = [
            "/search?q=' OR '1'='1",
            "/search?q=1' UNION SELECT NULL--",
            "/files/../../../etc/passwd",
            "/search?q=<script>alert(1)</script>",
        ];
        let any_detected = payloads.iter().any(|uri| {
            let result = Self::analyze("GET", uri, &[], None);
            result.blocked || result.risk_score > 0
        });
        assert!(
            any_detected,
            "Correctness check failed: no attack payloads detected. \
             Ensure data/rules.json exists and contains valid rules. \
             The benchmark may be measuring a no-op engine."
        );
    }
}

// ============================================================================
// Benchmarks
// ============================================================================

fn bench_clean_requests(c: &mut Criterion) {
    // Ensure engine is initialized and rules are loaded correctly
    DetectionEngine::ensure_init();
    DetectionEngine::validate_correctness();

    // Force load payloads
    let _ = &*PAYLOADS;

    let mut group = c.benchmark_group("clean_requests");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Pre-allocate headers outside the benchmark loop to avoid measuring heap allocation
    let json_headers = vec![("content-type".to_string(), "application/json".to_string())];

    // Use generated normal payloads
    for (i, payload) in PAYLOADS.normal.iter().take(5).enumerate() {
        let body_json = serde_json::to_string(&payload.data).unwrap();
        let name = format!("normal_{}_{}", payload._type, i);

        group.bench_with_input(
            BenchmarkId::new("detection", name),
            &body_json,
            |b, body| {
                b.iter(|| {
                    black_box(DetectionEngine::analyze(
                        black_box("POST"),
                        black_box("/api/action"),
                        black_box(&json_headers),
                        black_box(Some(body.as_bytes())),
                    ))
                })
            },
        );
    }

    // Keep some simple GETs for baseline
    let clean_uris = vec![
        ("/api/users/123", "simple_get"),
        ("/assets/logo.png", "static_asset"),
    ];

    for (uri, name) in clean_uris {
        group.bench_with_input(BenchmarkId::new("detection", name), &uri, |b, uri| {
            b.iter(|| {
                black_box(DetectionEngine::analyze(
                    black_box("GET"),
                    black_box(uri),
                    black_box(&[]),
                    black_box(None),
                ))
            })
        });
    }

    // Complex GET with many query parameters
    let complex_get_uri = "/api/search?q=wireless+headphones&category=electronics&brand=sony&min_price=50&max_price=200&sort=relevance&page=1&limit=20&in_stock=true&rating=4";
    group.bench_with_input(
        BenchmarkId::new("detection", "complex_get_many_params"),
        &complex_get_uri,
        |b, uri| {
            b.iter(|| {
                black_box(DetectionEngine::analyze(
                    black_box("GET"),
                    black_box(uri),
                    black_box(&[]),
                    black_box(None),
                ))
            })
        },
    );

    // POST with JSON body
    let json_body = r#"{"username":"john_doe","email":"john@example.com","preferences":{"theme":"dark","notifications":true,"language":"en-US"}}"#;
    let json_post_headers = vec![("content-type".to_string(), "application/json".to_string())];
    group.bench_with_input(
        BenchmarkId::new("detection", "post_json_body"),
        &json_body,
        |b, body| {
            b.iter(|| {
                black_box(DetectionEngine::analyze(
                    black_box("POST"),
                    black_box("/api/users/settings"),
                    black_box(&json_post_headers),
                    black_box(Some(body.as_bytes())),
                ))
            })
        },
    );

    // POST with form data
    let form_body = "username=john_doe&password=s3cur3P%40ss&remember=true&redirect=%2Fdashboard";
    let form_headers = vec![(
        "content-type".to_string(),
        "application/x-www-form-urlencoded".to_string(),
    )];
    group.bench_with_input(
        BenchmarkId::new("detection", "post_form_data"),
        &form_body,
        |b, body| {
            b.iter(|| {
                black_box(DetectionEngine::analyze(
                    black_box("POST"),
                    black_box("/api/login"),
                    black_box(&form_headers),
                    black_box(Some(body.as_bytes())),
                ))
            })
        },
    );

    group.finish();
}

fn bench_attack_detection(c: &mut Criterion) {
    DetectionEngine::ensure_init();
    let _ = &*PAYLOADS;

    let mut group = c.benchmark_group("attack_detection");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(100);

    // Helper to bench a list of attack strings
    let mut bench_list = |name_prefix: &str, attacks: &[String]| {
        for (i, attack) in attacks.iter().take(5).enumerate() {
            // Inject into query param
            let uri = format!("/search?q={}", urlencoding::encode(attack));
            let name = format!("{}_{}", name_prefix, i);

            group.bench_with_input(BenchmarkId::new("detection", name), &uri, |b, uri| {
                b.iter(|| {
                    black_box(DetectionEngine::analyze(
                        black_box("GET"),
                        black_box(uri),
                        black_box(&[]),
                        black_box(None),
                    ))
                })
            });
        }
    };

    bench_list("sqli", &PAYLOADS.attacks.sqli);
    bench_list("xss", &PAYLOADS.attacks.xss);
    bench_list("cmd_inj", &PAYLOADS.attacks.command_injection);
    bench_list("path_trav", &PAYLOADS.attacks.path_traversal);

    group.finish();
}

fn bench_with_headers(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let headers = vec![
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ),
        (
            "cookie".to_string(),
            "session=abc123; user=john".to_string(),
        ),
        (
            "referer".to_string(),
            "https://example.com/page".to_string(),
        ),
        (
            "x-forwarded-for".to_string(),
            "192.168.1.1, 10.0.0.1".to_string(),
        ),
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
                black_box(None),
            )
        })
    });

    // Attack in header
    let attack_headers = vec![(
        "user-agent".to_string(),
        "<script>alert(1)</script>".to_string(),
    )];
    group.bench_function("xss_in_header", |b| {
        b.iter(|| {
            let result = DetectionEngine::analyze(
                black_box("GET"),
                black_box("/api/users/123"),
                black_box(&attack_headers),
                black_box(None),
            );
            result
        })
    });

    group.finish();
}

fn bench_throughput(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    // Mixed workload simulating real traffic (70% clean, 30% attack)
    let requests: Vec<(&str, &str)> = vec![
        ("GET", "/api/users/123"),
        ("GET", "/api/search?q=hello"),
        ("POST", "/api/login"),
        ("GET", "/api/users?id=1' OR '1'='1"),
        ("GET", "/static/main.js"),
        ("GET", "/search?q=<script>alert(1)</script>"),
        ("GET", "/api/products"),
        ("GET", "/files/../../../etc/passwd"),
        ("PUT", "/api/users/123"),
        ("DELETE", "/api/users/123"),
    ];

    let mut group = c.benchmark_group("waf/throughput");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);
    // Tell criterion we process 10 requests per iteration for correct ops/sec reporting
    group.throughput(Throughput::Elements(requests.len() as u64));

    group.bench_function("mixed_workload_10_requests", |b| {
        b.iter(|| {
            for (method, uri) in &requests {
                black_box(DetectionEngine::analyze(
                    black_box(method),
                    black_box(uri),
                    black_box(&[]),
                    black_box(None),
                ));
            }
        })
    });

    group.finish();
}

fn bench_sub_10us_verification(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    // Pre-allocate headers outside the benchmark loop
    let headers = vec![
        ("user-agent".to_string(), "Mozilla/5.0".to_string()),
        ("cookie".to_string(), "session=abc".to_string()),
    ];

    let mut group = c.benchmark_group("waf/sub_10us_target");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10000);

    // This is THE key benchmark — must measure pure detection, not allocation
    group.bench_function("full_detection_cycle", |b| {
        b.iter(|| {
            black_box(DetectionEngine::analyze(
                black_box("GET"),
                black_box("/api/users?id=1' OR '1'='1&name=test&page=1"),
                black_box(&headers),
                black_box(None),
            ))
        })
    });

    group.finish();
}

fn bench_heavy_complex(c: &mut Criterion) {
    DetectionEngine::ensure_init();
    let _ = &*HEAVY_PAYLOADS;

    let body_bytes = serde_json::to_vec(&HEAVY_PAYLOADS.complex_request.body_json).unwrap();
    let headers = &HEAVY_PAYLOADS.complex_request.headers;
    let uri = &HEAVY_PAYLOADS.complex_request.uri;

    let mut group = c.benchmark_group("heavy_complex");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500); // Lower sample size for heavy requests

    group.bench_function("heavy_request_14kb_20headers", |b| {
        b.iter(|| {
            DetectionEngine::analyze(
                black_box("POST"),
                black_box(uri),
                black_box(headers),
                black_box(Some(&body_bytes)),
            )
        })
    });

    group.finish();
}

fn bench_realistic_scenarios(c: &mut Criterion) {
    DetectionEngine::ensure_init();
    let _ = &*SCENARIOS;

    let mut group = c.benchmark_group("realistic_scenarios");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(200);

    for scenario in SCENARIOS.iter() {
        let body_bytes = serde_json::to_vec(&scenario.body_json).unwrap();

        group.bench_with_input(
            BenchmarkId::new("scenario", &scenario.name),
            &body_bytes,
            |b, body| {
                b.iter(|| {
                    DetectionEngine::analyze(
                        black_box(&scenario.method),
                        black_box(&scenario.uri),
                        black_box(&scenario.headers),
                        black_box(Some(body)),
                    )
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// DLP Body Inspection Benchmarks
// ============================================================================

use synapse_pingora::dlp::{DlpConfig, DlpScanner};

/// Generate a realistic e-commerce order payload with some sensitive data
fn generate_order_payload(size_kb: usize) -> String {
    let base_order = r#"{
  "order_id": "ORD-12345678",
  "customer": {
    "name": "John Smith",
    "email": "john.smith@example.com",
    "phone": "212-555-1234",
    "address": {
      "street": "123 Main St",
      "city": "New York",
      "state": "NY",
      "zip": "10001"
    }
  },
  "payment": {
    "method": "credit_card",
    "card_number": "4532015112830366",
    "exp_date": "12/25"
  },
  "items": ["#;

    let item_template = r#"
    {"sku": "PROD-0001", "name": "Widget Pro", "qty": 2, "price": 29.99},"#;

    let mut payload = base_order.to_string();

    // Add items to reach target size
    let target_bytes = size_kb * 1024;
    while payload.len() < target_bytes {
        payload.push_str(item_template);
    }

    // Close the JSON
    payload.push_str("\n  ]\n}");
    payload
}

/// Generate a clean payload with no sensitive data
fn generate_clean_payload(size_kb: usize) -> String {
    let base = r#"{"data": ["#;
    let item =
        r#""Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor.","#;

    let mut payload = base.to_string();
    let target_bytes = size_kb * 1024;
    while payload.len() < target_bytes {
        payload.push_str(item);
    }
    payload.push_str("]}");
    payload
}

fn bench_dlp_body_inspection(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp/body_inspection");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    // Test payloads at different sizes
    let sizes_kb = [4, 8, 18, 32];

    // Create scanner with default config (8KB inspection cap)
    let scanner = DlpScanner::new(DlpConfig::default());

    for size_kb in sizes_kb {
        // Payload WITH sensitive data (realistic e-commerce scenario)
        let payload_with_pii = generate_order_payload(size_kb);
        let name = format!("with_pii_{}kb", size_kb);

        // Report bytes throughput so criterion shows MB/s
        group.throughput(Throughput::Bytes(payload_with_pii.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("scan", &name),
            &payload_with_pii,
            |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
        );

        // Payload WITHOUT sensitive data (clean traffic)
        let payload_clean = generate_clean_payload(size_kb);
        let name = format!("clean_{}kb", size_kb);

        group.throughput(Throughput::Bytes(payload_clean.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("scan", &name),
            &payload_clean,
            |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
        );
    }

    group.finish();
}

fn bench_dlp_content_type_skip(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp/content_type_skip");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);

    let scanner = DlpScanner::new(DlpConfig::default());

    // Test content-type checking overhead
    let content_types = [
        ("application/json", true),
        ("text/html", true),
        ("image/png", false),
        ("video/mp4", false),
        ("multipart/form-data", false),
        ("application/octet-stream", false),
    ];

    // Validate correctness once before benchmarking (not inside the hot loop)
    for (ct, should_scan) in &content_types {
        assert_eq!(
            scanner.is_scannable_content_type(ct),
            *should_scan,
            "Content-type {} should_scan={}",
            ct,
            should_scan
        );
    }

    for (ct, _should_scan) in content_types {
        group.bench_with_input(BenchmarkId::new("is_scannable", ct), &ct, |b, ct| {
            b.iter(|| black_box(scanner.is_scannable_content_type(black_box(ct))))
        });
    }

    group.finish();
}

fn bench_dlp_truncation_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp/truncation");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(500);

    // Compare scan times with different inspection caps
    let configs = [
        ("4kb_cap", 4 * 1024),
        ("8kb_cap", 8 * 1024),
        ("16kb_cap", 16 * 1024),
        ("32kb_cap", 32 * 1024),
    ];

    // 32KB payload to test truncation at different caps
    let large_payload = generate_order_payload(32);

    for (name, cap) in configs {
        let config = DlpConfig {
            max_body_inspection_bytes: cap,
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        group.bench_with_input(
            BenchmarkId::new("scan_32kb_payload", name),
            &large_payload,
            |b, payload| b.iter(|| scanner.scan(black_box(payload))),
        );
    }

    group.finish();
}

fn bench_dlp_fast_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp/fast_mode");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    // Test payloads at 4KB and 8KB (most relevant sizes)
    let sizes_kb = [4, 8];

    for size_kb in sizes_kb {
        let payload_with_pii = generate_order_payload(size_kb);

        // Normal mode (comprehensive)
        let normal_scanner = DlpScanner::new(DlpConfig::default());
        let name = format!("normal_{}kb", size_kb);

        group.bench_with_input(
            BenchmarkId::new("scan", &name),
            &payload_with_pii,
            |b, payload| b.iter(|| normal_scanner.scan(black_box(payload))),
        );

        // Fast mode (skip email, phone, IPv4)
        let fast_config = DlpConfig {
            fast_mode: true,
            ..Default::default()
        };
        let fast_scanner = DlpScanner::new(fast_config);
        let name = format!("fast_{}kb", size_kb);

        group.bench_with_input(
            BenchmarkId::new("scan", &name),
            &payload_with_pii,
            |b, payload| b.iter(|| fast_scanner.scan(black_box(payload))),
        );
    }

    group.finish();
}

/// Combined benchmark: libsynapse (237 rules + entity tracking) + DLP scanner
/// This simulates the realistic production path for a request with body inspection.
fn bench_combined_waf_dlp(c: &mut Criterion) {
    // Ensure libsynapse engine is initialized with 237 rules
    DetectionEngine::ensure_init();

    let mut group = c.benchmark_group("pipeline/waf_plus_dlp");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    // Test with realistic e-commerce payloads
    let sizes_kb = [4, 8];

    // Headers for a realistic POST request
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        (
            "user-agent".to_string(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        ),
        ("accept".to_string(), "application/json".to_string()),
        ("x-forwarded-for".to_string(), "203.0.113.42".to_string()),
    ];

    for size_kb in sizes_kb {
        let payload = generate_order_payload(size_kb);

        // Benchmark 1: libsynapse only (237 rules + entity tracking)
        let name = format!("waf_only_{}kb", size_kb);
        group.bench_with_input(
            BenchmarkId::new("analyze", &name),
            &(&payload, &headers),
            |b, (body, hdrs)| {
                b.iter(|| {
                    DetectionEngine::analyze(
                        black_box("POST"),
                        black_box("/api/checkout"),
                        black_box(hdrs),
                        black_box(Some(body.as_bytes())),
                    )
                })
            },
        );

        // Benchmark 2: DLP scanner only (for comparison)
        let dlp_scanner = DlpScanner::new(DlpConfig::default());
        let name = format!("dlp_only_{}kb", size_kb);
        group.bench_with_input(BenchmarkId::new("analyze", &name), &payload, |b, body| {
            b.iter(|| dlp_scanner.scan(black_box(body)))
        });

        // Benchmark 3: Combined WAF + DLP (realistic production path)
        let name = format!("waf_plus_dlp_{}kb", size_kb);
        group.bench_with_input(
            BenchmarkId::new("analyze", &name),
            &(&payload, &headers),
            |b, (body, hdrs)| {
                b.iter(|| {
                    // Step 1: WAF detection (headers, URI, body for rule matching)
                    let waf_result = DetectionEngine::analyze(
                        black_box("POST"),
                        black_box("/api/checkout"),
                        black_box(hdrs),
                        black_box(Some(body.as_bytes())),
                    );

                    // Step 2: DLP body inspection (sensitive data detection)
                    let dlp_result = dlp_scanner.scan(black_box(body));

                    // Return both results (simulates real decision logic)
                    (waf_result, dlp_result)
                })
            },
        );

        // Benchmark 4: Combined WAF + DLP fast mode
        let fast_scanner = DlpScanner::new(DlpConfig {
            fast_mode: true,
            ..Default::default()
        });
        let name = format!("waf_plus_dlp_fast_{}kb", size_kb);
        group.bench_with_input(
            BenchmarkId::new("analyze", &name),
            &(&payload, &headers),
            |b, (body, hdrs)| {
                b.iter(|| {
                    let waf_result = DetectionEngine::analyze(
                        black_box("POST"),
                        black_box("/api/checkout"),
                        black_box(hdrs),
                        black_box(Some(body.as_bytes())),
                    );
                    let dlp_result = fast_scanner.scan(black_box(body));
                    (waf_result, dlp_result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Rule Scaling & Large Body Benchmarks
// ============================================================================

fn bench_rule_scaling(c: &mut Criterion) {
    let rules_path = "data/rules.json";
    let rules_json = match fs::read(rules_path) {
        Ok(data) => data,
        Err(_) => {
            eprintln!("WARNING: data/rules.json not found, skipping rule scaling benchmark");
            return;
        }
    };

    let mut group = c.benchmark_group("waf/rule_scaling");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(100);
    group.noise_threshold(0.02);

    // Parse rules to get total count, then test with subsets
    // We create separate engines with different rule counts
    let all_rules: Vec<serde_json::Value> =
        serde_json::from_slice(&rules_json).expect("Failed to parse rules.json as array");
    let total = all_rules.len();

    let test_request = SynapseRequest {
        method: "GET",
        path: "/api/search?q=test' OR '1'='1&page=1",
        query: None,
        headers: vec![
            SynapseHeader::new("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            SynapseHeader::new("cookie", "session=abc123"),
        ],
        body: None,
        client_ip: "192.168.1.100",
        is_static: false,
    };

    for count in [10, 50, 100, total] {
        let subset: Vec<serde_json::Value> = all_rules.iter().take(count).cloned().collect();
        let subset_json = serde_json::to_vec(&subset).unwrap();

        let mut synapse = Synapse::new();
        if let Err(e) = synapse.load_rules(&subset_json) {
            eprintln!("Failed to load {} rules: {}", count, e);
            continue;
        }

        let label = if count == total {
            format!("all_{}", total)
        } else {
            format!("{}", count)
        };

        group.bench_with_input(
            BenchmarkId::new("analyze", &label),
            &synapse,
            |b, engine| b.iter(|| black_box(engine.analyze(black_box(&test_request)))),
        );
    }

    group.finish();
}

fn bench_dlp_large_bodies(c: &mut Criterion) {
    let mut group = c.benchmark_group("dlp/large_body");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    let scanner = DlpScanner::new(DlpConfig {
        max_body_inspection_bytes: 512 * 1024, // Raise cap to test large scans
        ..Default::default()
    });

    for size_kb in [128, 512] {
        let clean = generate_clean_payload(size_kb);
        group.throughput(Throughput::Bytes(clean.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("scan", format!("clean_{}kb", size_kb)),
            &clean,
            |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
        );

        let pii = generate_order_payload(size_kb);
        group.throughput(Throughput::Bytes(pii.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("scan", format!("pii_{}kb", size_kb)),
            &pii,
            |b, payload| b.iter(|| black_box(scanner.scan(black_box(payload)))),
        );
    }

    group.finish();
}

// ============================================================================
// Evasive Attacks & Mixed Traffic Benchmarks
// ============================================================================

fn bench_evasive_attacks(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let mut group = c.benchmark_group("evasive_attacks");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let evasion_payloads: Vec<(&str, &str)> = vec![
        // Encoded XSS variants
        (
            "xss_hex_encoded",
            "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        ),
        (
            "xss_double_encoded",
            "/search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        ),
        (
            "xss_unicode",
            "/search?q=\u{FF1C}script\u{FF1E}alert(1)\u{FF1C}/script\u{FF1E}",
        ),
        // Obfuscated SQLi
        ("sqli_comment_bypass", "/search?q=1'/**/OR/**/1=1--"),
        ("sqli_case_mixing", "/search?q=1'+uNiOn+SeLeCt+NuLl--"),
        ("sqli_concat", "/search?q=1'+OR+'a'||'b'='ab'--"),
        // Path traversal evasion
        (
            "path_traversal_encoded",
            "/files/..%2F..%2F..%2Fetc%2Fpasswd",
        ),
        (
            "path_traversal_double_dot",
            "/files/....//....//....//etc/passwd",
        ),
        (
            "path_traversal_null_byte",
            "/files/../../../etc/passwd%00.png",
        ),
        // Command injection evasion
        ("cmd_inj_newline", "/api/ping?host=127.0.0.1%0als+-la"),
        ("cmd_inj_backtick", "/api/ping?host=`cat /etc/passwd`"),
        // Polyglot
        ("polyglot_xss_sqli", "/search?q='-alert(1)-'/**/OR/**/1=1--"),
    ];

    for (name, uri) in &evasion_payloads {
        group.bench_with_input(BenchmarkId::new("detection", *name), uri, |b, uri| {
            b.iter(|| {
                black_box(DetectionEngine::analyze(
                    black_box("GET"),
                    black_box(uri),
                    black_box(&[]),
                    black_box(None),
                ))
            })
        });
    }

    group.finish();
}

fn bench_mixed_traffic(c: &mut Criterion) {
    DetectionEngine::ensure_init();

    let mut group = c.benchmark_group("mixed_traffic");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(200);

    // 95% benign / 5% attack ratio (more realistic than the existing 70/30 throughput bench)
    let requests: Vec<(&str, &str)> = vec![
        // 19 benign requests
        ("GET", "/"),
        ("GET", "/api/users/123"),
        ("GET", "/api/products?page=1&limit=20"),
        ("GET", "/static/main.css"),
        ("GET", "/static/app.js"),
        ("GET", "/api/health"),
        ("GET", "/api/search?q=wireless+headphones"),
        ("POST", "/api/login"),
        ("GET", "/api/users/456/orders"),
        ("PUT", "/api/users/123/settings"),
        ("GET", "/api/categories"),
        ("GET", "/images/logo.png"),
        ("GET", "/api/notifications"),
        ("DELETE", "/api/cart/items/789"),
        ("GET", "/api/recommendations"),
        ("POST", "/api/checkout"),
        ("GET", "/api/users/123/profile"),
        ("GET", "/api/inventory?sku=PROD-001"),
        ("GET", "/favicon.ico"),
        // 1 attack (5%)
        (
            "GET",
            "/api/search?q=1'+UNION+SELECT+username,password+FROM+users--",
        ),
    ];

    group.throughput(Throughput::Elements(requests.len() as u64));

    group.bench_function("95_benign_5_attack", |b| {
        b.iter(|| {
            for (method, uri) in &requests {
                black_box(DetectionEngine::analyze(
                    black_box(method),
                    black_box(uri),
                    black_box(&[]),
                    black_box(None),
                ));
            }
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
    bench_heavy_complex,
    bench_realistic_scenarios,
    bench_dlp_body_inspection,
    bench_dlp_content_type_skip,
    bench_dlp_truncation_performance,
    bench_dlp_fast_mode,
    bench_combined_waf_dlp,
    bench_rule_scaling,
    bench_dlp_large_bodies,
    bench_evasive_attacks,
    bench_mixed_traffic,
);

criterion_main!(benches);
