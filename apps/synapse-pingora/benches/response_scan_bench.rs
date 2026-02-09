//! Response-side DLP scanning benchmarks.
//!
//! Extends DLP coverage to response body scanning: HTML pages, JSON API
//! responses, streaming chunked scanning, content-type filtering, and
//! realistic mixed-traffic patterns.
//!
//! Run with: `cargo bench --bench response_scan_bench`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::dlp::{DlpConfig, DlpScanner, StreamingScanner};

// ============================================================================
// Helpers
// ============================================================================

/// Generate an HTML response body of approximately `target_size` bytes
/// with embedded PII (credit card and SSN).
fn generate_html_with_pii(target_size: usize) -> String {
    let header = "<html><body><h1>Customer Report</h1><p>Account details:</p><ul>";
    let pii_block = "<li>Card: 4532-0151-1283-0366</li><li>SSN: 123-45-6789</li>\
        <li>Email: john.smith@example.com</li>";
    let filler = "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
        Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
        Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.</p>";
    let footer = "</ul></body></html>";

    let mut body = String::with_capacity(target_size + 256);
    body.push_str(header);
    body.push_str(pii_block);

    while body.len() < target_size - footer.len() {
        body.push_str(filler);
    }
    body.push_str(footer);
    body.truncate(target_size);
    body
}

fn json_response_with_pii() -> String {
    r#"{"status":"ok","users":[{"name":"John Smith","ssn":"123-45-6789","email":"john@example.com","card":"4532015112830366"},{"name":"Jane Doe","ssn":"987-65-4321","email":"jane@example.com","phone":"212-555-0199"}],"pagination":{"page":1,"total":100}}"#.to_string()
}

fn clean_html() -> String {
    "<html><body><h1>Welcome</h1><p>Lorem ipsum dolor sit amet, consectetur \
     adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore \
     magna aliqua.</p></body></html>"
        .to_string()
}

// ============================================================================
// 1. HTML Response Scanning — Various Sizes
// ============================================================================

fn bench_html_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/html_response");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let scanner = DlpScanner::new(DlpConfig::default());

    for size in [4096, 16384, 65536] {
        let html = generate_html_with_pii(size);

        group.bench_with_input(
            BenchmarkId::new("scan", format!("{}B", size)),
            &html,
            |b, html| {
                b.iter(|| {
                    let result = scanner.scan(black_box(html));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 2. JSON API Response
// ============================================================================

fn bench_json_api_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/json_api_response");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let scanner = DlpScanner::new(DlpConfig::default());
    let json_body = json_response_with_pii();

    group.bench_function("scan_json_with_pii", |b| {
        b.iter(|| {
            let result = scanner.scan(black_box(&json_body));
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Streaming Chunks
// ============================================================================

fn bench_streaming_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/streaming_chunks");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let config = DlpConfig::default();
    let scanner = Arc::new(DlpScanner::new(config.clone()));

    // 64KB body with PII
    let body = generate_html_with_pii(65536);
    let body_bytes = body.as_bytes();

    for chunk_size in [1024, 4096, 16384] {
        let chunks: Vec<&[u8]> = body_bytes.chunks(chunk_size).collect();

        group.bench_with_input(
            BenchmarkId::new("chunk_size", format!("{}B", chunk_size)),
            &chunks,
            |b, chunks| {
                b.iter(|| {
                    let mut streaming =
                        StreamingScanner::with_auto_overlap(Arc::clone(&scanner), &config);
                    for chunk in chunks.iter() {
                        let _ = streaming.update(black_box(chunk));
                    }
                    let result = streaming.finish();
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// 4. Streaming vs Batch Comparison
// ============================================================================

fn bench_streaming_vs_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/streaming_vs_batch");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    let config = DlpConfig::default();
    let scanner = Arc::new(DlpScanner::new(config.clone()));
    let body = generate_html_with_pii(65536);
    let body_bytes = body.as_bytes();
    let chunks: Vec<&[u8]> = body_bytes.chunks(4096).collect();

    group.bench_function("batch_scan_64KB", |b| {
        b.iter(|| {
            let result = scanner.scan(black_box(&body));
            black_box(result);
        });
    });

    group.bench_function("streaming_scan_64KB_4KB_chunks", |b| {
        b.iter(|| {
            let mut streaming = StreamingScanner::with_auto_overlap(Arc::clone(&scanner), &config);
            for chunk in &chunks {
                let _ = streaming.update(black_box(chunk));
            }
            let result = streaming.finish();
            black_box(result);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Content-Type Filter Fast Path
// ============================================================================

fn bench_content_type_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/content_type_filter");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10000);

    let scanner = DlpScanner::new(DlpConfig::default());

    let content_types = [
        "image/png",
        "text/html",
        "application/json",
        "application/octet-stream",
        "text/plain",
        "video/mp4",
    ];

    group.bench_function("is_scannable_cycle", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ct = content_types[idx % content_types.len()];
            let result = scanner.is_scannable_content_type(black_box(ct));
            black_box(result);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 6. Mixed Response Traffic
// ============================================================================

fn bench_mixed_response_traffic(c: &mut Criterion) {
    let mut group = c.benchmark_group("response_dlp/mixed_response_traffic");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);
    group.throughput(Throughput::Elements(1000));

    let scanner = DlpScanner::new(DlpConfig::default());

    let clean = clean_html();
    let pii_json = json_response_with_pii();

    // 80% clean HTML, 15% JSON with PII, 5% binary (skip)
    struct TrafficItem<'a> {
        content_type: &'a str,
        body: &'a str,
    }

    let mut traffic: Vec<TrafficItem> = Vec::with_capacity(1000);
    for _ in 0..800 {
        traffic.push(TrafficItem {
            content_type: "text/html",
            body: &clean,
        });
    }
    for _ in 0..150 {
        traffic.push(TrafficItem {
            content_type: "application/json",
            body: &pii_json,
        });
    }
    for _ in 0..50 {
        traffic.push(TrafficItem {
            content_type: "image/png",
            body: "",
        });
    }

    group.bench_function("mixed_1000_requests", |b| {
        b.iter(|| {
            for item in &traffic {
                if scanner.is_scannable_content_type(black_box(item.content_type)) {
                    let result = scanner.scan(black_box(item.body));
                    black_box(result);
                }
            }
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    response_dlp_benches,
    bench_html_response,
    bench_json_api_response,
    bench_streaming_chunks,
    bench_streaming_vs_batch,
    bench_content_type_filter,
    bench_mixed_response_traffic,
);

criterion_main!(response_dlp_benches);
