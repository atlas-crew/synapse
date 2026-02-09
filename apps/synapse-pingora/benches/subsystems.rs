//! Subsystem benchmarks for Synapse-Pingora detection engines.
//!
//! Benchmarks: Session tracking, Trends/anomaly detection, Crawler detection,
//! Credential stuffing, Geo/impossible travel, and Interrogator (cookie signing).
//!
//! Run with: `cargo bench --bench subsystems`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use synapse_pingora::{
    AnomalyQueryOptions,
    AuthAttempt,
    AuthResult,
    CookieConfig,
    // Cookie manager (interrogator)
    CookieManager,
    CrawlerConfig,
    // Crawler
    CrawlerDetector,
    // Credential stuffing
    CredentialStuffingDetector,
    GeoLocation,
    // Geo / impossible travel
    ImpossibleTravelDetector,
    LoginEvent,
    // Session
    SessionConfig,
    SessionManager,
    Signal,
    SignalMetadata,
    TravelConfig,
    TrendQueryOptions,
    TrendsConfig,
    // Trends
    TrendsManager,
    TrendsSignalType,
};

// ============================================================================
// Helpers
// ============================================================================

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn test_ip(last: u8) -> IpAddr {
    format!("192.168.1.{}", last).parse().unwrap()
}

fn make_signal(entity_id: &str, signal_type: TrendsSignalType, value: &str) -> Signal {
    Signal {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        category: signal_type.category(),
        signal_type,
        value: value.to_string(),
        entity_id: entity_id.to_string(),
        session_id: None,
        metadata: SignalMetadata::default(),
    }
}

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

// ============================================================================
// 1. Session Validation
// ============================================================================

fn bench_session_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/validate_request");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    let manager = SessionManager::new(SessionConfig::default());
    let ip = test_ip(1);
    let ja4 = "t13d1516h2_abcdef123456";

    // Pre-create 100 sessions
    let mut tokens: Vec<String> = Vec::with_capacity(100);
    for i in 0..100 {
        let token = format!("session_token_{:04}", i);
        manager.create_session(&token, ip, Some(ja4));
        tokens.push(token);
    }

    group.bench_function("validate_existing", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let token = &tokens[idx % tokens.len()];
            let decision =
                manager.validate_request(black_box(token), black_box(ip), black_box(Some(ja4)));
            black_box(decision);
            idx += 1;
        });
    });

    group.bench_function("validate_unknown", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let token = format!("unknown_token_{}", idx);
            let decision =
                manager.validate_request(black_box(&token), black_box(ip), black_box(None));
            black_box(decision);
            idx += 1;
        });
    });

    group.bench_function("validate_ip_change", |b| {
        let alt_ip = test_ip(200);
        let mut idx = 0usize;
        b.iter(|| {
            let token = &tokens[idx % tokens.len()];
            let decision =
                manager.validate_request(black_box(token), black_box(alt_ip), black_box(Some(ja4)));
            black_box(decision);
            idx += 1;
        });
    });

    group.bench_function("touch_session", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let token = &tokens[idx % tokens.len()];
            manager.touch_session(black_box(token));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 2. Session Creation
// ============================================================================

fn bench_session_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/create");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    let ja4 = "t13d1516h2_abcdef123456";

    group.bench_function("create_session", |b| {
        let manager = SessionManager::new(SessionConfig::default());
        let ip = test_ip(10);
        let mut idx = 0u64;
        b.iter(|| {
            let token = format!("new_token_{}", idx);
            let session =
                manager.create_session(black_box(&token), black_box(ip), black_box(Some(ja4)));
            black_box(session);
            idx += 1;
        });
    });

    group.bench_function("get_session", |b| {
        let manager = SessionManager::new(SessionConfig::default());
        let ip = test_ip(10);
        let mut tokens = Vec::with_capacity(200);
        for i in 0..200 {
            let token = format!("get_token_{}", i);
            manager.create_session(&token, ip, Some(ja4));
            tokens.push(token);
        }
        let mut idx = 0usize;
        b.iter(|| {
            let token = &tokens[idx % tokens.len()];
            let session = manager.get_session(black_box(token));
            black_box(session);
            idx += 1;
        });
    });

    group.bench_function("get_actor_sessions", |b| {
        let manager = SessionManager::new(SessionConfig::default());
        let ip = test_ip(10);
        let actor_id = "actor-bench-001";
        for i in 0..10 {
            let token = format!("actor_sess_{}", i);
            manager.create_session(&token, ip, Some(ja4));
            manager.bind_to_actor(&token, actor_id);
        }
        b.iter(|| {
            let sessions = manager.get_actor_sessions(black_box(actor_id));
            black_box(sessions);
        });
    });

    group.finish();
}

// ============================================================================
// 3. Trends Recording
// ============================================================================

fn bench_trends_recording(c: &mut Criterion) {
    let mut group = c.benchmark_group("trends/record");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(500);

    group.bench_function("record_request", |b| {
        let manager = TrendsManager::new(TrendsConfig::default());
        let mut idx = 0u64;
        b.iter(|| {
            let entity = format!("10.0.0.{}", idx % 255);
            let sess = format!("sess-{}", idx % 50);
            manager.record_request(
                black_box(&entity),
                black_box(Some(sess.as_str())),
                black_box(Some(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )),
                black_box(Some("Bearer eyJhbGciOiJSUzI1NiJ9.test")),
                black_box(Some(&entity)),
                black_box(Some("t13d1516h2_abcdef123456")),
                black_box(Some("ge11cn20enus_abcdef")),
                black_box(Some(idx as i64)),
            );
            idx += 1;
        });
    });

    group.bench_function("record_signal", |b| {
        let manager = TrendsManager::new(TrendsConfig::default());
        let mut idx = 0u64;
        b.iter(|| {
            let entity = format!("10.0.0.{}", idx % 255);
            let signal = make_signal(&entity, TrendsSignalType::Ja4, "t13d1516h2_abcdef123456");
            manager.record_signal(black_box(signal));
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 4. Trends Query
// ============================================================================

fn bench_trends_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("trends/query");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(200);

    // Pre-populate with 1000 requests
    let manager = TrendsManager::new(TrendsConfig::default());
    for i in 0..1000u64 {
        let entity = format!("10.0.0.{}", i % 255);
        let sess = format!("sess-{}", i % 50);
        manager.record_request(
            &entity,
            Some(sess.as_str()),
            Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            None,
            Some(&entity),
            Some("t13d1516h2_abcdef123456"),
            None,
            Some(i as i64),
        );
    }

    group.bench_function("get_summary", |b| {
        b.iter(|| {
            let summary = manager.get_summary(black_box(TrendQueryOptions::default()));
            black_box(summary);
        });
    });

    group.bench_function("get_anomalies", |b| {
        b.iter(|| {
            let anomalies = manager.get_anomalies(black_box(AnomalyQueryOptions::default()));
            black_box(anomalies);
        });
    });

    group.bench_function("get_signals_for_entity", |b| {
        b.iter(|| {
            let signals = manager.get_signals_for_entity(
                black_box("10.0.0.1"),
                black_box(TrendQueryOptions::default()),
            );
            black_box(signals);
        });
    });

    group.finish();
}

// ============================================================================
// 5. Crawler Detection (bad bot check)
// ============================================================================

fn bench_crawler_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("crawler/bad_bot");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(5000);

    // Build a fully-initialised CrawlerDetector via the async constructor.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for bench");

    let detector = rt.block_on(async {
        let config = CrawlerConfig::default();
        CrawlerDetector::new(config)
            .await
            .unwrap_or_else(|_| CrawlerDetector::disabled())
    });

    group.bench_function("known_good_bot", |b| {
        b.iter(|| {
            let result = detector
                .check_bad_bot(black_box("Googlebot/2.1 (+http://www.google.com/bot.html)"));
            black_box(result);
        });
    });

    group.bench_function("known_bad_bot", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box("python-requests/2.28.0"));
            black_box(result);
        });
    });

    group.bench_function("normal_browser", |b| {
        b.iter(|| {
            let result = detector.check_bad_bot(black_box(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ));
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
// 6. Credential Stuffing
// ============================================================================

fn bench_credential_stuffing(c: &mut Criterion) {
    let mut group = c.benchmark_group("detection/credential_stuffing");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    group.bench_function("record_attempt", |b| {
        let detector = CredentialStuffingDetector::with_defaults();
        let mut idx = 0u64;
        b.iter(|| {
            let ts = now_ms() + idx;
            let ip = format!("10.0.{}.{}", (idx / 256) % 256, idx % 256);
            let attempt = AuthAttempt::new(&ip, "/api/login", ts);
            let verdict = detector.record_attempt(black_box(&attempt));
            black_box(verdict);
            idx += 1;
        });
    });

    group.bench_function("record_result", |b| {
        let detector = CredentialStuffingDetector::with_defaults();
        let mut idx = 0u64;
        b.iter(|| {
            let ts = now_ms() + idx;
            let ip = format!("10.0.{}.{}", (idx / 256) % 256, idx % 256);
            let result = AuthResult::new(&ip, "/api/login", false, ts);
            let alert = detector.record_result(black_box(&result));
            black_box(alert);
            idx += 1;
        });
    });

    group.bench_function("is_auth_endpoint", |b| {
        let detector = CredentialStuffingDetector::with_defaults();
        let paths = [
            "/api/login",
            "/api/auth/token",
            "/v1/signin",
            "/oauth/authorize",
            "/api/users",
            "/api/products",
            "/static/index.html",
            "/health",
        ];
        let mut idx = 0usize;
        b.iter(|| {
            let path = paths[idx % paths.len()];
            let is_auth = detector.is_auth_endpoint(black_box(path));
            black_box(is_auth);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 7. Impossible Travel
// ============================================================================

fn bench_impossible_travel(c: &mut Criterion) {
    let mut group = c.benchmark_group("geo/impossible_travel");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(1000);

    // Pre-load user with 5 logins from NYC
    let base_ts: u64 = 1_700_000_000_000; // Fixed base timestamp

    group.bench_function("check_login_normal", |b| {
        let mut detector = ImpossibleTravelDetector::new(TravelConfig::default());
        // Seed history: 5 logins from NYC
        for i in 0..5u64 {
            let loc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "United States", "US")
                .with_city("New York")
                .with_accuracy(10);
            let event = LoginEvent::new("bench-user", base_ts + i * 3600_000, loc);
            detector.check_login(&event);
        }

        let mut idx = 0u64;
        b.iter(|| {
            // Same city login (no alert expected)
            let ts = base_ts + 5 * 3600_000 + idx * 3600_000;
            let loc = GeoLocation::new("1.2.3.5", 40.7500, -74.0100, "United States", "US")
                .with_city("New York")
                .with_accuracy(10);
            let event = LoginEvent::new("bench-user", ts, loc);
            let alert = detector.check_login(black_box(&event));
            black_box(alert);
            idx += 1;
        });
    });

    group.bench_function("check_login_travel", |b| {
        let mut detector = ImpossibleTravelDetector::new(TravelConfig::default());
        // Seed: one login from NYC
        let loc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "United States", "US");
        let event = LoginEvent::new("travel-user", base_ts, loc);
        detector.check_login(&event);

        let mut idx = 0u64;
        b.iter(|| {
            // Login from London 10 min later (should trigger alert)
            let ts = base_ts + 600_000 + idx;
            let loc = GeoLocation::new("5.6.7.8", 51.5074, -0.1278, "United Kingdom", "GB")
                .with_city("London")
                .with_accuracy(10);
            let event = LoginEvent::new("travel-user", ts, loc);
            let alert = detector.check_login(black_box(&event));
            black_box(alert);
            idx += 1;
        });
    });

    group.bench_function("check_login_new_user", |b| {
        let mut detector = ImpossibleTravelDetector::new(TravelConfig::default());
        let mut idx = 0u64;
        b.iter(|| {
            // New user each time (no history, no alert)
            let user_id = format!("new-user-{}", idx);
            let loc = GeoLocation::new("1.2.3.4", 40.7128, -74.0060, "United States", "US");
            let event = LoginEvent::new(&user_id, base_ts + idx, loc);
            let alert = detector.check_login(black_box(&event));
            black_box(alert);
            idx += 1;
        });
    });

    group.finish();
}

// ============================================================================
// 8. Cookie Signing (Interrogator)
// ============================================================================

fn bench_cookie_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("interrogator/cookie");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(2000);

    let manager = CookieManager::new(test_cookie_config()).expect("CookieManager creation");

    group.bench_function("generate_tracking_cookie", |b| {
        let mut idx = 0u64;
        b.iter(|| {
            let actor = format!("actor-{}", idx);
            let challenge = manager.generate_tracking_cookie(black_box(&actor));
            black_box(challenge);
            idx += 1;
        });
    });

    // Pre-generate a valid cookie for validation benchmarks
    let valid_cookie = manager.generate_tracking_cookie("bench-actor");

    group.bench_function("validate_cookie", |b| {
        b.iter(|| {
            let result = manager.validate_cookie(
                black_box("bench-actor"),
                black_box(&valid_cookie.cookie_value),
            );
            black_box(result);
        });
    });

    group.bench_function("validate_cookie_invalid", |b| {
        b.iter(|| {
            let result = manager.validate_cookie(
                black_box("bench-actor"),
                black_box("garbage.invalid.data00000000000000"),
            );
            black_box(result);
        });
    });

    group.bench_function("correlate_actor", |b| {
        b.iter(|| {
            let correlated = manager.correlate_actor(black_box(&valid_cookie.cookie_value));
            black_box(correlated);
        });
    });

    group.finish();
}

// ============================================================================
// 9. Session Contention (multi-threaded)
// ============================================================================

fn bench_session_contention(c: &mut Criterion) {
    let mut group = c.benchmark_group("contention/session_manager");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);
    group.noise_threshold(0.05);

    let thread_counts = [1, 2, 4, 8];
    let ja4 = "t13d1516h2_contention_bench";

    for &threads in &thread_counts {
        group.bench_with_input(
            BenchmarkId::new("mixed_ops", threads),
            &threads,
            |b, &num_threads| {
                let manager = Arc::new(SessionManager::new(SessionConfig::default()));
                let ip = test_ip(1);

                // Pre-seed 500 sessions for validate_request to find
                for i in 0..500u64 {
                    let token = format!("contention_token_{}", i);
                    manager.create_session(&token, ip, Some(ja4));
                }

                b.iter(|| {
                    let ops_per_thread = 200;
                    std::thread::scope(|s| {
                        for t in 0..num_threads {
                            let mgr = Arc::clone(&manager);
                            s.spawn(move || {
                                for i in 0..ops_per_thread {
                                    let global_idx = t * ops_per_thread + i;
                                    if global_idx % 4 == 0 {
                                        // 25% creates
                                        let token = format!("new_contention_{}_{}", t, i);
                                        let session = mgr.create_session(&token, ip, Some(ja4));
                                        black_box(session);
                                    } else {
                                        // 75% validates on existing tokens
                                        let token =
                                            format!("contention_token_{}", global_idx % 500);
                                        let decision = mgr.validate_request(&token, ip, Some(ja4));
                                        black_box(decision);
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
// Criterion Groups & Main
// ============================================================================

criterion_group!(
    session_benches,
    bench_session_validation,
    bench_session_creation,
);

criterion_group!(trends_benches, bench_trends_recording, bench_trends_query,);

criterion_group!(crawler_benches, bench_crawler_detection,);

criterion_group!(detection_benches, bench_credential_stuffing,);

criterion_group!(geo_benches, bench_impossible_travel,);

criterion_group!(interrogator_benches, bench_cookie_signing,);

criterion_group!(contention_benches, bench_session_contention,);

criterion_main!(
    session_benches,
    trends_benches,
    crawler_benches,
    detection_benches,
    geo_benches,
    interrogator_benches,
    contention_benches,
);
