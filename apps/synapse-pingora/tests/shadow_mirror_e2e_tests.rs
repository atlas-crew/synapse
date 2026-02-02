//! End-to-end tests for the shadow mirroring pipeline.
//!
//! Validates delivery, rate limiting, and bounded queue behavior.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Json,
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, oneshot};

use synapse_pingora::shadow::{MirrorPayload, ShadowMirrorConfig, ShadowMirrorManager};

#[derive(Clone, Debug)]
struct ReceivedRequest {
    payload: MirrorPayload,
    headers: HashMap<String, String>,
}

struct HoneypotState {
    received: Mutex<Vec<ReceivedRequest>>,
    notify: Notify,
    delay: Duration,
}

impl HoneypotState {
    fn new(delay: Duration) -> Self {
        Self {
            received: Mutex::new(Vec::new()),
            notify: Notify::new(),
            delay,
        }
    }
}

async fn honeypot_handler(
    State(state): State<Arc<HoneypotState>>,
    headers: HeaderMap,
    Json(payload): Json<MirrorPayload>,
) -> StatusCode {
    if state.delay > Duration::from_secs(0) {
        tokio::time::sleep(state.delay).await;
    }

    let mut header_map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(val) = value.to_str() {
            header_map.insert(name.as_str().to_string(), val.to_string());
        }
    }

    let mut received = state.received.lock().await;
    received.push(ReceivedRequest { payload, headers: header_map });
    state.notify.notify_waiters();

    StatusCode::OK
}

async fn spawn_honeypot(delay: Duration) -> (SocketAddr, oneshot::Sender<()>, Arc<HoneypotState>) {
    let state = Arc::new(HoneypotState::new(delay));
    let app = Router::new()
        .route("/mirror", post(honeypot_handler))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind honeypot");
    let addr = listener.local_addr().expect("honeypot addr");

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    (addr, shutdown_tx, state)
}

async fn wait_for_received(
    state: &Arc<HoneypotState>,
    expected: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if state.received.lock().await.len() >= expected {
            return true;
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }

        let remaining = deadline - now;
        if tokio::time::timeout(remaining, state.notify.notified()).await.is_err() {
            return false;
        }
    }
}

fn base_config(url: String) -> ShadowMirrorConfig {
    ShadowMirrorConfig {
        enabled: true,
        min_risk_score: 10.0,
        max_risk_score: 90.0,
        honeypot_urls: vec![url],
        sampling_rate: 1.0,
        per_ip_rate_limit: 10,
        timeout_secs: 2,
        hmac_secret: None,
        include_body: true,
        max_body_size: 16,
        include_headers: vec![
            "User-Agent".to_string(),
            "X-Test".to_string(),
            "Authorization".to_string(),
            "Cookie".to_string(),
        ],
    }
}

fn compute_signature(secret: &str, payload: &MirrorPayload) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can accept any key length");
    let json = payload.to_json_bytes().expect("payload json");
    mac.update(&json);
    hex::encode(mac.finalize().into_bytes())
}

fn build_payload(manager: &ShadowMirrorManager, request_id: &str, ip: &str) -> MirrorPayload {
    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), "mirror-client".to_string());
    headers.insert("X-Test".to_string(), "present".to_string());
    headers.insert("Authorization".to_string(), "Bearer should-strip".to_string());
    headers.insert("Cookie".to_string(), "session=secret".to_string());

    manager.create_payload(
        request_id.to_string(),
        ip.to_string(),
        "POST".to_string(),
        "/login".to_string(),
        "example.com".to_string(),
        55.0,
        vec!["RULE-1".to_string()],
        Some("ja4".to_string()),
        Some("ja4h".to_string()),
        Some("campaign-1".to_string()),
        headers,
        Some("0123456789ABCDEF012345".to_string()),
    )
}

#[tokio::test]
async fn test_shadow_mirror_delivers_payload_and_headers() {
    let (addr, shutdown_tx, state) = spawn_honeypot(Duration::from_secs(0)).await;
    let url = format!("http://{}/mirror", addr);

    let mut config = base_config(url);
    config.hmac_secret = Some("test-secret".to_string());
    let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
        .expect("manager creation");

    assert!(manager.should_mirror(55.0, "203.0.113.10"));
    let payload = build_payload(&manager, "req-1", "203.0.113.10");
    let expected_signature = compute_signature("test-secret", &payload);

    assert!(manager.mirror_async(payload));
    assert!(wait_for_received(&state, 1, Duration::from_secs(2)).await);

    let received = {
        let guard = state.received.lock().await;
        guard[0].clone()
    };

    assert_eq!(received.payload.request_id, "req-1");
    assert_eq!(received.payload.source_ip, "203.0.113.10");
    assert_eq!(received.payload.site_name, "example.com");
    assert_eq!(received.payload.sensor_id, "sensor-01");
    assert_eq!(received.payload.risk_score, 55.0);
    assert_eq!(received.payload.body.as_deref(), Some("0123456789ABCDEF"));

    assert_eq!(
        received.payload.headers.get("User-Agent"),
        Some(&"mirror-client".to_string())
    );
    assert_eq!(
        received.payload.headers.get("X-Test"),
        Some(&"present".to_string())
    );
    assert!(!received.payload.headers.contains_key("Authorization"));
    assert!(!received.payload.headers.contains_key("Cookie"));

    assert_eq!(received.headers.get("x-shadow-mirror"), Some(&"1".to_string()));
    assert_eq!(received.headers.get("x-request-id"), Some(&"req-1".to_string()));
    assert_eq!(received.headers.get("x-protocol-version"), Some(&"1.0".to_string()));
    assert_eq!(received.headers.get("x-signature"), Some(&expected_signature));

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_shadow_mirror_respects_rate_limit() {
    let (addr, shutdown_tx, state) = spawn_honeypot(Duration::from_secs(0)).await;
    let url = format!("http://{}/mirror", addr);

    let mut config = base_config(url);
    config.per_ip_rate_limit = 2;
    config.include_headers.clear();
    let manager = ShadowMirrorManager::new(config, "sensor-01".to_string())
        .expect("manager creation");

    let ip = "198.51.100.55";
    for idx in 0..3 {
        if manager.should_mirror(55.0, ip) {
            let payload = manager.create_payload(
                format!("req-{}", idx),
                ip.to_string(),
                "GET".to_string(),
                "/rate".to_string(),
                "example.com".to_string(),
                55.0,
                Vec::new(),
                None,
                None,
                None,
                HashMap::new(),
                None,
            );
            manager.mirror_async(payload);
        }
    }

    assert!(wait_for_received(&state, 2, Duration::from_secs(2)).await);
    let received_count = state.received.lock().await.len();
    assert_eq!(received_count, 2);
    assert_eq!(manager.stats().skipped_rate_limit, 1);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_shadow_mirror_backpressure_is_non_blocking() {
    let (addr, shutdown_tx, state) = spawn_honeypot(Duration::from_millis(250)).await;
    let url = format!("http://{}/mirror", addr);

    let mut config = base_config(url);
    config.per_ip_rate_limit = 100;
    config.include_headers.clear();
    config.include_body = false;
    let manager = ShadowMirrorManager::with_max_concurrent(
        config,
        "sensor-01".to_string(),
        1,
    ).expect("manager creation");

    let payload_a = manager.create_payload(
        "req-a".to_string(),
        "203.0.113.20".to_string(),
        "POST".to_string(),
        "/slow".to_string(),
        "example.com".to_string(),
        55.0,
        Vec::new(),
        None,
        None,
        None,
        HashMap::new(),
        None,
    );

    let payload_b = manager.create_payload(
        "req-b".to_string(),
        "203.0.113.21".to_string(),
        "POST".to_string(),
        "/slow".to_string(),
        "example.com".to_string(),
        55.0,
        Vec::new(),
        None,
        None,
        None,
        HashMap::new(),
        None,
    );

    let start_first = Instant::now();
    let first_queued = manager.mirror_async(payload_a);
    let first_elapsed = start_first.elapsed();

    let start_second = Instant::now();
    let second_queued = manager.mirror_async(payload_b);
    let second_elapsed = start_second.elapsed();

    assert!(first_queued);
    assert!(!second_queued);
    assert!(first_elapsed < Duration::from_millis(100));
    assert!(second_elapsed < Duration::from_millis(100));

    assert!(wait_for_received(&state, 1, Duration::from_secs(2)).await);
    tokio::time::sleep(Duration::from_millis(350)).await;

    let stats = manager.stats();
    assert_eq!(stats.dropped_queue_full, 1);
    assert_eq!(stats.queue_available, 1);

    let _ = shutdown_tx.send(());
}
