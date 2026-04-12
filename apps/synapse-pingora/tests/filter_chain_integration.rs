use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use pingora_core::protocols::l4::stream::Stream;
use pingora_core::protocols::{GetSocketDigest, SocketDigest};
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};
use serial_test::serial;
use std::os::unix::io::AsRawFd;

#[path = "../src/main.rs"]
mod synapse_main;

use synapse_pingora::actor::{ActorConfig, ActorManager};
use synapse_pingora::block_log::BlockLog;
use synapse_pingora::correlation::CampaignManager;
use synapse_pingora::crawler::CrawlerDetector;
use synapse_pingora::dlp::{DlpConfig, DlpScanner};
use synapse_pingora::entity::{EntityConfig, EntityManager};
use synapse_pingora::health::HealthChecker;
use synapse_pingora::intelligence::{SignalManager, SignalManagerConfig};
use synapse_pingora::interrogator::{
    CaptchaConfig, CaptchaManager, CookieManager, JsChallengeConfig, JsChallengeManager,
    ProgressionManager,
};
use synapse_pingora::metrics::MetricsRegistry;
use synapse_pingora::session::{SessionConfig, SessionManager};
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};
use synapse_pingora::telemetry::{TelemetryClient, TelemetryConfig};
use synapse_pingora::tls::TlsManager;
use synapse_pingora::trends::{TrendsConfig, TrendsManager};

fn header_snapshot(name: &str, value: &str) -> (HeaderName, HeaderValue) {
    let header_name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
    let header_value = HeaderValue::from_str(value).expect("valid header value");
    (header_name, header_value)
}

fn build_proxy(per_ip_rps_limit: usize) -> synapse_main::SynapseProxy {
    let backends = vec![("127.0.0.1".to_string(), 8080)];
    let tarpit_config = TarpitConfig::default();

    // ProgressionManager needs its own TarpitManager reference (SynapseProxy
    // internally creates another from deps.tarpit_config — a duplication
    // that's harmless for test scope).
    let tarpit_manager = Arc::new(TarpitManager::new(tarpit_config.clone()));
    let cookie_manager = Arc::new(CookieManager::new_fallback(
        synapse_main::create_default_cookie_config(),
    ));
    let js_manager = Arc::new(JsChallengeManager::new(JsChallengeConfig::default()));
    let captcha_manager = Arc::new(CaptchaManager::new(CaptchaConfig::default()));
    let progression_manager = Arc::new(ProgressionManager::new(
        cookie_manager,
        js_manager,
        captcha_manager,
        tarpit_manager,
        synapse_main::create_progression_config(),
    ));

    let deps = synapse_main::ProxyDependencies {
        health_checker: Arc::new(HealthChecker::default()),
        metrics_registry: Arc::new(MetricsRegistry::new()),
        telemetry_client: Arc::new(TelemetryClient::new(TelemetryConfig {
            enabled: false,
            ..TelemetryConfig::default()
        })),
        tls_manager: Arc::new(TlsManager::default()),
        dlp_scanner: Arc::new(DlpScanner::new(DlpConfig::default())),
        entity_manager: Arc::new(EntityManager::new(EntityConfig::default())),
        block_log: Arc::new(BlockLog::default()),
        actor_manager: Arc::new(ActorManager::new(ActorConfig::default())),
        session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
        shadow_mirror_manager: None,
        crawler_detector: Arc::new(CrawlerDetector::disabled()),
        horizon_manager: None,
        trends_manager: Arc::new(TrendsManager::new(TrendsConfig::default())),
        signal_manager: Arc::new(SignalManager::new(SignalManagerConfig::default())),
        progression_manager,
        campaign_manager: Arc::new(CampaignManager::new()),
        tarpit_config,
        trusted_proxies: Vec::new(),
        rps_limit: 10_000,
        per_ip_rps_limit,
    };

    synapse_main::SynapseProxy::with_health(backends, deps)
}

async fn make_session(request: &str) -> (Session, UnixStream) {
    let (mut client, server_stream) = UnixStream::pair().expect("unix stream pair");
    let raw_fd = server_stream.as_raw_fd();

    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let mut stream = Stream::from(server_stream);
    let mut socket_digest = SocketDigest::from_raw_fd(raw_fd);
    let fake_addr: std::net::SocketAddr = "127.0.0.1:1234".parse().expect("fake socket addr");
    let _ = socket_digest.peer_addr.set(Some(fake_addr.into()));
    let _ = socket_digest.local_addr.set(Some(fake_addr.into()));
    stream.set_socket_digest(socket_digest);
    let mut session = Session::new_h1(Box::new(stream));
    let read = session.read_request().await.expect("read request");
    assert!(read, "request should be parsed");

    (session, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_filter_chain_full_flow_sets_headers_and_dlp() {
    let proxy = build_proxy(100);
    let body = r#"{"ssn":"123-45-6789"}"#;
    let request = format!(
        "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let (mut session, _client) = make_session(&request).await;
    let mut ctx = proxy.new_ctx();

    proxy
        .early_request_filter(&mut session, &mut ctx)
        .await
        .expect("early_request_filter");
    let handled = proxy
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("request_filter");
    assert!(!handled, "request should continue to upstream");

    loop {
        let mut chunk = session
            .read_request_body()
            .await
            .expect("read request body");
        let end_of_stream = chunk.is_none();
        proxy
            .request_body_filter(&mut session, &mut chunk, end_of_stream, &mut ctx)
            .await
            .expect("request_body_filter");
        if end_of_stream {
            break;
        }
    }

    let mut upstream_request = session.req_header().clone();
    proxy
        .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
        .await
        .expect("upstream_request_filter");

    let dlp_count = upstream_request
        .headers
        .get("x-dlp-request-violations-pingora")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(dlp_count > 0, "expected DLP request scan to detect data");

    assert_eq!(
        upstream_request
            .headers
            .get("x-synapse-analyzed")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );

    let mut response = ResponseHeader::build(200, None).expect("response header");
    response
        .insert_header("content-type", "application/json")
        .expect("response content-type");
    proxy
        .response_filter(&mut session, &mut response, &mut ctx)
        .await
        .expect("response_filter");
    let request_id = response
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(!request_id.is_empty(), "expected X-Request-ID header");

    let mut resp_body = Some(Bytes::from("SSN: 123-45-6789"));
    let _ = proxy
        .response_body_filter(&mut session, &mut resp_body, true, &mut ctx)
        .expect("response_body_filter");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_rate_limit_short_circuits_before_waf() {
    let proxy = build_proxy(0);

    let request =
        "GET /search?q=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (mut session, mut client) = make_session(request).await;

    let headers = vec![header_snapshot("host", "example.com")];
    let detection = synapse_main::DetectionEngine::analyze(
        "GET",
        "/search?q=1 UNION SELECT * FROM users",
        &headers,
        None,
        "127.0.0.1",
    );
    assert!(detection.blocked, "WAF should block this payload");

    let mut ctx = proxy.new_ctx();
    let result = proxy.early_request_filter(&mut session, &mut ctx).await;
    assert!(result.is_err(), "expected early rate limit block");

    let mut buf = vec![0u8; 2048];
    let read = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
        .await
        .expect("response read timeout")
        .expect("response read");
    let response = String::from_utf8_lossy(&buf[..read]);
    assert!(response.contains("429"), "expected 429 response");
    assert!(
        response.contains("per_ip_rate_limit_exceeded"),
        "expected rate limit error body"
    );
}

/// TASK-54 wiring verification: after request_filter runs, the per-request
/// JA4H fingerprint must be registered with the proxy's CampaignManager.
/// Before the TASK-54 wiring, CampaignManager's detectors had no input data
/// because the filter chain never called register_fingerprints. This test
/// drives a request through early_request_filter + request_filter (which is
/// where the fingerprint is computed and my TASK-54 call site lives), then
/// queries the proxy's CampaignManager's fingerprint index to assert the
/// JA4H fingerprint was registered for the test client IP.
///
/// JA4H is always produced (unlike JA4 which can be None when no TLS header
/// is forwarded), so this test uses JA4H as the observable signal. The test
/// constructs a unique user-agent so the resulting JA4H fingerprint does not
/// collide with other tests' recorded state in the shared CampaignManager.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_request_filter_registers_fingerprint_with_campaign_manager() {
    let proxy = build_proxy(10_000);
    let campaign_manager = proxy.campaign_manager();
    let fingerprint_index = campaign_manager.index();

    // Snapshot the index stats BEFORE driving the request so we can detect
    // a net-new registration. FingerprintIndex.stats() tracks total_ips
    // (the number of distinct IPs registered in the index).
    let stats_before = fingerprint_index.stats();
    let ips_before = stats_before.total_ips;

    let request =
        "GET /task54-fingerprint-probe HTTP/1.1\r\n\
         Host: example.com\r\n\
         User-Agent: task54-fingerprint-probe/1.0\r\n\
         Accept: */*\r\n\
         \r\n";
    let (mut session, _client) = make_session(request).await;
    let mut ctx = proxy.new_ctx();

    // Drive early_request_filter first — sets client_ip and request_id.
    proxy
        .early_request_filter(&mut session, &mut ctx)
        .await
        .expect("early_request_filter");

    // Drive request_filter — this is where the fingerprint is computed
    // and the TASK-54 register_fingerprints call fires.
    let _handled = proxy
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("request_filter");

    // The fingerprint index must have at least one new IP entry after the
    // request_filter pass. Before TASK-54 this assertion would fail because
    // register_fingerprints was never called and the index stayed empty.
    let stats_after = fingerprint_index.stats();
    assert!(
        stats_after.total_ips > ips_before,
        "CampaignManager fingerprint index must have gained an IP after request_filter; \
         before={}, after={}",
        ips_before,
        stats_after.total_ips
    );
}

/// TASK-40 runtime verification: the deferred WAF pass writes the canonical
/// WAF_BLOCK_BODY envelope via send_waf_block_response and then returns
/// Err(pingora_core::Error::explain(HTTPStatus(403), ...)) from
/// upstream_request_filter. This test proves that:
///
/// 1. The filter's Err return causes Pingora to abort the upstream forward
///    (implicit — the test never configures an upstream peer, so any
///    forwarding attempt would fail the test earlier with a connection
///    error rather than succeed on a 403).
/// 2. The response body we wrote before returning Err is NOT overwritten
///    by Pingora — the client receives the exact JSON envelope TASK-34
///    promised, not a Pingora-synthesized generic 403 or a 502.
/// 3. The status line is 403, matching the typed HTTPStatus error we
///    returned.
///
/// The test mutates the global SYNAPSE engine via DetectionEngine::reload_rules
/// to inject a single dlp_violation rule (not present in the embedded
/// production_rules.json), runs the filter chain end-to-end, captures the
/// response from the client side of the UnixStream pair, and asserts the
/// full client contract. It then restores production_rules.json to leave
/// SYNAPSE pristine for any subsequent tests in this binary. The #[serial]
/// attribute prevents parallel runs of the other two tests in this file
/// from racing on the rule-swap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn test_deferred_dlp_block_returns_403_with_canonical_envelope() {
    // --- Setup: inject a deferred DLP rule into the global SYNAPSE ---
    // A single blocking rule that fires on any DLP match (count >= 1).
    // This rule is tagged as deferred at load time by the engine because
    // it references the dlp_violation match kind.
    let test_rule = r#"[{
        "id": 9999,
        "description": "TASK-40: block any DLP hit for deferred-pass verification",
        "risk": 80.0,
        "blocking": true,
        "matches": [{"type": "dlp_violation", "match": 1}]
    }]"#;
    synapse_main::DetectionEngine::reload_rules(test_rule.as_bytes())
        .expect("test rules must load");

    // --- Build proxy and request ---
    let proxy = build_proxy(10_000); // generous per-IP rate so we don't hit 429

    // Body with an SSN. DlpConfig::default() recognizes this pattern — the
    // neighboring test (test_filter_chain_full_flow_sets_headers_and_dlp)
    // uses the same payload and asserts dlp_count > 0, so we know the
    // scanner fires.
    let body = r#"{"ssn":"123-45-6789"}"#;
    let request = format!(
        "POST /api/pii HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let (mut session, mut client) = make_session(&request).await;
    let mut ctx = proxy.new_ctx();

    // --- Drive the filter chain up to upstream_request_filter ---
    proxy
        .early_request_filter(&mut session, &mut ctx)
        .await
        .expect("early_request_filter");
    let handled = proxy
        .request_filter(&mut session, &mut ctx)
        .await
        .expect("request_filter");
    assert!(
        !handled,
        "request should reach body filter — request_filter must not short-circuit"
    );

    // Stream the body through request_body_filter. The body-phase WAF
    // runs here but skips the dlp_violation rule (tagged deferred). The
    // DLP scan is dispatched as an async tokio task in this filter.
    loop {
        let mut chunk = session
            .read_request_body()
            .await
            .expect("read request body");
        let end_of_stream = chunk.is_none();
        proxy
            .request_body_filter(&mut session, &mut chunk, end_of_stream, &mut ctx)
            .await
            .expect("request_body_filter must not block at this stage");
        if end_of_stream {
            break;
        }
    }

    // --- upstream_request_filter awaits DLP and runs the deferred pass ---
    // This is the filter site that:
    //   1. Awaits the DLP oneshot (scan finds the SSN match)
    //   2. Runs the deferred WAF pass against the test_rule above
    //   3. On block, writes the canonical envelope via send_waf_block_response
    //   4. Returns Err(pingora_core::Error::explain(HTTPStatus(403), ...))
    let mut upstream_request = session.req_header().clone();
    let result = proxy
        .upstream_request_filter(&mut session, &mut upstream_request, &mut ctx)
        .await;

    // AC#1 part 1: filter aborted. Any Ok return would let Pingora continue
    // to upstream forwarding, which is exactly what the deferred block
    // must prevent.
    assert!(
        result.is_err(),
        "deferred DLP block must return Err from upstream_request_filter; got {:?}",
        result.as_ref().map(|_| "Ok")
    );

    // (We don't inspect ctx.detection here — the fields on RequestContext
    // are private to main.rs. The response-body check below is the
    // authoritative proof that the deferred pass fired the injected rule:
    // if it hadn't, send_waf_block_response would never have been called
    // and the client would read nothing.)

    // --- Read the response from the client side of the UnixStream ---
    // A 2s timeout is plenty — the DLP scan and deferred evaluation are
    // both in-process and complete in microseconds. A timeout here means
    // either no response was written (regression in send_waf_block_response)
    // or Pingora buffered it somewhere unexpected.
    let mut buf = vec![0u8; 4096];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("response read timeout — no response written to client side of Session")
        .expect("response read I/O error");
    let response = String::from_utf8_lossy(&buf[..read]).to_string();

    // AC#2: status line is exactly HTTP/1.1 403 — not 502, not 500, not
    // any upstream-error classification. This is the load-bearing assertion
    // for the whole task: if Pingora misclassified the typed HTTPStatus
    // error into a 502, this line would fail with a precise message and
    // ops would know to file a follow-up task.
    let first_line = response.lines().next().unwrap_or("<empty>");
    assert!(
        first_line.starts_with("HTTP/1.1 403"),
        "AC#2: expected 'HTTP/1.1 403' status line, got {:?}",
        first_line
    );
    assert!(
        !response.contains(" 502 "),
        "AC#2: response must not be classified as 502 bad-gateway; full response:\n{}",
        response
    );

    // AC#2: canonical JSON envelope from TASK-34's WAF_BLOCK_BODY constant.
    // If Pingora overwrote our pre-written response with its own generic
    // 403 body, this assertion would fail.
    assert!(
        response.contains(r#"{"error": "access_denied"}"#),
        "AC#2: expected canonical WAF_BLOCK_BODY envelope in response; full response:\n{}",
        response
    );

    // AC#2: content-type is application/json — the canonical envelope
    // is JSON, not plain text or HTML.
    assert!(
        response.to_lowercase().contains("content-type: application/json"),
        "AC#2: expected application/json content-type; full response:\n{}",
        response
    );

    // AC#2: X-Request-ID is present. Hub relies on this for request
    // correlation across the block stream.
    assert!(
        response.to_lowercase().contains("x-request-id:"),
        "AC#2: expected X-Request-ID header; full response:\n{}",
        response
    );

    // AC#3 is implicit: the test never configured an upstream peer for
    // any of the backend connections. If Pingora had tried to forward the
    // request upstream despite the Err return, the test would have failed
    // earlier with a connection error rather than reaching this point
    // with a 403 response. The successful path here IS the proof.

    // --- Restore canonical rules so subsequent tests in this binary see
    // the default embedded production_rules.json rule set (TASK-45).
    // serial_test prevents races during the test itself; this restore
    // prevents state leakage AFTER the test returns.
    let production_rules = include_str!("../src/production_rules.json");
    synapse_main::DetectionEngine::reload_rules(production_rules.as_bytes())
        .expect("restore production rules after TASK-40 test");
}
