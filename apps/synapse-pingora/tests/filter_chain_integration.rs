use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use pingora_core::protocols::Stream;
use pingora_http::ResponseHeader;
use pingora_proxy::{ProxyHttp, Session};

#[path = "../src/main.rs"]
mod synapse_main;

use synapse_pingora::actor::{ActorConfig, ActorManager};
use synapse_pingora::block_log::BlockLog;
use synapse_pingora::crawler::CrawlerDetector;
use synapse_pingora::dlp::{DlpConfig, DlpScanner};
use synapse_pingora::entity::{EntityConfig, EntityManager};
use synapse_pingora::health::HealthChecker;
use synapse_pingora::intelligence::{SignalManager, SignalManagerConfig};
use synapse_pingora::metrics::MetricsRegistry;
use synapse_pingora::session::{SessionConfig, SessionManager};
use synapse_pingora::tarpit::TarpitConfig;
use synapse_pingora::telemetry::{TelemetryClient, TelemetryConfig};
use synapse_pingora::tls::TlsManager;
use synapse_pingora::trends::{TrendsConfig, TrendsManager};

fn build_proxy(per_ip_rps_limit: usize) -> synapse_main::SynapseProxy {
    let backends = vec![("127.0.0.1".to_string(), 8080)];
    let health_checker = Arc::new(HealthChecker::default());
    let metrics_registry = Arc::new(MetricsRegistry::new());
    let telemetry_client = Arc::new(TelemetryClient::new(TelemetryConfig {
        enabled: false,
        ..TelemetryConfig::default()
    }));
    let tls_manager = Arc::new(TlsManager::default());
    let entity_manager = Arc::new(EntityManager::new(EntityConfig::default()));
    let block_log = Arc::new(BlockLog::default());
    let actor_manager = Arc::new(ActorManager::new(ActorConfig::default()));
    let session_manager = Arc::new(SessionManager::new(SessionConfig::default()));
    let crawler_detector = Arc::new(CrawlerDetector::disabled());
    let trends_manager = Arc::new(TrendsManager::new(TrendsConfig::default()));
    let signal_manager = Arc::new(SignalManager::new(SignalManagerConfig::default()));

    synapse_main::SynapseProxy::with_health(
        backends,
        10_000,
        per_ip_rps_limit,
        health_checker,
        metrics_registry,
        telemetry_client,
        Vec::new(),
        tls_manager,
        TarpitConfig::default(),
        Arc::new(DlpScanner::new(DlpConfig::default())),
        entity_manager,
        block_log,
        actor_manager,
        session_manager,
        None,
        crawler_detector,
        None,
        trends_manager,
        signal_manager,
    )
}

async fn make_session(request: &str) -> (Session, tokio::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");

    let mut client = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect client");
    let (server_stream, _) = listener.accept().await.expect("accept");

    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    client.flush().await.expect("flush request");

    let stream = Stream::from(server_stream);
    let mut session = Session::new_h1(stream);
    let read = session.read_request().await.expect("read request");
    assert!(read, "request should be parsed");

    (session, client)
}

#[tokio::test(flavor = "current_thread")]
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

#[tokio::test(flavor = "current_thread")]
async fn test_rate_limit_short_circuits_before_waf() {
    let proxy = build_proxy(0);

    let request = "GET /search?q=' or '1'='1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let (mut session, mut client) = make_session(request).await;

    let headers = vec![("host".to_string(), "example.com".to_string())];
    let detection = synapse_main::DetectionEngine::analyze(
        "GET",
        "/search?q=' or '1'='1",
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
