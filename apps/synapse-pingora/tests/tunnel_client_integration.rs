use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Notify};
use tokio_tungstenite::{
    accept_async,
    tungstenite::{protocol::frame::coding::CloseCode, protocol::CloseFrame, Message},
};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

use synapse_pingora::metrics::MetricsRegistry;
use synapse_pingora::tunnel::{
    ConnectionState, TunnelChannel, TunnelClient, TunnelConfig, TunnelError,
};

const TEST_API_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug)]
enum ServerEvent {
    Auth(Value),
    ClientMessage(Value),
}

struct MockServerState {
    connections: AtomicUsize,
    notify: Notify,
    events: mpsc::Sender<ServerEvent>,
}

impl MockServerState {
    fn new(events: mpsc::Sender<ServerEvent>) -> Self {
        Self {
            connections: AtomicUsize::new(0),
            notify: Notify::new(),
            events,
        }
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    async fn wait_for_connections(&self, target: usize, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.connection_count() >= target {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::task::yield_now().await;
        }
    }
}

struct MockServer {
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
    state: Arc<MockServerState>,
}

impl MockServer {
    fn url(&self) -> String {
        format!("ws://{}/ws/tunnel/sensor", self.addr)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.handle.await;
    }
}

async fn spawn_mock_server<H, Fut>(mut handler: H) -> (MockServer, mpsc::Receiver<ServerEvent>)
where
    H: FnMut(
            tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
            Arc<MockServerState>,
        ) -> Fut
        + Send
        + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (events_tx, events_rx) = mpsc::channel(32);
    let state = Arc::new(MockServerState::new(events_tx));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let state_clone = Arc::clone(&state);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                accept_result = listener.accept() => {
                    let (stream, _) = match accept_result {
                        Ok(result) => result,
                        Err(_) => break,
                    };
                    let ws_stream = match accept_async(stream).await {
                        Ok(ws) => ws,
                        Err(_) => continue,
                    };
                    state_clone.connections.fetch_add(1, Ordering::SeqCst);
                    state_clone.notify.notify_waiters();
                    handler(ws_stream, Arc::clone(&state_clone)).await;
                }
            }
        }
    });

    (
        MockServer {
            addr,
            shutdown: shutdown_tx,
            handle,
            state,
        },
        events_rx,
    )
}

fn build_config(url: String) -> TunnelConfig {
    TunnelConfig {
        enabled: true,
        url,
        api_key: TEST_API_KEY.to_string(),
        sensor_id: "sensor-123".to_string(),
        auth_timeout_ms: 80,
        reconnect_delay_ms: 100,
        max_reconnect_attempts: 3,
        ..TunnelConfig::default()
    }
}

fn build_client(config: TunnelConfig) -> TunnelClient {
    TunnelClient::new(config, Arc::new(MetricsRegistry::new()))
}

async fn wait_for_state(client: &TunnelClient, expected: ConnectionState) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if client.state() == expected {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_state_with_timeout(
    client: &TunnelClient,
    expected: ConnectionState,
    timeout: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if client.state() == expected {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_state_watch(
    rx: &mut watch::Receiver<ConnectionState>,
    expected: ConnectionState,
) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if *rx.borrow() == expected {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        let _ = tokio::time::timeout(remaining, rx.changed()).await;
    }
}

fn build_auth_signature_payload(
    sensor_id: &str,
    tenant_id: &str,
    session_id: &str,
    timestamp: &str,
    capabilities: &[String],
    sensor_name: Option<&str>,
) -> String {
    let mut caps = capabilities.to_vec();
    caps.sort();
    let caps = caps.join(",");
    let sensor_name = sensor_name.unwrap_or("");
    [
        "type=auth-success".to_string(),
        format!("sensorId={}", sensor_id),
        format!("tenantId={}", tenant_id),
        format!("sessionId={}", session_id),
        format!("timestamp={}", timestamp),
        format!("capabilities={}", caps),
        format!("sensorName={}", sensor_name),
    ]
    .join("\n")
}

fn sign_auth_success(api_key: &str, payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

fn auth_success_message(sensor_id: &str, tenant_id: &str, api_key: &str) -> String {
    let session_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let capabilities = vec!["shell".to_string(), "logs".to_string()];
    let signature_payload = build_auth_signature_payload(
        sensor_id,
        tenant_id,
        &session_id,
        &timestamp,
        &capabilities,
        Some("sensor-alpha"),
    );
    let signature = sign_auth_success(api_key, &signature_payload);
    let payload = serde_json::json!({
        "sensorId": sensor_id,
        "tenantId": tenant_id,
        "capabilities": capabilities,
        "sensorName": "sensor-alpha",
    });
    serde_json::json!({
        "type": "auth-success",
        "payload": payload,
        "sessionId": session_id,
        "timestamp": timestamp,
        "signature": signature,
    })
    .to_string()
}

async fn next_non_heartbeat(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
) -> Option<Value> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                let json: Value = serde_json::from_str(&text).unwrap();
                let is_heartbeat = json.get("type").and_then(Value::as_str) == Some("heartbeat");
                if is_heartbeat {
                    continue;
                }
                return Some(json);
            }
            Some(Ok(_)) => continue,
            _ => return None,
        }
    }
}

#[tokio::test]
async fn auth_success_connects() {
    let (server, mut events) = spawn_mock_server(|mut ws, state| async move {
        if let Some(Ok(Message::Text(text))) = ws.next().await {
            let json: Value = serde_json::from_str(&text).unwrap();
            let _ = state.events.send(ServerEvent::Auth(json)).await;
            let _ = ws
                .send(Message::Text(auth_success_message(
                    "sensor-123",
                    "tenant-1",
                    TEST_API_KEY,
                )))
                .await;
        }
        while ws.next().await.is_some() {}
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let event = events.recv().await.expect("auth event");
    match event {
        ServerEvent::Auth(payload) => {
            assert_eq!(payload.get("type").and_then(Value::as_str), Some("auth"));
        }
        _ => panic!("unexpected event"),
    }

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn auth_error_sets_error_state() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(r#"{"type":"auth-error"}"#.to_string()))
            .await;
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Error).await);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn concurrent_state_watchers_observe_connected() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        while ws.next().await.is_some() {}
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    let receivers: Vec<_> = (0..128).map(|_| client.subscribe_state()).collect();

    client.start().await.unwrap();

    let mut tasks = Vec::new();
    for mut rx in receivers {
        tasks.push(tokio::spawn(async move {
            wait_for_state_watch(&mut rx, ConnectionState::Connected).await
        }));
    }

    for task in tasks {
        assert!(task.await.expect("watch task"));
    }

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn auth_timeout_retries_then_errors() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = ws.close(None).await;
    })
    .await;

    let mut config = build_config(server.url());
    config.auth_timeout_ms = 20;
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 1;

    let mut client = build_client(config);
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Error).await);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn heartbeat_timeout_disconnects() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        tokio::time::sleep(Duration::from_secs(8)).await;
    })
    .await;

    let mut config = build_config(server.url());
    config.heartbeat_interval_ms = 1_000;
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 1;

    let mut client = build_client(config);
    client.start().await.unwrap();

    assert!(
        wait_for_state_with_timeout(&client, ConnectionState::Error, Duration::from_secs(10)).await
    );
    assert!(client.stats().heartbeat_timeouts > 0);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn heartbeat_allows_slow_pong() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        while let Some(msg) = ws.next().await {
            match msg {
                Ok(Message::Ping(data)) => {
                    tokio::time::sleep(Duration::from_millis(1_500)).await;
                    let _ = ws.send(Message::Pong(data)).await;
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    })
    .await;

    let mut config = build_config(server.url());
    config.heartbeat_interval_ms = 1_000;
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 1;

    let mut client = build_client(config);
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Connected).await);
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert_eq!(client.state(), ConnectionState::Connected);
    assert_eq!(client.stats().heartbeat_timeouts, 0);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn routes_channel_message() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let message = serde_json::json!({
            "channel": "shell",
            "sessionId": "session-1",
            "sequenceId": 42,
            "timestamp": 1_700_000_000,
            "payload": { "command": "whoami" }
        });
        let _ = ws.send(Message::Text(message.to_string())).await;
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    let mut rx = client.subscribe_channel(TunnelChannel::Shell);
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let envelope = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("timeout waiting for channel message")
        .expect("channel message");

    assert_eq!(envelope.channel, TunnelChannel::Shell);
    assert_eq!(envelope.session_id.as_deref(), Some("session-1"));
    assert_eq!(envelope.sequence_id, Some(42));

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn serializes_outbound_messages() {
    let (server, mut events) = spawn_mock_server(|mut ws, state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        if let Some(json) = next_non_heartbeat(&mut ws).await {
            let _ = state.events.send(ServerEvent::ClientMessage(json)).await;
        }
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let payload = serde_json::json!({ "type": "shell", "payload": { "cmd": "uptime" }});
    client.send_json(payload.clone()).await.unwrap();

    let event = tokio::time::timeout(Duration::from_millis(200), events.recv())
        .await
        .expect("timeout waiting for outbound")
        .expect("outbound event");
    match event {
        ServerEvent::ClientMessage(value) => {
            assert_eq!(value.get("type"), payload.get("type"));
        }
        _ => panic!("unexpected event"),
    }

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn malformed_json_is_ignored() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        let _ = ws.send(Message::Text("{\"type\":".to_string())).await;
        while ws.next().await.is_some() {}
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    let mut legacy_rx = client.subscribe_legacy();
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let result = tokio::time::timeout(Duration::from_millis(100), legacy_rx.recv()).await;
    assert!(result.is_err());
    assert_eq!(client.state(), ConnectionState::Connected);

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn send_while_disconnected_errors() {
    let client = build_client(build_config("ws://127.0.0.1:1".to_string()));
    let payload = serde_json::json!({ "type": "shell", "payload": { "cmd": "whoami" }});

    let err = client
        .send_json(payload)
        .await
        .expect_err("expected not connected error");
    assert!(matches!(err, TunnelError::NotConnected));
}

#[tokio::test]
async fn oversized_payload_disconnects() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        if let Some(Ok(Message::Text(text))) = ws.next().await {
            if text.len() > 1024 {
                let _ = ws
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::Size,
                        reason: "payload too large".into(),
                    })))
                    .await;
            }
        }
    })
    .await;

    let mut config = build_config(server.url());
    config.max_reconnect_attempts = 1;
    config.reconnect_delay_ms = 100;

    let mut client = build_client(config);
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let large_payload = serde_json::json!({
        "type": "shell",
        "payload": { "data": "a".repeat(2048) }
    });
    client.send_json(large_payload).await.unwrap();

    assert!(
        wait_for_state_with_timeout(&client, ConnectionState::Error, Duration::from_secs(2)).await
    );

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn concurrent_message_send_delivers_all() {
    let expected = 16usize;
    let (server, mut events) = spawn_mock_server(move |mut ws, state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        let mut received = 0usize;
        while received < expected {
            match ws.next().await {
                Some(Ok(Message::Text(text))) => {
                    let json: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let is_heartbeat =
                        json.get("type").and_then(Value::as_str) == Some("heartbeat");
                    if is_heartbeat {
                        continue;
                    }
                    let _ = state.events.send(ServerEvent::ClientMessage(json)).await;
                    received += 1;
                }
                _ => break,
            }
        }
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let handle = client.handle().expect("handle");
    let payload = serde_json::json!({ "type": "shell", "payload": { "cmd": "uptime" }});
    let mut tasks = Vec::new();

    for _ in 0..expected {
        let handle = handle.clone();
        let payload = payload.clone();
        tasks.push(tokio::spawn(async move { handle.send_json(payload).await }));
    }

    for task in tasks {
        assert!(task.await.expect("send task").is_ok());
    }

    let mut received = 0usize;
    while received < expected {
        let event = tokio::time::timeout(Duration::from_millis(500), events.recv())
            .await
            .expect("timeout waiting for outbound")
            .expect("outbound event");
        if matches!(event, ServerEvent::ClientMessage(_)) {
            received += 1;
        }
    }

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn close_normal_reconnects() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = ws
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "normal close".into(),
            })))
            .await;
    })
    .await;

    let mut config = build_config(server.url());
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 1;

    let mut client = build_client(config);
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);
    assert!(
        wait_for_state_with_timeout(
            &client,
            ConnectionState::Reconnecting,
            Duration::from_secs(2)
        )
        .await
    );

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn close_abnormal_reconnects() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Drop connection without close frame (abnormal close)
    })
    .await;

    let mut config = build_config(server.url());
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 1;

    let mut client = build_client(config);
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);
    assert!(
        wait_for_state_with_timeout(
            &client,
            ConnectionState::Reconnecting,
            Duration::from_secs(2)
        )
        .await
    );

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
#[ignore = "stress test: 100MB payload"]
async fn large_payload_stress() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        let _ = ws.next().await;
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();
    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    let payload = serde_json::json!({
        "type": "shell",
        "payload": { "data": "a".repeat(100 * 1024 * 1024) }
    });
    let _ = client.send_json(payload).await;

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn reconnect_backoff_increases() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        let _ = ws.close(None).await;
    })
    .await;

    let mut config = build_config(server.url());
    config.reconnect_delay_ms = 100;
    config.max_reconnect_attempts = 3;
    let base_delay = config.reconnect_delay_ms;
    let max_first_delay = base_delay.saturating_mul(2);
    let max_second_delay = base_delay.saturating_mul(4);

    let mut client = build_client(config);
    client.start().await.unwrap();

    assert!(
        server
            .state
            .wait_for_connections(1, Duration::from_millis(200))
            .await
    );
    assert!(wait_for_state(&client, ConnectionState::Reconnecting).await);

    tokio::time::advance(Duration::from_millis(base_delay.saturating_sub(1))).await;
    assert_eq!(server.state.connection_count(), 1);

    tokio::time::advance(Duration::from_millis(
        max_first_delay.saturating_sub(base_delay.saturating_sub(1)),
    ))
    .await;
    assert!(
        server
            .state
            .wait_for_connections(2, Duration::from_millis(200))
            .await
    );
    assert!(wait_for_state(&client, ConnectionState::Reconnecting).await);

    tokio::time::advance(Duration::from_millis(max_second_delay)).await;
    assert!(
        server
            .state
            .wait_for_connections(3, Duration::from_millis(200))
            .await
    );

    client.stop().await;
    server.shutdown().await;
}

#[tokio::test]
async fn graceful_shutdown_disconnects() {
    let (server, _events) = spawn_mock_server(|mut ws, _state| async move {
        let _ = ws.next().await;
        let _ = ws
            .send(Message::Text(auth_success_message(
                "sensor-123",
                "tenant-1",
                TEST_API_KEY,
            )))
            .await;
        while ws.next().await.is_some() {}
    })
    .await;

    let mut client = build_client(build_config(server.url()));
    client.start().await.unwrap();

    assert!(wait_for_state(&client, ConnectionState::Connected).await);

    client.stop().await;
    assert!(wait_for_state(&client, ConnectionState::Disconnected).await);

    server.shutdown().await;
}
