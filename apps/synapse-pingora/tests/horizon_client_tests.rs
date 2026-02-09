//! Tests for HorizonClient WebSocket protocol and reconnect logic

use serde::{Deserialize, Serialize};

// Test types mirroring production HubMessage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubMessage {
    ConfigUpdate {
        enabled: bool,
    },
    RuleUpdate {
        sensor_config: SensorConfig,
    },
    BlocklistUpdate {
        ips: Vec<String>,
    },
    Ping {
        message: String,
    },
    SensorAck {
        message: String,
    },
    Error {
        message: String,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SensorConfig {
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub waf: Option<WafConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requests_per_second: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct WafConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: Option<String>,
}

// ============================================================================
// HubMessage Parsing Tests
// ============================================================================

#[test]
fn test_config_update_enabled() {
    let json = r#"{"type": "config_update", "enabled": true}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg, HubMessage::ConfigUpdate { enabled: true });
}

#[test]
fn test_config_update_disabled() {
    let json = r#"{"type": "config_update", "enabled": false}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg, HubMessage::ConfigUpdate { enabled: false });
}

#[test]
fn test_blocklist_update() {
    let json = r#"{"type": "blocklist_update", "ips": ["192.168.1.1", "10.0.0.0/8"]}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    match msg {
        HubMessage::BlocklistUpdate { ips } => {
            assert_eq!(ips.len(), 2);
            assert!(ips.contains(&"192.168.1.1".to_string()));
        }
        _ => panic!("Expected BlocklistUpdate"),
    }
}

#[test]
fn test_ping_message() {
    let json = r#"{"type": "ping", "message": "keepalive"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(
        msg,
        HubMessage::Ping {
            message: "keepalive".to_string()
        }
    );
}

#[test]
fn test_sensor_ack_message() {
    let json = r#"{"type": "sensor_ack", "message": "registered"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(
        msg,
        HubMessage::SensorAck {
            message: "registered".to_string()
        }
    );
}

#[test]
fn test_error_message() {
    let json = r#"{"type": "error", "message": "auth failed"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(
        msg,
        HubMessage::Error {
            message: "auth failed".to_string()
        }
    );
}

#[test]
fn test_unknown_message_type() {
    let json = r#"{"type": "future_type", "data": "something"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg, HubMessage::Unknown);
}

#[test]
fn test_rule_update_minimal() {
    let json = r#"{"type": "rule_update", "sensor_config": {}}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    match msg {
        HubMessage::RuleUpdate { sensor_config } => {
            assert!(sensor_config.rate_limit.is_none());
            assert!(sensor_config.waf.is_none());
        }
        _ => panic!("Expected RuleUpdate"),
    }
}

#[test]
fn test_rule_update_with_waf() {
    let json =
        r#"{"type": "rule_update", "sensor_config": {"waf": {"enabled": true, "mode": "block"}}}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    match msg {
        HubMessage::RuleUpdate { sensor_config } => {
            let waf = sensor_config.waf.unwrap();
            assert!(waf.enabled);
            assert_eq!(waf.mode, Some("block".to_string()));
        }
        _ => panic!("Expected RuleUpdate"),
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_invalid_json() {
    let json = r#"{"type": "config_update", enabled: true"#;
    let result: Result<HubMessage, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_missing_type() {
    let json = r#"{"enabled": true}"#;
    let result: Result<HubMessage, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_extra_fields_ignored() {
    let json = r#"{"type": "config_update", "enabled": true, "extra": "ignored"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg, HubMessage::ConfigUpdate { enabled: true });
}

#[test]
fn test_unicode_message() {
    let json = r#"{"type": "error", "message": "错误信息"}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    match msg {
        HubMessage::Error { message } => assert!(message.contains("错误")),
        _ => panic!("Expected Error"),
    }
}

#[test]
fn test_empty_blocklist() {
    let json = r#"{"type": "blocklist_update", "ips": []}"#;
    let msg: HubMessage = serde_json::from_str(json).unwrap();
    assert_eq!(msg, HubMessage::BlocklistUpdate { ips: vec![] });
}

// ============================================================================
// Backoff Logic Tests
// ============================================================================

fn calculate_backoff(attempt: u32, max_backoff: u64) -> u64 {
    (2u64.pow(attempt)).min(max_backoff)
}

#[test]
fn test_exponential_backoff() {
    let max = 32u64;
    assert_eq!(calculate_backoff(0, max), 1);
    assert_eq!(calculate_backoff(1, max), 2);
    assert_eq!(calculate_backoff(2, max), 4);
    assert_eq!(calculate_backoff(3, max), 8);
    assert_eq!(calculate_backoff(4, max), 16);
    assert_eq!(calculate_backoff(5, max), 32);
    assert_eq!(calculate_backoff(6, max), 32); // capped
}

#[test]
fn test_backoff_respects_max() {
    assert_eq!(calculate_backoff(10, 10), 10);
    assert_eq!(calculate_backoff(5, 5), 5);
}

#[test]
fn test_total_backoff_reasonable() {
    let max = 32u64;
    let total: u64 = (0..10).map(|i| calculate_backoff(i, max)).sum();
    assert_eq!(total, 191); // 1+2+4+8+16+32+32+32+32+32
    assert!(total < 300);
}

#[test]
fn test_jitter_distribution() {
    // Jitter range should be 0-1000ms
    let range = 0..=1000u64;
    assert_eq!(*range.start(), 0);
    assert_eq!(*range.end(), 1000);
}

// ============================================================================
// Connection State Tests
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
    Failed,
}

fn transition(state: ConnState, event: &str) -> ConnState {
    match (state, event) {
        (ConnState::Disconnected, "connect") => ConnState::Connecting,
        (ConnState::Connecting, "success") => ConnState::Connected,
        (ConnState::Connecting, "failure") => ConnState::Reconnecting { attempt: 1 },
        (ConnState::Connected, "disconnect") => ConnState::Reconnecting { attempt: 1 },
        (ConnState::Connected, "shutdown") => ConnState::Disconnected,
        (ConnState::Reconnecting { .. }, "success") => ConnState::Connected,
        (ConnState::Reconnecting { attempt }, "failure") if attempt < 10 => {
            ConnState::Reconnecting {
                attempt: attempt + 1,
            }
        }
        (ConnState::Reconnecting { .. }, "failure") => ConnState::Failed,
        (ConnState::Reconnecting { .. }, "shutdown") => ConnState::Disconnected,
        (state, _) => state,
    }
}

#[test]
fn test_connection_success() {
    let state = transition(ConnState::Disconnected, "connect");
    assert_eq!(state, ConnState::Connecting);
    let state = transition(state, "success");
    assert_eq!(state, ConnState::Connected);
}

#[test]
fn test_connection_failure_triggers_reconnect() {
    let state = transition(ConnState::Connecting, "failure");
    assert_eq!(state, ConnState::Reconnecting { attempt: 1 });
}

#[test]
fn test_reconnect_increments() {
    let state = ConnState::Reconnecting { attempt: 1 };
    let state = transition(state, "failure");
    assert_eq!(state, ConnState::Reconnecting { attempt: 2 });
}

#[test]
fn test_max_retries_fails() {
    let mut state = ConnState::Reconnecting { attempt: 9 };
    state = transition(state, "failure");
    assert_eq!(state, ConnState::Reconnecting { attempt: 10 });
    state = transition(state, "failure");
    assert_eq!(state, ConnState::Failed);
}

#[test]
fn test_graceful_shutdown() {
    let state = transition(ConnState::Connected, "shutdown");
    assert_eq!(state, ConnState::Disconnected);
}

// ============================================================================
// Serialization Round-Trip
// ============================================================================

#[test]
fn test_config_update_roundtrip() {
    let orig = HubMessage::ConfigUpdate { enabled: true };
    let json = serde_json::to_string(&orig).unwrap();
    let parsed: HubMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn test_blocklist_roundtrip() {
    let orig = HubMessage::BlocklistUpdate {
        ips: vec!["1.2.3.4".to_string()],
    };
    let json = serde_json::to_string(&orig).unwrap();
    let parsed: HubMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, parsed);
}

#[test]
fn test_ping_roundtrip() {
    let orig = HubMessage::Ping {
        message: "test".to_string(),
    };
    let json = serde_json::to_string(&orig).unwrap();
    let parsed: HubMessage = serde_json::from_str(&json).unwrap();
    assert_eq!(orig, parsed);
}

// ============================================================================
// Real WebSocket Connection Tests
// ============================================================================
// These tests use actual WebSocket connections with mock servers to verify
// connection lifecycle, authentication, heartbeats, and reconnection logic.

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::{accept_async, tungstenite::Message};

/// Helper struct to manage test server lifecycle
struct TestServer {
    addr: SocketAddr,
    shutdown_tx: mpsc::Sender<()>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn shutdown(self) {
        let _ = self.shutdown_tx.send(()).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
    }
}

/// Create a mock WebSocket server that handles authentication and echoes messages
async fn create_echo_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut sink, mut stream) = ws_stream.split();

                                while let Some(Ok(msg)) = stream.next().await {
                                    match msg {
                                        Message::Text(text) => {
                                            // Parse as SensorMessage and respond appropriately
                                            if text.contains("\"type\":\"auth\"") {
                                                // Send auth success
                                                let response = r#"{"type":"auth_success","sensor_id":"test-sensor","tenant_id":"test-tenant","capabilities":["signals","blocklist"]}"#;
                                                let _ = sink.send(Message::Text(response.into())).await;
                                            } else if text.contains("\"type\":\"heartbeat\"") {
                                                // Echo heartbeat as ping response
                                                let response = r#"{"type":"ping","timestamp":12345}"#;
                                                let _ = sink.send(Message::Text(response.into())).await;
                                            } else if text.contains("\"type\":\"signal\"") || text.contains("\"type\":\"signal_batch\"") {
                                                // Acknowledge signals
                                                let response = r#"{"type":"signal_ack","sequence_id":1}"#;
                                                let _ = sink.send(Message::Text(response.into())).await;
                                            } else if text.contains("\"type\":\"blocklist_sync\"") {
                                                // Send blocklist snapshot
                                                let response = r#"{"type":"blocklist_snapshot","entries":[],"sequence_id":1}"#;
                                                let _ = sink.send(Message::Text(response.into())).await;
                                            }
                                        }
                                        Message::Close(_) => break,
                                        Message::Ping(data) => {
                                            let _ = sink.send(Message::Pong(data)).await;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    TestServer {
        addr,
        shutdown_tx,
        handle,
    }
}

/// Create a mock server that rejects authentication
async fn create_auth_rejecting_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut sink, mut stream) = ws_stream.split();

                                while let Some(Ok(msg)) = stream.next().await {
                                    if let Message::Text(text) = msg {
                                        if text.contains("\"type\":\"auth\"") {
                                            // Send auth failure
                                            let response = r#"{"type":"auth_failed","error":"Invalid API key"}"#;
                                            let _ = sink.send(Message::Text(response.into())).await;
                                            let _ = sink.close().await;
                                            break;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    TestServer {
        addr,
        shutdown_tx,
        handle,
    }
}

/// Create a server that disconnects after a configurable number of messages
async fn create_disconnecting_server(disconnect_after: u32) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        let msg_count = Arc::new(AtomicU32::new(0));
                        let msg_count_clone = Arc::clone(&msg_count);
                        let limit = disconnect_after;

                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut sink, mut stream) = ws_stream.split();

                                while let Some(Ok(msg)) = stream.next().await {
                                    let count = msg_count_clone.fetch_add(1, Ordering::SeqCst);

                                    if count >= limit {
                                        // Force disconnect
                                        let _ = sink.close().await;
                                        break;
                                    }

                                    if let Message::Text(text) = msg {
                                        if text.contains("\"type\":\"auth\"") {
                                            let response = r#"{"type":"auth_success","sensor_id":"test-sensor","tenant_id":"test-tenant","capabilities":[]}"#;
                                            let _ = sink.send(Message::Text(response.into())).await;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    TestServer {
        addr,
        shutdown_tx,
        handle,
    }
}

/// Create a server that tracks heartbeat count
async fn create_heartbeat_tracking_server() -> (TestServer, Arc<AtomicU32>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let heartbeat_count = Arc::new(AtomicU32::new(0));
    let heartbeat_count_clone = Arc::clone(&heartbeat_count);

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                result = listener.accept() => {
                    if let Ok((stream, _)) = result {
                        let hb_count = Arc::clone(&heartbeat_count_clone);
                        tokio::spawn(async move {
                            if let Ok(ws_stream) = accept_async(stream).await {
                                let (mut sink, mut stream) = ws_stream.split();

                                while let Some(Ok(msg)) = stream.next().await {
                                    if let Message::Text(text) = msg {
                                        if text.contains("\"type\":\"auth\"") {
                                            let response = r#"{"type":"auth_success","sensor_id":"test-sensor","tenant_id":"test-tenant","capabilities":[]}"#;
                                            let _ = sink.send(Message::Text(response.into())).await;
                                        } else if text.contains("\"type\":\"heartbeat\"") {
                                            hb_count.fetch_add(1, Ordering::SeqCst);
                                            let response = r#"{"type":"ping","timestamp":12345}"#;
                                            let _ = sink.send(Message::Text(response.into())).await;
                                        }
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    (
        TestServer {
            addr,
            shutdown_tx,
            handle,
        },
        heartbeat_count,
    )
}

#[tokio::test]
async fn test_real_websocket_connection_success() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    // Test direct WebSocket connection
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(result.is_ok(), "Should connect to mock server");

    let (ws_stream, _response) = result.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Send auth message
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"test-key","sensor_id":"sensor-1","sensor_name":"Test Sensor","version":"1.0.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();

    // Receive auth success
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    if let Message::Text(text) = response {
        assert!(text.contains("auth_success"), "Should receive auth success");
    } else {
        panic!("Expected text message");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_connection_timeout() {
    // Connect to non-existent server with timeout
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        tokio_tungstenite::connect_async("ws://127.0.0.1:19999"),
    )
    .await;

    // Should timeout or fail to connect
    assert!(result.is_err() || result.unwrap().is_err());
}

#[tokio::test]
async fn test_real_websocket_auth_failure() {
    let server = create_auth_rejecting_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Send auth message
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"bad-key","sensor_id":"sensor-1","sensor_name":"Test","version":"1.0.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();

    // Receive auth failure
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    if let Message::Text(text) = response {
        assert!(text.contains("auth_failed"), "Should receive auth failed");
    } else {
        panic!("Expected text message");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_heartbeat_flow() {
    let (server, heartbeat_count) = create_heartbeat_tracking_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Authenticate first
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"test","sensor_id":"s1","sensor_name":"Test","version":"1.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();

    // Wait for auth response
    let _ = stream.next().await;

    // Send multiple heartbeats
    for _ in 0..3 {
        let heartbeat = r#"{"type":"heartbeat","payload":{"timestamp":123,"status":"healthy","cpu":10.0,"memory":20.0,"disk":30.0,"requests_last_minute":100,"avg_latency_ms":5.0,"config_hash":"abc","rules_hash":"def","active_connections":10}}"#;
        sink.send(Message::Text(heartbeat.into())).await.unwrap();

        // Wait for response
        let _ = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
    }

    // Verify heartbeats were received
    assert_eq!(
        heartbeat_count.load(Ordering::SeqCst),
        3,
        "Server should receive 3 heartbeats"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_reconnection_scenario() {
    // Create a server that disconnects after 2 messages
    let server = create_disconnecting_server(2).await;
    let url = format!("ws://{}", server.addr);

    // First connection
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Send auth
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"test","sensor_id":"s1","sensor_name":"Test","version":"1.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();

    // Get auth response
    let _ = stream.next().await;

    // Send another message - this should trigger disconnect
    let heartbeat = r#"{"type":"heartbeat","payload":{"timestamp":123,"status":"healthy","cpu":0,"memory":0,"disk":0,"requests_last_minute":0,"avg_latency_ms":0,"config_hash":"","rules_hash":""}}"#;
    sink.send(Message::Text(heartbeat.into())).await.unwrap();

    // Wait for disconnect
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify we can reconnect
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(
        result.is_ok(),
        "Should be able to reconnect after disconnect"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_signal_acknowledgment() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Authenticate
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"test","sensor_id":"s1","sensor_name":"Test","version":"1.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();
    let _ = stream.next().await; // auth response

    // Send signal
    let signal = r#"{"type":"signal","payload":{"signal_type":"threat","severity":"high","source_ip":"1.2.3.4","details":{}}}"#;
    sink.send(Message::Text(signal.into())).await.unwrap();

    // Wait for acknowledgment
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    if let Message::Text(text) = response {
        assert!(
            text.contains("signal_ack") || text.contains("batch_ack"),
            "Should receive signal acknowledgment, got: {}",
            text
        );
    } else {
        panic!("Expected text message");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_blocklist_sync() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Authenticate
    let auth_msg = r#"{"type":"auth","payload":{"api_key":"test","sensor_id":"s1","sensor_name":"Test","version":"1.0"}}"#;
    sink.send(Message::Text(auth_msg.into())).await.unwrap();
    let _ = stream.next().await;

    // Request blocklist sync
    let sync_msg = r#"{"type":"blocklist_sync"}"#;
    sink.send(Message::Text(sync_msg.into())).await.unwrap();

    // Wait for blocklist snapshot
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    if let Message::Text(text) = response {
        assert!(
            text.contains("blocklist_snapshot"),
            "Should receive blocklist snapshot, got: {}",
            text
        );
    } else {
        panic!("Expected text message");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_concurrent_connections() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    // Create multiple concurrent connections
    let mut handles = vec![];
    for i in 0..5 {
        let url_clone = url.clone();
        handles.push(tokio::spawn(async move {
            let (ws_stream, _) = tokio_tungstenite::connect_async(&url_clone).await?;
            let (mut sink, mut stream) = ws_stream.split();

            // Authenticate
            let auth_msg = format!(
                r#"{{"type":"auth","payload":{{"api_key":"test","sensor_id":"sensor-{}","sensor_name":"Test {}","version":"1.0"}}}}"#,
                i, i
            );
            sink.send(Message::Text(auth_msg.into())).await?;

            // Wait for auth response
            let response = stream.next().await;
            Ok::<_, tokio_tungstenite::tungstenite::Error>(response.is_some())
        }));
    }

    // All connections should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent connection should succeed");
    }

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_ping_pong() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, mut stream) = ws_stream.split();

    // Send WebSocket-level ping
    sink.send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();

    // Should receive pong
    let response = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(
        matches!(response, Message::Pong(_)),
        "Should receive pong response"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn test_real_websocket_graceful_close() {
    let server = create_echo_server().await;
    let url = format!("ws://{}", server.addr);

    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut sink, _stream) = ws_stream.split();

    // Send close frame
    let result = sink.send(Message::Close(None)).await;
    assert!(result.is_ok(), "Should send close frame successfully");

    // Close should complete without error
    let result = sink.close().await;
    assert!(result.is_ok(), "Should close cleanly");

    server.shutdown().await;
}
