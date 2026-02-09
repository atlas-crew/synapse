use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use uuid::Uuid;

use synapse_pingora::metrics::MetricsRegistry;
use synapse_pingora::tunnel::{ConnectionState, TunnelChannel, TunnelClient, TunnelConfig};

type HmacSha256 = Hmac<Sha256>;

#[derive(Parser, Debug)]
#[command(
    name = "tunnel-load-test",
    about = "Mock tunnel load test for synapse-pingora"
)]
struct Args {
    /// Number of concurrent tunnel clients
    #[arg(long, default_value_t = 50)]
    clients: usize,

    /// Duration of the load test in seconds
    #[arg(long, default_value_t = 60)]
    duration_secs: u64,

    /// Log messages per second per client
    #[arg(long, default_value_t = 1000)]
    logs_per_sec: u64,

    /// Shell messages per second per client
    #[arg(long, default_value_t = 100)]
    shell_per_sec: u64,

    /// Diagnostic requests per second per client
    #[arg(long, default_value_t = 50)]
    diag_per_sec: u64,

    /// Tunnel URL to use (omit to start a local mock server)
    #[arg(long)]
    url: Option<String>,

    /// API key used for auth (must be >= 32 chars)
    #[arg(long, default_value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    api_key: String,

    /// Heartbeat interval for clients (ms)
    #[arg(long, default_value_t = 30_000)]
    heartbeat_interval_ms: u64,

    /// Reconnect delay for clients (ms)
    #[arg(long, default_value_t = 5_000)]
    reconnect_delay_ms: u64,
}

struct MockServerStats {
    connections: AtomicUsize,
    messages: AtomicU64,
}

impl MockServerStats {
    fn new() -> Self {
        Self {
            connections: AtomicUsize::new(0),
            messages: AtomicU64::new(0),
        }
    }
}

struct LoadStats {
    logs_sent: AtomicU64,
    shell_sent: AtomicU64,
    diag_sent: AtomicU64,
    send_errors: AtomicU64,
}

impl LoadStats {
    fn new() -> Self {
        Self {
            logs_sent: AtomicU64::new(0),
            shell_sent: AtomicU64::new(0),
            diag_sent: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let (url, server_shutdown, server_stats) = if let Some(url) = args.url.clone() {
        (url, None, None)
    } else {
        let (url, shutdown, stats) = spawn_mock_server(args.api_key.clone()).await;
        (url, Some(shutdown), Some(stats))
    };

    let load_stats = Arc::new(LoadStats::new());
    let (stop_tx, _stop_rx) = broadcast::channel::<()>(1);
    let start = Instant::now();

    let mut client_handles = Vec::with_capacity(args.clients);
    for idx in 0..args.clients {
        let api_key = args.api_key.clone();
        let client_url = url.clone();
        let stats = Arc::clone(&load_stats);
        let mut stop_rx = stop_tx.subscribe();
        let cfg = ClientConfig {
            sensor_id: format!("sensor-load-{}", idx + 1),
            api_key,
            url: client_url,
            heartbeat_interval_ms: args.heartbeat_interval_ms,
            reconnect_delay_ms: args.reconnect_delay_ms,
            logs_per_sec: args.logs_per_sec,
            shell_per_sec: args.shell_per_sec,
            diag_per_sec: args.diag_per_sec,
        };

        let handle = tokio::spawn(async move {
            run_client(cfg, stats, &mut stop_rx).await;
        });
        client_handles.push(handle);
    }

    tokio::time::sleep(Duration::from_secs(args.duration_secs)).await;
    let _ = stop_tx.send(());

    for handle in client_handles {
        let _ = handle.await;
    }

    if let Some(shutdown) = server_shutdown {
        let _ = shutdown.send(());
    }

    let elapsed = start.elapsed().as_secs_f64().max(1.0);
    let logs = load_stats.logs_sent.load(Ordering::Relaxed);
    let shell = load_stats.shell_sent.load(Ordering::Relaxed);
    let diag = load_stats.diag_sent.load(Ordering::Relaxed);
    let errors = load_stats.send_errors.load(Ordering::Relaxed);

    println!("tunnel-load-test complete");
    println!("duration_secs={:.1}", elapsed);
    println!("logs_sent={} ({:.1}/sec)", logs, logs as f64 / elapsed);
    println!("shell_sent={} ({:.1}/sec)", shell, shell as f64 / elapsed);
    println!("diag_sent={} ({:.1}/sec)", diag, diag as f64 / elapsed);
    println!("send_errors={}", errors);

    if let Some(stats) = server_stats {
        println!(
            "server_connections={} server_messages={}",
            stats.connections.load(Ordering::Relaxed),
            stats.messages.load(Ordering::Relaxed)
        );
    }
}

struct ClientConfig {
    sensor_id: String,
    api_key: String,
    url: String,
    heartbeat_interval_ms: u64,
    reconnect_delay_ms: u64,
    logs_per_sec: u64,
    shell_per_sec: u64,
    diag_per_sec: u64,
}

async fn run_client(
    cfg: ClientConfig,
    stats: Arc<LoadStats>,
    stop_rx: &mut broadcast::Receiver<()>,
) {
    let mut config = TunnelConfig::default();
    config.enabled = true;
    config.url = cfg.url;
    config.api_key = cfg.api_key;
    config.sensor_id = cfg.sensor_id;
    config.heartbeat_interval_ms = cfg.heartbeat_interval_ms;
    config.reconnect_delay_ms = cfg.reconnect_delay_ms;
    config.max_reconnect_attempts = 0;

    let mut client = TunnelClient::new(config, Arc::new(MetricsRegistry::new()));
    if client.start().await.is_err() {
        stats.send_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if !wait_for_connected(&client, Duration::from_secs(5)).await {
        stats.send_errors.fetch_add(1, Ordering::Relaxed);
        let _ = client.stop().await;
        return;
    }

    let Some(handle) = client.handle() else {
        stats.send_errors.fetch_add(1, Ordering::Relaxed);
        let _ = client.stop().await;
        return;
    };

    let logs_session = Uuid::new_v4().to_string();
    let shell_session = Uuid::new_v4().to_string();
    let diag_session = Uuid::new_v4().to_string();

    let mut tasks = Vec::new();
    tasks.push(spawn_sender(
        handle.clone(),
        TunnelChannel::Logs,
        logs_session,
        cfg.logs_per_sec,
        stats.clone(),
    ));
    tasks.push(spawn_sender(
        handle.clone(),
        TunnelChannel::Shell,
        shell_session,
        cfg.shell_per_sec,
        stats.clone(),
    ));
    tasks.push(spawn_sender(
        handle.clone(),
        TunnelChannel::Diag,
        diag_session,
        cfg.diag_per_sec,
        stats.clone(),
    ));

    tokio::select! {
        _ = stop_rx.recv() => {},
    }

    for task in tasks {
        task.abort();
    }

    let _ = client.stop().await;
}

async fn wait_for_connected(client: &TunnelClient, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        if client.state() == ConnectionState::Connected {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        tokio::task::yield_now().await;
    }
}

fn spawn_sender(
    handle: synapse_pingora::tunnel::TunnelClientHandle,
    channel: TunnelChannel,
    session_id: String,
    rate_per_sec: u64,
    stats: Arc<LoadStats>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if rate_per_sec == 0 {
            return;
        }
        let tick_ms = 100u64;
        let ticks_per_sec = 1000 / tick_ms;
        let base = rate_per_sec / ticks_per_sec;
        let remainder = rate_per_sec % ticks_per_sec;
        let mut tick = 0u64;
        let mut sequence_id = 0u64;
        let mut interval = tokio::time::interval(Duration::from_millis(tick_ms));

        loop {
            interval.tick().await;
            let mut send_count = base;
            if remainder > 0 && (tick % ticks_per_sec) < remainder {
                send_count += 1;
            }

            for _ in 0..send_count {
                sequence_id = sequence_id.wrapping_add(1);
                let message = build_channel_message(
                    channel,
                    &session_id,
                    sequence_id,
                    chrono::Utc::now().timestamp_millis(),
                );
                if handle.send_json(message).await.is_err() {
                    stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                match channel {
                    TunnelChannel::Logs => stats.logs_sent.fetch_add(1, Ordering::Relaxed),
                    TunnelChannel::Shell => stats.shell_sent.fetch_add(1, Ordering::Relaxed),
                    TunnelChannel::Diag => stats.diag_sent.fetch_add(1, Ordering::Relaxed),
                    _ => stats.shell_sent.fetch_add(1, Ordering::Relaxed),
                };
            }

            tick = tick.wrapping_add(1);
        }
    })
}

fn build_channel_message(
    channel: TunnelChannel,
    session_id: &str,
    sequence_id: u64,
    timestamp_ms: i64,
) -> Value {
    match channel {
        TunnelChannel::Logs => serde_json::json!({
            "channel": "logs",
            "type": "entry",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": timestamp_ms,
            "level": "info",
            "message": "load-test log entry",
        }),
        TunnelChannel::Shell => serde_json::json!({
            "channel": "shell",
            "type": "data",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": timestamp_ms,
            "data": "d2hvYW1pCg==",
        }),
        TunnelChannel::Diag => serde_json::json!({
            "channel": "diag",
            "type": "request",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": timestamp_ms,
            "request": "health",
        }),
        _ => serde_json::json!({
            "channel": "control",
            "type": "noop",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": timestamp_ms,
        }),
    }
}

async fn spawn_mock_server(
    api_key: String,
) -> (String, broadcast::Sender<()>, Arc<MockServerStats>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let url = format!("ws://{}/ws/tunnel/sensor", addr);
    let stats = Arc::new(MockServerStats::new());
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);

    let stats_clone = Arc::clone(&stats);
    let api_key_clone = api_key.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { continue };
                    let stats = Arc::clone(&stats_clone);
                    let api_key = api_key_clone.clone();
                    tokio::spawn(async move {
                        if let Ok(ws) = accept_async(stream).await {
                            stats.connections.fetch_add(1, Ordering::Relaxed);
                            handle_mock_connection(ws, api_key, stats).await;
                        }
                    });
                }
            }
        }
    });

    (url, shutdown_tx, stats)
}

async fn handle_mock_connection(
    mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    api_key: String,
    stats: Arc<MockServerStats>,
) {
    let auth_msg = match ws.next().await {
        Some(Ok(Message::Text(text))) => text,
        _ => return,
    };

    let Some((sensor_id, capabilities, sensor_name)) = parse_auth(&auth_msg) else {
        return;
    };

    let session_id = Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let tenant_id = "tenant-load".to_string();
    let signature_payload = build_signature_payload(
        &sensor_id,
        &tenant_id,
        &session_id,
        &timestamp,
        &capabilities,
        sensor_name.as_deref(),
    );
    let signature = compute_hmac(&api_key, &signature_payload);

    let response = serde_json::json!({
        "type": "auth-success",
        "payload": {
            "sensorId": sensor_id,
            "tenantId": tenant_id,
            "capabilities": capabilities,
            "sensorName": sensor_name,
        },
        "sessionId": session_id,
        "timestamp": timestamp,
        "signature": signature,
    });

    let _ = ws.send(Message::Text(response.to_string())).await;

    while let Some(message) = ws.next().await {
        match message {
            Ok(Message::Ping(data)) => {
                let _ = ws.send(Message::Pong(data)).await;
            }
            Ok(Message::Text(_)) => {
                stats.messages.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Message::Binary(_)) => {
                stats.messages.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Message::Close(_)) | Err(_) => {
                break;
            }
            _ => {}
        }
    }
}

fn parse_auth(message: &str) -> Option<(String, Vec<String>, Option<String>)> {
    let value: Value = serde_json::from_str(message).ok()?;
    if value.get("type")?.as_str()? != "auth" {
        return None;
    }
    let payload = value.get("payload")?;
    let sensor_id = payload.get("sensorId")?.as_str()?.to_string();
    let _api_key = payload.get("apiKey")?.as_str()?;
    let capabilities = payload
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec!["dashboard".to_string()]);
    let sensor_name = payload
        .get("sensorName")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    Some((sensor_id, capabilities, sensor_name))
}

fn build_signature_payload(
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

fn compute_hmac(api_key: &str, payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(api_key.as_bytes()).expect("hmac key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}
