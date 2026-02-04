//! WebSocket client for Signal Horizon tunnel communication.

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use super::config::TunnelConfig;
use super::error::TunnelError;
use super::types::{
    ConnectionState, LegacyTunnelMessage, TunnelAuthMessage, TunnelAuthMetadata, TunnelAuthPayload,
    TunnelChannel, TunnelEnvelope,
};

const CHANNEL_BUFFER_SIZE: usize = 256;
const OUTBOUND_BUFFER_SIZE: usize = 1024;

struct InternalStats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    heartbeats_sent: AtomicU64,
    reconnect_attempts: AtomicU32,
}

/// Client statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelClientStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub heartbeats_sent: u64,
    pub reconnect_attempts: u32,
}

impl From<&InternalStats> for TunnelClientStats {
    fn from(stats: &InternalStats) -> Self {
        Self {
            messages_sent: stats.messages_sent.load(Ordering::Relaxed),
            messages_received: stats.messages_received.load(Ordering::Relaxed),
            heartbeats_sent: stats.heartbeats_sent.load(Ordering::Relaxed),
            reconnect_attempts: stats.reconnect_attempts.load(Ordering::Relaxed),
        }
    }
}

struct TunnelRouter {
    channels: HashMap<TunnelChannel, broadcast::Sender<TunnelEnvelope>>,
    legacy: broadcast::Sender<LegacyTunnelMessage>,
}

impl TunnelRouter {
    fn new() -> Self {
        let mut channels = HashMap::new();
        for channel in TunnelChannel::ALL {
            let (tx, _) = broadcast::channel(CHANNEL_BUFFER_SIZE);
            channels.insert(channel, tx);
        }

        let (legacy, _) = broadcast::channel(CHANNEL_BUFFER_SIZE);

        Self { channels, legacy }
    }

    fn subscribe_channel(&self, channel: TunnelChannel) -> broadcast::Receiver<TunnelEnvelope> {
        self.channels
            .get(&channel)
            .expect("channel sender missing")
            .subscribe()
    }

    fn subscribe_legacy(&self) -> broadcast::Receiver<LegacyTunnelMessage> {
        self.legacy.subscribe()
    }

    fn publish_channel(&self, channel: TunnelChannel, message: TunnelEnvelope) {
        if let Some(sender) = self.channels.get(&channel) {
            let _ = sender.send(message);
        }
    }

    fn publish_legacy(&self, message: LegacyTunnelMessage) {
        let _ = self.legacy.send(message);
    }
}

/// Handle for sending/receiving tunnel messages from other services.
#[derive(Clone)]
pub struct TunnelClientHandle {
    sender: mpsc::Sender<serde_json::Value>,
    router: Arc<TunnelRouter>,
}

impl TunnelClientHandle {
    /// Subscribe to a channel's incoming messages.
    pub fn subscribe_channel(&self, channel: TunnelChannel) -> broadcast::Receiver<TunnelEnvelope> {
        self.router.subscribe_channel(channel)
    }

    /// Subscribe to legacy tunnel messages.
    pub fn subscribe_legacy(&self) -> broadcast::Receiver<LegacyTunnelMessage> {
        self.router.subscribe_legacy()
    }

    /// Send a JSON message to the hub.
    pub async fn send_json(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        self.sender
            .send(value)
            .await
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Send a JSON message to the hub from a blocking context.
    pub fn send_json_blocking(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        self.sender
            .blocking_send(value)
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Try to send a JSON message without waiting (drops on backpressure).
    pub fn try_send_json(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        self.sender
            .try_send(value)
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Send a message to the hub with automatic serialization.
    pub async fn send<T: Serialize>(&self, message: T) -> Result<(), TunnelError> {
        let value = serde_json::to_value(message)?;
        self.send_json(value).await
    }
}

/// WebSocket client for Signal Horizon tunnel.
pub struct TunnelClient {
    config: TunnelConfig,
    state: Arc<RwLock<ConnectionState>>,
    router: Arc<TunnelRouter>,
    stats: Arc<InternalStats>,
    outbound_tx: Option<mpsc::Sender<serde_json::Value>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl TunnelClient {
    /// Create a new tunnel client.
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            router: Arc::new(TunnelRouter::new()),
            stats: Arc::new(InternalStats {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                heartbeats_sent: AtomicU64::new(0),
                reconnect_attempts: AtomicU32::new(0),
            }),
            outbound_tx: None,
            shutdown_tx: None,
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Get client stats.
    pub fn stats(&self) -> TunnelClientStats {
        TunnelClientStats::from(self.stats.as_ref())
    }

    /// Create a handle for sending/receiving messages.
    pub fn handle(&self) -> Option<TunnelClientHandle> {
        self.outbound_tx.as_ref().map(|sender| TunnelClientHandle {
            sender: sender.clone(),
            router: Arc::clone(&self.router),
        })
    }

    /// Subscribe to a channel's incoming messages.
    pub fn subscribe_channel(&self, channel: TunnelChannel) -> broadcast::Receiver<TunnelEnvelope> {
        self.router.subscribe_channel(channel)
    }

    /// Subscribe to legacy tunnel messages.
    pub fn subscribe_legacy(&self) -> broadcast::Receiver<LegacyTunnelMessage> {
        self.router.subscribe_legacy()
    }

    /// Send a message to the hub.
    pub async fn send_json(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        let tx = self
            .outbound_tx
            .as_ref()
            .ok_or(TunnelError::NotConnected)?;
        tx.send(value)
            .await
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Send a message to the hub with automatic serialization.
    pub async fn send<T: Serialize>(&self, message: T) -> Result<(), TunnelError> {
        let value = serde_json::to_value(message)?;
        self.send_json(value).await
    }

    /// Start the client.
    pub async fn start(&mut self) -> Result<(), TunnelError> {
        if !self.config.enabled {
            debug!("Tunnel client disabled, skipping start");
            return Ok(());
        }

        self.config.validate()?;

        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUFFER_SIZE);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        self.outbound_tx = Some(outbound_tx);
        self.shutdown_tx = Some(shutdown_tx);

        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let router = Arc::clone(&self.router);
        let stats = Arc::clone(&self.stats);

        tokio::spawn(async move {
            connection_loop(config, state, router, stats, outbound_rx, shutdown_rx).await;
        });

        Ok(())
    }

    /// Stop the client.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }
}

async fn connection_loop(
    config: TunnelConfig,
    state: Arc<RwLock<ConnectionState>>,
    router: Arc<TunnelRouter>,
    stats: Arc<InternalStats>,
    mut outbound_rx: mpsc::Receiver<serde_json::Value>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let mut reconnect_delay = config.reconnect_delay_ms;
    let mut attempt = 0u32;

    loop {
        if shutdown_rx.try_recv().is_ok() {
            info!("Tunnel client shutdown requested");
            *state.write() = ConnectionState::Disconnected;
            return;
        }

        if config.max_reconnect_attempts > 0 && attempt >= config.max_reconnect_attempts {
            error!("Tunnel client max reconnect attempts reached");
            *state.write() = ConnectionState::Error;
            return;
        }

        *state.write() = ConnectionState::Connecting;
        info!("Connecting to Tunnel: {}", config.url);

        match connect_and_run(
            &config,
            &state,
            &router,
            &stats,
            &mut outbound_rx,
            &mut shutdown_rx,
        )
        .await
        {
            ConnectionResult::Shutdown => {
                *state.write() = ConnectionState::Disconnected;
                return;
            }
            ConnectionResult::AuthFailed => {
                error!("Tunnel authentication failed, not retrying");
                *state.write() = ConnectionState::Error;
                return;
            }
            ConnectionResult::Disconnected => {
                attempt = attempt.saturating_add(1);
                stats.reconnect_attempts.store(attempt, Ordering::Relaxed);
                *state.write() = ConnectionState::Reconnecting;

                let delay = Duration::from_millis(reconnect_delay.max(1));
                warn!(
                    "Tunnel disconnected, reconnecting in {}ms (attempt {})",
                    delay.as_millis(),
                    attempt
                );
                tokio::time::sleep(delay).await;
                reconnect_delay = (reconnect_delay * 2).min(60_000);
            }
        }
    }
}

enum ConnectionResult {
    Shutdown,
    AuthFailed,
    Disconnected,
}

async fn connect_and_run(
    config: &TunnelConfig,
    state: &Arc<RwLock<ConnectionState>>,
    router: &Arc<TunnelRouter>,
    stats: &Arc<InternalStats>,
    outbound_rx: &mut mpsc::Receiver<serde_json::Value>,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> ConnectionResult {
    let ws_stream = match tokio_tungstenite::connect_async(&config.url).await {
        Ok((stream, _)) => stream,
        Err(e) => {
            error!("Tunnel WebSocket connection failed: {}", e);
            return ConnectionResult::Disconnected;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    *state.write() = ConnectionState::Authenticating;

    let auth_payload = TunnelAuthPayload {
        sensor_id: config.sensor_id.clone(),
        api_key: config.api_key.clone(),
        capabilities: if config.capabilities.is_empty() {
            None
        } else {
            Some(config.capabilities.clone())
        },
        metadata: Some(build_metadata(config)),
    };

    let auth_message = TunnelAuthMessage {
        message_type: "auth".to_string(),
        payload: auth_payload,
        timestamp: Some(chrono::Utc::now().to_rfc3339()),
    };

    let auth_json = match serde_json::to_string(&auth_message) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize tunnel auth: {}", e);
            return ConnectionResult::AuthFailed;
        }
    };

    if let Err(e) = ws_tx.send(Message::Text(auth_json.into())).await {
        error!("Failed to send tunnel auth: {}", e);
        return ConnectionResult::Disconnected;
    }

    let auth_timeout = tokio::time::timeout(
        Duration::from_millis(config.auth_timeout_ms.max(1)),
        ws_rx.next(),
    )
    .await;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => {
            match parse_auth_response(&text) {
                Ok(true) => {
                    *state.write() = ConnectionState::Connected;
                    info!("Tunnel authenticated and connected");
                }
                Ok(false) => {
                    error!("Tunnel auth failed");
                    return ConnectionResult::AuthFailed;
                }
                Err(e) => {
                    error!("Tunnel auth response error: {}", e);
                    return ConnectionResult::AuthFailed;
                }
            }
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
            warn!("Tunnel closed during auth");
            return ConnectionResult::Disconnected;
        }
        Ok(Some(Ok(_))) => {
            error!("Unexpected tunnel auth response");
            return ConnectionResult::AuthFailed;
        }
        Ok(Some(Err(e))) => {
            error!("Tunnel auth error: {}", e);
            return ConnectionResult::Disconnected;
        }
        _ => {
            error!("Tunnel auth timeout");
            return ConnectionResult::Disconnected;
        }
    }

    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_millis(config.heartbeat_interval_ms.max(1)));
    let mut last_heartbeat = Instant::now();

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Tunnel shutdown received");
                let _ = ws_tx.close().await;
                return ConnectionResult::Shutdown;
            }
            outbound = outbound_rx.recv() => {
                match outbound {
                    Some(payload) => {
                        match serde_json::to_string(&payload) {
                            Ok(text) => {
                                if let Err(e) = ws_tx.send(Message::Text(text.into())).await {
                                    error!("Tunnel send failed: {}", e);
                                    return ConnectionResult::Disconnected;
                                }
                                stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                error!("Tunnel message serialization failed: {}", e);
                            }
                        }
                    }
                    None => {
                        warn!("Tunnel outbound channel closed");
                        return ConnectionResult::Disconnected;
                    }
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        stats.messages_received.fetch_add(1, Ordering::Relaxed);
                        handle_incoming_message(&text, router);
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        warn!("Tunnel WebSocket closed");
                        return ConnectionResult::Disconnected;
                    }
                    Some(Err(e)) => {
                        error!("Tunnel WebSocket error: {}", e);
                        return ConnectionResult::Disconnected;
                    }
                    _ => {}
                }
            }
            _ = heartbeat_interval.tick() => {
                if last_heartbeat.elapsed().as_millis() < config.heartbeat_interval_ms as u128 {
                    continue;
                }
                last_heartbeat = Instant::now();
                let heartbeat = serde_json::json!({
                    "type": "heartbeat",
                    "payload": { "timestamp": chrono::Utc::now().to_rfc3339() },
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                if let Err(e) = ws_tx.send(Message::Text(heartbeat.to_string().into())).await {
                    error!("Failed to send tunnel heartbeat: {}", e);
                    return ConnectionResult::Disconnected;
                }
                stats.heartbeats_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn build_metadata(config: &TunnelConfig) -> TunnelAuthMetadata {
    let hostname = System::host_name().unwrap_or_default();
    let platform = std::env::consts::OS.to_string();
    TunnelAuthMetadata {
        hostname: if hostname.is_empty() { None } else { Some(hostname) },
        version: Some(config.version.clone()),
        platform: Some(platform),
    }
}

fn parse_auth_response(text: &str) -> Result<bool, TunnelError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| TunnelError::Deserialization(e.to_string()))?;
    let Some(msg_type) = value.get("type").and_then(|v| v.as_str()) else {
        return Err(TunnelError::Deserialization(
            "auth response missing type".to_string(),
        ));
    };

    match msg_type {
        "auth-success" => Ok(true),
        "auth-error" => Ok(false),
        _ => Err(TunnelError::Deserialization(format!(
            "unexpected auth response type: {}",
            msg_type
        ))),
    }
}

fn handle_incoming_message(text: &str, router: &TunnelRouter) {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            warn!("Failed to parse tunnel message: {}", e);
            return;
        }
    };

    if let Some(channel_value) = value.get("channel") {
        if let Ok(channel) = serde_json::from_value::<TunnelChannel>(channel_value.clone()) {
            let envelope = TunnelEnvelope {
                channel,
                session_id: value
                    .get("sessionId")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string()),
                sequence_id: value.get("sequenceId").and_then(|v| v.as_u64()),
                timestamp: value.get("timestamp").and_then(|v| v.as_i64()),
                raw: value,
            };
            router.publish_channel(channel, envelope);
            return;
        }
    }

    match serde_json::from_value::<LegacyTunnelMessage>(value.clone()) {
        Ok(legacy) => router.publish_legacy(legacy),
        Err(e) => {
            debug!("Ignoring unrecognized tunnel message: {}", e);
        }
    }
}
