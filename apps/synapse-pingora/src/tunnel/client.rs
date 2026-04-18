//! WebSocket client for Signal Horizon tunnel communication.

use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use subtle::ConstantTimeEq;
use sysinfo::System;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::config::TunnelConfig;
use super::error::TunnelError;
use super::types::{
    ConnectionState, LegacyTunnelMessage, TunnelAuthMessage, TunnelAuthMetadata, TunnelAuthPayload,
    TunnelChannel, TunnelEnvelope,
};
use crate::metrics::MetricsRegistry;

const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 256;
const LOGS_CHANNEL_BUFFER_SIZE: usize = 2048;
const CONTROL_CHANNEL_BUFFER_SIZE: usize = 1024;
const OUTBOUND_BUFFER_SIZE: usize = 1024;
const AUTH_TIMESTAMP_MAX_SKEW_MS: i64 = 5 * 60 * 1000;
const SHUTDOWN_TIMEOUT_MS: u64 = 5_000;
const MAX_RECONNECT_DELAY_MS: u64 = 300_000;
const OPEN_MIN_BACKOFF_MS: u64 = 5_000;
const OPEN_MAX_BACKOFF_MS: u64 = 60_000;
const HALF_OPEN_INTERVAL_MS: u64 = 60_000;
const HALF_OPEN_AUTH_TIMEOUT_MULTIPLIER: u64 = 2;
const MIN_HEARTBEAT_TIMEOUT_MS: u64 = 3_000;
const MAX_HEARTBEAT_BACKOFF_EXP: u32 = 4;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreakerState {
    fn as_u32(self) -> u32 {
        match self {
            CircuitBreakerState::Closed => 0,
            CircuitBreakerState::Open => 1,
            CircuitBreakerState::HalfOpen => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            CircuitBreakerState::Closed => "closed",
            CircuitBreakerState::Open => "open",
            CircuitBreakerState::HalfOpen => "half-open",
        }
    }
}

struct InternalStats {
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    heartbeats_sent: AtomicU64,
    heartbeat_timeouts: AtomicU64,
    heartbeat_rtt_ms: AtomicU64,
    reconnect_attempts: AtomicU32,
    circuit_breaker_state: AtomicU32,
}

/// Client statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelClientStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub heartbeats_sent: u64,
    pub heartbeat_timeouts: u64,
    pub heartbeat_rtt_ms: u64,
    pub reconnect_attempts: u32,
    pub circuit_breaker_state: u32,
}

impl From<&InternalStats> for TunnelClientStats {
    fn from(stats: &InternalStats) -> Self {
        Self {
            messages_sent: stats.messages_sent.load(Ordering::Relaxed),
            messages_received: stats.messages_received.load(Ordering::Relaxed),
            heartbeats_sent: stats.heartbeats_sent.load(Ordering::Relaxed),
            heartbeat_timeouts: stats.heartbeat_timeouts.load(Ordering::Relaxed),
            heartbeat_rtt_ms: stats.heartbeat_rtt_ms.load(Ordering::Relaxed),
            reconnect_attempts: stats.reconnect_attempts.load(Ordering::Relaxed),
            circuit_breaker_state: stats.circuit_breaker_state.load(Ordering::Relaxed),
        }
    }
}

struct ChannelQueue {
    inbound_tx: mpsc::Sender<TunnelEnvelope>,
    inbound_rx: Mutex<Option<mpsc::Receiver<TunnelEnvelope>>>,
    broadcast_tx: broadcast::Sender<TunnelEnvelope>,
    buffer_size: usize,
}

struct TunnelRouter {
    channels: HashMap<TunnelChannel, ChannelQueue>,
    legacy: broadcast::Sender<LegacyTunnelMessage>,
    started: AtomicBool,
    metrics: Arc<MetricsRegistry>,
}

impl TunnelRouter {
    fn new(metrics: Arc<MetricsRegistry>) -> Self {
        let mut channels = HashMap::new();
        for channel in TunnelChannel::ALL {
            let buffer_size = channel_buffer_size(channel);
            let (inbound_tx, inbound_rx) = mpsc::channel(buffer_size);
            let (broadcast_tx, _) = broadcast::channel(buffer_size);
            channels.insert(
                channel,
                ChannelQueue {
                    inbound_tx,
                    inbound_rx: Mutex::new(Some(inbound_rx)),
                    broadcast_tx,
                    buffer_size,
                },
            );
        }

        let (legacy, _) = broadcast::channel(DEFAULT_CHANNEL_BUFFER_SIZE);

        Self {
            channels,
            legacy,
            started: AtomicBool::new(false),
            metrics,
        }
    }

    fn start(&self) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }

        for (channel, queue) in &self.channels {
            let mut guard = queue
                .inbound_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(mut inbound_rx) = guard.take() else {
                continue;
            };
            let broadcast_tx = queue.broadcast_tx.clone();
            let channel = *channel;

            tokio::spawn(async move {
                while let Some(message) = inbound_rx.recv().await {
                    let _ = broadcast_tx.send(message);
                }
                debug!("Tunnel channel forwarder stopped for {:?}", channel);
            });
        }
    }

    fn subscribe_channel(&self, channel: TunnelChannel) -> broadcast::Receiver<TunnelEnvelope> {
        self.channels
            .get(&channel)
            .expect("channel sender missing")
            .broadcast_tx
            .subscribe()
    }

    fn subscribe_legacy(&self) -> broadcast::Receiver<LegacyTunnelMessage> {
        self.legacy.subscribe()
    }

    async fn publish_channel(&self, channel: TunnelChannel, message: TunnelEnvelope) {
        let Some(queue) = self.channels.get(&channel) else {
            return;
        };

        match queue.inbound_tx.try_send(message) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(message)) => {
                warn!(
                    "Tunnel channel {:?} buffer full ({}); applying backpressure",
                    channel, queue.buffer_size
                );
                self.metrics
                    .tunnel_metrics()
                    .record_channel_overflow(channel);
                if let Err(err) = queue.inbound_tx.send(message).await {
                    warn!(
                        "Tunnel channel {:?} closed while applying backpressure: {}",
                        channel, err
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("Tunnel channel {:?} closed; dropping message", channel);
            }
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
    shutdown_tx: broadcast::Sender<()>,
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

    /// Subscribe to the shutdown signal.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Send a JSON message to the hub.
    pub async fn send_json(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        self.sender
            .send(value)
            .await
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Send a JSON message to the hub from a blocking context with backpressure.
    pub fn send_json_sync(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        self.sender
            .blocking_send(value)
            .map_err(|e| TunnelError::SendFailed(e.to_string()))
    }

    /// Send a JSON message to the hub from a blocking context (legacy/non-blocking).
    /// WARNING: Spawns a task if in async context, potentially unbounded.
    pub fn send_json_blocking(&self, value: serde_json::Value) -> Result<(), TunnelError> {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let sender = self.sender.clone();
            handle.spawn(async move {
                if let Err(err) = sender.send(value).await {
                    warn!("Failed to send tunnel message: {}", err);
                }
            });
            Ok(())
        } else {
            self.sender
                .blocking_send(value)
                .map_err(|e| TunnelError::SendFailed(e.to_string()))
        }
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
    state_tx: watch::Sender<ConnectionState>,
    state_rx: watch::Receiver<ConnectionState>,
    router: Arc<TunnelRouter>,
    stats: Arc<InternalStats>,
    metrics: Arc<MetricsRegistry>,
    outbound_tx: Option<mpsc::Sender<serde_json::Value>>,
    shutdown_tx: Option<broadcast::Sender<()>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TunnelClient {
    /// Create a new tunnel client.
    pub fn new(config: TunnelConfig, metrics: Arc<MetricsRegistry>) -> Self {
        let (state_tx, state_rx) = watch::channel(ConnectionState::Disconnected);
        Self {
            config,
            state_tx,
            state_rx,
            router: Arc::new(TunnelRouter::new(Arc::clone(&metrics))),
            stats: Arc::new(InternalStats {
                messages_sent: AtomicU64::new(0),
                messages_received: AtomicU64::new(0),
                heartbeats_sent: AtomicU64::new(0),
                heartbeat_timeouts: AtomicU64::new(0),
                heartbeat_rtt_ms: AtomicU64::new(0),
                reconnect_attempts: AtomicU32::new(0),
                circuit_breaker_state: AtomicU32::new(CircuitBreakerState::Closed.as_u32()),
            }),
            metrics,
            outbound_tx: None,
            shutdown_tx: None,
            task_handle: None,
        }
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        *self.state_rx.borrow()
    }

    /// Subscribe to connection state updates.
    pub fn subscribe_state(&self) -> watch::Receiver<ConnectionState> {
        self.state_rx.clone()
    }

    /// Get client stats.
    pub fn stats(&self) -> TunnelClientStats {
        TunnelClientStats::from(self.stats.as_ref())
    }

    /// Create a handle for sending/receiving messages.
    pub fn handle(&self) -> Option<TunnelClientHandle> {
        let sender = self.outbound_tx.as_ref()?.clone();
        let shutdown_tx = self.shutdown_tx.as_ref()?.clone();
        Some(TunnelClientHandle {
            sender,
            router: Arc::clone(&self.router),
            shutdown_tx,
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
        let tx = self.outbound_tx.as_ref().ok_or(TunnelError::NotConnected)?;
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
        let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

        self.outbound_tx = Some(outbound_tx);
        self.shutdown_tx = Some(shutdown_tx.clone());

        let config = self.config.clone();
        let state_tx = self.state_tx.clone();
        let router = Arc::clone(&self.router);
        let stats = Arc::clone(&self.stats);
        let metrics = Arc::clone(&self.metrics);
        let shutdown_rx = shutdown_tx.subscribe();

        self.router.start();

        let handle = tokio::spawn(async move {
            connection_loop(
                config,
                state_tx,
                router,
                stats,
                metrics,
                outbound_rx,
                shutdown_rx,
            )
            .await;
        });
        self.task_handle = Some(handle);

        Ok(())
    }

    /// Stop the client.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        self.outbound_tx = None;
        if let Some(handle) = self.task_handle.take() {
            let mut handle = handle;
            match tokio::time::timeout(Duration::from_millis(SHUTDOWN_TIMEOUT_MS), &mut handle)
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!("Tunnel shutdown task failed: {}", err);
                }
                Err(_) => {
                    warn!("Tunnel shutdown timed out, aborting task");
                    handle.abort();
                    let _ = self.state_tx.send_replace(ConnectionState::Disconnected);
                }
            }
        }
        let _ = self.state_tx.send_replace(ConnectionState::Disconnected);
    }
}

async fn connection_loop(
    config: TunnelConfig,
    state_tx: watch::Sender<ConnectionState>,
    router: Arc<TunnelRouter>,
    stats: Arc<InternalStats>,
    metrics: Arc<MetricsRegistry>,
    mut outbound_rx: mpsc::Receiver<serde_json::Value>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let mut reconnect_delay = config.reconnect_delay_ms.max(1);
    let mut attempt = 0u32;
    let mut consecutive_failures = 0u32;
    let mut open_backoff_ms = OPEN_MIN_BACKOFF_MS;
    let mut circuit_state = CircuitBreakerState::Closed;

    stats
        .circuit_breaker_state
        .store(circuit_state.as_u32(), Ordering::Relaxed);

    loop {
        // Check for shutdown before each attempt
        if let Ok(()) | Err(broadcast::error::TryRecvError::Closed) = shutdown_rx.try_recv() {
            info!("Tunnel client shutdown requested");
            let _ = state_tx.send_replace(ConnectionState::Disconnected);
            return;
        }

        if config.max_reconnect_attempts > 0 && attempt >= config.max_reconnect_attempts {
            error!("Tunnel client max reconnect attempts reached");
            let _ = state_tx.send_replace(ConnectionState::Error);
            return;
        }

        metrics.tunnel_metrics().set_connected(false);
        let _ = state_tx.send_replace(ConnectionState::Connecting);
        info!("Connecting to Tunnel: {}", config.url);

        let mut shutdown_rx_run = shutdown_rx.resubscribe();
        let auth_timeout_override = if circuit_state == CircuitBreakerState::HalfOpen {
            Some(
                config
                    .auth_timeout_ms
                    .saturating_mul(HALF_OPEN_AUTH_TIMEOUT_MULTIPLIER),
            )
        } else {
            None
        };
        match connect_and_run(
            &config,
            &state_tx,
            &router,
            &stats,
            &metrics,
            &mut outbound_rx,
            &mut shutdown_rx_run,
            auth_timeout_override,
        )
        .await
        {
            ConnectionResult::Shutdown => {
                metrics.tunnel_metrics().set_connected(false);
                let _ = state_tx.send_replace(ConnectionState::Disconnected);
                return;
            }
            ConnectionResult::AuthFailed => {
                metrics.tunnel_metrics().set_connected(false);
                error!("Tunnel authentication failed, not retrying");
                let _ = state_tx.send_replace(ConnectionState::Error);
                return;
            }
            ConnectionResult::ConfigError => {
                metrics.tunnel_metrics().set_connected(false);
                error!("Tunnel configuration error, not retrying");
                let _ = state_tx.send_replace(ConnectionState::Error);
                return;
            }
            ConnectionResult::Disconnected { connected } => {
                if connected {
                    consecutive_failures = 0;
                    open_backoff_ms = OPEN_MIN_BACKOFF_MS;
                    update_circuit_state(&mut circuit_state, &stats, CircuitBreakerState::Closed);
                }

                attempt = attempt.saturating_add(1);
                consecutive_failures = consecutive_failures.saturating_add(1);
                stats.reconnect_attempts.store(attempt, Ordering::Relaxed);
                let _ = state_tx.send_replace(ConnectionState::Reconnecting);

                let was_half_open = circuit_state == CircuitBreakerState::HalfOpen;
                let was_closed = circuit_state == CircuitBreakerState::Closed;

                let mut delay_ms = reconnect_delay;
                if consecutive_failures >= 5 {
                    if was_closed {
                        open_backoff_ms = OPEN_MIN_BACKOFF_MS;
                    }
                    if was_half_open {
                        open_backoff_ms = HALF_OPEN_INTERVAL_MS;
                    }
                    update_circuit_state(&mut circuit_state, &stats, CircuitBreakerState::Open);
                    delay_ms = open_backoff_ms;
                    open_backoff_ms = (open_backoff_ms.saturating_mul(2))
                        .clamp(OPEN_MIN_BACKOFF_MS, OPEN_MAX_BACKOFF_MS);
                } else {
                    update_circuit_state(&mut circuit_state, &stats, CircuitBreakerState::Closed);
                    reconnect_delay =
                        (reconnect_delay.saturating_mul(2)).min(MAX_RECONNECT_DELAY_MS);
                }

                let delay_ms = apply_jitter(delay_ms.max(1));
                metrics.tunnel_metrics().record_reconnect_attempt(delay_ms);
                metrics.tunnel_metrics().set_connected(false);
                let delay = Duration::from_millis(delay_ms);
                warn!(
                    "Tunnel disconnected, reconnecting in {}ms (attempt {}, circuit {})",
                    delay.as_millis(),
                    attempt,
                    circuit_state.as_str()
                );

                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Tunnel client shutdown requested during backoff");
                        let _ = state_tx.send_replace(ConnectionState::Disconnected);
                        return;
                    }
                    _ = tokio::time::sleep(delay) => {}
                }

                if circuit_state == CircuitBreakerState::Open {
                    update_circuit_state(&mut circuit_state, &stats, CircuitBreakerState::HalfOpen);
                }
            }
        }
    }
}

enum ConnectionResult {
    Shutdown,
    AuthFailed,
    Disconnected { connected: bool },
    ConfigError,
}

fn apply_jitter(delay_ms: u64) -> u64 {
    if delay_ms == 0 {
        return 0;
    }
    let jitter = fastrand::u64(0..=delay_ms);
    delay_ms.saturating_add(jitter)
}

fn update_circuit_state(
    state: &mut CircuitBreakerState,
    stats: &InternalStats,
    next: CircuitBreakerState,
) {
    if *state != next {
        *state = next;
        stats
            .circuit_breaker_state
            .store(next.as_u32(), Ordering::Relaxed);
        info!("Tunnel circuit breaker -> {}", next.as_str());
    }
}

fn is_wss_url(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("wss://")
}

fn load_root_store() -> Result<RootCertStore, TunnelError> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Ok(path) = std::env::var("SYNAPSE_CA_BUNDLE") {
        let trimmed = path.trim().to_string();
        if trimmed.is_empty() {
            return Err(TunnelError::ConfigError(
                "SYNAPSE_CA_BUNDLE is set but empty".to_string(),
            ));
        }

        let file = File::open(&trimmed).map_err(|e| {
            TunnelError::ConfigError(format!(
                "failed to open SYNAPSE_CA_BUNDLE {}: {}",
                trimmed, e
            ))
        })?;
        let mut reader = BufReader::new(file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                TunnelError::ConfigError(format!(
                    "failed to read SYNAPSE_CA_BUNDLE {}: {}",
                    trimmed, e
                ))
            })?;
        if certs.is_empty() {
            return Err(TunnelError::ConfigError(format!(
                "SYNAPSE_CA_BUNDLE {} contained no certificates",
                trimmed
            )));
        }
        let (added, ignored) = root_store.add_parsable_certificates(certs);
        if added == 0 {
            return Err(TunnelError::ConfigError(format!(
                "SYNAPSE_CA_BUNDLE {} contained no valid certificates (ignored {})",
                trimmed, ignored
            )));
        }
        info!(
            "Loaded {} certificate(s) from SYNAPSE_CA_BUNDLE {}",
            added, trimmed
        );
    }

    if root_store.is_empty() {
        return Err(TunnelError::ConfigError(
            "no root certificates available for TLS validation".to_string(),
        ));
    }

    Ok(root_store)
}

fn build_tls_connector(url: &str) -> Result<Option<Connector>, TunnelError> {
    if !is_wss_url(url) {
        return Ok(None);
    }

    let root_store = load_root_store()?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(Some(Connector::Rustls(Arc::new(config))))
}

async fn connect_and_run(
    config: &TunnelConfig,
    state_tx: &watch::Sender<ConnectionState>,
    router: &Arc<TunnelRouter>,
    stats: &Arc<InternalStats>,
    metrics: &Arc<MetricsRegistry>,
    outbound_rx: &mut mpsc::Receiver<serde_json::Value>,
    shutdown_rx: &mut broadcast::Receiver<()>,
    auth_timeout_override: Option<u64>,
) -> ConnectionResult {
    let tls_connector = match build_tls_connector(&config.url) {
        Ok(connector) => connector,
        Err(e) => {
            error!("Tunnel TLS configuration error: {}", e);
            return ConnectionResult::ConfigError;
        }
    };

    let (ws_stream, response) = match tokio_tungstenite::connect_async_tls_with_config(
        &config.url,
        None,
        false,
        tls_connector,
    )
    .await
    {
        Ok((stream, response)) => (stream, response),
        Err(e) => {
            error!("Tunnel WebSocket connection failed: {}", e);
            return ConnectionResult::Disconnected { connected: false };
        }
    };

    log_rate_limit_headers(&response);

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    let _ = state_tx.send_replace(ConnectionState::Authenticating);

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

    if let Err(e) = ws_tx.send(Message::text(auth_json)).await {
        error!("Failed to send tunnel auth: {}", e);
        return ConnectionResult::Disconnected { connected: false };
    }

    let auth_timeout_ms = auth_timeout_override
        .unwrap_or(config.auth_timeout_ms)
        .max(1);
    let auth_timeout =
        tokio::time::timeout(Duration::from_millis(auth_timeout_ms), ws_rx.next()).await;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => {
            match parse_auth_response(&text, &config.sensor_id, &config.api_key) {
                Ok(true) => {
                    let _ = state_tx.send_replace(ConnectionState::Connected);
                    info!("Tunnel authenticated and connected");
                    metrics.tunnel_metrics().set_connected(true);
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
            return ConnectionResult::Disconnected { connected: false };
        }
        Ok(Some(Ok(_))) => {
            error!("Unexpected tunnel auth response");
            return ConnectionResult::AuthFailed;
        }
        Ok(Some(Err(e))) => {
            error!("Tunnel auth error: {}", e);
            return ConnectionResult::Disconnected { connected: false };
        }
        _ => {
            error!("Tunnel auth timeout");
            metrics.tunnel_metrics().record_auth_timeout();
            return ConnectionResult::Disconnected { connected: false };
        }
    }

    let authenticated = true;
    let heartbeat_interval_duration = Duration::from_millis(config.heartbeat_interval_ms.max(1));
    let mut heartbeat_interval = tokio::time::interval(heartbeat_interval_duration);
    let mut heartbeat_inflight_at: Option<tokio::time::Instant> = None;
    let mut heartbeat_misses: u32 = 0;
    let mut heartbeat_backoff_exp: u32 = 0;

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
                                if let Err(e) = ws_tx.send(Message::text(text)).await {
                                    error!("Tunnel send failed: {}", e);
                                    return ConnectionResult::Disconnected { connected: authenticated };
                                }
                                stats.messages_sent.fetch_add(1, Ordering::Relaxed);
                                metrics.tunnel_metrics().record_message_sent();
                            }
                            Err(e) => {
                                error!("Tunnel message serialization failed: {}", e);
                            }
                        }
                    }
                    None => {
                        warn!("Tunnel outbound channel closed");
                        return ConnectionResult::Disconnected { connected: authenticated };
                    }
                }
            }
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        stats.messages_received.fetch_add(1, Ordering::Relaxed);
                        metrics.tunnel_metrics().record_message_received();
                        handle_incoming_message(&text, router).await;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        let now = tokio::time::Instant::now();
                        if let Some(sent_at) = heartbeat_inflight_at.take() {
                            let rtt_ms = now.duration_since(sent_at).as_millis() as u64;
                            stats.heartbeat_rtt_ms.store(rtt_ms, Ordering::Relaxed);
                        }
                        heartbeat_misses = 0;
                        heartbeat_backoff_exp = 0;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        warn!("Tunnel WebSocket closed");
                        return ConnectionResult::Disconnected { connected: authenticated };
                    }
                    Some(Err(e)) => {
                        error!("Tunnel WebSocket error: {}", e);
                        return ConnectionResult::Disconnected { connected: authenticated };
                    }
                    _ => {}
                }
            }
            _ = heartbeat_interval.tick() => {
                let now = tokio::time::Instant::now();
                let observed_rtt_ms = stats.heartbeat_rtt_ms.load(Ordering::Relaxed);
                let base_timeout_ms = MIN_HEARTBEAT_TIMEOUT_MS.max(observed_rtt_ms);
                let backoff_factor =
                    1u64 << heartbeat_backoff_exp.min(MAX_HEARTBEAT_BACKOFF_EXP);
                let timeout_ms = base_timeout_ms.saturating_mul(backoff_factor);
                let timeout_duration = Duration::from_millis(timeout_ms);

                if let Some(sent_at) = heartbeat_inflight_at {
                    if now.duration_since(sent_at) > timeout_duration {
                        heartbeat_misses = heartbeat_misses.saturating_add(1);
                        stats.heartbeat_timeouts.fetch_add(1, Ordering::Relaxed);
                        metrics.tunnel_metrics().record_heartbeat_timeout();
                        warn!(
                            "Tunnel heartbeat timeout (miss {}, rtt={}ms, timeout={}ms, backoff=2^{})",
                            heartbeat_misses,
                            observed_rtt_ms,
                            timeout_ms,
                            heartbeat_backoff_exp
                        );
                        if heartbeat_misses >= 2 {
                            return ConnectionResult::Disconnected { connected: authenticated };
                        }
                        heartbeat_backoff_exp =
                            (heartbeat_backoff_exp.saturating_add(1)).min(MAX_HEARTBEAT_BACKOFF_EXP);
                        heartbeat_inflight_at = None;
                    }
                }

                let heartbeat = serde_json::json!({
                    "type": "heartbeat",
                    "payload": { "timestamp": chrono::Utc::now().to_rfc3339() },
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                if let Err(e) = ws_tx.send(Message::text(heartbeat.to_string())).await {
                    error!("Failed to send tunnel heartbeat: {}", e);
                    return ConnectionResult::Disconnected { connected: authenticated };
                }
                if heartbeat_inflight_at.is_none() {
                    if let Err(e) = ws_tx.send(Message::Ping(bytes::Bytes::new())).await {
                        error!("Failed to send tunnel ping: {}", e);
                        return ConnectionResult::Disconnected { connected: authenticated };
                    }
                    heartbeat_inflight_at = Some(now);
                    stats.heartbeats_sent.fetch_add(1, Ordering::Relaxed);
                    metrics.tunnel_metrics().record_heartbeat_sent();
                }
            }
        }
    }
}

fn build_metadata(config: &TunnelConfig) -> TunnelAuthMetadata {
    let hostname = System::host_name().unwrap_or_default();
    let platform = std::env::consts::OS.to_string();
    TunnelAuthMetadata {
        hostname: if hostname.is_empty() {
            None
        } else {
            Some(hostname)
        },
        version: Some(config.version.clone()),
        platform: Some(platform),
    }
}

fn parse_auth_response(
    text: &str,
    expected_sensor_id: &str,
    api_key: &str,
) -> Result<bool, TunnelError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| TunnelError::Deserialization(e.to_string()))?;
    let Some(msg_type) = value.get("type").and_then(|v| v.as_str()) else {
        return Err(TunnelError::Deserialization(
            "auth response missing type".to_string(),
        ));
    };

    match msg_type {
        "auth-success" => {
            let payload = value.get("payload").unwrap_or(&value);
            let sensor_id = payload
                .get("sensorId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    TunnelError::AuthFailed("auth-success missing sensorId".to_string())
                })?;
            if sensor_id != expected_sensor_id {
                return Err(TunnelError::AuthFailed(format!(
                    "auth-success sensorId mismatch: {}",
                    sensor_id
                )));
            }
            let tenant_id = payload
                .get("tenantId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    TunnelError::AuthFailed("auth-success missing tenantId".to_string())
                })?;
            let sensor_name = payload.get("sensorName").and_then(|v| v.as_str());
            let capabilities = parse_capabilities(payload.get("capabilities"));

            let session_id = value
                .get("sessionId")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    TunnelError::AuthFailed("auth-success missing sessionId".to_string())
                })?;
            if session_id.is_empty() || Uuid::parse_str(session_id).is_err() {
                return Err(TunnelError::AuthFailed(
                    "auth-success sessionId invalid".to_string(),
                ));
            }

            let timestamp_value = value.get("timestamp").ok_or_else(|| {
                TunnelError::AuthFailed("auth-success missing timestamp".to_string())
            })?;
            let timestamp_raw = timestamp_to_string(timestamp_value)?;
            let timestamp_ms = parse_timestamp_ms(&timestamp_raw)?;
            let now_ms = chrono::Utc::now().timestamp_millis();
            if (timestamp_ms - now_ms).abs() > AUTH_TIMESTAMP_MAX_SKEW_MS {
                return Err(TunnelError::AuthFailed(
                    "auth-success timestamp out of range".to_string(),
                ));
            }

            let signature = value
                .get("signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    TunnelError::AuthFailed("auth-success missing signature".to_string())
                })?;
            let signature_payload = build_auth_signature_payload(AuthSignaturePayload {
                sensor_id,
                tenant_id,
                session_id,
                timestamp: &timestamp_raw,
                sensor_name,
                capabilities: &capabilities,
            });
            let expected = compute_hmac_sha256(api_key, &signature_payload)?;
            if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
                return Err(TunnelError::AuthFailed(
                    "auth-success signature invalid".to_string(),
                ));
            }

            Ok(true)
        }
        "auth-error" | "auth-failed" => Ok(false),
        _ => Err(TunnelError::Deserialization(format!(
            "unexpected auth response type: {}",
            msg_type
        ))),
    }
}

struct AuthSignaturePayload<'a> {
    sensor_id: &'a str,
    tenant_id: &'a str,
    session_id: &'a str,
    timestamp: &'a str,
    sensor_name: Option<&'a str>,
    capabilities: &'a [String],
}

fn parse_capabilities(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(serde_json::Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str().map(|v| v.to_string()))
        .collect()
}

fn build_auth_signature_payload(payload: AuthSignaturePayload<'_>) -> String {
    let mut capabilities: Vec<String> = payload.capabilities.to_vec();
    capabilities.sort();
    let caps = capabilities.join(",");
    let sensor_name = payload.sensor_name.unwrap_or("");
    [
        "type=auth-success".to_string(),
        format!("sensorId={}", payload.sensor_id),
        format!("tenantId={}", payload.tenant_id),
        format!("sessionId={}", payload.session_id),
        format!("timestamp={}", payload.timestamp),
        format!("capabilities={}", caps),
        format!("sensorName={}", sensor_name),
    ]
    .join("\n")
}

fn compute_hmac_sha256(secret: &str, payload: &str) -> Result<String, TunnelError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| TunnelError::AuthFailed(format!("invalid hmac key: {}", e)))?;
    mac.update(payload.as_bytes());
    let result = mac.finalize().into_bytes();
    Ok(hex::encode(result))
}

fn timestamp_to_string(value: &serde_json::Value) -> Result<String, TunnelError> {
    match value {
        serde_json::Value::String(text) => Ok(text.clone()),
        serde_json::Value::Number(num) => Ok(num.to_string()),
        _ => Err(TunnelError::AuthFailed(
            "auth-success timestamp invalid".to_string(),
        )),
    }
}

fn parse_timestamp_ms(raw: &str) -> Result<i64, TunnelError> {
    if let Ok(value) = raw.parse::<i64>() {
        return Ok(value);
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.timestamp_millis())
        .map_err(|e| TunnelError::AuthFailed(format!("auth-success timestamp parse failed: {}", e)))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

fn log_rate_limit_headers<B>(response: &http::Response<B>) {
    let headers = response.headers();
    let Some(remaining) = headers
        .get("x-rate-limit-remaining")
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    if let Ok(remaining) = remaining.parse::<u64>() {
        if remaining == 0 {
            warn!("Tunnel handshake rate limit remaining is 0");
        }
    }
}

async fn handle_incoming_message(text: &str, router: &TunnelRouter) {
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
            router.publish_channel(channel, envelope).await;
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

fn channel_buffer_size(channel: TunnelChannel) -> usize {
    match channel {
        TunnelChannel::Logs => LOGS_CHANNEL_BUFFER_SIZE,
        TunnelChannel::Control => CONTROL_CHANNEL_BUFFER_SIZE,
        _ => DEFAULT_CHANNEL_BUFFER_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::Path;
    use tempfile::NamedTempFile;

    const TEST_API_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn clear(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    #[serial]
    fn tls_connector_uses_default_roots_without_bundle() {
        let _guard = EnvVarGuard::clear("SYNAPSE_CA_BUNDLE");
        let connector = build_tls_connector("wss://example.com/ws/tunnel/sensor").unwrap();
        assert!(connector.is_some());
    }

    #[test]
    #[serial]
    fn tls_connector_rejects_empty_bundle() {
        let temp = NamedTempFile::new().expect("create temp file");
        let _guard = EnvVarGuard::set("SYNAPSE_CA_BUNDLE", temp.path().to_string_lossy().as_ref());
        let result = build_tls_connector("wss://example.com/ws/tunnel/sensor");
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn tls_connector_accepts_valid_bundle() {
        let cert_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server.crt");
        let _guard = EnvVarGuard::set("SYNAPSE_CA_BUNDLE", cert_path.to_string_lossy().as_ref());
        let connector = build_tls_connector("wss://example.com/ws/tunnel/sensor").unwrap();
        assert!(connector.is_some());
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let base = 1_000u64;
        for _ in 0..25 {
            let jittered = apply_jitter(base);
            assert!(jittered >= base);
            assert!(jittered <= base.saturating_mul(2));
        }
    }

    fn build_auth_success(
        sensor_id: &str,
        tenant_id: &str,
        api_key: &str,
        session_id: &str,
        timestamp: &str,
        capabilities: &[&str],
    ) -> serde_json::Value {
        let payload = serde_json::json!({
            "sensorId": sensor_id,
            "tenantId": tenant_id,
            "capabilities": capabilities,
            "sensorName": "sensor-alpha",
        });
        let caps = capabilities
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        let signature_payload = build_auth_signature_payload(AuthSignaturePayload {
            sensor_id,
            tenant_id,
            session_id,
            timestamp,
            sensor_name: Some("sensor-alpha"),
            capabilities: &caps,
        });
        let signature = compute_hmac_sha256(api_key, &signature_payload).unwrap();
        serde_json::json!({
            "type": "auth-success",
            "payload": payload,
            "sessionId": session_id,
            "timestamp": timestamp,
            "signature": signature,
        })
    }

    #[test]
    fn auth_success_valid_signature() {
        let session_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let value = build_auth_success(
            "sensor-123",
            "tenant-1",
            TEST_API_KEY,
            &session_id,
            &timestamp,
            &["shell", "logs"],
        );
        let text = value.to_string();
        let result = parse_auth_response(&text, "sensor-123", TEST_API_KEY);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn auth_success_rejects_invalid_signature() {
        let session_id = Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let mut value = build_auth_success(
            "sensor-123",
            "tenant-1",
            TEST_API_KEY,
            &session_id,
            &timestamp,
            &["shell"],
        );
        value["signature"] = serde_json::Value::String("deadbeef".to_string());
        let text = value.to_string();
        let result = parse_auth_response(&text, "sensor-123", TEST_API_KEY);
        assert!(matches!(result, Err(TunnelError::AuthFailed(_))));
    }

    #[test]
    fn auth_success_rejects_expired_timestamp() {
        let session_id = Uuid::new_v4().to_string();
        let old_time = chrono::Utc::now() - chrono::Duration::minutes(10);
        let timestamp = old_time.to_rfc3339();
        let value = build_auth_success(
            "sensor-123",
            "tenant-1",
            TEST_API_KEY,
            &session_id,
            &timestamp,
            &["shell"],
        );
        let text = value.to_string();
        let result = parse_auth_response(&text, "sensor-123", TEST_API_KEY);
        assert!(matches!(result, Err(TunnelError::AuthFailed(_))));
    }

    #[test]
    fn auth_success_rejects_invalid_session_id() {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let value = build_auth_success(
            "sensor-123",
            "tenant-1",
            TEST_API_KEY,
            "not-a-uuid",
            &timestamp,
            &["shell"],
        );
        let text = value.to_string();
        let result = parse_auth_response(&text, "sensor-123", TEST_API_KEY);
        assert!(matches!(result, Err(TunnelError::AuthFailed(_))));
    }

    #[tokio::test]
    async fn logs_channel_delivers_without_drops_under_load() {
        let router = TunnelRouter::new(Arc::new(MetricsRegistry::new()));
        router.start();

        let mut rx = router.subscribe_channel(TunnelChannel::Logs);
        let total = 1000usize;

        let receiver = tokio::spawn(async move {
            let mut received = 0usize;
            while received < total {
                match rx.recv().await {
                    Ok(_envelope) => received += 1,
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        panic!("logs channel lagged by {} messages", count);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        panic!("logs channel closed early");
                    }
                }
            }
            received
        });

        for index in 0..total {
            let envelope = TunnelEnvelope {
                channel: TunnelChannel::Logs,
                session_id: None,
                sequence_id: Some(index as u64),
                timestamp: None,
                raw: serde_json::json!({
                    "channel": "logs",
                    "sequenceId": index,
                }),
            };
            router.publish_channel(TunnelChannel::Logs, envelope).await;
        }

        let received = tokio::time::timeout(Duration::from_secs(5), receiver)
            .await
            .expect("timeout waiting for logs channel")
            .expect("logs channel task failed");

        assert_eq!(received, total);
    }
}
