//! WebSocket client for Signal Horizon Hub communication.

use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use super::blocklist::BlocklistCache;
use super::config::HorizonConfig;
use super::error::HorizonError;
use super::types::{
    AuthPayload, ConnectionState, HeartbeatPayload, HubMessage, SensorMessage, ThreatSignal,
};
use crate::config_manager::ConfigManager;

/// Metrics provider interface for heartbeat data.
pub trait MetricsProvider: Send + Sync {
    fn cpu_usage(&self) -> f64;
    fn memory_usage(&self) -> f64;
    fn disk_usage(&self) -> f64;
    fn requests_last_minute(&self) -> u64;
    fn avg_latency_ms(&self) -> f64;
    fn config_hash(&self) -> String;
    fn rules_hash(&self) -> String;
    fn active_connections(&self) -> Option<u32>;
}

/// No-op metrics provider for testing.
pub struct NoopMetricsProvider;

impl MetricsProvider for NoopMetricsProvider {
    fn cpu_usage(&self) -> f64 {
        0.0
    }
    fn memory_usage(&self) -> f64 {
        0.0
    }
    fn disk_usage(&self) -> f64 {
        0.0
    }
    fn requests_last_minute(&self) -> u64 {
        0
    }
    fn avg_latency_ms(&self) -> f64 {
        0.0
    }
    fn config_hash(&self) -> String {
        String::new()
    }
    fn rules_hash(&self) -> String {
        String::new()
    }
    fn active_connections(&self) -> Option<u32> {
        None
    }
}

/// Internal statistics tracking.
struct InternalStats {
    signals_sent: AtomicU64,
    signals_acked: AtomicU64,
    batches_sent: AtomicU64,
    heartbeats_sent: AtomicU64,
    heartbeat_failures: AtomicU64,
    reconnect_attempts: AtomicU32,
}

/// Client statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientStats {
    pub signals_sent: u64,
    pub signals_acked: u64,
    pub batches_sent: u64,
    pub heartbeats_sent: u64,
    pub heartbeat_failures: u64,
    pub reconnect_attempts: u32,
}

impl From<&InternalStats> for ClientStats {
    fn from(stats: &InternalStats) -> Self {
        Self {
            signals_sent: stats.signals_sent.load(Ordering::Relaxed),
            signals_acked: stats.signals_acked.load(Ordering::Relaxed),
            batches_sent: stats.batches_sent.load(Ordering::Relaxed),
            heartbeats_sent: stats.heartbeats_sent.load(Ordering::Relaxed),
            heartbeat_failures: stats.heartbeat_failures.load(Ordering::Relaxed),
            reconnect_attempts: stats.reconnect_attempts.load(Ordering::Relaxed),
        }
    }
}

/// WebSocket client for Signal Horizon Hub.
pub struct HorizonClient {
    config: HorizonConfig,
    state: RwLock<ConnectionState>,
    blocklist: Arc<BlocklistCache>,
    stats: Arc<InternalStats>,
    metrics_provider: Arc<dyn MetricsProvider>,
    signal_tx: Option<mpsc::Sender<ThreatSignal>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    tenant_id: RwLock<Option<String>>,
    capabilities: RwLock<Vec<String>>,
    config_manager: Option<Arc<ConfigManager>>,
}

impl HorizonClient {
    /// Create a new Horizon client.
    pub fn new(config: HorizonConfig) -> Self {
        Self {
            config,
            state: RwLock::new(ConnectionState::Disconnected),
            blocklist: Arc::new(BlocklistCache::new()),
            stats: Arc::new(InternalStats {
                signals_sent: AtomicU64::new(0),
                signals_acked: AtomicU64::new(0),
                batches_sent: AtomicU64::new(0),
                heartbeats_sent: AtomicU64::new(0),
                heartbeat_failures: AtomicU64::new(0),
                reconnect_attempts: AtomicU32::new(0),
            }),
            metrics_provider: Arc::new(NoopMetricsProvider),
            signal_tx: None,
            shutdown_tx: None,
            tenant_id: RwLock::new(None),
            capabilities: RwLock::new(Vec::new()),
            config_manager: None,
        }
    }

    /// Set the configuration manager.
    pub fn with_config_manager(mut self, config_manager: Arc<ConfigManager>) -> Self {
        self.config_manager = Some(config_manager);
        self
    }

    /// Create with a custom metrics provider.
    pub fn with_metrics_provider(
        config: HorizonConfig,
        metrics_provider: Arc<dyn MetricsProvider>,
    ) -> Self {
        let mut client = Self::new(config);
        client.metrics_provider = metrics_provider;
        client
    }

    /// Start the client.
    pub async fn start(&mut self) -> Result<(), HorizonError> {
        if !self.config.enabled {
            debug!("Horizon client disabled, skipping start");
            return Ok(());
        }

        self.config.validate()?;

        // Create channels
        let (signal_tx, signal_rx) = mpsc::channel::<ThreatSignal>(self.config.max_queued_signals);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        self.signal_tx = Some(signal_tx);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn connection task
        let config = self.config.clone();
        let state = Arc::new(RwLock::new(ConnectionState::Disconnected));
        let state_clone = Arc::clone(&state);
        let blocklist = Arc::clone(&self.blocklist);
        let stats = Arc::clone(&self.stats);
        let metrics_provider = Arc::clone(&self.metrics_provider);
        let tenant_id = Arc::new(RwLock::new(None::<String>));
        let tenant_id_clone = Arc::clone(&tenant_id);
        let capabilities = Arc::new(RwLock::new(Vec::<String>::new()));
        let capabilities_clone = Arc::clone(&capabilities);
        let config_manager = self.config_manager.clone();

        tokio::spawn(async move {
            connection_loop(
                config,
                state_clone,
                blocklist,
                stats,
                metrics_provider,
                signal_rx,
                shutdown_rx,
                tenant_id_clone,
                capabilities_clone,
                config_manager,
            )
            .await;
        });

        Ok(())
    }

    /// Stop the client.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        *self.state.write() = ConnectionState::Disconnected;
    }

    /// Report a threat signal.
    pub fn report_signal(&self, signal: ThreatSignal) {
        if let Some(ref tx) = self.signal_tx {
            if let Err(e) = tx.try_send(signal) {
                warn!("Failed to queue signal: {}", e);
            } else {
                self.stats.signals_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Flush pending signals (currently no-op, signals are sent immediately when batched).
    pub async fn flush_signals(&self) {
        // In a full implementation, this would force-flush the signal batch
    }

    /// Check if an IP is blocked.
    #[inline]
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.blocklist.is_ip_blocked(ip)
    }

    /// Check if a fingerprint is blocked.
    #[inline]
    pub fn is_fingerprint_blocked(&self, fingerprint: &str) -> bool {
        self.blocklist.is_fingerprint_blocked(fingerprint)
    }

    /// Get the current connection state.
    pub async fn connection_state(&self) -> ConnectionState {
        *self.state.read()
    }

    /// Check if connected.
    pub async fn is_connected(&self) -> bool {
        *self.state.read() == ConnectionState::Connected
    }

    /// Get the blocklist size.
    pub fn blocklist_size(&self) -> usize {
        self.blocklist.size()
    }

    /// Get the blocklist cache.
    pub fn blocklist(&self) -> &Arc<BlocklistCache> {
        &self.blocklist
    }

    /// Get statistics.
    pub fn stats(&self) -> ClientStats {
        ClientStats::from(self.stats.as_ref())
    }

    /// Get the tenant ID (if authenticated).
    pub async fn tenant_id(&self) -> Option<String> {
        self.tenant_id.read().clone()
    }

    /// Get capabilities (if authenticated).
    pub async fn capabilities(&self) -> Vec<String> {
        self.capabilities.read().clone()
    }
}

/// Connection loop with auto-reconnect.
async fn connection_loop(
    config: HorizonConfig,
    state: Arc<RwLock<ConnectionState>>,
    blocklist: Arc<BlocklistCache>,
    stats: Arc<InternalStats>,
    metrics_provider: Arc<dyn MetricsProvider>,
    mut signal_rx: mpsc::Receiver<ThreatSignal>,
    mut shutdown_rx: mpsc::Receiver<()>,
    tenant_id: Arc<RwLock<Option<String>>>,
    capabilities: Arc<RwLock<Vec<String>>>,
    config_manager: Option<Arc<ConfigManager>>,
) {
    let mut reconnect_delay = config.reconnect_delay_ms;
    let mut attempt = 0u32;

    loop {
        // Check for shutdown
        if shutdown_rx.try_recv().is_ok() {
            info!("Horizon client shutdown requested");
            *state.write() = ConnectionState::Disconnected;
            return;
        }

        // Check max reconnect attempts
        if config.max_reconnect_attempts > 0 && attempt >= config.max_reconnect_attempts {
            error!("Max reconnect attempts reached");
            *state.write() = ConnectionState::Error;
            return;
        }

        // Connect
        *state.write() = ConnectionState::Connecting;
        info!("Connecting to Hub: {}", config.hub_url);

        match connect_and_run(
            &config,
            &state,
            &blocklist,
            &stats,
            &metrics_provider,
            &mut signal_rx,
            &mut shutdown_rx,
            &tenant_id,
            &capabilities,
            &config_manager,
        )
        .await
        {
            ConnectionResult::Shutdown => {
                info!("Horizon client shutdown");
                *state.write() = ConnectionState::Disconnected;
                return;
            }
            ConnectionResult::AuthFailed => {
                error!("Authentication failed, not retrying");
                *state.write() = ConnectionState::Error;
                return;
            }
            ConnectionResult::Disconnected => {
                attempt += 1;
                stats.reconnect_attempts.store(attempt, Ordering::Relaxed);

                // Add random jitter (±25%) to prevent thundering herd on reconnect
                // This spreads out reconnection attempts when many clients disconnect simultaneously
                // Using fastrand for efficient non-cryptographic randomness
                let jitter_percent = fastrand::u32(0..50); // 0-50 maps to 0.75-1.25
                let jitter_factor = 0.75 + (jitter_percent as f64 / 100.0);
                let delay_with_jitter = (reconnect_delay as f64 * jitter_factor) as u64;

                warn!(
                    "Disconnected, reconnecting in {}ms (attempt {}, base {}ms)",
                    delay_with_jitter, attempt, reconnect_delay
                );
                *state.write() = ConnectionState::Reconnecting;

                tokio::time::sleep(Duration::from_millis(delay_with_jitter)).await;

                // Exponential backoff (max 60s)
                reconnect_delay = (reconnect_delay * 2).min(60_000);
            }
            ConnectionResult::Stopped => {
                *state.write() = ConnectionState::Disconnected;
                return;
            }
        }
    }
}

enum ConnectionResult {
    Shutdown,
    AuthFailed,
    Disconnected,
    Stopped,
}

async fn connect_and_run(
    config: &HorizonConfig,
    state: &Arc<RwLock<ConnectionState>>,
    blocklist: &Arc<BlocklistCache>,
    stats: &Arc<InternalStats>,
    metrics_provider: &Arc<dyn MetricsProvider>,
    signal_rx: &mut mpsc::Receiver<ThreatSignal>,
    shutdown_rx: &mut mpsc::Receiver<()>,
    tenant_id: &Arc<RwLock<Option<String>>>,
    capabilities: &Arc<RwLock<Vec<String>>>,
    config_manager: &Option<Arc<ConfigManager>>,
) -> ConnectionResult {
    // Connect WebSocket
    let ws_stream = match tokio_tungstenite::connect_async(&config.hub_url).await {
        Ok((stream, _)) => stream,
        Err(e) => {
            error!("WebSocket connection failed: {}", e);
            return ConnectionResult::Disconnected;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Send auth
    *state.write() = ConnectionState::Authenticating;
    let auth_msg = SensorMessage::Auth {
        payload: AuthPayload {
            api_key: config.api_key.clone(),
            sensor_id: config.sensor_id.clone(),
            sensor_name: config.sensor_name.clone(),
            version: config.version.clone(),
        },
    };

    if let Err(e) = ws_tx
        .send(Message::Text(auth_msg.to_json().unwrap().into()))
        .await
    {
        error!("Failed to send auth: {}", e);
        return ConnectionResult::Disconnected;
    }

    // Wait for auth response
    let auth_timeout = tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => {
            match HubMessage::from_json(&text) {
                Ok(HubMessage::AuthSuccess {
                    sensor_id: _,
                    tenant_id: tid,
                    capabilities: caps,
                }) => {
                    info!("Authenticated with Hub (tenant: {})", tid);
                    *tenant_id.write() = Some(tid);
                    *capabilities.write() = caps;
                    *state.write() = ConnectionState::Connected;

                    // Request initial blocklist
                    let _ = ws_tx
                        .send(Message::Text(
                            SensorMessage::BlocklistSync.to_json().unwrap().into(),
                        ))
                        .await;
                }
                Ok(HubMessage::AuthFailed { error }) => {
                    error!("Auth failed: {}", error);
                    return ConnectionResult::AuthFailed;
                }
                _ => {
                    error!("Unexpected auth response");
                    return ConnectionResult::Disconnected;
                }
            }
        }
        _ => {
            error!("Auth timeout or error");
            return ConnectionResult::Disconnected;
        }
    }

    // Main loop
    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_millis(config.heartbeat_interval_ms));
    let mut signal_batch: Vec<ThreatSignal> = Vec::with_capacity(config.signal_batch_size);
    let mut batch_timer = tokio::time::interval(Duration::from_millis(config.signal_batch_delay_ms));

    loop {
        tokio::select! {
            // Shutdown signal
            _ = shutdown_rx.recv() => {
                info!("Shutdown received");
                let _ = ws_tx.close().await;
                return ConnectionResult::Shutdown;
            }

            // Incoming signal to send
            signal = signal_rx.recv() => {
                match signal {
                    Some(sig) => {
                        signal_batch.push(sig);
                        if signal_batch.len() >= config.signal_batch_size {
                            if let Err(e) = send_batch(&mut ws_tx, &mut signal_batch, stats).await {
                                error!("Failed to send batch: {}", e);
                                return ConnectionResult::Disconnected;
                            }
                        }
                    }
                    None => {
                        return ConnectionResult::Stopped;
                    }
                }
            }

            // Batch timer
            _ = batch_timer.tick() => {
                if !signal_batch.is_empty() {
                    if let Err(e) = send_batch(&mut ws_tx, &mut signal_batch, stats).await {
                        error!("Failed to send batch: {}", e);
                        return ConnectionResult::Disconnected;
                    }
                }
            }

            // WebSocket message
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(hub_msg) = HubMessage::from_json(&text) {
                            handle_hub_message(hub_msg, blocklist, stats, config_manager, &mut ws_tx).await;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        warn!("WebSocket closed");
                        return ConnectionResult::Disconnected;
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        return ConnectionResult::Disconnected;
                    }
                    _ => {}
                }
            }

            // Heartbeat
            _ = heartbeat_interval.tick() => {
                let payload = HeartbeatPayload {
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    status: "healthy".to_string(),
                    cpu: metrics_provider.cpu_usage(),
                    memory: metrics_provider.memory_usage(),
                    disk: metrics_provider.disk_usage(),
                    requests_last_minute: metrics_provider.requests_last_minute(),
                    avg_latency_ms: metrics_provider.avg_latency_ms(),
                    config_hash: metrics_provider.config_hash(),
                    rules_hash: metrics_provider.rules_hash(),
                    active_connections: metrics_provider.active_connections(),
                    blocklist_size: Some(blocklist.size()),
                };

                let msg = SensorMessage::Heartbeat { payload };
                if let Err(e) = ws_tx.send(Message::Text(msg.to_json().unwrap().into())).await {
                    warn!("Failed to send heartbeat: {}", e);
                    stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                } else {
                    stats.heartbeats_sent.fetch_add(1, Ordering::Relaxed);
                    debug!("Sent heartbeat");
                }
            }
        }
    }
}

async fn send_batch<S>(
    ws_tx: &mut futures_util::stream::SplitSink<S, Message>,
    batch: &mut Vec<ThreatSignal>,
    stats: &Arc<InternalStats>,
) -> Result<(), HorizonError>
where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    if batch.is_empty() {
        return Ok(());
    }

    let signals = std::mem::take(batch);
    let count = signals.len();

    let msg = if count == 1 {
        SensorMessage::Signal {
            payload: signals.into_iter().next().unwrap(),
        }
    } else {
        SensorMessage::SignalBatch { payload: signals }
    };

    ws_tx
        .send(Message::Text(msg.to_json()?.into()))
        .await
        .map_err(|e| HorizonError::SendFailed(e.to_string()))?;

    stats.batches_sent.fetch_add(1, Ordering::Relaxed);
    debug!("Sent batch of {} signals", count);

    Ok(())
}

use super::types::CommandAckPayload;

async fn handle_hub_message<S>(
    msg: HubMessage,
    blocklist: &Arc<BlocklistCache>,
    stats: &Arc<InternalStats>,
    config_manager: &Option<Arc<ConfigManager>>,
    ws_tx: &mut futures_util::stream::SplitSink<S, Message>,
) where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    match msg {
        HubMessage::SignalAck { sequence_id: _ } => {
            stats.signals_acked.fetch_add(1, Ordering::Relaxed);
        }
        HubMessage::BatchAck {
            count,
            sequence_id: _,
        } => {
            stats
                .signals_acked
                .fetch_add(count as u64, Ordering::Relaxed);
            debug!("Batch of {} signals acknowledged", count);
        }
        HubMessage::Ping { timestamp: _ } => {
            // Handled by WebSocket ping/pong
        }
        HubMessage::BlocklistSnapshot {
            entries,
            sequence_id,
        } => {
            info!(
                "Received blocklist snapshot: {} entries (seq: {})",
                entries.len(),
                sequence_id
            );
            blocklist.load_snapshot(entries, sequence_id);
        }
        HubMessage::BlocklistUpdate {
            updates,
            sequence_id,
        } => {
            debug!(
                "Received blocklist update: {} changes (seq: {})",
                updates.len(),
                sequence_id
            );
            blocklist.apply_updates(updates, sequence_id);
        }
        HubMessage::Error { error, code } => {
            warn!("Hub error: {} (code: {:?})", error, code);
        }
        HubMessage::ConfigUpdate { config: _, version } => {
            info!("Received config update (legacy direct) version: {}", version);
            // ... (legacy handling if needed, but PushConfig handles it better)
        }
        HubMessage::PushConfig { command_id, payload } => {
            info!("Received PushConfig command (id: {}, version: {})", command_id, payload.version);
            
            let result = if let Some(manager) = config_manager {
                match serde_json::from_value::<crate::config::ConfigFile>(payload.config) {
                    Ok(new_config) => {
                        match manager.update_full_config(new_config) {
                            Ok(_) => {
                                info!("Applied config update v{}", payload.version);
                                Ok(())
                            },
                            Err(e) => {
                                error!("Failed to apply config update v{}: {}", payload.version, e);
                                Err(e.to_string())
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse config update v{}: {}", payload.version, e);
                        Err(e.to_string())
                    }
                }
            } else {
                warn!("Config update received but no ConfigManager available");
                Err("ConfigManager not available".to_string())
            };

            // Send Ack
            let ack = SensorMessage::CommandAck {
                payload: CommandAckPayload {
                    command_id,
                    success: result.is_ok(),
                    message: result.err(),
                    result: None,
                },
            };

            if let Ok(json) = ack.to_json() {
                if let Err(e) = ws_tx.send(Message::Text(json.into())).await {
                    error!("Failed to send command ack: {}", e);
                }
            }
        }
        HubMessage::RulesUpdate { rules, version } => {
            info!("Received rules update (version: {})", version);

            // Apply rules update via ConfigManager
            let result = if let Some(manager) = config_manager {
                // Convert rules JSON to bytes for the WAF engine
                match serde_json::to_vec(&rules) {
                    Ok(rules_bytes) => {
                        match manager.update_waf_rules(&rules_bytes) {
                            Ok(count) => {
                                info!("Applied rules update v{}: {} rules loaded", version, count);
                                Ok(())
                            }
                            Err(e) => {
                                error!("Failed to apply rules update v{}: {}", version, e);
                                Err(e.to_string())
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize rules for update v{}: {}", version, e);
                        Err(e.to_string())
                    }
                }
            } else {
                warn!("Rules update received but no ConfigManager available");
                Err("ConfigManager not available".to_string())
            };

            // Send Ack for rules update
            let ack = SensorMessage::CommandAck {
                payload: CommandAckPayload {
                    command_id: format!("rules_update_{}", version),
                    success: result.is_ok(),
                    message: result.err(),
                    result: None,
                },
            };

            if let Ok(json) = ack.to_json() {
                if let Err(e) = ws_tx.send(Message::Text(json.into())).await {
                    error!("Failed to send rules update ack: {}", e);
                }
            }
        }
        HubMessage::AuthSuccess { tenant_id, sensor_id, capabilities } => {
            info!("Auth success: tenant={} sensor={} capabilities={:?}", tenant_id, sensor_id, capabilities);
            // Auth is handled in connect_once, this is a redundant message
        }
        HubMessage::AuthFailed { error } => {
            error!("Auth failed (redundant): {}", error);
            // Auth failure is handled in connect_once, this shouldn't happen
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_metrics_provider() {
        let provider = NoopMetricsProvider;
        assert_eq!(provider.cpu_usage(), 0.0);
        assert_eq!(provider.memory_usage(), 0.0);
        assert_eq!(provider.disk_usage(), 0.0);
        assert_eq!(provider.requests_last_minute(), 0);
        assert_eq!(provider.avg_latency_ms(), 0.0);
        assert!(provider.config_hash().is_empty());
        assert!(provider.rules_hash().is_empty());
        assert!(provider.active_connections().is_none());
    }

    #[test]
    fn test_client_stats_default() {
        let stats = ClientStats::default();
        assert_eq!(stats.signals_sent, 0);
        assert_eq!(stats.signals_acked, 0);
        assert_eq!(stats.batches_sent, 0);
        assert_eq!(stats.heartbeats_sent, 0);
    }

    #[tokio::test]
    async fn test_client_disabled() {
        let config = HorizonConfig::default();
        let mut client = HorizonClient::new(config);

        // Should succeed without actually connecting
        assert!(client.start().await.is_ok());
    }

    #[tokio::test]
    async fn test_client_blocklist_lookup() {
        let config = HorizonConfig::default();
        let client = HorizonClient::new(config);

        // Add entries to blocklist directly for testing
        client.blocklist.add(super::super::blocklist::BlocklistEntry {
            block_type: super::super::blocklist::BlockType::Ip,
            indicator: "192.168.1.100".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(client.is_ip_blocked("192.168.1.100"));
        assert!(!client.is_ip_blocked("192.168.1.101"));
    }
}
