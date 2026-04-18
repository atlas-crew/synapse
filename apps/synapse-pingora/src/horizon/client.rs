//! WebSocket client for Signal Horizon Hub communication.

use arc_swap::ArcSwap;
use futures_util::{SinkExt, StreamExt};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use super::blocklist::BlocklistCache;
use super::config::HorizonConfig;
use super::error::HorizonError;
use super::types::{
    AuthPayload, ConnectionState, HeartbeatPayload, HubMessage, SensorMessage, ThreatSignal,
    PROTOCOL_VERSION,
};
use crate::admin_server::{
    get_registered_integrations_config, set_registered_integrations_config,
    trigger_registered_restart,
};
use crate::access::{check_ssrf, SsrfCheckResult};
use crate::config_manager::ConfigManager;
use crate::utils::circuit_breaker::CircuitBreaker;
use async_trait::async_trait;

/// SignalSink - trait for targets that can receive threat signals.
#[async_trait]
pub trait SignalSink: Send + Sync {
    async fn report_signal(&self, signal: ThreatSignal) -> Result<(), String>;
}

#[async_trait]
impl SignalSink for HorizonClient {
    async fn report_signal(&self, signal: ThreatSignal) -> Result<(), String> {
        if !self.circuit_breaker().allow_request().await {
            return Err("Circuit breaker open".to_string());
        }
        self.report_signal(signal);
        Ok(())
    }
}

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
    signals_queued: AtomicU64,
    signals_dropped: AtomicU64,
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
    pub signals_queued: u64,
    pub signals_dropped: u64,
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
            signals_queued: stats.signals_queued.load(Ordering::Relaxed),
            signals_dropped: stats.signals_dropped.load(Ordering::Relaxed),
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
    state: Arc<RwLock<ConnectionState>>,
    blocklist: Arc<BlocklistCache>,
    stats: Arc<InternalStats>,
    metrics_provider: Arc<dyn MetricsProvider>,
    signal_tx: ArcSwap<Option<mpsc::Sender<ThreatSignal>>>,
    signal_retry: Arc<Mutex<VecDeque<ThreatSignal>>>,
    shutdown_tx: ArcSwap<Option<broadcast::Sender<()>>>,
    tenant_id: Arc<RwLock<Option<String>>>,
    capabilities: Arc<RwLock<Vec<String>>>,
    // P1-012: config_manager wrapped in Arc so it can be shared with connection_loop (live updates)
    config_manager: Arc<ArcSwap<Option<Arc<ConfigManager>>>>,
    circuit_breaker: Arc<CircuitBreaker>,
}

impl HorizonClient {
    /// Create a new Horizon client.
    pub fn new(config: HorizonConfig) -> Self {
        let circuit_breaker = Arc::new(CircuitBreaker::new(5, Duration::from_secs(30)));
        Self {
            config,
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            blocklist: Arc::new(BlocklistCache::new()),
            stats: Arc::new(InternalStats {
                signals_sent: AtomicU64::new(0),
                signals_acked: AtomicU64::new(0),
                signals_queued: AtomicU64::new(0),
                signals_dropped: AtomicU64::new(0),
                batches_sent: AtomicU64::new(0),
                heartbeats_sent: AtomicU64::new(0),
                heartbeat_failures: AtomicU64::new(0),
                reconnect_attempts: AtomicU32::new(0),
            }),
            metrics_provider: Arc::new(NoopMetricsProvider),
            signal_tx: ArcSwap::from_pointee(None),
            signal_retry: Arc::new(Mutex::new(VecDeque::new())),
            shutdown_tx: ArcSwap::from_pointee(None),
            tenant_id: Arc::new(RwLock::new(None)),
            capabilities: Arc::new(RwLock::new(Vec::new())),
            config_manager: Arc::new(ArcSwap::from_pointee(None)),
            circuit_breaker,
        }
    }

    /// Set a custom metrics provider.
    pub fn with_metrics_provider(mut self, provider: Arc<dyn MetricsProvider>) -> Self {
        self.metrics_provider = provider;
        self
    }

    /// Set the configuration manager (builder pattern).
    pub fn with_config_manager(mut self, manager: Arc<ConfigManager>) -> Self {
        // P2-001: Direct field assignment since self is owned (not concurrent).
        self.config_manager = Arc::new(ArcSwap::from_pointee(Some(manager)));
        self
    }

    /// Update the configuration manager in place (runtime).
    pub fn set_config_manager(&self, manager: Arc<ConfigManager>) {
        self.config_manager.store(Arc::new(Some(manager)));
    }

    /// Start the client.
    pub async fn start(&self) -> Result<(), HorizonError> {
        if !self.config.enabled {
            debug!("Horizon client disabled, skipping start");
            return Ok(());
        }

        // P1-001 Fix: Split lock scope. Acquire only to check/set Connecting.
        // Release before async perform_start() to avoid blocking request threads.
        {
            let mut state = self.state.write();
            if *state != ConnectionState::Disconnected {
                debug!("Horizon client already started (state: {:?})", *state);
                return Ok(());
            }
            *state = ConnectionState::Connecting;
        }

        if let Err(e) = self.perform_start().await {
            // Re-acquire briefly to reset state on error
            *self.state.write() = ConnectionState::Disconnected;
            return Err(e);
        }

        Ok(())
    }

    /// Internal start logic after state transition.
    async fn perform_start(&self) -> Result<(), HorizonError> {
        self.config.validate()?;

        // SP-07: SSRF protection for hub URL (fail-closed in production/release builds).
        // Enforce in release builds (production default); keep dev/test ergonomics in debug builds.
        if should_enforce_hub_url_ssrf() {
            validate_hub_url_ssrf(&self.config.hub_url).await?;
        }

        // Create channels
        let (signal_tx, signal_rx) = mpsc::channel::<ThreatSignal>(self.config.max_queued_signals);
        let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);

        self.signal_tx.store(Arc::new(Some(signal_tx.clone())));
        self.shutdown_tx.store(Arc::new(Some(shutdown_tx.clone())));

        // Spawn connection task
        let params = ConnectionParams {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
            blocklist: Arc::clone(&self.blocklist),
            stats: Arc::clone(&self.stats),
            metrics_provider: Arc::clone(&self.metrics_provider),
            tenant_id: Arc::clone(&self.tenant_id),
            capabilities: Arc::clone(&self.capabilities),
            config_manager: Arc::clone(&self.config_manager),
            circuit_breaker: Arc::clone(&self.circuit_breaker),
        };

        let retry_queue = Arc::clone(&self.signal_retry);
        let retry_stats = Arc::clone(&self.stats);
        let retry_tx = signal_tx.clone();
        let retry_limit = self.config.max_queued_signals;
        let shutdown_rx_conn = shutdown_tx.subscribe();

        tokio::spawn(async move {
            connection_loop(params, signal_rx, shutdown_rx_conn).await;
        });

        let mut shutdown_rx_retry = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut queue = retry_queue.lock();
                        if queue.is_empty() {
                            continue;
                        }
                        while let Some(signal) = queue.pop_front() {
                            match retry_tx.try_send(signal) {
                                Ok(()) => {
                                    retry_stats.signals_sent.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(TrySendError::Full(signal)) => {
                                    queue.push_front(signal);
                                    break;
                                }
                                Err(TrySendError::Closed(_)) => {
                                    // P2-003: Metric boundary — this covers async retry queue eviction.
                                    retry_stats.signals_dropped.fetch_add(1, Ordering::Relaxed);
                                    queue.clear();
                                    break;
                                }
                            }
                        }
                        if queue.len() > retry_limit {
                            let overflow = queue.len() - retry_limit;
                            for _ in 0..overflow {
                                queue.pop_front();
                            }
                            // P2-003: Metric boundary — this covers async retry queue overflow.
                            retry_stats
                                .signals_dropped
                                .fetch_add(overflow as u64, Ordering::Relaxed);
                        }
                    }
                    _ = shutdown_rx_retry.recv() => break,
                }
            }
        });

        Ok(())
    }

    /// Stop the client.
    pub async fn stop(&self) {
        if let Some(tx) = self.shutdown_tx.swap(Arc::new(None)).as_ref() {
            let _ = tx.send(());
        }
        *self.state.write() = ConnectionState::Disconnected;
    }

    /// Report a threat signal.
    pub fn report_signal(&self, signal: ThreatSignal) {
        if let Some(ref tx) = **self.signal_tx.load() {
            match tx.try_send(signal) {
                Ok(()) => {
                    self.stats.signals_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(signal)) => {
                    let mut queue = self.signal_retry.lock();
                    if queue.len() >= self.config.max_queued_signals {
                        // P2-003: Metric boundary — this covers synchronous report rejection.
                        self.stats.signals_dropped.fetch_add(1, Ordering::Relaxed);
                        warn!("Signal queue full; dropping signal");
                    } else {
                        queue.push_back(signal);
                        self.stats.signals_queued.fetch_add(1, Ordering::Relaxed);
                        warn!("Signal queue full; queued for retry");
                    }
                }
                Err(TrySendError::Closed(_)) => {
                    // P2-003: Metric boundary — this covers synchronous report on closed channel.
                    self.stats.signals_dropped.fetch_add(1, Ordering::Relaxed);
                    warn!("Signal channel closed; dropping signal");
                }
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

    /// Check if an IP or fingerprint is blocked.
    pub fn is_blocked(&self, ip: Option<&str>, fingerprint: Option<&str>) -> bool {
        if let Some(ip) = ip {
            if self.is_ip_blocked(ip) {
                return true;
            }
        }
        if let Some(fp) = fingerprint {
            if self.is_fingerprint_blocked(fp) {
                return true;
            }
        }
        false
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

    /// Get the circuit breaker.
    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        Arc::clone(&self.circuit_breaker)
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

/// Parameters for the Horizon connection and event loop.
struct ConnectionParams {
    config: HorizonConfig,
    state: Arc<RwLock<ConnectionState>>,
    blocklist: Arc<BlocklistCache>,
    stats: Arc<InternalStats>,
    metrics_provider: Arc<dyn MetricsProvider>,
    tenant_id: Arc<RwLock<Option<String>>>,
    capabilities: Arc<RwLock<Vec<String>>>,
    config_manager: Arc<ArcSwap<Option<Arc<ConfigManager>>>>,
    circuit_breaker: Arc<CircuitBreaker>,
}

/// Connection loop with auto-reconnect.
async fn connection_loop(
    params: ConnectionParams,
    mut signal_rx: mpsc::Receiver<ThreatSignal>,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    let mut reconnect_delay = params.config.reconnect_delay_ms;
    let mut attempt = 0u32;
    let mut consecutive_failures = 0u32;
    let mut circuit_open_until: Option<Instant> = None;
    let mut pending_signals: VecDeque<ThreatSignal> = VecDeque::new();
    let mut inflight_signals: VecDeque<ThreatSignal> = VecDeque::new();

    // Pre-enrollment announce: tell Horizon "I'm here" once per sensor
    // process before the WebSocket handshake, so the onboarding wizard can
    // surface us as a candidate even if the operator hasn't approved the
    // WebSocket-side enrollment yet. Best-effort — any failure is logged
    // and ignored; the WebSocket handshake remains the real enrollment.
    announce_to_horizon(&params.config).await;

    loop {
        // --- Shutdown Check ---
        if let Ok(()) | Err(broadcast::error::TryRecvError::Closed) = shutdown_rx.try_recv() {
            info!("Horizon client shutdown requested");
            *params.state.write() = ConnectionState::Disconnected;
            return;
        }

        // --- Circuit Breaker Check ---
        if let Some(until) = circuit_open_until {
            let now = Instant::now();
            if now < until {
                *params.state.write() = ConnectionState::Degraded;
                let remaining = until.saturating_duration_since(now);
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Horizon client shutdown requested");
                        *params.state.write() = ConnectionState::Disconnected;
                        return;
                    }
                    _ = tokio::time::sleep(remaining) => {}
                }
                continue;
            }

            circuit_open_until = None;
            info!("Horizon circuit breaker closed; resuming connection attempts");
        }

        // Check max reconnect attempts
        if params.config.max_reconnect_attempts > 0
            && attempt >= params.config.max_reconnect_attempts
        {
            error!("Max reconnect attempts reached");
            *params.state.write() = ConnectionState::Error;
            return;
        }

        // --- Connection Attempt ---
        *params.state.write() = ConnectionState::Connecting;
        info!("Connecting to Hub: {}", params.config.hub_url);

        match connect_and_run(
            &params,
            &mut signal_rx,
            &mut shutdown_rx,
            &mut pending_signals,
            &mut inflight_signals,
        )
        .await
        {
            ConnectionResult::Shutdown => {
                info!("Horizon client shutdown");
                *params.state.write() = ConnectionState::Disconnected;
                return;
            }
            ConnectionResult::AuthFailed => {
                error!("Authentication failed, not retrying");
                *params.state.write() = ConnectionState::Error;
                return;
            }
            ConnectionResult::Disconnected { had_connection } => {
                requeue_inflight(
                    &mut pending_signals,
                    &mut inflight_signals,
                    params.config.max_queued_signals,
                    &params.stats,
                );
                if had_connection {
                    attempt = 0;
                    reconnect_delay = params.config.reconnect_delay_ms;
                    consecutive_failures = 0;
                }

                attempt = attempt.saturating_add(1);
                params
                    .stats
                    .reconnect_attempts
                    .store(attempt, Ordering::Relaxed);
                consecutive_failures = consecutive_failures.saturating_add(1);

                if params.config.circuit_breaker_threshold > 0
                    && consecutive_failures >= params.config.circuit_breaker_threshold
                {
                    let cooldown =
                        Duration::from_millis(params.config.circuit_breaker_cooldown_ms.max(1));
                    circuit_open_until = Some(Instant::now() + cooldown);
                    *params.state.write() = ConnectionState::Degraded;
                    warn!(
                        "Horizon circuit breaker opened after {} consecutive failures; cooling down for {}ms",
                        consecutive_failures, cooldown.as_millis()
                    );
                    consecutive_failures = 0;
                    reconnect_delay = params.config.reconnect_delay_ms;
                    continue;
                }

                // Exponential backoff (max 60s)
                if attempt > 1 {
                    reconnect_delay = (reconnect_delay * 2).min(60_000);
                }

                // Add random jitter (±25%)
                let jitter_percent = fastrand::u32(0..50); // 0-50 maps to 0.75-1.25
                let jitter_factor = 0.75 + (jitter_percent as f64 / 100.0);
                let delay_with_jitter = (reconnect_delay as f64 * jitter_factor) as u64;

                warn!(
                    "Disconnected, reconnecting in {}ms (attempt {}, base {}ms)",
                    delay_with_jitter, attempt, reconnect_delay
                );
                *params.state.write() = ConnectionState::Reconnecting;

                tokio::time::sleep(Duration::from_millis(delay_with_jitter)).await;
            }
            ConnectionResult::Stopped => {
                *params.state.write() = ConnectionState::Disconnected;
                return;
            }
        }
    }
}

fn registration_token_for_auth(api_key: &str) -> Option<String> {
    let trimmed = api_key.trim();
    if trimmed.starts_with("sh_reg_") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

enum ConnectionResult {
    Shutdown,
    AuthFailed,
    Disconnected { had_connection: bool },
    Stopped,
}

fn should_enforce_hub_url_ssrf() -> bool {
    // Allow explicit override for local development and test rigs.
    if std::env::var("SYNAPSE_ALLOW_INTERNAL_HORIZON_URL")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        return false;
    }

    // Enforce in release builds (production default); keep dev/test ergonomics in debug builds.
    !cfg!(debug_assertions)
}

/// Derive the public announce URL from the configured WebSocket hub_url.
///
/// Input `wss://horizon.example.com:8443/sensor-gateway` ⇒ output
/// `https://horizon.example.com:8443/api/v1/sensors/announce`. Preserves
/// host and port (so operators running Horizon on a non-standard port keep
/// working) and strips any hub_url query/fragment.
fn derive_announce_url(hub_url: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(hub_url).map_err(|e| e.to_string())?;
    let new_scheme = match url.scheme() {
        "wss" | "https" => "https",
        "ws" | "http" => "http",
        other => return Err(format!("unsupported hub_url scheme '{}'", other)),
    };
    url.set_scheme(new_scheme)
        .map_err(|_| "failed to rewrite hub_url scheme for announce".to_string())?;
    url.set_path("/api/v1/sensors/announce");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

/// Best-effort HTTP announce to Horizon. Logs and swallows all errors —
/// the WebSocket handshake remains the authoritative enrollment path,
/// so announce failures must never prevent a sensor from coming online.
async fn announce_to_horizon(config: &HorizonConfig) {
    let announce_url = match derive_announce_url(&config.hub_url) {
        Ok(url) => url,
        Err(e) => {
            warn!(
                "Skipping sensor announce: could not derive announce URL from hub_url: {}",
                e
            );
            return;
        }
    };

    let fingerprint = config.sensor_id.trim();
    if fingerprint.len() < 8 {
        warn!(
            "Skipping sensor announce: sensor_id '{}' is shorter than 8 chars; \
             set horizon.sensor_id to a stable identifier (UUID, machine-id, etc.)",
            fingerprint
        );
        return;
    }

    let mut sys = System::new();
    sys.refresh_all();

    let payload = serde_json::json!({
        "fingerprint": fingerprint,
        "hostname": System::host_name(),
        "os": System::name(),
        "kernel": System::kernel_version(),
        "architecture": std::env::consts::ARCH,
        "version": config.version,
    });

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Skipping sensor announce: HTTP client build failed: {}", e);
            return;
        }
    };

    debug!("Announcing sensor to Horizon at {}", announce_url);
    match client
        .post(&announce_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
    {
        Ok(res) if res.status().is_success() => {
            info!(
                "Sensor announce registered as onboarding candidate (status {})",
                res.status()
            );
        }
        Ok(res) => {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            warn!(
                "Sensor announce returned non-success status {}: {}",
                status,
                body.chars().take(200).collect::<String>()
            );
        }
        Err(e) => {
            warn!("Sensor announce request failed: {}", e);
        }
    }
}

async fn validate_hub_url_ssrf(hub_url: &str) -> Result<(), HorizonError> {
    let url = reqwest::Url::parse(hub_url)
        .map_err(|e| HorizonError::ConfigError(format!("Invalid hub_url '{}': {}", hub_url, e)))?;

    let host = url
        .host_str()
        .ok_or_else(|| HorizonError::ConfigError("hub_url must include a hostname".to_string()))?;

    if host.eq_ignore_ascii_case("localhost") {
        return Err(HorizonError::ConfigError(
            "hub_url resolves to localhost which is not allowed in production".to_string(),
        ));
    }

    let port = url.port_or_known_default().unwrap_or(443);

    // Literal IP address (no DNS) — validate directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        let result = check_ssrf(&ip);
        if result.is_blocked() {
            return Err(HorizonError::ConfigError(format!(
                "hub_url targets blocked address {} ({:?})",
                ip, result
            )));
        }
        return Ok(());
    }

    // Hostname — resolve to IPs and validate all results.
    let mut any = false;
    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
        HorizonError::ConfigError(format!("Failed to resolve hub_url host '{}': {}", host, e))
    })?;

    for addr in addrs {
        any = true;
        let ip = addr.ip();
        let result: SsrfCheckResult = check_ssrf(&ip);
        if result.is_blocked() {
            return Err(HorizonError::ConfigError(format!(
                "hub_url resolves to blocked address {} ({:?})",
                ip, result
            )));
        }
    }

    if !any {
        return Err(HorizonError::ConfigError(format!(
            "hub_url host '{}' did not resolve to any addresses",
            host
        )));
    }

    Ok(())
}

/// FIFO Eviction: Drops oldest signals from the front of the queue to make room for new ones. (P2-002)
fn stash_pending(
    pending: &mut VecDeque<ThreatSignal>,
    batch: &mut Vec<ThreatSignal>,
    max_size: usize,
    stats: &Arc<InternalStats>,
) {
    if batch.is_empty() {
        return;
    }

    let to_add = batch.len();
    let current_size = pending.len();

    if current_size + to_add > max_size {
        let overflow = (current_size + to_add).saturating_sub(max_size);
        // FIFO: Drop from the front of pending (the absolute oldest)
        let drop_from_pending = overflow.min(current_size);
        if drop_from_pending > 0 {
            for _ in 0..drop_from_pending {
                pending.pop_front();
            }
            // P2-003: Metric boundary — this covers connection loss/error eviction.
            stats
                .signals_dropped
                .fetch_add(drop_from_pending as u64, Ordering::Relaxed);
        }

        // If still overflowing, drop from the front of the incoming batch
        let drop_from_batch = overflow.saturating_sub(drop_from_pending);
        if drop_from_batch > 0 {
            batch.drain(0..drop_from_batch);
            // P2-003: Metric boundary — this covers batch-delay overflow eviction.
            stats
                .signals_dropped
                .fetch_add(drop_from_batch as u64, Ordering::Relaxed);
        }

        warn!(
            "Signal buffer overflow ({} > {}); dropped {} oldest signals (FIFO)",
            current_size + to_add,
            max_size,
            overflow
        );
    }

    pending.extend(batch.drain(..));
}

/// FIFO Eviction: Preserves fresher signals by dropping the oldest first. (P2-002)
fn requeue_inflight(
    pending: &mut VecDeque<ThreatSignal>,
    inflight: &mut VecDeque<ThreatSignal>,
    max_size: usize,
    stats: &Arc<InternalStats>,
) {
    if inflight.is_empty() {
        return;
    }

    let to_add = inflight.len();
    let current_size = pending.len();

    if current_size + to_add > max_size {
        let overflow = (current_size + to_add).saturating_sub(max_size);
        // FIFO: Drop from pending first (they were queued before the currently inflight ones)
        let drop_count = overflow.min(current_size);
        for _ in 0..drop_count {
            pending.pop_front();
        }
        // P2-003: Metric boundary — this covers requeue overflow from older pending.
        stats
            .signals_dropped
            .fetch_add(drop_count as u64, Ordering::Relaxed);

        // If still overflowing, drop from inflight (they are newer than pending but still too old to keep)
        let remaining_overflow = overflow.saturating_sub(drop_count);
        if remaining_overflow > 0 {
            for _ in 0..remaining_overflow {
                inflight.pop_front();
            }
            // P2-003: Metric boundary — this covers requeue overflow from newer inflight.
            stats
                .signals_dropped
                .fetch_add(remaining_overflow as u64, Ordering::Relaxed);
        }

        warn!(
            "Signal buffer overflow during requeue ({} > {}); dropped {} oldest signals (FIFO)",
            current_size + to_add,
            max_size,
            overflow
        );
    }

    // Prepend inflight to pending (inflight were sent before any new pending)
    let mut combined = VecDeque::with_capacity(pending.len() + inflight.len());
    combined.extend(inflight.drain(..));
    combined.extend(pending.drain(..));
    *pending = combined;
}

async fn connect_and_run(
    params: &ConnectionParams,
    signal_rx: &mut mpsc::Receiver<ThreatSignal>,
    shutdown_rx: &mut broadcast::Receiver<()>,
    pending_signals: &mut VecDeque<ThreatSignal>,
    inflight_signals: &mut VecDeque<ThreatSignal>,
) -> ConnectionResult {
    let mut had_connection = false;

    // --- Connect WebSocket ---
    let mut request = match params.config.hub_url.clone().into_client_request() {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to build WebSocket request: {}", e);
            return ConnectionResult::Disconnected { had_connection };
        }
    };

    if let Ok(value) = http::HeaderValue::from_str(&format!("Bearer {}", params.config.api_key)) {
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, value);
    }

    let ws_stream = match tokio_tungstenite::connect_async(request).await {
        Ok((stream, _)) => stream,
        Err(e) => {
            error!("WebSocket connection failed: {}", e);
            params.circuit_breaker.record_failure().await;
            return ConnectionResult::Disconnected { had_connection };
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // --- Auth Handshake ---
    *params.state.write() = ConnectionState::Authenticating;
    let auth_msg = SensorMessage::Auth {
        payload: AuthPayload {
            api_key: params.config.api_key.clone(),
            sensor_id: params.config.sensor_id.clone(),
            sensor_name: params.config.sensor_name.clone(),
            version: params.config.version.clone(),
            registration_token: registration_token_for_auth(&params.config.api_key),
            fingerprint: Some(params.config.sensor_id.clone()),
            protocol_version: Some(PROTOCOL_VERSION.to_string()),
        },
    };

    if let Err(e) = ws_tx.send(Message::text(auth_msg.to_json().unwrap())).await {
        error!("Failed to send auth: {}", e);
        return ConnectionResult::Disconnected { had_connection };
    }

    let auth_timeout = tokio::time::timeout(Duration::from_secs(10), ws_rx.next()).await;

    match auth_timeout {
        Ok(Some(Ok(Message::Text(text)))) => match HubMessage::from_json(&text) {
            Ok(HubMessage::AuthSuccess {
                sensor_id: _,
                tenant_id: tid,
                capabilities: caps,
                protocol_version: negotiated_version,
            }) => {
                if let Some(ref pv) = negotiated_version {
                    info!("Authenticated with Hub (tenant: {}, protocol: {})", tid, pv);
                } else {
                    info!("Authenticated with Hub (tenant: {})", tid);
                }
                params.circuit_breaker.record_success().await;
                *params.tenant_id.write() = Some(tid);
                *params.capabilities.write() = caps;
                *params.state.write() = ConnectionState::Connected;
                had_connection = true;

                let _ = ws_tx
                    .send(Message::text(
                        SensorMessage::BlocklistSync.to_json().unwrap(),
                    ))
                    .await;
            }
            Ok(HubMessage::AuthFailed { error }) => {
                error!("Auth failed: {}", error);
                return ConnectionResult::AuthFailed;
            }
            _ => {
                error!("Unexpected auth response");
                params.circuit_breaker.record_failure().await;
                return ConnectionResult::Disconnected { had_connection };
            }
        },
        _ => {
            error!("Auth timeout or error");
            params.circuit_breaker.record_failure().await;
            return ConnectionResult::Disconnected { had_connection };
        }
    }

    // --- Main Event Loop ---
    let mut heartbeat_interval =
        tokio::time::interval(Duration::from_millis(params.config.heartbeat_interval_ms));
    let mut signal_batch: Vec<ThreatSignal> = Vec::with_capacity(params.config.signal_batch_size);
    let mut batch_timer =
        tokio::time::interval(Duration::from_millis(params.config.signal_batch_delay_ms));

    if !pending_signals.is_empty() {
        signal_batch.extend(pending_signals.drain(..));
        if let Err(e) = send_batch(
            &mut ws_tx,
            &mut signal_batch,
            inflight_signals,
            &params.stats,
        )
        .await
        {
            error!("Failed to send buffered signals: {}", e);
            params.circuit_breaker.record_failure().await;
            stash_pending(
                pending_signals,
                &mut signal_batch,
                params.config.max_queued_signals,
                &params.stats,
            );
            return ConnectionResult::Disconnected { had_connection };
        }
    }

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Shutdown received");
                let _ = ws_tx.close().await;
                return ConnectionResult::Shutdown;
            }

            signal = signal_rx.recv() => {
                match signal {
                    Some(sig) => {
                        signal_batch.push(sig);
                        if signal_batch.len() >= params.config.signal_batch_size {
                            if let Err(e) = send_batch(&mut ws_tx, &mut signal_batch, inflight_signals, &params.stats).await {
                                error!("Failed to send batch: {}", e);
                                params.circuit_breaker.record_failure().await;
                                stash_pending(pending_signals, &mut signal_batch, params.config.max_queued_signals, &params.stats);
                                return ConnectionResult::Disconnected { had_connection };
                            }
                            params.circuit_breaker.record_success().await;
                        }
                    }
                    None => {
                        return ConnectionResult::Stopped;
                    }
                }
            }

            _ = batch_timer.tick() => {
                if !signal_batch.is_empty() {
                    if let Err(e) = send_batch(&mut ws_tx, &mut signal_batch, inflight_signals, &params.stats).await {
                        error!("Failed to send batch: {}", e);
                        params.circuit_breaker.record_failure().await;
                        stash_pending(pending_signals, &mut signal_batch, params.config.max_queued_signals, &params.stats);
                        return ConnectionResult::Disconnected { had_connection };
                    }
                    params.circuit_breaker.record_success().await;
                }
            }

            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(hub_msg) = HubMessage::from_json(&text) {
                            let cm = params.config_manager.load();
                            handle_hub_message(
                                hub_msg,
                                &params.blocklist,
                                &params.stats,
                                &params.metrics_provider,
                                &**cm,
                                inflight_signals,
                                &mut ws_tx,
                            )
                            .await;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        warn!("WebSocket closed");
                        stash_pending(pending_signals, &mut signal_batch, params.config.max_queued_signals, &params.stats);
                        return ConnectionResult::Disconnected { had_connection };
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        stash_pending(pending_signals, &mut signal_batch, params.config.max_queued_signals, &params.stats);
                        return ConnectionResult::Disconnected { had_connection };
                    }
                    _ => {}
                }
            }

            _ = heartbeat_interval.tick() => {
                let payload = HeartbeatPayload {
                    timestamp: chrono::Utc::now().timestamp_millis(),
                    status: "healthy".to_string(),
                    cpu: params.metrics_provider.cpu_usage(),
                    memory: params.metrics_provider.memory_usage(),
                    disk: params.metrics_provider.disk_usage(),
                    requests_last_minute: params.metrics_provider.requests_last_minute(),
                    avg_latency_ms: params.metrics_provider.avg_latency_ms(),
                    config_hash: params.metrics_provider.config_hash(),
                    rules_hash: params.metrics_provider.rules_hash(),
                    active_connections: params.metrics_provider.active_connections(),
                    blocklist_size: Some(params.blocklist.size()),
                };

                let msg = SensorMessage::Heartbeat { payload };
                if let Err(e) = ws_tx.send(Message::text(msg.to_json().unwrap())).await {
                    warn!("Failed to send heartbeat: {}", e);
                    params.stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                } else {
                    params.stats.heartbeats_sent.fetch_add(1, Ordering::Relaxed);
                    debug!("Sent heartbeat");
                }
            }
        }
    }
}

async fn send_batch<S>(
    ws_tx: &mut futures_util::stream::SplitSink<S, Message>,
    batch: &mut Vec<ThreatSignal>,
    inflight: &mut VecDeque<ThreatSignal>,
    stats: &Arc<InternalStats>,
) -> Result<(), HorizonError>
where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    if batch.is_empty() {
        return Ok(());
    }

    let signals: Vec<ThreatSignal> = std::mem::take(batch);
    let count = signals.len();

    if count == 0 {
        return Ok(());
    }

    for signal in &signals {
        inflight.push_back(signal.clone());
    }

    let msg = if count == 1 {
        SensorMessage::Signal {
            payload: signals.into_iter().next().unwrap(),
        }
    } else {
        SensorMessage::SignalBatch { payload: signals }
    };

    ws_tx
        .send(Message::text(msg.to_json()?))
        .await
        .map_err(|e| HorizonError::SendFailed(e.to_string()))?;

    stats.batches_sent.fetch_add(1, Ordering::Relaxed);
    debug!("Sent batch of {} signals", count);

    Ok(())
}

use super::types::CommandAckPayload;

async fn send_command_ack<S>(
    ws_tx: &mut futures_util::stream::SplitSink<S, Message>,
    command_id: String,
    result: Result<Option<serde_json::Value>, String>,
) where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let (success, message, result_value) = match result {
        Ok(result_value) => (true, None, result_value),
        Err(message) => (false, Some(message), None),
    };

    let ack = SensorMessage::CommandAck {
        payload: CommandAckPayload {
            command_id,
            success,
            message,
            result: result_value,
        },
    };

    if let Ok(json) = ack.to_json() {
        if let Err(e) = ws_tx.send(Message::text(json)).await {
            error!("Failed to send command ack: {}", e);
        }
    }
}

fn sanitize_filename_component(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn stage_update_payload(
    command_id: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let update_dir =
        std::env::var("SYNAPSE_UPDATE_DIR").unwrap_or_else(|_| "/tmp/synapse-updates".to_string());

    fs::create_dir_all(&update_dir)
        .map_err(|e| format!("Failed to create update dir {}: {}", update_dir, e))?;

    let safe_id = sanitize_filename_component(command_id);
    let file_name = format!(
        "update-{}-{}.json",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        safe_id
    );
    let path = PathBuf::from(&update_dir).join(file_name);

    let body = serde_json::to_string_pretty(payload)
        .map_err(|e| format!("Failed to serialize update payload: {}", e))?;
    fs::write(&path, body.as_bytes())
        .map_err(|e| format!("Failed to stage update payload: {}", e))?;

    Ok(serde_json::json!({
        "staged": true,
        "path": path.to_string_lossy(),
        "bytes": body.len(),
        "update_dir": update_dir,
        "payload_version": payload.get("version").and_then(|value| value.as_str()),
    }))
}

fn soft_restart(config_manager: &Option<Arc<ConfigManager>>) -> Result<serde_json::Value, String> {
    let manager = config_manager
        .as_ref()
        .ok_or_else(|| "ConfigManager not available".to_string())?;

    let config = manager.get_full_config();
    let mutation = manager
        .update_full_config(config)
        .map_err(|e| e.to_string())?;

    let rules = manager.list_rules();
    let rules_count = rules.len();
    let rules_loaded = manager
        .replace_rules(rules, None)
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "restart_mode": "soft",
        "config_reloaded": true,
        "rules_loaded": rules_loaded,
        "rules_count": rules_count,
        "applied": mutation.applied,
        "persisted": mutation.persisted,
        "rebuild_required": mutation.rebuild_required,
        "warnings": mutation.warnings,
    }))
}

fn apply_sensor_api_key_handoff(
    payload: &super::types::ConfigPayload,
) -> Result<serde_json::Value, String> {
    let sensor_api_key = payload
        .sensor_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "push_config action 'replace_sensor_api_key' requires sensorApiKey".to_string()
        })?;

    let mut integrations = get_registered_integrations_config()?;
    let mut updated_targets = Vec::new();

    if !integrations.horizon_hub_url.trim().is_empty()
        || !integrations.horizon_api_key.trim().is_empty()
    {
        integrations.horizon_api_key = sensor_api_key.to_string();
        updated_targets.push("horizon");
    }

    if !integrations.tunnel_url.trim().is_empty() || !integrations.tunnel_api_key.trim().is_empty()
    {
        integrations.tunnel_api_key = sensor_api_key.to_string();
        updated_targets.push("tunnel");
    }

    if updated_targets.is_empty() {
        return Err(
            "No configured Horizon or tunnel integration was available for sensor key handoff"
                .to_string(),
        );
    }

    set_registered_integrations_config(integrations)?;

    let restart_requested = payload.restart_process.unwrap_or(true);
    let restart_result = if restart_requested {
        Some(trigger_registered_restart()?)
    } else {
        None
    };

    Ok(serde_json::json!({
        "action": "replace_sensor_api_key",
        "updated_targets": updated_targets,
        "restart_requested": restart_requested,
        "restart": restart_result,
        "source": payload.source,
    }))
}

fn collect_diagnostics(
    metrics_provider: &Arc<dyn MetricsProvider>,
    config_manager: &Option<Arc<ConfigManager>>,
    blocklist: &Arc<BlocklistCache>,
    stats: &Arc<InternalStats>,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let include_config = payload
        .get("include_config")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let include_sites = payload
        .get("include_sites")
        .and_then(|value| value.as_bool())
        .unwrap_or(true);
    let include_rules = payload
        .get("include_rules")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let mut sys = System::new_all();
    sys.refresh_all();

    let system_info = serde_json::json!({
        "hostname": System::host_name().unwrap_or_default(),
        "os": System::name().unwrap_or_default(),
        "os_version": System::os_version().unwrap_or_default(),
        "kernel_version": System::kernel_version().unwrap_or_default(),
        "cpu_count": sys.cpus().len(),
        "total_memory_mb": sys.total_memory() / 1024 / 1024,
        "used_memory_mb": sys.used_memory() / 1024 / 1024,
        "uptime_secs": System::uptime(),
    });

    let mut config_summary = serde_json::Map::new();
    let mut rules_summary = serde_json::Map::new();

    if let Some(manager) = config_manager {
        let config = manager.get_full_config();
        let site_count = config.sites.len();
        let tls_sites = config
            .sites
            .iter()
            .filter(|site| site.tls.is_some())
            .count();
        let waf_sites = config
            .sites
            .iter()
            .filter(|site| site.waf.as_ref().map(|waf| waf.enabled).unwrap_or(false))
            .count();
        config_summary.insert("available".to_string(), serde_json::json!(true));
        config_summary.insert("site_count".to_string(), serde_json::json!(site_count));
        config_summary.insert("tls_site_count".to_string(), serde_json::json!(tls_sites));
        config_summary.insert(
            "waf_enabled_sites".to_string(),
            serde_json::json!(waf_sites),
        );
        if include_sites {
            let site_hostnames = config
                .sites
                .iter()
                .map(|site| site.hostname.clone())
                .collect::<Vec<_>>();
            config_summary.insert(
                "site_hostnames".to_string(),
                serde_json::json!(site_hostnames),
            );
        }
        if include_config {
            if let Ok(value) = serde_json::to_value(&config) {
                config_summary.insert("config".to_string(), value);
            }
        }

        let rules = manager.list_rules();
        rules_summary.insert("count".to_string(), serde_json::json!(rules.len()));
        if include_rules {
            if let Ok(value) = serde_json::to_value(&rules) {
                rules_summary.insert("rules".to_string(), value);
            }
        }
    } else {
        config_summary.insert("available".to_string(), serde_json::json!(false));
        rules_summary.insert("count".to_string(), serde_json::json!(0));
    }

    let stats_value = serde_json::to_value(ClientStats::from(stats.as_ref()))
        .unwrap_or_else(|_| serde_json::json!({}));

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "system": system_info,
        "metrics": {
            "cpu": metrics_provider.cpu_usage(),
            "memory": metrics_provider.memory_usage(),
            "disk": metrics_provider.disk_usage(),
            "requests_last_minute": metrics_provider.requests_last_minute(),
            "avg_latency_ms": metrics_provider.avg_latency_ms(),
            "active_connections": metrics_provider.active_connections(),
            "config_hash": metrics_provider.config_hash(),
            "rules_hash": metrics_provider.rules_hash(),
        },
        "blocklist": { "size": blocklist.size() },
        "client_stats": stats_value,
        "config": serde_json::Value::Object(config_summary),
        "rules": serde_json::Value::Object(rules_summary),
    })
}

async fn handle_hub_message<S>(
    msg: HubMessage,
    blocklist: &Arc<BlocklistCache>,
    stats: &Arc<InternalStats>,
    metrics_provider: &Arc<dyn MetricsProvider>,
    config_manager: &Option<Arc<ConfigManager>>,
    inflight_signals: &mut VecDeque<ThreatSignal>,
    ws_tx: &mut futures_util::stream::SplitSink<S, Message>,
) where
    S: futures_util::Sink<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    match msg {
        HubMessage::SignalAck { sequence_id: _ } => {
            stats.signals_acked.fetch_add(1, Ordering::Relaxed);
            if inflight_signals.pop_front().is_none() {
                warn!("Received signal ack but no inflight signals were tracked");
            }
        }
        HubMessage::BatchAck {
            count,
            sequence_id: _,
        } => {
            stats
                .signals_acked
                .fetch_add(count as u64, Ordering::Relaxed);
            debug!("Batch of {} signals acknowledged", count);
            let mut remaining = count as usize;
            while remaining > 0 {
                if inflight_signals.pop_front().is_none() {
                    warn!(
                        "Received batch ack for {} signals but inflight queue was empty",
                        count
                    );
                    break;
                }
                remaining -= 1;
            }
        }
        HubMessage::Ping { timestamp: _ } => {}
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
            info!(
                "Received config update (legacy direct) version: {}",
                version
            );
        }
        HubMessage::PushConfig {
            command_id,
            payload,
        } => {
            let version = payload
                .version
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            info!(
                "Received PushConfig command (id: {}, version: {})",
                command_id, version
            );

            let result = if let Some(manager) = config_manager {
                if let Some(config_value) = payload.config.as_ref() {
                    match serde_json::from_value::<crate::config::ConfigFile>(config_value.clone())
                    {
                        Ok(new_config) => match manager.update_full_config(new_config) {
                            Ok(result) => {
                                info!("Applied config update v{}", version);
                                Ok(Some(serde_json::json!({
                                    "applied": result.applied,
                                    "persisted": result.persisted,
                                    "rebuild_required": result.rebuild_required,
                                    "warnings": result.warnings,
                                })))
                            }
                            Err(e) => {
                                error!("Failed to apply config update v{}: {}", version, e);
                                Err(e.to_string())
                            }
                        },
                        Err(e) => {
                            error!("Failed to parse config update v{}: {}", version, e);
                            Err(e.to_string())
                        }
                    }
                } else if let Some(action) = payload.action.as_deref() {
                    match action {
                        "replace_sensor_api_key" => {
                            apply_sensor_api_key_handoff(&payload).map(Some)
                        }
                        _ => Err(format!(
                            "push_config action '{}' not supported via hub",
                            action
                        )),
                    }
                } else {
                    Err("push_config payload missing config".to_string())
                }
            } else {
                warn!("Config update received but no ConfigManager available");
                Err("ConfigManager not available".to_string())
            };

            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::PushRules {
            command_id,
            payload,
        } => {
            info!("Received PushRules command (id: {})", command_id);

            let result = if let Some(manager) = config_manager {
                let rules_value = payload.get("rules").unwrap_or(&payload);
                let rules_hash = payload.get("hash").and_then(|value| value.as_str());
                if !rules_value.is_array() {
                    Err("push_rules payload missing rules array".to_string())
                } else {
                    match serde_json::to_vec(rules_value) {
                        Ok(rules_bytes) => match manager.update_waf_rules(&rules_bytes, rules_hash)
                        {
                            Ok(count) => {
                                info!("Applied push_rules: {} rules loaded", count);
                                Ok(Some(serde_json::json!({ "rules_loaded": count })))
                            }
                            Err(e) => {
                                error!("Failed to apply push_rules: {}", e);
                                Err(e.to_string())
                            }
                        },
                        Err(e) => {
                            error!("Failed to serialize push_rules payload: {}", e);
                            Err(e.to_string())
                        }
                    }
                }
            } else {
                warn!("PushRules received but no ConfigManager available");
                Err("ConfigManager not available".to_string())
            };

            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::Restart {
            command_id,
            payload,
        } => {
            info!("Received Restart command (id: {})", command_id);
            let requested_mode = payload
                .get("mode")
                .and_then(|value| value.as_str())
                .unwrap_or("soft");

            let result = match soft_restart(config_manager) {
                Ok(mut value) => {
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert(
                            "requested_mode".to_string(),
                            serde_json::json!(requested_mode),
                        );
                    }
                    Ok(Some(value))
                }
                Err(e) => Err(e),
            };

            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::CollectDiagnostics {
            command_id,
            payload,
        } => {
            info!("Received CollectDiagnostics command (id: {})", command_id);
            let result = Ok(Some(collect_diagnostics(
                metrics_provider,
                config_manager,
                blocklist,
                stats,
                &payload,
            )));
            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::Update {
            command_id,
            payload,
        } => {
            info!("Received Update command (id: {})", command_id);
            let result = stage_update_payload(&command_id, &payload)
                .map(Some)
                .map_err(|e| e.to_string());
            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::SyncBlocklist {
            command_id,
            payload: _,
        } => {
            info!("Received SyncBlocklist command (id: {})", command_id);
            let result = match SensorMessage::BlocklistSync.to_json() {
                Ok(json) => {
                    if let Err(e) = ws_tx.send(Message::text(json)).await {
                        Err(format!("Failed to request blocklist sync: {}", e))
                    } else {
                        Ok(None)
                    }
                }
                Err(e) => Err(format!("Failed to serialize blocklist sync: {}", e)),
            };

            send_command_ack(ws_tx, command_id, result).await;
        }
        HubMessage::RulesUpdate { rules, version } => {
            info!("Received rules update (version: {})", version);

            let result = if let Some(manager) = config_manager {
                match serde_json::to_vec(&rules) {
                    Ok(rules_bytes) => match manager.update_waf_rules(&rules_bytes, None) {
                        Ok(count) => {
                            info!("Applied rules update v{}: {} rules loaded", version, count);
                            Ok(count)
                        }
                        Err(e) => {
                            error!("Failed to apply rules update v{}: {}", version, e);
                            Err(e.to_string())
                        }
                    },
                    Err(e) => {
                        error!("Failed to serialize rules for update v{}: {}", version, e);
                        Err(e.to_string())
                    }
                }
            } else {
                warn!("Rules update received but no ConfigManager available");
                Err("ConfigManager not available".to_string())
            };

            send_command_ack(
                ws_tx,
                format!("rules_update_{}", version),
                result.map(|count| Some(serde_json::json!({ "rules_loaded": count }))),
            )
            .await;
        }
        HubMessage::AuthSuccess {
            tenant_id,
            sensor_id,
            capabilities,
            protocol_version,
        } => {
            info!(
                "Auth success: tenant={} sensor={} capabilities={:?} protocol={:?}",
                tenant_id, sensor_id, capabilities, protocol_version
            );
        }
        HubMessage::AuthFailed { error } => {
            error!("Auth failed (redundant): {}", error);
        }
        HubMessage::TunnelOpen {
            tunnel_id,
            target_host,
            target_port,
        } => {
            warn!(
                "Tunnel open requested (id: {}, target: {}:{}) but tunnels are not supported",
                tunnel_id, target_host, target_port
            );
            let error_msg = SensorMessage::TunnelError {
                tunnel_id,
                code: "TUNNEL_UNSUPPORTED".to_string(),
                message: "This sensor does not support tunnel connections".to_string(),
            };
            if let Ok(json) = error_msg.to_json() {
                let _ = ws_tx.send(Message::text(json)).await;
            }
        }
        HubMessage::TunnelClose { tunnel_id } => {
            warn!(
                "Tunnel close requested (id: {}) but tunnels are not supported",
                tunnel_id
            );
        }
        HubMessage::TunnelData { tunnel_id, .. } => {
            warn!(
                "Tunnel data received (id: {}) but tunnels are not supported",
                tunnel_id
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin_server::{
        register_integrations_callbacks, register_restart_callback, IntegrationsConfig,
    };

    #[test]
    fn test_derive_announce_url_wss() {
        let url = derive_announce_url("wss://horizon.example.com/sensor-gateway").unwrap();
        assert_eq!(url, "https://horizon.example.com/api/v1/sensors/announce");
    }

    #[test]
    fn test_derive_announce_url_ws_plain() {
        let url = derive_announce_url("ws://localhost:8080/ws").unwrap();
        assert_eq!(url, "http://localhost:8080/api/v1/sensors/announce");
    }

    #[test]
    fn test_derive_announce_url_preserves_nonstandard_port() {
        let url = derive_announce_url("wss://horizon.example.com:8443/sensor-gateway").unwrap();
        assert_eq!(
            url,
            "https://horizon.example.com:8443/api/v1/sensors/announce"
        );
    }

    #[test]
    fn test_derive_announce_url_strips_query_and_fragment() {
        let url =
            derive_announce_url("wss://horizon.example.com/sensor-gateway?foo=1#frag").unwrap();
        assert_eq!(url, "https://horizon.example.com/api/v1/sensors/announce");
    }

    #[test]
    fn test_derive_announce_url_rejects_unsupported_scheme() {
        assert!(derive_announce_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_registration_token_for_auth_detects_registration_tokens() {
        assert_eq!(
            registration_token_for_auth("sh_reg_example"),
            Some("sh_reg_example".to_string())
        );
        assert_eq!(registration_token_for_auth("sensor-api-key"), None);
    }

    #[test]
    fn test_apply_sensor_api_key_handoff_updates_integrations_and_requests_restart() {
        let current = Arc::new(Mutex::new(IntegrationsConfig {
            horizon_hub_url: "wss://horizon.example.com/ws/sensors".to_string(),
            horizon_api_key: "sh_reg_pending".to_string(),
            tunnel_url: "wss://horizon.example.com/ws/tunnel/sensor".to_string(),
            tunnel_api_key: "sh_reg_pending".to_string(),
            apparatus_url: String::new(),
        }));
        let persisted = Arc::new(Mutex::new(None::<IntegrationsConfig>));
        let restart_calls = Arc::new(AtomicU32::new(0));

        let current_for_getter = Arc::clone(&current);
        let persisted_for_setter = Arc::clone(&persisted);
        register_integrations_callbacks(
            move || current_for_getter.lock().clone(),
            move |config| {
                *persisted_for_setter.lock() = Some(config);
                Ok(())
            },
        );

        let restart_calls_for_callback = Arc::clone(&restart_calls);
        register_restart_callback(move || {
            restart_calls_for_callback.fetch_add(1, Ordering::Relaxed);
            Ok(crate::admin_server::RestartResult {
                success: true,
                message: "restart requested".to_string(),
            })
        });

        let result = apply_sensor_api_key_handoff(&crate::horizon::types::ConfigPayload {
            config: None,
            version: None,
            component: None,
            action: Some("replace_sensor_api_key".to_string()),
            sensor_api_key: Some("sensor-api-key-abcdefghijklmnopqrstuvwxyz".to_string()),
            restart_process: Some(true),
            source: Some("test".to_string()),
        })
        .expect("handoff should succeed");

        let saved = persisted.lock().clone().expect("config should be persisted");
        assert_eq!(
            saved.horizon_api_key,
            "sensor-api-key-abcdefghijklmnopqrstuvwxyz"
        );
        assert_eq!(
            saved.tunnel_api_key,
            "sensor-api-key-abcdefghijklmnopqrstuvwxyz"
        );
        assert_eq!(restart_calls.load(Ordering::Relaxed), 1);
        assert_eq!(result["action"], "replace_sensor_api_key");
        assert_eq!(result["restart_requested"], true);
    }

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
        assert_eq!(stats.signals_queued, 0);
        assert_eq!(stats.signals_dropped, 0);
        assert_eq!(stats.batches_sent, 0);
        assert_eq!(stats.heartbeats_sent, 0);
    }

    #[tokio::test]
    async fn test_client_disabled() {
        let config = HorizonConfig::default();
        let client = HorizonClient::new(config);

        assert!(client.start().await.is_ok());
    }

    #[tokio::test]
    async fn test_client_blocklist_lookup() {
        let config = HorizonConfig::default();
        let client = HorizonClient::new(config);

        client
            .blocklist
            .add(super::super::blocklist::BlocklistEntry {
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

    #[tokio::test]
    async fn test_validate_hub_url_ssrf_blocks_cloud_metadata() {
        let err = validate_hub_url_ssrf("wss://169.254.169.254/ws")
            .await
            .expect_err("expected metadata IP to be blocked");
        assert!(matches!(err, HorizonError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_validate_hub_url_ssrf_blocks_loopback() {
        let err = validate_hub_url_ssrf("ws://127.0.0.1:1234/ws")
            .await
            .expect_err("expected loopback IP to be blocked");
        assert!(matches!(err, HorizonError::ConfigError(_)));
    }

    #[tokio::test]
    async fn test_validate_hub_url_ssrf_allows_public_ip() {
        validate_hub_url_ssrf("wss://8.8.8.8/ws")
            .await
            .expect("expected public IP to be allowed");
    }
}
