//! Signal Horizon Telemetry Integration Module
//!
//! Provides resilient asynchronous telemetry delivery with batching,
//! retry logic, and circuit breaker patterns for the synapse-pingora WAF proxy.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::{broadcast, Mutex, Notify};
use tracing::{debug, warn};

use crate::signals::auth_coverage::AuthCoverageSummary;

use crate::utils::circuit_breaker::CircuitBreaker;

pub mod auth_coverage_aggregator;

/// Telemetry-specific errors.
#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("telemetry endpoint unreachable: {message}")]
    EndpointUnreachable { message: String },

    #[error("circuit breaker open, rejecting telemetry")]
    CircuitBreakerOpen,

    #[error("buffer overflow, {dropped} events dropped")]
    BufferOverflow { dropped: usize },

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("send timeout after {elapsed:?}")]
    Timeout { elapsed: Duration },
}

pub type TelemetryResult<T> = Result<T, TelemetryError>;

/// Types of telemetry events.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    RequestProcessed,
    WafBlock,
    RateLimitHit,
    ConfigReload,
    ServiceHealth,
    SensorReport,
    CampaignReport,
    AuthCoverage,
    LogEntry,
}

/// Telemetry event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", content = "data", rename_all = "snake_case")]
pub enum TelemetryEvent {
    RequestProcessed {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        latency_ms: u64,
        status_code: u16,
        waf_action: Option<String>,
        site: String,
        method: String,
        path: String,
    },
    LogEntry {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        id: String,
        source: String,
        level: String,
        message: String,
        log_timestamp_ms: u64,
        fields: Option<serde_json::Value>,
        method: Option<String>,
        path: Option<String>,
        status_code: Option<u16>,
        latency_ms: Option<f64>,
        client_ip: Option<String>,
        rule_id: Option<String>,
    },
    WafBlock {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        rule_id: String,
        severity: String,
        client_ip: String,
        site: String,
        path: String,
    },
    RateLimitHit {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        client_ip: String,
        limit: u32,
        window_secs: u32,
        site: String,
    },
    ConfigReload {
        sites_loaded: usize,
        duration_ms: u64,
        success: bool,
        error: Option<String>,
    },
    ServiceHealth {
        uptime_secs: u64,
        memory_mb: u64,
        active_connections: u64,
        requests_per_sec: f64,
    },
    SensorReport {
        sensor_id: String,
        actor: ExternalActorContext,
        signal: ExternalSignalContext,
        request: ExternalRequestContext,
    },
    CampaignReport {
        campaign_id: String,
        confidence: f64,
        attack_types: Vec<String>,
        actor_count: usize,
        correlation_reasons: Vec<String>,
        timestamp_ms: u64,
    },
    AuthCoverage(AuthCoverageSummary),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalActorContext {
    pub ip: String,
    pub session_id: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalSignalContext {
    #[serde(rename = "type")]
    pub signal_type: String,
    pub severity: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalRequestContext {
    pub path: String,
    pub method: String,
    pub user_agent: Option<String>,
}

impl TelemetryEvent {
    pub fn event_type(&self) -> EventType {
        match self {
            Self::RequestProcessed { .. } => EventType::RequestProcessed,
            Self::WafBlock { .. } => EventType::WafBlock,
            Self::RateLimitHit { .. } => EventType::RateLimitHit,
            Self::ConfigReload { .. } => EventType::ConfigReload,
            Self::ServiceHealth { .. } => EventType::ServiceHealth,
            Self::SensorReport { .. } => EventType::SensorReport,
            Self::CampaignReport { .. } => EventType::CampaignReport,
            Self::AuthCoverage(_) => EventType::AuthCoverage,
            Self::LogEntry { .. } => EventType::LogEntry,
        }
    }
}

/// Timestamped event wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedEvent {
    pub timestamp_ms: u64,
    pub instance_id: Option<String>,
    pub event: TelemetryEvent,
}

impl TimestampedEvent {
    pub fn new(event: TelemetryEvent, instance_id: Option<String>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            timestamp_ms,
            instance_id,
            event,
        }
    }
}

/// Batch of telemetry events for transmission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryBatch {
    pub batch_id: String,
    pub events: Vec<TimestampedEvent>,
    pub created_at_ms: u64,
}

impl TelemetryBatch {
    pub fn new(events: Vec<TimestampedEvent>) -> Self {
        let created_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let batch_id = format!("batch-{}", created_at_ms);
        Self {
            batch_id,
            events,
            created_at_ms,
        }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

/// Thread-safe event buffer.
#[derive(Debug)]
pub struct TelemetryBuffer {
    events: Mutex<Vec<TimestampedEvent>>,
    max_size: usize,
    dropped: AtomicU64,
    notify: Notify,
}

impl TelemetryBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: Mutex::new(Vec::with_capacity(max_size.min(1000))),
            max_size,
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    pub async fn push(&self, event: TimestampedEvent) -> bool {
        let mut events = self.events.lock().await;
        if events.len() >= self.max_size {
            let dropped = self.dropped.fetch_add(1, Ordering::SeqCst);
            if dropped % 100 == 0 {
                warn!(
                    event_type = ?event.event.event_type(),
                    total_dropped = dropped + 1,
                    "Telemetry buffer overflow, dropping event"
                );
            }
            return false;
        }
        events.push(event);
        self.notify.notify_one();
        true
    }

    pub async fn drain(&self) -> Vec<TimestampedEvent> {
        let mut events = self.events.lock().await;
        std::mem::take(&mut *events)
    }

    pub async fn len(&self) -> usize {
        self.events.lock().await.len()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::SeqCst)
    }

    pub fn notified(&self) -> impl std::future::Future<Output = ()> + '_ {
        self.notify.notified()
    }
}

impl Default for TelemetryBuffer {
    fn default() -> Self {
        Self::new(10_000)
    }
}

/// Telemetry statistics.
#[derive(Debug, Default)]
pub struct TelemetryStats {
    pub events_sent: AtomicU64,
    pub batches_sent: AtomicU64,
    pub send_failures: AtomicU64,
    pub retries: AtomicU64,
}

impl TelemetryStats {
    pub fn snapshot(&self) -> TelemetryStatsSnapshot {
        TelemetryStatsSnapshot {
            events_sent: self.events_sent.load(Ordering::SeqCst),
            batches_sent: self.batches_sent.load(Ordering::SeqCst),
            send_failures: self.send_failures.load(Ordering::SeqCst),
            retries: self.retries.load(Ordering::SeqCst),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryStatsSnapshot {
    pub events_sent: u64,
    pub batches_sent: u64,
    pub send_failures: u64,
    pub retries: u64,
}

/// Configuration for telemetry client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub api_key: Option<String>,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_buffer_size: usize,
    pub circuit_breaker_threshold: u64,
    pub circuit_breaker_timeout: Duration,
    #[serde(default)]
    pub enabled_events: HashSet<EventType>,
    pub instance_id: Option<String>,
    /// When true, skips actual HTTP sending (for testing)
    #[serde(default)]
    pub dry_run: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "http://localhost:3100/telemetry".to_string(),
            api_key: None,
            batch_size: 100,
            flush_interval: Duration::from_secs(10),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            max_buffer_size: 10_000,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            enabled_events: HashSet::new(),
            instance_id: None,
            dry_run: false,
        }
    }
}

impl TelemetryConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Default::default()
        }
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn with_flush_interval(mut self, interval: Duration) -> Self {
        self.flush_interval = interval;
        self
    }

    pub fn with_instance_id(mut self, id: impl Into<String>) -> Self {
        self.instance_id = Some(id.into());
        self
    }

    pub fn with_enabled_events(mut self, events: HashSet<EventType>) -> Self {
        self.enabled_events = events;
        self
    }

    pub fn is_event_enabled(&self, event_type: &EventType) -> bool {
        self.enabled_events.is_empty() || self.enabled_events.contains(event_type)
    }
}

/// Telemetry client for sending events to Signal Horizon.
#[derive(Clone)] // Derived Clone to support Fire-and-Forget emitting
pub struct TelemetryClient {
    config: TelemetryConfig,
    buffer: Arc<TelemetryBuffer>,
    circuit_breaker: Arc<CircuitBreaker>,
    stats: Arc<TelemetryStats>,
    shutdown: broadcast::Sender<()>,
}

impl TelemetryClient {
    pub fn new(config: TelemetryConfig) -> Self {
        let buffer = Arc::new(TelemetryBuffer::new(config.max_buffer_size));
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            config.circuit_breaker_threshold,
            config.circuit_breaker_timeout,
        ));
        let (shutdown, _) = broadcast::channel(1);

        Self {
            config,
            buffer,
            circuit_breaker,
            stats: Arc::new(TelemetryStats::default()),
            shutdown,
        }
    }

    fn apply_auth_headers(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref key) = self.config.api_key {
            request
                .bearer_auth(key)
                .header("X-API-Key", key)
                .header("X-Admin-Key", key)
        } else {
            request
        }
    }

    /// Records a telemetry event.
    pub async fn record(&self, event: TelemetryEvent) -> TelemetryResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.config.is_event_enabled(&event.event_type()) {
            return Ok(());
        }

        let timestamped = TimestampedEvent::new(event, self.config.instance_id.clone());
        if !self.buffer.push(timestamped).await {
            return Err(TelemetryError::BufferOverflow { dropped: 1 });
        }

        // Auto-flush if batch size reached
        if self.buffer.len().await >= self.config.batch_size {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flushes buffered events.
    pub async fn flush(&self) -> TelemetryResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.circuit_breaker.allow_request().await {
            return Err(TelemetryError::CircuitBreakerOpen);
        }

        let events = self.buffer.drain().await;
        if events.is_empty() {
            return Ok(());
        }

        let batch = TelemetryBatch::new(events);
        self.send_batch_with_retry(&batch).await
    }

    /// Reports a single event immediately (bypassing batching).
    /// Used for critical security alerts like blocks.
    pub async fn report(&self, event: TelemetryEvent) -> TelemetryResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Map TelemetryEvent::SensorReport to the flat format expected by Risk Server
        let payload = match event {
            TelemetryEvent::SensorReport {
                sensor_id,
                actor,
                signal,
                request,
            } => {
                serde_json::json!({
                    "sensorId": sensor_id,
                    "actor": actor,
                    "signal": signal,
                    "request": request,
                    "timestamp": TimestampedEvent::new(TelemetryEvent::ServiceHealth {
                        uptime_secs: 0, memory_mb: 0, active_connections: 0, requests_per_sec: 0.0
                    }, None).timestamp_ms
                })
            }
            _ => serde_json::to_value(&event)
                .map_err(|e| TelemetryError::SerializationError(e.to_string()))?,
        };

        let client = reqwest::Client::new();
        let request = client
            .post(&self.config.endpoint)
            .json(&payload)
            .timeout(Duration::from_secs(2));
        let response = self.apply_auth_headers(request).send().await.map_err(|e| {
            TelemetryError::EndpointUnreachable {
                message: e.to_string(),
            }
        })?;

        if !response.status().is_success() {
            return Err(TelemetryError::EndpointUnreachable {
                message: format!("HTTP {}", response.status()),
            });
        }

        Ok(())
    }

    async fn send_batch_with_retry(&self, batch: &TelemetryBatch) -> TelemetryResult<()> {
        // In dry_run mode, skip actual HTTP sending but still update stats
        if self.config.dry_run {
            self.stats
                .events_sent
                .fetch_add(batch.len() as u64, Ordering::SeqCst);
            self.stats.batches_sent.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }

        let mut backoff = self.config.initial_backoff;

        for attempt in 0..=self.config.max_retries {
            match self.send_batch(batch).await {
                Ok(()) => {
                    self.circuit_breaker.record_success().await;
                    self.stats
                        .events_sent
                        .fetch_add(batch.len() as u64, Ordering::SeqCst);
                    self.stats.batches_sent.fetch_add(1, Ordering::SeqCst);
                    return Ok(());
                }
                Err(e) => {
                    if attempt < self.config.max_retries {
                        self.stats.retries.fetch_add(1, Ordering::SeqCst);
                        debug!(
                            "Telemetry send failed (attempt {}), retrying: {}",
                            attempt + 1,
                            e
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = backoff
                            .checked_mul(2)
                            .unwrap_or(self.config.max_backoff)
                            .min(self.config.max_backoff);
                    } else {
                        self.circuit_breaker.record_failure().await;
                        self.stats.send_failures.fetch_add(1, Ordering::SeqCst);
                        warn!(
                            "Telemetry send failed after {} retries: {}",
                            self.config.max_retries, e
                        );
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn send_batch(&self, batch: &TelemetryBatch) -> TelemetryResult<()> {
        debug!(
            batch_id = %batch.batch_id,
            event_count = batch.len(),
            "Sending telemetry batch to {}",
            self.config.endpoint
        );

        // Build the batch payload
        let payload = serde_json::json!({
            "batch_id": batch.batch_id.to_string(),
            "events": batch.events,
            "timestamp_ms": SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        });

        // Send HTTP POST to telemetry endpoint
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| TelemetryError::EndpointUnreachable {
                message: e.to_string(),
            })?;

        let response = client.post(&self.config.endpoint).json(&payload);
        let response = self
            .apply_auth_headers(response)
            .send()
            .await
            .map_err(|e| {
                warn!(error = %e, "Telemetry batch send failed");
                TelemetryError::EndpointUnreachable {
                    message: e.to_string(),
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            warn!(status = %status, "Telemetry endpoint returned error status");
            return Err(TelemetryError::EndpointUnreachable {
                message: format!("HTTP {}", status),
            });
        }

        debug!(batch_id = %batch.batch_id, "Telemetry batch sent successfully");
        Ok(())
    }

    /// Starts the background flush task.
    pub fn start_background_flush(&self) -> tokio::task::JoinHandle<()> {
        let client = self.clone();
        let mut shutdown = client.shutdown.subscribe();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(client.config.flush_interval);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(err) = client.flush().await {
                            debug!("Background telemetry flush failed: {}", err);
                        }
                    }
                    _ = shutdown.recv() => {
                        if let Err(err) = client.flush().await {
                            debug!("Final telemetry flush failed: {}", err);
                        }
                        break;
                    }
                }
            }
        })
    }

    /// Triggers shutdown of background tasks.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    /// Returns telemetry statistics.
    pub fn stats(&self) -> TelemetryStatsSnapshot {
        self.stats.snapshot()
    }

    /// Returns the dropped event count.
    pub fn dropped_count(&self) -> u64 {
        self.buffer.dropped_count()
    }

    /// Returns whether telemetry is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Trait for emitting arbitrary signals.
#[async_trait]
pub trait SignalEmitter: Send + Sync {
    async fn emit(&self, signal_type: &str, payload: serde_json::Value);
}

#[async_trait]
impl SignalEmitter for TelemetryClient {
    async fn emit(&self, signal_type: &str, payload: serde_json::Value) {
        if signal_type == "auth_coverage_summary" {
            if let Ok(summary) = serde_json::from_value::<AuthCoverageSummary>(payload) {
                // Clone self is cheap because it just increments ref counts of Arcs
                // Wait, TelemetryClient struct fields are Arc except config.
                // So cloning TelemetryClient is cheap.
                let _ = self.record(TelemetryEvent::AuthCoverage(summary)).await;
            }
        }
    }
}

// Convenience functions for creating events
pub fn request_processed(
    latency_ms: u64,
    status_code: u16,
    waf_action: Option<String>,
    site: String,
    method: String,
    path: String,
) -> TelemetryEvent {
    TelemetryEvent::RequestProcessed {
        request_id: None,
        latency_ms,
        status_code,
        waf_action,
        site,
        method,
        path,
    }
}

pub fn waf_block(
    rule_id: String,
    severity: String,
    client_ip: String,
    site: String,
    path: String,
) -> TelemetryEvent {
    TelemetryEvent::WafBlock {
        request_id: None,
        rule_id,
        severity,
        client_ip,
        site,
        path,
    }
}

pub fn rate_limit_hit(
    request_id: Option<String>,
    client_ip: String,
    limit: u32,
    window_secs: u32,
    site: String,
) -> TelemetryEvent {
    TelemetryEvent::RateLimitHit {
        request_id,
        client_ip,
        limit,
        window_secs,
        site,
    }
}

pub fn config_reload(
    sites_loaded: usize,
    duration_ms: u64,
    success: bool,
    error: Option<String>,
) -> TelemetryEvent {
    TelemetryEvent::ConfigReload {
        sites_loaded,
        duration_ms,
        success,
        error,
    }
}

pub fn service_health(
    uptime_secs: u64,
    memory_mb: u64,
    active_connections: u64,
    requests_per_sec: f64,
) -> TelemetryEvent {
    TelemetryEvent::ServiceHealth {
        uptime_secs,
        memory_mb,
        active_connections,
        requests_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::circuit_breaker::CircuitState;

    fn test_config() -> TelemetryConfig {
        TelemetryConfig {
            enabled: true,
            endpoint: "http://test:8080/telemetry".to_string(),
            batch_size: 10,
            flush_interval: Duration::from_millis(100),
            max_buffer_size: 100,
            dry_run: true, // Skip actual HTTP for tests
            ..Default::default()
        }
    }

    #[test]
    fn test_config_defaults() {
        let config = TelemetryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_config_builder() {
        let config = TelemetryConfig::new("http://custom:9000")
            .with_api_key("secret")
            .with_batch_size(50)
            .with_instance_id("node-1");

        assert_eq!(config.endpoint, "http://custom:9000");
        assert_eq!(config.api_key, Some("secret".to_string()));
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.instance_id, Some("node-1".to_string()));
    }

    #[test]
    fn test_event_type_classification() {
        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
        assert_eq!(event.event_type(), EventType::RequestProcessed);

        let event = waf_block(
            "rule-1".into(),
            "high".into(),
            "1.2.3.4".into(),
            "site".into(),
            "/".into(),
        );
        assert_eq!(event.event_type(), EventType::WafBlock);

        let event = TelemetryEvent::LogEntry {
            request_id: None,
            id: "log-1".into(),
            source: "access".into(),
            level: "info".into(),
            message: "GET /".into(),
            log_timestamp_ms: 1234,
            fields: None,
            method: Some("GET".into()),
            path: Some("/".into()),
            status_code: Some(200),
            latency_ms: Some(12.5),
            client_ip: Some("203.0.113.1".into()),
            rule_id: None,
        };
        assert_eq!(event.event_type(), EventType::LogEntry);

        let event = rate_limit_hit(None, "1.2.3.4".into(), 100, 60, "site".into());
        assert_eq!(event.event_type(), EventType::RateLimitHit);

        let event = config_reload(5, 100, true, None);
        assert_eq!(event.event_type(), EventType::ConfigReload);

        let event = service_health(3600, 512, 100, 1000.0);
        assert_eq!(event.event_type(), EventType::ServiceHealth);
    }

    #[test]
    fn test_event_serialization() {
        let event = request_processed(
            100,
            200,
            Some("pass".into()),
            "site".into(),
            "GET".into(),
            "/api".into(),
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("request_processed"));
        assert!(json.contains("100"));
    }

    #[test]
    fn test_request_id_serialization() {
        let event = TelemetryEvent::RequestProcessed {
            request_id: Some("req_123".into()),
            latency_ms: 100,
            status_code: 200,
            waf_action: None,
            site: "site".into(),
            method: "GET".into(),
            path: "/".into(),
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "request_processed");
        assert_eq!(value["data"]["request_id"], "req_123");
    }

    #[test]
    fn test_log_entry_request_id_serialization() {
        let event = TelemetryEvent::LogEntry {
            request_id: Some("req_456".into()),
            id: "log-1".into(),
            source: "access".into(),
            level: "info".into(),
            message: "GET /".into(),
            log_timestamp_ms: 1234,
            fields: None,
            method: Some("GET".into()),
            path: Some("/".into()),
            status_code: Some(200),
            latency_ms: Some(12.5),
            client_ip: Some("203.0.113.1".into()),
            rule_id: None,
        };
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(value["event_type"], "log_entry");
        assert_eq!(value["data"]["request_id"], "req_456");
    }

    #[test]
    fn test_timestamped_event() {
        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
        let timestamped = TimestampedEvent::new(event, Some("node-1".to_string()));

        assert!(timestamped.timestamp_ms > 0);
        assert_eq!(timestamped.instance_id, Some("node-1".to_string()));
    }

    #[test]
    fn test_batch_creation() {
        let events: Vec<TimestampedEvent> = (0..5)
            .map(|i| {
                let event =
                    request_processed(i * 10, 200, None, "site".into(), "GET".into(), "/".into());
                TimestampedEvent::new(event, None)
            })
            .collect();

        let batch = TelemetryBatch::new(events);
        assert_eq!(batch.len(), 5);
        assert!(!batch.is_empty());
        assert!(batch.batch_id.starts_with("batch-"));
    }

    #[tokio::test]
    async fn test_circuit_breaker_closed() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.allow_request().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));

        for _ in 0..3 {
            cb.record_failure().await;
        }

        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.allow_request().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_resets() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));

        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;

        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.allow_request().await);
    }

    #[tokio::test]
    async fn test_buffer_push_and_drain() {
        let buffer = TelemetryBuffer::new(10);
        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
        let timestamped = TimestampedEvent::new(event, None);

        assert!(buffer.push(timestamped).await);
        assert_eq!(buffer.len().await, 1);

        let drained = buffer.drain().await;
        assert_eq!(drained.len(), 1);
        assert_eq!(buffer.len().await, 0);
    }

    #[tokio::test]
    async fn test_buffer_overflow() {
        let buffer = TelemetryBuffer::new(2);

        for _ in 0..3 {
            let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
            let timestamped = TimestampedEvent::new(event, None);
            buffer.push(timestamped).await;
        }

        assert_eq!(buffer.len().await, 2);
        assert_eq!(buffer.dropped_count(), 1);
    }

    #[tokio::test]
    async fn test_client_record_event() {
        let client = TelemetryClient::new(test_config());
        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());

        let result = client.record(event).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_client_flush() {
        let client = TelemetryClient::new(test_config());

        for _ in 0..5 {
            let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
            client.record(event).await.unwrap();
        }

        let result = client.flush().await;
        assert!(result.is_ok());

        let stats = client.stats();
        assert_eq!(stats.events_sent, 5);
        assert_eq!(stats.batches_sent, 1);
    }

    #[tokio::test]
    async fn test_client_auto_flush_on_batch_size() {
        let mut config = test_config();
        config.batch_size = 3;
        let client = TelemetryClient::new(config);

        for _ in 0..3 {
            let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
            client.record(event).await.unwrap();
        }

        // Should have auto-flushed
        let stats = client.stats();
        assert_eq!(stats.events_sent, 3);
    }

    #[tokio::test]
    async fn test_client_disabled() {
        let mut config = test_config();
        config.enabled = false;
        let client = TelemetryClient::new(config);

        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
        let result = client.record(event).await;
        assert!(result.is_ok());

        let stats = client.stats();
        assert_eq!(stats.events_sent, 0);
    }

    #[tokio::test]
    async fn test_client_event_filtering() {
        let mut config = test_config();
        config.enabled_events = [EventType::WafBlock].into_iter().collect();
        let client = TelemetryClient::new(config);

        // This event type is not enabled
        let event = request_processed(100, 200, None, "site".into(), "GET".into(), "/".into());
        client.record(event).await.unwrap();

        // This event type is enabled
        let event = waf_block(
            "rule-1".into(),
            "high".into(),
            "1.2.3.4".into(),
            "site".into(),
            "/".into(),
        );
        client.record(event).await.unwrap();

        client.flush().await.unwrap();
        let stats = client.stats();
        assert_eq!(stats.events_sent, 1);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = TelemetryStats::default();
        stats.events_sent.store(100, Ordering::SeqCst);
        stats.batches_sent.store(10, Ordering::SeqCst);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.events_sent, 100);
        assert_eq!(snapshot.batches_sent, 10);
    }

    #[test]
    fn test_config_event_enabled() {
        let mut config = TelemetryConfig::default();
        // Empty means all enabled
        assert!(config.is_event_enabled(&EventType::WafBlock));

        config.enabled_events = [EventType::WafBlock].into_iter().collect();
        assert!(config.is_event_enabled(&EventType::WafBlock));
        assert!(!config.is_event_enabled(&EventType::RequestProcessed));
    }
}
