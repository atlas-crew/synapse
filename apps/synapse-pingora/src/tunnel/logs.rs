//! Log streaming service for Signal Horizon tunnel.
//!
//! Subscribes to log stream requests from Signal Horizon and
//! forwards filtered log entries over the tunnel connection.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Once, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, warn};

use super::client::TunnelClientHandle;
use super::types::{TunnelChannel, TunnelEnvelope};
use crate::metrics::MetricsRegistry;
use crate::telemetry::{TelemetryClient, TelemetryEvent};

const LOG_CHANNEL_BUFFER: usize = 2048;
const LOG_CACHE_SIZE: usize = 1000;
const DEFAULT_BACKFILL: usize = 200;

#[derive(Clone, Debug)]
pub struct LogStreamEntry {
    pub id: String,
    pub request_id: Option<String>,
    pub timestamp_ms: u64,
    pub timestamp: String,
    pub source: String,
    pub level: String,
    pub message: String,
    pub fields: Option<Value>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub latency_ms: Option<f64>,
    pub client_ip: Option<String>,
    pub rule_id: Option<String>,
}

impl LogStreamEntry {
    fn new(
        source: impl Into<String>,
        level: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let timestamp = chrono::Utc::now();
        Self {
            id: fastrand::u64(..).to_string(),
            request_id: None,
            timestamp_ms: timestamp.timestamp_millis().max(0) as u64,
            timestamp: timestamp.to_rfc3339(),
            source: source.into(),
            level: level.into(),
            message: message.into(),
            fields: None,
            method: None,
            path: None,
            status_code: None,
            latency_ms: None,
            client_ip: None,
            rule_id: None,
        }
    }

    fn to_entry_payload(&self) -> Value {
        let mut entry = serde_json::json!({
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source,
            "level": self.level,
            "message": self.message,
            "logTimestamp": self.timestamp_ms,
        });

        if let Some(request_id) = &self.request_id {
            entry["requestId"] = Value::String(request_id.clone());
        }
        if let Some(fields) = &self.fields {
            entry["fields"] = fields.clone();
        }
        if let Some(method) = &self.method {
            entry["method"] = Value::String(method.clone());
        }
        if let Some(path) = &self.path {
            entry["path"] = Value::String(path.clone());
        }
        if let Some(status_code) = self.status_code {
            entry["statusCode"] = Value::Number(serde_json::Number::from(status_code as u64));
        }
        if let Some(latency_ms) = self.latency_ms {
            entry["latencyMs"] = Value::Number(
                serde_json::Number::from_f64(latency_ms)
                    .unwrap_or_else(|| serde_json::Number::from(0)),
            );
        }
        if let Some(client_ip) = &self.client_ip {
            entry["clientIp"] = Value::String(client_ip.clone());
        }
        if let Some(rule_id) = &self.rule_id {
            entry["ruleId"] = Value::String(rule_id.clone());
        }

        entry
    }

    fn flat_fields(&self) -> serde_json::Map<String, Value> {
        let mut fields = serde_json::Map::new();
        fields.insert("source".to_string(), Value::String(self.source.clone()));
        fields.insert("level".to_string(), Value::String(self.level.clone()));
        fields.insert("message".to_string(), Value::String(self.message.clone()));
        fields.insert(
            "logTimestamp".to_string(),
            Value::Number(self.timestamp_ms.into()),
        );

        if let Some(request_id) = &self.request_id {
            fields.insert("requestId".to_string(), Value::String(request_id.clone()));
        }
        if let Some(extra) = &self.fields {
            fields.insert("fields".to_string(), extra.clone());
        }
        if let Some(method) = &self.method {
            fields.insert("method".to_string(), Value::String(method.clone()));
        }
        if let Some(path) = &self.path {
            fields.insert("path".to_string(), Value::String(path.clone()));
        }
        if let Some(status_code) = self.status_code {
            fields.insert(
                "statusCode".to_string(),
                Value::Number((status_code as u64).into()),
            );
        }
        if let Some(latency_ms) = self.latency_ms {
            fields.insert(
                "latencyMs".to_string(),
                Value::Number(
                    serde_json::Number::from_f64(latency_ms)
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ),
            );
        }
        if let Some(client_ip) = &self.client_ip {
            fields.insert("clientIp".to_string(), Value::String(client_ip.clone()));
        }
        if let Some(rule_id) = &self.rule_id {
            fields.insert("ruleId".to_string(), Value::String(rule_id.clone()));
        }

        fields
    }
}

struct LogStreamState {
    sender: broadcast::Sender<LogStreamEntry>,
    buffer: RwLock<VecDeque<LogStreamEntry>>,
}

static LOG_STREAM: Lazy<LogStreamState> = Lazy::new(|| {
    let (sender, _) = broadcast::channel(LOG_CHANNEL_BUFFER);
    LogStreamState {
        sender,
        buffer: RwLock::new(VecDeque::with_capacity(LOG_CACHE_SIZE)),
    }
});
static LOG_TAILERS_STARTED: Once = Once::new();

fn push_to_buffer(entry: &LogStreamEntry) {
    let mut buffer = LOG_STREAM
        .buffer
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if buffer.len() >= LOG_CACHE_SIZE {
        buffer.pop_front();
    }
    buffer.push_back(entry.clone());
}

pub fn publish_log(entry: LogStreamEntry) {
    push_to_buffer(&entry);
    let _ = LOG_STREAM.sender.send(entry);
}

pub fn publish_internal_log(level: &str, source: &str, message: String) {
    publish_log(LogStreamEntry::new(source, level, message));
}

pub fn publish_access_log(
    method: &str,
    path: &str,
    status_code: u16,
    latency_ms: f64,
    client_ip: Option<&str>,
    request_id: Option<&str>,
) {
    let level = if status_code >= 500 {
        "error"
    } else if status_code >= 400 {
        "warn"
    } else {
        "info"
    };

    let mut entry = LogStreamEntry::new(
        "access",
        level,
        format!("{} {} status={}", method, path, status_code),
    );
    entry.method = Some(method.to_string());
    entry.path = Some(path.to_string());
    entry.status_code = Some(status_code);
    entry.latency_ms = Some(latency_ms);
    entry.client_ip = client_ip.map(|ip| ip.to_string());
    entry.request_id = request_id.map(|v| v.to_string());

    publish_log(entry);
}

pub fn publish_waf_log(
    rule_ids: &[u32],
    risk_score: u16,
    client_ip: Option<&str>,
    path: Option<&str>,
    message: String,
    request_id: Option<&str>,
) {
    let level = if risk_score >= 80 {
        "error"
    } else if risk_score >= 50 {
        "warn"
    } else {
        "info"
    };

    let mut entry = LogStreamEntry::new("waf", level, message);
    if let Some(first) = rule_ids.first() {
        entry.rule_id = Some(first.to_string());
    }
    entry.client_ip = client_ip.map(|ip| ip.to_string());
    entry.path = path.map(|p| p.to_string());
    entry.request_id = request_id.map(|v| v.to_string());
    entry.fields = Some(serde_json::json!({
        "riskScore": risk_score,
        "ruleIds": rule_ids,
    }));

    publish_log(entry);
}

fn subscribe_logs() -> broadcast::Receiver<LogStreamEntry> {
    LOG_STREAM.sender.subscribe()
}

fn recent_logs(limit: usize) -> Vec<LogStreamEntry> {
    let buffer = LOG_STREAM
        .buffer
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let take = limit.min(buffer.len());
    buffer.iter().rev().take(take).cloned().collect()
}

#[derive(Clone, Debug, Default)]
struct LogStreamFilter {
    sources: Option<HashSet<String>>,
    levels: Option<HashSet<String>>,
    search: Option<String>,
    since_ms: Option<u64>,
}

impl LogStreamFilter {
    fn matches(&self, entry: &LogStreamEntry) -> bool {
        if let Some(sources) = &self.sources {
            if !sources.contains(&entry.source) {
                return false;
            }
        }

        if let Some(levels) = &self.levels {
            if !levels.contains(&entry.level) {
                return false;
            }
        }

        if let Some(since_ms) = self.since_ms {
            if entry.timestamp_ms < since_ms {
                return false;
            }
        }

        if let Some(search) = &self.search {
            let search_lower = search.to_lowercase();
            let mut haystack = entry.message.to_lowercase();
            if let Some(path) = &entry.path {
                haystack.push_str(path);
            }
            if let Some(client_ip) = &entry.client_ip {
                haystack.push_str(client_ip);
            }
            if let Some(rule_id) = &entry.rule_id {
                haystack.push_str(rule_id);
            }
            if !haystack.contains(&search_lower) {
                return false;
            }
        }

        true
    }
}

struct LogSession {
    filter: Arc<RwLock<LogStreamFilter>>,
    task: JoinHandle<()>,
}

/// Tunnel service for log streaming.
pub struct TunnelLogService {
    handle: TunnelClientHandle,
    sessions: Arc<DashMap<String, LogSession>>,
    metrics: Arc<MetricsRegistry>,
}

impl TunnelLogService {
    pub fn new(handle: TunnelClientHandle, metrics: Arc<MetricsRegistry>) -> Self {
        Self {
            handle,
            sessions: Arc::new(DashMap::new()),
            metrics,
        }
    }

    pub async fn run(self, mut shutdown_rx: broadcast::Receiver<()>) {
        start_log_tailers();
        let mut rx = self.handle.subscribe_channel(TunnelChannel::Logs);
        loop {
            tokio::select! {
                message = rx.recv() => {
                    match message {
                        Ok(envelope) => {
                            let started = Instant::now();
                            self.handle_message(envelope).await;
                            self.metrics
                                .tunnel_metrics()
                                .record_handler_latency_ms(
                                    TunnelChannel::Logs,
                                    started.elapsed().as_millis() as u64,
                                );
                        }
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            warn!("Log service lagged by {} messages", count);
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            warn!("Log service channel closed");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    debug!("Log service shutdown signal received");
                    break;
                }
            }
        }

        // Stop all active log sessions
        let session_ids: Vec<String> = self.sessions.iter().map(|e| e.key().clone()).collect();
        for id in session_ids {
            self.stop_session(&id);
        }
    }

    async fn handle_message(&self, envelope: TunnelEnvelope) {
        let Some(message_type) = envelope.raw.get("type").and_then(|v| v.as_str()) else {
            return;
        };

        let session_id = envelope.session_id.clone().or_else(|| {
            envelope
                .raw
                .get("sessionId")
                .and_then(|v| v.as_str())
                .map(|v| v.to_string())
        });

        match message_type {
            "subscribe" => {
                if let Some(session_id) = session_id {
                    self.start_session(&session_id, &envelope.raw).await;
                } else {
                    warn!("Log subscribe missing sessionId");
                }
            }
            "unsubscribe" => {
                if let Some(session_id) = session_id {
                    self.stop_session(&session_id);
                }
            }
            "filter" => {
                if let Some(session_id) = session_id {
                    self.update_filter(&session_id, &envelope.raw);
                }
            }
            "session-close" | "session-closed" => {
                if let Some(session_id) = session_id {
                    self.stop_session(&session_id);
                }
            }
            _ => {}
        }
    }

    async fn start_session(&self, session_id: &str, payload: &Value) {
        if self.sessions.contains_key(session_id) {
            self.update_filter(session_id, payload);
            return;
        }

        let filter = Arc::new(RwLock::new(parse_filter(payload)));
        let backfill_enabled = payload
            .get("backfill")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let backfill_lines = payload
            .get("backfillLines")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(DEFAULT_BACKFILL);
        let mut rx = subscribe_logs();
        let handle = self.handle.clone();
        let session_id = session_id.to_string();
        let task_session_id = session_id.clone();
        let filter_ref = Arc::clone(&filter);

        let task = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        let passes = filter_ref
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .matches(&entry);
                        if !passes {
                            continue;
                        }

                        let mut message = serde_json::json!({
                            "type": "entry",
                            "channel": "logs",
                            "sessionId": task_session_id.as_str(),
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                        });
                        if let Value::Object(ref mut map) = message {
                            map.extend(entry.flat_fields());
                        }
                        let _ = handle.try_send_json(message);
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        debug!("Log stream lagged by {} messages", count);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        self.sessions
            .insert(session_id.clone(), LogSession { filter, task });

        if backfill_enabled {
            self.send_backfill(&session_id, backfill_lines).await;
        }
    }

    fn stop_session(&self, session_id: &str) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            session.task.abort();
        }
    }

    fn update_filter(&self, session_id: &str, payload: &Value) {
        if let Some(session) = self.sessions.get(session_id) {
            let mut filter = session
                .filter
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *filter = parse_filter(payload);
        }
    }

    async fn send_backfill(&self, session_id: &str, limit: usize) {
        let entries = recent_logs(limit);
        if entries.is_empty() {
            return;
        }

        let filter = self
            .sessions
            .get(session_id)
            .map(|session| session.filter.clone());
        let Some(filter) = filter else {
            return;
        };

        let filter_guard = filter
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let filtered: Vec<Value> = entries
            .into_iter()
            .filter(|entry| filter_guard.matches(entry))
            .map(|entry| entry.to_entry_payload())
            .collect();

        if filtered.is_empty() {
            return;
        }

        let batch = serde_json::json!({
            "type": "log-batch",
            "channel": "logs",
            "sessionId": session_id,
            "entries": filtered,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let _ = self.handle.try_send_json(batch);

        let complete = serde_json::json!({
            "type": "backfill-complete",
            "channel": "logs",
            "sessionId": session_id,
            "count": filtered.len(),
            "sources": serde_json::json!(["access", "waf", "system", "audit", "error"]),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        let _ = self.handle.try_send_json(complete);
    }
}

/// Telemetry-forwarding service for log entries.
pub struct LogTelemetryService {
    telemetry: Arc<TelemetryClient>,
}

impl LogTelemetryService {
    pub fn new(telemetry: Arc<TelemetryClient>) -> Self {
        Self { telemetry }
    }

    pub async fn run(self) {
        start_log_tailers();
        if !self.telemetry.is_enabled() {
            return;
        }

        let mut rx = subscribe_logs();
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    let event = TelemetryEvent::LogEntry {
                        request_id: entry.request_id.clone(),
                        id: entry.id.clone(),
                        source: entry.source.clone(),
                        level: entry.level.clone(),
                        message: entry.message.clone(),
                        log_timestamp_ms: entry.timestamp_ms,
                        fields: entry.fields.clone(),
                        method: entry.method.clone(),
                        path: entry.path.clone(),
                        status_code: entry.status_code,
                        latency_ms: entry.latency_ms,
                        client_ip: entry.client_ip.clone(),
                        rule_id: entry.rule_id.clone(),
                    };

                    if let Err(err) = self.telemetry.record(event).await {
                        warn!("Failed to record log telemetry: {}", err);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    debug!("Log telemetry lagged by {} entries", count);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
}

fn parse_filter(payload: &Value) -> LogStreamFilter {
    let filter_value = payload.get("filter").unwrap_or(payload);

    let sources = filter_value
        .get("sources")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<HashSet<_>>()
        });

    let levels = filter_value
        .get("levels")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<HashSet<_>>()
        });

    let search = filter_value
        .get("search")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let since_ms = filter_value.get("since").and_then(|value| {
        if let Some(s) = value.as_str() {
            chrono::DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.timestamp_millis().max(0) as u64)
        } else if let Some(ms) = value.as_u64() {
            Some(ms)
        } else {
            None
        }
    });

    LogStreamFilter {
        sources,
        levels,
        search,
        since_ms,
    }
}

fn start_log_tailers() {
    LOG_TAILERS_STARTED.call_once(|| {
        let kernel_paths = [
            "/var/log/kern.log",
            "/var/log/kernel.log",
            "/var/log/messages",
        ];
        let syslog_paths = ["/var/log/syslog", "/var/log/messages"];

        for path in kernel_paths {
            if std::path::Path::new(path).exists() {
                spawn_tailer(path.to_string(), "kernel");
            }
        }

        for path in syslog_paths {
            if std::path::Path::new(path).exists() {
                spawn_tailer(path.to_string(), "syslog");
            }
        }
    });
}

fn spawn_tailer(path: String, subsource: &'static str) {
    tokio::spawn(async move {
        if let Err(err) = tail_file(path.clone(), subsource).await {
            warn!("Failed to tail {}: {}", path, err);
        }
    });
}

async fn tail_file(path: String, subsource: &'static str) -> Result<(), String> {
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|err| format!("open error: {}", err))?;

    // Get initial metadata to track rotation
    let mut last_metadata = file.metadata().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(file);
    reader
        .seek(std::io::SeekFrom::End(0))
        .await
        .map_err(|err| format!("seek error: {}", err))?;

    let mut last_rotation_check = Instant::now();

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .await
            .map_err(|err| format!("read error: {}", err))?;

        if bytes == 0 {
            // Periodically check for rotation (every 5 seconds or when idle)
            if last_rotation_check.elapsed() > Duration::from_secs(5) {
                if let Ok(current_metadata) = tokio::fs::metadata(&path).await {
                    let rotated = if let (Some(old_ino), Some(new_ino)) =
                        (get_inode(&last_metadata), get_inode(&current_metadata))
                    {
                        old_ino != new_ino
                    } else {
                        // Fallback to size/mtime if inodes not available or comparable
                        current_metadata.len() < last_metadata.len()
                    };

                    if rotated {
                        debug!("Log file {} rotated, re-opening", path);
                        let new_file = tokio::fs::File::open(&path)
                            .await
                            .map_err(|err| format!("re-open error: {}", err))?;
                        last_metadata = new_file.metadata().await.map_err(|e| e.to_string())?;
                        reader = BufReader::new(new_file);
                        // Start reading from the beginning of the new file
                    }
                }
                last_rotation_check = Instant::now();
            }

            sleep(Duration::from_millis(250)).await;
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let level = infer_level(trimmed);
        let mut entry = LogStreamEntry::new("system", level, trimmed.to_string());
        entry.fields = Some(serde_json::json!({
            "subsource": subsource,
            "path": path,
        }));
        publish_log(entry);
    }
}

#[cfg(unix)]
fn get_inode(metadata: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.ino())
}

#[cfg(not(unix))]
fn get_inode(_metadata: &std::fs::Metadata) -> Option<u64> {
    None
}

fn infer_level(line: &str) -> &'static str {
    let lower = line.to_lowercase();
    if lower.contains("fatal") || lower.contains("panic") {
        "fatal"
    } else if lower.contains("error") || lower.contains("failed") {
        "error"
    } else if lower.contains("warn") {
        "warn"
    } else if lower.contains("debug") {
        "debug"
    } else if lower.contains("trace") {
        "trace"
    } else {
        "info"
    }
}
