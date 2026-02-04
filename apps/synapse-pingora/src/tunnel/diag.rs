//! Diagnostics channel handler for the Signal Horizon tunnel.
//!
//! Responds to diagnostic requests over the tunnel channel and returns
//! health, memory, connections, rules, actors, config, metrics, threads,
//! and cache snapshots.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::broadcast;
use tracing::warn;

use crate::actor::ActorManager;
use crate::config_manager::ConfigManager;
use crate::health::{HealthChecker, HealthStatus};
use crate::metrics::MetricsRegistry;

use super::client::TunnelClientHandle;
use super::types::{TunnelChannel, TunnelEnvelope};

/// Diagnostics channel handler for tunnel messages.
pub struct TunnelDiagService {
    handle: TunnelClientHandle,
    health: Arc<HealthChecker>,
    metrics: Arc<MetricsRegistry>,
    actor_manager: Arc<ActorManager>,
    config_manager: Option<Arc<ConfigManager>>,
}

impl TunnelDiagService {
    pub fn new(
        handle: TunnelClientHandle,
        health: Arc<HealthChecker>,
        metrics: Arc<MetricsRegistry>,
        actor_manager: Arc<ActorManager>,
        config_manager: Option<Arc<ConfigManager>>,
    ) -> Self {
        Self {
            handle,
            health,
            metrics,
            actor_manager,
            config_manager,
        }
    }

    pub async fn run(self, mut shutdown_rx: broadcast::Receiver<()>) {
        let mut rx = self.handle.subscribe_channel(TunnelChannel::Diag);
        loop {
            tokio::select! {
                envelope = rx.recv() => {
                    match envelope {
                        Ok(envelope) => self.handle_message(envelope).await,
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            warn!("Diag service lagged by {} messages", count);
                            continue;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            warn!("Diag service channel closed");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::debug!("Diag service shutdown signal received");
                    break;
                }
            }
        }
    }

    async fn handle_message(&self, envelope: TunnelEnvelope) {
        let Some(message_type) = envelope.raw.get("type").and_then(|v| v.as_str()) else {
            return;
        };

        if message_type != "request" {
            return;
        }

        let diag_type = envelope
            .raw
            .get("diagType")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let request_id = envelope
            .raw
            .get("requestId")
            .and_then(|v| v.as_str())
            .or_else(|| envelope.session_id.as_deref())
            .unwrap_or("unknown");

        let session_id = envelope
            .session_id
            .clone()
            .unwrap_or_else(|| request_id.to_string());

        let sequence_id = envelope.sequence_id.unwrap_or(0);
        let now_ms = now_ms();

        let start = std::time::Instant::now();
        let payload = match diag_type {
            "health" => self.build_health(),
            "memory" => self.build_memory(),
            "connections" => self.build_connections(),
            "rules" => self.build_rules(),
            "actors" => self.build_actors(),
            "config" => self.build_config(),
            "metrics" => self.build_metrics(),
            "threads" => self.build_threads(),
            "cache" => self.build_cache(),
            _ => {
                self.send_error(
                    &session_id,
                    request_id,
                    sequence_id,
                    "UNSUPPORTED_DIAG",
                    format!("Unsupported diagnostic type: {}", diag_type),
                );
                return;
            }
        };
        let duration_ms = start.elapsed().as_millis() as u64;

        let response = serde_json::json!({
            "channel": "diag",
            "type": "response",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": now_ms,
            "requestId": request_id,
            "data": payload,
            "collectionTimeMs": duration_ms,
        });

        let _ = self.handle.try_send_json(response);
    }

    fn build_health(&self) -> Value {
        let health = self.health.check();
        let mut components = Vec::new();

        let backend_status = if health.backends.unhealthy > 0 {
            "degraded"
        } else {
            "healthy"
        };
        components.push(serde_json::json!({
            "name": "backends",
            "status": backend_status,
            "message": format!(
                "{} healthy / {} total",
                health.backends.healthy,
                health.backends.total
            ),
        }));

        let waf_status = if health.waf.block_rate_percent > 50.0 {
            "degraded"
        } else {
            "healthy"
        };
        components.push(serde_json::json!({
            "name": "waf",
            "status": waf_status,
            "message": format!(
                "analyzed={} blocked={} ({:.1}%)",
                health.waf.analyzed,
                health.waf.blocked,
                health.waf.block_rate_percent
            ),
        }));

        serde_json::json!({
            "diagType": "health",
            "status": match health.status {
                HealthStatus::Healthy => "healthy",
                HealthStatus::Degraded => "degraded",
                HealthStatus::Unhealthy => "unhealthy",
            },
            "uptime": health.uptime_secs,
            "version": env!("CARGO_PKG_VERSION"),
            "components": components,
        })
    }

    fn build_memory(&self) -> Value {
        let mut sys = System::new_all();
        sys.refresh_memory();

        let total_bytes = sys.total_memory() * 1024;
        let used_bytes = sys.used_memory() * 1024;

        serde_json::json!({
            "diagType": "memory",
            "heapUsed": used_bytes,
            "heapTotal": total_bytes,
            "heapLimit": total_bytes,
            "external": 0,
            "rss": used_bytes,
            "arrayBuffers": 0,
        })
    }

    fn build_connections(&self) -> Value {
        serde_json::json!({
            "diagType": "connections",
            "activeConnections": 0,
            "maxConnections": 0,
            "connectionsByType": {},
            "recentConnections": [],
        })
    }

    fn build_rules(&self) -> Value {
        let mut total_rules = 0u64;
        let mut enabled = 0u64;
        let mut disabled = 0u64;
        let mut rules_by_category: HashMap<String, u64> = HashMap::new();
        let mut top_rules: Vec<(String, String, u64, u64)> = Vec::new();
        let mut last_updated = 0u64;
        let mut rules_hash = String::new();

        if let Some(manager) = &self.config_manager {
            let rules = manager.list_rules();
            total_rules = rules.len() as u64;
            enabled = 0;
            disabled = 0;

            for rule in &rules {
                let is_enabled = rule.meta.enabled.unwrap_or(true);
                if is_enabled {
                    enabled += 1;
                } else {
                    disabled += 1;
                }

                let category = rule
                    .meta
                    .rule_type
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                *rules_by_category.entry(category).or_insert(0) += 1;

                let hit_count = rule.meta.hit_count.unwrap_or(0);
                if hit_count > 0 {
                    let last_hit = rule
                        .meta
                        .last_hit
                        .as_deref()
                        .and_then(parse_rfc3339_ms)
                        .unwrap_or(0);
                    top_rules.push((
                        rule.rule.id.to_string(),
                        rule.meta
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("rule-{}", rule.rule.id)),
                        hit_count,
                        last_hit,
                    ));
                }

                if let Some(updated_at) = rule.meta.updated_at.as_deref() {
                    if let Some(updated_ms) = parse_rfc3339_ms(updated_at) {
                        if updated_ms > last_updated {
                            last_updated = updated_ms;
                        }
                    }
                }
            }

            rules_hash = manager.rules_hash();
        }

        top_rules.sort_by(|a, b| b.2.cmp(&a.2));
        top_rules.truncate(10);

        serde_json::json!({
            "diagType": "rules",
            "totalRules": total_rules,
            "enabledRules": enabled,
            "disabledRules": disabled,
            "rulesByCategory": rules_by_category,
            "lastUpdated": last_updated,
            "rulesHash": rules_hash,
            "topTriggeredRules": top_rules.into_iter().map(|(id, name, count, last)| {
                serde_json::json!({
                    "id": id,
                    "name": name,
                    "triggerCount": count,
                    "lastTriggered": last,
                })
            }).collect::<Vec<_>>(),
        })
    }

    fn build_actors(&self) -> Value {
        let stats = self.actor_manager.stats().snapshot();
        let mut actors = self.actor_manager.snapshot();

        actors.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));
        actors.truncate(10);

        let top = actors
            .into_iter()
            .map(|actor| {
                let actor_type = if !actor.ips.is_empty() {
                    "ip"
                } else if !actor.fingerprints.is_empty() {
                    "fingerprint"
                } else {
                    "unknown"
                };
                let risk_score = actor.risk_score.clamp(0.0, 100.0);
                serde_json::json!({
                    "id": actor.actor_id,
                    "type": actor_type,
                    "riskScore": risk_score,
                    "hitCount": actor.rule_matches.len() as u64,
                    "lastSeen": actor.last_seen,
                })
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "diagType": "actors",
            "trackedActors": stats.total_actors,
            "blockedActors": stats.blocked_actors,
            "actorsByType": {},
            "topActors": top,
        })
    }

    fn build_config(&self) -> Value {
        let now = now_ms();
        let mut config_hash = String::new();
        let mut settings = Map::new();

        if let Some(manager) = &self.config_manager {
            let config = manager.get_full_config();
            config_hash = manager.config_hash();
            let site_count = config.sites.len();
            let waf_enabled = config
                .sites
                .iter()
                .filter(|site| site.waf.as_ref().map(|w| w.enabled).unwrap_or(false))
                .count();
            let tls_sites = config.sites.iter().filter(|site| site.tls.is_some()).count();

            settings.insert("siteCount".to_string(), Value::Number(site_count.into()));
            settings.insert("wafEnabledSites".to_string(), Value::Number(waf_enabled.into()));
            settings.insert("tlsSiteCount".to_string(), Value::Number(tls_sites.into()));
        }

        serde_json::json!({
            "diagType": "config",
            "configHash": config_hash,
            "lastUpdated": now,
            "settings": Value::Object(settings),
        })
    }

    fn build_metrics(&self) -> Value {
        let total = self.metrics.total_requests();
        let errors = self.metrics.error_requests();
        let mut error_rate = if total > 0 {
            errors as f64 / total as f64
        } else {
            0.0
        };
        if error_rate > 1.0 {
            error_rate = 1.0;
        } else if error_rate < 0.0 {
            error_rate = 0.0;
        }
        let rps = self.metrics.requests_last_minute() as f64 / 60.0;
        let bandwidth = self.metrics.get_bandwidth_stats();

        serde_json::json!({
            "diagType": "metrics",
            "requestsTotal": total,
            "requestsPerSecond": rps,
            "latencyP50": self.metrics.latency_percentile_ms(0.50),
            "latencyP95": self.metrics.latency_percentile_ms(0.95),
            "latencyP99": self.metrics.latency_percentile_ms(0.99),
            "errorsTotal": errors,
            "errorRate": error_rate,
            "bytesIn": bandwidth.total_bytes_in,
            "bytesOut": bandwidth.total_bytes_out,
        })
    }

    fn build_threads(&self) -> Value {
        let cpu_count = System::new_all().cpus().len() as u64;
        serde_json::json!({
            "diagType": "threads",
            "workerThreads": cpu_count,
            "activeThreads": 0,
            "pendingTasks": 0,
            "completedTasks": 0,
            "threadPool": [],
        })
    }

    fn build_cache(&self) -> Value {
        serde_json::json!({
            "diagType": "cache",
            "caches": [],
        })
    }

    fn send_error(
        &self,
        session_id: &str,
        request_id: &str,
        sequence_id: u64,
        code: &str,
        message: String,
    ) {
        let payload = serde_json::json!({
            "channel": "diag",
            "type": "error",
            "sessionId": session_id,
            "sequenceId": sequence_id,
            "timestamp": now_ms(),
            "requestId": request_id,
            "code": code,
            "message": message,
        });
        let _ = self.handle.try_send_json(payload);
    }
}

fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn parse_rfc3339_ms(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp_millis().max(0) as u64)
}
