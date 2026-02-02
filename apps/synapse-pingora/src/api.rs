//! Management HTTP API for runtime configuration and monitoring.
//!
//! Provides REST endpoints for:
//! - Health status (`GET /health`)
//! - Prometheus metrics (`GET /metrics`)
//! - Configuration reload (`POST /reload`)
//! - Site management (`GET/POST/PUT/DELETE /sites`)
//! - WAF statistics (`GET /waf/stats`)
//! - Site-specific configuration (`PUT /sites/:hostname/waf`, etc.)

use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;
use subtle::ConstantTimeEq;

use crate::health::{HealthChecker, HealthResponse};
use crate::metrics::MetricsRegistry;
use crate::reload::{ConfigReloader, ReloadResult};
use crate::ratelimit::{RateLimitManager, RateLimitStats};
use crate::access::AccessListManager;
use crate::config_manager::{
    ConfigManager, CreateSiteRequest, UpdateSiteRequest, SiteWafRequest,
    RateLimitRequest, AccessListRequest, MutationResult, SiteDetailResponse,
};
use crate::block_log::{BlockLog, BlockEvent};
use crate::entity::{EntityManager, EntitySnapshot};
use crate::correlation::CampaignManager;
use crate::actor::{ActorManager, ActorState, ActorStatsSnapshot};
use crate::session::{SessionManager, SessionState, SessionStatsSnapshot};
use crate::payload::{PayloadManager, EndpointSortBy};
use crate::trends::{TrendsManager, AnomalyQueryOptions, TrendQueryOptions, TopSignalType, TimeRange};
use crate::intelligence::{SignalManager, SignalQueryOptions, Signal, SignalSummary};
use crate::crawler::CrawlerDetector;
use crate::horizon::HorizonClient;
use crate::dlp::DlpScanner;
use crate::waf::{Synapse, Request as SynapseRequest, Header as SynapseHeader, Action as SynapseAction};

/// API response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Whether the operation succeeded
    pub success: bool,
    /// Response data (if successful)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Error message (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response.
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Creates an error response.
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// API endpoint handlers.
pub struct ApiHandler {
    /// Health checker
    health: Arc<HealthChecker>,
    /// Metrics registry
    metrics: Arc<MetricsRegistry>,
    /// Configuration reloader
    reloader: Option<Arc<ConfigReloader>>,
    /// Rate limit manager
    rate_limiter: Arc<RwLock<RateLimitManager>>,
    /// Access list manager
    access_lists: Arc<RwLock<AccessListManager>>,
    /// Configuration manager for CRUD operations
    config_manager: Option<Arc<ConfigManager>>,
    /// API authentication token (if enabled)
    auth_token: Option<String>,
    /// Entity manager for per-IP tracking (dashboard feature)
    entity_manager: Option<Arc<EntityManager>>,
    /// Block log for recent block events (dashboard feature)
    block_log: Option<Arc<BlockLog>>,
    /// Campaign manager for threat correlation (dashboard feature)
    campaign_manager: Option<Arc<CampaignManager>>,
    /// Actor manager for behavioral tracking (Phase 5)
    actor_manager: Option<Arc<ActorManager>>,
    /// Session manager for session validation and hijack detection (Phase 5)
    session_manager: Option<Arc<SessionManager>>,
    /// Synapse detection engine for dry-run evaluation (Phase 2)
    synapse_engine: Option<Arc<RwLock<Synapse>>>,
    /// Payload profiling manager (Phase 6)
    payload_manager: Option<Arc<PayloadManager>>,
    /// Trends/anomaly detection manager (Phase 6)
    trends_manager: Option<Arc<TrendsManager>>,
    /// Signal intelligence manager (Phase 6)
    signal_manager: Option<Arc<SignalManager>>,
    /// Crawler/bot detection (Phase 6)
    crawler_detector: Option<Arc<CrawlerDetector>>,
    /// DLP scanner for sensitive data detection (Phase 4)
    dlp_scanner: Option<Arc<DlpScanner>>,
    /// Signal Horizon client (Phase 6)
    horizon_client: Option<Arc<HorizonClient>>,
}

impl ApiHandler {
    /// Creates a new API handler builder.
    pub fn builder() -> ApiHandlerBuilder {
        ApiHandlerBuilder::default()
    }

    /// Returns the DLP scanner (if configured).
    pub fn dlp_scanner(&self) -> Option<Arc<DlpScanner>> {
        self.dlp_scanner.as_ref().map(Arc::clone)
    }

    /// Handles GET /health request.
    pub fn handle_health(&self) -> ApiResponse<HealthResponse> {
        ApiResponse::ok(self.health.check())
    }

    /// Handles GET /metrics request.
    /// Returns Prometheus exposition format.
    pub fn handle_metrics(&self) -> String {
        self.metrics.render_prometheus()
    }

    /// Handles POST /reload request.
    pub fn handle_reload(&self) -> ApiResponse<ReloadResultResponse> {
        match &self.reloader {
            Some(reloader) => {
                let result = reloader.reload();
                ApiResponse::ok(ReloadResultResponse::from(result))
            }
            None => ApiResponse::err("Configuration reloader not available"),
        }
    }

    /// Handles GET /sites request.
    pub fn handle_list_sites(&self) -> ApiResponse<SiteListResponse> {
        // Try ConfigReloader first (legacy path)
        if let Some(reloader) = &self.reloader {
            let config = reloader.config();
            let config_read = config.read();
            let sites: Vec<SiteInfo> = config_read
                .sites
                .iter()
                .map(|s| SiteInfo {
                    hostname: s.hostname.clone(),
                    upstreams: s.upstreams.iter().map(|u| format!("{}:{}", u.host, u.port)).collect(),
                    tls_enabled: s.tls.is_some(),
                    waf_enabled: s.waf.as_ref().map(|w| w.enabled).unwrap_or(true),
                })
                .collect();
            return ApiResponse::ok(SiteListResponse { sites });
        }

        // Fall back to ConfigManager (multi-site mode)
        if let Some(config_manager) = &self.config_manager {
            let sites = config_manager.get_sites_info();
            return ApiResponse::ok(SiteListResponse { sites });
        }

        // Legacy single-backend mode: return empty sites (not an error)
        ApiResponse::ok(SiteListResponse { sites: vec![] })
    }

    /// Handles GET /stats request.
    pub fn handle_stats(&self) -> ApiResponse<StatsResponse> {
        let rate_limit_stats = self.rate_limiter.read().stats();
        let uptime = self.health.uptime();

        ApiResponse::ok(StatsResponse {
            uptime_secs: uptime.as_secs(),
            rate_limit: rate_limit_stats,
            access_list_sites: self.access_lists.read().site_count(),
        })
    }

    /// Handles GET /waf/stats request.
    pub fn handle_waf_stats(&self) -> ApiResponse<WafStatsResponse> {
        let health = self.health.check();
        ApiResponse::ok(WafStatsResponse {
            enabled: health.waf.enabled,
            analyzed: health.waf.analyzed,
            blocked: health.waf.blocked,
            block_rate_percent: health.waf.block_rate_percent,
            avg_detection_us: health.waf.avg_detection_us,
        })
    }

    /// Handles GET /debug/profiles request.
    /// Note: This requires the profiles_getter callback to be set; returns empty vec if not available.
    /// In the full binary context, profiles are retrieved via DetectionEngine which uses thread-local storage.
    pub fn handle_get_profiles(&self) -> ApiResponse<Vec<crate::profiler::EndpointProfile>> {
        // Library context: profiles_getter not available, return empty
        // The binary (main.rs) should provide profiles via a route handler that calls DetectionEngine directly
        ApiResponse::ok(Vec::new())
    }

    /// Handles POST /api/profiles/reset request.
    /// Clears all learned endpoint behavioral baselines.
    pub fn handle_reset_profiles(&self) {
        // Reset profiling metrics in the registry
        // The actual profile store reset will be handled by the Profiler in pipeline context
        self.metrics.reset_profiles();
        tracing::info!("Endpoint profiles reset via API");
    }

    /// Handles POST /api/schemas/reset request.
    /// Clears all learned API schemas from the schema learner.
    pub fn handle_reset_schemas(&self) {
        // Reset schema metrics in the registry
        // Full schema learner reset requires pipeline access
        self.metrics.reset_schemas();
        tracing::info!("Schema learner reset via API");
    }

    // =========================================================================
    // CRUD Mutation Handlers (Phase 5)
    // =========================================================================

    /// Handles POST /sites request - creates a new site.
    pub fn handle_create_site(&self, request: CreateSiteRequest) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.create_site(request) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles GET /sites/:hostname request - gets site details.
    pub fn handle_get_site(&self, hostname: &str) -> ApiResponse<SiteDetailResponse> {
        match &self.config_manager {
            Some(manager) => match manager.get_site(hostname) {
                Ok(site) => ApiResponse::ok(site),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles PUT /sites/:hostname request - updates site configuration.
    pub fn handle_update_site(&self, hostname: &str, request: UpdateSiteRequest) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.update_site(hostname, request) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles DELETE /sites/:hostname request - deletes a site.
    pub fn handle_delete_site(&self, hostname: &str) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.delete_site(hostname) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles PUT /sites/:hostname/waf request - updates WAF configuration.
    pub fn handle_update_site_waf(&self, hostname: &str, request: SiteWafRequest) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.update_site_waf(hostname, request) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles PUT /sites/:hostname/rate-limit request - updates rate limit configuration.
    pub fn handle_update_site_rate_limit(&self, hostname: &str, request: RateLimitRequest) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.update_site_rate_limit(hostname, request) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles PUT /sites/:hostname/access-list request - updates access list.
    pub fn handle_update_site_access_list(&self, hostname: &str, request: AccessListRequest) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.update_site_access_list(hostname, request) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles GET /config request - retrieves full configuration.
    pub fn handle_get_config(&self) -> ApiResponse<crate::config::ConfigFile> {
        match &self.config_manager {
            Some(manager) => ApiResponse::ok(manager.get_full_config()),
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Handles POST /config request - updates full configuration.
    pub fn handle_update_config(&self, config: crate::config::ConfigFile) -> ApiResponse<MutationResult> {
        match &self.config_manager {
            Some(manager) => match manager.update_full_config(config) {
                Ok(result) => ApiResponse::ok(result),
                Err(e) => ApiResponse::err(e.to_string()),
            },
            None => ApiResponse::err("Configuration manager not available"),
        }
    }

    /// Validates the API authentication token using constant-time comparison.
    ///
    /// Uses `subtle::ConstantTimeEq` to prevent timing attacks that could
    /// allow attackers to guess valid tokens character-by-character.
    pub fn validate_auth(&self, token: Option<&str>) -> bool {
        match (self.auth_token.as_deref(), token) {
            (Some(expected), Some(provided)) => {
                let expected_bytes = expected.as_bytes();
                let provided_bytes = provided.as_bytes();
                // Constant-time comparison: prevents timing attacks
                expected_bytes.len() == provided_bytes.len()
                    && bool::from(expected_bytes.ct_eq(provided_bytes))
            }
            _ => false,
        }
    }

    /// Returns the metrics registry for recording.
    pub fn metrics(&self) -> Arc<MetricsRegistry> {
        Arc::clone(&self.metrics)
    }

    /// Returns the health checker.
    pub fn health(&self) -> Arc<HealthChecker> {
        Arc::clone(&self.health)
    }

    /// Returns the entity manager (if configured).
    pub fn entity_manager(&self) -> Option<Arc<EntityManager>> {
        self.entity_manager.as_ref().map(Arc::clone)
    }

    /// Returns the block log (if configured).
    pub fn block_log(&self) -> Option<Arc<BlockLog>> {
        self.block_log.as_ref().map(Arc::clone)
    }

    /// Returns the config manager (if configured).
    pub fn config_manager(&self) -> Option<&Arc<ConfigManager>> {
        self.config_manager.as_ref()
    }

    /// Returns the campaign manager (if configured).
    pub fn campaign_manager(&self) -> Option<&Arc<CampaignManager>> {
        self.campaign_manager.as_ref()
    }

    /// Returns the actor manager (if configured).
    pub fn actor_manager(&self) -> Option<Arc<ActorManager>> {
        self.actor_manager.as_ref().map(Arc::clone)
    }

    /// Returns the session manager (if configured).
    pub fn session_manager(&self) -> Option<Arc<SessionManager>> {
        self.session_manager.as_ref().map(Arc::clone)
    }

    /// Returns the signal manager (if configured).
    pub fn signal_manager(&self) -> Option<Arc<SignalManager>> {
        self.signal_manager.as_ref().map(Arc::clone)
    }

    /// Returns the synapse engine (if configured).
    pub fn synapse_engine(&self) -> Option<Arc<RwLock<Synapse>>> {
        self.synapse_engine.as_ref().map(Arc::clone)
    }

    /// Evaluates a request against the WAF rules (dry-run mode).
    /// Returns the detection result without actually blocking.
    pub fn evaluate_request(
        &self,
        method: &str,
        uri: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        client_ip: &str,
    ) -> Option<EvaluateResult> {
        let engine = self.synapse_engine.as_ref()?;

        let start = std::time::Instant::now();

        // Build Synapse Request
        let synapse_headers: Vec<SynapseHeader> = headers
            .iter()
            .map(|(name, value)| SynapseHeader::new(name, value))
            .collect();

        let request = SynapseRequest {
            method,
            path: uri,
            query: None,
            headers: synapse_headers,
            body,
            client_ip,
            is_static: false,
        };

        // Run detection
        let verdict = engine.read().analyze(&request);
        let elapsed = start.elapsed();

        Some(EvaluateResult {
            blocked: matches!(verdict.action, SynapseAction::Block),
            risk_score: verdict.risk_score,
            matched_rules: verdict.matched_rules.clone(),
            block_reason: verdict.block_reason.clone(),
            detection_time_us: elapsed.as_micros() as u64,
        })
    }

    /// Handles GET /_sensor/actors request - returns actors (most recently seen first).
    pub fn handle_list_actors(&self, limit: usize) -> Vec<ActorState> {
        match &self.actor_manager {
            Some(manager) => manager.list_actors(limit, 0),
            None => Vec::new(),
        }
    }

    /// Handles GET /_sensor/actors/stats request - returns actor statistics.
    pub fn handle_actor_stats(&self) -> Option<ActorStatsSnapshot> {
        self.actor_manager.as_ref().map(|manager| manager.stats().snapshot())
    }

    /// Handles GET /_sensor/sessions request - returns active sessions.
    pub fn handle_list_sessions(&self, limit: usize) -> Vec<SessionState> {
        match &self.session_manager {
            Some(manager) => manager.list_sessions(limit, 0),
            None => Vec::new(),
        }
    }

    /// Handles GET /_sensor/sessions/stats request - returns session statistics.
    pub fn handle_session_stats(&self) -> Option<SessionStatsSnapshot> {
        self.session_manager.as_ref().map(|manager| manager.stats().snapshot())
    }

    /// Handles GET /_sensor/entities request - returns top entities by risk.
    pub fn handle_list_entities(&self, limit: usize) -> Vec<EntitySnapshot> {
        match &self.entity_manager {
            Some(manager) => manager.list_top_risk(limit),
            None => Vec::new(),
        }
    }

    /// Handles GET /_sensor/blocks request - returns recent block events.
    pub fn handle_list_blocks(&self, limit: usize) -> Vec<BlockEvent> {
        match &self.block_log {
            Some(log) => log.recent(limit),
            None => Vec::new(),
        }
    }

    // =========================================================================
    // Payload Profiling Endpoints
    // =========================================================================

    /// Handles GET /_sensor/payload/stats - returns payload profiling summary.
    pub fn handle_payload_stats(&self) -> ApiResponse<PayloadSummaryResponse> {
        match &self.payload_manager {
            Some(manager) => ApiResponse::ok(PayloadSummaryResponse::from(manager.get_summary())),
            None => ApiResponse::err("Payload manager not available"),
        }
    }

    /// Handles GET /_sensor/payload/endpoints - returns top endpoints by traffic.
    pub fn handle_payload_endpoints(&self, limit: usize) -> ApiResponse<Vec<EndpointPayloadSummary>> {
        match &self.payload_manager {
            Some(manager) => {
                let endpoints = manager.list_top_endpoints(limit, EndpointSortBy::RequestCount);
                let summaries: Vec<EndpointPayloadSummary> = endpoints
                    .into_iter()
                    .map(|stats| EndpointPayloadSummary {
                        template: stats.template,
                        request_count: stats.request_count,
                        avg_request_size: stats.request.avg_bytes(),
                        avg_response_size: stats.response.avg_bytes(),
                    })
                    .collect();
                ApiResponse::ok(summaries)
            }
            None => ApiResponse::err("Payload manager not available"),
        }
    }

    /// Handles GET /_sensor/payload/anomalies - returns recent payload anomalies.
    pub fn handle_payload_anomalies(&self, limit: usize) -> ApiResponse<Vec<PayloadAnomalyResponse>> {
        match &self.payload_manager {
            Some(manager) => {
                let anomalies = manager.get_anomalies(limit);
                let responses: Vec<PayloadAnomalyResponse> = anomalies
                    .into_iter()
                    .map(|a| PayloadAnomalyResponse {
                        anomaly_type: format!("{:?}", a.anomaly_type),
                        severity: format!("{:?}", a.severity),
                        risk_applied: a.risk_applied,
                        template: a.template,
                        entity_id: a.entity_id,
                        detected_at_ms: a.detected_at,
                        description: a.description,
                    })
                    .collect();
                ApiResponse::ok(responses)
            }
            None => ApiResponse::err("Payload manager not available"),
        }
    }

    // =========================================================================
    // Trends/Anomaly Detection Endpoints
    // =========================================================================

    /// Handles GET /_sensor/trends/summary - returns trends summary.
    pub fn handle_trends_summary(&self) -> ApiResponse<TrendsSummaryResponse> {
        match &self.trends_manager {
            Some(manager) => {
                let summary = manager.get_summary(TrendQueryOptions::default());
                let signal_counts: HashMap<String, usize> = summary
                    .by_category
                    .iter()
                    .map(|(category, data)| (category.to_string(), data.count))
                    .collect();
                ApiResponse::ok(TrendsSummaryResponse {
                    total_signals: summary.total_signals,
                    signal_counts,
                    top_signal_types: summary.top_signal_types.clone(),
                    time_range: summary.time_range,
                    anomaly_count: summary.anomaly_count,
                })
            }
            None => ApiResponse::err("Trends manager not available"),
        }
    }

    /// Handles GET /_sensor/trends/anomalies - returns detected anomalies.
    pub fn handle_trends_anomalies(&self, limit: usize) -> ApiResponse<Vec<TrendsAnomalyResponse>> {
        match &self.trends_manager {
            Some(manager) => {
                let mut opts = AnomalyQueryOptions::default();
                opts.limit = Some(limit);
                let anomalies = manager.get_anomalies(opts);
                let responses: Vec<TrendsAnomalyResponse> = anomalies
                    .into_iter()
                    .map(|a| TrendsAnomalyResponse {
                        anomaly_type: format!("{:?}", a.anomaly_type),
                        severity: format!("{:?}", a.severity),
                        entities: a.entities,
                        description: a.description,
                        detected_at_ms: a.detected_at,
                    })
                    .collect();
                ApiResponse::ok(responses)
            }
            None => ApiResponse::err("Trends manager not available"),
        }
    }

    // =========================================================================
    // Signal Intelligence Endpoints
    // =========================================================================

    /// Handles GET /_sensor/signals - returns recent intelligence signals.
    pub fn handle_signals(&self, options: SignalQueryOptions) -> ApiResponse<SignalListResponse> {
        match &self.signal_manager {
            Some(manager) => {
                let signals = manager.list_signals(options);
                let summary = manager.summary();
                ApiResponse::ok(SignalListResponse { signals, summary })
            }
            None => ApiResponse::err("Signal manager not available"),
        }
    }

    // =========================================================================
    // Crawler/Bot Detection Endpoints
    // =========================================================================

    /// Handles GET /_sensor/crawler/stats - returns crawler detection stats.
    pub fn handle_crawler_stats(&self) -> ApiResponse<CrawlerStatsResponse> {
        match &self.crawler_detector {
            Some(detector) => {
                let stats = detector.stats();
                let total = stats.cache_hits + stats.cache_misses;
                let cache_hit_rate = if total > 0 {
                    stats.cache_hits as f64 / total as f64
                } else {
                    0.0
                };
                ApiResponse::ok(CrawlerStatsResponse {
                    total_verifications: stats.total_verifications,
                    verified_crawlers: stats.verified_crawlers,
                    unverified_crawlers: stats.unverified_crawlers,
                    bad_bots: stats.bad_bots,
                    cache_hit_rate,
                })
            }
            None => ApiResponse::err("Crawler detector not available"),
        }
    }

    // =========================================================================
    // Signal Horizon Endpoints
    // =========================================================================

    /// Handles GET /_sensor/horizon/stats - returns Signal Horizon connection stats.
    pub fn handle_horizon_stats(&self) -> ApiResponse<HorizonStatsResponse> {
        match &self.horizon_client {
            Some(client) => {
                let stats = client.stats();
                ApiResponse::ok(HorizonStatsResponse {
                    signals_sent: stats.signals_sent,
                    signals_acked: stats.signals_acked,
                    batches_sent: stats.batches_sent,
                    heartbeats_sent: stats.heartbeats_sent,
                    heartbeat_failures: stats.heartbeat_failures,
                    reconnect_attempts: stats.reconnect_attempts,
                    blocklist_size: client.blocklist_size(),
                })
            }
            None => ApiResponse::err("Horizon client not available"),
        }
    }

    /// Handles GET /_sensor/horizon/blocklist - returns blocklist entries.
    pub fn handle_horizon_blocklist(&self, limit: usize) -> ApiResponse<Vec<BlocklistEntryResponse>> {
        match &self.horizon_client {
            Some(client) => {
                let blocklist = client.blocklist();
                let mut entries: Vec<BlocklistEntryResponse> = blocklist.all_ips()
                    .into_iter()
                    .chain(blocklist.all_fingerprints().into_iter())
                    .take(limit)
                    .map(|e| BlocklistEntryResponse {
                        entry_type: format!("{:?}", e.block_type),
                        value: e.indicator,
                        reason: e.reason.unwrap_or_default(),
                        source: e.source,
                        expires_at: e.expires_at,
                    })
                    .collect();
                entries.truncate(limit);
                ApiResponse::ok(entries)
            }
            None => ApiResponse::err("Horizon client not available"),
        }
    }
}

// =============================================================================
// Response Types for New Endpoints
// =============================================================================

/// Payload profiling summary response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSummaryResponse {
    pub total_endpoints: usize,
    pub total_entities: usize,
    pub total_requests: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub avg_request_size: f64,
    pub avg_response_size: f64,
    pub active_anomalies: usize,
}

impl From<crate::payload::PayloadSummary> for PayloadSummaryResponse {
    fn from(s: crate::payload::PayloadSummary) -> Self {
        Self {
            total_endpoints: s.total_endpoints,
            total_entities: s.total_entities,
            total_requests: s.total_requests,
            total_request_bytes: s.total_request_bytes,
            total_response_bytes: s.total_response_bytes,
            avg_request_size: s.avg_request_size,
            avg_response_size: s.avg_response_size,
            active_anomalies: s.active_anomalies,
        }
    }
}

/// Per-endpoint payload summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointPayloadSummary {
    pub template: String,
    pub request_count: u64,
    pub avg_request_size: f64,
    pub avg_response_size: f64,
}

/// Payload anomaly response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadAnomalyResponse {
    pub anomaly_type: String,
    pub severity: String,
    pub risk_applied: Option<f64>,
    pub template: String,
    pub entity_id: String,
    pub detected_at_ms: i64,
    pub description: String,
}

/// Trends summary response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendsSummaryResponse {
    pub total_signals: usize,
    pub signal_counts: HashMap<String, usize>,
    pub top_signal_types: Vec<TopSignalType>,
    pub time_range: TimeRange,
    pub anomaly_count: usize,
}

/// Trends anomaly response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendsAnomalyResponse {
    pub anomaly_type: String,
    pub severity: String,
    pub entities: Vec<String>,
    pub description: String,
    pub detected_at_ms: i64,
}

/// Signal list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalListResponse {
    pub signals: Vec<Signal>,
    pub summary: SignalSummary,
}

/// Crawler detection stats response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerStatsResponse {
    pub total_verifications: u64,
    pub verified_crawlers: u64,
    pub unverified_crawlers: u64,
    pub bad_bots: u64,
    pub cache_hit_rate: f64,
}

/// Signal Horizon stats response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HorizonStatsResponse {
    pub signals_sent: u64,
    pub signals_acked: u64,
    pub batches_sent: u64,
    pub heartbeats_sent: u64,
    pub heartbeat_failures: u64,
    pub reconnect_attempts: u32,
    pub blocklist_size: usize,
}

/// Blocklist entry response from Signal Horizon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistEntryResponse {
    pub entry_type: String,
    pub value: String,
    pub reason: String,
    pub source: String,
    pub expires_at: Option<String>,
}

/// Builder for ApiHandler.
#[derive(Default)]
pub struct ApiHandlerBuilder {
    health: Option<Arc<HealthChecker>>,
    metrics: Option<Arc<MetricsRegistry>>,
    reloader: Option<Arc<ConfigReloader>>,
    rate_limiter: Option<Arc<RwLock<RateLimitManager>>>,
    access_lists: Option<Arc<RwLock<AccessListManager>>>,
    config_manager: Option<Arc<ConfigManager>>,
    auth_token: Option<String>,
    entity_manager: Option<Arc<EntityManager>>,
    block_log: Option<Arc<BlockLog>>,
    campaign_manager: Option<Arc<CampaignManager>>,
    actor_manager: Option<Arc<ActorManager>>,
    session_manager: Option<Arc<SessionManager>>,
    synapse_engine: Option<Arc<RwLock<Synapse>>>,
    payload_manager: Option<Arc<PayloadManager>>,
    trends_manager: Option<Arc<TrendsManager>>,
    signal_manager: Option<Arc<SignalManager>>,
    crawler_detector: Option<Arc<CrawlerDetector>>,
    dlp_scanner: Option<Arc<DlpScanner>>,
    horizon_client: Option<Arc<HorizonClient>>,
}

impl ApiHandlerBuilder {
    /// Sets the health checker.
    pub fn health(mut self, health: Arc<HealthChecker>) -> Self {
        self.health = Some(health);
        self
    }

    /// Sets the metrics registry.
    pub fn metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Sets the configuration reloader.
    pub fn reloader(mut self, reloader: Arc<ConfigReloader>) -> Self {
        self.reloader = Some(reloader);
        self
    }

    /// Sets the rate limit manager.
    pub fn rate_limiter(mut self, rate_limiter: Arc<RwLock<RateLimitManager>>) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Sets the access list manager.
    pub fn access_lists(mut self, access_lists: Arc<RwLock<AccessListManager>>) -> Self {
        self.access_lists = Some(access_lists);
        self
    }

    /// Sets the configuration manager for CRUD operations.
    pub fn config_manager(mut self, config_manager: Arc<ConfigManager>) -> Self {
        self.config_manager = Some(config_manager);
        self
    }

    /// Sets the API authentication token.
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Sets the entity manager for dashboard entity tracking.
    pub fn entity_manager(mut self, entity_manager: Arc<EntityManager>) -> Self {
        self.entity_manager = Some(entity_manager);
        self
    }

    /// Sets the block log for dashboard block event history.
    pub fn block_log(mut self, block_log: Arc<BlockLog>) -> Self {
        self.block_log = Some(block_log);
        self
    }

    /// Sets the campaign manager for threat correlation.
    pub fn campaign_manager(mut self, manager: Arc<CampaignManager>) -> Self {
        self.campaign_manager = Some(manager);
        self
    }

    /// Sets the actor manager for behavioral tracking.
    pub fn actor_manager(mut self, manager: Arc<ActorManager>) -> Self {
        self.actor_manager = Some(manager);
        self
    }

    /// Sets the session manager for session validation and hijack detection.
    pub fn session_manager(mut self, manager: Arc<SessionManager>) -> Self {
        self.session_manager = Some(manager);
        self
    }

    /// Sets the synapse detection engine for dry-run evaluation.
    pub fn synapse_engine(mut self, engine: Arc<RwLock<Synapse>>) -> Self {
        self.synapse_engine = Some(engine);
        self
    }

    /// Sets the payload profiling manager.
    pub fn payload_manager(mut self, manager: Arc<PayloadManager>) -> Self {
        self.payload_manager = Some(manager);
        self
    }

    /// Sets the trends/anomaly detection manager.
    pub fn trends_manager(mut self, manager: Arc<TrendsManager>) -> Self {
        self.trends_manager = Some(manager);
        self
    }

    /// Sets the signal intelligence manager.
    pub fn signal_manager(mut self, manager: Arc<SignalManager>) -> Self {
        self.signal_manager = Some(manager);
        self
    }

    /// Sets the crawler/bot detector.
    pub fn crawler_detector(mut self, detector: Arc<CrawlerDetector>) -> Self {
        self.crawler_detector = Some(detector);
        self
    }

    /// Sets the DLP scanner.
    pub fn dlp_scanner(mut self, scanner: Arc<DlpScanner>) -> Self {
        self.dlp_scanner = Some(scanner);
        self
    }

    /// Sets the Signal Horizon client.
    pub fn horizon_client(mut self, client: Arc<HorizonClient>) -> Self {
        self.horizon_client = Some(client);
        self
    }

    /// Builds the API handler.
    pub fn build(self) -> ApiHandler {
        ApiHandler {
            health: self.health.unwrap_or_else(|| Arc::new(HealthChecker::default())),
            metrics: self.metrics.unwrap_or_else(|| Arc::new(MetricsRegistry::new())),
            reloader: self.reloader,
            rate_limiter: self.rate_limiter.unwrap_or_else(|| {
                Arc::new(RwLock::new(RateLimitManager::new()))
            }),
            access_lists: self.access_lists.unwrap_or_else(|| {
                Arc::new(RwLock::new(AccessListManager::new()))
            }),
            config_manager: self.config_manager,
            auth_token: self.auth_token,
            entity_manager: self.entity_manager,
            block_log: self.block_log,
            campaign_manager: self.campaign_manager,
            actor_manager: self.actor_manager,
            session_manager: self.session_manager,
            synapse_engine: self.synapse_engine,
            payload_manager: self.payload_manager,
            trends_manager: self.trends_manager,
            signal_manager: self.signal_manager,
            crawler_detector: self.crawler_detector,
            dlp_scanner: self.dlp_scanner,
            horizon_client: self.horizon_client,
        }
    }
}

/// Response for reload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReloadResultResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub sites_loaded: usize,
    pub certs_loaded: usize,
    pub duration_ms: u64,
}

/// Result of a dry-run WAF evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluateResult {
    /// Whether the request would have been blocked
    pub blocked: bool,
    /// Calculated risk score
    pub risk_score: u16,
    /// Rules that matched
    pub matched_rules: Vec<u32>,
    /// Reason for blocking (if blocked)
    pub block_reason: Option<String>,
    /// Time taken for detection in microseconds
    pub detection_time_us: u64,
}

impl From<ReloadResult> for ReloadResultResponse {
    fn from(r: ReloadResult) -> Self {
        Self {
            success: r.success,
            error: r.error,
            sites_loaded: r.sites_loaded,
            certs_loaded: r.certs_loaded,
            duration_ms: r.duration_ms,
        }
    }
}

/// Response for site list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteListResponse {
    pub sites: Vec<SiteInfo>,
}

/// Information about a single site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteInfo {
    pub hostname: String,
    pub upstreams: Vec<String>,
    pub tls_enabled: bool,
    pub waf_enabled: bool,
}

/// Response for stats endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    pub uptime_secs: u64,
    pub rate_limit: RateLimitStats,
    pub access_list_sites: usize,
}

/// Response for WAF stats endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafStatsResponse {
    pub enabled: bool,
    pub analyzed: u64,
    pub blocked: u64,
    pub block_rate_percent: f64,
    pub avg_detection_us: u64,
}

/// HTTP method for API routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

/// API route definition.
#[derive(Debug, Clone)]
pub struct ApiRoute {
    pub method: HttpMethod,
    pub path: &'static str,
    pub description: &'static str,
    pub auth_required: bool,
}

/// Available API routes.
pub const API_ROUTES: &[ApiRoute] = &[
    // Health and monitoring (no auth)
    ApiRoute {
        method: HttpMethod::Get,
        path: "/health",
        description: "Health check endpoint",
        auth_required: false,
    },
    ApiRoute {
        method: HttpMethod::Get,
        path: "/metrics",
        description: "Prometheus metrics endpoint",
        auth_required: false,
    },
    // Configuration management (auth required)
    ApiRoute {
        method: HttpMethod::Post,
        path: "/reload",
        description: "Reload configuration from file",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Get,
        path: "/sites",
        description: "List all configured sites",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Post,
        path: "/sites",
        description: "Create a new site",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Get,
        path: "/sites/:hostname",
        description: "Get site details",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Put,
        path: "/sites/:hostname",
        description: "Update site configuration",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Delete,
        path: "/sites/:hostname",
        description: "Delete a site",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Put,
        path: "/sites/:hostname/waf",
        description: "Update site WAF configuration",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Put,
        path: "/sites/:hostname/rate-limit",
        description: "Update site rate limit configuration",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Put,
        path: "/sites/:hostname/access-list",
        description: "Update site access list",
        auth_required: true,
    },
    // Statistics
    ApiRoute {
        method: HttpMethod::Get,
        path: "/stats",
        description: "Runtime statistics",
        auth_required: true,
    },
    ApiRoute {
        method: HttpMethod::Get,
        path: "/waf/stats",
        description: "WAF statistics",
        auth_required: true,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_ok() {
        let response: ApiResponse<String> = ApiResponse::ok("test".to_string());
        assert!(response.success);
        assert_eq!(response.data, Some("test".to_string()));
        assert!(response.error.is_none());
    }

    #[test]
    fn test_api_response_err() {
        let response: ApiResponse<String> = ApiResponse::err("error message");
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error, Some("error message".to_string()));
    }

    #[test]
    fn test_api_handler_builder() {
        let handler = ApiHandler::builder()
            .auth_token("secret")
            .build();

        assert!(handler.validate_auth(Some("secret")));
        assert!(!handler.validate_auth(Some("wrong")));
        assert!(!handler.validate_auth(None));
    }

    #[test]
    fn test_api_handler_no_auth() {
        let handler = ApiHandler::builder().build();

        // No configured auth token should deny access
        assert!(!handler.validate_auth(None));
        assert!(!handler.validate_auth(Some("anything")));
    }

    #[test]
    fn test_handle_health() {
        let handler = ApiHandler::builder().build();
        let response = handler.handle_health();

        assert!(response.success);
        assert!(response.data.is_some());
    }

    #[test]
    fn test_handle_metrics() {
        let handler = ApiHandler::builder().build();
        let metrics = handler.handle_metrics();

        assert!(metrics.contains("synapse_"));
    }

    #[test]
    fn test_handle_stats() {
        let handler = ApiHandler::builder().build();
        let response = handler.handle_stats();

        assert!(response.success);
        let stats = response.data.unwrap();
        assert!(stats.uptime_secs < 1); // Just created
    }

    #[test]
    fn test_handle_waf_stats() {
        let handler = ApiHandler::builder().build();
        let response = handler.handle_waf_stats();

        assert!(response.success);
        let waf = response.data.unwrap();
        assert!(waf.enabled);
    }

    #[test]
    fn test_handle_reload_no_reloader() {
        let handler = ApiHandler::builder().build();
        let response = handler.handle_reload();

        assert!(!response.success);
        assert!(response.error.is_some());
    }

    #[test]
    fn test_handle_list_sites_no_reloader() {
        let handler = ApiHandler::builder().build();
        let response = handler.handle_list_sites();

        // Returns success with empty sites for legacy single-backend mode
        assert!(response.success);
        assert!(response.error.is_none());
        assert!(response.data.unwrap().sites.is_empty());
    }

    #[test]
    fn test_api_routes() {
        assert!(!API_ROUTES.is_empty());

        // Health should not require auth
        let health_route = API_ROUTES.iter().find(|r| r.path == "/health").unwrap();
        assert!(!health_route.auth_required);

        // Reload should require auth
        let reload_route = API_ROUTES.iter().find(|r| r.path == "/reload").unwrap();
        assert!(reload_route.auth_required);
    }

    #[test]
    fn test_reload_result_response() {
        let result = ReloadResult {
            success: true,
            error: None,
            sites_loaded: 5,
            certs_loaded: 3,
            duration_ms: 100,
        };

        let response = ReloadResultResponse::from(result);
        assert!(response.success);
        assert_eq!(response.sites_loaded, 5);
        assert_eq!(response.certs_loaded, 3);
    }

    #[test]
    fn test_site_info_serialization() {
        let site = SiteInfo {
            hostname: "example.com".to_string(),
            upstreams: vec!["127.0.0.1:8080".to_string()],
            tls_enabled: true,
            waf_enabled: true,
        };

        let json = serde_json::to_string(&site).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("tls_enabled"));
    }
}
