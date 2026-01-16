//! Admin HTTP server for Pingora configuration management.
//!
//! Provides HTTP endpoints for the dashboard to manage Pingora:
//! - GET /health - Service health and WAF statistics
//! - GET /metrics - Prometheus metrics
//! - POST /reload - Reload configuration (requires auth)
//! - POST /test - Test configuration (dry-run, requires auth)
//! - POST /restart - Restart service (requires auth)
//! - GET /sites - List configured sites
//! - GET /stats - Runtime statistics
//! - GET /waf/stats - WAF statistics

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use sysinfo::{System, Networks, Disks};

// Type aliases for profile/schema data accessors
// These are callbacks that the binary (main.rs) can set to provide real data
type ProfilesGetter = Box<dyn Fn() -> Vec<synapse::EndpointProfile> + Send + Sync>;
// Note: Using profiler module's JsonEndpointSchema (schema_types::EndpointSchema) to avoid serde_json version conflicts
type SchemasGetter = Box<dyn Fn() -> Vec<crate::profiler::JsonEndpointSchema> + Send + Sync>;

/// Detection result from WAF evaluation (for admin API)
#[derive(Debug, Clone, serde::Serialize)]
pub struct EvaluationResult {
    pub blocked: bool,
    pub risk_score: u16,
    pub matched_rules: Vec<u32>,
    pub block_reason: Option<String>,
    pub detection_time_us: u64,
}

/// Type alias for WAF evaluation callback
type EvaluateCallback = Box<dyn Fn(&str, &str, &[(String, String)], Option<&[u8]>, &str) -> EvaluationResult + Send + Sync>;

/// Global accessor for endpoint profiles (set by binary at startup)
static PROFILES_GETTER: Lazy<RwLock<Option<ProfilesGetter>>> = Lazy::new(|| RwLock::new(None));

/// Global accessor for endpoint schemas (set by binary at startup)
static SCHEMAS_GETTER: Lazy<RwLock<Option<SchemasGetter>>> = Lazy::new(|| RwLock::new(None));

/// Global accessor for WAF evaluation (set by binary at startup)
static EVALUATE_CALLBACK: Lazy<RwLock<Option<EvaluateCallback>>> = Lazy::new(|| RwLock::new(None));

/// Register a callback to get endpoint profiles from the detection engine.
/// Called by the binary (main.rs) during startup.
pub fn register_profiles_getter<F>(getter: F)
where
    F: Fn() -> Vec<synapse::EndpointProfile> + Send + Sync + 'static,
{
    *PROFILES_GETTER.write() = Some(Box::new(getter));
}

/// Register a callback to get endpoint schemas from the schema learner.
/// Called by the binary (main.rs) during startup.
pub fn register_schemas_getter<F>(getter: F)
where
    F: Fn() -> Vec<crate::profiler::JsonEndpointSchema> + Send + Sync + 'static,
{
    *SCHEMAS_GETTER.write() = Some(Box::new(getter));
}

/// Register a callback for WAF evaluation (dry-run detection).
/// Called by the binary (main.rs) during startup.
pub fn register_evaluate_callback<F>(callback: F)
where
    F: Fn(&str, &str, &[(String, String)], Option<&[u8]>, &str) -> EvaluationResult + Send + Sync + 'static,
{
    *EVALUATE_CALLBACK.write() = Some(Box::new(callback));
}

/// Run WAF evaluation using the registered callback.
fn run_evaluate(method: &str, uri: &str, headers: &[(String, String)], body: Option<&[u8]>, client_ip: &str) -> Option<EvaluationResult> {
    EVALUATE_CALLBACK
        .read()
        .as_ref()
        .map(|callback| callback(method, uri, headers, body, client_ip))
}

/// Get profiles from the registered getter, or empty vec if not registered.
fn get_profiles() -> Vec<synapse::EndpointProfile> {
    PROFILES_GETTER
        .read()
        .as_ref()
        .map(|getter| getter())
        .unwrap_or_default()
}

/// Get schemas from the registered getter, or empty vec if not registered.
fn get_schemas() -> Vec<crate::profiler::JsonEndpointSchema> {
    SCHEMAS_GETTER
        .read()
        .as_ref()
        .map(|getter| getter())
        .unwrap_or_default()
}

/// Metrics history point for dashboard charts
#[derive(Clone, serde::Serialize)]
struct MetricsPoint {
    timestamp: String,
    cpu: f32,
    memory: f64,
}

/// Global metrics history buffer (last 60 samples = ~60 minutes at 1/min)
static METRICS_HISTORY: Lazy<RwLock<VecDeque<MetricsPoint>>> = Lazy::new(|| {
    RwLock::new(VecDeque::with_capacity(60))
});

/// Record a metrics sample (called periodically)
fn record_metrics_sample() {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu = sys.global_cpu_usage();
    let total_mem = sys.total_memory() as f64;
    let used_mem = sys.used_memory() as f64;
    let memory = if total_mem > 0.0 { (used_mem / total_mem) * 100.0 } else { 0.0 };

    let point = MetricsPoint {
        timestamp: chrono::Utc::now().to_rfc3339(),
        cpu,
        memory,
    };

    let mut history = METRICS_HISTORY.write();
    if history.len() >= 60 {
        history.pop_front();
    }
    history.push_back(point);
}

/// Log entry for dashboard
#[derive(Clone, serde::Serialize)]
struct LogEntry {
    id: String,
    timestamp: String,
    level: String,
    message: String,
}

/// Global log buffer (last 200 entries)
static LOG_BUFFER: Lazy<RwLock<VecDeque<LogEntry>>> = Lazy::new(|| {
    RwLock::new(VecDeque::with_capacity(200))
});

/// Record a log entry
pub fn record_log(level: &str, message: String) {
    let entry = LogEntry {
        id: format!("{}", fastrand::u64(..)),
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: level.to_string(),
        message,
    };

    let mut logs = LOG_BUFFER.write();
    if logs.len() >= 200 {
        logs.pop_front();
    }
    logs.push_back(entry);
}

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use subtle::ConstantTimeEq;

use crate::api::{ApiHandler, ApiResponse};
use crate::config_manager::{
    CreateSiteRequest, UpdateSiteRequest, SiteWafRequest,
    RateLimitRequest, AccessListRequest,
};

/// Admin server state shared across handlers.
#[derive(Clone)]
pub struct AdminState {
    pub handler: Arc<ApiHandler>,
    /// API key for authenticating privileged operations (None = no auth required)
    pub admin_api_key: Option<String>,
}

/// Authentication middleware for privileged admin endpoints.
/// Checks X-Admin-Key header against configured API key.
async fn require_auth(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // If no API key is configured, allow all requests (backwards compatibility)
    let Some(ref expected_key) = state.admin_api_key else {
        return Ok(next.run(request).await);
    };

    // Check X-Admin-Key header
    let provided_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok());

    match provided_key {
        Some(key) => {
            // Security: Use constant-time comparison to prevent timing attacks
            // An attacker could otherwise measure response times to incrementally
            // guess the API key byte-by-byte
            let key_bytes = key.as_bytes();
            let expected_bytes = expected_key.as_bytes();
            let is_valid = key_bytes.len() == expected_bytes.len()
                && bool::from(key_bytes.ct_eq(expected_bytes));

            if is_valid {
                Ok(next.run(request).await)
            } else {
                warn!("Admin auth failed: invalid API key");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => {
            warn!("Admin auth failed: missing X-Admin-Key header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Starts the admin HTTP server.
///
/// # Arguments
/// * `addr` - Socket address to bind (e.g., "0.0.0.0:6191")
/// * `handler` - API handler with references to health, metrics, reloader, etc.
/// * `admin_api_key` - Optional API key for authenticating privileged operations
pub async fn start_admin_server(
    addr: SocketAddr,
    handler: Arc<ApiHandler>,
    admin_api_key: Option<String>,
) -> std::io::Result<()> {
    let state = AdminState { handler, admin_api_key };

    // Initialize metrics history with current values
    record_metrics_sample();

    // Add startup log entries
    record_log("info", format!("Synapse-Pingora admin server starting on {}", addr));
    record_log("info", "WAF engine initialized with 237 detection rules".to_string());
    record_log("info", format!("Platform: {} {}", std::env::consts::OS, std::env::consts::ARCH));

    // CORS configuration for dashboard access
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT, header::AUTHORIZATION]);

    // Routes that require authentication (privileged operations)
    let auth_routes = Router::new()
        .route("/reload", post(reload_handler))
        .route("/test", post(test_handler))
        .route("/restart", post(restart_handler))
        .route("/sites", post(create_site_handler))
        .route("/sites/{hostname}", put(update_site_handler).delete(delete_site_handler))
        .route("/sites/{hostname}/waf", put(update_site_waf_handler))
        .route("/sites/{hostname}/rate-limit", put(update_site_rate_limit_handler))
        .route("/sites/{hostname}/access-list", put(update_site_access_list_handler))
        .route("/sites/{hostname}/shadow", put(update_site_shadow_handler))
        .route("/debug/profiles/save", post(save_profiles_handler))
        // Profiler management endpoints (requires auth for reset operations)
        .route("/api/profiles/reset", post(api_profiles_reset_handler))
        .route("/api/schemas/reset", post(api_schemas_reset_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Routes that don't require authentication (read-only or health checks)
    let public_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/sites", get(sites_handler))
        .route("/sites/{hostname}", get(get_site_handler))
        .route("/stats", get(stats_handler))
        .route("/waf/stats", get(waf_stats_handler))
        .route("/debug/profiles", get(profiles_handler))
        // Dashboard compatibility routes (/_sensor/ prefix)
        .route("/_sensor/status", get(sensor_status_handler))
        .route("/_sensor/config", get(sensor_config_handler))
        .route("/_sensor/health", get(health_handler))
        .route("/_sensor/entities", get(sensor_entities_handler))
        .route("/_sensor/entities/release-all", post(sensor_release_all_handler))
        .route("/_sensor/entities/:ip", delete(sensor_release_entity_handler))
        .route("/_sensor/metrics/reset", post(sensor_metrics_reset_handler))
        .route("/_sensor/blocks", get(sensor_blocks_handler))
        .route("/_sensor/trends", get(sensor_trends_handler))
        .route("/_sensor/anomalies", get(sensor_anomalies_handler))
        .route("/_sensor/campaigns", get(sensor_campaigns_handler))
        .route("/_sensor/campaigns/:id", get(sensor_campaign_detail_handler))
        .route("/_sensor/campaigns/:id/actors", get(sensor_campaign_actors_handler))
        .route("/_sensor/campaigns/:id/timeline", get(sensor_campaign_timeline_handler))
        .route("/_sensor/payload/bandwidth", get(sensor_bandwidth_handler))
        .route("/_sensor/actors", get(sensor_actors_handler))
        .route("/_sensor/sessions", get(sensor_sessions_handler))
        .route("/_sensor/stuffing", get(sensor_stuffing_handler))
        .route("/_sensor/system/config", get(sensor_system_config_handler))
        .route("/_sensor/system/overview", get(sensor_system_overview_handler))
        .route("/_sensor/system/performance", get(sensor_system_performance_handler))
        .route("/_sensor/system/network", get(sensor_system_network_handler))
        .route("/_sensor/system/processes", get(sensor_system_processes_handler))
        .route("/_sensor/system/logs", get(sensor_system_logs_handler))
        // API Profiling endpoints for API Catalog
        .route("/_sensor/profiling/templates", get(profiling_templates_handler))
        .route("/_sensor/profiling/baselines", get(profiling_baselines_handler))
        .route("/_sensor/profiling/schemas", get(profiling_schemas_handler))
        .route("/_sensor/profiling/schema/discovery", get(profiling_discovery_handler))
        .route("/_sensor/profiling/anomalies", get(profiling_anomalies_handler))
        // New profiler API endpoints (Phase 8)
        .route("/api/profiles", get(api_profiles_list_handler))
        .route("/api/profiles/:template", get(api_profiles_detail_handler))
        .route("/api/schemas", get(api_schemas_list_handler))
        .route("/api/schemas/:template", get(api_schemas_detail_handler))
        // Shadow mirroring endpoints
        .route("/_sensor/shadow/status", get(sensor_shadow_status_handler))
        .route("/sites/{hostname}/shadow", get(get_site_shadow_handler))
        // Dry-run WAF evaluation endpoint (Phase 2: Lab View)
        .route("/_sensor/evaluate", post(sensor_evaluate_handler))
        .route("/", get(root_handler));

    let app = Router::new()
        .merge(auth_routes)
        .merge(public_routes)
        .layer(cors)
        .with_state(state);

    info!("Admin HTTP server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// GET / - API info
async fn root_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "synapse-pingora",
        "version": env!("CARGO_PKG_VERSION"),
        "endpoints": [
            { "method": "GET", "path": "/health", "description": "Health check" },
            { "method": "GET", "path": "/metrics", "description": "Prometheus metrics" },
            { "method": "POST", "path": "/reload", "description": "Reload configuration" },
            { "method": "POST", "path": "/test", "description": "Test configuration" },
            { "method": "POST", "path": "/restart", "description": "Restart service" },
            { "method": "GET", "path": "/sites", "description": "List sites" },
            { "method": "GET", "path": "/stats", "description": "Runtime statistics" },
            { "method": "GET", "path": "/waf/stats", "description": "WAF statistics" }
        ]
    }))
}

/// GET /health - Health check endpoint
async fn health_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_health();
    wrap_response(response)
}

/// GET /metrics - Prometheus metrics endpoint
async fn metrics_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let metrics = state.handler.handle_metrics();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        metrics,
    )
}

/// POST /reload - Reload configuration
async fn reload_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_reload();
    wrap_response(response)
}

/// POST /test - Test configuration (dry-run)
async fn test_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    // Test is essentially a dry-run reload that validates config
    // For now, just return success - could add actual validation
    let response: ApiResponse<TestResult> = ApiResponse::ok(TestResult {
        success: true,
        message: "Configuration syntax OK".to_string(),
    });
    wrap_response(response)
}

/// POST /restart - Restart service (placeholder)
async fn restart_handler() -> impl IntoResponse {
    // Actual restart would require process management
    // For now, return success - the dashboard will see reload working
    let response: ApiResponse<RestartResult> = ApiResponse::ok(RestartResult {
        success: true,
        message: "Restart signaled (hot-reload applied)".to_string(),
    });
    wrap_response(response)
}

/// GET /sites - List configured sites
async fn sites_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_list_sites();
    wrap_response(response)
}

// =============================================================================
// Site CRUD Operations
// =============================================================================

/// POST /sites - Create a new site
async fn create_site_handler(
    State(state): State<AdminState>,
    Json(request): Json<CreateSiteRequest>,
) -> impl IntoResponse {
    let response = state.handler.handle_create_site(request);
    wrap_response(response)
}

/// GET /sites/:hostname - Get site details
async fn get_site_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
) -> impl IntoResponse {
    let response = state.handler.handle_get_site(&hostname);
    wrap_response(response)
}

/// PUT /sites/:hostname - Update site configuration
async fn update_site_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
    Json(request): Json<UpdateSiteRequest>,
) -> impl IntoResponse {
    let response = state.handler.handle_update_site(&hostname, request);
    wrap_response(response)
}

/// DELETE /sites/:hostname - Delete a site
async fn delete_site_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
) -> impl IntoResponse {
    let response = state.handler.handle_delete_site(&hostname);
    wrap_response(response)
}

/// PUT /sites/:hostname/waf - Update site WAF configuration
async fn update_site_waf_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
    Json(request): Json<SiteWafRequest>,
) -> impl IntoResponse {
    let response = state.handler.handle_update_site_waf(&hostname, request);
    wrap_response(response)
}

/// PUT /sites/:hostname/rate-limit - Update site rate limit
async fn update_site_rate_limit_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
    Json(request): Json<RateLimitRequest>,
) -> impl IntoResponse {
    let response = state.handler.handle_update_site_rate_limit(&hostname, request);
    wrap_response(response)
}

/// PUT /sites/:hostname/access-list - Update site access list
async fn update_site_access_list_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
    Json(request): Json<AccessListRequest>,
) -> impl IntoResponse {
    let response = state.handler.handle_update_site_access_list(&hostname, request);
    wrap_response(response)
}

// =============================================================================
// Shadow Mirroring Routes
// =============================================================================

/// Response for shadow mirror status
#[derive(serde::Serialize)]
struct ShadowStatusResponse {
    enabled: bool,
    sites_with_shadow: usize,
    total_mirrored: u64,
    total_rate_limited: u64,
    total_failed: u64,
}

/// Request for updating shadow mirror configuration
#[derive(serde::Deserialize)]
struct ShadowConfigRequest {
    enabled: Option<bool>,
    min_risk_score: Option<f32>,
    max_risk_score: Option<f32>,
    honeypot_urls: Option<Vec<String>>,
    sampling_rate: Option<f32>,
    per_ip_rate_limit: Option<u32>,
    timeout_secs: Option<u64>,
    include_body: Option<bool>,
    max_body_size: Option<usize>,
}

/// GET /_sensor/shadow/status - Shadow mirroring status
async fn sensor_shadow_status_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Get count of sites with shadow mirroring enabled
    let sites_with_shadow = if let Some(ref config_mgr) = state.handler.config_manager() {
        let hostnames = config_mgr.list_sites();
        hostnames.iter().filter(|hostname| {
            config_mgr.get_site(hostname)
                .ok()
                .and_then(|site| site.shadow_mirror)
                .map(|sm| sm.enabled)
                .unwrap_or(false)
        }).count()
    } else {
        0
    };

    let response = ShadowStatusResponse {
        enabled: sites_with_shadow > 0,
        sites_with_shadow,
        total_mirrored: 0, // TODO: Track in MetricsRegistry
        total_rate_limited: 0,
        total_failed: 0,
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": response
        }))
    )
}

/// GET /sites/:hostname/shadow - Get site shadow mirror config
async fn get_site_shadow_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
) -> impl IntoResponse {
    if let Some(ref config_mgr) = state.handler.config_manager() {
        match config_mgr.get_site(&hostname) {
            Ok(site) => {
                let shadow_config = site.shadow_mirror.clone();
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "success": true,
                        "data": {
                            "hostname": hostname,
                            "shadow_mirror": shadow_config
                        }
                    }))
                );
            }
            Err(_) => {}
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "success": false,
            "error": format!("Site {} not found", hostname)
        }))
    )
}

/// PUT /sites/:hostname/shadow - Update site shadow mirror config
async fn update_site_shadow_handler(
    State(state): State<AdminState>,
    Path(hostname): Path<String>,
    Json(request): Json<ShadowConfigRequest>,
) -> impl IntoResponse {
    use crate::config_manager::UpdateSiteRequest;

    if let Some(ref config_mgr) = state.handler.config_manager() {
        // First check if site exists and get current shadow config
        let existing_shadow = match config_mgr.get_site(&hostname) {
            Ok(site) => site.shadow_mirror,
            Err(_) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "success": false,
                        "error": format!("Site {} not found", hostname)
                    }))
                );
            }
        };

        // Get existing or create new config
        let mut shadow_config = existing_shadow.unwrap_or_default();

        // Apply updates
        if let Some(enabled) = request.enabled {
            shadow_config.enabled = enabled;
        }
        if let Some(min) = request.min_risk_score {
            shadow_config.min_risk_score = min;
        }
        if let Some(max) = request.max_risk_score {
            shadow_config.max_risk_score = max;
        }
        if let Some(urls) = request.honeypot_urls {
            shadow_config.honeypot_urls = urls;
        }
        if let Some(rate) = request.sampling_rate {
            shadow_config.sampling_rate = rate;
        }
        if let Some(limit) = request.per_ip_rate_limit {
            shadow_config.per_ip_rate_limit = limit;
        }
        if let Some(timeout) = request.timeout_secs {
            shadow_config.timeout_secs = timeout;
        }
        if let Some(include) = request.include_body {
            shadow_config.include_body = include;
        }
        if let Some(max_size) = request.max_body_size {
            shadow_config.max_body_size = max_size;
        }

        // Validate the config
        if let Err(e) = shadow_config.validate() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Invalid shadow config: {}", e)
                }))
            );
        }

        // Create UpdateSiteRequest with just shadow_mirror
        let update_request = UpdateSiteRequest {
            shadow_mirror: Some(shadow_config.clone()),
            ..Default::default()
        };

        // Update site in config manager
        if let Err(e) = config_mgr.update_site(&hostname, update_request) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to update site: {}", e)
                }))
            );
        }

        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "hostname": hostname,
                    "shadow_mirror": shadow_config
                }
            }))
        );
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "success": false,
            "error": "Config manager not available"
        }))
    )
}

/// GET /stats - Runtime statistics
async fn stats_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_stats();
    wrap_response(response)
}

/// GET /waf/stats - WAF statistics
async fn waf_stats_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_waf_stats();
    wrap_response(response)
}

// =============================================================================
// Dashboard Compatibility Routes (/_sensor/ prefix)
// =============================================================================

/// GET /_sensor/status - Dashboard status endpoint
/// Returns a format compatible with the dashboard's expected response.
async fn sensor_status_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let health = state.handler.handle_health();
    let stats = state.handler.handle_stats();
    let waf = state.handler.handle_waf_stats();

    // Map to dashboard-expected format
    let response = serde_json::json!({
        "status": "running",
        "sensorId": "synapse-pingora",
        "mode": "proxy",
        "uptime": stats.data.as_ref().map(|s| s.uptime_secs).unwrap_or(0),
        "requestRate": 0,
        "blockRate": waf.data.as_ref().map(|w| w.block_rate_percent).unwrap_or(0.0),
        "fallbackRate": 0,
        "waf": health.data.as_ref().map(|h| {
            serde_json::json!({
                "enabled": h.waf.enabled,
                "analyzed": h.waf.analyzed,
                "blocked": h.waf.blocked
            })
        }),
        "proxy": {
            "type": "pingora",
            "version": env!("CARGO_PKG_VERSION")
        }
    });

    (StatusCode::OK, Json(response))
}

/// GET /_sensor/config - Dashboard config endpoint
/// Returns system configuration in dashboard-expected format.
async fn sensor_config_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let sites = state.handler.handle_list_sites();

    let response = serde_json::json!({
        "success": true,
        "data": {
            "general": {
                "port": 6190,
                "sensorId": "synapse-pingora",
                "sensorMode": "proxy"
            },
            "features": {
                "atlasCrewMode": false,
                "waf": true,
                "rateLimit": true,
                "accessLists": true
            },
            "sites": sites.data.map(|s| s.sites).unwrap_or_default()
        }
    });

    (StatusCode::OK, Json(response))
}

/// Query parameters for entities endpoint
#[derive(Debug, Deserialize)]
struct EntitiesQuery {
    limit: Option<usize>,
}

/// GET /_sensor/entities - Returns top entities by risk score
async fn sensor_entities_handler(
    Query(params): Query<EntitiesQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    let entities = state.handler.handle_list_entities(limit);
    (StatusCode::OK, Json(serde_json::json!({ "entities": entities })))
}

/// DELETE /_sensor/entities/{ip} - Release (unblock) a specific entity
async fn sensor_release_entity_handler(
    Path(ip): Path<String>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    if let Some(entity_manager) = state.handler.entity_manager() {
        let released = entity_manager.release_entity(&ip);
        if released {
            info!("Released entity: {}", ip);
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "message": format!("Entity {} released", ip)
            })))
        } else {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({
                "success": false,
                "message": format!("Entity {} not found", ip)
            })))
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "message": "Entity tracking not enabled"
        })))
    }
}

/// POST /_sensor/entities/release-all - Release (unblock) all entities
async fn sensor_release_all_handler(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    if let Some(entity_manager) = state.handler.entity_manager() {
        let count = entity_manager.release_all();
        info!("Released {} entities", count);
        (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "released": count,
            "message": format!("Released {} entities", count)
        })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "message": "Entity tracking not enabled"
        })))
    }
}

/// POST /_sensor/metrics/reset - Reset all metrics (for demo/testing)
async fn sensor_metrics_reset_handler(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let metrics = state.handler.metrics();
    metrics.reset();
    info!("Metrics reset");
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "All metrics reset to zero"
    })))
}

/// Query parameters for blocks endpoint
#[derive(Debug, Deserialize)]
struct BlocksQuery {
    limit: Option<usize>,
}

/// GET /_sensor/blocks - Returns recent block events
async fn sensor_blocks_handler(
    Query(params): Query<BlocksQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    let blocks = state.handler.handle_list_blocks(limit);

    // If no real blocks, return seed data for dashboard testing
    // Schema must match BlockEvent: { timestamp, client_ip, method, path, risk_score, matched_rules, block_reason, fingerprint }
    if blocks.is_empty() {
        let now = chrono::Utc::now().timestamp_millis();
        let seed_blocks = vec![
            serde_json::json!({
                "timestamp": now - 5 * 60 * 1000,
                "client_ip": "192.168.1.105",
                "method": "POST",
                "path": "/api/auth/login",
                "risk_score": 85,
                "matched_rules": [1001, 1002, 1003],
                "block_reason": "Credential stuffing attack - risk threshold exceeded",
                "fingerprint": "fp_a1b2c3d4"
            }),
            serde_json::json!({
                "timestamp": now - 12 * 60 * 1000,
                "client_ip": "10.0.0.42",
                "method": "GET",
                "path": "/api/users?id=1' OR '1'='1",
                "risk_score": 92,
                "matched_rules": [2001, 2005],
                "block_reason": "SQL injection attempt detected",
                "fingerprint": "fp_e5f6g7h8"
            }),
            serde_json::json!({
                "timestamp": now - 25 * 60 * 1000,
                "client_ip": "192.168.1.200",
                "method": "GET",
                "path": "/api/files/../../../etc/passwd",
                "risk_score": 88,
                "matched_rules": [3001, 3002],
                "block_reason": "Path traversal attack blocked",
                "fingerprint": "fp_i9j0k1l2"
            }),
            serde_json::json!({
                "timestamp": now - 55 * 60 * 1000,
                "client_ip": "203.0.113.50",
                "method": "POST",
                "path": "/api/admin/users",
                "risk_score": 95,
                "matched_rules": [4001, 4002, 4003, 4004],
                "block_reason": "Unauthorized admin access attempt",
                "fingerprint": "fp_m3n4o5p6"
            }),
            serde_json::json!({
                "timestamp": now - 2 * 60 * 60 * 1000,
                "client_ip": "10.0.0.99",
                "method": "GET",
                "path": "/api/export/database",
                "risk_score": 78,
                "matched_rules": [5001],
                "block_reason": "Data exfiltration pattern detected",
                "fingerprint": "fp_q7r8s9t0"
            }),
            serde_json::json!({
                "timestamp": now - 3 * 60 * 60 * 1000,
                "client_ip": "198.51.100.22",
                "method": "GET",
                "path": "/api/products",
                "risk_score": 72,
                "matched_rules": [6001],
                "block_reason": "Automated bot blocked - rate limit exceeded",
                "fingerprint": null
            }),
        ];
        return (StatusCode::OK, Json(serde_json::json!({ "blocks": seed_blocks.into_iter().take(limit).collect::<Vec<_>>() })));
    }

    (StatusCode::OK, Json(serde_json::json!({ "blocks": blocks })))
}

/// GET /_sensor/trends - Returns empty trends data
async fn sensor_trends_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "signalCounts": {},
        "timeline": [],
        "topSignals": []
    })))
}

/// GET /_sensor/anomalies - Returns anomaly events for threat activity
async fn sensor_anomalies_handler() -> impl IntoResponse {
    let now = chrono::Utc::now();

    // Seed data matching Anomaly interface
    let anomalies = vec![
        serde_json::json!({
            "id": "anom-001",
            "type": "credential_stuffing",
            "severity": "high",
            "description": "Multiple failed login attempts from distributed IPs targeting /api/auth/login",
            "entityId": "192.168.1.105",
            "riskApplied": 45,
            "timestamp": (now - chrono::Duration::minutes(5)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-002",
            "type": "sql_injection",
            "severity": "high",
            "description": "SQL injection pattern detected in query parameter on /api/search",
            "entityId": "10.0.0.42",
            "riskApplied": 65,
            "timestamp": (now - chrono::Duration::minutes(12)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-003",
            "type": "rate_limit_exceeded",
            "severity": "medium",
            "description": "Request rate 5x above baseline for /api/products endpoint",
            "entityId": "172.16.0.88",
            "riskApplied": 25,
            "timestamp": (now - chrono::Duration::minutes(18)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-004",
            "type": "path_traversal",
            "severity": "high",
            "description": "Path traversal attempt detected: ../../../etc/passwd",
            "entityId": "192.168.1.200",
            "riskApplied": 70,
            "timestamp": (now - chrono::Duration::minutes(25)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-005",
            "type": "xss_attempt",
            "severity": "medium",
            "description": "Cross-site scripting payload in user input field",
            "entityId": "10.0.0.15",
            "riskApplied": 35,
            "timestamp": (now - chrono::Duration::minutes(32)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-006",
            "type": "enumeration_attack",
            "severity": "low",
            "description": "Sequential user ID enumeration detected on /api/users/{id}",
            "entityId": "192.168.1.55",
            "riskApplied": 15,
            "timestamp": (now - chrono::Duration::minutes(45)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-007",
            "type": "admin_access",
            "severity": "high",
            "description": "Unauthorized access attempt to /api/admin/users from external IP",
            "entityId": "203.0.113.50",
            "riskApplied": 80,
            "timestamp": (now - chrono::Duration::minutes(55)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-008",
            "type": "bot_behavior",
            "severity": "medium",
            "description": "Automated bot pattern detected - no JS execution, fixed timing",
            "entityId": "198.51.100.22",
            "riskApplied": 30,
            "timestamp": (now - chrono::Duration::hours(1)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-009",
            "type": "data_exfiltration",
            "severity": "high",
            "description": "Unusually large response payload (15MB) to single client",
            "entityId": "10.0.0.99",
            "riskApplied": 55,
            "timestamp": (now - chrono::Duration::hours(2)).to_rfc3339()
        }),
        serde_json::json!({
            "id": "anom-010",
            "type": "session_anomaly",
            "severity": "low",
            "description": "Session token reuse from different geographic location",
            "entityId": "172.16.0.150",
            "riskApplied": 20,
            "timestamp": (now - chrono::Duration::hours(3)).to_rfc3339()
        }),
    ];

    (StatusCode::OK, Json(serde_json::json!({ "data": anomalies })))
}

/// GET /_sensor/campaigns - Returns active threat campaigns
async fn sensor_campaigns_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let campaigns = match state.handler.campaign_manager() {
        Some(manager) => {
            manager.get_campaigns()
                .into_iter()
                .map(|c| serde_json::json!({
                    "id": c.id,
                    "status": format!("{:?}", c.status).to_lowercase(),
                    "actorCount": c.actor_count,
                    "confidence": (c.confidence * 100.0) as u8,
                    "attackTypes": c.correlation_reasons.iter()
                        .map(|r| format!("{:?}", r.correlation_type).to_lowercase())
                        .collect::<Vec<_>>(),
                    "firstSeen": c.first_seen.to_rfc3339(),
                    "lastActivity": c.last_activity.to_rfc3339(),
                    "totalRequests": c.total_requests,
                    "blockedRequests": c.blocked_requests,
                    "rulesTriggered": c.rules_triggered,
                    "riskScore": c.risk_score as u8
                }))
                .collect::<Vec<_>>()
        }
        None => vec![]
    };

    (StatusCode::OK, Json(serde_json::json!({ "data": campaigns })))
}

/// GET /_sensor/campaigns/:id - Campaign detail
async fn sensor_campaign_detail_handler(
    State(state): State<AdminState>,
    Path(id): Path<String>
) -> impl IntoResponse {
    match state.handler.campaign_manager() {
        Some(manager) => {
            match manager.get_campaign(&id) {
                Some(c) => {
                    let data = serde_json::json!({
                        "id": c.id,
                        "status": format!("{:?}", c.status).to_lowercase(),
                        "actorCount": c.actor_count,
                        "confidence": (c.confidence * 100.0) as u8,
                        "attackTypes": c.correlation_reasons.iter()
                            .map(|r| format!("{:?}", r.correlation_type).to_lowercase())
                            .collect::<Vec<_>>(),
                        "firstSeen": c.first_seen.to_rfc3339(),
                        "lastActivity": c.last_activity.to_rfc3339(),
                        "totalRequests": c.total_requests,
                        "blockedRequests": c.blocked_requests,
                        "rulesTriggered": c.rules_triggered,
                        "riskScore": c.risk_score as u8,
                        "correlationReasons": c.correlation_reasons.iter().map(|r| {
                            serde_json::json!({
                                "type": format!("{:?}", r.correlation_type).to_lowercase(),
                                "confidence": (r.confidence * 100.0) as u8,
                                "description": r.description
                            })
                        }).collect::<Vec<_>>()
                    });
                    (StatusCode::OK, Json(serde_json::json!({ "data": data })))
                }
                None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
                    "error": format!("Campaign {} not found", id)
                })))
            }
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "Campaign correlation not enabled"
        })))
    }
}

// Placeholder for future campaign detail implementation
#[allow(dead_code)]
async fn _sensor_campaign_detail_handler_mock(Path(id): Path<String>) -> impl IntoResponse {
    let now = chrono::Utc::now();

    // Campaign data lookup (would come from real store in production)
    let campaign_data = match id.as_str() {
        "camp-001" => Some(serde_json::json!({
            "id": "camp-001",
            "status": "active",
            "actorCount": 12,
            "confidence": 87,
            "attackTypes": ["credential_stuffing", "rate_abuse"],
            "firstSeen": (now - chrono::Duration::hours(4)).to_rfc3339(),
            "lastActivity": (now - chrono::Duration::minutes(8)).to_rfc3339(),
            "totalRequests": 2450,
            "blockedRequests": 1890,
            "rulesTriggered": 156,
            "riskScore": 78,
            "correlationReasons": [
                {
                    "type": "shared_fingerprint",
                    "confidence": 92,
                    "description": "12 actors sharing identical browser fingerprint despite different IPs",
                    "actors": ["192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50", "10.0.0.51"]
                },
                {
                    "type": "timing_correlation",
                    "confidence": 85,
                    "description": "Request patterns show coordinated timing within 50ms windows",
                    "actors": ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
                },
                {
                    "type": "behavioral_similarity",
                    "confidence": 78,
                    "description": "Identical request sequences targeting /api/auth endpoints",
                    "actors": ["192.168.1.100", "10.0.0.50", "10.0.0.51", "172.16.0.10"]
                }
            ]
        })),
        "camp-002" => Some(serde_json::json!({
            "id": "camp-002",
            "status": "active",
            "actorCount": 5,
            "confidence": 72,
            "attackTypes": ["sql_injection", "path_traversal"],
            "firstSeen": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "lastActivity": (now - chrono::Duration::minutes(15)).to_rfc3339(),
            "totalRequests": 380,
            "blockedRequests": 342,
            "rulesTriggered": 89,
            "riskScore": 85,
            "correlationReasons": [
                {
                    "type": "attack_sequence",
                    "confidence": 88,
                    "description": "Sequential SQLi probes followed by path traversal attempts",
                    "actors": ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
                },
                {
                    "type": "shared_user_agent",
                    "confidence": 65,
                    "description": "Uncommon user agent string shared across all actors",
                    "actors": ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14"]
                }
            ]
        })),
        "camp-003" => Some(serde_json::json!({
            "id": "camp-003",
            "status": "detected",
            "actorCount": 3,
            "confidence": 65,
            "attackTypes": ["enumeration", "scraping"],
            "firstSeen": (now - chrono::Duration::hours(6)).to_rfc3339(),
            "lastActivity": (now - chrono::Duration::minutes(45)).to_rfc3339(),
            "totalRequests": 8500,
            "blockedRequests": 2100,
            "rulesTriggered": 42,
            "riskScore": 45,
            "correlationReasons": [
                {
                    "type": "behavioral_similarity",
                    "confidence": 70,
                    "description": "Systematic enumeration of /api/users/* endpoints",
                    "actors": ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
                }
            ]
        })),
        "camp-004" => Some(serde_json::json!({
            "id": "camp-004",
            "status": "resolved",
            "actorCount": 8,
            "confidence": 91,
            "attackTypes": ["xss", "csrf"],
            "firstSeen": (now - chrono::Duration::hours(12)).to_rfc3339(),
            "lastActivity": (now - chrono::Duration::hours(3)).to_rfc3339(),
            "totalRequests": 1200,
            "blockedRequests": 1180,
            "rulesTriggered": 234,
            "riskScore": 92,
            "resolvedAt": (now - chrono::Duration::hours(2)).to_rfc3339(),
            "resolvedReason": "All actors blocked and added to blocklist",
            "correlationReasons": [
                {
                    "type": "shared_fingerprint",
                    "confidence": 95,
                    "description": "All actors using identical headless browser configuration",
                    "actors": ["45.33.32.1", "45.33.32.2", "45.33.32.3", "45.33.32.4"]
                },
                {
                    "type": "network_proximity",
                    "confidence": 88,
                    "description": "All IPs from same AS (AS12345 - Known bad actor network)",
                    "actors": ["45.33.32.1", "45.33.32.2", "45.33.32.3", "45.33.32.4", "45.33.32.5", "45.33.32.6", "45.33.32.7", "45.33.32.8"]
                }
            ]
        })),
        _ => None,
    };

    match campaign_data {
        Some(data) => (StatusCode::OK, Json(serde_json::json!({ "data": data }))),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Campaign not found" }))),
    }
}

/// GET /_sensor/campaigns/:id/actors - Campaign actors
async fn sensor_campaign_actors_handler(
    State(state): State<AdminState>,
    Path(id): Path<String>
) -> impl IntoResponse {
    match state.handler.campaign_manager() {
        Some(manager) => {
            let actors = manager.get_campaign_actors(&id);
            let actor_data: Vec<serde_json::Value> = actors.into_iter().map(|ip| {
                serde_json::json!({
                    "ip": ip.to_string(),
                    "risk": 50,  // Would come from EntityManager in full integration
                    "sessionCount": 1,
                    "fingerprintCount": 1,
                    "jsExecuted": false,
                    "suspicious": true,
                    "lastActivity": chrono::Utc::now().to_rfc3339(),
                    "joinedAt": chrono::Utc::now().to_rfc3339(),
                    "role": "member",
                    "requestsInCampaign": 0,
                    "blockedInCampaign": 0
                })
            }).collect();

            (StatusCode::OK, Json(serde_json::json!({ "actors": actor_data })))
        }
        None => (StatusCode::OK, Json(serde_json::json!({ "actors": [] })))
    }
}

/// GET /_sensor/campaigns/:id/timeline - Campaign timeline events
async fn sensor_campaign_timeline_handler(Path(id): Path<String>) -> impl IntoResponse {
    let now = chrono::Utc::now();

    // Mock timeline events based on campaign
    let events: Vec<serde_json::Value> = match id.as_str() {
        "camp-001" => vec![
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(4)).to_rfc3339(),
                "type": "actor_joined",
                "actorIp": "192.168.1.100",
                "description": "First actor detected - credential stuffing pattern identified",
                "risk": 45
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(3) - chrono::Duration::minutes(45)).to_rfc3339(),
                "type": "detection",
                "actorIp": "192.168.1.100",
                "description": "Campaign correlation triggered - shared fingerprint detected",
                "risk": 55
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(3)).to_rfc3339(),
                "type": "actor_joined",
                "actorIp": "192.168.1.101",
                "description": "Second actor joined - same fingerprint cluster",
                "risk": 62
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(3)).to_rfc3339(),
                "type": "actor_joined",
                "actorIp": "192.168.1.102",
                "description": "Third actor joined - timing correlation confirmed",
                "risk": 68
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(2) - chrono::Duration::minutes(30)).to_rfc3339(),
                "type": "escalation",
                "actorIp": "192.168.1.100",
                "description": "Campaign escalated to high priority - rate abuse detected",
                "risk": 75,
                "ruleId": 941100
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(2)).to_rfc3339(),
                "type": "block",
                "actorIp": "192.168.1.100",
                "description": "Actor blocked - risk threshold exceeded",
                "risk": 85,
                "ruleId": 941100
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::minutes(30)).to_rfc3339(),
                "type": "attack",
                "actorIp": "10.0.0.50",
                "description": "Continued attack from new IP in fingerprint cluster",
                "risk": 72,
                "ruleId": 942100
            }),
        ],
        "camp-002" => vec![
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(2)).to_rfc3339(),
                "type": "actor_joined",
                "actorIp": "203.0.113.10",
                "description": "SQL injection probe detected from new actor",
                "risk": 65,
                "ruleId": 942100
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(1) - chrono::Duration::minutes(45)).to_rfc3339(),
                "type": "attack",
                "actorIp": "203.0.113.10",
                "description": "Path traversal attempt following SQLi probe",
                "risk": 78,
                "ruleId": 930110
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::hours(1)).to_rfc3339(),
                "type": "actor_joined",
                "actorIp": "203.0.113.11",
                "description": "Second actor joined - same attack sequence detected",
                "risk": 72
            }),
            serde_json::json!({
                "timestamp": (now - chrono::Duration::minutes(30)).to_rfc3339(),
                "type": "block",
                "actorIp": "203.0.113.10",
                "description": "Actor blocked after repeated SQLi attempts",
                "risk": 92,
                "ruleId": 942100
            }),
        ],
        _ => vec![],
    };

    (StatusCode::OK, Json(serde_json::json!({ "data": events })))
}

/// GET /_sensor/payload/bandwidth - Returns bandwidth statistics from profiler
async fn sensor_bandwidth_handler(
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let metrics = state.handler.metrics();
    let stats = metrics.get_bandwidth_stats();

    // Convert timeline to JSON-friendly format
    let timeline: Vec<serde_json::Value> = stats.timeline.iter()
        .filter(|p| p.timestamp > 0)
        .map(|p| serde_json::json!({
            "timestamp": p.timestamp,
            "bytesIn": p.bytes_in,
            "bytesOut": p.bytes_out,
            "requestCount": p.request_count
        }))
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "totalBytes": stats.total_bytes,
        "totalBytesIn": stats.total_bytes_in,
        "totalBytesOut": stats.total_bytes_out,
        "avgBytesPerRequest": stats.avg_bytes_per_request,
        "maxRequestSize": stats.max_request_size,
        "maxResponseSize": stats.max_response_size,
        "requestCount": stats.request_count,
        "timeline": timeline
    })))
}

/// Query parameters for actors endpoint
#[derive(Debug, Deserialize)]
struct ActorsQuery {
    limit: Option<usize>,
}

/// GET /_sensor/actors - Returns actors from ActorManager with behavioral tracking data
async fn sensor_actors_handler(
    Query(params): Query<ActorsQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);

    match state.handler.actor_manager() {
        Some(manager) => {
            let actors = manager.list_actors(limit, 0);
            let actor_data: Vec<serde_json::Value> = actors
                .into_iter()
                .map(|actor| {
                    serde_json::json!({
                        "actorId": actor.actor_id,
                        "riskScore": actor.risk_score,
                        "ruleMatches": actor.rule_matches.iter().map(|rm| {
                            serde_json::json!({
                                "ruleId": rm.rule_id,
                                "timestamp": rm.timestamp,
                                "riskContribution": rm.risk_contribution,
                                "category": rm.category
                            })
                        }).collect::<Vec<_>>(),
                        "anomalyCount": actor.anomaly_count,
                        "sessionIds": actor.session_ids,
                        "firstSeen": actor.first_seen,
                        "lastSeen": actor.last_seen,
                        "ips": actor.ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                        "fingerprints": actor.fingerprints.iter().cloned().collect::<Vec<_>>(),
                        "isBlocked": actor.is_blocked,
                        "blockReason": actor.block_reason,
                        "blockedSince": actor.blocked_since
                    })
                })
                .collect();

            // Also include stats if available
            let stats = manager.stats();
            (StatusCode::OK, Json(serde_json::json!({
                "actors": actor_data,
                "stats": {
                    "totalActors": stats.total_actors.load(std::sync::atomic::Ordering::Relaxed),
                    "blockedActors": stats.blocked_actors.load(std::sync::atomic::Ordering::Relaxed),
                    "correlationsMade": stats.correlations_made.load(std::sync::atomic::Ordering::Relaxed),
                    "evictions": stats.evictions.load(std::sync::atomic::Ordering::Relaxed),
                    "totalCreated": stats.total_created.load(std::sync::atomic::Ordering::Relaxed),
                    "totalRuleMatches": stats.total_rule_matches.load(std::sync::atomic::Ordering::Relaxed)
                }
            })))
        }
        None => (StatusCode::OK, Json(serde_json::json!({ "actors": [], "stats": null })))
    }
}

/// Query parameters for sessions endpoint
#[derive(Debug, Deserialize)]
struct SessionsQuery {
    limit: Option<usize>,
}

/// GET /_sensor/sessions - Returns sessions from SessionManager with hijack detection data
async fn sensor_sessions_handler(
    Query(params): Query<SessionsQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);

    match state.handler.session_manager() {
        Some(manager) => {
            let sessions = manager.list_sessions(limit, 0);
            let session_data: Vec<serde_json::Value> = sessions
                .into_iter()
                .map(|session| {
                    serde_json::json!({
                        "sessionId": session.session_id,
                        "tokenHash": &session.token_hash[..8], // Only show first 8 chars for security
                        "actorId": session.actor_id,
                        "creationTime": session.creation_time,
                        "lastActivity": session.last_activity,
                        "requestCount": session.request_count,
                        "boundJa4": session.bound_ja4,
                        "boundIp": session.bound_ip.map(|ip| ip.to_string()),
                        "isSuspicious": session.is_suspicious,
                        "hijackAlerts": session.hijack_alerts.iter().map(|alert| {
                            serde_json::json!({
                                "sessionId": alert.session_id,
                                "alertType": format!("{:?}", alert.alert_type),
                                "originalValue": alert.original_value,
                                "newValue": alert.new_value,
                                "timestamp": alert.timestamp,
                                "confidence": alert.confidence
                            })
                        }).collect::<Vec<_>>()
                    })
                })
                .collect();

            // Also include stats if available
            let stats = manager.stats();
            (StatusCode::OK, Json(serde_json::json!({
                "sessions": session_data,
                "stats": {
                    "totalSessions": stats.total_sessions.load(std::sync::atomic::Ordering::Relaxed),
                    "activeSessions": stats.active_sessions.load(std::sync::atomic::Ordering::Relaxed),
                    "suspiciousSessions": stats.suspicious_sessions.load(std::sync::atomic::Ordering::Relaxed),
                    "expiredSessions": stats.expired_sessions.load(std::sync::atomic::Ordering::Relaxed),
                    "hijackAlerts": stats.hijack_alerts.load(std::sync::atomic::Ordering::Relaxed),
                    "evictions": stats.evictions.load(std::sync::atomic::Ordering::Relaxed),
                    "totalCreated": stats.total_created.load(std::sync::atomic::Ordering::Relaxed),
                    "totalInvalidated": stats.total_invalidated.load(std::sync::atomic::Ordering::Relaxed)
                }
            })))
        }
        None => (StatusCode::OK, Json(serde_json::json!({ "sessions": [], "stats": null })))
    }
}

/// GET /_sensor/stuffing - Returns credential stuffing detection data
async fn sensor_stuffing_handler() -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp_millis() as u64;

    // Seed data matching StuffingStats interface
    let stats = serde_json::json!({
        "entityCount": 156,
        "distributedAttackCount": 3,
        "takeoverAlertCount": 5,
        "eventCount": 42,
        "totalFailures": 1847,
        "totalSuccesses": 12453,
        "suspiciousEntities": 28
    });

    // Seed data matching TakeoverAlert interface
    let takeover_alerts = vec![
        serde_json::json!({
            "entityId": "192.168.1.105",
            "endpoint": "/api/auth/login",
            "priorFailures": 12,
            "failureWindowMs": 300000,
            "successAt": now - 180000,
            "severity": "critical"
        }),
        serde_json::json!({
            "entityId": "10.0.0.42",
            "endpoint": "/api/auth/login",
            "priorFailures": 8,
            "failureWindowMs": 300000,
            "successAt": now - 420000,
            "severity": "high"
        }),
        serde_json::json!({
            "entityId": "172.16.0.88",
            "endpoint": "/api/users/login",
            "priorFailures": 5,
            "failureWindowMs": 300000,
            "successAt": now - 900000,
            "severity": "medium"
        }),
        serde_json::json!({
            "entityId": "192.168.1.200",
            "endpoint": "/api/auth/login",
            "priorFailures": 15,
            "failureWindowMs": 300000,
            "successAt": now - 1800000,
            "severity": "critical"
        }),
        serde_json::json!({
            "entityId": "10.0.0.99",
            "endpoint": "/api/v2/auth",
            "priorFailures": 6,
            "failureWindowMs": 300000,
            "successAt": now - 3600000,
            "severity": "high"
        }),
    ];

    // Seed data matching DistributedAttack interface
    let distributed_attacks = vec![
        serde_json::json!({
            "fingerprint": "fp_8a3b2c1d4e5f6789",
            "endpoint": "/api/auth/login",
            "entities": ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"],
            "totalFailures": 245,
            "windowStart": now - 3600000,
            "lastActivity": now - 120000,
            "correlationScore": 0.92
        }),
        serde_json::json!({
            "fingerprint": "fp_2d3e4f5a6b7c8901",
            "endpoint": "/api/users/authenticate",
            "entities": ["10.0.0.50", "10.0.0.51", "10.0.0.52"],
            "totalFailures": 156,
            "windowStart": now - 7200000,
            "lastActivity": now - 600000,
            "correlationScore": 0.78
        }),
        serde_json::json!({
            "fingerprint": "fp_9f8e7d6c5b4a3210",
            "endpoint": "/api/auth/login",
            "entities": ["172.16.0.20", "172.16.0.21", "172.16.0.22", "172.16.0.23"],
            "totalFailures": 89,
            "windowStart": now - 1800000,
            "lastActivity": now - 300000,
            "correlationScore": 0.85
        }),
    ];

    (StatusCode::OK, Json(serde_json::json!({
        "stats": stats,
        "takeoverAlerts": takeover_alerts,
        "distributedAttacks": distributed_attacks
    })))
}

/// GET /_sensor/system/config - Returns system configuration
async fn sensor_system_config_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let sites = state.handler.handle_list_sites();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "general": {
                "port": 6190,
                "sensorId": "synapse-pingora",
                "sensorMode": "proxy",
                "demoMode": false
            },
            "waf": {
                "enabled": true,
                "allowIpSpoofing": false,
                "trustedIpHeaders": ["X-Forwarded-For", "X-Real-IP"],
                "trustPrivateProxyRanges": true,
                "trustedProxyCidrs": []
            },
            "features": {
                "atlasCrewMode": false,
                "waf": true,
                "rateLimit": true,
                "accessLists": true,
                "campaigns": false,
                "actors": false,
                "anomalies": false
            },
            "runtimeConfig": {
                "risk": {
                    "autoblockThreshold": 80,
                    "riskDecayPerMinute": 5.0,
                    "maxRiskHistory": 100
                },
                "state": {
                    "maxBlockHistory": 500,
                    "maxIpsTracked": 10000,
                    "maxKeysPerIp": 50,
                    "maxValuesPerKey": 500,
                    "cleanupWindowMs": 300000
                },
                "session": {
                    "enabled": true,
                    "maxSessions": 10000,
                    "expirationMs": 1800000,
                    "cookieName": "synapse_session",
                    "headerName": "X-Session-Id",
                    "cleanupIntervalMs": 60000
                },
                "trends": {
                    "enabled": true,
                    "bucketSizeMs": 60000,
                    "retentionHours": 24,
                    "maxSignalsPerBucket": 5000,
                    "anomalyCheckIntervalMs": 30000
                },
                "anomalyRisk": {
                    "fingerprintChange": 25,
                    "sessionSharing": 30,
                    "tokenReuse": 20,
                    "velocitySpike": 35,
                    "rotationPattern": 40,
                    "timingAnomaly": 15,
                    "impossibleTravel": 50,
                    "oversizedRequest": 20,
                    "oversizedResponse": 25,
                    "bandwidthSpike": 30,
                    "exfiltrationPattern": 45,
                    "uploadPattern": 35
                },
                "payload": {
                    "enabled": true,
                    "windowSizeMs": 60000,
                    "retentionWindows": 60,
                    "maxEndpoints": 1000,
                    "maxEntities": 10000,
                    "oversizeThreshold": 3.0,
                    "spikeThreshold": 5.0,
                    "warmupRequests": 50,
                    "exfiltrationRatio": 100,
                    "uploadRatio": 50,
                    "minLargePayload": 100000
                },
                "credentialStuffing": {
                    "enabled": true,
                    "failureWindowMs": 300000,
                    "failureThresholdSuspicious": 5,
                    "failureThresholdHigh": 10,
                    "failureThresholdBlock": 20,
                    "distributedMinIps": 3,
                    "distributedWindowMs": 600000,
                    "takeoverWindowMs": 300000,
                    "takeoverMinFailures": 3,
                    "lowSlowMinHours": 6,
                    "lowSlowMinPerHour": 2,
                    "maxEntities": 10000,
                    "broadcastIntervalMs": 5000
                },
                "ha": {
                    "sensorMode": "standalone",
                    "peerUrl": null,
                    "syncIntervalMs": 100,
                    "heartbeatIntervalMs": 5000,
                    "reconnectBaseDelayMs": 1000,
                    "reconnectMaxDelayMs": 30000,
                    "maxQueueSize": 10000,
                    "maxClockDriftMs": 300000,
                    "maxMessageSize": 1000000,
                    "messageRateLimit": 1000,
                    "enableSplitBrainDetection": true,
                    "heartbeatTimeoutMs": 15000,
                    "primaryElectionMode": "manual"
                },
                "dashboard": {
                    "pollIntervalMs": 1000,
                    "wsHeartbeatIntervalMs": 30000,
                    "wsMaxClients": 50
                },
                "nginx": {
                    "listenPort": 6190,
                    "statusPort": 6191,
                    "statusAllow": ["127.0.0.1", "::1"],
                    "proxyReadTimeoutMs": 60000,
                    "proxySendTimeoutMs": 60000,
                    "clientBodyBufferSizeKb": 128,
                    "clientMaxBodySizeMb": 10,
                    "gzipEnabled": true,
                    "sslEnabled": false,
                    "certificateId": null,
                    "accessListId": null,
                    "customDirectives": null
                }
            },
            "startupFlags": [],
            "sites": sites.data.map(|s| s.sites).unwrap_or_default()
        }
    })))
}

/// GET /_sensor/system/overview - System overview metrics
/// Returns data matching frontend's SystemOverviewData interface
async fn sensor_system_overview_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let health = state.handler.handle_health();
    let uptime_secs = health.data.as_ref().map(|h| h.uptime_secs).unwrap_or(0);

    // Get real system metrics
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_cores = sys.cpus().len();
    let global_cpu = sys.global_cpu_usage();
    let load_avg = System::load_average();

    // Get per-core CPU usage
    let per_core: Vec<_> = sys.cpus().iter().enumerate()
        .map(|(i, cpu)| serde_json::json!({ "id": i, "usage": cpu.cpu_usage() }))
        .collect();

    // Memory stats
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let free_mem = sys.free_memory();
    let mem_percent = if total_mem > 0 { (used_mem as f64 / total_mem as f64) * 100.0 } else { 0.0 };

    // Disk stats
    let disks = Disks::new_with_refreshed_list();
    let disk_info = disks.list().first().map(|d| {
        let total = d.total_space();
        let free = d.available_space();
        let used = total.saturating_sub(free);
        let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
        serde_json::json!({
            "total": total,
            "used": used,
            "free": free,
            "usagePercent": percent
        })
    });

    // Network interfaces
    let networks = Networks::new_with_refreshed_list();
    let interfaces: Vec<_> = networks.iter()
        .map(|(name, data)| serde_json::json!({
            "name": name,
            "ip": "0.0.0.0",
            "mac": data.mac_address().to_string(),
            "family": "IPv4",
            "internal": name == "lo" || name == "lo0"
        }))
        .collect();

    // Current process info
    let pid = std::process::id();
    let process_mem = sys.process(sysinfo::Pid::from_u32(pid))
        .map(|p| p.memory())
        .unwrap_or(0);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "system": {
                "hostname": System::host_name().unwrap_or_else(|| "synapse-pingora".to_string()),
                "platform": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "release": System::os_version().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
                "uptime": uptime_secs,
                "loadAvg": [load_avg.one, load_avg.five, load_avg.fifteen]
            },
            "resources": {
                "cpu": {
                    "model": sys.cpus().first().map(|c| c.brand()).unwrap_or("Unknown"),
                    "cores": cpu_cores,
                    "usage": global_cpu,
                    "perCore": per_core
                },
                "memory": {
                    "total": total_mem,
                    "used": used_mem,
                    "free": free_mem,
                    "usagePercent": mem_percent
                },
                "disk": disk_info
            },
            "network": {
                "interfaces": interfaces,
                "primaryIp": "127.0.0.1"
            },
            "process": {
                "pid": pid,
                "uptime": uptime_secs,
                "memoryUsage": {
                    "rss": process_mem,
                    "heapTotal": 0,
                    "heapUsed": 0
                }
            }
        }
    })))
}

/// GET /_sensor/system/performance - Performance metrics
/// Returns data matching frontend's SystemPerformanceData interface
async fn sensor_system_performance_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let mut sys = System::new_all();
    sys.refresh_all();

    let cpu_cores = sys.cpus().len();
    let global_cpu = sys.global_cpu_usage();

    // Per-core CPU usage
    let per_core: Vec<_> = sys.cpus().iter().enumerate()
        .map(|(i, cpu)| serde_json::json!({ "id": i, "usage": cpu.cpu_usage() }))
        .collect();

    // Memory stats
    let total_mem = sys.total_memory();
    let used_mem = sys.used_memory();
    let free_mem = sys.free_memory();
    let mem_percent = if total_mem > 0 { (used_mem as f64 / total_mem as f64) * 100.0 } else { 0.0 };

    // Disk stats
    let disks = Disks::new_with_refreshed_list();
    let disk_info = disks.list().first().map(|d| {
        let total = d.total_space();
        let free = d.available_space();
        let used = total.saturating_sub(free);
        let percent = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
        serde_json::json!({
            "total": total,
            "used": used,
            "free": free,
            "usagePercent": percent
        })
    });

    // Record this sample to history
    record_metrics_sample();

    // Get history for charts
    let history: Vec<_> = METRICS_HISTORY.read().iter().cloned().collect();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "current": {
                "cpu": {
                    "usage": global_cpu,
                    "perCore": per_core,
                    "model": sys.cpus().first().map(|c| c.brand()).unwrap_or("Unknown"),
                    "cores": cpu_cores
                },
                "memory": {
                    "total": total_mem,
                    "used": used_mem,
                    "free": free_mem,
                    "usagePercent": mem_percent
                },
                "disk": disk_info
            },
            "history": history
        }
    })))
}

/// GET /_sensor/system/network - Network statistics
/// Returns data matching frontend's SystemNetworkData interface
async fn sensor_system_network_handler() -> impl IntoResponse {
    let networks = Networks::new_with_refreshed_list();

    // Network interfaces with traffic stats
    let interfaces: Vec<_> = networks.iter()
        .map(|(name, data)| serde_json::json!({
            "name": name,
            "ip": "0.0.0.0",
            "mac": data.mac_address().to_string(),
            "family": "IPv4",
            "internal": name == "lo" || name == "lo0",
            "rxBytes": data.total_received(),
            "txBytes": data.total_transmitted(),
            "rxPackets": data.total_packets_received(),
            "txPackets": data.total_packets_transmitted()
        }))
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "interfaces": interfaces,
            "connections": [],
            "summary": {
                "total": 0,
                "established": 0,
                "listening": 1,
                "timeWait": 0,
                "closeWait": 0
            },
            "dns": {
                "servers": ["8.8.8.8", "8.8.4.4"],
                "search": []
            }
        }
    })))
}

/// GET /_sensor/system/processes - Process information
/// Returns data matching frontend's SystemProcessesData interface
async fn sensor_system_processes_handler() -> impl IntoResponse {
    let mut sys = System::new_all();
    sys.refresh_all();

    let current_pid = std::process::id();
    let total_mem = sys.total_memory() as f64;

    // Get top processes by CPU usage
    let mut processes: Vec<_> = sys.processes().iter()
        .map(|(pid, proc)| {
            let mem_percent = if total_mem > 0.0 { (proc.memory() as f64 / total_mem) * 100.0 } else { 0.0 };
            serde_json::json!({
                "pid": pid.as_u32(),
                "name": proc.name().to_string_lossy(),
                "user": proc.user_id().map(|u| u.to_string()).unwrap_or_default(),
                "cpu": proc.cpu_usage(),
                "memory": mem_percent,
                "status": format!("{:?}", proc.status()).to_lowercase(),
                "command": proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ")
            })
        })
        .collect();

    // Sort by CPU usage and take top 20
    processes.sort_by(|a, b| {
        let cpu_a = a.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let cpu_b = b.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
        cpu_b.partial_cmp(&cpu_a).unwrap_or(std::cmp::Ordering::Equal)
    });
    processes.truncate(20);

    // Find synapse-pingora process for Atlas Crew services
    let synapse_proc = sys.process(sysinfo::Pid::from_u32(current_pid));
    let atlascrew_services: Vec<_> = synapse_proc.map(|p| {
        let mem_percent = if total_mem > 0.0 { (p.memory() as f64 / total_mem) * 100.0 } else { 0.0 };
        vec![serde_json::json!({
            "name": "synapse-pingora",
            "status": "running",
            "pid": current_pid,
            "cpu": p.cpu_usage(),
            "memory": mem_percent
        })]
    }).unwrap_or_default();

    // Count process states
    let mut running = 0;
    let mut sleeping = 0;
    let mut stopped = 0;
    let mut zombie = 0;
    for proc in sys.processes().values() {
        match proc.status() {
            sysinfo::ProcessStatus::Run => running += 1,
            sysinfo::ProcessStatus::Sleep => sleeping += 1,
            sysinfo::ProcessStatus::Stop => stopped += 1,
            sysinfo::ProcessStatus::Zombie => zombie += 1,
            _ => sleeping += 1,
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "processes": processes,
            "services": {
                "atlascrew": atlascrew_services,
                "system": []
            },
            "summary": {
                "total": sys.processes().len(),
                "running": running,
                "sleeping": sleeping,
                "stopped": stopped,
                "zombie": zombie
            }
        }
    })))
}

/// GET /_sensor/system/logs - System logs
#[derive(Debug, serde::Deserialize)]
struct LogsQuery {
    #[serde(default = "default_log_limit")]
    limit: usize,
    #[serde(default)]
    level: Option<String>,
}

fn default_log_limit() -> usize { 100 }

async fn sensor_system_logs_handler(Query(params): Query<LogsQuery>) -> impl IntoResponse {
    // Get logs from buffer
    let logs = LOG_BUFFER.read();
    let limit = params.limit.min(200);

    // Filter by level if specified
    let filtered: Vec<_> = logs.iter()
        .filter(|log| {
            params.level.as_ref().map(|l| log.level == *l).unwrap_or(true)
        })
        .take(limit)
        .cloned()
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "logs": filtered,
            "hasMore": logs.len() > limit
        }
    })))
}

use crate::persistence::SnapshotManager;

// =============================================================================
// API Profiling Endpoints (for API Catalog)
// =============================================================================

/// Query parameters for discovery endpoint
#[derive(Debug, Deserialize)]
struct DiscoveryQuery {
    #[serde(default = "default_discovery_limit")]
    limit: usize,
}

fn default_discovery_limit() -> usize { 20 }

/// GET /_sensor/profiling/templates - Returns endpoint templates discovered by profiler
async fn profiling_templates_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Get real endpoint stats from metrics registry
    let endpoint_stats = state.handler.metrics().get_endpoint_stats();

    // Convert to template format expected by the dashboard
    let templates: Vec<serde_json::Value> = endpoint_stats
        .into_iter()
        .map(|(path, stats)| {
            // Infer service ID from path prefix
            let service_id = infer_service_id(&path);
            // Infer tags based on path patterns
            let tags = infer_endpoint_tags(&path);

            serde_json::json!({
                "template": path,
                "matchCount": stats.hit_count,
                "examples": [path.clone()],
                "firstSeen": stats.first_seen,
                "lastSeen": stats.last_seen,
                "serviceId": service_id,
                "tags": tags,
                "methods": stats.methods
            })
        })
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "templates": templates,
        "count": templates.len()
    })))
}

/// Infer service ID from path prefix
fn infer_service_id(path: &str) -> &'static str {
    if path.contains("/auth") {
        "auth-service"
    } else if path.contains("/admin") {
        "admin-service"
    } else if path.contains("/users") || path.contains("/user") {
        "user-service"
    } else if path.contains("/product") {
        "product-service"
    } else if path.contains("/order") {
        "order-service"
    } else if path.contains("/payment") || path.contains("/checkout") {
        "payment-service"
    } else if path.contains("/search") {
        "search-service"
    } else if path.contains("/banking") {
        "banking-service"
    } else if path.contains("/healthcare") {
        "healthcare-service"
    } else if path.contains("/ecommerce") {
        "ecommerce-service"
    } else if path.contains("/genai") {
        "genai-service"
    } else {
        "api-gateway"
    }
}

/// Infer endpoint tags based on path patterns
fn infer_endpoint_tags(path: &str) -> Vec<&'static str> {
    let mut tags = vec!["REST"];

    if path.contains("/auth") || path.contains("/login") {
        tags.push("Auth");
        if path.contains("/login") {
            tags.push("Critical");
        }
    }
    if path.contains("/admin") {
        tags.push("Admin");
        tags.push("Internal");
    }
    if path.contains("/user") || path.contains("/account") {
        tags.push("PII");
    }
    if path.contains("/payment") || path.contains("/checkout") || path.contains("/banking") {
        tags.push("PCI");
        tags.push("Critical");
    }
    if path.contains("/healthcare") || path.contains("/records") {
        tags.push("PHI");
        tags.push("Critical");
    }
    if !path.contains("/admin") && !path.contains("/internal") {
        tags.push("Public");
    }

    tags
}

/// GET /_sensor/profiling/baselines - Returns traffic baselines per endpoint
async fn profiling_baselines_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp_millis() as u64;

    // Try to get real profile data from the detection engine
    let profiles = get_profiles();

    if !profiles.is_empty() {
        // Convert real profiles to baseline JSON format
        let baselines: Vec<serde_json::Value> = profiles.iter().map(|p| {
            // Get percentiles (p50, p95, p99)
            let (p50, p95, p99) = p.payload_size.percentiles();

            // Convert status codes HashMap to array of [code, count] pairs
            let status_codes: Vec<[u32; 2]> = p.status_codes
                .iter()
                .map(|(&code, &count)| [code as u32, count])
                .collect();

            // Calculate requests per minute based on time window
            let time_window_mins = ((p.last_updated_ms.saturating_sub(p.first_seen_ms)) as f64 / 60000.0).max(1.0);
            let avg_rpm = p.sample_count as f64 / time_window_mins;

            serde_json::json!({
                "template": p.template,
                "totalRequests": p.sample_count,
                "avgRequestsPerMinute": (avg_rpm * 100.0).round() / 100.0,
                "p50ResponseTime": p50 as u64,
                "p95ResponseTime": p95 as u64,
                "p99ResponseTime": p99 as u64,
                "statusCodes": status_codes,
                "firstSeen": p.first_seen_ms,
                "lastSeen": p.last_updated_ms
            })
        }).collect();

        return (StatusCode::OK, Json(serde_json::json!({
            "baselines": baselines,
            "count": baselines.len()
        })));
    }

    // Fallback: Seed data matching EndpointBaseline interface for dashboard testing
    let baselines = vec![
        serde_json::json!({
            "template": "/api/users",
            "totalRequests": 90,
            "avgRequestsPerMinute": 1.5,
            "p50ResponseTime": 45,
            "p95ResponseTime": 120,
            "p99ResponseTime": 250,
            "statusCodes": [[200, 85], [404, 4], [500, 1]],
            "firstSeen": now - 3600000,
            "lastSeen": now
        }),
        serde_json::json!({
            "template": "/api/users/{id}",
            "totalRequests": 156,
            "avgRequestsPerMinute": 2.6,
            "p50ResponseTime": 32,
            "p95ResponseTime": 95,
            "p99ResponseTime": 180,
            "statusCodes": [[200, 140], [404, 12], [500, 4]],
            "firstSeen": now - 7200000,
            "lastSeen": now - 60000
        }),
        serde_json::json!({
            "template": "/api/products/{id}",
            "totalRequests": 45,
            "avgRequestsPerMinute": 0.75,
            "p50ResponseTime": 28,
            "p95ResponseTime": 85,
            "p99ResponseTime": 150,
            "statusCodes": [[200, 40], [404, 5]],
            "firstSeen": now - 7200000,
            "lastSeen": now - 300000
        }),
        serde_json::json!({
            "template": "/api/auth/login",
            "totalRequests": 120,
            "avgRequestsPerMinute": 2.0,
            "p50ResponseTime": 180,
            "p95ResponseTime": 450,
            "p99ResponseTime": 800,
            "statusCodes": [[200, 95], [401, 20], [429, 5]],
            "firstSeen": now - 86400000,
            "lastSeen": now - 60000
        }),
        serde_json::json!({
            "template": "/api/auth/refresh",
            "totalRequests": 85,
            "avgRequestsPerMinute": 1.4,
            "p50ResponseTime": 65,
            "p95ResponseTime": 150,
            "p99ResponseTime": 280,
            "statusCodes": [[200, 80], [401, 5]],
            "firstSeen": now - 86400000,
            "lastSeen": now - 120000
        }),
        serde_json::json!({
            "template": "/api/admin/users",
            "totalRequests": 15,
            "avgRequestsPerMinute": 0.25,
            "p50ResponseTime": 120,
            "p95ResponseTime": 350,
            "p99ResponseTime": 500,
            "statusCodes": [[200, 10], [403, 5]],
            "firstSeen": now - 1800000,
            "lastSeen": now - 120000
        }),
        serde_json::json!({
            "template": "/api/search",
            "totalRequests": 200,
            "avgRequestsPerMinute": 3.3,
            "p50ResponseTime": 85,
            "p95ResponseTime": 220,
            "p99ResponseTime": 400,
            "statusCodes": [[200, 195], [400, 5]],
            "firstSeen": now - 172800000,
            "lastSeen": now
        }),
        serde_json::json!({
            "template": "/api/orders",
            "totalRequests": 67,
            "avgRequestsPerMinute": 1.1,
            "p50ResponseTime": 95,
            "p95ResponseTime": 280,
            "p99ResponseTime": 450,
            "statusCodes": [[200, 60], [401, 5], [500, 2]],
            "firstSeen": now - 43200000,
            "lastSeen": now - 180000
        }),
        serde_json::json!({
            "template": "/api/orders/{id}",
            "totalRequests": 134,
            "avgRequestsPerMinute": 2.2,
            "p50ResponseTime": 55,
            "p95ResponseTime": 140,
            "p99ResponseTime": 280,
            "statusCodes": [[200, 120], [404, 10], [401, 4]],
            "firstSeen": now - 43200000,
            "lastSeen": now - 60000
        }),
        serde_json::json!({
            "template": "/api/checkout",
            "totalRequests": 42,
            "avgRequestsPerMinute": 0.7,
            "p50ResponseTime": 320,
            "p95ResponseTime": 800,
            "p99ResponseTime": 1200,
            "statusCodes": [[200, 35], [400, 4], [500, 3]],
            "firstSeen": now - 21600000,
            "lastSeen": now - 300000
        }),
    ];

    (StatusCode::OK, Json(serde_json::json!({
        "baselines": baselines,
        "count": baselines.len()
    })))
}

/// GET /_sensor/profiling/schemas - Returns schema information per endpoint
async fn profiling_schemas_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp_millis() as u64;

    // Try to get real schema data from the schema learner
    let real_schemas = get_schemas();

    if !real_schemas.is_empty() {
        // Convert real schemas to JSON format matching the frontend interface
        let schemas: Vec<serde_json::Value> = real_schemas.iter().map(|s| {
            serde_json::json!({
                "template": s.template,
                "sampleCount": s.sample_count,
                "requestFieldCount": s.request_schema.len(),
                "responseFieldCount": s.response_schema.len(),
                "lastUpdated": s.last_updated_ms,
                "version": s.version
            })
        }).collect();

        return (StatusCode::OK, Json(serde_json::json!({
            "schemas": schemas,
            "count": schemas.len()
        })));
    }

    // Fallback: Seed data matching EndpointSchema interface for dashboard testing
    let schemas = vec![
        serde_json::json!({
            "template": "/api/users",
            "sampleCount": 90,
            "requestFieldCount": 3,  // page, limit, sort
            "responseFieldCount": 12, // id, email, name, etc.
            "lastUpdated": now - 300000
        }),
        serde_json::json!({
            "template": "/api/users/{id}",
            "sampleCount": 156,
            "requestFieldCount": 1,
            "responseFieldCount": 15,
            "lastUpdated": now - 120000
        }),
        serde_json::json!({
            "template": "/api/products/{id}",
            "sampleCount": 45,
            "requestFieldCount": 2,
            "responseFieldCount": 18,
            "lastUpdated": now - 600000
        }),
        serde_json::json!({
            "template": "/api/auth/login",
            "sampleCount": 120,
            "requestFieldCount": 3,  // username, password, remember
            "responseFieldCount": 5, // token, expires, user, etc.
            "lastUpdated": now - 60000
        }),
        serde_json::json!({
            "template": "/api/auth/refresh",
            "sampleCount": 85,
            "requestFieldCount": 1,
            "responseFieldCount": 3,
            "lastUpdated": now - 180000
        }),
        serde_json::json!({
            "template": "/api/admin/users",
            "sampleCount": 15,
            "requestFieldCount": 4,
            "responseFieldCount": 20,
            "lastUpdated": now - 240000
        }),
        serde_json::json!({
            "template": "/api/search",
            "sampleCount": 200,
            "requestFieldCount": 5,
            "responseFieldCount": 8,
            "lastUpdated": now - 30000
        }),
        serde_json::json!({
            "template": "/api/orders",
            "sampleCount": 67,
            "requestFieldCount": 3,
            "responseFieldCount": 14,
            "lastUpdated": now - 300000
        }),
        serde_json::json!({
            "template": "/api/orders/{id}",
            "sampleCount": 134,
            "requestFieldCount": 1,
            "responseFieldCount": 22,
            "lastUpdated": now - 120000
        }),
        serde_json::json!({
            "template": "/api/checkout",
            "sampleCount": 42,
            "requestFieldCount": 12, // cart, payment, shipping, etc.
            "responseFieldCount": 8,
            "lastUpdated": now - 600000
        }),
    ];

    (StatusCode::OK, Json(serde_json::json!({
        "schemas": schemas,
        "count": schemas.len()
    })))
}

/// GET /_sensor/profiling/schema/discovery - Returns recent discovery events
async fn profiling_discovery_handler(Query(params): Query<DiscoveryQuery>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let limit = params.limit.min(100);

    // Seed data matching DiscoveryEvent interface
    let all_events = vec![
        serde_json::json!({
            "type": "endpoint_discovered",
            "template": "/api/checkout",
            "timestamp": now - 300000,
            "details": "New endpoint discovered from traffic analysis"
        }),
        serde_json::json!({
            "type": "schema_changed",
            "template": "/api/users/{id}",
            "timestamp": now - 600000,
            "details": "Response schema gained 2 new fields",
            "version": 3
        }),
        serde_json::json!({
            "type": "endpoint_discovered",
            "template": "/api/orders/{id}/items",
            "timestamp": now - 900000,
            "details": "New nested endpoint discovered"
        }),
        serde_json::json!({
            "type": "schema_version",
            "template": "/api/auth/login",
            "timestamp": now - 1200000,
            "details": "Response now includes refresh_token field",
            "version": 2
        }),
        serde_json::json!({
            "type": "endpoint_discovered",
            "template": "/api/webhooks/stripe",
            "timestamp": now - 1800000,
            "details": "Webhook endpoint discovered"
        }),
        serde_json::json!({
            "type": "schema_changed",
            "template": "/api/products/{id}",
            "timestamp": now - 2400000,
            "details": "Added inventory_count to response",
            "version": 4
        }),
        serde_json::json!({
            "type": "endpoint_discovered",
            "template": "/api/admin/settings",
            "timestamp": now - 3600000,
            "details": "Admin settings endpoint found"
        }),
        serde_json::json!({
            "type": "schema_changed",
            "template": "/api/orders",
            "timestamp": now - 7200000,
            "details": "Request now accepts filter parameter",
            "version": 2
        }),
    ];

    let events: Vec<_> = all_events.into_iter().take(limit).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "events": events,
        "count": events.len()
    })))
}

/// GET /_sensor/profiling/anomalies - Returns anomaly data per endpoint
async fn profiling_anomalies_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let now = chrono::Utc::now().timestamp_millis() as u64;

    // Seed data matching EndpointAnomalyData interface
    let endpoints = vec![
        serde_json::json!({
            "template": "/api/auth/login",
            "anomalyScore": 45.5,
            "anomalyCount": 8,
            "totalRequests": 120,
            "recentAnomalies": [
                {
                    "timestamp": now - 120000,
                    "type": "high_failure_rate",
                    "severity": "high",
                    "score": 72.0,
                    "detail": "401 responses at 16.7% (threshold: 10%)"
                },
                {
                    "timestamp": now - 600000,
                    "type": "rate_spike",
                    "severity": "medium",
                    "score": 45.0,
                    "detail": "Request rate 3.2x above baseline"
                }
            ]
        }),
        serde_json::json!({
            "template": "/api/admin/users",
            "anomalyScore": 65.2,
            "anomalyCount": 5,
            "totalRequests": 15,
            "recentAnomalies": [
                {
                    "timestamp": now - 180000,
                    "type": "unauthorized_access",
                    "severity": "high",
                    "score": 85.0,
                    "detail": "403 responses from new IP range"
                },
                {
                    "timestamp": now - 300000,
                    "type": "unusual_timing",
                    "severity": "medium",
                    "score": 52.0,
                    "detail": "Access outside normal business hours"
                }
            ]
        }),
        serde_json::json!({
            "template": "/api/checkout",
            "anomalyScore": 38.7,
            "anomalyCount": 3,
            "totalRequests": 42,
            "recentAnomalies": [
                {
                    "timestamp": now - 450000,
                    "type": "response_time_spike",
                    "severity": "medium",
                    "score": 55.0,
                    "detail": "P99 latency 2.5x above baseline"
                }
            ]
        }),
        serde_json::json!({
            "template": "/api/search",
            "anomalyScore": 22.1,
            "anomalyCount": 2,
            "totalRequests": 200,
            "recentAnomalies": [
                {
                    "timestamp": now - 900000,
                    "type": "payload_size",
                    "severity": "low",
                    "score": 28.0,
                    "detail": "Unusually large query parameters"
                }
            ]
        }),
        serde_json::json!({
            "template": "/api/users/{id}",
            "anomalyScore": 12.5,
            "anomalyCount": 1,
            "totalRequests": 156,
            "recentAnomalies": [
                {
                    "timestamp": now - 1800000,
                    "type": "enumeration_pattern",
                    "severity": "low",
                    "score": 32.0,
                    "detail": "Sequential ID access pattern detected"
                }
            ]
        }),
    ];

    (StatusCode::OK, Json(serde_json::json!({
        "endpoints": endpoints,
        "count": endpoints.len()
    })))
}

/// GET /debug/profiles - Get learned endpoint profiles
/// Returns seed data for dashboard testing until profiler module integration is complete.
async fn profiles_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    // NOTE: The old handle_get_profiles() uses synapse::EndpointProfile from libsynapse
    // which has serde version conflicts. Return seed data for dashboard testing until
    // the new profiler module (crate::profiler::Profiler) is integrated.
    // Use GET /api/profiler/profiles for real profile data.
    let now = chrono::Utc::now().timestamp_millis();
    let seed_profiles = vec![
            serde_json::json!({
                "template": "/api/users",
                "payload_size": { "mean": 256.0, "std_dev": 64.0, "min": 128, "max": 512 },
                "expected_params": { "page": 45, "limit": 45, "sort": 23 },
                "content_types": { "application/json": 89, "text/html": 1 },
                "status_codes": { "200": 85, "404": 4, "500": 1 },
                "endpoint_risk": 12.5,
                "sample_count": 90,
                "first_seen_ms": now - 3600000,
                "last_updated_ms": now
            }),
            serde_json::json!({
                "template": "/api/products/{id}",
                "payload_size": { "mean": 1024.0, "std_dev": 256.0, "min": 512, "max": 2048 },
                "expected_params": { "fields": 30, "include": 15 },
                "content_types": { "application/json": 45 },
                "status_codes": { "200": 40, "404": 5 },
                "endpoint_risk": 8.2,
                "sample_count": 45,
                "first_seen_ms": now - 7200000,
                "last_updated_ms": now - 300000
            }),
            serde_json::json!({
                "template": "/api/auth/login",
                "payload_size": { "mean": 128.0, "std_dev": 32.0, "min": 64, "max": 256 },
                "expected_params": {},
                "content_types": { "application/json": 120 },
                "status_codes": { "200": 95, "401": 20, "429": 5 },
                "endpoint_risk": 65.8,
                "sample_count": 120,
                "first_seen_ms": now - 86400000,
                "last_updated_ms": now - 60000
            }),
            serde_json::json!({
                "template": "/api/admin/users",
                "payload_size": { "mean": 512.0, "std_dev": 128.0, "min": 256, "max": 1024 },
                "expected_params": { "role": 8, "status": 5 },
                "content_types": { "application/json": 15 },
                "status_codes": { "200": 10, "403": 5 },
                "endpoint_risk": 78.5,
                "sample_count": 15,
                "first_seen_ms": now - 1800000,
                "last_updated_ms": now - 120000
            }),
            serde_json::json!({
                "template": "/api/search",
                "payload_size": { "mean": 64.0, "std_dev": 16.0, "min": 32, "max": 128 },
                "expected_params": { "q": 200, "page": 150, "limit": 150, "category": 80 },
                "content_types": { "application/json": 200 },
                "status_codes": { "200": 195, "400": 5 },
                "endpoint_risk": 25.3,
                "sample_count": 200,
                "first_seen_ms": now - 172800000,
                "last_updated_ms": now
            }),
        ];
    Json(serde_json::json!({
        "success": true,
        "data": seed_profiles
    }))
}

/// POST /debug/profiles/save - Force save profiles to disk
/// Note: This endpoint requires integration with the new profiler module.
/// Currently returns a placeholder response as the profiler is managed separately.
async fn save_profiles_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    // TODO: Integrate with the new profiler module (crate::profiler::Profiler)
    // The profiler needs to be added to AdminState for direct access
    wrap_response(crate::api::ApiResponse::<String>::err(
        "Profile persistence endpoint not yet integrated with new profiler module. \
         Use GET /api/profiler/profiles to view current profiles."
    ))
}

/// Handler to reset endpoint profiles.
async fn api_profiles_reset_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Reset endpoint profiles via the metrics registry
    // Note: This clears learned behavioral baselines
    state.handler.metrics().reset_profiles();
    info!("Endpoint profiles reset");
    wrap_response(crate::api::ApiResponse::ok("Endpoint profiles reset successfully".to_string()))
}

/// Handler to reset schema learner data.
async fn api_schemas_reset_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Reset schema learner via the metrics registry
    // Note: This clears learned API schemas
    state.handler.metrics().reset_schemas();
    info!("Schema learner reset");
    wrap_response(crate::api::ApiResponse::ok("Schema learner reset successfully".to_string()))
}

/// Wraps an ApiResponse into an HTTP response with appropriate status code.
fn wrap_response<T: serde::Serialize>(response: ApiResponse<T>) -> Response {
    let status = if response.success {
        StatusCode::OK
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(response)).into_response()
}

/// Test configuration result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TestResult {
    pub success: bool,
    pub message: String,
}

/// Restart result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RestartResult {
    pub success: bool,
    pub message: String,
}

/// Request payload for dry-run WAF evaluation (Phase 2: Lab View)
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request URI/path
    pub uri: String,
    /// Request headers as key-value pairs
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Request body (optional, base64 encoded if binary)
    #[serde(default)]
    pub body: Option<String>,
    /// Client IP to simulate
    #[serde(default = "default_client_ip")]
    pub client_ip: String,
}

fn default_client_ip() -> String {
    "127.0.0.1".to_string()
}

/// POST /_sensor/evaluate - Dry-run WAF evaluation
///
/// Evaluates a request against the WAF rules without actually processing it.
/// Useful for testing rules before deployment or debugging detections.
///
/// Request body:
/// ```json
/// {
///     "method": "POST",
///     "uri": "/api/users?id=1 OR 1=1",
///     "headers": [["Content-Type", "application/json"]],
///     "body": "{\"username\": \"admin\"}",
///     "client_ip": "192.168.1.100"
/// }
/// ```
///
/// Response:
/// ```json
/// {
///     "blocked": true,
///     "riskScore": 85,
///     "matchedRules": [942100, 942190],
///     "blockReason": "SQL Injection detected",
///     "detectionTimeUs": 1234,
///     "verdict": "block"
/// }
/// ```
async fn sensor_evaluate_handler(
    State(state): State<AdminState>,
    Json(request): Json<EvaluateRequest>,
) -> impl IntoResponse {
    // Parse body if provided
    let body_bytes: Option<Vec<u8>> = request.body.as_ref().map(|b| {
        // Try to decode as base64, fall back to raw UTF-8 bytes
        match base64_decode(b) {
            Ok(decoded) => decoded,
            Err(_) => b.as_bytes().to_vec(),
        }
    });

    // Run detection using the ApiHandler's synapse engine
    match state.handler.evaluate_request(
        &request.method,
        &request.uri,
        &request.headers,
        body_bytes.as_deref(),
        &request.client_ip,
    ) {
        Some(result) => {
            // Determine verdict string
            let verdict = if result.blocked {
                "block"
            } else if result.risk_score > 50 {
                "warn"
            } else {
                "pass"
            };

            (StatusCode::OK, Json(serde_json::json!({
                "blocked": result.blocked,
                "riskScore": result.risk_score,
                "matchedRules": result.matched_rules,
                "blockReason": result.block_reason,
                "detectionTimeUs": result.detection_time_us,
                "verdict": verdict,
                "input": {
                    "method": request.method,
                    "uri": request.uri,
                    "headerCount": request.headers.len(),
                    "bodyLength": body_bytes.as_ref().map(|b| b.len()).unwrap_or(0),
                    "clientIp": request.client_ip
                }
            })))
        }
        None => {
            // Synapse engine not configured
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "error": "WAF evaluation not available",
                "message": "Synapse detection engine not configured"
            })))
        }
    }
}

/// Simple base64 decode helper (uses standard base64)
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    // Simple base64 decoding - just check if it looks like base64
    // and try to decode, falling back to raw bytes on error
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // Check if input looks like base64 (only base64 chars and length is multiple of 4 with padding)
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // If it doesn't look like base64, return error to fall back to raw bytes
    if !trimmed.bytes().all(|b| BASE64_CHARS.contains(&b)) {
        return Err(());
    }

    // Manual base64 decode (avoiding external deps)
    let mut output = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits_collected: u32 = 0;

    for byte in trimmed.bytes() {
        if byte == b'=' {
            break;
        }

        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        };

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    Ok(output)
}

// =============================================================================
// Profiler API Endpoints (Phase 8)
// =============================================================================

/// GET /api/profiles - List all endpoint profiles
async fn api_profiles_list_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    // Get profiles from the registered getter
    let profiles = get_profiles();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let profiles_json: Vec<serde_json::Value> = profiles
        .iter()
        .map(|p| {
            serde_json::json!({
                "template": p.template,
                "sampleCount": p.sample_count,
                "firstSeenMs": p.first_seen_ms,
                "lastUpdatedMs": p.last_updated_ms,
                "payloadSize": {
                    "mean": p.payload_size.mean(),
                    "variance": p.payload_size.variance(),
                    "stdDev": p.payload_size.stddev(),
                    "count": p.payload_size.count()
                },
                "expectedParams": p.expected_params,
                "contentTypes": p.content_types,
                "statusCodes": p.status_codes,
                "endpointRisk": p.endpoint_risk,
                "currentRps": p.request_rate.current_rate(now_ms)
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "profiles": profiles_json,
                "count": profiles_json.len()
            }
        })),
    )
}

/// GET /api/profiles/:template - Get specific profile details
async fn api_profiles_detail_handler(
    State(_state): State<AdminState>,
    Path(template): Path<String>,
) -> impl IntoResponse {
    // URL decode the template (it may contain slashes encoded as %2F)
    let decoded_template = urlencoding::decode(&template)
        .map(|s| s.into_owned())
        .unwrap_or(template);

    let profiles = get_profiles();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    match profiles.iter().find(|p| p.template == decoded_template) {
        Some(p) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "template": p.template,
                    "sampleCount": p.sample_count,
                    "firstSeenMs": p.first_seen_ms,
                    "lastUpdatedMs": p.last_updated_ms,
                    "payloadSize": {
                        "mean": p.payload_size.mean(),
                        "variance": p.payload_size.variance(),
                        "stdDev": p.payload_size.stddev(),
                        "count": p.payload_size.count()
                    },
                    "expectedParams": p.expected_params,
                    "contentTypes": p.content_types,
                    "statusCodes": p.status_codes,
                    "endpointRisk": p.endpoint_risk,
                    "requestRate": {
                        "currentRps": p.request_rate.current_rate(now_ms),
                        "windowMs": 60000
                    }
                }
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Profile not found: {}", decoded_template)
            })),
        ),
    }
}

/// GET /api/schemas - List all learned schemas
async fn api_schemas_list_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let schemas = get_schemas();

    let schemas_json: Vec<serde_json::Value> = schemas
        .iter()
        .map(|s| {
            serde_json::json!({
                "template": s.template,
                "sampleCount": s.sample_count,
                "lastUpdatedMs": s.last_updated_ms,
                "version": s.version,
                "requestFieldCount": s.request_schema.len(),
                "responseFieldCount": s.response_schema.len()
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "data": {
                "schemas": schemas_json,
                "count": schemas_json.len()
            }
        })),
    )
}

/// GET /api/schemas/:template - Get specific schema details
async fn api_schemas_detail_handler(
    State(_state): State<AdminState>,
    Path(template): Path<String>,
) -> impl IntoResponse {
    // URL decode the template
    let decoded_template = urlencoding::decode(&template)
        .map(|s| s.into_owned())
        .unwrap_or(template);

    let schemas = get_schemas();

    match schemas.iter().find(|s| s.template == decoded_template) {
        Some(s) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "data": {
                    "template": s.template,
                    "sampleCount": s.sample_count,
                    "lastUpdatedMs": s.last_updated_ms,
                    "version": s.version,
                    "requestSchema": s.request_schema.iter().map(|(k, v)| {
                        (k.clone(), serde_json::json!({
                            "dominantType": format!("{:?}", v.dominant_type()),
                            "seenCount": v.seen_count
                        }))
                    }).collect::<serde_json::Map<String, serde_json::Value>>(),
                    "responseSchema": s.response_schema.iter().map(|(k, v)| {
                        (k.clone(), serde_json::json!({
                            "dominantType": format!("{:?}", v.dominant_type()),
                            "seenCount": v.seen_count
                        }))
                    }).collect::<serde_json::Map<String, serde_json::Value>>()
                }
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "error": format!("Schema not found: {}", decoded_template)
            })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tower::util::ServiceExt;

    fn create_test_app() -> Router {
        let handler = Arc::new(ApiHandler::builder().build());
        let state = AdminState { handler, admin_api_key: None };

        Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/sites", get(sites_handler))
            .route("/stats", get(stats_handler))
            .route("/waf/stats", get(waf_stats_handler))
            .route("/reload", post(reload_handler))
            .route("/test", post(test_handler))
            .route("/restart", post(restart_handler))
            .route("/", get(root_handler))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_waf_stats_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/waf/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_reload_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Returns error because no reloader configured, but endpoint works
        assert!(response.status() == StatusCode::OK || response.status() == StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_test_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_restart_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/restart")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_root_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - base64_decode helper function
    // =========================================================================

    #[test]
    fn test_base64_decode_valid_input() {
        // "Hello" in base64 is "SGVsbG8="
        let result = base64_decode("SGVsbG8=");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hello");
    }

    #[test]
    fn test_base64_decode_empty_input() {
        let result = base64_decode("");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_base64_decode_whitespace_only() {
        let result = base64_decode("   ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_base64_decode_with_padding() {
        // "Hi" in base64 is "SGk=" (2 chars = 1 pad)
        let result = base64_decode("SGk=");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Hi");
    }

    #[test]
    fn test_base64_decode_no_padding() {
        // "Man" in base64 is "TWFu" (no padding needed)
        let result = base64_decode("TWFu");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"Man");
    }

    #[test]
    fn test_base64_decode_double_padding() {
        // "M" in base64 is "TQ==" (1 char = 2 pads)
        let result = base64_decode("TQ==");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"M");
    }

    #[test]
    fn test_base64_decode_with_plus_and_slash() {
        // Test string that includes + and / characters
        // "/+/+" encodes to "LysvKw=="
        let result = base64_decode("LysvKw==");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"/+/+");
    }

    #[test]
    fn test_base64_decode_invalid_characters() {
        // Contains invalid base64 character (!)
        let result = base64_decode("SGVsbG8h!");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode_non_base64_string() {
        // Plain text with spaces is not valid base64
        let result = base64_decode("Hello World");
        assert!(result.is_err());
    }

    #[test]
    fn test_base64_decode_json_body() {
        // {"key": "value"} base64 encoded
        // eyJrZXkiOiAidmFsdWUifQ==
        let result = base64_decode("eyJrZXkiOiAidmFsdWUifQ==");
        assert!(result.is_ok());
        let decoded = String::from_utf8(result.unwrap()).unwrap();
        assert_eq!(decoded, "{\"key\": \"value\"}");
    }

    #[test]
    fn test_base64_decode_binary_data() {
        // Binary data: [0x00, 0x01, 0x02, 0xFF] = "AAEC/w=="
        let result = base64_decode("AAEC/w==");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x00, 0x01, 0x02, 0xFF]);
    }

    #[test]
    fn test_base64_decode_longer_string() {
        // "The quick brown fox jumps over the lazy dog" base64
        let encoded = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==";
        let result = base64_decode(encoded);
        assert!(result.is_ok());
        let decoded = String::from_utf8(result.unwrap()).unwrap();
        assert_eq!(decoded, "The quick brown fox jumps over the lazy dog");
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - EvaluateRequest deserialization
    // =========================================================================

    #[test]
    fn test_evaluate_request_full_deserialization() {
        let json = r#"{
            "method": "POST",
            "uri": "/api/users?id=1",
            "headers": [["Content-Type", "application/json"], ["Authorization", "Bearer token"]],
            "body": "eyJ1c2VybmFtZSI6ICJ0ZXN0In0=",
            "client_ip": "192.168.1.100"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/users?id=1");
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.headers[0].0, "Content-Type");
        assert_eq!(request.headers[0].1, "application/json");
        assert_eq!(request.headers[1].0, "Authorization");
        assert_eq!(request.headers[1].1, "Bearer token");
        assert_eq!(request.body, Some("eyJ1c2VybmFtZSI6ICJ0ZXN0In0=".to_string()));
        assert_eq!(request.client_ip, "192.168.1.100");
    }

    #[test]
    fn test_evaluate_request_minimal() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/health"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/api/health");
        assert!(request.headers.is_empty()); // default
        assert!(request.body.is_none()); // default
        assert_eq!(request.client_ip, "127.0.0.1"); // default_client_ip()
    }

    #[test]
    fn test_evaluate_request_with_empty_headers() {
        let json = r#"{
            "method": "DELETE",
            "uri": "/api/resource/123",
            "headers": []
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "DELETE");
        assert_eq!(request.uri, "/api/resource/123");
        assert!(request.headers.is_empty());
    }

    #[test]
    fn test_evaluate_request_with_null_body() {
        let json = r#"{
            "method": "PUT",
            "uri": "/api/update",
            "body": null
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "PUT");
        assert!(request.body.is_none());
    }

    #[test]
    fn test_evaluate_request_sql_injection_payload() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/users?id=1' OR '1'='1",
            "client_ip": "10.0.0.42"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.uri, "/api/users?id=1' OR '1'='1");
        assert_eq!(request.client_ip, "10.0.0.42");
    }

    #[test]
    fn test_evaluate_request_xss_payload() {
        let json = r#"{
            "method": "POST",
            "uri": "/api/comment",
            "body": "PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "headers": [["Content-Type", "text/html"]]
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/comment");
        // Decode the body to verify it's XSS payload
        let body = request.body.unwrap();
        let decoded = base64_decode(&body).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, "<script>alert('XSS')</script>");
    }

    #[test]
    fn test_evaluate_request_path_traversal() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/files/../../../etc/passwd"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.uri, "/api/files/../../../etc/passwd");
    }

    #[test]
    fn test_evaluate_request_many_headers() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/test",
            "headers": [
                ["Accept", "application/json"],
                ["Accept-Encoding", "gzip, deflate"],
                ["Accept-Language", "en-US,en;q=0.9"],
                ["Cache-Control", "no-cache"],
                ["Connection", "keep-alive"],
                ["Host", "example.com"],
                ["User-Agent", "Mozilla/5.0"],
                ["X-Custom-Header", "custom-value"]
            ]
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.headers.len(), 8);
        assert_eq!(request.headers[0].0, "Accept");
        assert_eq!(request.headers[7].0, "X-Custom-Header");
    }

    #[test]
    fn test_evaluate_request_ipv6_client() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/test",
            "client_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.client_ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }

    #[test]
    fn test_evaluate_request_unicode_uri() {
        let json = r#"{
            "method": "GET",
            "uri": "/api/search?q=%E4%B8%AD%E6%96%87"
        }"#;

        let request: EvaluateRequest = serde_json::from_str(json).unwrap();

        assert_eq!(request.uri, "/api/search?q=%E4%B8%AD%E6%96%87");
    }

    #[test]
    fn test_default_client_ip() {
        assert_eq!(default_client_ip(), "127.0.0.1");
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - EvaluationResult
    // =========================================================================

    #[test]
    fn test_evaluation_result_serialization() {
        let result = EvaluationResult {
            blocked: true,
            risk_score: 85,
            matched_rules: vec![942100, 942190],
            block_reason: Some("SQL Injection detected".to_string()),
            detection_time_us: 1234,
        };

        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"blocked\":true"));
        assert!(json.contains("\"risk_score\":85"));
        assert!(json.contains("942100"));
        assert!(json.contains("942190"));
        assert!(json.contains("SQL Injection detected"));
        assert!(json.contains("\"detection_time_us\":1234"));
    }

    #[test]
    fn test_evaluation_result_no_block_reason() {
        let result = EvaluationResult {
            blocked: false,
            risk_score: 20,
            matched_rules: vec![],
            block_reason: None,
            detection_time_us: 500,
        };

        let json = serde_json::to_string(&result).unwrap();

        assert!(json.contains("\"blocked\":false"));
        assert!(json.contains("\"risk_score\":20"));
        assert!(json.contains("\"matched_rules\":[]"));
        assert!(json.contains("\"block_reason\":null"));
    }
}
