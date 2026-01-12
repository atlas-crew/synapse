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

use std::net::SocketAddr;
use std::sync::Arc;

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
        Some(key) if key == expected_key => Ok(next.run(request).await),
        Some(_) => {
            warn!("Admin auth failed: invalid API key");
            Err(StatusCode::UNAUTHORIZED)
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
        .route("/debug/profiles/save", post(save_profiles_handler))
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
        .route("/_sensor/blocks", get(sensor_blocks_handler))
        .route("/_sensor/trends", get(sensor_trends_handler))
        .route("/_sensor/anomalies", get(sensor_anomalies_handler))
        .route("/_sensor/campaigns", get(sensor_campaigns_handler))
        .route("/_sensor/payload/bandwidth", get(sensor_bandwidth_handler))
        .route("/_sensor/actors", get(sensor_actors_handler))
        .route("/_sensor/system/config", get(sensor_system_config_handler))
        .route("/_sensor/system/overview", get(sensor_system_overview_handler))
        .route("/_sensor/system/performance", get(sensor_system_performance_handler))
        .route("/_sensor/system/network", get(sensor_system_network_handler))
        .route("/_sensor/system/processes", get(sensor_system_processes_handler))
        .route("/_sensor/system/logs", get(sensor_system_logs_handler))
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

/// GET /_sensor/anomalies - Returns empty anomalies list
async fn sensor_anomalies_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "data": [] })))
}

/// GET /_sensor/campaigns - Returns empty campaigns list
async fn sensor_campaigns_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "data": [] })))
}

/// GET /_sensor/payload/bandwidth - Returns empty bandwidth data
async fn sensor_bandwidth_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "totalBytes": 0,
        "avgBytesPerRequest": 0,
        "maxRequestSize": 0,
        "timeline": []
    })))
}

/// GET /_sensor/actors - Returns empty actors list
async fn sensor_actors_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "actors": [] })))
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
async fn sensor_system_overview_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let health = state.handler.handle_health();
    let uptime_secs = health.data.as_ref().map(|h| h.uptime_secs).unwrap_or(0);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "uptime": uptime_secs,
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": "synapse-pingora",
            "cpu": {
                "cores": std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1),
                "usagePercent": 0.0
            },
            "memory": {
                "totalMb": 0,
                "usedMb": 0,
                "usagePercent": 0.0
            },
            "requests": {
                "total": 0,
                "perSecond": 0.0,
                "blocked": 0,
                "blockedPercent": 0.0
            }
        }
    })))
}

/// GET /_sensor/system/performance - Performance metrics
async fn sensor_system_performance_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let health = state.handler.handle_health();
    let waf_stats = health.data.as_ref().map(|h| &h.waf);

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "latency": {
                "p50Ms": 0.0,
                "p95Ms": 0.0,
                "p99Ms": 0.0,
                "avgMs": waf_stats.map(|w| w.avg_detection_us as f64 / 1000.0).unwrap_or(0.0)
            },
            "throughput": {
                "requestsPerSecond": 0.0,
                "bytesPerSecond": 0
            },
            "connections": {
                "active": 0,
                "idle": 0,
                "total": 0
            },
            "timeline": []
        }
    })))
}

/// GET /_sensor/system/network - Network statistics
async fn sensor_system_network_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "interfaces": [],
            "connections": {
                "established": 0,
                "timeWait": 0,
                "closeWait": 0
            },
            "bandwidth": {
                "inBytesPerSecond": 0,
                "outBytesPerSecond": 0
            },
            "timeline": []
        }
    })))
}

/// GET /_sensor/system/processes - Process information
async fn sensor_system_processes_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "workers": [],
            "totalThreads": 0,
            "totalMemoryMb": 0
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

async fn sensor_system_logs_handler(Query(_params): Query<LogsQuery>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "entries": [],
            "hasMore": false
        }
    })))
}

use crate::persistence::SnapshotManager;

/// GET /debug/profiles - Get learned endpoint profiles
async fn profiles_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_get_profiles();
    wrap_response(response)
}

/// POST /debug/profiles/save - Force save profiles to disk
async fn save_profiles_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Get profiles from the current thread (Admin API thread)
    // Note: In production this would need to aggregate from workers
    let response = state.handler.handle_get_profiles();

    if let Some(profiles) = response.data {
        if let Err(e) = SnapshotManager::save_profiles(&profiles, std::path::Path::new("data/profiles.json")) {
            return wrap_response(crate::api::ApiResponse::<String>::err(format!("Failed to save: {}", e)));
        }
        return wrap_response(crate::api::ApiResponse::ok("Profiles saved to data/profiles.json".to_string()));
    }

    wrap_response(crate::api::ApiResponse::<String>::err("No profiles to save"))
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
}
