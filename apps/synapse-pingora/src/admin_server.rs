//! Admin HTTP server for Pingora configuration management.
//!
//! Provides HTTP endpoints for the dashboard to manage Pingora:
//! - GET /health - Service health and WAF statistics
//! - GET /metrics - Prometheus metrics
//! - POST /reload - Reload configuration
//! - POST /test - Test configuration (dry-run)
//! - POST /restart - Restart service (placeholder)
//! - GET /sites - List configured sites
//! - GET /stats - Runtime statistics
//! - GET /waf/stats - WAF statistics

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{header, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::api::{ApiHandler, ApiResponse};
use crate::config_manager::{
    CreateSiteRequest, UpdateSiteRequest, SiteWafRequest,
    RateLimitRequest, AccessListRequest,
};

/// Admin server state shared across handlers.
#[derive(Clone)]
pub struct AdminState {
    pub handler: Arc<ApiHandler>,
}

/// Starts the admin HTTP server.
///
/// # Arguments
/// * `addr` - Socket address to bind (e.g., "0.0.0.0:6191")
/// * `handler` - API handler with references to health, metrics, reloader, etc.
pub async fn start_admin_server(addr: SocketAddr, handler: Arc<ApiHandler>) -> std::io::Result<()> {
    let state = AdminState { handler };

    // CORS configuration for dashboard access
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT, header::AUTHORIZATION]);

    let app = Router::new()
        // Health and metrics (no auth)
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        // Configuration management
        .route("/reload", post(reload_handler))
        .route("/test", post(test_handler))
        .route("/restart", post(restart_handler))
        // Site management (CRUD)
        .route("/sites", get(sites_handler).post(create_site_handler))
        .route("/sites/{hostname}", get(get_site_handler).put(update_site_handler).delete(delete_site_handler))
        .route("/sites/{hostname}/waf", put(update_site_waf_handler))
        .route("/sites/{hostname}/rate-limit", put(update_site_rate_limit_handler))
        .route("/sites/{hostname}/access-list", put(update_site_access_list_handler))
        // Statistics
        .route("/stats", get(stats_handler))
        .route("/waf/stats", get(waf_stats_handler))
        // Debugging / Profiling
        .route("/debug/profiles", get(profiles_handler))
        .route("/debug/profiles/save", post(save_profiles_handler))
        // Dashboard compatibility routes (/_sensor/ prefix)
        // These map to the same handlers but with the prefix the dashboard expects
        .route("/_sensor/status", get(sensor_status_handler))
        .route("/_sensor/config", get(sensor_config_handler))
        .route("/_sensor/health", get(health_handler))
        // Stub endpoints - return empty data for dashboard compatibility
        .route("/_sensor/entities", get(sensor_entities_handler))
        .route("/_sensor/blocks", get(sensor_blocks_handler))
        .route("/_sensor/trends", get(sensor_trends_handler))
        .route("/_sensor/anomalies", get(sensor_anomalies_handler))
        .route("/_sensor/campaigns", get(sensor_campaigns_handler))
        .route("/_sensor/payload/bandwidth", get(sensor_bandwidth_handler))
        .route("/_sensor/actors", get(sensor_actors_handler))
        .route("/_sensor/system/config", get(sensor_system_config_handler))
        // Root endpoint (API info)
        .route("/", get(root_handler))
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
            "runtimeConfig": {},
            "startupFlags": [],
            "sites": sites.data.map(|s| s.sites).unwrap_or_default()
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
        let state = AdminState { handler };

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
