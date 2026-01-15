//! Management HTTP API for runtime configuration and monitoring.
//!
//! Provides REST endpoints for:
//! - Health status (`GET /health`)
//! - Prometheus metrics (`GET /metrics`)
//! - Configuration reload (`POST /reload`)
//! - Site management (`GET/POST/PUT/DELETE /sites`)
//! - WAF statistics (`GET /waf/stats`)
//! - Site-specific configuration (`PUT /sites/:hostname/waf`, etc.)

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use parking_lot::RwLock;

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
}

impl ApiHandler {
    /// Creates a new API handler builder.
    pub fn builder() -> ApiHandlerBuilder {
        ApiHandlerBuilder::default()
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
    pub fn handle_get_profiles(&self) -> ApiResponse<Vec<synapse::EndpointProfile>> {
        // Library context: profiles_getter not available, return empty
        // The binary (main.rs) should provide profiles via a route handler that calls DetectionEngine directly
        ApiResponse::ok(Vec::new())
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

    /// Validates the API authentication token.
    pub fn validate_auth(&self, token: Option<&str>) -> bool {
        match (&self.auth_token, token) {
            (None, _) => true, // No auth required
            (Some(expected), Some(provided)) => expected == provided,
            (Some(_), None) => false,
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

    /// Returns the campaign manager (if configured).
    pub fn campaign_manager(&self) -> Option<&Arc<CampaignManager>> {
        self.campaign_manager.as_ref()
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

        // Should allow any auth when no token configured
        assert!(handler.validate_auth(None));
        assert!(handler.validate_auth(Some("anything")));
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

        assert!(!response.success);
        assert!(response.error.is_some());
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
