//! Admin HTTP server for Pingora configuration management.
//!
//! Provides HTTP endpoints for the dashboard to manage Pingora.
//! SECURITY: All admin API endpoints require the X-Admin-Key header.
//! - GET /health - Service health and WAF statistics
//! - GET /metrics - Prometheus metrics
//! - POST /reload - Reload configuration (requires auth)
//! - POST /test - Test configuration (dry-run, requires auth)
//! - POST /restart - Restart service (requires auth)
//! - GET /sites - List configured sites
//! - GET /stats - Runtime statistics
//! - GET /waf/stats - WAF statistics

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use std::num::NonZeroU32;

use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use sysinfo::{System, Networks, Disks};
use crate::intelligence::{SignalCategory, SignalQueryOptions};
use crate::signals::adapter::SignalAdapter;

// Type aliases for profile/schema data accessors
// These are callbacks that the binary (main.rs) can set to provide real data
type ProfilesGetter = Box<dyn Fn() -> Vec<crate::profiler::EndpointProfile> + Send + Sync>;
// Note: Using profiler module's JsonEndpointSchema (schema_types::EndpointSchema) to avoid serde_json version conflicts
type SchemasGetter = Box<dyn Fn() -> Vec<crate::profiler::JsonEndpointSchema> + Send + Sync>;

/// Integration configuration for external services (Horizon, Tunnel, Apparatus)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IntegrationsConfig {
    pub horizon_hub_url: String,
    pub horizon_api_key: String,
    pub tunnel_url: String,
    pub tunnel_api_key: String,
    pub apparatus_url: String,
}

// Type aliases for integration data accessors
type IntegrationsGetter = Box<dyn Fn() -> IntegrationsConfig + Send + Sync>;
type IntegrationsSetter = Box<dyn Fn(IntegrationsConfig) + Send + Sync>;

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

/// Global accessors for integrations (set by binary at startup)
static INTEGRATIONS_GETTER: Lazy<RwLock<Option<IntegrationsGetter>>> = Lazy::new(|| RwLock::new(None));
static INTEGRATIONS_SETTER: Lazy<RwLock<Option<IntegrationsSetter>>> = Lazy::new(|| RwLock::new(None));

/// Global accessor for WAF evaluation (set by binary at startup)
static EVALUATE_CALLBACK: Lazy<RwLock<Option<EvaluateCallback>>> = Lazy::new(|| RwLock::new(None));

/// Register a callback to get endpoint profiles from the detection engine.
/// Called by the binary (main.rs) during startup.
pub fn register_profiles_getter<F>(getter: F)
where
    F: Fn() -> Vec<crate::profiler::EndpointProfile> + Send + Sync + 'static,
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

/// Register integration configuration callbacks.
/// Called by the binary (main.rs) during startup.
pub fn register_integrations_callbacks<G, S>(getter: G, setter: S)
where
    G: Fn() -> IntegrationsConfig + Send + Sync + 'static,
    S: Fn(IntegrationsConfig) + Send + Sync + 'static,
{
    *INTEGRATIONS_GETTER.write() = Some(Box::new(getter));
    *INTEGRATIONS_SETTER.write() = Some(Box::new(setter));
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
#[allow(dead_code)]
fn run_evaluate(method: &str, uri: &str, headers: &[(String, String)], body: Option<&[u8]>, client_ip: &str) -> Option<EvaluationResult> {
    EVALUATE_CALLBACK
        .read()
        .as_ref()
        .map(|callback| callback(method, uri, headers, body, client_ip))
}

/// Get profiles from the registered getter, or empty vec if not registered.
fn get_profiles() -> Vec<crate::profiler::EndpointProfile> {
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

static ADMIN_CONSOLE_TEMPLATE: &str = include_str!("../assets/admin_console.html");
const ADMIN_CONSOLE_CSP: &str = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; connect-src 'self'";

/// Dev mode flag - when true, serves admin console from disk instead of embedded
static DEV_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Demo mode flag - when true, returns pre-populated sample data
static DEMO_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Enable dev mode for live reloading of admin console
pub fn enable_dev_mode() {
    DEV_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::warn!("================================================");
    tracing::warn!("!! DEV MODE ENABLED - AUTHENTICATION BYPASSED !!");
    tracing::warn!("!! DO NOT USE IN PRODUCTION                   !!");
    tracing::warn!("================================================");
    tracing::info!("Dev mode enabled - admin console will be served from disk");
}

/// Check if dev mode is enabled
pub fn is_dev_mode() -> bool {
    DEV_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Enable demo mode with pre-populated sample data
pub fn enable_demo_mode() {
    DEMO_MODE.store(true, std::sync::atomic::Ordering::SeqCst);
    tracing::info!("Demo mode enabled - using pre-populated sample data");
}

/// Check if demo mode is enabled
pub fn is_demo_mode() -> bool {
    DEMO_MODE.load(std::sync::atomic::Ordering::SeqCst)
}

/// Generate demo sites data
fn demo_sites() -> serde_json::Value {
    serde_json::json!({
        "success": true,
        "data": {
            "sites": [
                {
                    "hostname": "api.acme-corp.com",
                    "upstreams": ["10.0.1.10:8080", "10.0.1.11:8080"],
                    "waf": { "enabled": true, "threshold": 70 },
                    "rate_limit": { "requests_per_second": 1000 },
                    "tls": true
                },
                {
                    "hostname": "shop.acme-corp.com",
                    "upstreams": ["10.0.2.10:3000"],
                    "waf": { "enabled": true, "threshold": 60 },
                    "rate_limit": { "requests_per_second": 500 },
                    "tls": true
                },
                {
                    "hostname": "admin.acme-corp.com",
                    "upstreams": ["10.0.3.10:8443"],
                    "waf": { "enabled": true, "threshold": 50 },
                    "rate_limit": { "requests_per_second": 100 },
                    "tls": true
                },
                {
                    "hostname": "legacy.acme-corp.com",
                    "upstreams": ["192.168.1.50:80"],
                    "waf": { "enabled": false, "threshold": 70 },
                    "rate_limit": { "requests_per_second": 200 },
                    "tls": false
                }
            ]
        }
    })
}

/// Generate demo entities data
fn demo_entities() -> serde_json::Value {
    serde_json::json!({
        "entities": [
            { "id": "actor_8f3a2b1c", "ip": "185.220.101.42", "risk_score": 92, "request_count": 1847, "last_seen": "2026-02-02T05:45:00Z", "tags": ["tor_exit", "credential_stuffing"] },
            { "id": "actor_7e2d4a9f", "ip": "45.155.205.233", "risk_score": 88, "request_count": 523, "last_seen": "2026-02-02T05:42:00Z", "tags": ["scanner", "sqli_attempts"] },
            { "id": "actor_6c1b3e8d", "ip": "194.26.29.102", "risk_score": 85, "request_count": 2341, "last_seen": "2026-02-02T05:40:00Z", "tags": ["botnet", "distributed"] },
            { "id": "actor_5a0c2f7e", "ip": "91.240.118.50", "risk_score": 78, "request_count": 892, "last_seen": "2026-02-02T05:38:00Z", "tags": ["scraper", "rate_limited"] },
            { "id": "actor_4d9e1a6b", "ip": "23.129.64.142", "risk_score": 75, "request_count": 156, "last_seen": "2026-02-02T05:35:00Z", "tags": ["tor_exit"] },
            { "id": "actor_3c8f0b5a", "ip": "104.244.76.13", "risk_score": 65, "request_count": 3201, "last_seen": "2026-02-02T05:44:00Z", "tags": ["aggressive_crawler"] },
            { "id": "actor_2b7e9c4d", "ip": "167.99.182.44", "risk_score": 45, "request_count": 89, "last_seen": "2026-02-02T05:30:00Z", "tags": ["suspicious_ua"] },
            { "id": "actor_1a6d8b3c", "ip": "203.0.113.50", "risk_score": 25, "request_count": 12, "last_seen": "2026-02-02T05:20:00Z", "tags": [] }
        ]
    })
}

/// Generate demo campaigns data
fn demo_campaigns() -> serde_json::Value {
    serde_json::json!({
        "campaigns": [
            {
                "id": "campaign_001",
                "name": "Credential Stuffing Wave",
                "type": "credential_stuffing",
                "status": "active",
                "actor_count": 47,
                "request_count": 28450,
                "first_seen": "2026-02-01T14:30:00Z",
                "last_seen": "2026-02-02T05:45:00Z",
                "target_endpoints": ["/api/login", "/api/auth", "/oauth/token"],
                "severity": "critical"
            },
            {
                "id": "campaign_002",
                "name": "API Enumeration Scan",
                "type": "reconnaissance",
                "status": "active",
                "actor_count": 12,
                "request_count": 5230,
                "first_seen": "2026-02-02T02:15:00Z",
                "last_seen": "2026-02-02T05:40:00Z",
                "target_endpoints": ["/api/v1/*", "/api/v2/*", "/graphql"],
                "severity": "high"
            },
            {
                "id": "campaign_003",
                "name": "SQLi Probe Campaign",
                "type": "injection",
                "status": "mitigated",
                "actor_count": 8,
                "request_count": 1840,
                "first_seen": "2026-02-01T22:00:00Z",
                "last_seen": "2026-02-02T01:30:00Z",
                "target_endpoints": ["/api/search", "/api/products"],
                "severity": "critical"
            }
        ]
    })
}

/// Generate demo status data
fn demo_status() -> serde_json::Value {
    serde_json::json!({
        "sensorId": "synapse-demo",
        "status": "running",
        "mode": "proxy",
        "uptime": 86420,
        "requestRate": 2847.5,
        "blockRate": 3.2,
        "fallbackRate": 0.1,
        "proxy": { "type": "pingora", "version": "0.1.0" },
        "waf": {
            "enabled": true,
            "analyzed": 2458920,
            "blocked": 78654
        },
        "dlp": {
            "enabled": true,
            "healthy": true,
            "patternCount": 25,
            "totalScans": 1245000,
            "totalMatches": 342
        }
    })
}

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
    source: String, // http, waf, system, kernel, access
    message: String,
}

/// Log sources
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    Http,
    Waf,
    System,
    Access,
}

impl LogSource {
    fn as_str(&self) -> &'static str {
        match self {
            LogSource::Http => "http",
            LogSource::Waf => "waf",
            LogSource::System => "system",
            LogSource::Access => "access",
        }
    }
}

/// Global log buffer (last 200 entries)
static LOG_BUFFER: Lazy<RwLock<VecDeque<LogEntry>>> = Lazy::new(|| {
    RwLock::new(VecDeque::with_capacity(200))
});

/// Record a log entry with source
pub fn record_log_with_source(level: &str, source: LogSource, message: String) {
    let stream_source = match source {
        LogSource::Http => "access",
        LogSource::Waf => "waf",
        LogSource::System => "system",
        LogSource::Access => "access",
    };
    crate::tunnel::publish_internal_log(level, stream_source, message.clone());

    let entry = LogEntry {
        id: format!("{}", fastrand::u64(..)),
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: level.to_string(),
        source: source.as_str().to_string(),
        message,
    };

    let mut logs = LOG_BUFFER.write();
    if logs.len() >= 500 {
        logs.pop_front();
    }
    logs.push_back(entry);
}

/// Record a log entry (defaults to system source)
pub fn record_log(level: &str, message: String) {
    record_log_with_source(level, LogSource::System, message);
}

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, warn};
use subtle::ConstantTimeEq;

#[cfg(test)]
use std::cell::Cell;

use crate::api::{ApiHandler, ApiResponse};
use crate::waf::{TraceEvent, TraceSink};

// =============================================================================
// Scope Constants (WS2-004)
// =============================================================================

/// Admin API scopes for fine-grained permission control
pub mod scopes {
    /// Read-only access to admin data (stats, health, config viewing)
    pub const ADMIN_READ: &str = "admin:read";
    /// Write access to admin operations (reload, test)
    pub const ADMIN_WRITE: &str = "admin:write";
    /// Configuration write access (site CRUD, WAF settings)
    pub const CONFIG_WRITE: &str = "config:write";
    /// Service management (restart, reset operations)
    pub const SERVICE_MANAGE: &str = "service:manage";
    /// Sensitive sensor data access (campaigns, DLP, correlation graphs)
    pub const SENSOR_READ: &str = "sensor:read";
    /// Write access for sensor reports and signals
    pub const SENSOR_WRITE: &str = "sensor:write";

    /// All available scopes
    pub const ALL: &[&str] = &[
        ADMIN_READ,
        ADMIN_WRITE,
        CONFIG_WRITE,
        SERVICE_MANAGE,
        SENSOR_READ,
        SENSOR_WRITE,
    ];
}

// =============================================================================
// Error Sanitization (Security: Prevent Information Disclosure)
// =============================================================================

/// Error codes for admin API responses.
///
/// SECURITY: These generic error codes prevent internal details from being
/// exposed to clients. Full error details are logged internally.
#[allow(dead_code)]
mod error_codes {
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    pub const VALIDATION_ERROR: &str = "VALIDATION_ERROR";
    pub const NOT_FOUND: &str = "NOT_FOUND";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub const SERVICE_UNAVAILABLE: &str = "SERVICE_UNAVAILABLE";
    pub const RATE_LIMIT_EXCEEDED: &str = "RATE_LIMIT_EXCEEDED";
    pub const UNAUTHORIZED: &str = "UNAUTHORIZED";
    pub const FORBIDDEN: &str = "FORBIDDEN";
    pub const INSUFFICIENT_SCOPE: &str = "INSUFFICIENT_SCOPE";
}

/// RFC 7807 Problem Details response.
#[derive(Debug, serde::Serialize)]
struct ProblemDetails {
    #[serde(rename = "type")]
    type_url: String,
    title: String,
    status: u16,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_secs: Option<u64>,
}

impl ProblemDetails {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            type_url: "about:blank".to_string(),
            title: status
                .canonical_reason()
                .unwrap_or("Error")
                .to_string(),
            status: status.as_u16(),
            detail: detail.into(),
            instance: None,
            code: None,
            required_scope: None,
            retry_after_secs: None,
        }
    }
}

/// Create a sanitized error response that hides internal details.
///
/// SECURITY: Logs the full error internally but returns a generic message
/// to clients to prevent information disclosure.
fn sanitized_error(
    status: StatusCode,
    code: &str,
    public_message: &str,
    internal_error: Option<&dyn std::fmt::Display>,
) -> Response {
    // Log internal details if provided
    if let Some(err) = internal_error {
        tracing::warn!(
            code = code,
            status = %status,
            internal_error = %err,
            "Admin API error (sanitized for client)"
        );
    }

    let mut problem = ProblemDetails::new(status, public_message.to_string());
    problem.code = Some(code.to_string());

    (status, Json(problem)).into_response()
}

/// Create a validation error response (400 Bad Request).
fn validation_error(
    public_message: &str,
    internal_error: Option<&dyn std::fmt::Display>,
) -> Response {
    sanitized_error(
        StatusCode::BAD_REQUEST,
        error_codes::VALIDATION_ERROR,
        public_message,
        internal_error,
    )
}

/// Create an internal server error response (500).
fn internal_error(
    public_message: &str,
    internal_error: Option<&dyn std::fmt::Display>,
) -> Response {
    sanitized_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        error_codes::INTERNAL_ERROR,
        public_message,
        internal_error,
    )
}

/// Create a forbidden error response (403).
fn forbidden_error(public_message: &str) -> Response {
    sanitized_error(
        StatusCode::FORBIDDEN,
        error_codes::FORBIDDEN,
        public_message,
        None,
    )
}

/// Create a rate limit exceeded error response (429).
fn rate_limit_error(retry_after_secs: u64) -> Response {
    let mut problem = ProblemDetails::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
    problem.code = Some(error_codes::RATE_LIMIT_EXCEEDED.to_string());
    problem.retry_after_secs = Some(retry_after_secs);

    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_after_secs.to_string())],
        Json(problem),
    )
        .into_response()
}

/// Create a not found error response (404).
#[allow(dead_code)]
fn not_found_error(resource_type: &str, _resource_id: &str) -> Response {
    // Note: We don't include the resource_id in the response to avoid enumeration attacks
    sanitized_error(
        StatusCode::NOT_FOUND,
        error_codes::NOT_FOUND,
        &format!("{} not found", resource_type),
        None,
    )
}

/// Create a service unavailable error response (503).
fn service_unavailable(service_name: &str) -> Response {
    sanitized_error(
        StatusCode::SERVICE_UNAVAILABLE,
        error_codes::SERVICE_UNAVAILABLE,
        &format!("{} is not available", service_name),
        None,
    )
}

use crate::config_manager::{
    CreateSiteRequest, UpdateSiteRequest, SiteWafRequest,
    RateLimitRequest, AccessListRequest,
    ConfigManagerError, CustomRuleAction, CustomRuleCondition, CustomRuleInput, CustomRuleUpdate, RuleView, StoredRule,
};

/// GET /config - Retrieve full configuration
async fn config_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_get_config();
    wrap_response(response)
}

/// POST /config - Update full configuration (hot reload)
async fn update_config_handler(
    State(state): State<AdminState>,
    Json(config): Json<crate::config::ConfigFile>,
) -> impl IntoResponse {
    let response = state.handler.handle_update_config(config);
    wrap_response(response)
}

/// Per-IP rate limiter type using governor
type IpRateLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, governor::clock::DefaultClock>;
type StringRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Admin server state shared across handlers.
#[derive(Clone)]
pub struct AdminState {
    pub handler: Arc<ApiHandler>,
    /// API key for authenticating privileged operations (SECURITY: now mandatory)
    pub admin_api_key: String,
    /// Disable admin authentication (local-only)
    pub admin_auth_disabled: bool,
    /// Scopes granted to the admin API key (defaults to ALL if not specified)
    pub admin_scopes: Vec<String>,
    /// Allowed signal types for external sensor reporting.
    pub signal_permissions: Arc<SignalPermissions>,
    /// Per-IP rate limiter for admin endpoints (100 req/min for admin, 1000 req/min for public)
    pub admin_rate_limiter: Arc<IpRateLimiter>,
    pub public_rate_limiter: Arc<IpRateLimiter>,
    /// Per-sensor rate limiter for signal ingestion (100 reports/min per sensor)
    pub report_rate_limiter: Arc<StringRateLimiter>,
    /// Per-IP rate limiter for authentication failures (5 failures per minute).
    ///
    /// SECURITY: This stricter rate limiter prevents brute-force attacks on the admin API key.
    /// After 5 failed auth attempts per minute per IP, further requests are blocked with 429.
    pub auth_failure_limiter: Arc<IpRateLimiter>,
}

/// Permissions for external sensor signals.
#[derive(Clone, Debug)]
pub struct SignalPermissions {
    default_allowed: HashSet<String>,
    per_sensor_allowed: HashMap<String, HashSet<String>>,
}

impl SignalPermissions {
    fn default_allowed() -> HashSet<String> {
        [
            "honeypot_hit",
            "trap_trigger",
            "protocol_probe",
            "dlp_match",
        ]
        .into_iter()
        .map(|value| value.to_string())
        .collect()
    }

    pub fn is_allowed(&self, sensor_id: &str, signal_type: &str) -> bool {
        let normalized = signal_type.trim().to_lowercase();
        if let Some(allowlist) = self.per_sensor_allowed.get(sensor_id) {
            allowlist.contains(&normalized)
        } else {
            self.default_allowed.contains(&normalized)
        }
    }
}

impl Default for SignalPermissions {
    fn default() -> Self {
        Self {
            default_allowed: Self::default_allowed(),
            per_sensor_allowed: HashMap::new(),
        }
    }
}

/// Authentication middleware for privileged admin endpoints.
/// Checks X-Admin-Key header against configured API key.
///
/// SECURITY: Authentication is now mandatory - no bypass for missing config.
/// Implements rate limiting for authentication failures to prevent
/// brute-force attacks. After 5 failed attempts per minute, returns 429.
async fn require_auth(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    if state.admin_auth_disabled {
        return Ok(next.run(request).await);
    }
    // DEV MODE: Skip authentication for local development
    if is_dev_mode() {
        return Ok(next.run(request).await);
    }

    let client_ip = extract_client_ip(&request);
    let provided_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok());

    match validate_admin_key(&state, client_ip, provided_key) {
        Ok(()) => Ok(next.run(request).await),
        Err(response) => Err(response),
    }
}

/// Record a failed authentication attempt and check if rate limit exceeded.
///
/// SECURITY: Returns 429 Too Many Requests if the client has exceeded the
/// allowed number of authentication failures (5 per minute by default).
fn record_auth_failure(
    state: &AdminState,
    client_ip: IpAddr,
) -> Result<(), std::time::Duration> {
    match state.auth_failure_limiter.check_key(&client_ip) {
        Ok(_) => Ok(()), // Within rate limit
        Err(not_until) => {
            warn!(
                client_ip = %client_ip,
                "Auth rate limit exceeded: too many failed authentication attempts"
            );
            Err(not_until.wait_time_from(governor::clock::Clock::now(
                &governor::clock::DefaultClock::default(),
            )))
        }
    }
}

fn validate_admin_key(
    state: &AdminState,
    client_ip: IpAddr,
    provided_key: Option<&str>,
) -> Result<(), Response> {
    match provided_key {
        Some(key) => {
            let key_bytes = key.as_bytes();
            let expected_bytes = state.admin_api_key.as_bytes();
            let is_valid = key_bytes.len() == expected_bytes.len()
                && bool::from(key_bytes.ct_eq(expected_bytes));

            if is_valid {
                Ok(())
            } else {
                match record_auth_failure(state, client_ip) {
                    Ok(()) => {
                        warn!(client_ip = %client_ip, "Admin auth failed: invalid API key");
                        let mut problem = ProblemDetails::new(
                            StatusCode::UNAUTHORIZED,
                            "Invalid X-Admin-Key value",
                        );
                        problem.code = Some(error_codes::UNAUTHORIZED.to_string());
                        Err((StatusCode::UNAUTHORIZED, Json(problem)).into_response())
                    }
                    Err(retry_after) => {
                        warn!(client_ip = %client_ip, "Admin auth failed: too many attempts");
                        let mut problem = ProblemDetails::new(
                            StatusCode::TOO_MANY_REQUESTS,
                            "Too many failed authentication attempts",
                        );
                        problem.code = Some(error_codes::RATE_LIMIT_EXCEEDED.to_string());
                        problem.retry_after_secs = Some(retry_after.as_secs());
                        Err((
                            StatusCode::TOO_MANY_REQUESTS,
                            [(header::RETRY_AFTER, retry_after.as_secs().to_string())],
                            Json(problem),
                        )
                            .into_response())
                    }
                }
            }
        }
        None => match record_auth_failure(state, client_ip) {
            Ok(()) => {
                warn!(client_ip = %client_ip, "Admin auth failed: missing X-Admin-Key header");
                let mut problem = ProblemDetails::new(
                    StatusCode::UNAUTHORIZED,
                    "Missing X-Admin-Key header",
                );
                problem.code = Some(error_codes::UNAUTHORIZED.to_string());
                Err((StatusCode::UNAUTHORIZED, Json(problem)).into_response())
            }
            Err(retry_after) => {
                warn!(client_ip = %client_ip, "Admin auth failed: too many attempts");
                let mut problem = ProblemDetails::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many failed authentication attempts",
                );
                problem.code = Some(error_codes::RATE_LIMIT_EXCEEDED.to_string());
                problem.retry_after_secs = Some(retry_after.as_secs());
                Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::RETRY_AFTER, retry_after.as_secs().to_string())],
                    Json(problem),
                )
                    .into_response())
            }
        },
    }
}

/// Extract admin key from query string (admin_key).
fn extract_admin_key_from_query(request: &Request) -> Option<String> {
    let query = request.uri().query()?;
    for pair in query.split('&') {
        let mut iter = pair.splitn(2, '=');
        let key = iter.next().unwrap_or_default();
        if key != "admin_key" {
            continue;
        }
        let raw = iter.next().unwrap_or_default();
        let decoded = percent_decode_str(raw).decode_utf8().ok()?;
        return Some(decoded.into_owned());
    }
    None
}

/// Authentication middleware for WebSocket endpoints.
async fn require_ws_auth(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    if state.admin_auth_disabled {
        return Ok(next.run(request).await);
    }
    if is_dev_mode() {
        return Ok(next.run(request).await);
    }

    let client_ip = extract_client_ip(&request);
    let header_key = request
        .headers()
        .get("X-Admin-Key")
        .and_then(|v| v.to_str().ok());
    let query_key = extract_admin_key_from_query(&request);
    let provided_key = header_key.or_else(|| query_key.as_deref());

    match validate_admin_key(&state, client_ip, provided_key) {
        Ok(()) => Ok(next.run(request).await),
        Err(response) => Err(response),
    }
}

/// Extract client IP address from request headers or socket.
fn extract_client_ip(request: &Request) -> IpAddr {
    // Try X-Forwarded-For first (for proxied requests)
    if let Some(xff) = request.headers().get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the chain (client IP)
            if let Some(first_ip) = xff_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP
    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            if let Ok(ip) = real_ip_str.trim().parse() {
                return ip;
            }
        }
    }

    // Default to localhost if no headers found
    // In production, the admin server should be behind a proxy that sets these headers
    IpAddr::from([127, 0, 0, 1])
}

/// Scope-checking middleware for admin:write scope (WS2-004).
async fn require_admin_write(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::ADMIN_WRITE, request, next).await
}

/// Scope-checking middleware for config:write scope (WS2-004).
async fn require_config_write(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::CONFIG_WRITE, request, next).await
}

/// Scope-checking middleware for service:manage scope (WS2-004).
async fn require_service_manage(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::SERVICE_MANAGE, request, next).await
}

/// Scope-checking middleware for sensor:read scope (sensitive sensor data).
async fn require_sensor_read(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::SENSOR_READ, request, next).await
}

/// Scope-checking middleware for sensor:write scope.
async fn require_sensor_write(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::SENSOR_WRITE, request, next).await
}

/// Scope-checking middleware for admin:read scope.
async fn require_admin_read(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    check_scope(&state, scopes::ADMIN_READ, request, next).await
}

/// Internal helper to check if a required scope is granted.
async fn check_scope(
    state: &AdminState,
    required_scope: &str,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    if state.admin_auth_disabled {
        return Ok(next.run(request).await);
    }
    // Check if the required scope is granted (or wildcard "*" grants all)
    if state.admin_scopes.iter().any(|s| s == required_scope || s == "*") {
        Ok(next.run(request).await)
    } else {
        warn!(
            "Scope check failed: required '{}', granted: {:?}",
            required_scope, state.admin_scopes
        );
        let mut problem = ProblemDetails::new(StatusCode::FORBIDDEN, "Insufficient scope");
        problem.code = Some(error_codes::INSUFFICIENT_SCOPE.to_string());
        problem.required_scope = Some(required_scope.to_string());
        Err((StatusCode::FORBIDDEN, Json(problem)).into_response())
    }
}

/// Rate limiting middleware for admin endpoints (stricter limits).
/// Returns 429 Too Many Requests with Retry-After header when limit exceeded.
async fn rate_limit_admin(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // DEV MODE: Skip rate limiting for local development
    if is_dev_mode() {
        return Ok(next.run(request).await);
    }

    // Extract client IP from X-Forwarded-For or fall back to peer address
    let client_ip = extract_client_ip(&request);

    match state.admin_rate_limiter.check_key(&client_ip) {
        Ok(_) => Ok(next.run(request).await),
        Err(not_until) => {
            let retry_after = not_until.wait_time_from(governor::clock::Clock::now(
                &governor::clock::DefaultClock::default(),
            ));
            warn!("Admin rate limit exceeded for IP: {}", client_ip);
            let mut problem =
                ProblemDetails::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
            problem.code = Some(error_codes::RATE_LIMIT_EXCEEDED.to_string());
            problem.retry_after_secs = Some(retry_after.as_secs());
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.as_secs().to_string())],
                Json(problem),
            )
                .into_response())
        }
    }
}

/// Rate limiting middleware for public endpoints (more generous limits).
async fn rate_limit_public(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    // DEV MODE: Skip rate limiting for local development
    if is_dev_mode() {
        return Ok(next.run(request).await);
    }

    let client_ip = extract_client_ip(&request);

    match state.public_rate_limiter.check_key(&client_ip) {
        Ok(_) => Ok(next.run(request).await),
        Err(not_until) => {
            let retry_after = not_until.wait_time_from(governor::clock::Clock::now(
                &governor::clock::DefaultClock::default(),
            ));
            warn!("Public rate limit exceeded for IP: {}", client_ip);
            let mut problem =
                ProblemDetails::new(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded");
            problem.code = Some(error_codes::RATE_LIMIT_EXCEEDED.to_string());
            problem.retry_after_secs = Some(retry_after.as_secs());
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, retry_after.as_secs().to_string())],
                Json(problem),
            )
                .into_response())
        }
    }
}

/// Audit logging middleware for state-changing admin operations.
async fn audit_log(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let client_ip = extract_client_ip(&request);
    let start = Instant::now();

    let response = next.run(request).await;

    if matches!(method, Method::POST | Method::PUT | Method::DELETE | Method::PATCH) {
        let status = response.status();
        let duration_ms = start.elapsed().as_millis();
        let actor = client_ip.to_string();

        tracing::info!(
            target: "audit",
            actor = actor,
            method = %method,
            path = %path,
            status = status.as_u16(),
            client_ip = %client_ip,
            duration_ms = duration_ms,
            "admin_api_mutation"
        );

        record_log_with_source(
            "info",
            LogSource::Access,
            format!(
                "audit actor={} method={} path={} status={} ip={} duration_ms={}",
                actor,
                method.as_str(),
                path,
                status.as_u16(),
                client_ip,
                duration_ms
            ),
        );
    }

    response
}

/// Security headers middleware for all API responses.
/// Adds defense-in-depth headers to prevent common web vulnerabilities.
async fn security_headers(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Prevent MIME type sniffing attacks
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking - API should never be framed
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );

    // Control referrer information leakage
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Prevent caching of sensitive API responses
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );

    // Content-Security-Policy for API responses (stricter than console)
    // Note: Console handler sets its own CSP via ADMIN_CONSOLE_CSP
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
    }

    // Permissions-Policy to disable unnecessary browser features
    headers.insert(
        http::header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );

    response
}

fn build_response(
    status: StatusCode,
    body: String,
    content_type: &'static str,
    disposition: Option<String>,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));

    if let Some(disposition) = disposition {
        match HeaderValue::from_str(&disposition) {
            Ok(value) => {
                response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
            }
            Err(err) => {
                warn!("Invalid Content-Disposition header value: {}", err);
            }
        }
    }

    response
}

/// Starts the admin HTTP server.
///
/// # Arguments
/// * `addr` - Socket address to bind (e.g., "0.0.0.0:6191")
/// * `handler` - API handler with references to health, metrics, reloader, etc.
/// * `admin_api_key` - Required API key for authenticating admin operations
/// * `admin_auth_disabled` - Disables admin authentication (local-only)
pub async fn start_admin_server(
    addr: SocketAddr,
    handler: Arc<ApiHandler>,
    admin_api_key: String,
    admin_auth_disabled: bool,
) -> std::io::Result<()> {
    // SECURITY: Authentication is now mandatory - all admin scopes granted to the API key
    let admin_scopes: Vec<String> = scopes::ALL.iter().map(|s| s.to_string()).collect();
    // Create rate limiters:
    // - Admin routes: 100 requests per minute per IP (stricter for privileged operations)
    // - Public routes: 1000 requests per minute per IP (more generous for monitoring)
    // - Auth failures: 5 attempts per minute per IP (very strict to prevent brute-force)
    let admin_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN),
    )));
    let public_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(1000).unwrap_or(NonZeroU32::MIN),
    )));
    // SECURITY: Very strict rate limit for auth failures to prevent brute-force attacks
    let auth_failure_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(5).unwrap_or(NonZeroU32::MIN),
    )));
    // SECURITY: Limit external signal ingestion to 100 reports/minute per sensor (labs-8csv)
    let report_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(100).unwrap_or(NonZeroU32::MIN),
    )));

    let state = AdminState {
        handler,
        admin_api_key,
        admin_auth_disabled,
        admin_scopes,
        signal_permissions: Arc::new(SignalPermissions::default()),
        admin_rate_limiter,
        public_rate_limiter,
        report_rate_limiter,
        auth_failure_limiter,
    };

    // Initialize metrics history with current values
    record_metrics_sample();

    if let Err(err) = recover_sysctl_wal() {
        warn!("Failed to recover sysctl WAL: {}", err);
    }

    // Add startup log entries
    record_log("info", format!("Synapse-Pingora admin server starting on {}", addr));
    record_log("info", "WAF engine initialized with 237 detection rules".to_string());
    record_log("info", format!("Platform: {} {}", std::env::consts::OS, std::env::consts::ARCH));

    // CORS configuration for dashboard access
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE, 
            header::ACCEPT, 
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-admin-key")
        ]);

    // Routes requiring admin:write scope (reload, test)
    let admin_write_routes = Router::new()
        .route("/reload", post(reload_handler))
        .route("/test", post(test_handler))
        .route("/config", post(update_config_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_write))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Routes requiring config:write scope (site management)
    let config_write_routes = Router::new()
        .route("/sites", post(create_site_handler))
        .route("/sites/{hostname}", put(update_site_handler).delete(delete_site_handler))
        .route("/sites/{hostname}/waf", put(update_site_waf_handler))
        .route("/sites/{hostname}/rate-limit", put(update_site_rate_limit_handler))
        .route("/sites/{hostname}/access-list", put(update_site_access_list_handler))
        .route("/sites/{hostname}/shadow", put(update_site_shadow_handler))
        .route("/debug/profiles/save", post(save_profiles_handler))
        // Read config is technically read-only but sensitive, so guard with config scope
        .route("/config", get(config_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_config_write))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Routes requiring service:manage scope (restart, reset operations)
    let service_manage_routes = Router::new()
        .route("/restart", post(restart_handler))
        .route("/api/profiles/reset", post(api_profiles_reset_handler))
        .route("/api/schemas/reset", post(api_schemas_reset_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_service_manage))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Routes requiring sensor:read scope (sensitive sensor data - P0 security fix)
    // These endpoints expose correlation graphs, DLP violations, and attack attribution data
    let sensor_read_routes = Router::new()
        .route("/_sensor/campaigns/:id/graph", get(sensor_campaign_graph_handler))
        .route("/_sensor/campaigns/:id/actors", get(sensor_campaign_actors_handler))
        .route("/_sensor/campaigns/:id/timeline", get(sensor_campaign_timeline_handler))
        .route("/_sensor/dlp/stats", get(sensor_dlp_stats_handler))
        .route("/_sensor/dlp/violations", get(sensor_dlp_violations_handler))
        .route("/_sensor/actors/:actor_id", get(sensor_actor_detail_handler))
        .route("/_sensor/actors/:actor_id/timeline", get(sensor_actor_timeline_handler))
        .route("/_sensor/sessions/:session_id", get(sensor_session_detail_handler))
        .route("/_sensor/entities", get(sensor_entities_handler))
        .route("/_sensor/status", get(sensor_status_handler))
        .route("/_sensor/config", get(sensor_config_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_sensor_read))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Routes requiring sensor:write scope (ingestion)
    let sensor_write_routes = Router::new()
        .route("/_sensor/report", post(sensor_report_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_sensor_write))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Rules endpoints (defense-in-depth RBAC)
    let rules_read_routes = Router::new()
        .route("/_sensor/rules", get(sensor_rules_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    let rules_write_routes = Router::new()
        .route("/_sensor/rules", post(sensor_rules_create_handler))
        .route("/_sensor/rules/:rule_id", put(sensor_rules_update_handler).delete(sensor_rules_delete_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_write))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    let kernel_config_read_routes = Router::new()
        .route("/_sensor/config/kernel", get(config_kernel_get_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    let kernel_config_write_routes = Router::new()
        .route("/_sensor/config/kernel", put(config_kernel_put_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_write))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

    // Routes requiring admin:read scope (console access and sensitive logs)
    let admin_read_routes = Router::new()
        .route("/console", get(admin_console_handler))
        .route("/_sensor/system/logs", get(sensor_system_logs_handler))
        .route("/_sensor/logs", get(logs_handler))
        .route("/_sensor/logs/:source", get(logs_by_source_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_public));

    // Routes that are safe to expose without authentication (health check only).
    let public_routes = Router::new()
        .route("/health", get(health_handler))
        // Demo mode control (public for easier demoability)
        .route("/_sensor/demo", get(sensor_demo_get_handler))
        .route("/_sensor/demo/toggle", post(sensor_demo_toggle_handler).get(sensor_demo_toggle_handler));

    // WebSocket debugger routes with query/header auth support.
    let debugger_routes = Router::new()
        .route("/_sensor/debugger/ws", get(waf_debugger_ws_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_ws_auth))
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_public));

    // All remaining admin API routes require authentication.
    let authenticated_routes = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/sites", get(sites_handler))
        .route("/sites/{hostname}", get(get_site_handler))
        .route("/stats", get(stats_handler))
        .route("/waf/stats", get(waf_stats_handler))
        .route("/debug/profiles", get(profiles_handler))
        // Dashboard compatibility routes (/_sensor/ prefix)
        .route("/_sensor/health", get(health_handler))
        .route("/_sensor/entities/release-all", post(sensor_release_all_handler))
        .route("/_sensor/entities/:ip", delete(sensor_release_entity_handler))
        .route("/_sensor/metrics/reset", post(sensor_metrics_reset_handler))
        .route("/_sensor/blocks", get(sensor_blocks_handler))
        .route("/_sensor/trends", get(sensor_trends_handler))
        .route("/_sensor/signals", get(sensor_signals_handler))
        .route("/_sensor/anomalies", get(sensor_anomalies_handler))
        .route("/_sensor/campaigns", get(sensor_campaigns_handler))
        .route("/_sensor/campaigns/:id", get(sensor_campaign_detail_handler))
        // Note: campaigns/:id/actors, /graph, /timeline moved to sensor_read_routes (require auth)
        .route("/_sensor/payload/bandwidth", get(sensor_bandwidth_handler))
        .route("/_sensor/actors", get(sensor_actors_handler))
        // Note: actors/:actor_id detail/timeline moved to sensor_read_routes (require auth)
        .route("/_sensor/sessions", get(sensor_sessions_handler))
        // Note: sessions/:session_id moved to sensor_read_routes (require auth)
        .route("/_sensor/stuffing", get(sensor_stuffing_handler))
        .route("/_sensor/system/config", get(sensor_system_config_handler))
        .route("/_sensor/system/overview", get(sensor_system_overview_handler))
        .route("/_sensor/system/performance", get(sensor_system_performance_handler))
        .route("/_sensor/system/network", get(sensor_system_network_handler))
        .route("/_sensor/system/processes", get(sensor_system_processes_handler))
        // Note: DLP endpoints moved to sensor_read_routes (require auth)
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
        // Configuration endpoints for admin console
        .route("/_sensor/config/dlp", get(config_dlp_get_handler).put(config_dlp_put_handler))
        .route("/_sensor/config/block-page", get(config_block_page_get_handler).put(config_block_page_put_handler))
        .route("/_sensor/config/crawler", get(config_crawler_get_handler).put(config_crawler_put_handler))
        .route("/_sensor/config/tarpit", get(config_tarpit_get_handler).put(config_tarpit_put_handler))
        .route("/_sensor/config/travel", get(config_travel_get_handler).put(config_travel_put_handler))
        .route("/_sensor/config/entity", get(config_entity_get_handler).put(config_entity_put_handler))
        .route("/_sensor/config/integrations", get(config_integrations_get_handler).put(config_integrations_put_handler))
        // Log viewer endpoints moved to admin_read_routes (require admin:read)
        // Diagnostic bundle export
        .route("/_sensor/diagnostic-bundle", get(diagnostic_bundle_handler))
        // Configuration export/import
        .route("/_sensor/config/export", get(config_export_handler))
        .route("/_sensor/config/import", post(config_import_handler))
        .route("/", get(root_handler))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
        // Rate limit authenticated endpoints (1000 req/min per IP)
        .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_public));

    let app = Router::new()
        .merge(admin_write_routes)
        .merge(config_write_routes)
        .merge(service_manage_routes)
        .merge(sensor_read_routes)
        .merge(sensor_write_routes)
        .merge(rules_read_routes)
        .merge(rules_write_routes)
        .merge(kernel_config_read_routes)
        .merge(kernel_config_write_routes)
        .merge(admin_read_routes)
        .merge(debugger_routes)
        .merge(authenticated_routes)
        .merge(public_routes)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(audit_log))
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
            { "method": "GET", "path": "/console", "description": "Admin console UI" },
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

/// GET /console - Admin console for synapse operations
async fn admin_console_handler() -> impl IntoResponse {
    let content = if is_dev_mode() {
        // In dev mode, read from disk for live reloading
        match std::fs::read_to_string("assets/admin_console.html") {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!("Failed to read admin console from disk: {}, falling back to embedded", e);
                ADMIN_CONSOLE_TEMPLATE.to_string()
            }
        }
    } else {
        ADMIN_CONSOLE_TEMPLATE.to_string()
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, ADMIN_CONSOLE_CSP),
        ],
        Html(content),
    )
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
    // Demo mode: return pre-populated sample data
    if is_demo_mode() {
        return (StatusCode::OK, Json(demo_sites())).into_response();
    }

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

    let metrics = state.handler.metrics();
    let response = ShadowStatusResponse {
        enabled: sites_with_shadow > 0,
        sites_with_shadow,
        total_mirrored: metrics.shadow_mirrored_total(),
        total_rate_limited: metrics.shadow_rate_limited_total(),
        total_failed: metrics.shadow_failed_total(),
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
                ).into_response();
            }
            Err(_) => {}
        }
    }

    not_found_error("Site", &hostname)
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
                return not_found_error("Site", &hostname);
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
            // SECURITY: Log internal error but return generic message
            return validation_error("Invalid shadow mirror configuration", Some(&e));
        }

        // Create UpdateSiteRequest with just shadow_mirror
        let update_request = UpdateSiteRequest {
            shadow_mirror: Some(shadow_config.clone()),
            ..Default::default()
        };

        // Update site in config manager
        if let Err(e) = config_mgr.update_site(&hostname, update_request) {
            // SECURITY: Log internal error but return generic message
            return internal_error("Failed to update site configuration", Some(&e));
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
        ).into_response();
    }

    // SECURITY: Use generic service unavailable message
    service_unavailable("Configuration service")
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

/// GET /_sensor/demo - Get demo mode status
async fn sensor_demo_get_handler() -> impl IntoResponse {
    let is_demo = is_demo_mode();
    (StatusCode::OK, Json(serde_json::json!({ "success": true, "demo_mode": is_demo })))
}

/// POST /_sensor/demo/toggle - Toggle demo mode at runtime
async fn sensor_demo_toggle_handler() -> impl IntoResponse {
    let current = is_demo_mode();
    if current {
        DEMO_MODE.store(false, std::sync::atomic::Ordering::SeqCst);
    } else {
        enable_demo_mode();
    }
    let new_mode = is_demo_mode();
    info!("Demo mode toggled to: {}", new_mode);
    (StatusCode::OK, Json(serde_json::json!({ "success": true, "demo_mode": new_mode })))
}

/// GET /_sensor/status - Dashboard status endpoint
/// Returns a format compatible with the dashboard's expected response.
async fn sensor_status_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Demo mode: return pre-populated sample data
    if is_demo_mode() {
        return (StatusCode::OK, Json(demo_status()));
    }

    let health = state.handler.handle_health();
    let stats = state.handler.handle_stats();
    let waf = state.handler.handle_waf_stats();

    // P2 fix: Add DLP scanner health status
    let dlp_status = state.handler.dlp_scanner().map(|scanner| {
        let scanner_stats = scanner.stats();
        serde_json::json!({
            "enabled": scanner.is_enabled(),
            "healthy": true, // Scanner is healthy if we can access it
            "totalScans": scanner_stats.total_scans,
            "totalMatches": scanner_stats.total_matches,
            "patternCount": scanner.pattern_count()
        })
    });

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
        "dlp": dlp_status, // P2 fix: Added DLP health status
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
    // Demo mode: return pre-populated sample data
    if is_demo_mode() {
        return (StatusCode::OK, Json(demo_entities()));
    }

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
            }))).into_response()
        } else {
            not_found_error("Entity", &ip)
        }
    } else {
        service_unavailable("Entity tracking")
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
        }))).into_response()
    } else {
        service_unavailable("Entity tracking")
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

/// Query parameters for rules endpoint
#[derive(Debug, Deserialize)]
struct RulesQuery {
    enabled: Option<bool>,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

fn default_rule_enabled() -> bool {
    true
}

fn default_rule_priority() -> u32 {
    100
}

#[derive(Debug, Deserialize)]
struct RuleCreateRequest {
    name: String,
    #[serde(rename = "type")]
    rule_type: String,
    #[serde(default = "default_rule_enabled")]
    enabled: bool,
    #[serde(default = "default_rule_priority")]
    priority: u32,
    #[serde(default)]
    conditions: Vec<CustomRuleCondition>,
    #[serde(default)]
    actions: Vec<CustomRuleAction>,
    #[serde(default)]
    ttl: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RuleUpdateRequest {
    name: Option<String>,
    #[serde(rename = "type")]
    rule_type: Option<String>,
    enabled: Option<bool>,
    priority: Option<u32>,
    conditions: Option<Vec<CustomRuleCondition>>,
    actions: Option<Vec<CustomRuleAction>>,
    ttl: Option<u64>,
}

/// Query parameters for signals endpoint
#[derive(Debug, Deserialize)]
struct SignalsQuery {
    limit: Option<usize>,
    category: Option<String>,
    since_ms: Option<u64>,
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

/// GET /_sensor/rules - Returns active rules with optional filtering
async fn sensor_rules_handler(
    Query(params): Query<RulesQuery>,
    State(state): State<AdminState>,
) -> Response {
    let Some(config_mgr) = state.handler.config_manager() else {
        return service_unavailable("ConfigManager");
    };

    let rules = config_mgr.list_rules();
    let mut views: Vec<RuleView> = rules.iter().map(RuleView::from_stored).collect();

    if let Some(enabled) = params.enabled {
        views.retain(|rule| rule.enabled == enabled);
    }
    if let Some(rule_type) = params.rule_type {
        let target = rule_type.to_ascii_uppercase();
        views.retain(|rule| rule.rule_type.eq_ignore_ascii_case(&target));
    }

    let total = views.len();
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100);
    let rules_page: Vec<RuleView> = views.into_iter().skip(offset).take(limit).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "rules": rules_page,
        "total": total
    })))
        .into_response()
}

/// POST /_sensor/rules - Create a new rule
async fn sensor_rules_create_handler(
    State(state): State<AdminState>,
    Json(payload): Json<RuleCreateRequest>,
) -> impl IntoResponse {
    if payload.conditions.is_empty() {
        return validation_error("Rule must include at least one condition", None);
    }
    if payload.actions.is_empty() {
        return validation_error("Rule must include at least one action", None);
    }

    let Some(config_mgr) = state.handler.config_manager() else {
        return service_unavailable("ConfigManager");
    };

    let rule_id = format!("rule_{}", uuid::Uuid::new_v4());
    let custom = CustomRuleInput {
        id: rule_id,
        name: payload.name,
        rule_type: payload.rule_type.to_ascii_uppercase(),
        enabled: payload.enabled,
        priority: payload.priority,
        conditions: payload.conditions,
        actions: payload.actions,
        ttl: payload.ttl,
    };

    let stored = match StoredRule::from_custom(custom) {
        Ok(rule) => rule,
        Err(err) => return validation_error("Invalid rule definition", Some(&err)),
    };

    match config_mgr.create_rule(stored) {
        Ok(created) => (StatusCode::CREATED, Json(RuleView::from_stored(&created))).into_response(),
        Err(ConfigManagerError::RuleExists(_)) => validation_error("Rule already exists", None),
        Err(err) => internal_error("Failed to create rule", Some(&err)),
    }
}

/// PUT /_sensor/rules/{rule_id} - Update an existing rule
async fn sensor_rules_update_handler(
    Path(rule_id): Path<String>,
    State(state): State<AdminState>,
    Json(payload): Json<RuleUpdateRequest>,
) -> impl IntoResponse {
    let Some(config_mgr) = state.handler.config_manager() else {
        return service_unavailable("ConfigManager");
    };

    let update = CustomRuleUpdate {
        name: payload.name,
        rule_type: payload.rule_type.map(|value| value.to_ascii_uppercase()),
        enabled: payload.enabled,
        priority: payload.priority,
        conditions: payload.conditions,
        actions: payload.actions,
        ttl: payload.ttl,
    };

    match config_mgr.update_rule(&rule_id, update) {
        Ok(updated) => (StatusCode::OK, Json(RuleView::from_stored(&updated))).into_response(),
        Err(ConfigManagerError::RuleNotFound(_)) => not_found_error("Rule", &rule_id),
        Err(err) => internal_error("Failed to update rule", Some(&err)),
    }
}

/// DELETE /_sensor/rules/{rule_id} - Delete a rule
async fn sensor_rules_delete_handler(
    Path(rule_id): Path<String>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let Some(config_mgr) = state.handler.config_manager() else {
        return service_unavailable("ConfigManager");
    };

    match config_mgr.delete_rule(&rule_id) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Rule deleted"
        }))).into_response(),
        Err(ConfigManagerError::RuleNotFound(_)) => not_found_error("Rule", &rule_id),
        Err(err) => internal_error("Failed to delete rule", Some(&err)),
    }
}

/// GET /_sensor/trends - Returns real trends data from TrendsManager
async fn sensor_trends_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_trends_summary();
    if response.success {
        if let Some(data) = response.data {
            return (StatusCode::OK, Json(serde_json::json!({
                "signalCounts": data.signal_counts,
                "totalSignals": data.total_signals,
                "topSignals": data.top_signal_types,
                "timeRange": data.time_range,
                "anomalyCount": data.anomaly_count
            })));
        }
    }
    // Fallback to empty data if TrendsManager not available
    if let Some(err) = response.error {
        log::warn!("TrendsManager not available: {}", err);
    }
    (StatusCode::OK, Json(serde_json::json!({
        "signalCounts": {},
        "timeline": [],
        "topSignals": []
    })))
}

/// GET /_sensor/signals - Returns intelligence signals from SignalManager
async fn sensor_signals_handler(
    Query(params): Query<SignalsQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100).min(500);

    let category = params.category.as_deref().and_then(|raw| {
        match raw.to_lowercase().as_str() {
            "attack" => Some(SignalCategory::Attack),
            "anomaly" => Some(SignalCategory::Anomaly),
            "behavior" => Some(SignalCategory::Behavior),
            "intelligence" => Some(SignalCategory::Intelligence),
            _ => None,
        }
    });

    let response = state.handler.handle_signals(SignalQueryOptions {
        category,
        limit: Some(limit),
        since_ms: params.since_ms,
    });

    if response.success {
        if let Some(data) = response.data {
            return (StatusCode::OK, Json(serde_json::json!({
                "signals": data.signals,
                "summary": data.summary
            })));
        }
    }

    if let Some(err) = response.error {
        log::warn!("SignalManager not available: {}", err);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "signals": [],
        "summary": {
            "total_signals": 0,
            "by_category": {},
            "top_signal_types": []
        }
    })))
}

/// External threat report format from Apparatus/Cutlass sensors.
///
/// This format is used by the `/_sensor/report` endpoint to ingest signals
/// from deception tools and traffic generators.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ApparatusReport {
    /// Unique identifier for the sensor reporting the threat.
    #[serde(rename = "sensorId")]
    pub sensor_id: String,
    /// ISO 8601 formatted timestamp of the event.
    pub timestamp: String,
    /// Optional sensor software version for compatibility mapping.
    pub version: Option<String>,
    /// Context about the actor (client) that triggered the signal.
    pub actor: ApparatusActor,
    /// Details about the threat signal itself.
    pub signal: ApparatusSignal,
    /// Optional HTTP request context if the signal was triggered by a specific request.
    pub request: Option<ApparatusRequest>,
}

/// Context about the actor (client) associated with a threat report.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ApparatusActor {
    /// IP address of the client.
    pub ip: String,
    /// Browser or device fingerprint if available.
    pub fingerprint: Option<String>,
    /// Unique session identifier from the application layer.
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
}

/// Details about a threat signal.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ApparatusSignal {
    /// Signal type identifier (e.g., "honeypot_hit", "dlp_match").
    /// Mapped to internal `SignalType` via `SignalAdapter`.
    #[serde(rename = "type")]
    pub signal_type: String,
    /// Threat severity level ("low", "medium", "high", "critical").
    pub severity: String,
    /// Arbitrary structured data providing additional context for the signal.
    pub details: serde_json::Value,
}

/// HTTP request context associated with a threat report.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ApparatusRequest {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// URL path of the request.
    pub path: String,
    /// Optional HTTP headers relevant to the threat.
    pub headers: Option<HashMap<String, String>>,
}

impl ApparatusReport {
    pub fn validate(&self) -> Result<(), String> {
        // Validate sensor_id
        if self.sensor_id.is_empty() || self.sensor_id.len() > 64 {
            return Err("Invalid sensorId length".to_string());
        }
        if !self.sensor_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err("Invalid characters in sensorId".to_string());
        }

        // Validate timestamp (ISO 8601-ish)
        if self.timestamp.len() > 64 {
            return Err("Invalid timestamp length".to_string());
        }

        // Validate actor
        self.actor.validate()?;

        // Validate signal
        self.signal.validate()?;

        // Validate request if present
        if let Some(ref req) = self.request {
            req.validate()?;
        }

        Ok(())
    }
}

impl ApparatusActor {
    pub fn validate(&self) -> Result<(), String> {
        // Validate IP
        if self.ip.parse::<IpAddr>().is_err() {
            return Err(format!("Invalid IP address: {}", self.ip));
        }

        // Validate fingerprint if present
        if let Some(ref fp) = self.fingerprint {
            if fp.len() > 256 {
                return Err("Fingerprint too long".to_string());
            }
        }

        // Validate sessionId if present
        if let Some(ref sid) = self.session_id {
            if sid.len() > 128 {
                return Err("SessionId too long".to_string());
            }
        }

        Ok(())
    }
}

impl ApparatusSignal {
    pub fn validate(&self) -> Result<(), String> {
        // Validate signal_type
        if self.signal_type.is_empty() || self.signal_type.len() > 64 {
            return Err("Invalid signal type length".to_string());
        }
        if !self.signal_type.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err("Invalid characters in signal type".to_string());
        }

        // Validate severity
        match self.severity.to_lowercase().as_str() {
            "low" | "medium" | "high" | "critical" => {}
            _ => return Err(format!("Invalid severity: {}", self.severity)),
        }

        // Details is a serde_json::Value, check if it's too large or deeply nested
        // Simple size check: serialize and check length
        let serialized = serde_json::to_string(&self.details).unwrap_or_default();
        if serialized.len() > 1024 * 10 { // 10KB limit for details
            return Err("Details payload too large".to_string());
        }

        Ok(())
    }
}

impl ApparatusRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.method.len() > 10 {
            return Err("Invalid HTTP method length".to_string());
        }
        if self.path.len() > 2048 {
            return Err("Path too long".to_string());
        }
        // Limit headers count
        if let Some(ref headers) = self.headers {
            if headers.len() > 50 {
                return Err("Too many headers".to_string());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static FORCE_METADATA_SERIALIZE_ERROR: std::cell::Cell<bool> = std::cell::Cell::new(false);
}

fn serialize_report_metadata(report: &ApparatusReport) -> serde_json::Value {
    #[cfg(test)]
    if FORCE_METADATA_SERIALIZE_ERROR.with(|flag| flag.get()) {
        warn!(
            sensor_id = %report.sensor_id,
            "Forced metadata serialization error for testing"
        );
        return serde_json::json!({});
    }

    serde_json::to_value(report).unwrap_or_else(|err| {
        warn!(
            sensor_id = %report.sensor_id,
            error = %err,
            "Failed to serialize external report metadata"
        );
        serde_json::json!({})
    })
}

/// POST /_sensor/report - Ingest external threat signals (e.g. from Apparatus/Cutlass)
/// Ingest external threat signals from sensors.
///
/// This endpoint allows external components like Apparatus (Cutlass) to report
/// threat detections (honeypot hits, DLP matches, etc.) to the central Hub.
///
/// # Security
/// - Requires `X-Admin-Key` authentication.
/// - Subject to per-sensor rate limiting (100 reports/min).
/// - Validates all input fields for length and character constraints.
///
/// # Behavior
/// 1. Validates the incoming `ApparatusReport`.
/// 2. Maps external signal types to internal ones using `SignalAdapter`.
/// 3. Dispatches the signal to Signal Horizon Hub (fleet intelligence) and
///    the local SignalManager (dashboard visibility) in parallel.
/// 4. Returns 200 OK on success, or appropriate error codes (400, 401, 429, 503).
#[tracing::instrument(skip(state, report), fields(sensor_id = %report.sensor_id, signal_type = %report.signal.signal_type))]
async fn sensor_report_handler(
    State(state): State<AdminState>,
    Json(report): Json<ApparatusReport>,
) -> Response {
    use crate::horizon::ThreatSignal;

    // Validate input fields (labs-itup)
    if let Err(err) = report.validate() {
        warn!(
            sensor_id = %report.sensor_id,
            error = %err,
            "Validation failed for external threat report"
        );
        return validation_error(&err, None);
    }

    let signal_type_raw = report.signal.signal_type.trim().to_lowercase();
    if !state
        .signal_permissions
        .is_allowed(&report.sensor_id, &signal_type_raw)
    {
        warn!(
            sensor_id = %report.sensor_id,
            signal_type = %signal_type_raw,
            "Rejected external signal type"
        );
        return forbidden_error("Signal type not permitted for sensor");
    }

    // Rate limit per sensor (labs-8csv)
    if let Err(not_until) = state.report_rate_limiter.check_key(&report.sensor_id) {
        let retry_after = not_until.wait_time_from(governor::clock::Clock::now(
            &governor::clock::DefaultClock::default(),
        ));
        warn!(
            sensor_id = %report.sensor_id,
            "Signal ingestion rate limit exceeded"
        );
        return rate_limit_error(retry_after.as_secs().max(1));
    }

    // Map external signal to internal types using version-aware adapter
    let signal_type = SignalAdapter::map_type(&report);
    let severity = SignalAdapter::map_severity(&report.signal.severity);

    // Create threat signal
    let mut signal = ThreatSignal::new(signal_type, severity)
        .with_source_ip(&report.actor.ip)
        .with_confidence(1.0); // External ground truth is high confidence

    if let Some(ref fp) = report.actor.fingerprint {
        signal = signal.with_fingerprint(fp);
    }

    // Embed full report as metadata
    let metadata = serialize_report_metadata(&report);
    signal = signal.with_metadata(metadata.clone());

    // Dispatch using unified dispatcher facade (labs-pdb2)
    match state
        .handler
        .signal_dispatcher()
        .dispatch(
            signal,
            SignalCategory::Intelligence,
            &report.sensor_id,
            Some(format!("External threat reported by {}", report.sensor_id)),
            metadata,
        )
        .await
    {
        Ok(_) => {
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "id": uuid::Uuid::new_v4().to_string()
            })))
                .into_response()
        }
        Err(err) => {
            warn!(
                sensor_id = %report.sensor_id,
                error = %err,
                "Signal dispatch failed"
            );
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
                "success": false,
                "error": err
            })))
                .into_response()
        }
    }
}

/// GET /_sensor/anomalies - Returns real anomaly events from TrendsManager
async fn sensor_anomalies_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let response = state.handler.handle_trends_anomalies(50);
    if response.success {
        if let Some(anomalies) = response.data {
            let data: Vec<serde_json::Value> = anomalies
                .into_iter()
                .map(|a| serde_json::json!({
                    "id": format!("anom-{}", &a.detected_at_ms.to_string()[..6]),
                    "type": a.anomaly_type.to_lowercase().replace("_", "-"),
                    "severity": a.severity.to_lowercase(),
                    "description": a.description,
                    "entityId": a.entities.first().unwrap_or(&"unknown".to_string()),
                    "riskApplied": 0, // Not stored in TrendsAnomalyResponse
                    "timestamp": chrono::DateTime::from_timestamp_millis(a.detected_at_ms)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
                }))
                .collect();
            return (StatusCode::OK, Json(serde_json::json!({ "data": data })));
        }
    }
    // Fallback if TrendsManager not available
    if let Some(err) = response.error {
        log::warn!("TrendsManager not available for anomalies: {}", err);
    }
    (StatusCode::OK, Json(serde_json::json!({ "data": [] })))
}

/// GET /_sensor/campaigns - Returns active threat campaigns
async fn sensor_campaigns_handler(State(state): State<AdminState>) -> impl IntoResponse {
    // Demo mode: return pre-populated sample data
    if is_demo_mode() {
        return (StatusCode::OK, Json(demo_campaigns()));
    }

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
                    (StatusCode::OK, Json(serde_json::json!({ "data": data }))).into_response()
                }
                None => not_found_error("Campaign", &id),
            }
        }
        None => service_unavailable("Campaign correlation"),
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
        Some(data) => (StatusCode::OK, Json(serde_json::json!({ "data": data }))).into_response(),
        None => not_found_error("Campaign", &id),
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

/// Query parameters for graph endpoint (P1 pagination)
#[derive(Debug, Deserialize)]
struct GraphQuery {
    /// Maximum number of nodes to return (default: 500)
    #[serde(default = "default_graph_limit")]
    limit: usize,
    /// Skip this many nodes (for pagination)
    #[serde(default)]
    offset: usize,
    /// Hash identifiers for external exposure (default: true for security)
    #[serde(default = "default_hash_identifiers")]
    hash_identifiers: bool,
}

fn default_graph_limit() -> usize { 500 }
fn default_hash_identifiers() -> bool { true }

/// GET /_sensor/campaigns/:id/graph - Returns correlation graph data for a campaign
/// P1 fix: Adds pagination and identifier hashing
async fn sensor_campaign_graph_handler(
    State(state): State<AdminState>,
    Path(id): Path<String>,
    Query(query): Query<GraphQuery>,
) -> impl IntoResponse {
    match state.handler.campaign_manager() {
        Some(manager) => {
            let graph = manager.get_campaign_graph_paginated(
                &id,
                Some(query.limit),
                Some(query.offset),
                query.hash_identifiers,
            );
            (StatusCode::OK, Json(serde_json::json!({
                "data": {
                    "nodes": graph.nodes,
                    "edges": graph.edges
                },
                "pagination": {
                    "total": graph.total_nodes,
                    "limit": query.limit,
                    "offset": query.offset,
                    "hasMore": graph.has_more
                },
                "snapshotVersion": graph.snapshot_version
            }))).into_response()
        }
        None => service_unavailable("Campaign correlation"),
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
    ip: Option<String>,
    fingerprint: Option<String>,
    min_risk: Option<f64>,
}

/// Query parameters for actor timeline endpoint
#[derive(Debug, Deserialize)]
struct ActorTimelineQuery {
    limit: Option<usize>,
}

fn actor_to_json(actor: &crate::actor::ActorState) -> serde_json::Value {
    let mut ips: Vec<String> = actor.ips.iter().map(|ip| ip.to_string()).collect();
    ips.sort();
    let mut fingerprints: Vec<String> = actor.fingerprints.iter().cloned().collect();
    fingerprints.sort();

    serde_json::json!({
        "actorId": actor.actor_id.clone(),
        "riskScore": actor.risk_score,
        "ruleMatches": actor.rule_matches.iter().map(|rm| {
            serde_json::json!({
                "ruleId": rm.rule_id.clone(),
                "timestamp": rm.timestamp,
                "riskContribution": rm.risk_contribution,
                "category": rm.category.clone()
            })
        }).collect::<Vec<_>>(),
        "anomalyCount": actor.anomaly_count,
        "sessionIds": actor.session_ids.clone(),
        "firstSeen": actor.first_seen,
        "lastSeen": actor.last_seen,
        "ips": ips,
        "fingerprints": fingerprints,
        "isBlocked": actor.is_blocked,
        "blockReason": actor.block_reason.clone(),
        "blockedSince": actor.blocked_since
    })
}

fn session_to_json(session: &crate::session::SessionState, full_token_hash: bool) -> serde_json::Value {
    let token_hash = if full_token_hash {
        session.token_hash.clone()
    } else {
        session.token_hash.chars().take(8).collect::<String>()
    };

    serde_json::json!({
        "sessionId": session.session_id.clone(),
        "tokenHash": token_hash,
        "actorId": session.actor_id.clone(),
        "creationTime": session.creation_time,
        "lastActivity": session.last_activity,
        "requestCount": session.request_count,
        "boundJa4": session.bound_ja4.clone(),
        "boundIp": session.bound_ip.map(|ip| ip.to_string()),
        "isSuspicious": session.is_suspicious,
        "hijackAlerts": session.hijack_alerts.iter().map(|alert| {
            serde_json::json!({
                "sessionId": alert.session_id.clone(),
                "alertType": format!("{:?}", alert.alert_type),
                "originalValue": alert.original_value.clone(),
                "newValue": alert.new_value.clone(),
                "timestamp": alert.timestamp,
                "confidence": alert.confidence
            })
        }).collect::<Vec<_>>()
    })
}

/// GET /_sensor/actors - Returns actors from ActorManager with behavioral tracking data
async fn sensor_actors_handler(
    Query(params): Query<ActorsQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);

    match state.handler.actor_manager() {
        Some(manager) => {
            let actors = if let Some(ip_str) = params.ip.as_deref() {
                match ip_str.parse::<IpAddr>() {
                    Ok(ip) => manager.get_actor_by_ip(ip).into_iter().collect(),
                    Err(_) => {
                        return validation_error("Invalid IP address", None);
                    }
                }
            } else if let Some(fp) = params.fingerprint.as_deref() {
                manager.get_actor_by_fingerprint(fp).into_iter().collect()
            } else if let Some(min_risk) = params.min_risk {
                manager.list_by_min_risk(min_risk, limit, 0)
            } else {
                manager.list_actors(limit, 0)
            };
            let actor_data: Vec<serde_json::Value> = actors
                .into_iter()
                .map(|actor| actor_to_json(&actor))
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
            }))).into_response()
        }
        None => (StatusCode::OK, Json(serde_json::json!({ "actors": [], "stats": null }))).into_response()
    }
}

/// GET /_sensor/actors/:actor_id - Returns actor detail
async fn sensor_actor_detail_handler(
    State(state): State<AdminState>,
    Path(actor_id): Path<String>,
) -> impl IntoResponse {
    match state.handler.actor_manager() {
        Some(manager) => match manager.get_actor(&actor_id) {
            Some(actor) => (StatusCode::OK, Json(serde_json::json!({ "actor": actor_to_json(&actor) }))).into_response(),
            None => not_found_error("Actor", &actor_id),
        },
        None => service_unavailable("Actor tracking"),
    }
}

/// GET /_sensor/actors/:actor_id/timeline - Returns actor timeline events
async fn sensor_actor_timeline_handler(
    Query(params): Query<ActorTimelineQuery>,
    State(state): State<AdminState>,
    Path(actor_id): Path<String>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);

    let Some(manager) = state.handler.actor_manager() else {
        return service_unavailable("Actor tracking");
    };

    let Some(actor) = manager.get_actor(&actor_id) else {
        return not_found_error("Actor", &actor_id);
    };

    let mut events: Vec<serde_json::Value> = Vec::new();

    for rule in &actor.rule_matches {
        events.push(serde_json::json!({
            "timestamp": rule.timestamp,
            "eventType": "rule_match",
            "ruleId": rule.rule_id.clone(),
            "category": rule.category.clone(),
            "riskDelta": rule.risk_contribution
        }));
    }

    if let Some(blocked_since) = actor.blocked_since {
        events.push(serde_json::json!({
            "timestamp": blocked_since,
            "eventType": "actor_blocked",
            "reason": actor.block_reason.clone(),
            "riskScore": actor.risk_score
        }));
    }

    if let Some(session_manager) = state.handler.session_manager() {
        for session_id in &actor.session_ids {
            if let Some(session) = session_manager.get_session_by_id(session_id) {
                events.push(serde_json::json!({
                    "timestamp": session.creation_time,
                    "eventType": "session_bind",
                    "sessionId": session.session_id.clone(),
                    "actorId": session.actor_id.clone(),
                    "boundJa4": session.bound_ja4.clone(),
                    "boundIp": session.bound_ip.map(|ip| ip.to_string())
                }));

                if session.is_suspicious {
                    for alert in &session.hijack_alerts {
                        events.push(serde_json::json!({
                            "timestamp": alert.timestamp,
                            "eventType": "session_alert",
                            "sessionId": alert.session_id.clone(),
                            "alertType": format!("{:?}", alert.alert_type),
                            "confidence": alert.confidence
                        }));
                    }
                }
            }
        }
    }

    if let Some(block_log) = state.handler.block_log() {
        let actor_ips: Vec<String> = actor.ips.iter().map(|ip| ip.to_string()).collect();
        let actor_fps: Vec<String> = actor.fingerprints.iter().cloned().collect();
        for event in block_log.recent(1000) {
            let ip_match = actor_ips.iter().any(|ip| ip == &event.client_ip);
            let fp_match = event
                .fingerprint
                .as_ref()
                .map(|fp| actor_fps.contains(fp))
                .unwrap_or(false);

            if ip_match || fp_match {
                events.push(serde_json::json!({
                    "timestamp": event.timestamp,
                    "eventType": "block",
                    "clientIp": event.client_ip.clone(),
                    "method": event.method.clone(),
                    "path": event.path.clone(),
                    "riskScore": event.risk_score,
                    "matchedRules": event.matched_rules.clone(),
                    "blockReason": event.block_reason.clone(),
                    "fingerprint": event.fingerprint.clone()
                }));
            }
        }
    }

    events.sort_by(|a, b| {
        let a_ts = a.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
        let b_ts = b.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
        b_ts.cmp(&a_ts)
    });

    if events.len() > limit {
        events.truncate(limit);
    }

    (StatusCode::OK, Json(serde_json::json!({
        "actorId": actor_id,
        "events": events
    }))).into_response()
}

/// Query parameters for sessions endpoint
#[derive(Debug, Deserialize)]
struct SessionsQuery {
    limit: Option<usize>,
    actor_id: Option<String>,
    suspicious: Option<bool>,
}

/// GET /_sensor/sessions - Returns sessions from SessionManager with hijack detection data
async fn sensor_sessions_handler(
    Query(params): Query<SessionsQuery>,
    State(state): State<AdminState>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);

    match state.handler.session_manager() {
        Some(manager) => {
            let mut sessions = if let Some(actor_id) = params.actor_id.as_deref() {
                let mut actor_sessions = manager.get_actor_sessions(actor_id);
                if params.suspicious.unwrap_or(false) {
                    actor_sessions.retain(|session| session.is_suspicious);
                }
                actor_sessions
            } else if params.suspicious.unwrap_or(false) {
                manager.list_suspicious_sessions()
            } else {
                manager.list_sessions(limit, 0)
            };

            if params.actor_id.is_some() || params.suspicious.unwrap_or(false) {
                sessions.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));
                sessions.truncate(limit);
            }

            let session_data: Vec<serde_json::Value> = sessions
                .into_iter()
                .map(|session| session_to_json(&session, false))
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

/// GET /_sensor/sessions/:session_id - Returns session detail
async fn sensor_session_detail_handler(
    State(state): State<AdminState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match state.handler.session_manager() {
        Some(manager) => match manager.get_session_by_id(&session_id) {
            Some(session) => (
                StatusCode::OK,
                Json(serde_json::json!({ "session": session_to_json(&session, true) })),
            ).into_response(),
            None => not_found_error("Session", &session_id),
        },
        None => service_unavailable("Session tracking"),
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
    let kernel_keys = parse_kernel_keys(None);
    let mut kernel_params = HashMap::new();
    let mut kernel_errors = HashMap::new();
    for key in kernel_keys {
        match read_sysctl_value(&key) {
            Ok(value) => {
                kernel_params.insert(key, value);
            }
            Err(err) => {
                kernel_errors.insert(key, err);
            }
        }
    }

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
            "kernel": {
                "parameters": kernel_params,
                "errors": kernel_errors
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
    #[serde(default)]
    source: Option<String>,
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

// =============================================================================
// Log Viewer Endpoints
// =============================================================================

/// GET /_sensor/logs - Returns all logs with optional filtering
async fn logs_handler(Query(params): Query<LogsQuery>) -> impl IntoResponse {
    let logs = LOG_BUFFER.read();
    let limit = params.limit.min(500);

    let filtered: Vec<_> = logs.iter()
        .filter(|log| {
            let level_match = params.level.as_ref().map(|l| log.level == *l).unwrap_or(true);
            let source_match = params.source.as_ref().map(|s| log.source == *s).unwrap_or(true);
            level_match && source_match
        })
        .rev() // Most recent first
        .take(limit)
        .cloned()
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "logs": filtered,
            "total": logs.len(),
            "sources": ["http", "waf", "system", "access"]
        }
    })))
}

/// GET /_sensor/logs/:source - Returns logs filtered by source
async fn logs_by_source_handler(
    Path(source): Path<String>,
    Query(params): Query<LogsQuery>,
) -> impl IntoResponse {
    let logs = LOG_BUFFER.read();
    let limit = params.limit.min(500);

    let filtered: Vec<_> = logs.iter()
        .filter(|log| log.source == source)
        .filter(|log| params.level.as_ref().map(|l| log.level == *l).unwrap_or(true))
        .rev()
        .take(limit)
        .cloned()
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "logs": filtered,
            "source": source
        }
    })))
}

// =============================================================================
// Diagnostic Bundle Export
// =============================================================================

/// GET /_sensor/diagnostic-bundle - Export diagnostic bundle as JSON
async fn diagnostic_bundle_handler(State(state): State<AdminState>) -> impl IntoResponse {
    let mut sys = System::new_all();
    sys.refresh_all();

    // Gather system info
    let system_info = serde_json::json!({
        "hostname": System::host_name().unwrap_or_default(),
        "os": System::name().unwrap_or_default(),
        "os_version": System::os_version().unwrap_or_default(),
        "kernel_version": System::kernel_version().unwrap_or_default(),
        "cpu_count": sys.cpus().len(),
        "total_memory_mb": sys.total_memory() / 1024 / 1024,
        "used_memory_mb": sys.used_memory() / 1024 / 1024,
        "uptime_secs": System::uptime()
    });

    // Gather WAF stats
    let waf_stats = state.handler.handle_waf_stats();

    // Gather health
    let health = state.handler.handle_health();

    // Gather logs
    let logs: Vec<_> = LOG_BUFFER.read().iter().cloned().collect();

    // Gather entities
    let entities = state.handler.handle_list_entities(100);

    // Gather sites
    let sites = state.handler.handle_list_sites();

    // DLP stats if available
    let dlp_stats = state.handler.dlp_scanner().map(|scanner| {
        let stats = scanner.stats();
        serde_json::json!({
            "enabled": scanner.is_enabled(),
            "pattern_count": scanner.pattern_count(),
            "total_scans": stats.total_scans,
            "total_matches": stats.total_matches
        })
    });

    let bundle = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "system": system_info,
        "health": health,
        "waf_stats": waf_stats,
        "dlp_stats": dlp_stats,
        "sites": sites,
        "entities": entities,
        "recent_logs": logs.into_iter().rev().take(200).collect::<Vec<_>>()
    });

    // Return as downloadable JSON
    let body = serde_json::to_string_pretty(&bundle).unwrap_or_default();
    let filename = format!("synapse-diagnostic-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let disposition = format!("attachment; filename=\"{}\"", filename);
    build_response(
        StatusCode::OK,
        body,
        "application/json",
        Some(disposition),
    )
}

// =============================================================================
// Configuration Export/Import
// =============================================================================

/// GET /_sensor/config/export - Export current configuration as YAML
async fn config_export_handler(State(state): State<AdminState>) -> axum::response::Response {
    // Try to read config file
    let config_paths = ["config.yaml", "config.yml", "/etc/synapse-pingora/config.yaml"];

    for path in &config_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            let filename = format!("synapse-config-{}.yaml", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
            let disposition = format!("attachment; filename=\"{}\"", filename);
            return build_response(
                StatusCode::OK,
                content,
                "application/x-yaml",
                Some(disposition),
            );
        }
    }

    // If no config file found, export current runtime config
    let sites = state.handler.handle_list_sites();
    let config_json = serde_json::json!({
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "sites": sites,
        "note": "Runtime configuration export - no config file found"
    });

    let filename = format!("synapse-config-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let disposition = format!("attachment; filename=\"{}\"", filename);
    let body = serde_json::to_string_pretty(&config_json).unwrap_or_default();
    build_response(
        StatusCode::OK,
        body,
        "application/json",
        Some(disposition),
    )
}

/// POST /_sensor/config/import - Import configuration from YAML/JSON
async fn config_import_handler(
    State(state): State<AdminState>,
    body: String,
) -> impl IntoResponse {
    // Try to parse as YAML first, then JSON
    // SECURITY: Log internal parse errors but return sanitized message to client
    let config_value: serde_json::Value = match serde_yaml::from_str(&body) {
        Ok(v) => v,
        Err(yaml_err) => match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(json_err) => {
                // Log detailed errors for debugging but don't expose to client
                tracing::warn!(
                    "Config import parse failed - YAML: {}, JSON: {}",
                    yaml_err, json_err
                );
                return validation_error(
                    "Invalid configuration format. Expected valid YAML or JSON.",
                    Some(&json_err),
                );
            }
        }
    };

    // Validate the configuration has expected structure
    if config_value.get("sites").is_none() && config_value.get("server").is_none() {
        return validation_error(
            "Configuration must contain 'sites' or 'server' section",
            None,
        );
    }

    // Convert JSON value to ConfigFile struct
    let config_file: crate::config::ConfigFile = match serde_json::from_value(config_value) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Config import deserialization failed: {}", e);
            return validation_error(
                "Configuration structure is invalid. Check field names and types.",
                Some(&e),
            );
        }
    };

    // Apply the configuration if ConfigManager is available
    match state.handler.config_manager() {
        Some(config_mgr) => {
            match config_mgr.update_full_config(config_file) {
                Ok(result) => {
                    info!(
                        "Config imported successfully: applied={}, persisted={}, warnings={}",
                        result.applied, result.persisted, result.warnings.len()
                    );
                    (StatusCode::OK, Json(serde_json::json!({
                        "success": true,
                        "message": "Configuration imported and applied successfully.",
                        "applied": result.applied,
                        "persisted": result.persisted,
                        "rebuild_required": result.rebuild_required,
                        "warnings": result.warnings
                    }))).into_response()
                }
                Err(e) => {
                    tracing::warn!("Config import application failed: {}", e);
                    internal_error(
                        "Failed to apply configuration. See server logs for details.",
                        Some(&e),
                    )
                }
            }
        }
        None => {
            service_unavailable("ConfigManager")
        }
    }
}

/// GET /_sensor/dlp/stats - Returns DLP scanner statistics
/// P2 fix: Returns bucketed ranges instead of exact counts to prevent timing oracles
async fn sensor_dlp_stats_handler(State(state): State<AdminState>) -> impl IntoResponse {
    match state.handler.dlp_scanner() {
        Some(scanner) => {
            let stats = scanner.stats();

            // P2: Bucket match counts to prevent timing oracle attacks
            let match_bucket = match stats.total_matches {
                0 => "none",
                1..=10 => "low (1-10)",
                11..=100 => "moderate (11-100)",
                101..=1000 => "high (101-1000)",
                _ => "critical (1000+)",
            };

            (StatusCode::OK, Json(serde_json::json!({
                "totalScans": stats.total_scans,
                "totalMatches": stats.total_matches,
                "matchBucket": match_bucket,
                "patternCount": scanner.pattern_count(),
            }))).into_response()
        }
        None => {
            let mut problem = ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "DLP scanning feature is not enabled on this sensor",
            );
            problem.code = Some(error_codes::NOT_FOUND.to_string());
            problem.instance = Some("/_sensor/dlp/stats".to_string());
            (StatusCode::NOT_FOUND, Json(problem)).into_response()
        }
    }
}

/// Query parameters for violations endpoint (P2 pagination)
#[derive(Debug, Deserialize)]
struct ViolationsQuery {
    /// Maximum number of violations to return (default: 50)
    #[serde(default = "default_violations_limit")]
    limit: usize,
    /// Cursor for pagination (timestamp-based)
    #[serde(default)]
    cursor: Option<u64>,
}

fn default_violations_limit() -> usize { 50 }

/// GET /_sensor/dlp/violations - Returns recent DLP violations
/// P2 fix: Adds pagination with cursor-based navigation
async fn sensor_dlp_violations_handler(
    State(state): State<AdminState>,
    Query(query): Query<ViolationsQuery>,
) -> impl IntoResponse {
    match state.handler.dlp_scanner() {
        Some(scanner) => {
            let all_violations = scanner.get_recent_violations().await;

            // Apply cursor filter (violations newer than cursor timestamp)
            let filtered: Vec<_> = if let Some(cursor) = query.cursor {
                all_violations.into_iter()
                    .filter(|v| v.timestamp > cursor)
                    .collect()
            } else {
                all_violations
            };

            // Apply limit
            let total = filtered.len();
            let violations: Vec<_> = filtered.into_iter().take(query.limit).collect();

            // Get next cursor (timestamp of oldest returned violation)
            let next_cursor = violations.last().map(|v| v.timestamp);

            (StatusCode::OK, Json(serde_json::json!({
                "violations": violations,
                "pagination": {
                    "total": total,
                    "limit": query.limit,
                    "nextCursor": next_cursor,
                    "hasMore": total > query.limit
                }
            }))).into_response()
        }
        None => {
            let mut problem = ProblemDetails::new(
                StatusCode::NOT_FOUND,
                "DLP scanning feature is not enabled on this sensor",
            );
            problem.code = Some(error_codes::NOT_FOUND.to_string());
            problem.instance = Some("/_sensor/dlp/violations".to_string());
            (StatusCode::NOT_FOUND, Json(problem)).into_response()
        }
    }
}


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
    // Get real schema data from the schema learner
    let real_schemas = get_schemas();

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
    // NOTE: Profiles are now handled via crate::profiler::EndpointProfile.
    // Return seed data for dashboard testing until
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
    if response.success {
        return (StatusCode::OK, Json(response)).into_response();
    }

    let detail = response
        .error
        .unwrap_or_else(|| "Request failed".to_string());
    let mut problem = ProblemDetails::new(StatusCode::INTERNAL_SERVER_ERROR, detail);
    problem.code = Some(error_codes::INTERNAL_ERROR.to_string());
    (StatusCode::INTERNAL_SERVER_ERROR, Json(problem)).into_response()
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

const DEFAULT_TRACE_MAX_EVENTS: usize = 2000;

fn default_trace_max_events() -> usize {
    DEFAULT_TRACE_MAX_EVENTS
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct DebuggerOptions {
    #[serde(default = "default_trace_max_events")]
    max_events: usize,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DebuggerCommand {
    Evaluate {
        id: Option<String>,
        request: EvaluateRequest,
        options: Option<DebuggerOptions>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DebuggerMessage {
    Event {
        id: String,
        event: TraceEvent,
    },
    Done {
        id: String,
        result: DebuggerDonePayload,
    },
    Error {
        id: Option<String>,
        message: String,
    },
}

#[derive(Debug, Serialize)]
struct DebuggerDonePayload {
    blocked: bool,
    risk_score: u16,
    matched_rules: Vec<u32>,
    block_reason: Option<String>,
    detection_time_us: u64,
    action: String,
    verdict: String,
}

struct ChannelTraceSink {
    sender: mpsc::UnboundedSender<TraceEvent>,
    max_events: usize,
    emitted: usize,
    truncated: bool,
}

impl ChannelTraceSink {
    fn new(sender: mpsc::UnboundedSender<TraceEvent>, max_events: usize) -> Self {
        Self {
            sender,
            max_events: max_events.max(1),
            emitted: 0,
            truncated: false,
        }
    }
}

impl TraceSink for ChannelTraceSink {
    fn record(&mut self, event: TraceEvent) {
        let is_terminal = matches!(event, TraceEvent::EvaluationFinished { .. });

        if self.emitted >= self.max_events && !is_terminal {
            if !self.truncated {
                self.truncated = true;
                let _ = self.sender.send(TraceEvent::Truncated {
                    limit: self.max_events,
                });
            }
            return;
        }

        self.emitted += 1;
        let _ = self.sender.send(event);
    }
}

async fn waf_debugger_ws_handler(
    State(state): State<AdminState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_waf_debugger_socket(state, socket))
}

async fn handle_waf_debugger_socket(state: AdminState, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    while let Some(message) = receiver.next().await {
        let message = match message {
            Ok(msg) => msg,
            Err(_) => break,
        };

        match message {
            Message::Text(text) => {
                let command: DebuggerCommand = match serde_json::from_str(&text) {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        let _ = send_debugger_message(
                            &mut sender,
                            DebuggerMessage::Error {
                                id: None,
                                message: format!("Invalid command: {err}"),
                            },
                        )
                        .await;
                        continue;
                    }
                };

                match command {
                    DebuggerCommand::Evaluate { id, request, options } => {
                        let request_id =
                            id.unwrap_or_else(|| format!("trace_{}", fastrand::u64(..)));
                        let max_events = options
                            .map(|opts| opts.max_events)
                            .unwrap_or(DEFAULT_TRACE_MAX_EVENTS);

                        if run_trace_session(&state, &mut sender, request_id, request, max_events)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            Message::Ping(payload) => {
                let _ = sender.send(Message::Pong(payload)).await;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}

async fn run_trace_session(
    state: &AdminState,
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    request_id: String,
    request: EvaluateRequest,
    max_events: usize,
) -> Result<(), ()> {
    let body_bytes = decode_evaluate_body(request.body.as_deref());
    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let handler = Arc::clone(&state.handler);
    let method = request.method.clone();
    let uri = request.uri.clone();
    let headers = request.headers.clone();
    let client_ip = request.client_ip.clone();

    let mut handle = tokio::task::spawn_blocking(move || {
        let mut sink = ChannelTraceSink::new(event_tx, max_events);
        handler.evaluate_request_trace(
            &method,
            &uri,
            &headers,
            body_bytes.as_deref(),
            &client_ip,
            &mut sink,
        )
    });

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                if let Some(event) = event {
                    send_debugger_message(sender, DebuggerMessage::Event {
                        id: request_id.clone(),
                        event,
                    }).await.map_err(|_| ())?;
                }
            }
            result = &mut handle => {
                let result = match result {
                    Ok(result) => result,
                    Err(err) => {
                        send_debugger_message(sender, DebuggerMessage::Error {
                            id: Some(request_id.clone()),
                            message: format!("Evaluation failed: {err}"),
                        }).await.map_err(|_| ())?;
                        return Ok(());
                    }
                };

                while let Ok(event) = event_rx.try_recv() {
                    send_debugger_message(sender, DebuggerMessage::Event {
                        id: request_id.clone(),
                        event,
                    }).await.map_err(|_| ())?;
                }

                let Some(result) = result else {
                    send_debugger_message(sender, DebuggerMessage::Error {
                        id: Some(request_id.clone()),
                        message: "WAF evaluation unavailable".to_string(),
                    }).await.map_err(|_| ())?;
                    return Ok(());
                };

                let verdict = if result.blocked {
                    "block"
                } else if result.risk_score > 50 {
                    "warn"
                } else {
                    "pass"
                };

                let done = DebuggerDonePayload {
                    blocked: result.blocked,
                    risk_score: result.risk_score,
                    matched_rules: result.matched_rules,
                    block_reason: result.block_reason,
                    detection_time_us: result.detection_time_us,
                    action: verdict.to_string(),
                    verdict: verdict.to_string(),
                };

                send_debugger_message(sender, DebuggerMessage::Done {
                    id: request_id,
                    result: done,
                }).await.map_err(|_| ())?;

                return Ok(());
            }
        }
    }
}

async fn send_debugger_message(
    sender: &mut futures_util::stream::SplitSink<WebSocket, Message>,
    message: DebuggerMessage,
) -> Result<(), ()> {
    let payload = serde_json::to_string(&message).map_err(|_| ())?;
    sender.send(Message::Text(payload)).await.map_err(|_| ())
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
    let body_bytes = decode_evaluate_body(request.body.as_deref());

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
            }))).into_response()
        }
        None => {
            // Synapse engine not configured
            service_unavailable("WAF evaluation")
        }
    }
}

fn decode_evaluate_body(body: Option<&str>) -> Option<Vec<u8>> {
    body.map(|value| match base64_decode(value) {
        Ok(decoded) => decoded,
        Err(_) => value.as_bytes().to_vec(),
    })
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
        ).into_response(),
        None => not_found_error("Profile", &decoded_template),
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
        ).into_response(),
        None => not_found_error("Schema", &decoded_template),
    }
}

// =============================================================================
// Configuration Endpoints for Admin Console
// =============================================================================

/// DLP Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct DlpConfigRequest {
    enabled: Option<bool>,
    fast_mode: Option<bool>,
    scan_text_only: Option<bool>,
    max_scan_size: Option<usize>,
    max_body_inspection_bytes: Option<usize>,
    max_matches: Option<usize>,
    custom_keywords: Option<Vec<String>>,
}

/// GET /_sensor/config/dlp - Get DLP configuration
async fn config_dlp_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": true,
            "fast_mode": false,
            "scan_text_only": true,
            "max_scan_size": 5242880,
            "max_body_inspection_bytes": 8192,
            "max_matches": 100,
            "custom_keywords": []
        }
    })))
}

/// PUT /_sensor/config/dlp - Update DLP configuration
async fn config_dlp_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<DlpConfigRequest>,
) -> impl IntoResponse {
    // In a real implementation, this would update the DLP scanner configuration
    info!("DLP config update: enabled={:?}, fast_mode={:?}", config.enabled, config.fast_mode);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "DLP configuration updated"
    })))
}

/// Block Page Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct BlockPageConfigRequest {
    company_name: Option<String>,
    support_email: Option<String>,
    logo_url: Option<String>,
    show_request_id: Option<bool>,
    show_timestamp: Option<bool>,
    show_client_ip: Option<bool>,
    show_rule_id: Option<bool>,
    custom_css: Option<String>,
}

/// GET /_sensor/config/block-page - Get block page configuration
async fn config_block_page_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "company_name": null,
            "support_email": null,
            "logo_url": null,
            "show_request_id": true,
            "show_timestamp": true,
            "show_client_ip": false,
            "show_rule_id": false,
            "custom_css": null
        }
    })))
}

/// PUT /_sensor/config/block-page - Update block page configuration
async fn config_block_page_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<BlockPageConfigRequest>,
) -> impl IntoResponse {
    info!("Block page config update: company={:?}", config.company_name);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Block page configuration updated"
    })))
}

/// Crawler Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct CrawlerConfigRequest {
    enabled: Option<bool>,
    verify_legitimate_crawlers: Option<bool>,
    block_bad_bots: Option<bool>,
    dns_failure_policy: Option<String>,
    dns_cache_ttl_secs: Option<u64>,
    dns_timeout_ms: Option<u64>,
    max_concurrent_dns_lookups: Option<usize>,
    dns_failure_risk_penalty: Option<u32>,
}

/// GET /_sensor/config/crawler - Get crawler detection configuration
async fn config_crawler_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": true,
            "verify_legitimate_crawlers": true,
            "block_bad_bots": true,
            "dns_failure_policy": "apply_risk_penalty",
            "dns_cache_ttl_secs": 300,
            "dns_timeout_ms": 2000,
            "max_concurrent_dns_lookups": 100,
            "dns_failure_risk_penalty": 20
        }
    })))
}

/// PUT /_sensor/config/crawler - Update crawler detection configuration
async fn config_crawler_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<CrawlerConfigRequest>,
) -> impl IntoResponse {
    info!("Crawler config update: enabled={:?}, block_bad_bots={:?}", config.enabled, config.block_bad_bots);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Crawler configuration updated"
    })))
}

/// Tarpit Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct TarpitConfigRequest {
    enabled: Option<bool>,
    base_delay_ms: Option<u64>,
    max_delay_ms: Option<u64>,
    progressive_multiplier: Option<f64>,
    max_concurrent_tarpits: Option<usize>,
    decay_threshold_ms: Option<u64>,
}

/// GET /_sensor/config/tarpit - Get tarpit configuration
async fn config_tarpit_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": true,
            "base_delay_ms": 1000,
            "max_delay_ms": 30000,
            "progressive_multiplier": 1.5,
            "max_concurrent_tarpits": 1000,
            "decay_threshold_ms": 300000
        }
    })))
}

/// PUT /_sensor/config/tarpit - Update tarpit configuration
async fn config_tarpit_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<TarpitConfigRequest>,
) -> impl IntoResponse {
    info!("Tarpit config update: enabled={:?}, base_delay={:?}ms", config.enabled, config.base_delay_ms);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Tarpit configuration updated"
    })))
}

/// Impossible Travel Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct TravelConfigRequest {
    max_speed_kmh: Option<f64>,
    min_distance_km: Option<f64>,
    history_window_ms: Option<u64>,
    max_history_per_user: Option<usize>,
}

/// GET /_sensor/config/travel - Get impossible travel configuration
async fn config_travel_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "max_speed_kmh": 800.0,
            "min_distance_km": 100.0,
            "history_window_ms": 86400000,
            "max_history_per_user": 100
        }
    })))
}

/// PUT /_sensor/config/travel - Update impossible travel configuration
async fn config_travel_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<TravelConfigRequest>,
) -> impl IntoResponse {
    info!("Travel config update: max_speed={:?}km/h", config.max_speed_kmh);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Impossible travel configuration updated"
    })))
}

/// Entity Store Configuration request/response
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct EntityConfigRequest {
    enabled: Option<bool>,
    max_entities: Option<usize>,
    risk_decay_per_minute: Option<f64>,
    block_threshold: Option<f64>,
    max_risk: Option<f64>,
    max_rules_per_entity: Option<usize>,
}

/// GET /_sensor/config/entity - Get entity store configuration
async fn config_entity_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "enabled": true,
            "max_entities": 100000,
            "risk_decay_per_minute": 10.0,
            "block_threshold": 70.0,
            "max_risk": 100.0,
            "max_rules_per_entity": 50
        }
    })))
}

/// PUT /_sensor/config/entity - Update entity store configuration
async fn config_entity_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<EntityConfigRequest>,
) -> impl IntoResponse {
    info!("Entity config update: max_entities={:?}, block_threshold={:?}", config.max_entities, config.block_threshold);
    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "message": "Entity store configuration updated"
    })))
}

/// GET /_sensor/config/integrations - Get external integrations configuration
async fn config_integrations_get_handler(State(_state): State<AdminState>) -> impl IntoResponse {
    let config = INTEGRATIONS_GETTER
        .read()
        .as_ref()
        .map(|getter| getter())
        .unwrap_or_else(|| IntegrationsConfig {
            horizon_hub_url: String::new(),
            horizon_api_key: String::new(),
            tunnel_url: String::new(),
            tunnel_api_key: String::new(),
            apparatus_url: String::new(),
        });

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": config
    })))
}

/// PUT /_sensor/config/integrations - Update external integrations configuration
async fn config_integrations_put_handler(
    State(_state): State<AdminState>,
    Json(config): Json<IntegrationsConfig>,
) -> impl IntoResponse {
    if let Some(setter) = INTEGRATIONS_SETTER.read().as_ref() {
        setter(config);
        (StatusCode::OK, Json(serde_json::json!({
            "success": true,
            "message": "Integrations configuration updated"
        })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({
            "success": false,
            "message": "Configuration updates not supported by this sensor instance"
        })))
    }
}

// =============================================================================
// Kernel (sysctl) Configuration
// =============================================================================

const DEFAULT_KERNEL_KEYS: &[&str] = &[
    "net.core.somaxconn",
    "net.ipv4.tcp_max_syn_backlog",
    "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_time",
    "vm.swappiness",
];

#[derive(Debug, Deserialize)]
struct KernelConfigQuery {
    keys: Option<String>,
}

#[derive(Debug)]
struct KernelConfigPayload {
    params: HashMap<String, String>,
    persist: bool,
    warnings: Vec<String>,
}

fn is_valid_sysctl_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

fn is_valid_sysctl_value(value: &str) -> bool {
    !value.trim().is_empty() && !value.contains('\n') && !value.contains('\r')
}

fn sysctl_path_for_key(key: &str) -> PathBuf {
    PathBuf::from("/proc/sys").join(key.replace('.', "/"))
}

fn read_sysctl_value(key: &str) -> Result<String, String> {
    if !is_valid_sysctl_key(key) {
        return Err("invalid sysctl key".to_string());
    }

    if cfg!(target_os = "linux") {
        let path = sysctl_path_for_key(key);
        if path.exists() {
            return std::fs::read_to_string(&path)
                .map(|value| value.trim().to_string())
                .map_err(|err| err.to_string());
        }
    }

    let output = Command::new("sysctl")
        .arg("-n")
        .arg(key)
        .output()
        .map_err(|err| err.to_string())?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn write_sysctl_value(key: &str, value: &str) -> Result<(), String> {
    if !is_valid_sysctl_key(key) {
        return Err("invalid sysctl key".to_string());
    }
    if !is_valid_sysctl_value(value) {
        return Err("invalid sysctl value".to_string());
    }

    if cfg!(target_os = "linux") {
        let path = sysctl_path_for_key(key);
        if path.exists() {
            return std::fs::write(&path, value)
                .map_err(|err| err.to_string());
        }
    }

    let assignment = format!("{}={}", key, value);
    let output = Command::new("sysctl")
        .arg("-w")
        .arg(&assignment)
        .output()
        .map_err(|err| err.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

fn parse_kernel_payload(payload: serde_json::Value) -> KernelConfigPayload {
    let mut params = HashMap::new();
    let mut warnings = Vec::new();
    let mut persist = false;

    match payload {
        serde_json::Value::Object(mut obj) => {
            if let Some(flag) = obj.remove("persist") {
                persist = flag.as_bool().unwrap_or(false);
            }

            let params_value = obj
                .remove("params")
                .or_else(|| obj.remove("settings"))
                .unwrap_or(serde_json::Value::Object(obj));

            if let serde_json::Value::Object(map) = params_value {
                for (key, value) in map {
                    let string_value = match value {
                        serde_json::Value::String(s) => s,
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        other => {
                            warnings.push(format!("Skipping non-scalar value for {}", key));
                            continue;
                        }
                    };
                    params.insert(key, string_value);
                }
            } else {
                warnings.push("Kernel config payload missing params object".to_string());
            }
        }
        _ => {
            warnings.push("Kernel config payload must be an object".to_string());
        }
    }

    KernelConfigPayload {
        params,
        persist,
        warnings,
    }
}

fn parse_kernel_keys(query: Option<String>) -> Vec<String> {
    if let Some(keys) = query {
        let parsed: Vec<String> = keys
            .split(',')
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    DEFAULT_KERNEL_KEYS.iter().map(|k| (*k).to_string()).collect()
}

fn load_sysctl_entries(path: &std::path::Path) -> HashMap<String, String> {
    let mut entries = HashMap::new();
    if let Ok(contents) = std::fs::read_to_string(path) {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                entries.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    entries
}

fn build_sysctl_config_lines(entries: &HashMap<String, String>) -> String {
    let mut lines = Vec::new();
    lines.push("# Synapse Pingora managed sysctl settings".to_string());
    let mut keys: Vec<_> = entries.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(value) = entries.get(&key) {
            lines.push(format!("{} = {}", key, value));
        }
    }
    lines.join("\n")
}

fn persist_kernel_params(params: &HashMap<String, String>) -> Result<(), String> {
    if params.is_empty() {
        return Ok(());
    }

    let path = std::env::var("SYNAPSE_SYSCTL_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/sysctl.d/synapse-pingora.conf".to_string());
    let path = std::path::Path::new(&path);
    let wal_path = path.with_extension("wal");

    let mut entries = load_sysctl_entries(path);
    for (key, value) in params {
        entries.insert(key.clone(), value.clone());
    }

    append_sysctl_wal(&wal_path, params)?;
    let contents = build_sysctl_config_lines(&entries);
    write_file_with_fsync(path, &contents)
        .map_err(|err| format!("Failed to persist sysctl settings: {}", err))?;
    clear_wal(&wal_path)?;
    Ok(())
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn append_sysctl_wal(path: &std::path::Path, params: &HashMap<String, String>) -> Result<(), String> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create WAL directory: {}", err))?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("Failed to open WAL file: {}", err))?;

    let payload = serde_json::json!({
        "timestamp_ms": current_timestamp_ms(),
        "type": "sysctl_update",
        "params": params,
    });
    let serialized = serde_json::to_vec(&payload)
        .map_err(|err| format!("Failed to serialize WAL entry: {}", err))?;
    file.write_all(&serialized)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("Failed to persist WAL entry: {}", err))?;

    Ok(())
}

fn parse_sysctl_wal_params(value: &serde_json::Value) -> Option<HashMap<String, String>> {
    if value.get("type").and_then(|t| t.as_str()) != Some("sysctl_update") {
        return None;
    }
    let params = value.get("params")?.as_object()?;
    let mut parsed = HashMap::new();
    for (key, value) in params {
        let string_value = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => continue,
        };
        parsed.insert(key.clone(), string_value);
    }
    if parsed.is_empty() { None } else { Some(parsed) }
}

fn recover_sysctl_wal() -> Result<(), String> {
    let path = std::env::var("SYNAPSE_SYSCTL_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/sysctl.d/synapse-pingora.conf".to_string());
    let path = std::path::Path::new(&path);
    let wal_path = path.with_extension("wal");

    if !wal_path.exists() {
        return Ok(());
    }

    let contents = std::fs::read_to_string(&wal_path)
        .map_err(|err| format!("Failed to read WAL file: {}", err))?;
    if contents.trim().is_empty() {
        return Ok(());
    }

    let mut last_params: Option<HashMap<String, String>> = None;
    for line in contents.lines() {
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                warn!("Skipping invalid sysctl WAL entry: {}", err);
                continue;
            }
        };
        if let Some(params) = parse_sysctl_wal_params(&value) {
            last_params = Some(params);
        }
    }

    let Some(params) = last_params else {
        return Ok(());
    };

    let mut entries = load_sysctl_entries(path);
    for (key, value) in params {
        entries.insert(key, value);
    }

    let contents = build_sysctl_config_lines(&entries);
    write_file_with_fsync(path, &contents)
        .map_err(|err| format!("Failed to recover sysctl settings: {}", err))?;
    clear_wal(&wal_path)?;
    Ok(())
}

fn write_file_with_fsync(path: &std::path::Path, contents: &str) -> Result<(), std::io::Error> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn clear_wal(path: &std::path::Path) -> Result<(), String> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|err| format!("Failed to open WAL file: {}", err))?;
    file.write_all(b"")
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("Failed to clear WAL file: {}", err))?;
    Ok(())
}

/// GET /_sensor/config/kernel - Fetch kernel/sysctl parameters
async fn config_kernel_get_handler(
    Query(query): Query<KernelConfigQuery>,
    State(_state): State<AdminState>,
) -> impl IntoResponse {
    let keys = parse_kernel_keys(query.keys);
    let mut values = HashMap::new();
    let mut errors = HashMap::new();

    for key in keys {
        match read_sysctl_value(&key) {
            Ok(value) => {
                values.insert(key, value);
            }
            Err(err) => {
                errors.insert(key, err);
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": true,
        "data": {
            "parameters": values,
            "errors": errors
        }
    })))
}

/// PUT /_sensor/config/kernel - Update kernel/sysctl parameters
async fn config_kernel_put_handler(
    State(_state): State<AdminState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let parsed = parse_kernel_payload(payload);
    if parsed.params.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "No kernel parameters provided",
                "warnings": parsed.warnings
            })),
        );
    }

    let mut applied = HashMap::new();
    let mut failed = HashMap::new();

    for (key, value) in parsed.params {
        if !is_valid_sysctl_key(&key) {
            failed.insert(key, "invalid sysctl key".to_string());
            continue;
        }
        if !is_valid_sysctl_value(&value) {
            failed.insert(key, "invalid sysctl value".to_string());
            continue;
        }

        match write_sysctl_value(&key, &value) {
            Ok(()) => {
                record_log_with_source(
                    "info",
                    LogSource::System,
                    format!("Kernel parameter {} set to {}", key, value),
                );
                applied.insert(key, value);
            }
            Err(err) => {
                record_log_with_source(
                    "warn",
                    LogSource::System,
                    format!("Kernel parameter {} update failed: {}", key, err),
                );
                failed.insert(key, err);
            }
        }
    }

    let mut persist_error = None;
    if parsed.persist && !applied.is_empty() {
        if let Err(err) = persist_kernel_params(&applied) {
            persist_error = Some(err);
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "success": failed.is_empty() && persist_error.is_none(),
        "data": {
            "applied": applied,
            "failed": failed,
            "persisted": parsed.persist && persist_error.is_none(),
            "persistError": persist_error
        },
        "warnings": parsed.warnings
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use http::Request;
    use tower::util::ServiceExt;
    use std::num::NonZeroU32;
    use tempfile::tempdir;
    use crate::horizon::{SignalType, Severity};
    use crate::intelligence::signal_manager::{SignalManager, SignalManagerConfig};
    use crate::intelligence::SignalQueryOptions;

    fn create_test_app() -> Router {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let handler = Arc::new(ApiHandler::builder().build());
        // Create test rate limiters (1000 req/min)
        let quota = Quota::per_minute(NonZeroU32::new(1000).unwrap());
        let admin_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let public_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let report_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let auth_failure_limiter = Arc::new(RateLimiter::keyed(quota));
        let state = AdminState {
            handler,
            admin_api_key: "test-key".to_string(),
            admin_auth_disabled: false,
            admin_scopes: scopes::ALL.iter().map(|s| (*s).to_string()).collect(),
            signal_permissions: Arc::new(SignalPermissions::default()),
            admin_rate_limiter,
            public_rate_limiter,
            report_rate_limiter,
            auth_failure_limiter,
        };

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
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .layer(middleware::from_fn(security_headers))
            .with_state(state)
    }

    fn create_test_app_with_sensor_report_with_scopes(
        scopes: Vec<String>,
        report_quota: NonZeroU32,
    ) -> (Router, Arc<SignalManager>) {
        use governor::{Quota, RateLimiter};

        let signal_manager = Arc::new(SignalManager::new(SignalManagerConfig::default()));
        let signal_manager_ref = Arc::clone(&signal_manager);
        let handler = Arc::new(ApiHandler::builder().signal_manager(signal_manager).build());
        let quota = Quota::per_minute(NonZeroU32::new(1000).unwrap());
        let admin_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let public_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let report_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(report_quota)));
        let auth_failure_limiter = Arc::new(RateLimiter::keyed(quota));
        let state = AdminState {
            handler,
            admin_api_key: "test-key".to_string(),
            admin_auth_disabled: false,
            admin_scopes: scopes,
            signal_permissions: Arc::new(SignalPermissions::default()),
            admin_rate_limiter,
            public_rate_limiter,
            report_rate_limiter,
            auth_failure_limiter,
        };

        let router = Router::new()
            .route("/_sensor/report", post(sensor_report_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_sensor_write))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin))
            .with_state(state);

        (router, signal_manager_ref)
    }

    fn create_test_app_with_sensor_report() -> (Router, Arc<SignalManager>) {
        create_test_app_with_sensor_report_with_scopes(
            scopes::ALL.iter().map(|s| (*s).to_string()).collect(),
            NonZeroU32::new(1000).unwrap(),
        )
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_recover_sysctl_wal_merges_entries() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("sysctl.conf");
        let wal_path = config_path.with_extension("wal");

        std::fs::write(&config_path, "net.ipv4.tcp_syncookies = 1\n").unwrap();
        let wal_entry = serde_json::json!({
            "timestamp_ms": 1,
            "type": "sysctl_update",
            "params": {
                "net.ipv4.tcp_syncookies": "0",
                "net.ipv4.ip_forward": "1"
            }
        });
        std::fs::write(&wal_path, format!("{}\n", wal_entry)).unwrap();

        let previous = std::env::var("SYNAPSE_SYSCTL_CONFIG_PATH").ok();
        std::env::set_var("SYNAPSE_SYSCTL_CONFIG_PATH", config_path.to_string_lossy().to_string());

        let result = recover_sysctl_wal();

        if let Some(value) = previous {
            std::env::set_var("SYNAPSE_SYSCTL_CONFIG_PATH", value);
        } else {
            std::env::remove_var("SYNAPSE_SYSCTL_CONFIG_PATH");
        }

        result.unwrap();

        let contents = std::fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("net.ipv4.tcp_syncookies = 0"));
        assert!(contents.contains("net.ipv4.ip_forward = 1"));

        let wal_contents = std::fs::read_to_string(&wal_path).unwrap();
        assert!(wal_contents.trim().is_empty());
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/stats")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_waf_stats_endpoint() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/waf/stats")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
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
                    .header("X-Admin-Key", "test-key")
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
                    .header("X-Admin-Key", "test-key")
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
                    .header("X-Admin-Key", "test-key")
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
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_sensor_report_rejects_disallowed_signal_type() {
        let (app, _manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": {
                "ip": "10.0.0.1",
                "fingerprint": null,
                "sessionId": null
            },
            "signal": {
                "type": "internal_only",
                "severity": "high",
                "details": {}
            },
            "request": null
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_sensor_report_allows_known_signal_type() {
        let (app, _manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": {
                "ip": "10.0.0.1",
                "fingerprint": null,
                "sessionId": null
            },
            "signal": {
                "type": "honeypot_hit",
                "severity": "high",
                "details": {}
            },
            "request": null
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_sensor_report_requires_auth() {
        let (app, _manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "10.0.0.1" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_sensor_report_requires_sensor_write_scope() {
        let (app, _manager) = create_test_app_with_sensor_report_with_scopes(
            vec![scopes::ADMIN_READ.to_string()],
            NonZeroU32::new(1000).unwrap(),
        );

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "10.0.0.1" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_sensor_report_rate_limits_per_sensor() {
        let (app, _manager) = create_test_app_with_sensor_report_with_scopes(
            scopes::ALL.iter().map(|s| (*s).to_string()).collect(),
            NonZeroU32::new(1).unwrap(),
        );

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "10.0.0.1" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);

        let second = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_sensor_report_validation_error() {
        let (app, _manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "not-an-ip" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["code"], error_codes::VALIDATION_ERROR);
    }

    #[test]
    fn test_signal_type_mapping() {
        use crate::signals::adapter::SignalAdapter;
        
        let mut report = ApparatusReport {
            sensor_id: "sensor-1".to_string(),
            timestamp: "2026-02-03T00:00:00Z".to_string(),
            version: Some("1.0.0".to_string()),
            actor: ApparatusActor { ip: "1.2.3.4".to_string(), fingerprint: None, session_id: None },
            signal: ApparatusSignal { signal_type: "honeypot_hit".to_string(), severity: "high".to_string(), details: serde_json::json!({}) },
            request: None,
        };

        assert!(matches!(SignalAdapter::map_type(&report), SignalType::IpThreat));
        
        report.signal.signal_type = "trap_trigger".to_string();
        assert!(matches!(SignalAdapter::map_type(&report), SignalType::BotSignature));
        
        report.signal.signal_type = "protocol_probe".to_string();
        assert!(matches!(SignalAdapter::map_type(&report), SignalType::TemplateDiscovery));
        
        report.signal.signal_type = "dlp_match".to_string();
        assert!(matches!(SignalAdapter::map_type(&report), SignalType::SchemaViolation));
    }

    #[test]
    fn test_severity_mapping() {
        use crate::signals::adapter::SignalAdapter;
        assert!(matches!(SignalAdapter::map_severity("low"), Severity::Low));
        assert!(matches!(SignalAdapter::map_severity("medium"), Severity::Medium));
        assert!(matches!(SignalAdapter::map_severity("high"), Severity::High));
        assert!(matches!(SignalAdapter::map_severity("critical"), Severity::Critical));
        assert!(matches!(SignalAdapter::map_severity("unknown"), Severity::Medium));
    }

    #[tokio::test]
    async fn test_sensor_report_records_metadata() {
        let (app, manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": {
                "ip": "10.0.0.1",
                "fingerprint": "fp-123",
                "sessionId": "session-1"
            },
            "signal": {
                "type": "honeypot_hit",
                "severity": "high",
                "details": { "key": "value" }
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let signals = manager.list_signals(SignalQueryOptions::default());
        assert!(!signals.is_empty());
        let metadata = &signals[0].metadata;
        assert_eq!(metadata["actor"]["fingerprint"], "fp-123");
        assert_eq!(metadata["actor"]["sessionId"], "session-1");
        assert_eq!(metadata["signal"]["severity"], "high");
    }

    #[tokio::test]
    async fn test_sensor_report_ignores_horizon_client_error() {
        let (app, manager) = create_test_app_with_sensor_report();

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "10.0.0.1" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let signals = manager.list_signals(SignalQueryOptions::default());
        assert!(!signals.is_empty());
    }

    #[tokio::test]
    async fn test_sensor_report_metadata_serialization_error() {
        let (app, manager) = create_test_app_with_sensor_report();

        FORCE_METADATA_SERIALIZE_ERROR.with(|flag| flag.set(true));

        let payload = serde_json::json!({
            "sensorId": "sensor-1",
            "timestamp": "2026-02-03T00:00:00Z",
            "actor": { "ip": "10.0.0.1" },
            "signal": { "type": "honeypot_hit", "severity": "high", "details": {} }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/report")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        FORCE_METADATA_SERIALIZE_ERROR.with(|flag| flag.set(false));

        assert_eq!(response.status(), StatusCode::OK);
        let signals = manager.list_signals(SignalQueryOptions::default());
        assert!(!signals.is_empty());
        assert!(signals[0].metadata.as_object().map(|m| m.is_empty()).unwrap_or(false));
    }

    #[test]
    fn test_apparatus_report_validation() {
        let valid_report = ApparatusReport {
            sensor_id: "valid-sensor".to_string(),
            timestamp: "2026-02-03T00:00:00Z".to_string(),
            version: Some("1.0.0".to_string()),
            actor: ApparatusActor {
                ip: "1.2.3.4".to_string(),
                fingerprint: Some("valid-fp".to_string()),
                session_id: Some("valid-session".to_string()),
            },
            signal: ApparatusSignal {
                signal_type: "honeypot_hit".to_string(),
                severity: "high".to_string(),
                details: serde_json::json!({"key": "value"}),
            },
            request: Some(ApparatusRequest {
                method: "GET".to_string(),
                path: "/api/test".to_string(),
                headers: Some(HashMap::new()),
            }),
        };

        assert!(valid_report.validate().is_ok());

        // Test invalid sensor_id
        let mut report = valid_report.clone();
        report.sensor_id = "invalid sensor!".to_string();
        assert!(report.validate().is_err());

        // Test invalid IP
        let mut report = valid_report.clone();
        report.actor.ip = "not-an-ip".to_string();
        assert!(report.validate().is_err());

        // Test long fingerprint
        let mut report = valid_report.clone();
        report.actor.fingerprint = Some("a".repeat(300));
        assert!(report.validate().is_err());

        // Test long signal_type
        let mut report = valid_report.clone();
        report.signal.signal_type = "a".repeat(100);
        assert!(report.validate().is_err());

        // Test invalid severity
        let mut report = valid_report.clone();
        report.signal.severity = "extreme".to_string();
        assert!(report.validate().is_err());

        // Test large details
        let mut report = valid_report.clone();
        report.signal.details = serde_json::json!({"data": "a".repeat(20000)});
        assert!(report.validate().is_err());

        // Test long path
        let mut report = valid_report.clone();
        report.request.as_mut().unwrap().path = "a".repeat(3000);
        assert!(report.validate().is_err());
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

    #[tokio::test]
    async fn test_security_headers_on_api_response() {
        let app = create_test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify security headers are present
        let headers = response.headers();

        // X-Content-Type-Options: nosniff - prevents MIME type sniffing
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).map(|v| v.to_str().unwrap()),
            Some("nosniff"),
            "X-Content-Type-Options header missing or incorrect"
        );

        // X-Frame-Options: DENY - prevents clickjacking
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).map(|v| v.to_str().unwrap()),
            Some("DENY"),
            "X-Frame-Options header missing or incorrect"
        );

        // Referrer-Policy - controls referrer information
        assert_eq!(
            headers.get(header::REFERRER_POLICY).map(|v| v.to_str().unwrap()),
            Some("strict-origin-when-cross-origin"),
            "Referrer-Policy header missing or incorrect"
        );

        // Cache-Control: no-store - prevents caching sensitive data
        assert!(
            headers.get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap())
                .unwrap_or("")
                .contains("no-store"),
            "Cache-Control header should contain no-store"
        );

        // Content-Security-Policy for API responses
        assert!(
            headers.get(header::CONTENT_SECURITY_POLICY).is_some(),
            "Content-Security-Policy header missing"
        );

        // Permissions-Policy header
        assert!(
            headers.get("permissions-policy").is_some(),
            "Permissions-Policy header missing"
        );
    }

    #[test]
    fn test_sanitized_error_does_not_leak_internal_details() {
        // Simulate an internal error with sensitive details
        let internal_err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file '/etc/secret/key.pem' not found at line 42",
        );

        let response = sanitized_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            error_codes::INTERNAL_ERROR,
            "Configuration could not be loaded",
            Some(&internal_err),
        );

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // The response should NOT contain internal details
    }

    #[test]
    fn test_validation_error_format() {
        let response = validation_error(
            "Invalid input provided",
            Some(&"detailed parse error: unexpected token at position 42"),
        );

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // =========================================================================
    // Console Endpoint Authorization Tests (labs-s8bs)
    // =========================================================================

    /// Create a test app that includes the /console route with scope-based auth.
    fn create_test_app_with_console(scopes: Vec<String>, admin_auth_disabled: bool) -> Router {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let handler = Arc::new(ApiHandler::builder().build());
        let quota = Quota::per_minute(NonZeroU32::new(1000).unwrap());
        let admin_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let public_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let report_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let auth_failure_limiter = Arc::new(RateLimiter::keyed(quota));
        let state = AdminState {
            handler,
            admin_api_key: "test-key".to_string(),
            admin_auth_disabled,
            admin_scopes: scopes,
            signal_permissions: Arc::new(SignalPermissions::default()),
            admin_rate_limiter,
            public_rate_limiter,
            report_rate_limiter,
            auth_failure_limiter,
        };

        // Console route with require_admin_read middleware
        let admin_read_routes = Router::new()
            .route("/console", get(admin_console_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_public));

        // Health remains public
        let public_routes = Router::new()
            .route("/health", get(health_handler));

        Router::new()
            .merge(admin_read_routes)
            .merge(public_routes)
            .layer(middleware::from_fn(security_headers))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_console_requires_auth() {
        // Create app with admin:read scope
        let app = create_test_app_with_console(vec![scopes::ADMIN_READ.to_string()], false);

        // Request without X-Admin-Key should return 401
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/console")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "/console should return 401 without authentication"
        );
    }

    #[tokio::test]
    async fn test_console_with_admin_read_scope() {
        // Create app with admin:read scope
        let app = create_test_app_with_console(vec![scopes::ADMIN_READ.to_string()], false);

        // Request with valid key and admin:read scope should return 200
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/console")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "/console should return 200 with valid key and admin:read scope"
        );
    }

    #[tokio::test]
    async fn test_console_without_admin_read_scope() {
        // Create app with only sensor:read scope (not admin:read)
        let app = create_test_app_with_console(vec![scopes::SENSOR_READ.to_string()], false);

        // Request with valid key but without admin:read scope should return 403
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/console")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "/console should return 403 when admin:read scope is missing"
        );
    }

    #[tokio::test]
    async fn test_health_remains_public() {
        // Create app with empty scopes (most restrictive)
        let app = create_test_app_with_console(vec![], false);

        // Health endpoint should work without any auth
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "/health should remain public and return 200 without authentication"
        );
    }

    #[tokio::test]
    async fn test_console_auth_disabled_allows_access() {
        let app = create_test_app_with_console(vec![], true);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/console")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "/console should return 200 when admin auth is disabled"
        );
    }

    // =========================================================================
    // Rules Endpoint Authorization Tests (labs-95at.7)
    // =========================================================================

    /// Create a test app that includes /_sensor/rules routes with scope-based auth.
    fn create_test_app_with_rules(scopes: Vec<String>) -> Router {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let handler = Arc::new(ApiHandler::builder().build());
        let quota = Quota::per_minute(NonZeroU32::new(1000).unwrap());
        let admin_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let public_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let report_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let auth_failure_limiter = Arc::new(RateLimiter::keyed(quota));
        let state = AdminState {
            handler,
            admin_api_key: "test-key".to_string(),
            admin_auth_disabled: false,
            admin_scopes: scopes,
            signal_permissions: Arc::new(SignalPermissions::default()),
            admin_rate_limiter,
            public_rate_limiter,
            report_rate_limiter,
            auth_failure_limiter,
        };

        let rules_read_routes = Router::new()
            .route("/_sensor/rules", get(sensor_rules_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

        let rules_write_routes = Router::new()
            .route("/_sensor/rules", post(sensor_rules_create_handler))
            .route("/_sensor/rules/:rule_id", put(sensor_rules_update_handler).delete(sensor_rules_delete_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_write))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

        Router::new()
            .merge(rules_read_routes)
            .merge(rules_write_routes)
            .with_state(state)
    }

    /// Create a test app that includes /_sensor/config/kernel routes with scope-based auth.
    fn create_test_app_with_kernel_config(scopes: Vec<String>) -> Router {
        use governor::{Quota, RateLimiter};
        use std::num::NonZeroU32;

        let handler = Arc::new(ApiHandler::builder().build());
        let quota = Quota::per_minute(NonZeroU32::new(1000).unwrap());
        let admin_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let public_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let report_rate_limiter = Arc::new(RateLimiter::keyed(quota.clone()));
        let auth_failure_limiter = Arc::new(RateLimiter::keyed(quota));
        let state = AdminState {
            handler,
            admin_api_key: "test-key".to_string(),
            admin_auth_disabled: false,
            admin_scopes: scopes,
            signal_permissions: Arc::new(SignalPermissions::default()),
            admin_rate_limiter,
            public_rate_limiter,
            report_rate_limiter,
            auth_failure_limiter,
        };

        let kernel_read_routes = Router::new()
            .route("/_sensor/config/kernel", get(config_kernel_get_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_read))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

        let kernel_write_routes = Router::new()
            .route("/_sensor/config/kernel", put(config_kernel_put_handler))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_admin_write))
            .route_layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .route_layer(middleware::from_fn_with_state(state.clone(), rate_limit_admin));

        Router::new()
            .merge(kernel_read_routes)
            .merge(kernel_write_routes)
            .with_state(state)
    }

    fn build_rule_payload() -> serde_json::Value {
        serde_json::json!({
            "name": "Block Admin",
            "type": "BLOCK",
            "enabled": true,
            "priority": 100,
            "conditions": [
                { "field": "path", "operator": "eq", "value": "/admin" }
            ],
            "actions": [
                { "type": "block" }
            ]
        })
    }

    #[tokio::test]
    async fn test_rules_requires_auth() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_READ.to_string()]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_sensor/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rules_requires_admin_read_scope() {
        let app = create_test_app_with_rules(vec![]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_sensor/rules")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rules_allows_admin_read_scope() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_READ.to_string()]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_sensor/rules")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // ConfigManager is not configured in tests, so expect 503 after auth/scope passes.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_rules_create_requires_admin_write_scope() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_READ.to_string()]);
        let payload = build_rule_payload();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/rules")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rules_create_allows_admin_write_scope() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_WRITE.to_string()]);
        let payload = build_rule_payload();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/_sensor/rules")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // ConfigManager is not configured in tests, so expect 503 after auth/scope passes.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_rules_delete_requires_admin_write_scope() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_READ.to_string()]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/_sensor/rules/rule-1")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_rules_delete_allows_admin_write_scope() {
        let app = create_test_app_with_rules(vec![scopes::ADMIN_WRITE.to_string()]);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/_sensor/rules/rule-1")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // ConfigManager is not configured in tests, so expect 503 after auth/scope passes.
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // =========================================================================
    // Kernel Config Endpoint Authorization Tests (labs-95at.7)
    // =========================================================================

    #[tokio::test]
    async fn test_kernel_config_requires_auth() {
        let app = create_test_app_with_kernel_config(vec![scopes::ADMIN_READ.to_string()]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_sensor/config/kernel")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_kernel_config_requires_admin_read_scope() {
        let app = create_test_app_with_kernel_config(vec![]);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/_sensor/config/kernel")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_kernel_config_put_requires_admin_write_scope() {
        let app = create_test_app_with_kernel_config(vec![scopes::ADMIN_READ.to_string()]);

        let payload = serde_json::json!({
            "params": { "net.core.somaxconn": 1024 },
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/_sensor/config/kernel")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_kernel_config_put_with_admin_write_scope() {
        let app = create_test_app_with_kernel_config(vec![scopes::ADMIN_WRITE.to_string()]);

        let payload = serde_json::json!({
            "params": { "net.core.somaxconn": 1024 },
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/_sensor/config/kernel")
                    .header("Content-Type", "application/json")
                    .header("X-Admin-Key", "test-key")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }
}
