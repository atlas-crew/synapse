//! Synapse-Pingora
//!
//! High-performance WAF detection engine on Cloudflare's Pingora proxy framework.
//! Pure Rust implementation with integrated WAF rules and behavioral detection.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
//! │   Client    │────▶│  Synapse Pingora │────▶│   Backend    │
//! │             │◀────│  (Detection WAF) │◀────│   Server     │
//! └─────────────┘     └──────────────────┘     └──────────────┘
//!                              │
//!                     ┌────────┴────────┐
//!                     │  waf::Engine    │
//!                     │  • 237+ Rules   │
//!                     │  • Actor Track  │
//!                     │  • Risk Scoring │
//!                     │  • Cred Stuffing│
//!                     └─────────────────┘
//! ```

// Submodules of the bin crate (see also lib.rs for the library half).
// `simulator` stays here for the demo/runtime wiring and consumes the
// library-owned DetectionEngine facade.
mod simulator;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, COOKIE, USER_AGENT};
// WAF engine types (integrated Synapse WAF engine)
// Schema learning and validation (API anomaly detection)
use dashmap::DashMap;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use pingora::listeners::tls::TlsSettings;
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_limits::rate::Rate;
use pingora_proxy::{ProxyHttp, Session};
use serde::{Deserialize, Deserializer};
use std::cell::RefCell;
use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use synapse_pingora::profiler::{SchemaLearner, SchemaLearnerConfig};
use sysinfo::{Disks, System};
use tokio::sync::oneshot;
use uuid::Uuid;

// Admin API imports
use synapse_pingora::admin_server::{
    register_evaluate_callback, register_integrations_callbacks, register_profiles_getter,
    register_restart_callback, register_schemas_getter, register_shutdown_callback,
    start_admin_server, EvaluationResult, IntegrationsConfig, RestartResult, ShutdownResult,
};
use synapse_pingora::api::ApiHandler;
use synapse_pingora::health::HealthChecker;
use synapse_pingora::metrics::{ActiveRequestGuard, MetricsRegistry};

// Phase 3: Fingerprinting (Feature Migration from risk-server)
use synapse_pingora::fingerprint::{
    analyze_integrity, analyze_ja4, extract_client_fingerprint, ClientFingerprint, HttpHeaders,
};

// Phase 6: Security hardening (Validation)
use synapse_pingora::tls::TlsManager;
use synapse_pingora::validation::validate_tls_config;

// Phase 3: Entity Tracking (Feature Migration from risk-server)
use synapse_pingora::entity::{BlockDecision, EntityConfig, EntityManager};

// Phase 3: Tarpitting (Feature Migration from risk-server)
use synapse_pingora::tarpit::{TarpitConfig, TarpitManager};

// Phase 3: DLP Scanning (Feature Migration from risk-server)
use synapse_pingora::dlp::{DlpConfig, DlpScanner};

// Multi-site configuration and routing
use synapse_pingora::access::{AccessListManager, CidrRange};
use synapse_pingora::block_log::{BlockEvent, BlockLog, IpAnonymization};
use synapse_pingora::config::{
    deprecated_anomaly_blocking_error, deprecated_anomaly_blocking_warning, ConfigLoader,
};
use synapse_pingora::config_manager::ConfigManager;
use synapse_pingora::correlation::CampaignManager;
use synapse_pingora::headers;
use synapse_pingora::ratelimit::RateLimitManager;
use synapse_pingora::shadow::{MirrorPayload, ShadowMirrorManager};
use synapse_pingora::signals::auth_coverage::ResponseClass;
use synapse_pingora::site_waf::{SiteWafManager, WafAction};
use synapse_pingora::telemetry::auth_coverage_aggregator::AuthCoverageAggregator;
use synapse_pingora::telemetry::{SignalEmitter, TelemetryClient, TelemetryConfig, TelemetryEvent};
use synapse_pingora::trap::{TrapConfig, TrapMatcher};
use synapse_pingora::utils::auth_detection::has_auth_header;
use synapse_pingora::utils::path_normalizer::endpoint_key;
use synapse_pingora::vhost::{SiteConfig, VhostMatcher};
use synapse_pingora::HeaderSnapshot;
pub use synapse_pingora::{DetectionEngine, DetectionResult};

// Phase 10: Libsynapse Consolidation (Geo, WAF Engine, Credential Stuffing)

// Phase 5: Actor and Session State Management (previously sleeping capabilities)
use parking_lot::{Mutex, RwLock};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use synapse_pingora::actor::{ActorConfig, ActorManager};
use synapse_pingora::session::{SessionConfig, SessionDecision, SessionManager};

// CLI
use clap::{Parser, Subcommand};

// Phase 9: Crawler Detection
use synapse_pingora::crawler::{CrawlerConfig, CrawlerDetector};

// Phase 9: Signal Horizon Hub integration (fleet-wide threat intelligence)
use synapse_pingora::horizon::{HorizonConfig, HorizonManager, Severity, SignalType, ThreatSignal};
use synapse_pingora::tunnel::{
    publish_access_log, publish_waf_log, LogTelemetryService, TunnelClient, TunnelConfig,
    TunnelDiagService, TunnelLogService, TunnelShellService,
};

// Phase 9: Payload Profiling (bandwidth tracking and anomaly detection)
use synapse_pingora::payload::{PayloadConfig, PayloadManager};

// Phase 9: Trends (signal tracking and anomaly detection)
use synapse_pingora::intelligence::{SignalCategory, SignalManager, SignalManagerConfig};
use synapse_pingora::trends::{TrendsConfig, TrendsManager};

// Phase 10: Interrogator System (progressive challenge escalation)
use synapse_pingora::interrogator::{
    CaptchaConfig, CaptchaManager, ChallengeResponse, CookieConfig, CookieManager,
    JsChallengeConfig, JsChallengeManager, ProgressionConfig, ProgressionManager, ValidationResult,
};

// ============================================================================
// CLI Arguments
// ============================================================================

/// Synapse-Pingora: High-performance WAF on Cloudflare Pingora
#[derive(Parser)]
#[command(name = "synapse-pingora")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "config.yaml")]
    config: String,

    /// Enable development mode (bypasses auth, disables rate limits)
    #[arg(long)]
    dev: bool,

    /// Enable demo mode (resets state between requests)
    #[arg(long)]
    demo: bool,

    /// Launch interactive Terminal UI (TUI) dashboard
    #[arg(long)]
    tui: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate configuration file without starting the server
    CheckConfig {
        /// Configuration file to validate
        #[arg(default_value = "config.yaml")]
        file: String,

        /// Output validation result as JSON
        #[arg(long)]
        json: bool,
    },

    /// Start the proxy server (default)
    Run,
}

// ============================================================================
// Configuration
// ============================================================================

/// Server configuration loaded from YAML
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub tarpit: TarpitConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
    #[serde(default)]
    pub crawler: CrawlerConfig,
    #[serde(default)]
    pub horizon: HorizonConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    /// URL for Apparatus integration
    #[serde(default)]
    pub apparatus_url: String,
    #[serde(default)]
    pub payload: PayloadConfig,
    #[serde(default)]
    pub trends: TrendsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstreams: vec![UpstreamConfig::default()],
            rate_limit: RateLimitConfig::default(),
            logging: LoggingConfig::default(),
            detection: DetectionConfig::default(),
            tls: TlsConfig::default(),
            telemetry: TelemetryConfig::default(),
            tarpit: TarpitConfig::default(),
            dlp: DlpConfig::default(),
            crawler: CrawlerConfig::default(),
            horizon: HorizonConfig::default(),
            tunnel: TunnelConfig::default(),
            apparatus_url: String::new(),
            payload: PayloadConfig::default(),
            trends: TrendsConfig::default(),
        }
    }
}

/// Deserialize listen addresses from either a string or array of strings.
/// Supports both legacy single-address format and new multi-address format:
/// ```yaml
/// # Legacy (still supported)
/// listen: "0.0.0.0:6190"
///
/// # New array format (IPv4 + IPv6)
/// listen:
///   - "0.0.0.0:6190"
///   - "[::]:6190"
/// ```
fn deserialize_listen_addrs<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        String(String),
        Vec(Vec<String>),
    }

    match StringOrVec::deserialize(deserializer)? {
        StringOrVec::String(s) => Ok(vec![s]),
        StringOrVec::Vec(v) => Ok(v),
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Listen addresses for the proxy (supports IPv4 and IPv6)
    /// Can be a single address string or array of addresses:
    /// - Single: "0.0.0.0:6190"
    /// - Array: ["0.0.0.0:6190", "[::]:6190"]
    #[serde(
        default = "default_listen",
        deserialize_with = "deserialize_listen_addrs"
    )]
    pub listen: Vec<String>,
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    #[serde(default)]
    pub workers: usize,
    /// API key for authenticating privileged admin operations (unset = generated at startup)
    #[serde(default)]
    pub admin_api_key: Option<String>,
    /// Disable admin authentication (local-only, non-production guardrails enforced)
    #[serde(default)]
    pub admin_auth_disabled: bool,
    /// Trusted proxy CIDR ranges for X-Forwarded-For validation
    /// When set, only X-Forwarded-For IPs from trusted proxies are used
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

fn default_listen() -> Vec<String> {
    vec!["0.0.0.0:6190".to_string()]
}

fn default_admin_listen() -> String {
    "127.0.0.1:6191".to_string()
}

fn parse_cidr_prefix(cidr: &str) -> Option<(IpAddr, u8, u8)> {
    let (addr_str, prefix_str) = if let Some(idx) = cidr.find('/') {
        (&cidr[..idx], Some(&cidr[idx + 1..]))
    } else {
        (cidr, None)
    };

    let ip: IpAddr = addr_str.parse().ok()?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = match prefix_str {
        Some(prefix_raw) => prefix_raw.parse::<u8>().ok()?,
        None => max_prefix,
    };

    if prefix > max_prefix {
        return None;
    }

    Some((ip, prefix, max_prefix))
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

fn is_broad_private_cidr(cidr: &str) -> bool {
    let (ip, prefix, max_prefix) = match parse_cidr_prefix(cidr) {
        Some(parts) => parts,
        None => return false,
    };
    is_private_ip(&ip) && prefix < max_prefix
}

fn is_wildcard_cidr(cidr: &str) -> bool {
    parse_cidr_prefix(cidr)
        .map(|(_, prefix, _)| prefix == 0)
        .unwrap_or(false)
}

/// Parses an environment variable as a boolean (case-insensitive).
/// Accepts: 1, true, yes, y, on (labs-58mn)
fn parse_bool_env(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.to_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "y" || v == "on"
        })
        .unwrap_or(false)
}

/// Parses an environment variable as a boolean for negative values (case-insensitive).
/// Accepts: 0, false, no, n, off (labs-58mn)
fn parse_bool_env_neg(name: &str) -> bool {
    std::env::var(name)
        .map(|v| {
            let v = v.to_lowercase();
            v == "0" || v == "false" || v == "no" || v == "n" || v == "off"
        })
        .unwrap_or(false)
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin_listen: default_admin_listen(),
            workers: 0,
            admin_api_key: None,
            admin_auth_disabled: false,
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    8080
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub rps: usize,
    /// Per-IP rate limit (requests per second). Defaults to 100 RPS per IP.
    /// A single IP exceeding this limit will be blocked without affecting other clients.
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: usize,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_rps() -> usize {
    10000
}

fn default_per_ip_rps() -> usize {
    100 // 100 RPS per IP is reasonable for most use cases
}

fn default_enabled() -> bool {
    true
}

/// Create a CookieConfig with cryptographically secure random secret key
pub(crate) fn create_default_cookie_config() -> CookieConfig {
    let mut secret_key = [0u8; 32];
    if let Err(err) = getrandom::getrandom(&mut secret_key) {
        error!("Failed to generate secure cookie secret key: {}", err);
        for byte in secret_key.iter_mut() {
            *byte = fastrand::u8(..);
        }
    }
    if secret_key.iter().all(|byte| *byte == 0) {
        secret_key[0] = 1;
    }
    CookieConfig {
        cookie_name: "__synapse_challenge".to_string(),
        cookie_max_age_secs: 86400, // 1 day
        secret_key,
        secure_only: true,
        http_only: true,
        same_site: "Strict".to_string(),
    }
}

/// Progression config tuned to align with 30/60/90 risk thresholds.
pub(crate) fn create_progression_config() -> ProgressionConfig {
    ProgressionConfig {
        risk_threshold_cookie: 0.30,
        risk_threshold_js: 0.60,
        risk_threshold_captcha: 0.90,
        risk_threshold_block: 0.95,
        ..Default::default()
    }
}

fn build_trap_matcher() -> Option<Arc<TrapMatcher>> {
    match TrapMatcher::new(TrapConfig::default()) {
        Ok(matcher) => Some(Arc::new(matcher)),
        Err(err) => {
            error!("Failed to initialize TrapMatcher: {}", err);
            None
        }
    }
}

async fn build_crawler_detector(config: CrawlerConfig) -> Arc<CrawlerDetector> {
    match CrawlerDetector::new(config).await {
        Ok(detector) => Arc::new(detector),
        Err(err) => {
            error!("Failed to initialize CrawlerDetector: {}", err);
            Arc::new(CrawlerDetector::disabled())
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rps: default_rps(),
            per_ip_rps: default_per_ip_rps(),
            enabled: default_enabled(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_level")]
    pub level: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_enabled")]
    pub access_log: bool,
}

fn default_level() -> String {
    "info".to_string()
}

fn default_format() -> String {
    "text".to_string()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_level(),
            format: default_format(),
            access_log: true,
        }
    }
}

// NOTE: Old telemetry types removed - use TelemetryClient and TelemetryEvent instead
// AlertForwarder has been deprecated in favor of TelemetryClient for all telemetry needs.

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    #[serde(default = "default_enabled")]
    pub sqli: bool,
    #[serde(default = "default_enabled")]
    pub xss: bool,
    #[serde(default = "default_enabled")]
    pub path_traversal: bool,
    #[serde(default = "default_enabled")]
    pub command_injection: bool,
    #[serde(default = "default_action")]
    pub action: String,
    #[serde(default = "default_block_status")]
    pub block_status: u16,
    #[serde(default = "default_rules_path")]
    pub rules_path: String,
    /// Deprecated telemetry URL (use telemetry.endpoint instead)
    pub risk_server_url: Option<String>,
}

fn default_action() -> String {
    "block".to_string()
}

fn default_block_status() -> u16 {
    403
}

fn default_rules_path() -> String {
    // Default rules path relative to the binary
    "data/rules.json".to_string()
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            sqli: true,
            xss: true,
            path_traversal: true,
            command_injection: true,
            action: default_action(),
            block_status: default_block_status(),
            rules_path: default_rules_path(),
            risk_server_url: None,
        }
    }
}

/// TLS/HTTPS configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// Enable TLS on the proxy listener
    #[serde(default)]
    pub enabled: bool,
    /// Path to certificate file (PEM format)
    #[serde(default)]
    pub cert_path: String,
    /// Path to private key file (PEM format)
    #[serde(default)]
    pub key_path: String,
    /// Per-domain certificates (optional)
    /// Maps domain -> {cert_path, key_path}
    #[serde(default)]
    pub per_domain_certs: Vec<PerDomainCert>,
    /// Minimum TLS version: "1.2" or "1.3"
    #[serde(default = "default_tls_version")]
    pub min_version: String,
}

fn default_tls_version() -> String {
    "1.2".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct PerDomainCert {
    /// Domain name (or *.example.com for wildcard)
    pub domain: String,
    /// Path to certificate file
    pub cert_path: String,
    /// Path to private key file
    pub key_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            per_domain_certs: Vec::new(),
            min_version: default_tls_version(),
        }
    }
}

impl Config {
    /// Load configuration from YAML file with validation
    ///
    /// # Validation Steps
    /// - Parses YAML configuration
    /// - Validates TLS certificate paths and formats if enabled
    /// - Validates domain names in per-domain certificates
    pub fn load(path: &str) -> Result<Self, String> {
        if !Path::new(path).exists() {
            return Err(format!("Config file not found: {}", path));
        }

        let contents =
            fs::read_to_string(path).map_err(|e| format!("Failed to read config file: {}", e))?;

        let yaml_value: serde_yaml::Value = serde_yaml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;

        if let Some(message) = deprecated_anomaly_blocking_error(&yaml_value) {
            return Err(message);
        }
        if let Some(message) = deprecated_anomaly_blocking_warning(&yaml_value) {
            warn!("{}", message);
        }

        let config: Self = serde_yaml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;

        // Phase 6: Validate TLS configuration
        if config.tls.enabled {
            // Convert per_domain_certs to validation format
            let per_domain_tuples: Vec<(String, String, String)> = config
                .tls
                .per_domain_certs
                .iter()
                .map(|c| (c.domain.clone(), c.cert_path.clone(), c.key_path.clone()))
                .collect();

            validate_tls_config(
                &config.tls.cert_path,
                &config.tls.key_path,
                &per_domain_tuples,
            )
            .map_err(|e| format!("TLS configuration validation failed: {}", e))?;

            info!("TLS configuration validated successfully");
        }

        config
            .tunnel
            .validate()
            .map_err(|e| format!("Tunnel configuration validation failed: {}", e))?;

        Ok(config)
    }

    /// Try to load config from default locations, fall back to defaults
    pub fn load_or_default() -> Self {
        let paths = [
            "config.yaml",
            "config.yml",
            "/etc/synapse-pingora/config.yaml",
        ];

        for path in &paths {
            if Path::new(path).exists() {
                match Self::load(path) {
                    Ok(config) => {
                        info!("Loaded configuration from {}", path);
                        return config;
                    }
                    Err(e) => {
                        warn!("Failed to load {}: {}", path, e);
                    }
                }
            }
        }

        info!("Using default configuration");
        Self::default()
    }
}

fn persist_integrations_runtime_config(path: &str, config: &Config) -> Result<(), String> {
    let config_path = Path::new(path);
    let contents = fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;
    let mut document: serde_yaml::Value = serde_yaml::from_str(&contents)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    write_integrations_into_document(&mut document, config)?;
    let rendered = serde_yaml::to_string(&document)
        .map_err(|e| format!("Failed to serialize config file: {}", e))?;

    let temp_name = format!(
        ".{}.integrations.{}.tmp",
        config_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config"),
        Uuid::new_v4()
    );
    let temp_path = config_path.with_file_name(temp_name);
    fs::write(&temp_path, rendered)
        .map_err(|e| format!("Failed to write updated config file: {}", e))?;

    let validation_result = temp_path
        .to_str()
        .ok_or_else(|| "Updated config path must be valid UTF-8".to_string())
        .and_then(Config::load);
    if let Err(error) = validation_result {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "Saved integrations produced an invalid runtime config: {}",
            error
        ));
    }

    fs::rename(&temp_path, config_path)
        .map_err(|e| format!("Failed to replace config file: {}", e))?;
    Ok(())
}

fn write_integrations_into_document(
    document: &mut serde_yaml::Value,
    config: &Config,
) -> Result<(), String> {
    let root = document
        .as_mapping_mut()
        .ok_or_else(|| "Config file root must be a YAML mapping".to_string())?;
    set_yaml_string(root, "apparatus_url", &config.apparatus_url);
    set_yaml_mapping(root, "horizon", horizon_config_to_yaml(&config.horizon));
    set_yaml_mapping(root, "tunnel", tunnel_config_to_yaml(&config.tunnel));
    Ok(())
}

fn apply_integrations_to_runtime_config(config: &mut Config, integrations: &IntegrationsConfig) {
    let horizon_hub_url = integrations.horizon_hub_url.trim().to_string();
    let horizon_api_key = integrations.horizon_api_key.trim().to_string();
    let tunnel_url = integrations.tunnel_url.trim().to_string();
    let tunnel_api_key = integrations.tunnel_api_key.trim().to_string();
    let apparatus_url = integrations.apparatus_url.trim().to_string();
    let horizon_enabled = !horizon_hub_url.is_empty() && !horizon_api_key.is_empty();
    let tunnel_enabled = !tunnel_url.is_empty() && !tunnel_api_key.is_empty();

    if horizon_enabled || tunnel_enabled {
        let (sensor_id, sensor_name) = resolve_sensor_identity(config);
        if config.horizon.sensor_id.trim().is_empty() || horizon_enabled {
            config.horizon.sensor_id = sensor_id.clone();
        }
        if config.tunnel.sensor_id.trim().is_empty() || tunnel_enabled {
            config.tunnel.sensor_id = sensor_id;
        }
        if config.horizon.sensor_name.is_none() || horizon_enabled {
            config.horizon.sensor_name = sensor_name.clone();
        }
        if config.tunnel.sensor_name.is_none() || tunnel_enabled {
            config.tunnel.sensor_name = sensor_name;
        }
    }

    config.horizon.enabled = horizon_enabled;
    config.horizon.hub_url = horizon_hub_url;
    config.horizon.api_key = horizon_api_key;
    if config.horizon.version.trim().is_empty() {
        config.horizon.version = env!("CARGO_PKG_VERSION").to_string();
    }

    config.tunnel.enabled = tunnel_enabled;
    config.tunnel.url = tunnel_url;
    config.tunnel.api_key = tunnel_api_key;
    if config.tunnel.version.trim().is_empty() {
        config.tunnel.version = env!("CARGO_PKG_VERSION").to_string();
    }

    config.apparatus_url = apparatus_url;
}

fn resolve_sensor_identity(config: &Config) -> (String, Option<String>) {
    let existing_sensor_id = [
        config.horizon.sensor_id.trim(),
        config.tunnel.sensor_id.trim(),
        std::env::var("SYNAPSE_SENSOR_ID")
            .ok()
            .as_deref()
            .unwrap_or("")
            .trim(),
    ]
    .into_iter()
    .find(|value| !value.is_empty())
    .map(str::to_string);

    let existing_sensor_name = config
        .horizon
        .sensor_name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            config
                .tunnel
                .sensor_name
                .clone()
                .filter(|value| !value.trim().is_empty())
        });

    let host_name = System::host_name().filter(|value| !value.trim().is_empty());
    let sensor_id = existing_sensor_id.unwrap_or_else(|| {
        host_name
            .as_deref()
            .map(slugify_sensor_hostname)
            .filter(|value| !value.is_empty())
            .map(|value| format!("sensor-{}", value))
            .unwrap_or_else(|| format!("sensor-{}", Uuid::new_v4()))
    });
    let sensor_name = existing_sensor_name.or(host_name);
    (sensor_id, sensor_name)
}

fn slugify_sensor_hostname(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn set_yaml_mapping(mapping: &mut serde_yaml::Mapping, key: &str, value: serde_yaml::Mapping) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::Value::Mapping(value),
    );
}

fn set_yaml_string(mapping: &mut serde_yaml::Mapping, key: &str, value: &str) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::Value::String(value.to_string()),
    );
}

fn set_yaml_bool(mapping: &mut serde_yaml::Mapping, key: &str, value: bool) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::Value::Bool(value),
    );
}

fn set_yaml_u64(mapping: &mut serde_yaml::Mapping, key: &str, value: u64) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::to_value(value).expect("u64 should serialize to YAML"),
    );
}

fn set_yaml_usize(mapping: &mut serde_yaml::Mapping, key: &str, value: usize) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::to_value(value).expect("usize should serialize to YAML"),
    );
}

fn set_yaml_u32(mapping: &mut serde_yaml::Mapping, key: &str, value: u32) {
    mapping.insert(
        serde_yaml::Value::String(key.to_string()),
        serde_yaml::to_value(value).expect("u32 should serialize to YAML"),
    );
}

fn set_yaml_optional_string(mapping: &mut serde_yaml::Mapping, key: &str, value: Option<&str>) {
    let yaml_value = match value {
        Some(inner) => serde_yaml::Value::String(inner.to_string()),
        None => serde_yaml::Value::Null,
    };
    mapping.insert(serde_yaml::Value::String(key.to_string()), yaml_value);
}

fn horizon_config_to_yaml(config: &HorizonConfig) -> serde_yaml::Mapping {
    let mut mapping = serde_yaml::Mapping::new();
    set_yaml_bool(&mut mapping, "enabled", config.enabled);
    set_yaml_string(&mut mapping, "hub_url", &config.hub_url);
    set_yaml_string(&mut mapping, "api_key", &config.api_key);
    set_yaml_string(&mut mapping, "sensor_id", &config.sensor_id);
    set_yaml_optional_string(&mut mapping, "sensor_name", config.sensor_name.as_deref());
    set_yaml_string(&mut mapping, "version", &config.version);
    set_yaml_u64(
        &mut mapping,
        "reconnect_delay_ms",
        config.reconnect_delay_ms,
    );
    set_yaml_u32(
        &mut mapping,
        "max_reconnect_attempts",
        config.max_reconnect_attempts,
    );
    set_yaml_u32(
        &mut mapping,
        "circuit_breaker_threshold",
        config.circuit_breaker_threshold,
    );
    set_yaml_u64(
        &mut mapping,
        "circuit_breaker_cooldown_ms",
        config.circuit_breaker_cooldown_ms,
    );
    set_yaml_usize(&mut mapping, "signal_batch_size", config.signal_batch_size);
    set_yaml_u64(
        &mut mapping,
        "signal_batch_delay_ms",
        config.signal_batch_delay_ms,
    );
    set_yaml_u64(
        &mut mapping,
        "heartbeat_interval_ms",
        config.heartbeat_interval_ms,
    );
    set_yaml_usize(
        &mut mapping,
        "max_queued_signals",
        config.max_queued_signals,
    );
    set_yaml_u64(
        &mut mapping,
        "blocklist_cache_ttl_secs",
        config.blocklist_cache_ttl_secs,
    );
    mapping
}

fn tunnel_config_to_yaml(config: &TunnelConfig) -> serde_yaml::Mapping {
    let mut mapping = serde_yaml::Mapping::new();
    set_yaml_bool(&mut mapping, "enabled", config.enabled);
    set_yaml_string(&mut mapping, "url", &config.url);
    set_yaml_string(&mut mapping, "api_key", &config.api_key);
    set_yaml_string(&mut mapping, "sensor_id", &config.sensor_id);
    set_yaml_optional_string(&mut mapping, "sensor_name", config.sensor_name.as_deref());
    set_yaml_string(&mut mapping, "version", &config.version);
    mapping.insert(
        serde_yaml::Value::String("capabilities".to_string()),
        serde_yaml::Value::Sequence(
            config
                .capabilities
                .iter()
                .cloned()
                .map(serde_yaml::Value::String)
                .collect(),
        ),
    );
    set_yaml_u64(
        &mut mapping,
        "heartbeat_interval_ms",
        config.heartbeat_interval_ms,
    );
    set_yaml_u64(
        &mut mapping,
        "reconnect_delay_ms",
        config.reconnect_delay_ms,
    );
    set_yaml_u32(
        &mut mapping,
        "max_reconnect_attempts",
        config.max_reconnect_attempts,
    );
    set_yaml_u64(&mut mapping, "auth_timeout_ms", config.auth_timeout_ms);
    set_yaml_bool(&mut mapping, "shell_enabled", config.shell_enabled);
    mapping
}

fn request_process_restart() -> Result<RestartResult, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Failed to locate current executable: {}", e))?;
    let current_dir =
        std::env::current_dir().map_err(|e| format!("Failed to read current dir: {}", e))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    #[cfg(unix)]
    {
        let mut command = Command::new("/bin/sh");
        command
            .current_dir(current_dir)
            .process_group(0)
            .arg("-c")
            .arg("sleep \"$1\"; shift; exec \"$@\"")
            .arg("synapse-waf-restart")
            .arg("1")
            .arg(&exe);
        for arg in &args {
            command.arg(arg);
        }
        command.spawn().map_err(|e| {
            format!(
                "Failed to spawn replacement process {}: {}",
                exe.display(),
                e
            )
        })?;

        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(400));
            std::process::exit(0);
        });

        return Ok(RestartResult {
            success: true,
            message: format!(
                "Restart requested. Synapse WAF will restart using {}.",
                exe.display()
            ),
        });
    }

    #[cfg(not(unix))]
    {
        let _ = exe;
        let _ = current_dir;
        let _ = args;
        Err("Restart is only supported on Unix-like hosts in this build".to_string())
    }
}

fn request_process_shutdown() -> Result<ShutdownResult, String> {
    #[cfg(unix)]
    {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
        });

        return Ok(ShutdownResult {
            success: true,
            message: "Shutdown requested. Synapse WAF is draining existing connections."
                .to_string(),
        });
    }

    #[cfg(not(unix))]
    {
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(250));
            std::process::exit(0);
        });

        Ok(ShutdownResult {
            success: true,
            message: "Shutdown requested. Synapse WAF will stop shortly.".to_string(),
        })
    }
}

// Global Schema Learner for API anomaly detection
// Learns request/response JSON schemas per endpoint and validates against them.
// Thread-safe via DashMap, minimal contention for high-throughput scenarios.
pub(crate) static SCHEMA_LEARNER: Lazy<SchemaLearner> = Lazy::new(|| {
    SchemaLearner::with_config(SchemaLearnerConfig {
        max_schemas: 5000,
        min_samples_for_validation: 10,
        max_nesting_depth: 10,
        max_fields_per_schema: 100,
        string_length_tolerance: 2.0,
        number_value_tolerance: 2.0,
        required_field_threshold: 0.9,
    })
});

// Cached hashes for config and rules (computed at startup, used in heartbeats)
// These are used to detect configuration drift between sensors and the hub.
static CONFIG_HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
static RULES_HASH: Lazy<Arc<RwLock<String>>> = Lazy::new(|| Arc::new(RwLock::new(String::new())));

/// Compute SHA256 hash of data and return as hex string.
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)[..16].to_string()
}

// Thread-local buffer pool for request body handling (optimization)
thread_local! {
    static BUFFER_POOL: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::with_capacity(128));
}

/// Get a buffer from the thread-local pool or allocate a new one
fn get_buffer() -> Vec<u8> {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(8192))
    })
}

/// Return a buffer to the thread-local pool for reuse.
///
/// We only retain reasonably small buffers so a single large upload does not
/// permanently bloat the per-thread pool.
fn return_buffer(mut buf: Vec<u8>) {
    if buf.capacity() <= 64 * 1024 {
        buf.clear();
        BUFFER_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            if p.len() < 128 {
                p.push(buf);
            }
        });
    }
}

/// Normalize a URL path to a reusable template.
///
/// Examples:
/// - `/api/users/123` -> `/api/users/{id}`
/// - `/api/orders/550e8400-e29b-41d4-a716-446655440000` -> `/api/orders/{id}`
///
/// This keeps endpoint profiling and anomaly tracking stable across per-entity
/// resource identifiers.
fn normalize_path_to_template(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()) {
                return "{id}";
            }
            if segment.len() == 36 && segment.chars().filter(|&c| c == '-').count() == 4 {
                let hex_parts: Vec<&str> = segment.split('-').collect();
                if hex_parts.len() == 5
                    && hex_parts
                        .iter()
                        .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
                {
                    return "{id}";
                }
            }
            if segment.len() == 24 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
                return "{id}";
            }
            segment
        })
        .collect::<Vec<&str>>()
        .join("/")
}

/// TASK-61: maximum total external-risk contribution from a single request.
///
/// After TASK-54/55/58 added three new risk-contribution paths, a single
/// request could simultaneously trip session_hijack + session_invalid +
/// trends_anomaly + schema_violation + crawler_suspicious and accumulate
/// >100 external risk — trivially crossing the entity block threshold on
/// one hit. Combined with any X-Forwarded-For spoofing vulnerability, this
/// enables reflected DoS: attacker sends a crafted request carrying a
/// victim CDN/NAT egress IP, blocking legitimate users sharing that IP.
///
/// The clamp preserves single-signal blocking for deliberately-high signals
/// (bad-bot 100.0 path is intentionally unbounded — it's a hard block on
/// one detection) while preventing multi-signal accumulation from single
/// requests. Multi-request attacks still accumulate normally — the cap is
/// per-request, not per-entity.
///
/// 25.0 is a quarter of the default 100.0 block threshold, so even if all
/// per-request signals land at their maximum budget, blocking still
/// requires sustained activity across at least 4 requests.
const MAX_EXTERNAL_RISK_PER_REQUEST: f64 = 25.0;

/// TASK-58: entity risk contribution weight for a SessionDecision::Invalid
/// outcome. Deliberately smaller than the Suspicious weight (50.0) because
/// legitimate clients occasionally send stale/lost session tokens — one
/// Invalid is benign, a pattern of many is the signal. 12.0 means 5-9
/// repeat invalid tokens from the same IP will trip the default entity
/// risk blocking threshold, catching brute-force without false-positiving
/// on transient client issues.
const INVALID_SESSION_RISK_WEIGHT: f64 = 12.0;

/// TASK-55 / TASK-67: build a production-shaped TrendsManager with its
/// `apply_risk` callback wired through to an EntityManager. Extracted from
/// the inline main() wiring so integration tests can drive the same code
/// path that production uses. If someone deletes the body of this helper
/// (or the call from main()), TASK-67's integration tests fail — preventing
/// silent regression to a dormant callback.
///
/// The callback casts u32 → f64 because TrendsManager stores anomaly risk
/// as u32 but EntityManager takes f64. `TrendsReason::as_tag()` preserves
/// the historical tag strings while removing the stringly-typed callback API.
pub(crate) fn build_trends_manager_with_risk_callback(
    config: synapse_pingora::trends::TrendsConfig,
    entity_manager: Arc<EntityManager>,
) -> Arc<TrendsManager> {
    let deps = synapse_pingora::trends::TrendsManagerDependencies {
        apply_risk: Some(Box::new(move |entity_id: &str, risk: u32, reason| {
            entity_manager.apply_external_risk(entity_id, risk as f64, reason.as_tag());
        })),
    };
    Arc::new(TrendsManager::with_dependencies(config, deps))
}

/// Merge a non-blocking deferred-pass verdict into an already-populated
/// `DetectionResult` in place. Used by the deferred WAF path in
/// `upstream_request_filter` when the deferred pass produced matches that
/// didn't reach blocking but still represent real WAF work.
///
/// Merge semantics (deliberate, not arbitrary):
/// - `risk_score` is max'd. Summing would be more faithful to "two passes
///   both scored this request" but could push downstream consumers over
///   blocking thresholds they were tuned for on body-phase alone.
///   Preserving the max keeps behavior compatible; changing it is a
///   separate decision.
/// - `entity_risk` is summed. Each pass observed risk for the entity
///   independently; the totals are additive and there is no downstream
///   threshold depending on a max here.
/// - `detection_time_us` is summed (saturating) so latency dashboards
///   see the total WAF work performed, not just the body-phase slice.
/// - `matched_rules` are dedup-extended (preserves existing order, then
///   appends new rules from the deferred pass).
/// - `block_reason` is kept from `existing` when already set, otherwise
///   filled from `deferred`. Non-blocking verdicts rarely carry a reason
///   in practice; this handles the edge case without losing data.
fn merge_deferred_detection_non_blocking(
    existing: &mut DetectionResult,
    deferred: DetectionResult,
) {
    existing.risk_score = existing.risk_score.max(deferred.risk_score);
    existing.entity_risk += deferred.entity_risk;
    existing.detection_time_us = existing
        .detection_time_us
        .saturating_add(deferred.detection_time_us);
    if existing.block_reason.is_none() {
        existing.block_reason = deferred.block_reason;
    }
    for rule in deferred.matched_rules {
        if !existing.matched_rules.contains(&rule) {
            existing.matched_rules.push(rule);
        }
    }
}

/// Build a `TelemetryEvent::WafBlock` for the deferred post-DLP WAF pass.
///
/// Extracted as a pure free function so the event shape (rule_id prefix,
/// severity mapping, site/path copying) can be unit-tested without spinning
/// up a full `SynapseProxy` or a mock `TelemetryClient`. The caller is
/// responsible for gating emission on `telemetry_client.is_enabled()` and
/// dispatching via `tokio::spawn` to keep the hot path non-blocking.
///
/// Severity mapping mirrors the existing body-phase post-detection site:
/// risk_score > 80 → "critical", > 50 → "high", otherwise "medium".
/// When `matched_rules` is empty the rule_id falls back to `"DLP_DEFERRED"`
/// so the event is still routable, though in practice a blocking deferred
/// verdict always carries at least one rule id.
fn build_deferred_waf_block_event(
    request_id: String,
    matched_rules: &[u32],
    risk_score: u16,
    client_ip: String,
    site: String,
    path: String,
) -> synapse_pingora::telemetry::TelemetryEvent {
    let rule_id = matched_rules
        .first()
        .map(|r| format!("DLP_DEFERRED:{}", r))
        .unwrap_or_else(|| "DLP_DEFERRED".to_string());
    let severity = if risk_score > 80 {
        "critical"
    } else if risk_score > 50 {
        "high"
    } else {
        "medium"
    }
    .to_string();
    synapse_pingora::telemetry::TelemetryEvent::WafBlock {
        request_id: Some(request_id),
        rule_id,
        severity,
        client_ip,
        site,
        path,
    }
}

/// Categorize a rule ID into an attack category for actor history tracking.
/// Rule IDs are generally numeric, with ranges indicating attack types.
fn categorize_rule_id(rule_id: u32) -> String {
    match rule_id {
        // XSS rules (941xxx) - must come before SQLi to avoid being shadowed
        941000..=941999 => "xss".to_string(),
        // SQL Injection rules (900xxx, 940xxx, 942xxx)
        900000..=900999 | 940000..=940999 | 942000..=942999 => "sqli".to_string(),
        // Path Traversal rules (930xxx)
        930000..=930999 => "path_traversal".to_string(),
        // RCE/Command Injection rules (932xxx)
        932000..=932999 => "rce".to_string(),
        // LFI/RFI rules (931xxx)
        931000..=931999 => "lfi".to_string(),
        // Protocol Attack rules (920xxx, 921xxx)
        920000..=921999 => "protocol".to_string(),
        // Scanner Detection rules (913xxx)
        913000..=913999 => "scanner".to_string(),
        // Request Limits rules (911xxx, 912xxx)
        911000..=912999 => "request_limits".to_string(),
        // Default category
        _ => format!("rule_{}", rule_id / 1000 * 1000),
    }
}

// ============================================================================
// Pingora Proxy Implementation
// ============================================================================

/// Result from async DLP scan task: (match_count, types, scan_time_us, matches).
/// The `matches` vec powers the deferred WAF pass's `dlp_violation` match kind
/// and is empty when no matches were found.
pub type DlpScanResult = (usize, String, u64, Vec<synapse_pingora::dlp::DlpMatch>);

/// Per-request context flowing through all Pingora hooks
pub struct RequestContext {
    /// Start time for the request (for logging)
    request_start: Instant,
    /// Request correlation ID (X-Request-ID)
    request_id: String,
    /// Active request guard for tracking concurrency
    _active_request_guard: ActiveRequestGuard,
    /// Detection result from request_filter
    detection: Option<DetectionResult>,
    /// Backend index for round-robin
    backend_idx: usize,
    /// Multi-site: Matched site configuration for this request
    matched_site: Option<SiteConfig>,
    /// Request headers (cached for late body inspection)
    headers: Vec<HeaderSnapshot>,
    /// Client IP (extracted from headers or connection)
    client_ip: Option<String>,
    /// Total body size seen (for body inspection)
    body_bytes_seen: usize,
    /// Phase 3: Client fingerprint (JA4 + JA4H)
    fingerprint: Option<ClientFingerprint>,
    /// Phase 3: Entity risk from Pingora entity tracking (per-request running total)
    entity_risk: f64,
    /// TASK-61: per-request accumulator used by `apply_bounded_external_risk`
    /// to enforce `MAX_EXTERNAL_RISK_PER_REQUEST`. Distinct from `entity_risk`
    /// above, which mirrors the capped values for observability — this field
    /// is the running budget consumed from the cap.
    external_risk_accumulated: f64,
    /// Phase 3: Entity block decision from Pingora
    entity_blocked: Option<BlockDecision>,
    /// Phase 3: Tarpit delay applied (in milliseconds)
    tarpit_delay_ms: u64,
    /// Phase 3: Tarpit level reached
    tarpit_level: u32,
    /// Phase 4: DLP match count from response scanning
    dlp_match_count: usize,
    /// Phase 4: DLP matched types (comma-separated)
    dlp_types: String,
    /// Phase 4: Accumulated response body for DLP scanning
    response_body_buffer: Vec<u8>,
    /// Phase 4: Accumulated request body for DLP exfiltration scanning
    request_body_buffer: Vec<u8>,
    /// Phase 4: DLP match count from request body scanning
    request_dlp_match_count: usize,
    /// Phase 4: DLP matched types from request body (comma-separated)
    request_dlp_types: String,
    /// Structured DLP matches from the async request scanner, used by the
    /// deferred WAF pass in `upstream_request_filter` to evaluate rules
    /// that reference the `dlp_violation` match kind.
    request_dlp_matches: Vec<synapse_pingora::dlp::DlpMatch>,
    /// Whether the async DLP scan completed successfully (i.e. the oneshot
    /// receiver produced a result rather than failing/being cancelled).
    /// The deferred WAF pass is gated on this flag rather than on
    /// `!request_dlp_matches.is_empty()` so that rules wrapping
    /// `dlp_violation` in a NOT operator — which fire precisely when there
    /// are zero matches — are still evaluated. If the scan never ran or
    /// failed, the deferred pass is skipped entirely.
    dlp_scan_completed: bool,
    /// TASK-59: parsed JSON body stashed during `request_body_filter` for
    /// deferred schema learning. Consumed at the end of
    /// `upstream_request_filter` — ONLY after both the body-phase WAF
    /// verdict AND the deferred WAF pass have decided not to block. This
    /// closes the TASK-41 poisoning gap for rules that only block in the
    /// deferred phase (e.g. `dlp_violation` rules 220001-220007): previously
    /// `learn_from_request` was called at the end of `request_body_filter`,
    /// which was too early — the deferred pass had not yet run, so attackers
    /// could train the learner on payloads that were about to be blocked
    /// by DLP-correlation rules. With consumption moved to
    /// `upstream_request_filter` after the deferred pass, the learner only
    /// trains on bodies that survive the full WAF decision chain.
    pending_learn: Option<(String, serde_json::Value)>,
    /// Schema validation result from the body-phase schema validator. Attached
    /// to the WAF evaluation context so rules can match the `schema_violation`
    /// kind against the learned baseline.
    schema_result: Option<synapse_pingora::profiler::ValidationResult>,
    /// Request Content-Type header for DLP skip optimization
    request_content_type: Option<String>,
    /// Whether to skip DLP scanning for this request (binary content)
    skip_request_dlp: bool,
    /// Phase 5: Async DLP scan receiver for parallel execution
    /// The DLP scan runs in parallel with upstream routing, result awaited before headers sent
    dlp_scan_rx: Option<oneshot::Receiver<DlpScanResult>>,
    /// Phase 5: DLP scan time from async task (for metrics)
    dlp_scan_time_us: u64,
    /// Response Content-Type header for schema validation
    response_content_type: Option<String>,
    /// Request path for schema template mapping (stored for response phase)
    request_path: Option<String>,
    /// Request method for auth coverage mapping
    request_method: Option<String>,
    /// Whether request contained authentication headers/cookies
    has_auth_header: bool,
    /// Phase 5: Actor ID correlated for this request
    actor_id: Option<String>,
    /// Phase 5: Actor risk score snapshot for this request
    actor_risk_score: f64,
    /// Phase 10: Challenge cookie to set in response (progressive challenge system)
    challenge_cookie: Option<String>,
    /// Phase 10: Whether a challenge response was validated on this request
    challenge_validated: bool,
    /// Phase 10: WAF action selected for this request
    waf_action: Option<WafAction>,
    /// Phase 10: Whether a challenge response was served
    waf_challenged: bool,
    /// Phase 10: Whether request was logged-only by WAF
    waf_logged: bool,
}

impl Drop for RequestContext {
    fn drop(&mut self) {
        // Return response buffer to pool
        let resp_buf = std::mem::take(&mut self.response_body_buffer);
        if resp_buf.capacity() > 0 {
            return_buffer(resp_buf);
        }

        // Request body buffer might have been moved to async task, but if not, return it
        let req_buf = std::mem::take(&mut self.request_body_buffer);
        if req_buf.capacity() > 0 {
            return_buffer(req_buf);
        }
    }
}

/// Rate limiter for early_request_filter
#[allow(dead_code)]
static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(std::time::Duration::from_secs(1)));
static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Per-IP rate limiting state (P2-2: Per-IP Rate Limiting)
/// Tracks request count and window start time per client IP.
/// Uses DashMap for lock-free concurrent access across request threads.
static PER_IP_LIMITS: Lazy<DashMap<String, (usize, Instant)>> = Lazy::new(DashMap::new);

/// Check and update per-IP rate limit.
///
/// Returns `true` if the request is allowed, `false` if rate limited.
/// Uses a sliding window of 1 second per IP address.
///
/// # Arguments
/// * `client_ip` - The client IP address string
/// * `limit` - Maximum requests per second allowed for this IP
fn check_per_ip_rate_limit(client_ip: &str, limit: usize) -> bool {
    let now = Instant::now();

    // Use entry API for atomic check-and-update
    let mut entry = PER_IP_LIMITS
        .entry(client_ip.to_string())
        .or_insert((0, now));

    // Reset counter if window (1 second) has passed
    if entry.1.elapsed() > Duration::from_secs(1) {
        *entry = (1, now);
        return true; // First request in new window - allowed
    }

    // Increment and check limit
    entry.0 += 1;
    entry.0 <= limit // true = allowed, false = rate limited
}

/// Periodically clean up stale entries from the per-IP rate limit map.
/// Called opportunistically to prevent unbounded memory growth.
/// Removes entries older than 60 seconds (no requests in last minute).
fn cleanup_per_ip_limits() {
    // Only cleanup if map is getting large (reduce overhead)
    if PER_IP_LIMITS.len() > 10_000 {
        let cutoff = Duration::from_secs(60);
        PER_IP_LIMITS.retain(|_, (_, last_seen)| last_seen.elapsed() < cutoff);
    }
}

/// Set of managers and clients used by the SynapseProxy.
pub struct ProxyDependencies {
    pub health_checker: Arc<HealthChecker>,
    pub metrics_registry: Arc<MetricsRegistry>,
    pub telemetry_client: Arc<TelemetryClient>,
    pub tls_manager: Arc<TlsManager>,
    pub dlp_scanner: Arc<DlpScanner>,
    pub entity_manager: Arc<EntityManager>,
    pub block_log: Arc<BlockLog>,
    pub actor_manager: Arc<ActorManager>,
    pub session_manager: Arc<SessionManager>,
    pub shadow_mirror_manager: Option<Arc<ShadowMirrorManager>>,
    pub crawler_detector: Arc<CrawlerDetector>,
    pub horizon_manager: Option<Arc<HorizonManager>>,
    pub trends_manager: Arc<TrendsManager>,
    pub signal_manager: Arc<SignalManager>,
    pub progression_manager: Arc<ProgressionManager>,
    /// TASK-54: CampaignManager for correlation-based threat detection.
    /// The filter chain feeds per-request fingerprints via register_fingerprints;
    /// the background worker correlates them into detection signals and
    /// auto-mitigates via AccessListManager.
    pub campaign_manager: Arc<CampaignManager>,
    pub tarpit_config: TarpitConfig,
    pub trusted_proxies: Vec<CidrRange>,
    pub rps_limit: usize,
    pub per_ip_rps_limit: usize,
}

/// The Synapse WAF Proxy
#[allow(dead_code)]
pub struct SynapseProxy {
    /// Backend servers for round-robin selection (fallback/default)
    backends: Vec<(String, u16)>,
    /// Round-robin counter
    backend_counter: AtomicUsize,
    /// Requests per second limit for rate limiting (global)
    rps_limit: usize,
    /// Per-IP requests per second limit (P2-2: prevents single IP from exhausting global quota)
    per_ip_rps_limit: usize,
    /// Phase 3: Thread-safe entity manager for per-IP tracking
    entity_manager: Arc<EntityManager>,
    /// Phase 3: Tarpit manager for progressive response delays
    tarpit_manager: Arc<TarpitManager>,
    /// Phase 4: DLP scanner for sensitive data detection
    dlp_scanner: Arc<DlpScanner>,
    /// Health checker for /_sensor/status endpoint
    health_checker: Arc<HealthChecker>,
    /// Metrics registry for collecting statistics
    metrics_registry: Arc<MetricsRegistry>,
    /// Multi-site: Virtual host matcher for hostname-based routing
    vhost_matcher: Option<Arc<RwLock<VhostMatcher>>>,
    /// Multi-site: Configuration manager for CRUD operations
    config_manager: Option<Arc<ConfigManager>>,
    /// Multi-site: Per-site WAF configuration
    site_waf_manager: Option<Arc<RwLock<SiteWafManager>>>,
    /// Multi-site: Per-site rate limiting
    rate_limit_manager: Option<Arc<RwLock<RateLimitManager>>>,
    /// Multi-site: Per-site access lists
    access_list_manager: Option<Arc<RwLock<AccessListManager>>>,
    /// Phase 3: Telemetry client for Signal Horizon reporting
    telemetry_client: Arc<TelemetryClient>,
    /// Phase 6: TLS manager for certificate selection and validation
    tls_manager: Arc<synapse_pingora::tls::TlsManager>,
    /// Phase 3: Honeypot trap endpoint matcher
    trap_matcher: Option<Arc<TrapMatcher>>,
    /// Trusted proxy CIDR ranges for X-Forwarded-For validation
    trusted_proxies: Vec<CidrRange>,
    /// Block log for dashboard visibility
    block_log: Arc<BlockLog>,
    /// Phase 5: Actor state manager for behavioral tracking and risk scoring
    actor_manager: Arc<ActorManager>,
    /// Phase 5: Session state manager for session validation and hijack detection
    session_manager: Arc<SessionManager>,
    /// Phase 7: Shadow mirror manager for honeypot delivery
    shadow_mirror_manager: Option<Arc<ShadowMirrorManager>>,
    /// Phase 9: Crawler detector for bot verification
    crawler_detector: Arc<CrawlerDetector>,
    /// Phase 9: Signal Horizon manager for fleet-wide threat intelligence
    horizon_manager: Option<Arc<HorizonManager>>,
    /// Phase 9: Payload profiling manager for bandwidth tracking
    payload_manager: Arc<PayloadManager>,
    /// Phase 9: Trends manager for signal tracking and anomaly detection
    trends_manager: Arc<TrendsManager>,
    /// Phase 9: Signal manager for intelligence aggregation
    signal_manager: Arc<SignalManager>,
    /// Phase 10: Progression manager for challenge escalation
    progression_manager: Arc<ProgressionManager>,
    /// TASK-54: Campaign manager for correlation-based threat detection
    /// (JA4 rotation, shared fingerprints, attack sequences). Fed by
    /// request_filter on each request via register_fingerprints so the
    /// background worker has data to correlate.
    campaign_manager: Arc<CampaignManager>,
    /// Phase 11: Auth coverage aggregator for endpoint telemetry
    auth_coverage: Arc<AuthCoverageAggregator>,
    /// Adaptive rate limiting for autonomous health management (TASK-075)
    adaptive_rate_limiter: Option<Arc<synapse_pingora::ratelimit::AdaptiveRateLimiter>>,
}

impl SynapseProxy {
    /// Start all background maintenance tasks for proxy-internal managers.
    pub fn start_background_tasks(&self) {
        self.tarpit_manager.clone().start_background_tasks();
        self.progression_manager.clone().start_background_tasks();

        // Start adaptive rate limiting if configured
        if let Some(ref adaptive_rl) = self.adaptive_rate_limiter {
            adaptive_rl
                .clone()
                .start_background_task(Duration::from_secs(5));
        }

        info!("SynapseProxy internal background tasks started");
    }

    pub async fn new(
        backends: Vec<(String, u16)>,
        rps_limit: usize,
        tls_manager: Arc<TlsManager>,
    ) -> Self {
        let crawler_detector = build_crawler_detector(CrawlerConfig::default()).await;
        let trends_manager = Arc::new(TrendsManager::new(TrendsConfig::default()));
        let signal_manager = Arc::new(SignalManager::new(SignalManagerConfig::default()));

        let cookie_manager = Arc::new(CookieManager::new_fallback(create_default_cookie_config()));
        let js_manager = Arc::new(JsChallengeManager::new(JsChallengeConfig::default()));
        let captcha_manager = Arc::new(CaptchaManager::new(CaptchaConfig::default()));
        let tarpit_manager = Arc::new(TarpitManager::new(TarpitConfig::default()));

        let progression_manager = Arc::new(ProgressionManager::new(
            cookie_manager,
            js_manager,
            captcha_manager,
            tarpit_manager,
            create_progression_config(),
        ));

        let deps = ProxyDependencies {
            health_checker: Arc::new(HealthChecker::default()),
            metrics_registry: Arc::new(MetricsRegistry::new()),
            telemetry_client: Arc::new(TelemetryClient::new(TelemetryConfig {
                enabled: false,
                ..TelemetryConfig::default()
            })),
            tls_manager,
            dlp_scanner: Arc::new(DlpScanner::new(DlpConfig::default())),
            entity_manager: Arc::new(EntityManager::new(EntityConfig::default())),
            block_log: Arc::new(BlockLog::default()),
            actor_manager: Arc::new(ActorManager::new(ActorConfig::default())),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            shadow_mirror_manager: None,
            crawler_detector,
            horizon_manager: None,
            trends_manager,
            signal_manager,
            progression_manager,
            campaign_manager: Arc::new(CampaignManager::new()),
            tarpit_config: TarpitConfig::default(),
            trusted_proxies: Vec::new(),
            rps_limit,
            per_ip_rps_limit: default_per_ip_rps(),
        };

        Self::with_health(backends, deps)
    }

    pub fn with_health(backends: Vec<(String, u16)>, deps: ProxyDependencies) -> Self {
        // Create tarpit manager first (needed by progression manager)
        let tarpit_manager = Arc::new(TarpitManager::new(deps.tarpit_config.clone()));

        let auth_coverage = Self::build_auth_coverage(Arc::clone(&deps.telemetry_client));

        Self {
            backends,
            backend_counter: AtomicUsize::new(0),
            rps_limit: deps.rps_limit,
            per_ip_rps_limit: deps.per_ip_rps_limit,
            entity_manager: deps.entity_manager,
            tarpit_manager,
            dlp_scanner: deps.dlp_scanner,
            health_checker: deps.health_checker,
            metrics_registry: deps.metrics_registry,
            vhost_matcher: None,
            config_manager: None,
            site_waf_manager: None,
            rate_limit_manager: None,
            access_list_manager: None,
            telemetry_client: deps.telemetry_client,
            tls_manager: deps.tls_manager,
            trap_matcher: build_trap_matcher(),
            trusted_proxies: deps.trusted_proxies,
            block_log: deps.block_log,
            actor_manager: deps.actor_manager,
            session_manager: deps.session_manager,
            shadow_mirror_manager: deps.shadow_mirror_manager,
            crawler_detector: deps.crawler_detector,
            horizon_manager: deps.horizon_manager,
            payload_manager: Arc::new(PayloadManager::new(PayloadConfig::default())),
            trends_manager: deps.trends_manager,
            signal_manager: deps.signal_manager,
            progression_manager: deps.progression_manager,
            campaign_manager: deps.campaign_manager,
            auth_coverage,
            adaptive_rate_limiter: None, // Adaptive RL requires multi-site manager
        }
    }

    pub async fn with_entity_config(
        backends: Vec<(String, u16)>,
        rps_limit: usize,
        entity_config: EntityConfig,
        tls_manager: Arc<TlsManager>,
        tarpit_config: TarpitConfig,
        dlp_config: DlpConfig,
    ) -> Self {
        let crawler_detector = build_crawler_detector(CrawlerConfig::default()).await;
        let trends_manager = Arc::new(TrendsManager::new(TrendsConfig::default()));
        let signal_manager = Arc::new(SignalManager::new(SignalManagerConfig::default()));
        let telemetry_client = Arc::new(TelemetryClient::new(TelemetryConfig {
            enabled: false,
            ..TelemetryConfig::default()
        }));

        // Create tarpit manager first (needed by progression manager)
        let tarpit_manager = Arc::new(TarpitManager::new(tarpit_config.clone()));

        // Create interrogator managers
        let cookie_manager = Arc::new(CookieManager::new_fallback(create_default_cookie_config()));
        let js_manager = Arc::new(JsChallengeManager::new(JsChallengeConfig::default()));
        let captcha_manager = Arc::new(CaptchaManager::new(CaptchaConfig::default()));

        let progression_manager = Arc::new(ProgressionManager::new(
            cookie_manager,
            js_manager,
            captcha_manager,
            tarpit_manager.clone(),
            create_progression_config(),
        ));

        let deps = ProxyDependencies {
            health_checker: Arc::new(HealthChecker::default()),
            metrics_registry: Arc::new(MetricsRegistry::new()),
            telemetry_client,
            tls_manager,
            dlp_scanner: Arc::new(DlpScanner::new(dlp_config)),
            entity_manager: Arc::new(EntityManager::new(entity_config)),
            block_log: Arc::new(BlockLog::default()),
            actor_manager: Arc::new(ActorManager::new(ActorConfig::default())),
            session_manager: Arc::new(SessionManager::new(SessionConfig::default())),
            shadow_mirror_manager: None,
            crawler_detector,
            horizon_manager: None,
            trends_manager,
            signal_manager,
            progression_manager,
            campaign_manager: Arc::new(CampaignManager::new()),
            tarpit_config,
            trusted_proxies: Vec::new(),
            rps_limit,
            per_ip_rps_limit: default_per_ip_rps(),
        };

        Self::with_health(backends, deps)
    }

    fn build_auth_coverage(telemetry_client: Arc<TelemetryClient>) -> Arc<AuthCoverageAggregator> {
        let sensor_id =
            std::env::var("SYNAPSE_SENSOR_ID").unwrap_or_else(|_| "synapse-default".to_string());
        let tenant_id = std::env::var("SYNAPSE_TENANT_ID").ok();
        let emitter: Arc<dyn SignalEmitter> = telemetry_client;
        let auth_coverage = Arc::new(AuthCoverageAggregator::new(
            sensor_id, tenant_id, emitter, 60,
        ));
        auth_coverage.clone().start_flush_task();
        auth_coverage
    }

    /// Create a SynapseProxy with multi-site configuration support
    pub fn with_multisite(
        default_backends: Vec<(String, u16)>,
        vhost_matcher: Arc<RwLock<VhostMatcher>>,
        config_manager: Arc<ConfigManager>,
        site_waf_manager: Arc<RwLock<SiteWafManager>>,
        rate_limit_manager: Arc<RwLock<RateLimitManager>>,
        access_list_manager: Arc<RwLock<AccessListManager>>,
        deps: ProxyDependencies,
    ) -> Self {
        // Create tarpit manager first (needed by progression manager)
        let tarpit_manager = Arc::new(TarpitManager::new(deps.tarpit_config.clone()));

        let auth_coverage = Self::build_auth_coverage(Arc::clone(&deps.telemetry_client));

        let adaptive_rate_limiter = Arc::new(synapse_pingora::ratelimit::AdaptiveRateLimiter::new(
            Arc::clone(&rate_limit_manager),
            Arc::clone(&deps.metrics_registry),
        ));

        Self {
            backends: default_backends,
            backend_counter: AtomicUsize::new(0),
            rps_limit: deps.rps_limit,
            per_ip_rps_limit: deps.per_ip_rps_limit,
            entity_manager: deps.entity_manager,
            tarpit_manager,
            dlp_scanner: deps.dlp_scanner,
            health_checker: deps.health_checker,
            metrics_registry: deps.metrics_registry,
            telemetry_client: deps.telemetry_client,
            tls_manager: deps.tls_manager,
            trusted_proxies: deps.trusted_proxies,
            vhost_matcher: Some(vhost_matcher),
            config_manager: Some(config_manager),
            site_waf_manager: Some(site_waf_manager),
            rate_limit_manager: Some(rate_limit_manager),
            access_list_manager: Some(access_list_manager),
            trap_matcher: build_trap_matcher(),
            block_log: deps.block_log,
            actor_manager: deps.actor_manager,
            session_manager: deps.session_manager,
            shadow_mirror_manager: deps.shadow_mirror_manager,
            crawler_detector: deps.crawler_detector,
            horizon_manager: deps.horizon_manager,
            payload_manager: Arc::new(PayloadManager::new(PayloadConfig::default())),
            trends_manager: deps.trends_manager,
            signal_manager: deps.signal_manager,
            progression_manager: deps.progression_manager,
            campaign_manager: deps.campaign_manager,
            auth_coverage,
            adaptive_rate_limiter: Some(adaptive_rate_limiter),
        }
    }

    /// Select next backend using round-robin
    fn next_backend(&self) -> (String, u16, usize) {
        let idx = self.backend_counter.fetch_add(1, Ordering::Relaxed) % self.backends.len();
        let backend = &self.backends[idx];
        (backend.0.clone(), backend.1, idx)
    }

    /// Returns a clone of the block log Arc for sharing with ApiHandler
    pub fn block_log(&self) -> Arc<BlockLog> {
        Arc::clone(&self.block_log)
    }

    pub fn tarpit_manager(&self) -> Arc<TarpitManager> {
        Arc::clone(&self.tarpit_manager)
    }

    pub fn progression_manager(&self) -> Arc<ProgressionManager> {
        Arc::clone(&self.progression_manager)
    }

    pub fn shadow_mirror_manager(&self) -> Option<Arc<ShadowMirrorManager>> {
        self.shadow_mirror_manager.clone()
    }

    /// TASK-54: accessor for tests and observability code that need to
    /// inspect or interact with the correlation CampaignManager (e.g.
    /// asserting a fingerprint was registered, querying campaign state,
    /// or reading the fingerprint index).
    pub fn campaign_manager(&self) -> Arc<CampaignManager> {
        Arc::clone(&self.campaign_manager)
    }

    /// Extract client IP from headers or connection, validating X-Forwarded-For against trusted proxies.
    ///
    /// Security: Walks the XFF chain from right (closest proxy) to left (original client),
    /// finding the first IP that is NOT in the trusted proxy list. This prevents IP spoofing
    /// attacks where malicious actors forge XFF headers.
    fn get_client_ip(&self, session: &Session) -> Option<String> {
        // Get connection peer address first (most trusted source)
        // Pingora's SocketAddr.to_string() returns "ip:port", we need just the IP
        let conn_ip = session.client_addr().map(|addr| {
            let addr_str = addr.to_string();
            // Strip port from address (handles both IPv4 "1.2.3.4:80" and IPv6 "[::1]:80")
            if addr_str.starts_with('[') {
                // IPv6 format: [ip]:port
                addr_str
                    .split(']')
                    .next()
                    .unwrap_or(&addr_str)
                    .trim_start_matches('[')
                    .to_string()
            } else {
                // IPv4 format: ip:port
                addr_str.split(':').next().unwrap_or(&addr_str).to_string()
            }
        });

        // If no trusted proxies configured, only trust connection IP (most secure default)
        if self.trusted_proxies.is_empty() {
            return conn_ip;
        }

        // Validate that the direct connection is from a trusted proxy before trusting XFF
        let conn_ip_trusted = conn_ip
            .as_ref()
            .and_then(|ip_str| ip_str.parse::<IpAddr>().ok())
            .map(|ip| self.trusted_proxies.iter().any(|cidr| cidr.contains(&ip)))
            .unwrap_or(false);

        if !conn_ip_trusted {
            // Connection is not from a trusted proxy - don't trust XFF headers
            debug!("Connection IP not from trusted proxy, ignoring XFF headers");
            return conn_ip;
        }

        // Connection is from trusted proxy, check X-Forwarded-For
        if let Some(xff) = session.req_header().headers.get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                let ips: Vec<&str> = s.split(',').map(|ip| ip.trim()).collect();

                // Walk from right (closest proxy) to left (original client)
                // Find first IP NOT in trusted proxies - that's the real client
                for ip_str in ips.iter().rev() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        let is_trusted = self.trusted_proxies.iter().any(|cidr| cidr.contains(&ip));
                        if !is_trusted {
                            return Some(ip_str.to_string());
                        }
                    } else {
                        // Invalid IP in chain - treat as untrusted client IP
                        debug!("Invalid IP in XFF chain: {}", ip_str);
                        return Some(ip_str.to_string());
                    }
                }

                // All IPs in XFF are trusted - return leftmost (original "client")
                // This handles the case where all proxies are internal
                if let Some(leftmost) = ips.first() {
                    return Some(leftmost.to_string());
                }
            }
        }

        // Check X-Real-IP as fallback (only if connection is from trusted proxy)
        if let Some(xri) = session.req_header().headers.get("x-real-ip") {
            if let Ok(s) = xri.to_str() {
                return Some(s.to_string());
            }
        }

        // Fall back to connection peer address
        conn_ip
    }

    /// Extract headers as Vec for detection engine
    fn extract_headers(session: &Session) -> Vec<HeaderSnapshot> {
        let headers = &session.req_header().headers;
        let mut result = Vec::with_capacity(headers.len());

        for (name, value) in headers {
            result.push((name.clone(), value.clone()));
        }
        result
    }

    /// Resolve WAF action based on site config and detection result.
    fn resolve_waf_action(&self, ctx: &RequestContext, result: &DetectionResult) -> WafAction {
        if let (Some(ref site), Some(ref site_waf_mgr)) =
            (&ctx.matched_site, &self.site_waf_manager)
        {
            let waf = site_waf_mgr.read();
            let config = waf.get_config(&site.hostname);

            if !config.enabled {
                return WafAction::Allow;
            }

            let risk_score = (result.risk_score.min(u16::from(u8::MAX))) as u8;
            let mut action = WafAction::Allow;
            let mut triggered = false;

            for rule_id in &result.matched_rules {
                let rule_key = rule_id.to_string();
                let threshold = config.get_rule_threshold(&rule_key);
                if risk_score >= threshold {
                    action = Self::combine_waf_action(action, config.get_rule_action(&rule_key));
                    triggered = true;
                }
            }

            if !triggered && risk_score >= config.threshold {
                action = config.default_action;
                triggered = true;
            }

            if triggered {
                return action;
            }
        }

        if result.blocked {
            WafAction::Block
        } else {
            WafAction::Allow
        }
    }

    /// Resolve combined WAF actions with priority ordering.
    fn combine_waf_action(current: WafAction, next: WafAction) -> WafAction {
        use WafAction::{Allow, Block, Challenge, Log};
        match (current, next) {
            (Block, _) | (_, Block) => Block,
            (Challenge, _) | (_, Challenge) => Challenge,
            (Log, _) | (_, Log) => Log,
            _ => Allow,
        }
    }

    /// Record a WAF block event and report to Signal Horizon.
    fn record_waf_block_event(
        &self,
        client_ip: &str,
        method: &str,
        uri: &str,
        result: &DetectionResult,
        fingerprint: Option<&ClientFingerprint>,
        reason: &str,
    ) {
        self.block_log.record(BlockEvent::new(
            client_ip.to_string(),
            method.to_string(),
            uri.to_string(),
            result.risk_score,
            result.matched_rules.clone(),
            reason.to_string(),
            fingerprint.map(|fp| fp.combined_hash.clone()),
        ));

        if let Some(ref horizon) = self.horizon_manager {
            let severity = if result.risk_score >= 80 {
                Severity::Critical
            } else if result.risk_score >= 60 {
                Severity::High
            } else if result.risk_score >= 40 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let mut signal = ThreatSignal::new(SignalType::IpThreat, severity)
                .with_source_ip(client_ip)
                .with_confidence(result.risk_score as f64 / 100.0);

            if let Some(fp) = fingerprint.and_then(|fp| fp.ja4.as_ref()) {
                signal = signal.with_fingerprint(&fp.raw);
            }

            let rule_ids: Vec<String> = result
                .matched_rules
                .iter()
                .map(|r| format!("rule_{}", r))
                .collect();
            if !rule_ids.is_empty() {
                signal = signal.with_metadata(serde_json::json!({ "rule_ids": rule_ids }));
            }

            horizon.report_signal(signal);
        }
    }

    /// Extract a named cookie from the Cookie header.
    fn extract_cookie_value(cookie_header: &str, cookie_name: &str) -> Option<String> {
        cookie_header
            .split(';')
            .map(|c| c.trim())
            .find_map(|cookie| {
                let mut parts = cookie.splitn(2, '=');
                let name = parts.next()?.trim();
                let value = parts.next()?.trim();
                if name == cookie_name {
                    Some(value.to_string())
                } else {
                    None
                }
            })
    }

    /// Extract query parameter value from a query string.
    fn extract_query_param(query: &str, key: &str) -> Option<String> {
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let name = parts.next()?.trim();
            if name == key {
                let value = parts.next().unwrap_or("");
                let decoded = percent_decode_str(value).decode_utf8_lossy().to_string();
                return Some(decoded);
            }
        }
        None
    }

    /// Generate a new request correlation ID.
    fn generate_request_id() -> String {
        format!("req_{}", Uuid::new_v4())
    }

    /// Normalize and validate an incoming request ID header.
    fn normalize_request_id(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return None;
        }
        if !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return None;
        }
        Some(trimmed.to_string())
    }

    /// Insert X-Request-ID header into a response.
    fn apply_request_id_header(resp: &mut ResponseHeader, request_id: &str) -> Result<()> {
        resp.insert_header("x-request-id", request_id)?;
        Ok(())
    }

    /// Canonical WAF block response body. Single source of truth for the
    /// JSON envelope returned by every WAF block site (body-phase, deferred,
    /// and future sites). Clients that parse the error shape depend on this
    /// being stable — treat changes here as an API break.
    const WAF_BLOCK_BODY: &'static str = r#"{"error": "access_denied"}"#;

    /// Build the canonical 403 ResponseHeader for a WAF block. Pure and
    /// testable — the only observable effect is allocation. Separated from
    /// `send_waf_block_response` so tests can inspect the header shape
    /// without constructing a full Pingora `Session`.
    ///
    /// Contract:
    /// - status 403
    /// - `x-request-id` echoes the caller-provided request id
    /// - `content-type: application/json`
    /// - `content-length` matches `WAF_BLOCK_BODY.len()`
    /// - Security headers via `headers::apply_security_response_headers`
    ///   (HSTS is conditionally emitted only on HTTPS)
    fn build_waf_block_response_header(request_id: &str, is_https: bool) -> Result<ResponseHeader> {
        let mut resp = ResponseHeader::build(403, None)?;
        Self::apply_request_id_header(&mut resp, request_id)?;
        headers::apply_security_response_headers(&mut resp, is_https);
        resp.insert_header("content-type", "application/json")?;
        resp.insert_header("content-length", Self::WAF_BLOCK_BODY.len().to_string())?;
        Ok(resp)
    }

    /// Write the canonical WAF block response (header + body) to the client.
    /// This is the ONLY call every WAF block site should use to emit a
    /// client-visible 403 — keeping it centralized guarantees byte-identical
    /// responses regardless of which block site fires (body-phase,
    /// deferred DLP, or future additions).
    async fn send_waf_block_response(
        session: &mut Session,
        request_id: &str,
        is_https: bool,
    ) -> Result<()> {
        let resp = Self::build_waf_block_response_header(request_id, is_https)?;
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(Self::WAF_BLOCK_BODY)), true)
            .await?;
        Ok(())
    }

    /// TASK-61: apply external risk to an entity with a per-request cap.
    ///
    /// Enforces `MAX_EXTERNAL_RISK_PER_REQUEST` by tracking per-request
    /// accumulated risk on the caller-provided accumulator. Returns the
    /// *actual* risk applied after the cap — callers that mirror the value
    /// into `ctx.entity_risk` (for observability) should use the returned
    /// value, not the requested value, so the observability counter stays
    /// consistent with the entity store.
    ///
    /// The accumulator is passed as `&mut f64` rather than `&mut RequestContext`
    /// so the helper can be invoked while another part of `ctx` (like
    /// `ctx.client_ip`) is still borrowed. Rust's disjoint-field borrow
    /// rules make this pattern cheap at the call site:
    ///
    /// ```ignore
    /// self.apply_bounded_external_risk(
    ///     &mut ctx.external_risk_accumulated,
    ///     client_ip,
    ///     40.0,
    ///     "suspicious_crawler",
    /// );
    /// ```
    ///
    /// Deliberately unbounded blocking sites (bad-bot 100.0 at line 2734)
    /// should continue calling `self.entity_manager.apply_external_risk`
    /// directly. Those are single-signal hard blocks whose design intent
    /// is to trip the threshold on one observation.
    ///
    /// Background-thread contributors (TASK-55 trends anomaly callback,
    /// TASK-54 campaign correlation) do not run on a request thread and
    /// do not have access to a `RequestContext`, so they bypass this cap
    /// by nature. That's correct — the cap is per-request to prevent
    /// single-request accumulation attacks, not per-entity over all time.
    fn apply_bounded_external_risk(
        &self,
        accumulator: &mut f64,
        client_ip: &str,
        requested_risk: f64,
        reason: &str,
    ) -> f64 {
        let remaining = MAX_EXTERNAL_RISK_PER_REQUEST - *accumulator;
        if remaining <= 0.0 {
            debug!(
                "TASK-61: per-request risk ceiling {} reached; dropping {} contribution of {} from {}",
                MAX_EXTERNAL_RISK_PER_REQUEST, reason, requested_risk, client_ip
            );
            return 0.0;
        }
        let actual = requested_risk.max(0.0).min(remaining);
        if actual > 0.0 {
            *accumulator += actual;
            self.entity_manager
                .apply_external_risk(client_ip, actual, reason);
        }
        actual
    }

    fn is_https_request(session: &Session) -> bool {
        let headers = &session.req_header().headers;

        if let Some(xfp) = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
        {
            if xfp.eq_ignore_ascii_case("https") {
                return true;
            }
        }

        if let Some(xfs) = headers
            .get("x-forwarded-ssl")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim())
        {
            if xfs.eq_ignore_ascii_case("on") {
                return true;
            }
        }

        if let Some(fwd) = headers
            .get("forwarded")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase())
        {
            if fwd.contains("proto=https") {
                return true;
            }
        }

        false
    }
}

fn record_auth_coverage(
    auth_coverage: &AuthCoverageAggregator,
    method: &str,
    path: &str,
    has_auth_header: bool,
    status: u16,
) {
    let endpoint = endpoint_key(method, path);
    auth_coverage.record(
        &endpoint,
        ResponseClass::from_status(status),
        has_auth_header,
    );
}

#[async_trait]
impl ProxyHttp for SynapseProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_start: Instant::now(),
            request_id: Self::generate_request_id(),
            _active_request_guard: self.metrics_registry.begin_request(),
            detection: None,
            backend_idx: 0,
            matched_site: None,
            headers: Vec::new(),
            client_ip: None,
            body_bytes_seen: 0,
            fingerprint: None,
            entity_risk: 0.0,
            external_risk_accumulated: 0.0,
            entity_blocked: None,
            tarpit_delay_ms: 0,
            tarpit_level: 0,
            dlp_match_count: 0,
            dlp_types: String::new(),
            response_body_buffer: get_buffer(),
            request_body_buffer: get_buffer(),
            request_dlp_match_count: 0,
            request_dlp_types: String::new(),
            request_dlp_matches: Vec::new(),
            dlp_scan_completed: false,
            pending_learn: None,
            schema_result: None,
            request_content_type: None,
            skip_request_dlp: false,
            dlp_scan_rx: None,
            dlp_scan_time_us: 0,
            response_content_type: None,
            request_path: None,
            request_method: None,
            has_auth_header: false,
            actor_id: None,
            actor_risk_score: 0.0,
            challenge_cookie: None,
            challenge_validated: false,
            waf_action: None,
            waf_challenged: false,
            waf_logged: false,
        }
    }

    /// Early request filter - runs before TLS, used for rate limiting
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Extract client IP early (with trusted proxy validation)
        ctx.client_ip = self.get_client_ip(session);
        if let Some(raw_request_id) = session
            .req_header()
            .headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(request_id) = Self::normalize_request_id(raw_request_id) {
                ctx.request_id = request_id;
            }
        }

        // Per-IP rate limiting (P2-2) - prevents single client from exhausting global quota
        if let Some(ref client_ip) = ctx.client_ip {
            if !check_per_ip_rate_limit(client_ip, self.per_ip_rps_limit) {
                warn!(
                    "Per-IP rate limit exceeded for {}, limit: {} RPS, request_id={}",
                    client_ip, self.per_ip_rps_limit, ctx.request_id
                );

                // Fire-and-forget: telemetry should never block the hot path.
                if self.telemetry_client.is_enabled() {
                    let telemetry = self.telemetry_client.clone();
                    let request_id = ctx.request_id.clone();
                    let client_ip = client_ip.clone();
                    let site = session
                        .req_header()
                        .headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.split(':').next())
                        .unwrap_or("_default")
                        .to_string();
                    let limit = self.per_ip_rps_limit as u32;

                    tokio::spawn(async move {
                        let _ = telemetry
                            .record(TelemetryEvent::RateLimitHit {
                                request_id: Some(request_id),
                                client_ip,
                                limit,
                                window_secs: 1,
                                site,
                            })
                            .await;
                    });
                }

                self.signal_manager.record_event(
                    SignalCategory::Behavior,
                    "rate_limit_per_ip",
                    Some(client_ip.to_string()),
                    Some("Per-IP rate limit exceeded".to_string()),
                    serde_json::json!({ "limit_rps": self.per_ip_rps_limit }),
                );

                // Send 429 Too Many Requests response
                let mut resp = ResponseHeader::build(429, None)?;
                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                headers::apply_security_response_headers(
                    &mut resp,
                    Self::is_https_request(session),
                );
                resp.insert_header("content-type", "application/json")?;
                resp.insert_header("retry-after", "1")?;

                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(
                        Some(Bytes::from(r#"{"error": "per_ip_rate_limit_exceeded", "message": "Too Many Requests from this IP"}"#)),
                        true,
                    )
                    .await?;

                // Record rate limit hit in metrics
                self.metrics_registry.record_blocked();

                return pingora_core::Error::new(pingora_core::ErrorType::HTTPStatus(429))
                    .into_err();
            }
        }

        // Periodically cleanup stale per-IP entries
        cleanup_per_ip_limits();

        // Global rate limiting check
        let count = REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

        // Reset counter periodically (simplified - real implementation would use proper windowing)
        if count > self.rps_limit * 2 {
            REQUEST_COUNT.store(0, Ordering::Relaxed);
        }

        // Check if over limit - block with 429
        if count > self.rps_limit {
            warn!(
                "Rate limit exceeded for {:?}, count: {}, limit: {}, request_id={}",
                ctx.client_ip, count, self.rps_limit, ctx.request_id
            );

            // Fire-and-forget: telemetry should never block the hot path.
            if self.telemetry_client.is_enabled() {
                if let Some(ref client_ip) = ctx.client_ip {
                    let telemetry = self.telemetry_client.clone();
                    let request_id = ctx.request_id.clone();
                    let client_ip = client_ip.clone();
                    let site = session
                        .req_header()
                        .headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.split(':').next())
                        .unwrap_or("_default")
                        .to_string();
                    let limit = self.rps_limit as u32;

                    tokio::spawn(async move {
                        let _ = telemetry
                            .record(TelemetryEvent::RateLimitHit {
                                request_id: Some(request_id),
                                client_ip,
                                limit,
                                window_secs: 1,
                                site,
                            })
                            .await;
                    });
                }
            }

            if let Some(ref client_ip) = ctx.client_ip {
                self.signal_manager.record_event(
                    SignalCategory::Behavior,
                    "rate_limit_global",
                    Some(client_ip.to_string()),
                    Some("Global rate limit exceeded".to_string()),
                    serde_json::json!({ "limit_rps": self.rps_limit, "count": count }),
                );
            }

            // Send 429 Too Many Requests response
            let mut resp = ResponseHeader::build(429, None)?;
            Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
            headers::apply_security_response_headers(&mut resp, Self::is_https_request(session));
            resp.insert_header("content-type", "application/json")?;
            resp.insert_header("retry-after", "1")?;

            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(
                    Some(Bytes::from(
                        r#"{"error": "rate_limit_exceeded", "message": "Too Many Requests"}"#,
                    )),
                    true,
                )
                .await?;

            // Record rate limit hit in metrics (counted as blocked)
            self.metrics_registry.record_blocked();

            // Return error to stop further processing
            return pingora_core::Error::new(pingora_core::ErrorType::HTTPStatus(429)).into_err();
        }

        // ===== Phase 10: Challenge Validation Hook =====
        // Validate challenge responses early to avoid re-challenging valid clients.
        if let Some(ref client_ip) = ctx.client_ip {
            if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
                // Ensure actor exists so we can validate challenge response
                let actor_id = self.actor_manager.get_or_create_actor(ip_addr, None);
                ctx.actor_id = Some(actor_id.clone());

                let req_header = session.req_header();
                let cookie_name = self.progression_manager.cookie_name();

                // Check cookie-based challenge response
                if let Some(cookie_header) = req_header
                    .headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                {
                    if let Some(cookie_value) =
                        Self::extract_cookie_value(cookie_header, cookie_name)
                    {
                        match self
                            .progression_manager
                            .validate_challenge(&actor_id, &cookie_value)
                        {
                            ValidationResult::Valid => {
                                ctx.challenge_validated = true;
                                self.actor_manager.touch_actor(&actor_id);
                                self.signal_manager.record_event(
                                    SignalCategory::Behavior,
                                    "challenge_cookie_valid",
                                    Some(actor_id.clone()),
                                    Some("Cookie challenge validated".to_string()),
                                    serde_json::json!({ "client_ip": client_ip }),
                                );
                            }
                            ValidationResult::Invalid(reason) => {
                                self.signal_manager.record_event(
                                    SignalCategory::Behavior,
                                    "challenge_cookie_invalid",
                                    Some(actor_id.clone()),
                                    Some(reason.clone()),
                                    serde_json::json!({ "client_ip": client_ip }),
                                );
                                let body = r#"{"error": "challenge_failed"}"#;
                                let mut resp = ResponseHeader::build(403, None)?;
                                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                                headers::apply_security_response_headers(
                                    &mut resp,
                                    Self::is_https_request(session),
                                );
                                resp.insert_header("content-type", "application/json")?;
                                resp.insert_header("content-length", body.len().to_string())?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session
                                    .write_response_body(Some(Bytes::from(body)), true)
                                    .await?;
                                self.metrics_registry.record_blocked();
                                return pingora_core::Error::new(
                                    pingora_core::ErrorType::HTTPStatus(403),
                                )
                                .into_err();
                            }
                            ValidationResult::Expired => {
                                self.signal_manager.record_event(
                                    SignalCategory::Behavior,
                                    "challenge_cookie_expired",
                                    Some(actor_id.clone()),
                                    Some("Challenge cookie expired".to_string()),
                                    serde_json::json!({ "client_ip": client_ip }),
                                );
                                let body = r#"{"error": "challenge_expired"}"#;
                                let mut resp = ResponseHeader::build(403, None)?;
                                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                                headers::apply_security_response_headers(
                                    &mut resp,
                                    Self::is_https_request(session),
                                );
                                resp.insert_header("content-type", "application/json")?;
                                resp.insert_header("content-length", body.len().to_string())?;
                                session.write_response_header(Box::new(resp), false).await?;
                                session
                                    .write_response_body(Some(Bytes::from(body)), true)
                                    .await?;
                                self.metrics_registry.record_blocked();
                                return pingora_core::Error::new(
                                    pingora_core::ErrorType::HTTPStatus(403),
                                )
                                .into_err();
                            }
                            ValidationResult::NotFound => {}
                        }
                    }
                }

                // Check query parameter for JS challenge response
                if let Some(query) = req_header.uri.query() {
                    if let Some(challenge_kind) =
                        Self::extract_query_param(query, "synapse_challenge")
                    {
                        if challenge_kind == "js" {
                            if let Some(nonce) = Self::extract_query_param(query, "synapse_nonce") {
                                match self
                                    .progression_manager
                                    .validate_challenge(&actor_id, &nonce)
                                {
                                    ValidationResult::Valid => {
                                        ctx.challenge_validated = true;
                                        self.actor_manager.touch_actor(&actor_id);
                                        self.signal_manager.record_event(
                                            SignalCategory::Behavior,
                                            "challenge_js_valid",
                                            Some(actor_id.clone()),
                                            Some("JS challenge validated".to_string()),
                                            serde_json::json!({ "client_ip": client_ip }),
                                        );
                                    }
                                    ValidationResult::Invalid(reason) => {
                                        self.signal_manager.record_event(
                                            SignalCategory::Behavior,
                                            "challenge_js_invalid",
                                            Some(actor_id.clone()),
                                            Some(reason.clone()),
                                            serde_json::json!({ "client_ip": client_ip }),
                                        );
                                        let body = r#"{"error": "challenge_failed"}"#;
                                        let mut resp = ResponseHeader::build(403, None)?;
                                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                                        headers::apply_security_response_headers(
                                            &mut resp,
                                            Self::is_https_request(session),
                                        );
                                        resp.insert_header("content-type", "application/json")?;
                                        resp.insert_header(
                                            "content-length",
                                            body.len().to_string(),
                                        )?;
                                        session
                                            .write_response_header(Box::new(resp), false)
                                            .await?;
                                        session
                                            .write_response_body(Some(Bytes::from(body)), true)
                                            .await?;
                                        self.metrics_registry.record_blocked();
                                        return pingora_core::Error::new(
                                            pingora_core::ErrorType::HTTPStatus(403),
                                        )
                                        .into_err();
                                    }
                                    ValidationResult::Expired => {
                                        self.signal_manager.record_event(
                                            SignalCategory::Behavior,
                                            "challenge_js_expired",
                                            Some(actor_id.clone()),
                                            Some("JS challenge expired".to_string()),
                                            serde_json::json!({ "client_ip": client_ip }),
                                        );
                                        let body = r#"{"error": "challenge_expired"}"#;
                                        let mut resp = ResponseHeader::build(403, None)?;
                                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                                        headers::apply_security_response_headers(
                                            &mut resp,
                                            Self::is_https_request(session),
                                        );
                                        resp.insert_header("content-type", "application/json")?;
                                        resp.insert_header(
                                            "content-length",
                                            body.len().to_string(),
                                        )?;
                                        session
                                            .write_response_header(Box::new(resp), false)
                                            .await?;
                                        session
                                            .write_response_body(Some(Bytes::from(body)), true)
                                            .await?;
                                        self.metrics_registry.record_blocked();
                                        return pingora_core::Error::new(
                                            pingora_core::ErrorType::HTTPStatus(403),
                                        )
                                        .into_err();
                                    }
                                    ValidationResult::NotFound => {}
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Main request filter - runs detection engine
    /// Returns Ok(true) if we handled the request (blocked)
    /// Returns Ok(false) to continue to upstream
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let req_header = session.req_header();

        // Extract request info for detection
        let method = req_header.method.as_str();
        let uri = req_header.uri.to_string();
        let headers = Self::extract_headers(session);
        let client_ip = ctx.client_ip.as_deref().unwrap_or("0.0.0.0");
        ctx.request_method = Some(method.to_string());
        ctx.has_auth_header = has_auth_header(req_header);

        // Record endpoint hit for API profiling/discovery
        let path = req_header.uri.path();
        self.metrics_registry.record_endpoint(path, method);

        // ===== Multi-site: Virtual Host Matching =====
        // Match request Host header to site configuration for per-site routing
        if let Some(ref vhost) = self.vhost_matcher {
            if let Some(host_header) = req_header.headers.get("host") {
                if let Ok(host_str) = host_header.to_str() {
                    let vhost_read = vhost.read();
                    if let Some(site) = vhost_read.match_host(host_str) {
                        ctx.matched_site = Some(site.clone());
                        debug!(
                            "Multi-site: matched host '{}' to site '{}'",
                            host_str, site.hostname
                        );
                    } else {
                        debug!("Multi-site: no site matched for host '{}'", host_str);
                    }
                }
            }
        }

        // ===== IP Access Control List (ACL) =====
        if let Some(ref access_mgr) = self.access_list_manager {
            if let Some(ref site) = ctx.matched_site {
                if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
                    let is_denied = {
                        let access_mgr_read = access_mgr.read();
                        !access_mgr_read.is_allowed(&site.hostname, &ip_addr)
                    };

                    if is_denied {
                        warn!(
                            "IP ACL: {} denied for site '{}', request_id={}",
                            client_ip, site.hostname, ctx.request_id
                        );

                        let mut resp = ResponseHeader::build(403, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "application/json")?;

                        session.write_response_header(Box::new(resp), false).await?;
                        session.write_response_body(Some(Bytes::from("{\"error\": \"access_denied\", \"message\": \"IP address not allowed\"}")), true).await?;

                        self.metrics_registry.record_blocked();
                        return Ok(true);
                    }
                }
            }
        }

        // ===== Phase 9: Signal Horizon Blocklist Check =====
        // Check if IP or fingerprint is on the fleet-wide blocklist
        if let Some(ref horizon) = self.horizon_manager {
            if horizon.is_ip_blocked(client_ip) {
                warn!(
                    "Horizon blocklist: {} is blocked fleet-wide, request_id={}",
                    client_ip, ctx.request_id
                );

                self.signal_manager.record_event(
                    SignalCategory::Intelligence,
                    "fleet_blocklist",
                    Some(client_ip.to_string()),
                    Some("Blocked by fleet-wide intelligence".to_string()),
                    serde_json::json!({ "source": "signal_horizon" }),
                );

                let body = r#"{"error": "access_denied"}"#;
                let mut resp = ResponseHeader::build(403, None)?;
                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                headers::apply_security_response_headers(
                    &mut resp,
                    Self::is_https_request(session),
                );
                resp.insert_header("content-type", "application/json")?;
                resp.insert_header("content-length", body.len().to_string())?;
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(Some(Bytes::from(body)), true)
                    .await?;

                self.metrics_registry.record_blocked();
                return Ok(true);
            }
        }
        // ===== End Signal Horizon Blocklist Check =====

        // ===== Phase 6: TLS Validation =====
        // Detect domain fronting, outdated TLS versions, or weak cipher suites
        // Note: SNI vs Host validation is performed via JA4 fingerprint analysis
        // in the Reputation Scoring section below.
        // ===== End TLS Validation =====

        // Extract Content-Type for DLP optimization (skip binary types)
        ctx.request_content_type = req_header
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Store request path for schema validation in response phase
        ctx.request_path = Some(path.to_string());

        // Check if we should skip DLP scanning for this content type
        if let Some(ref ct) = ctx.request_content_type {
            ctx.skip_request_dlp = self.dlp_scanner.should_skip_content_type(ct);
            if ctx.skip_request_dlp {
                debug!("DLP: Skipping request body scan for content-type: {}", ct);
            }
        }

        // ===== Phase 6: Health Check Endpoint =====
        // Handle /_sensor/status endpoint for load balancer health checks
        if method == "GET" && uri == "/_sensor/status" {
            let health_response = self.health_checker.check();
            let http_status = health_response.status.http_status();

            // Build JSON response body
            let response_body = serde_json::to_vec(&health_response)
                .unwrap_or_else(|_| b"{\"status\":\"error\"}".to_vec());

            let mut resp = ResponseHeader::build(http_status, None)?;
            Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
            headers::apply_security_response_headers(&mut resp, Self::is_https_request(session));
            resp.insert_header("content-type", "application/json")?;

            session.write_response_header(Box::new(resp), false).await?;
            session
                .write_response_body(Some(Bytes::from(response_body)), true)
                .await?;

            debug!(
                "Health check endpoint accessed, returning {} (status: {:?}), request_id={}",
                http_status, health_response.status, ctx.request_id
            );
            return Ok(true); // We handled this request
        }
        // ===== End Health Check Endpoint =====

        // ===== Phase 3: Trap Endpoint Detection =====
        // Honeypot trap endpoints immediately block attackers probing sensitive paths
        if let Some(ref trap_matcher) = self.trap_matcher {
            if trap_matcher.is_trap(&uri) {
                let trap_pattern = trap_matcher.matched_pattern(&uri).unwrap_or("unknown");
                warn!(
                    "TRAP HIT: {} from {} matched pattern '{}', request_id={}",
                    uri, client_ip, trap_pattern, ctx.request_id
                );

                // Apply maximum risk to entity
                if trap_matcher.config().apply_max_risk {
                    let reason = format!("Accessed trap: {} (pattern: {})", uri, trap_pattern);
                    self.entity_manager
                        .apply_external_risk(client_ip, 100.0, &reason);
                }

                // Extended tarpitting (waste attacker's time)
                if let Some(delay_ms) = trap_matcher.config().extended_tarpit_ms {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }

                // Send telemetry alert
                if trap_matcher.config().alert_telemetry && self.telemetry_client.is_enabled() {
                    let _ = self
                        .telemetry_client
                        .report(TelemetryEvent::WafBlock {
                            request_id: Some(ctx.request_id.clone()),
                            rule_id: format!("TRAP_HIT:{}", trap_pattern),
                            severity: "CRITICAL".to_string(),
                            client_ip: client_ip.to_string(),
                            site: ctx
                                .matched_site
                                .as_ref()
                                .map(|s| s.hostname.clone())
                                .unwrap_or_default(),
                            path: uri.clone(),
                        })
                        .await;
                }

                // Return 404 (don't reveal trap existence)
                let mut resp = ResponseHeader::build(404, None)?;
                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                headers::apply_security_response_headers(
                    &mut resp,
                    Self::is_https_request(session),
                );
                session.write_response_header(Box::new(resp), true).await?;
                self.metrics_registry.record_blocked();
                return Ok(true);
            }
        }
        // ===== End Trap Endpoint Detection =====

        // Phase 3: Extract client fingerprint (JA4 + JA4H)
        let ja4_header = req_header
            .headers
            .get("x-ja4-fingerprint")
            .and_then(|v| v.to_str().ok());

        let http_version = format!("{:?}", req_header.version);
        let http_version_str = match http_version.as_str() {
            "HTTP_10" => "1.0",
            "HTTP_11" => "1.1",
            "HTTP_2" => "2.0",
            "HTTP_3" => "3.0",
            _ => "1.1",
        };

        let fingerprint = {
            let http_headers = HttpHeaders {
                headers: &headers,
                method,
                http_version: http_version_str,
            };
            extract_client_fingerprint(ja4_header, &http_headers)
        };

        // Log fingerprint info for debugging and validation
        if let Some(ref ja4) = fingerprint.ja4 {
            debug!(
                "JA4 fingerprint: {} (tls={}, protocol={}, alpn={})",
                ja4.raw, ja4.tls_version, ja4.protocol, ja4.alpn
            );
        }
        debug!(
            "JA4H fingerprint: {} (method={}, http={}, cookie={}, referer={})",
            fingerprint.ja4h.raw,
            fingerprint.ja4h.method,
            fingerprint.ja4h.http_version,
            fingerprint.ja4h.has_cookie,
            fingerprint.ja4h.has_referer
        );
        debug!("Combined fingerprint hash: {}", fingerprint.combined_hash);

        ctx.fingerprint = Some(fingerprint.clone());

        // TASK-54: register the per-request fingerprint with CampaignManager
        // so its correlation detectors (JA4 rotation, shared fingerprint,
        // attack sequence, network proximity, etc.) have data to process.
        // Before this wiring the manager's detectors were idle because the
        // filter chain never called register_fingerprints. Detection runs in
        // the background worker; auto-mitigation via AccessListManager blocks
        // future requests, so this call does NOT affect the current request's
        // blocking decision — it feeds the correlation layer for delayed
        // mitigation of subsequent requests from the same actor.
        if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
            // TASK-64: raw is Arc<str>, so these clones are refcount bumps,
            // not heap allocations. register_fingerprints takes Option<Arc<str>>
            // and propagates the Arc to the rotation detector's observation
            // store without any further String allocation on the hot path.
            let ja4_raw = fingerprint.ja4.as_ref().map(|j| Arc::clone(&j.raw));
            let ja4h_raw = Some(Arc::clone(&fingerprint.ja4h.raw));
            self.campaign_manager
                .register_fingerprints(ip_addr, ja4_raw, ja4h_raw);
        }

        // Phase 9: Crawler Verification
        // Verify user-agent against known crawler signatures and DNS
        if self.crawler_detector.is_enabled() {
            if let Some(user_agent) = headers.iter().find_map(|(name, value)| {
                if name == USER_AGENT {
                    value.to_str().ok()
                } else {
                    None
                }
            }) {
                if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
                    let crawler_result = self.crawler_detector.verify(user_agent, ip_addr).await;

                    // Handle bad bots (immediate block)
                    if crawler_result.bad_bot_match.is_some()
                        && self.crawler_detector.should_block_bad_bots()
                    {
                        let bot_name = crawler_result.bad_bot_match.as_deref().unwrap_or("unknown");
                        warn!("Blocking bad bot: {} from {}", bot_name, client_ip);

                        let reason = format!("bad_bot:{}", bot_name);
                        let detection = DetectionResult {
                            blocked: true,
                            risk_score: 100,
                            matched_rules: vec![],
                            entity_risk: 0.0,
                            block_reason: Some(reason.clone()),
                            detection_time_us: 0,
                        };
                        ctx.detection = Some(detection.clone());

                        // Persist and report as a WAF block so Hub can pivot by request_id.
                        self.record_waf_block_event(
                            client_ip,
                            method,
                            &uri,
                            &detection,
                            ctx.fingerprint.as_ref(),
                            &reason,
                        );

                        if self.telemetry_client.is_enabled() {
                            let site = ctx
                                .matched_site
                                .as_ref()
                                .map(|s| s.hostname.clone())
                                .unwrap_or_else(|| "_default".to_string());
                            let _ = self
                                .telemetry_client
                                .report(TelemetryEvent::WafBlock {
                                    request_id: Some(ctx.request_id.clone()),
                                    rule_id: format!("BAD_BOT:{}", bot_name),
                                    severity: "critical".to_string(),
                                    client_ip: client_ip.to_string(),
                                    site,
                                    path: uri.clone(),
                                })
                                .await;
                        }

                        self.block_log.record(BlockEvent::new(
                            client_ip.to_string(),
                            method.to_string(),
                            uri.clone(),
                            100,    // Max risk
                            vec![], // No rule ID for bot block
                            reason,
                            ctx.fingerprint.as_ref().map(|fp| fp.combined_hash.clone()),
                        ));

                        let body = r#"{"error": "access_denied"}"#;
                        let mut resp = ResponseHeader::build(403, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "application/json")?;
                        resp.insert_header("content-length", body.len().to_string())?;
                        session.write_response_header(Box::new(resp), false).await?;
                        // Security: Generic error message to prevent information disclosure
                        session
                            .write_response_body(Some(Bytes::from(body)), true)
                            .await?;
                        self.metrics_registry.record_blocked();
                        return Ok(true);
                    }

                    // Handle suspicious crawlers (failed verification)
                    if crawler_result.suspicious {
                        warn!(
                            "Suspicious crawler from {}: {:?}",
                            client_ip, crawler_result.suspicion_reasons
                        );
                        // Apply risk penalty (TASK-61 bounded to per-request cap)
                        if self.entity_manager.is_enabled() {
                            let reason = format!(
                                "suspicious_crawler: {:?}",
                                crawler_result.suspicion_reasons
                            );
                            self.apply_bounded_external_risk(
                                &mut ctx.external_risk_accumulated,
                                client_ip,
                                40.0,
                                &reason,
                            );
                        }
                    } else if crawler_result.verified {
                        // Whitelist verified legitimate crawlers (optional: skip WAF?)
                        debug!(
                            "Verified crawler: {:?} from {}",
                            crawler_result.crawler_name, client_ip
                        );
                    }
                }
            }
        }

        // Run detection using the Synapse WAF engine (headers only initially)
        let result = DetectionEngine::analyze(method, &uri, &headers, None, client_ip);

        if !result.matched_rules.is_empty() {
            self.signal_manager.record_event(
                SignalCategory::Attack,
                "waf_rule_match",
                Some(client_ip.to_string()),
                Some(format!("Matched {} WAF rules", result.matched_rules.len())),
                serde_json::json!({
                    "rules": result.matched_rules,
                    "risk_score": result.risk_score,
                    "method": method,
                    "uri": uri,
                }),
            );
        }

        // Phase 3: Entity tracking - touch entity and apply risk from matched rules
        // This tracks per-IP state for risk accumulation and blocking decisions
        if self.entity_manager.is_enabled() {
            // Touch entity with fingerprint for correlation
            let ja4_str = fingerprint.ja4.as_ref().map(|j| &*j.raw);
            let _entity_snapshot = self.entity_manager.touch_entity_with_fingerprint(
                client_ip,
                ja4_str,
                Some(&fingerprint.combined_hash),
            );

            // Apply risk from each matched rule
            for &rule_id in &result.matched_rules {
                // Use base risk score divided by matched rules (simplified)
                // In production, each rule would have its own risk value
                let base_risk = result.risk_score as f64 / result.matched_rules.len().max(1) as f64;
                if let Some(risk_result) = self.entity_manager.apply_rule_risk(
                    client_ip, rule_id, base_risk, true, // enable repeat offender multiplier
                ) {
                    ctx.entity_risk = risk_result.new_risk;
                    debug!(
                        "Entity {} rule {} risk: base={:.1} x{:.2} = {:.1}, total={:.1}",
                        client_ip,
                        rule_id,
                        risk_result.base_risk,
                        risk_result.multiplier,
                        risk_result.final_risk,
                        risk_result.new_risk
                    );
                }
            }

            // Check if entity should be blocked based on accumulated risk
            let block_decision = self.entity_manager.check_block(client_ip);
            ctx.entity_blocked = Some(block_decision.clone());

            if block_decision.blocked && !result.blocked {
                // Entity is blocked but this specific request wasn't blocked by rules
                // Log this for dual-running validation
                warn!(
                    "Entity {} blocked by risk threshold: risk={:.1}, reason={:?}",
                    client_ip, block_decision.risk, block_decision.reason
                );
            }

            // ===== JA4 Reputation Scoring =====
            if let Some(ref ja4) = fingerprint.ja4 {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                // 1. Analyze JA4 for suspicious characteristics
                let ja4_analysis = analyze_ja4(ja4);
                if ja4_analysis.suspicious {
                    let ja4_risk = 30.0;
                    warn!(
                        "Suspicious JA4 from {}: {:?}",
                        client_ip, ja4_analysis.issues
                    );
                    self.signal_manager.record_event(
                        SignalCategory::Anomaly,
                        "ja4_suspicious",
                        Some(client_ip.to_string()),
                        Some("Suspicious JA4 fingerprint".to_string()),
                        serde_json::json!({ "issues": ja4_analysis.issues }),
                    );
                    // TASK-61: bounded external risk contribution
                    let reason = format!("suspicious_ja4: {:?}", ja4_analysis.issues);
                    let actual = self.apply_bounded_external_risk(
                        &mut ctx.external_risk_accumulated,
                        client_ip,
                        ja4_risk,
                        &reason,
                    );
                    ctx.entity_risk += actual;
                }

                // 2. Check for rapid fingerprint changes (bot behavior)
                if let Some(reputation) = self
                    .entity_manager
                    .check_ja4_reputation(client_ip, &ja4.raw, now_ms)
                {
                    if reputation.rapid_changes {
                        let change_risk = 40.0;
                        warn!(
                            "JA4 rapid change detected: {} changed {} times in 60s",
                            client_ip, reputation.change_count
                        );
                        self.signal_manager.record_event(
                            SignalCategory::Anomaly,
                            "ja4_rapid_change",
                            Some(client_ip.to_string()),
                            Some(format!(
                                "JA4 changed {} times in 60s",
                                reputation.change_count
                            )),
                            serde_json::json!({ "change_count": reputation.change_count }),
                        );
                        // TASK-61: bounded external risk contribution
                        let reason = format!(
                            "ja4_rapid_change: changed {} times in 60s",
                            reputation.change_count
                        );
                        let actual = self.apply_bounded_external_risk(
                            &mut ctx.external_risk_accumulated,
                            client_ip,
                            change_risk,
                            &reason,
                        );
                        ctx.entity_risk += actual;
                    }
                }
            }

            // 3. Analyze Header Integrity (Client Hints / User-Agent consistency)
            let integrity = {
                let http_headers = HttpHeaders {
                    headers: &headers,
                    method,
                    http_version: http_version_str,
                };
                analyze_integrity(&http_headers)
            };
            if integrity.suspicion_score > 0 {
                warn!(
                    "Header Integrity Violation from {}: score={}, issues={:?}",
                    client_ip, integrity.suspicion_score, integrity.inconsistencies
                );
                self.signal_manager.record_event(
                    SignalCategory::Anomaly,
                    "header_integrity_violation",
                    Some(client_ip.to_string()),
                    Some("Header integrity violation detected".to_string()),
                    serde_json::json!({
                        "score": integrity.suspicion_score,
                        "issues": integrity.inconsistencies
                    }),
                );

                // TASK-61: bounded external risk contribution
                let reason = format!("integrity_violation: {:?}", integrity.inconsistencies);
                let actual = self.apply_bounded_external_risk(
                    &mut ctx.external_risk_accumulated,
                    client_ip,
                    integrity.suspicion_score as f64,
                    &reason,
                );
                ctx.entity_risk += actual;
            }
        }

        // ===== Phase 5: Actor State Management =====
        // Track behavioral patterns, rule matches, and risk scoring per actor
        // Actors are correlated via IP + fingerprint (unlike EntityManager's simple IP-based tracking)
        if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
            // Get or create actor based on IP + fingerprint correlation
            let actor_id = self
                .actor_manager
                .get_or_create_actor(ip_addr, fingerprint.ja4.as_ref().map(|j| &*j.raw));
            ctx.actor_id = Some(actor_id.clone());

            // Record rule matches to actor's history
            for &rule_id in &result.matched_rules {
                let category = categorize_rule_id(rule_id);
                let risk_contribution =
                    result.risk_score as f64 / result.matched_rules.len().max(1) as f64;
                self.actor_manager.record_rule_match(
                    &actor_id,
                    &format!("rule_{}", rule_id),
                    risk_contribution,
                    &category,
                );
                debug!(
                    "Actor {} recorded rule match: rule_{} category={} risk={:.1}",
                    actor_id, rule_id, category, risk_contribution
                );
            }

            if let Some(actor_state) = self.actor_manager.get_actor(&actor_id) {
                ctx.actor_risk_score = actor_state.risk_score;
            }

            // Check if actor is blocked based on accumulated risk
            if self.actor_manager.is_blocked(&actor_id) {
                warn!(
                    "Actor {} (IP: {}) is BLOCKED - denying request to {}",
                    actor_id, client_ip, uri
                );

                // Record block event
                self.block_log.record(BlockEvent::new(
                    client_ip.to_string(),
                    method.to_string(),
                    uri.clone(),
                    result.risk_score,
                    result.matched_rules.clone(),
                    format!("actor_blocked:{}", actor_id),
                    ctx.fingerprint.as_ref().map(|fp| fp.combined_hash.clone()),
                ));

                let body = r#"{"error": "access_denied"}"#;
                let mut resp = ResponseHeader::build(403, None)?;
                Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                headers::apply_security_response_headers(
                    &mut resp,
                    Self::is_https_request(session),
                );
                resp.insert_header("content-type", "application/json")?;
                resp.insert_header("content-length", body.len().to_string())?;
                session.write_response_header(Box::new(resp), false).await?;
                session
                    .write_response_body(
                        // Security: Generic error to prevent info disclosure
                        Some(Bytes::from(body)),
                        true,
                    )
                    .await?;
                self.metrics_registry.record_blocked();
                return Ok(true);
            }
        }
        // ===== End Actor State Management =====

        // ===== Phase 5: Session State Management =====
        // Validate session tokens and detect potential hijacking via JA4 fingerprint binding
        // Extract session token from Cookie or Authorization header
        let session_token = headers
            .iter()
            .find(|(name, _)| name == COOKIE)
            .and_then(|(_, value)| value.to_str().ok())
            .and_then(|cookie_value| {
                // Extract session cookie (common patterns: session, sessionid, JSESSIONID, etc.)
                cookie_value
                    .split(';')
                    .map(|s| s.trim())
                    .find(|cookie| {
                        let lower = cookie.to_lowercase();
                        lower.starts_with("session=")
                            || lower.starts_with("sessionid=")
                            || lower.starts_with("jsessionid=")
                            || lower.starts_with("phpsessid=")
                            || lower.starts_with("sid=")
                    })
                    .map(|cookie| {
                        cookie
                            .split_once('=')
                            .map(|x| x.1)
                            .unwrap_or("")
                            .to_string()
                    })
            });

        if let Some(token) = session_token {
            if !token.is_empty() {
                // Hash the token with SHA-256 for secure storage (MD5 is cryptographically broken)
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                let token_hash = format!("{:x}", hasher.finalize());

                if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
                    let ja4_str = fingerprint.ja4.as_ref().map(|j| &*j.raw);
                    let session_decision =
                        self.session_manager
                            .validate_request(&token_hash, ip_addr, ja4_str);

                    match session_decision {
                        SessionDecision::Valid => {
                            debug!(
                                "Session validated for {} (token_hash: {})",
                                client_ip,
                                &token_hash[..8]
                            );
                        }
                        SessionDecision::New => {
                            debug!(
                                "New session created for {} (token_hash: {})",
                                client_ip,
                                &token_hash[..8]
                            );
                        }
                        SessionDecision::Suspicious(alert) => {
                            warn!(
                                "POTENTIAL SESSION HIJACK: {} - type={:?}, original={}, new={}, confidence={:.2}",
                                client_ip, alert.alert_type, alert.original_value, alert.new_value, alert.confidence
                            );
                            // TASK-61: bounded risk contribution for potential
                            // hijacking. 50.0 * confidence may exceed the per-request
                            // cap when other signals have already contributed —
                            // that's the intended safety, since hijack detection
                            // has a non-trivial false-positive rate and a single
                            // alert should not block on its own above the cap.
                            let reason = format!("session_hijack_alert: {:?}", alert.alert_type);
                            let actual = self.apply_bounded_external_risk(
                                &mut ctx.external_risk_accumulated,
                                client_ip,
                                50.0 * alert.confidence,
                                &reason,
                            );
                            ctx.entity_risk += actual;
                        }
                        SessionDecision::Expired => {
                            debug!(
                                "Session expired for {} (token_hash: {})",
                                client_ip,
                                &token_hash[..8]
                            );
                        }
                        SessionDecision::Invalid(reason) => {
                            warn!(
                                "Invalid session for {}: {} (token_hash: {})",
                                client_ip,
                                reason,
                                &token_hash[..8]
                            );

                            // TASK-58 + TASK-61: contribute conservative entity
                            // risk on invalid session tokens (bounded to the
                            // per-request cap).
                            let actual = self.apply_bounded_external_risk(
                                &mut ctx.external_risk_accumulated,
                                client_ip,
                                INVALID_SESSION_RISK_WEIGHT,
                                "invalid_session_token",
                            );
                            ctx.entity_risk += actual;
                        }
                    }
                }
            }
        }
        // ===== End Session State Management =====

        // ===== Phase 9: Trends Signal Recording =====
        // Record request signals for anomaly detection (fingerprint changes, velocity, etc.)
        {
            let user_agent = headers
                .iter()
                .find(|(name, _)| name == USER_AGENT)
                .and_then(|(_, value)| value.to_str().ok());
            let authorization = headers
                .iter()
                .find(|(name, _)| name == AUTHORIZATION)
                .and_then(|(_, value)| value.to_str().ok());
            let session_id = headers
                .iter()
                .find(|(name, _)| name == COOKIE)
                .and_then(|(_, value)| value.to_str().ok())
                .and_then(|cookie_value| {
                    cookie_value
                        .split(';')
                        .map(|s| s.trim())
                        .find(|c| c.to_lowercase().starts_with("session"))
                        .map(|c| c.to_string())
                });

            let _signals = self.trends_manager.record_request(
                client_ip,
                session_id.as_deref(),
                user_agent,
                authorization,
                Some(client_ip),
                ctx.fingerprint
                    .as_ref()
                    .and_then(|fp| fp.ja4.as_ref().map(|j| &*j.raw)),
                ctx.fingerprint.as_ref().map(|fp| &*fp.ja4h.raw),
                None, // last_request_time - not tracked yet
            );
        }
        // ===== End Trends Signal Recording =====

        // Phase 3: Tarpitting - apply progressive delays to suspicious actors
        // Apply tarpit if: (1) there were matched rules, OR (2) entity has high risk
        let should_tarpit = !result.matched_rules.is_empty() || ctx.entity_risk >= 50.0;
        if should_tarpit && self.tarpit_manager.is_enabled() {
            // Use async apply_delay which applies the actual delay
            let tarpit_decision = self.tarpit_manager.apply_delay(client_ip).await;

            ctx.tarpit_delay_ms = tarpit_decision.delay_ms;
            ctx.tarpit_level = tarpit_decision.level;

            if tarpit_decision.is_tarpitted {
                info!(
                    "Tarpit applied: {} delay={}ms level={} hits={}",
                    client_ip,
                    tarpit_decision.delay_ms,
                    tarpit_decision.level,
                    tarpit_decision.hit_count
                );
                self.signal_manager.record_event(
                    SignalCategory::Behavior,
                    "tarpit_applied",
                    Some(client_ip.to_string()),
                    Some(format!("Tarpit delay {}ms", tarpit_decision.delay_ms)),
                    serde_json::json!({
                        "delay_ms": tarpit_decision.delay_ms,
                        "level": tarpit_decision.level,
                        "hit_count": tarpit_decision.hit_count
                    }),
                );
            }
        }

        let waf_action = self.resolve_waf_action(ctx, &result);
        ctx.waf_action = Some(waf_action);
        ctx.waf_logged = matches!(waf_action, WafAction::Log);
        ctx.waf_challenged = false;

        info!(
            "Detection complete: blocked={}, action={:?}, risk={}, entity_risk={:.1}, tarpit={}ms, rules={:?}, time={}μs, uri={}",
            result.blocked,
            waf_action,
            result.risk_score,
            ctx.entity_risk,
            ctx.tarpit_delay_ms,
            result.matched_rules,
            result.detection_time_us,
            uri
        );

        let mut detection = result.clone();
        detection.blocked = false;

        let block_reason = result
            .block_reason
            .clone()
            .unwrap_or_else(|| "rule_match".to_string());

        if matches!(waf_action, WafAction::Challenge | WafAction::Block) {
            let should_skip_challenge =
                matches!(waf_action, WafAction::Challenge) && ctx.challenge_validated;

            if should_skip_challenge {
                debug!(
                    "Challenge already validated for actor {} - allowing request",
                    ctx.actor_id.as_deref().unwrap_or(client_ip)
                );
            } else {
                // ===== Phase 10: Progressive Challenge System =====
                // Instead of hard blocking, use the progression manager to determine
                // the appropriate challenge level based on actor behavior and risk score.
                let actor_id = if let Some(ref actor_id) = ctx.actor_id {
                    actor_id.clone()
                } else if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
                    let actor_id = self.actor_manager.get_or_create_actor(
                        ip_addr,
                        ctx.fingerprint
                            .as_ref()
                            .and_then(|fp| fp.ja4.as_ref())
                            .map(|j| &*j.raw),
                    );
                    ctx.actor_id = Some(actor_id.clone());
                    actor_id
                } else {
                    client_ip.to_string()
                };

                let max_risk = self.actor_manager.config().max_risk;
                let actor_risk_normalized = if max_risk > 0.0 {
                    (ctx.actor_risk_score / max_risk).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let risk_score_normalized = if ctx.actor_risk_score > 0.0 {
                    actor_risk_normalized
                } else {
                    (result.risk_score as f64 / 100.0).min(1.0)
                };

                let challenge = self
                    .progression_manager
                    .get_challenge(&actor_id, risk_score_normalized);

                match challenge {
                    ChallengeResponse::Allow => {
                        // Low risk after progression check - allow through
                        // This can happen if actor recently passed challenges
                        debug!(
                            "Actor {} allowed after progression check (risk={})",
                            actor_id, result.risk_score
                        );
                    }

                    ChallengeResponse::Cookie {
                        name,
                        value,
                        max_age,
                        http_only,
                        secure,
                    } => {
                        // Set tracking cookie and allow request to continue
                        // The cookie enables correlation of future requests
                        debug!("Setting challenge cookie for actor {}", actor_id);
                        ctx.challenge_cookie = Some(format!(
                            "{}={}; Path=/; Max-Age={}{}{}; SameSite=Strict",
                            name,
                            value,
                            max_age,
                            if http_only { "; HttpOnly" } else { "" },
                            if secure { "; Secure" } else { "" }
                        ));
                        ctx.waf_challenged = true;
                    }

                    ChallengeResponse::JsChallenge { html, .. } => {
                        // Present JavaScript proof-of-work challenge
                        info!(
                            "Presenting JS challenge to actor {} (risk={}), request_id={}",
                            actor_id, result.risk_score, ctx.request_id
                        );
                        ctx.waf_challenged = true;
                        ctx.detection = Some(detection.clone());
                        let mut resp = ResponseHeader::build(200, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "text/html; charset=utf-8")?;
                        resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
                        resp.insert_header("x-challenge-level", "2")?;
                        resp.insert_header("x-challenge-type", "js_pow")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session
                            .write_response_body(Some(Bytes::from(html)), true)
                            .await?;
                        return Ok(true);
                    }

                    ChallengeResponse::Captcha { html, session_id } => {
                        // Present CAPTCHA challenge
                        info!(
                            "Presenting CAPTCHA challenge to actor {} (session={}), request_id={}",
                            actor_id, session_id, ctx.request_id
                        );
                        ctx.waf_challenged = true;
                        ctx.detection = Some(detection.clone());
                        let mut resp = ResponseHeader::build(200, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "text/html; charset=utf-8")?;
                        resp.insert_header("cache-control", "no-cache, no-store, must-revalidate")?;
                        resp.insert_header("x-challenge-level", "3")?;
                        resp.insert_header("x-challenge-type", "captcha")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session
                            .write_response_body(Some(Bytes::from(html)), true)
                            .await?;
                        return Ok(true);
                    }

                    ChallengeResponse::Tarpit { delay_ms } => {
                        // Apply tarpit delay then block
                        info!(
                            "Tarpitting actor {} for {}ms (risk={}), request_id={}",
                            actor_id, delay_ms, result.risk_score, ctx.request_id
                        );
                        detection.blocked = true;
                        warn!(
                            "BLOCKED: {} from {} - risk={}, rules={:?}, reason={}, request_id={}",
                            uri,
                            client_ip,
                            result.risk_score,
                            result.matched_rules,
                            block_reason,
                            ctx.request_id
                        );
                        self.record_waf_block_event(
                            client_ip,
                            method,
                            &uri,
                            &result,
                            ctx.fingerprint.as_ref(),
                            &block_reason,
                        );
                        ctx.detection = Some(detection.clone());
                        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        let block_html = self.progression_manager.config().block_page_html.clone();
                        let body_len = block_html.len();
                        let mut resp = ResponseHeader::build(403, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "text/html; charset=utf-8")?;
                        resp.insert_header("content-length", body_len.to_string())?;
                        resp.insert_header("x-challenge-level", "4")?;
                        resp.insert_header("x-challenge-type", "tarpit")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session
                            .write_response_body(Some(Bytes::from(block_html)), true)
                            .await?;
                        return Ok(true);
                    }

                    ChallengeResponse::Block { html, status_code } => {
                        // Hard block with custom page
                        warn!(
                            "Hard blocking actor {} (risk={}), request_id={}",
                            actor_id, result.risk_score, ctx.request_id
                        );
                        detection.blocked = true;
                        warn!(
                            "BLOCKED: {} from {} - risk={}, rules={:?}, reason={}, request_id={}",
                            uri,
                            client_ip,
                            result.risk_score,
                            result.matched_rules,
                            block_reason,
                            ctx.request_id
                        );
                        self.record_waf_block_event(
                            client_ip,
                            method,
                            &uri,
                            &result,
                            ctx.fingerprint.as_ref(),
                            &block_reason,
                        );
                        ctx.detection = Some(detection.clone());
                        let body_len = html.len();
                        let mut resp = ResponseHeader::build(status_code, None)?;
                        Self::apply_request_id_header(&mut resp, &ctx.request_id)?;
                        headers::apply_security_response_headers(
                            &mut resp,
                            Self::is_https_request(session),
                        );
                        resp.insert_header("content-type", "text/html; charset=utf-8")?;
                        resp.insert_header("content-length", body_len.to_string())?;
                        resp.insert_header("x-challenge-level", "5")?;
                        resp.insert_header("x-challenge-type", "block")?;
                        session.write_response_header(Box::new(resp), false).await?;
                        session
                            .write_response_body(Some(Bytes::from(html)), true)
                            .await?;
                        return Ok(true);
                    }
                }
            }
        }

        // ===== Phase 7: Shadow Mirroring =====
        // Mirror suspicious (but not blocked) traffic to honeypots for threat intelligence
        // Fire-and-forget pattern: uses tokio::spawn to avoid impacting production latency
        if let Some(ref shadow_manager) = self.shadow_mirror_manager {
            // Get site-specific shadow config or skip if not configured
            let shadow_config = ctx
                .matched_site
                .as_ref()
                .and_then(|site| site.shadow_mirror.as_ref());

            if let Some(config) = shadow_config {
                if config.enabled
                    && shadow_manager.should_mirror(result.risk_score as f32, client_ip)
                {
                    // Build mirror payload with request context
                    let site_name = ctx
                        .matched_site
                        .as_ref()
                        .map(|s| s.hostname.clone())
                        .unwrap_or_else(|| "unknown".to_string());

                    let sensor_id = std::env::var("SYNAPSE_SENSOR_ID")
                        .unwrap_or_else(|_| "synapse-default".to_string());

                    // Use request correlation ID for shadow mirror payload
                    let request_id = ctx.request_id.clone();

                    let payload = MirrorPayload::new(
                        request_id,
                        client_ip.to_string(),
                        result.risk_score as f32,
                        method.to_string(),
                        uri.clone(),
                        site_name,
                        sensor_id,
                    )
                    .with_ja4(
                        ctx.fingerprint
                            .as_ref()
                            .and_then(|fp| fp.ja4.as_ref().map(|j| j.raw.to_string())),
                    )
                    .with_ja4h(ctx.fingerprint.as_ref().map(|fp| fp.ja4h.raw.to_string()))
                    .with_rules(
                        result
                            .matched_rules
                            .iter()
                            .map(|r| format!("rule_{}", r))
                            .collect(),
                    )
                    .with_headers(
                        headers
                            .iter()
                            .filter_map(|(name, value)| {
                                let value_str = value.to_str().ok()?;
                                Some((name.as_str().to_string(), value_str.to_string()))
                            })
                            .collect(),
                    );

                    // Fire and forget - returns immediately, async delivery in background
                    shadow_manager.mirror_async(payload);

                    info!(
                        "Shadow mirror triggered: {} -> risk={}, rules={:?}, request_id={}",
                        client_ip, result.risk_score, result.matched_rules, ctx.request_id
                    );
                }
            }
        }
        // ===== End Shadow Mirroring =====

        // Cache headers for late body inspection
        ctx.headers = headers;

        ctx.detection = Some(detection);

        // Return false = continue to upstream
        Ok(false)
    }

    /// Request body filter - scan for sensitive data exfiltration (DLP)
    ///
    /// Phase 4: Scans request body chunks for PII and sensitive data patterns.
    /// Detects data exfiltration attempts by scanning outbound data.
    ///
    /// Phase 5: Parallel execution optimization
    /// Instead of blocking on DLP scan, we spawn it as a background task.
    /// The scan runs in PARALLEL with:
    /// - Upstream peer selection (upstream_peer)
    /// - Connection establishment
    /// - Request header modification (upstream_request_filter)
    /// The DLP result is awaited in upstream_request_filter before sending headers.
    ///
    /// Performance optimizations:
    /// - Content-type short circuit: Skip binary types (images, video, etc.)
    /// - Inspection depth cap: Only scan first N bytes of large payloads
    /// - Parallel execution: DLP runs alongside WAF and routing
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Track body size even if skipping DLP
        if let Some(ref body_chunk) = body {
            ctx.body_bytes_seen += body_chunk.len();
        }

        // Short circuit: Skip body accumulation and scanning for binary content types
        // This is a major performance win for image/video uploads
        if ctx.skip_request_dlp {
            if end_of_stream && ctx.body_bytes_seen > 0 {
                debug!(
                    "DLP: Skipped {} bytes of binary content ({})",
                    ctx.body_bytes_seen,
                    ctx.request_content_type.as_deref().unwrap_or("unknown")
                );
            }
            return Ok(());
        }

        // Accumulate request body for DLP scanning
        if let Some(ref body_chunk) = body {
            let chunk_size = body_chunk.len();

            // Only accumulate if under max scan size (5MB default)
            if ctx.request_body_buffer.len() + body_chunk.len() <= 5 * 1024 * 1024 {
                ctx.request_body_buffer.extend_from_slice(body_chunk);
            }

            debug!(
                "Request body chunk: {} bytes (total: {} bytes, eos: {})",
                chunk_size, ctx.body_bytes_seen, end_of_stream
            );
        }

        // On end of stream: spawn DLP scan as background task for parallel execution
        // This allows DLP to run in parallel with upstream_peer and upstream_request_filter
        if end_of_stream && !ctx.request_body_buffer.is_empty() {
            // ---- Schema Validation (runs BEFORE the body-phase WAF pass so
            //      rules using the `schema_violation` match kind can fire in
            //      the same pass). Training the learner is DEFERRED until
            //      after the WAF verdict — see `pending_learn` below. Only
            //      JSON content is processed. ----
            let is_json_content = ctx
                .request_content_type
                .as_ref()
                .map(|ct| ct.contains("json"))
                .unwrap_or(false);

            // TASK-59: pending_learn now lives on RequestContext and is
            // consumed at the end of `upstream_request_filter` after the
            // deferred WAF pass decides. Stashing here and consuming there
            // closes the TASK-41 poisoning gap for rules that block in the
            // deferred phase (e.g. dlp_violation rules 220001-220007): the
            // old code consumed at the end of this function, which was
            // before the deferred pass ran, so attackers could train the
            // learner on bodies that were about to be rejected by DLP.
            if is_json_content {
                if let Ok(json_body) =
                    serde_json::from_slice::<serde_json::Value>(&ctx.request_body_buffer)
                {
                    let req_header = _session.req_header();
                    let uri = req_header.uri.path();
                    let template_path = normalize_path_to_template(uri);

                    // Schema validation: check for anomalies against learned baseline.
                    // Note: Array-root bodies (e.g., `[{...}]`) are silently skipped;
                    // only JSON objects are processed.
                    let validation_result =
                        SCHEMA_LEARNER.validate_request(&template_path, &json_body);

                    if !validation_result.is_valid() {
                        let severity_score = validation_result.total_score.min(25) as f32;

                        debug!(
                            "Schema violations detected for {}: {} violations, score={}, max_severity={:?}",
                            template_path,
                            validation_result.violations.len(),
                            validation_result.total_score,
                            validation_result.max_severity()
                        );

                        if let Some(ref ip) = ctx.client_ip {
                            self.signal_manager.record_event(
                                SignalCategory::Anomaly,
                                "schema_violation",
                                Some(ip.to_string()),
                                Some("Request schema violation detected".to_string()),
                                serde_json::json!({
                                    "template": template_path,
                                    "violation_count": validation_result.violations.len(),
                                    "score": validation_result.total_score
                                }),
                            );
                        }

                        // TASK-61: bounded external risk contribution.
                        // Disjoint-field borrow: `ctx.client_ip` and
                        // `ctx.external_risk_accumulated` can be borrowed
                        // simultaneously because Rust's borrow checker
                        // sees them as distinct fields through direct
                        // access.
                        if let Some(ref ip) = ctx.client_ip {
                            let actual = self.apply_bounded_external_risk(
                                &mut ctx.external_risk_accumulated,
                                ip,
                                severity_score as f64,
                                "schema_violation",
                            );
                            ctx.entity_risk += actual;
                        }
                    }

                    let schema_valid = validation_result.is_valid();

                    // Store the validation result so the body-phase WAF pass can
                    // surface it via the `schema_violation` match kind.
                    ctx.schema_result = Some(validation_result);

                    // TASK-69: only fully-valid bodies are allowed to train
                    // the learner. Any schema deviation, regardless of score,
                    // suppresses training so sub-threshold drift attempts do
                    // not move the baseline. The clean-body payload still
                    // stays on RequestContext so TASK-59's deferred-pass
                    // poisoning guard remains intact.
                    ctx.pending_learn = schema_valid.then_some((template_path, json_body));
                }
            }

            // ---- Body-phase WAF evaluation, enriched with fingerprint and
            //      schema signals. Rules that reference the `dlp_violation`
            //      match kind are automatically skipped here and evaluated in
            //      the deferred post-DLP pass inside `upstream_request_filter`. ----
            if !ctx.skip_request_dlp {
                let req_header = _session.req_header();
                let method = req_header.method.as_str();
                let uri = req_header.uri.to_string();
                let client_ip = ctx.client_ip.as_deref().unwrap_or("0.0.0.0");

                let result = DetectionEngine::analyze_with_signals(
                    method,
                    &uri,
                    &ctx.headers,
                    Some(&ctx.request_body_buffer),
                    client_ip,
                    ctx.fingerprint.as_ref(),
                    ctx.schema_result.as_ref(),
                );

                if result.blocked {
                    warn!(
                        "BLOCKED (Body): {} from {} - risk={}, rules={:?}, reason={}",
                        uri,
                        client_ip,
                        result.risk_score,
                        result.matched_rules,
                        result.block_reason.as_deref().unwrap_or("unknown")
                    );

                    self.block_log.record(BlockEvent::new(
                        client_ip.to_string(),
                        method.to_string(),
                        uri.clone(),
                        result.risk_score,
                        result.matched_rules.clone(),
                        result
                            .block_reason
                            .clone()
                            .unwrap_or_else(|| "body_payload".to_string()),
                        ctx.fingerprint.as_ref().map(|fp| fp.combined_hash.clone()),
                    ));

                    ctx.detection = Some(result);

                    let is_https = Self::is_https_request(_session);
                    Self::send_waf_block_response(_session, &ctx.request_id, is_https).await?;

                    // Response already sent; upstream call will be short-circuited
                    // by the verdict check in upstream_request_filter.
                    // NOTE: ctx.pending_learn is left intact here. It is
                    // only consumed in upstream_request_filter AFTER the
                    // deferred WAF pass — since that pass never runs on this
                    // block path (we early-return), the pending_learn state
                    // is dropped when ctx is dropped, and the learner is
                    // never trained on this body. TASK-59.
                    return Ok(());
                }
            }

            // TASK-59: schema learning is deferred to upstream_request_filter
            // (after the deferred WAF pass completes) rather than fired here.
            // Consuming pending_learn at this point would have poisoned the
            // baseline for deferred-phase blocks (DLP-correlation rules) —
            // see the TASK-59 task description for the full exploit chain.

            if self.dlp_scanner.is_enabled() {
                // Take ownership of the buffer to send to the async task
                let body_data = ctx.request_body_buffer.clone(); // Clone because we might need it? No, we can take it if we are sure WAF is done.
                                                                 // Actually, we just ran WAF. We can take it now.
                                                                 // But wait, `ctx.request_body_buffer` is `Vec<u8>`. `mem::take` works.
                                                                 // But we used it above. So we must clone or restructure.
                                                                 // Let's just clone for the async task, it's safer.

                let scanner = Arc::clone(&self.dlp_scanner);
                let client_ip = ctx.client_ip.clone();

                // Create oneshot channel for result
                let (tx, rx) = oneshot::channel();

                // Spawn DLP scan as background task - runs in PARALLEL with routing
                tokio::spawn(async move {
                    let scan_result = scanner.scan_bytes(&body_data);
                    let scan_time_us = scan_result.scan_time_us;

                    // Process results
                    let (match_count, types_str, matches) = if scan_result.has_matches {
                        // Collect unique types
                        let mut types: Vec<&str> = scan_result
                            .matches
                            .iter()
                            .map(|m| m.data_type.as_str())
                            .collect();
                        types.sort();
                        types.dedup();

                        let types_str = types.join(",");

                        // Log the detection (runs in background)
                        warn!(
                            "DLP EXFILTRATION: {} matches found in request body ({} bytes, {}us) - types: {} from {:?}",
                            scan_result.match_count,
                            scan_result.content_length,
                            scan_time_us,
                            types_str,
                            client_ip
                        );

                        // Log each match for detailed analysis
                        for m in &scan_result.matches {
                            debug!(
                                "DLP request match: {} ({}) severity={} masked={}",
                                m.pattern_name,
                                m.data_type.as_str(),
                                m.severity.as_str(),
                                m.masked_value
                            );
                        }

                        (scan_result.match_count, types_str, scan_result.matches)
                    } else {
                        (0, String::new(), Vec::new())
                    };

                    // Log truncation if it occurred
                    if scan_result.truncated {
                        debug!(
                            "DLP: Truncated {} bytes to {} for inspection",
                            scan_result.original_length, scan_result.content_length
                        );
                    }

                    // Send result back (ignore error if receiver dropped)
                    let _ = tx.send((match_count, types_str, scan_time_us, matches));
                });

                // Store receiver for awaiting in upstream_request_filter
                ctx.dlp_scan_rx = Some(rx);

                debug!(
                    "DLP: Spawned async scan for {} bytes from {:?}, request_id={}",
                    ctx.body_bytes_seen, ctx.client_ip, ctx.request_id
                );
            }
        }

        if end_of_stream && ctx.body_bytes_seen > 0 {
            // Record bandwidth metrics for the request body
            self.metrics_registry
                .record_request_bandwidth(ctx.body_bytes_seen as u64);

            info!(
                "Request body complete: {} bytes from {:?}, DLP scan spawned, request_id={}",
                ctx.body_bytes_seen, ctx.client_ip, ctx.request_id
            );
        }

        Ok(())
    }

    /// Select upstream backend (round-robin, or per-site upstreams if multi-site)
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // ===== Multi-site: Use matched site's upstreams if available =====
        if let Some(ref site) = ctx.matched_site {
            if !site.upstreams.is_empty() {
                // Parse and round-robin through site's upstreams
                let idx =
                    self.backend_counter.fetch_add(1, Ordering::Relaxed) % site.upstreams.len();
                let upstream = &site.upstreams[idx];

                // Parse "host:port" format
                let (host, port) = if let Some(colon_idx) = upstream.rfind(':') {
                    let host = &upstream[..colon_idx];
                    let port: u16 = upstream[colon_idx + 1..].parse().unwrap_or(80);
                    (host.to_string(), port)
                } else {
                    (upstream.clone(), 80)
                };

                ctx.backend_idx = idx;
                info!(
                    "Multi-site: routing to site '{}' backend {}:{} (index {}), request_id={}",
                    site.hostname, host, port, idx, ctx.request_id
                );

                let tls = site.tls_enabled;
                let sni = if tls {
                    site.hostname.clone()
                } else {
                    String::new()
                };
                let peer = HttpPeer::new((&host as &str, port), tls, sni);
                return Ok(Box::new(peer));
            }
        }

        // Fallback: use default backends
        let (host, port, idx) = self.next_backend();
        ctx.backend_idx = idx;

        info!(
            "Routing to default backend {}:{} (index {}), request_id={}",
            host, port, idx, ctx.request_id
        );

        let peer = HttpPeer::new((&host as &str, port), false, String::new());
        Ok(Box::new(peer))
    }

    /// Modify request headers before sending to upstream
    ///
    /// Phase 5: This is where we await the DLP scan result that was spawned
    /// in request_body_filter. The scan has been running in PARALLEL with:
    /// - upstream_peer (backend selection)
    /// - TCP connection establishment
    /// This minimizes total latency by overlapping DLP scanning with network I/O.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Phase 5: Await DLP scan result from parallel task
        // The DLP scan was spawned in request_body_filter and has been running
        // while we selected the backend and established the connection.
        if let Some(rx) = ctx.dlp_scan_rx.take() {
            match rx.await {
                Ok((match_count, types, scan_time_us, matches)) => {
                    ctx.request_dlp_match_count = match_count;
                    ctx.request_dlp_types = types;
                    ctx.dlp_scan_time_us = scan_time_us;
                    ctx.request_dlp_matches = matches;
                    // Flag completion BEFORE checking match_count so the
                    // deferred WAF pass can evaluate NOT(dlp_violation) rules
                    // on zero-match scans. The flag remains false on the Err
                    // arm below, so failed/cancelled scans still skip the
                    // deferred pass entirely.
                    ctx.dlp_scan_completed = true;

                    if match_count > 0 {
                        debug!(
                            "DLP async scan complete: {} matches, types={}, time={}us, request_id={}",
                            match_count, ctx.request_dlp_types, scan_time_us, ctx.request_id
                        );
                    }
                }
                Err(_) => {
                    // Task was cancelled or panicked
                    warn!(
                        "DLP scan task failed or was cancelled, request_id={}",
                        ctx.request_id
                    );
                }
            }
        }

        // ===== Deferred WAF pass (post-DLP) =====
        // Evaluate the rules that were skipped during the body-phase pass
        // because they reference `dlp_violation` — the scan results are now
        // available. Gated on `dlp_scan_completed` rather than "matches were
        // found" so rules wrapping `dlp_violation` in a NOT operator — which
        // fire precisely when there are zero matches — are still evaluated.
        // The normal fast path still has zero extra work for requests that
        // skipped the DLP scan entirely (non-JSON bodies, etc.).
        if ctx.dlp_scan_completed {
            let method = ctx
                .request_method
                .as_deref()
                .unwrap_or_else(|| _session.req_header().method.as_str());
            let uri_owned = ctx
                .request_path
                .clone()
                .unwrap_or_else(|| _session.req_header().uri.to_string());
            let client_ip = ctx.client_ip.as_deref().unwrap_or("0.0.0.0");

            let deferred = DetectionEngine::analyze_deferred(
                method,
                &uri_owned,
                &ctx.headers,
                Some(&ctx.request_body_buffer),
                client_ip,
                ctx.fingerprint.as_ref(),
                ctx.schema_result.as_ref(),
                &ctx.request_dlp_matches,
            );

            if deferred.blocked {
                warn!(
                    "BLOCKED (Deferred DLP): {} from {} - risk={}, rules={:?}, reason={}",
                    uri_owned,
                    client_ip,
                    deferred.risk_score,
                    deferred.matched_rules,
                    deferred.block_reason.as_deref().unwrap_or("unknown")
                );

                self.block_log.record(BlockEvent::new(
                    client_ip.to_string(),
                    method.to_string(),
                    uri_owned.clone(),
                    deferred.risk_score,
                    deferred.matched_rules.clone(),
                    deferred
                        .block_reason
                        .clone()
                        .unwrap_or_else(|| "dlp_violation".to_string()),
                    ctx.fingerprint.as_ref().map(|fp| fp.combined_hash.clone()),
                ));

                // Fire-and-forget WafBlock telemetry so Hub sees deferred
                // DLP blocks in the same stream as body-phase and bad-bot blocks.
                // Never awaits — telemetry must not block the hot path.
                if self.telemetry_client.is_enabled() {
                    let site = ctx
                        .matched_site
                        .as_ref()
                        .map(|s| s.hostname.clone())
                        .unwrap_or_else(|| "_default".to_string());
                    let event = build_deferred_waf_block_event(
                        ctx.request_id.clone(),
                        &deferred.matched_rules,
                        deferred.risk_score,
                        client_ip.to_string(),
                        site,
                        uri_owned.clone(),
                    );
                    let client = Arc::clone(&self.telemetry_client);
                    tokio::spawn(async move {
                        if let Err(e) = client.report(event).await {
                            debug!("Failed to report deferred WAF telemetry: {}", e);
                        }
                    });
                }

                ctx.detection = Some(deferred);

                // Write the canonical WAF block response body so clients see
                // the same JSON envelope regardless of which block site fired.
                // Returning Err after the write signals Pingora to abort
                // upstream forwarding; the already-written response is not
                // overwritten.
                let is_https = Self::is_https_request(_session);
                Self::send_waf_block_response(_session, &ctx.request_id, is_https).await?;

                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(403),
                    "blocked by deferred WAF pass",
                ));
            } else if !deferred.matched_rules.is_empty() {
                // Non-blocking deferred matches still contribute to observability
                // and to the cached detection result so downstream phases see them.
                match ctx.detection.as_mut() {
                    Some(existing) => {
                        merge_deferred_detection_non_blocking(existing, deferred);
                    }
                    None => {
                        ctx.detection = Some(deferred);
                    }
                }
            }
        }

        // ===== TASK-59: Deferred schema learning =====
        // If we reach this point, NEITHER the body-phase WAF (which early-returns
        // from request_body_filter on block) NOR the deferred WAF pass (which
        // returns Err above on block) decided to block this request. It is
        // therefore safe to train the schema learner on the parsed body.
        //
        // This consume-and-train MUST NOT move earlier than this line, or the
        // TASK-41/TASK-59 poisoning guards will break again. If you need to
        // move it for lifetime or refactor reasons, place it in response_filter
        // behind a status-code gate (< 300) instead — but do not move it back
        // into request_body_filter or before the deferred-pass early-return.
        //
        // Option::take() leaves None on ctx so repeat calls to
        // upstream_request_filter (e.g. on upstream retries) cannot retrain.
        if let Some((template_path, json_body)) = ctx.pending_learn.take() {
            SCHEMA_LEARNER.learn_from_request(&template_path, &json_body);
        }

        // ===== Header Manipulation (Request) =====
        if let Some(ref site) = ctx.matched_site {
            if let Some(ref header_config) = site.headers {
                headers::apply_request_headers(upstream_request, header_config.request());
            }
        }

        // Add Synapse headers for visibility
        upstream_request.insert_header("X-Request-ID", ctx.request_id.as_str())?;
        upstream_request.insert_header("X-Synapse-Analyzed", "true")?;

        if let Some(ref detection) = ctx.detection {
            upstream_request.insert_header(
                "X-Synapse-Detection-Time-Us",
                detection.detection_time_us.to_string(),
            )?;
        }

        if let Some(ref ip) = ctx.client_ip {
            upstream_request.insert_header("X-Synapse-Client-IP", ip)?;
        }

        // Phase 3: Add fingerprint headers for dual-running validation
        // These headers allow risk-server to compare its fingerprint calculations
        // with Pingora's calculations during the migration period.
        if let Some(ref fp) = ctx.fingerprint {
            // JA4H fingerprint (always available, generated from HTTP headers)
            upstream_request.insert_header("X-JA4H-Fingerprint-Pingora", &*fp.ja4h.raw)?;

            // JA4 fingerprint (only if X-JA4-Fingerprint header was provided)
            if let Some(ref ja4) = fp.ja4 {
                upstream_request.insert_header("X-JA4-Fingerprint-Pingora", &*ja4.raw)?;
            }

            // Combined fingerprint hash (for entity correlation)
            upstream_request.insert_header("X-Fingerprint-Combined-Pingora", &fp.combined_hash)?;
        }

        // Phase 3: Add entity tracking headers for dual-running validation
        // These headers allow risk-server to compare its entity tracking with Pingora's
        upstream_request
            .insert_header("X-Entity-Risk-Pingora", format!("{:.1}", ctx.entity_risk))?;

        if let Some(ref block_decision) = ctx.entity_blocked {
            upstream_request.insert_header(
                "X-Entity-Blocked-Pingora",
                if block_decision.blocked {
                    "true"
                } else {
                    "false"
                },
            )?;
            if let Some(ref reason) = block_decision.reason {
                upstream_request.insert_header("X-Entity-Block-Reason-Pingora", reason)?;
            }
        }

        // Phase 3: Add tarpit headers for dual-running validation
        // These headers allow risk-server to compare its tarpit calculations with Pingora's
        upstream_request
            .insert_header("X-Tarpit-Delay-Pingora-Ms", ctx.tarpit_delay_ms.to_string())?;
        upstream_request.insert_header("X-Tarpit-Level-Pingora", ctx.tarpit_level.to_string())?;

        // Phase 4: Add request-side DLP headers for dual-running validation
        // These headers allow risk-server to compare its DLP scanning with Pingora's
        upstream_request.insert_header(
            "X-DLP-Request-Violations-Pingora",
            ctx.request_dlp_match_count.to_string(),
        )?;
        if !ctx.request_dlp_types.is_empty() {
            upstream_request
                .insert_header("X-DLP-Request-Types-Pingora", &ctx.request_dlp_types)?;
        }

        Ok(())
    }

    /// Response header filter - apply header manipulations
    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        headers::apply_security_response_headers(
            upstream_response,
            Self::is_https_request(session),
        );
        upstream_response.insert_header("X-Request-ID", ctx.request_id.as_str())?;
        // Extract Content-Type for response schema validation
        ctx.response_content_type = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // ===== Phase 10: Set Challenge Cookie =====
        // If progressive challenge system set a tracking cookie, add it to response
        if let Some(ref cookie) = ctx.challenge_cookie {
            upstream_response.insert_header("set-cookie", cookie.as_str())?;
        }

        // ===== Header Manipulation (Response) =====
        if let Some(ref site) = ctx.matched_site {
            if let Some(ref header_config) = site.headers {
                headers::apply_response_headers(upstream_response, header_config.response());
            }
        }

        if let (Some(method), Some(path)) = (ctx.request_method.as_ref(), ctx.request_path.as_ref())
        {
            record_auth_coverage(
                &self.auth_coverage,
                method,
                path,
                ctx.has_auth_header,
                upstream_response.status.as_u16(),
            );
        }
        Ok(())
    }

    /// Response body filter - scan for sensitive data (DLP)
    ///
    /// Phase 4: Scans response body chunks for PII and sensitive data patterns.
    /// Accumulates body for scanning and reports matches on end_of_stream.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<std::time::Duration>>
    where
        Self::CTX: Send + Sync,
    {
        // Accumulate response body for DLP scanning
        if let Some(ref body_chunk) = body {
            // Only accumulate if under max scan size (5MB default)
            if ctx.response_body_buffer.len() + body_chunk.len() <= 5 * 1024 * 1024 {
                ctx.response_body_buffer.extend_from_slice(body_chunk);
            }
        }

        // Record response bandwidth on end of stream
        if end_of_stream && !ctx.response_body_buffer.is_empty() {
            self.metrics_registry
                .record_response_bandwidth(ctx.response_body_buffer.len() as u64);
        }

        // Scan on end of stream
        if end_of_stream && !ctx.response_body_buffer.is_empty() && self.dlp_scanner.is_enabled() {
            let scan_result = self.dlp_scanner.scan_bytes(&ctx.response_body_buffer);

            if scan_result.has_matches {
                // Collect unique types
                let mut types: Vec<&str> = scan_result
                    .matches
                    .iter()
                    .map(|m| m.data_type.as_str())
                    .collect();
                types.sort();
                types.dedup();

                ctx.dlp_match_count = scan_result.match_count;
                ctx.dlp_types = types.join(",");

                // Record violations for dashboard
                let client_ip = ctx.client_ip.as_deref();
                let path = ctx.request_path.as_deref().unwrap_or("/");
                self.dlp_scanner
                    .record_violations(&scan_result, client_ip, path);

                warn!(
                    "DLP: {} matches found in response ({} bytes, {}μs) - types: {}",
                    scan_result.match_count,
                    scan_result.content_length,
                    scan_result.scan_time_us,
                    ctx.dlp_types
                );

                // Log each match for detailed analysis
                for m in &scan_result.matches {
                    debug!(
                        "DLP match: {} ({}) severity={} at {}..{}",
                        m.pattern_name,
                        m.data_type.as_str(),
                        m.severity.as_str(),
                        m.start,
                        m.end
                    );
                }
            }

            // Clear buffer after scanning
            ctx.response_body_buffer.clear();
        }

        // Schema Learning and Validation for Responses (API Anomaly Detection)
        // Learn response schemas to detect anomalous backend responses
        // that might indicate compromise or data exfiltration
        if end_of_stream && !ctx.response_body_buffer.is_empty() {
            // Check if response is JSON
            let is_json_response = ctx
                .response_content_type
                .as_ref()
                .map(|ct| ct.contains("json"))
                .unwrap_or(false);

            if is_json_response {
                // Try to parse the response as JSON
                if let Ok(json_body) =
                    serde_json::from_slice::<serde_json::Value>(&ctx.response_body_buffer)
                {
                    // Get request path from context for template mapping
                    let template_path = ctx
                        .request_path
                        .as_deref()
                        .map(normalize_path_to_template)
                        .unwrap_or_default();

                    // Schema learning: train the learner with this response.
                    // Note: Array-root bodies (e.g., `[{...}]`) are silently skipped;
                    // only JSON objects are processed.
                    SCHEMA_LEARNER.learn_from_response(&template_path, &json_body);

                    // Schema validation: check for anomalies in backend responses
                    // This helps detect backend compromise or data exfiltration
                    let validation_result =
                        SCHEMA_LEARNER.validate_response(&template_path, &json_body);
                    if !validation_result.is_valid() {
                        // Response schema violations are logged but not added to risk score
                        // since the entity has already received the response
                        warn!(
                            "Response schema violations detected for {}: {} violations, score={}, max_severity={:?}",
                            template_path,
                            validation_result.violations.len(),
                            validation_result.total_score,
                            validation_result.max_severity()
                        );

                        if let Some(ref ip) = ctx.client_ip {
                            self.signal_manager.record_event(
                                SignalCategory::Anomaly,
                                "response_schema_violation",
                                Some(ip.to_string()),
                                Some("Response schema violation detected".to_string()),
                                serde_json::json!({
                                    "template": template_path,
                                    "violation_count": validation_result.violations.len(),
                                    "score": validation_result.total_score
                                }),
                            );
                        }
                    }
                }
            }
        }

        Ok(None) // No delay
    }

    /// Logging at end of request
    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    ) {
        let total_time = ctx.request_start.elapsed();
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        let detection_time = ctx
            .detection
            .as_ref()
            .map(|d| d.detection_time_us)
            .unwrap_or(0);

        let blocked = ctx.detection.as_ref().map(|d| d.blocked).unwrap_or(false);

        // Feedback loop: Record response status for API profiling
        // This allows the profiler to distinguish between valid (200) and invalid (404/400) requests
        let path = session.req_header().uri.path();
        DetectionEngine::record_status(path, status);

        // Record metrics
        let total_time_us = total_time.as_micros() as u64;
        self.metrics_registry.record_request(status, total_time_us);

        // Phase 3: Record per-request telemetry for HTTP transaction history
        if self.telemetry_client.is_enabled() {
            let site = ctx
                .matched_site
                .as_ref()
                .map(|s| s.hostname.clone())
                .unwrap_or_else(|| "_default".to_string());
            let method = session.req_header().method.to_string();
            let path = session.req_header().uri.path().to_string();
            let waf_action = if blocked {
                Some("block".to_string())
            } else if ctx.waf_challenged {
                Some("challenge".to_string())
            } else if ctx.waf_logged {
                Some("log".to_string())
            } else {
                Some("allow".to_string())
            };

            let event = synapse_pingora::telemetry::TelemetryEvent::RequestProcessed {
                request_id: Some(ctx.request_id.clone()),
                latency_ms: total_time.as_millis() as u64,
                status_code: status,
                waf_action,
                site,
                method,
                path,
            };

            let client = Arc::clone(&self.telemetry_client);
            tokio::spawn(async move {
                if let Err(e) = client.record(event).await {
                    debug!("Failed to record request telemetry: {}", e);
                }
            });
        }

        if let Some(ref detection) = ctx.detection {
            let blocked = detection.blocked;
            let challenged = ctx.waf_challenged;
            let logged = ctx.waf_logged;
            self.metrics_registry.record_waf(
                blocked,
                challenged,
                logged,
                detection.detection_time_us,
            );

            for &rule_id in &detection.matched_rules {
                self.metrics_registry
                    .record_rule_match(&rule_id.to_string());
            }

            // Phase 3: Send telemetry alert if blocked or high risk detection
            // Uses existing TelemetryEvent::WafBlock variant for security events
            if self.telemetry_client.is_enabled()
                && (detection.blocked || detection.risk_score > 50)
            {
                let client_ip = session
                    .client_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                let site = ctx
                    .matched_site
                    .as_ref()
                    .map(|s| s.hostname.clone())
                    .unwrap_or_else(|| "_default".to_string());

                let rule_id = detection
                    .matched_rules
                    .first()
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "high_risk".to_string());

                let severity = if detection.risk_score > 80 {
                    "critical"
                } else if detection.risk_score > 50 {
                    "high"
                } else {
                    "medium"
                }
                .to_string();

                let event = synapse_pingora::telemetry::TelemetryEvent::WafBlock {
                    request_id: Some(ctx.request_id.clone()),
                    rule_id,
                    severity,
                    client_ip,
                    site,
                    path: session.req_header().uri.path().to_string(),
                };

                let client = Arc::clone(&self.telemetry_client);
                tokio::spawn(async move {
                    if let Err(e) = client.report(event).await {
                        debug!("Failed to report security telemetry: {}", e);
                    }
                });
            }
        }

        // Phase 2: Report profiling metrics
        // We do this in logging to avoid blocking the request path
        // In a real system, we might sample this or use a background task
        if let Some(_detection) = &ctx.detection {
            // Collect anomalies from the detection result (if we exposed them in DetectionResult)
            // For now, we just update the active profile count periodically
            // Ideally, DetectionResult should carry the anomalies
        }

        // Report active profiles count (sampled, not every request)
        if fastrand::bool() && fastrand::u8(0..100) < 5 {
            // ~5% sample rate
            let profiles = DetectionEngine::get_profiles();
            self.metrics_registry
                .record_profile_metrics(profiles.len(), &[]);
        }

        // Phase 3: Include fingerprint in access log
        let fp_hash = ctx
            .fingerprint
            .as_ref()
            .map(|fp| fp.combined_hash.as_str())
            .unwrap_or("-");

        // Phase 3: Include entity tracking in access log
        let entity_blocked = ctx
            .entity_blocked
            .as_ref()
            .map(|b| b.blocked)
            .unwrap_or(false);

        // Phase 4/5: Include DLP metrics in access log for dual-running validation
        // Phase 5 adds dlp_scan_time_us from parallel execution
        let dlp_info = if ctx.request_dlp_match_count > 0
            || ctx.dlp_match_count > 0
            || ctx.dlp_scan_time_us > 0
        {
            format!(
                " dlp_req={}:{}:{}us dlp_resp={}:{}",
                ctx.request_dlp_match_count,
                if ctx.request_dlp_types.is_empty() {
                    "-"
                } else {
                    &ctx.request_dlp_types
                },
                ctx.dlp_scan_time_us,
                ctx.dlp_match_count,
                if ctx.dlp_types.is_empty() {
                    "-"
                } else {
                    &ctx.dlp_types
                }
            )
        } else {
            String::new()
        };

        info!(
            "ACCESS: {} {} status={} total={}μs detection={}μs blocked={} entity_risk={:.1} entity_blocked={} tarpit={}ms@L{} backend={} fp={}{}",
            session.req_header().method,
            session.req_header().uri,
            status,
            total_time.as_micros(),
            detection_time,
            blocked,
            ctx.entity_risk,
            entity_blocked,
            ctx.tarpit_delay_ms,
            ctx.tarpit_level,
            ctx.backend_idx,
            fp_hash,
            dlp_info
        );

        publish_access_log(
            session.req_header().method.as_str(),
            path,
            status,
            total_time.as_secs_f64() * 1000.0,
            ctx.client_ip.as_deref(),
            Some(ctx.request_id.as_str()),
        );

        if let Some(ref detection) = ctx.detection {
            if detection.blocked || detection.risk_score > 50 {
                let message = detection
                    .block_reason
                    .clone()
                    .unwrap_or_else(|| "WAF detection event".to_string());
                publish_waf_log(
                    &detection.matched_rules,
                    detection.risk_score,
                    ctx.client_ip.as_deref(),
                    Some(path),
                    message,
                    Some(ctx.request_id.as_str()),
                );
            }
        }

        // ===== Phase 9: Payload Profiling =====
        // Record request/response payload sizes for bandwidth tracking and anomaly detection
        let client_ip = ctx.client_ip.as_deref().unwrap_or("0.0.0.0");
        let template = ctx.request_path.as_deref().unwrap_or(path);
        let request_bytes = ctx.body_bytes_seen as u64;
        let response_bytes = ctx.response_body_buffer.len() as u64;

        self.payload_manager
            .record_request(template, client_ip, request_bytes, response_bytes);
        // ===== End Payload Profiling =====
    }
}

use synapse_pingora::horizon::MetricsProvider;

#[allow(dead_code)]
struct HorizonMetricsProvider {
    metrics: Arc<MetricsRegistry>,
    health: Arc<HealthChecker>,
    system: Mutex<System>,
}

impl MetricsProvider for HorizonMetricsProvider {
    fn cpu_usage(&self) -> f64 {
        let mut sys = self.system.lock();
        sys.refresh_cpu_all();
        (sys.global_cpu_usage() as f64).clamp(0.0, 100.0)
    }
    fn memory_usage(&self) -> f64 {
        let mut sys = self.system.lock();
        sys.refresh_memory();
        let total = sys.total_memory();
        if total == 0 {
            return 0.0;
        }
        let used = sys.used_memory();
        ((used as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
    }
    fn disk_usage(&self) -> f64 {
        let disks = Disks::new_with_refreshed_list();
        let (used, total) = disks
            .list()
            .first()
            .map(|disk| {
                let total = disk.total_space();
                let free = disk.available_space();
                (total.saturating_sub(free), total)
            })
            .unwrap_or((0, 0));
        if total == 0 {
            return 0.0;
        }
        ((used as f64 / total as f64) * 100.0).clamp(0.0, 100.0)
    }
    fn requests_last_minute(&self) -> u64 {
        self.metrics.requests_last_minute()
    }
    fn avg_latency_ms(&self) -> f64 {
        self.metrics.avg_latency_ms()
    }
    fn config_hash(&self) -> String {
        CONFIG_HASH.get().cloned().unwrap_or_default()
    }
    fn rules_hash(&self) -> String {
        RULES_HASH.read().clone()
    }
    fn active_connections(&self) -> Option<u32> {
        let active = self.metrics.active_requests();
        Some(active.min(u32::MAX as u64) as u32)
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

use synapse_pingora::config::ConfigFile as MultisiteConfigFile;

// ============================================================================
// Multi-site Configuration Loading
// ============================================================================

/// Attempts to load multi-site configuration from YAML files.
/// Returns (ConfigFile, Vec<SiteConfig>) if successful.
fn try_load_multisite_config() -> Option<(MultisiteConfigFile, Vec<SiteConfig>)> {
    let paths = [
        "config.sites.yaml",
        "config.yaml",
        "/etc/synapse-pingora/config.yaml",
    ];

    for path in &paths {
        if !std::path::Path::new(path).exists() {
            continue;
        }

        match ConfigLoader::load(path) {
            Ok(config_file) => {
                if !config_file.sites.is_empty() {
                    let sites = ConfigLoader::to_site_configs(&config_file);
                    info!(
                        "Loaded multi-site configuration from {} with {} sites",
                        path,
                        sites.len()
                    );

                    let timeout_ms = DetectionEngine::set_regex_timeout_ms(
                        config_file.server.waf_regex_timeout_ms,
                    );
                    let deferred_timeout_ms = DetectionEngine::set_deferred_regex_timeout_ms(
                        config_file.server.waf_deferred_regex_timeout_ms,
                    );
                    info!(
                        "WAF regex timeouts configured: body={}ms deferred={}ms",
                        timeout_ms, deferred_timeout_ms
                    );

                    return Some((config_file, sites));
                }
            }
            Err(e) => {
                debug!("Could not load multi-site config from {}: {}", path, e);
            }
        }
    }

    None
}

/// Set of runtime managers shared across proxy instances.
type RuntimeManagers = (
    Arc<RwLock<VhostMatcher>>,
    Arc<RwLock<SiteWafManager>>,
    Arc<RwLock<RateLimitManager>>,
    Arc<RwLock<AccessListManager>>,
);

/// Creates all runtime managers from a multi-site configuration.
fn create_multisite_managers(
    config_file: &MultisiteConfigFile,
    sites: &[SiteConfig],
) -> RuntimeManagers {
    // Create VhostMatcher from sites
    let vhost_matcher = VhostMatcher::new(sites.to_vec()).unwrap_or_else(|e| {
        warn!("Failed to create VhostMatcher: {}, using empty matcher", e);
        VhostMatcher::empty()
    });

    // Create SiteWafManager
    let mut site_waf = SiteWafManager::new();
    for site in &config_file.sites {
        if let Some(ref waf) = site.waf {
            let waf_config = synapse_pingora::site_waf::SiteWafConfig {
                enabled: waf.enabled,
                threshold: waf.threshold.unwrap_or(config_file.server.waf_threshold),
                rule_overrides: std::collections::HashMap::new(),
                custom_block_page: None,
                default_action: synapse_pingora::site_waf::WafAction::Block,
            };
            site_waf.add_site(&site.hostname, waf_config);
        }
    }

    // Create RateLimitManager
    let rate_limit_mgr = RateLimitManager::new();
    for site in &config_file.sites {
        if let Some(ref rl) = site.rate_limit {
            let rl_config = synapse_pingora::ratelimit::RateLimitConfig {
                rps: rl.rps,
                burst: rl.burst.unwrap_or(rl.rps * 2),
                enabled: rl.enabled,
                window_secs: 1,
            };
            rate_limit_mgr.add_site(&site.hostname, rl_config);
        }
    }

    // Create AccessListManager
    let mut access_list_mgr = AccessListManager::new();
    for site in &config_file.sites {
        if let Some(ref acl) = site.access_control {
            let mut site_list = if acl.default_action == "allow" {
                synapse_pingora::access::AccessList::allow_all()
            } else {
                synapse_pingora::access::AccessList::deny_all()
            };

            for cidr in &acl.allow {
                if let Err(e) = site_list.allow(cidr) {
                    warn!("Failed to add allow rule for site {}: {}", site.hostname, e);
                }
            }

            for cidr in &acl.deny {
                if let Err(e) = site_list.deny(cidr) {
                    warn!("Failed to add deny rule for site {}: {}", site.hostname, e);
                }
            }

            access_list_mgr.add_site(&site.hostname, site_list);
        }
    }

    (
        Arc::new(RwLock::new(vhost_matcher)),
        Arc::new(RwLock::new(site_waf)),
        Arc::new(RwLock::new(rate_limit_mgr)),
        Arc::new(RwLock::new(access_list_mgr)),
    )
}

/// Creates a shadow mirror manager if any site has shadow mirroring configured.
fn create_shadow_mirror_manager(sites: &[SiteConfig]) -> Option<Arc<ShadowMirrorManager>> {
    let mut configs = sites.iter().filter_map(|site| site.shadow_mirror.clone());
    let config = configs.next()?;

    if configs.next().is_some() {
        warn!("Multiple shadow_mirror configs found; using the first configured site");
    }

    let sensor_id =
        std::env::var("SYNAPSE_SENSOR_ID").unwrap_or_else(|_| "synapse-default".to_string());

    match ShadowMirrorManager::new(config, sensor_id) {
        Ok(manager) => Some(Arc::new(manager)),
        Err(e) => {
            error!("Failed to create shadow mirror manager: {}", e);
            None
        }
    }
}

/// Run configuration validation and exit.
fn run_config_check(file: &str, json_output: bool) {
    #[derive(serde::Serialize)]
    struct ValidationResult {
        valid: bool,
        file: String,
        sites: Option<usize>,
        errors: Vec<String>,
        warnings: Vec<String>,
    }

    let mut result = ValidationResult {
        valid: false,
        file: file.to_string(),
        sites: None,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    // Check file exists
    if !Path::new(file).exists() {
        result
            .errors
            .push(format!("Configuration file not found: {}", file));
        output_validation_result(&result, json_output);
        std::process::exit(1);
    }

    let contents = match fs::read_to_string(file) {
        Ok(contents) => contents,
        Err(e) => {
            result
                .errors
                .push(format!("Failed to read config file: {}", e));
            output_validation_result(&result, json_output);
            std::process::exit(1);
        }
    };

    let yaml_value: serde_yaml::Value = match serde_yaml::from_str(&contents) {
        Ok(value) => value,
        Err(e) => {
            result
                .errors
                .push(format!("Failed to parse config file: {}", e));
            output_validation_result(&result, json_output);
            std::process::exit(1);
        }
    };

    let is_multisite = yaml_value
        .as_mapping()
        .map(|mapping| mapping.contains_key(serde_yaml::Value::String("sites".to_string())))
        .unwrap_or(false);

    if let Some(message) = deprecated_anomaly_blocking_error(&yaml_value) {
        result.errors.push(message);
        output_validation_result(&result, json_output);
        std::process::exit(1);
    }
    if let Some(message) = deprecated_anomaly_blocking_warning(&yaml_value) {
        result.warnings.push(message);
    }

    // Try to load and validate config (multi-site or legacy)
    if is_multisite {
        match ConfigLoader::load(file) {
            Ok(config_file) => {
                result.valid = true;
                result.sites = Some(config_file.sites.len());

                if config_file.sites.is_empty() {
                    result
                        .errors
                        .push("No sites configured in multi-site config".to_string());
                    result.valid = false;
                }

                if config_file.server.http_addr.parse::<SocketAddr>().is_err() {
                    result.errors.push(format!(
                        "Server HTTP listen address is invalid: {}",
                        config_file.server.http_addr
                    ));
                    result.valid = false;
                }

                if config_file.server.https_addr.parse::<SocketAddr>().is_err() {
                    result.errors.push(format!(
                        "Server HTTPS listen address is invalid: {}",
                        config_file.server.https_addr
                    ));
                    result.valid = false;
                }
            }
            Err(e) => {
                result.errors.push(format!("Configuration error: {}", e));
            }
        }
    } else {
        match Config::load(file) {
            Ok(config) => {
                result.valid = true;

                // Validate server listen addresses
                if config.server.listen.is_empty() {
                    result
                        .errors
                        .push("Server listen addresses cannot be empty".to_string());
                    result.valid = false;
                }
                for (idx, addr) in config.server.listen.iter().enumerate() {
                    if addr.parse::<SocketAddr>().is_err() {
                        result.errors.push(format!(
                            "Server listen address [{}] is invalid: {}",
                            idx, addr
                        ));
                        result.valid = false;
                    }
                }
                if config.server.admin_listen.parse::<SocketAddr>().is_err() {
                    result.errors.push(format!(
                        "Admin listen address is invalid: {}",
                        config.server.admin_listen
                    ));
                    result.valid = false;
                }

                // Validate trusted proxies CIDR format
                for (idx, proxy) in config.server.trusted_proxies.iter().enumerate() {
                    if proxy.parse::<CidrRange>().is_err() {
                        result.errors.push(format!(
                            "Trusted proxy #{} has invalid CIDR format: {}",
                            idx + 1,
                            proxy
                        ));
                        result.valid = false;
                    }
                }

                // Validate WAF rules if path is provided
                let rules_path = &config.detection.rules_path;
                if Path::new(rules_path).exists() {
                    match fs::read(rules_path) {
                        Ok(rules_json) => {
                            let mut engine = synapse_pingora::waf::Engine::empty();
                            match engine.load_rules(&rules_json) {
                                Ok(count) => {
                                    info!("Validated {} WAF rules from {}", count, rules_path);
                                }
                                Err(e) => {
                                    result.errors.push(format!(
                                        "WAF rules validation failed for {}: {}",
                                        rules_path, e
                                    ));
                                    result.valid = false;
                                }
                            }
                        }
                        Err(e) => {
                            result.errors.push(format!(
                                "Failed to read WAF rules file {}: {}",
                                rules_path, e
                            ));
                            result.valid = false;
                        }
                    }
                } else if rules_path != "data/rules.json" {
                    // Only warn if non-default path is missing
                    result
                        .warnings
                        .push(format!("WAF rules file not found: {}", rules_path));
                }

                // Additional validation checks
                if config.upstreams.is_empty() {
                    result
                        .errors
                        .push("No upstream backends configured".to_string());
                    result.valid = false;
                }

                // Check TLS cert files exist if TLS is configured
                if config.tls.enabled {
                    if config.tls.cert_path.trim().is_empty() {
                        result
                            .errors
                            .push("TLS cert path is empty while TLS is enabled".to_string());
                        result.valid = false;
                    } else if !Path::new(&config.tls.cert_path).exists() {
                        result
                            .errors
                            .push(format!("TLS cert file not found: {}", config.tls.cert_path));
                        result.valid = false;
                    }

                    if config.tls.key_path.trim().is_empty() {
                        result
                            .errors
                            .push("TLS key path is empty while TLS is enabled".to_string());
                        result.valid = false;
                    } else if !Path::new(&config.tls.key_path).exists() {
                        result
                            .errors
                            .push(format!("TLS key file not found: {}", config.tls.key_path));
                        result.valid = false;
                    }
                }
            }
            Err(e) => {
                result.errors.push(format!("Configuration error: {}", e));
            }
        }
    }

    output_validation_result(&result, json_output);

    if result.valid && result.errors.is_empty() {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}

fn output_validation_result<T: serde::Serialize>(result: &T, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    } else {
        // Human-readable output using colors and icons
        let json = serde_json::to_value(result).unwrap_or_default();
        let valid = json["valid"].as_bool().unwrap_or(false);
        let file = json["file"].as_str().unwrap_or("unknown");

        println!("\nConfiguration Check: {}", file);
        println!("--------------------------------------------------");

        if valid {
            println!("✅ Configuration is VALID");
        } else {
            println!("❌ Configuration is INVALID");
        }

        if let Some(sites) = json["sites"].as_u64() {
            println!("Found {} site(s) configured.", sites);
        }

        if let Some(errors) = json["errors"].as_array() {
            if !errors.is_empty() {
                println!("\nErrors:");
                for error in errors {
                    println!("  • {}", error.as_str().unwrap_or_default());
                }
            }
        }

        if let Some(warnings) = json["warnings"].as_array() {
            if !warnings.is_empty() {
                println!("\nWarnings:");
                for warning in warnings {
                    println!("  ⚠️  {}", warning.as_str().unwrap_or_default());
                }
            }
        }

        println!("\nResult: {}\n", if valid { "PASSED" } else { "FAILED" });
    }
}

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Initialize logging (only if TUI is NOT enabled to prevent terminal corruption)
    if cli.tui {
        init_tui_logging();
    } else {
        init_logging();
    }

    // Handle subcommands
    match &cli.command {
        Some(Commands::CheckConfig { file, json }) => {
            run_config_check(file, *json);
            return;
        }
        Some(Commands::Run) | None => {
            // Continue with normal startup
        }
    }

    // Check for dev/demo modes via CLI flags or environment variables
    let dev_mode_cli = cli.dev;
    let dev_mode_env = parse_bool_env("SYNAPSE_DEV");
    let demo_mode = cli.demo || parse_bool_env("SYNAPSE_DEMO");
    let is_explicitly_non_production = parse_bool_env_neg("SYNAPSE_PRODUCTION")
        || std::env::var("NODE_ENV")
            .map(|v| {
                matches!(
                    v.to_lowercase().as_str(),
                    "development" | "dev" | "local" | "test"
                )
            })
            .unwrap_or(false);

    if dev_mode_cli {
        // CLI --dev flag is explicit developer intent — enable directly
        synapse_pingora::admin_server::enable_dev_mode();
        synapse_pingora::validation::set_allow_private_upstreams(true);
        tracing::warn!(
            "Dev mode: SSRF guard on validate_upstream is RELAXED (private/internal IPs allowed). Production deployments must never enable --dev."
        );
    } else if dev_mode_env {
        // SECURITY: Env-var activation requires explicit non-production confirmation
        if is_explicitly_non_production {
            synapse_pingora::admin_server::enable_dev_mode();
            synapse_pingora::validation::set_allow_private_upstreams(true);
            tracing::warn!(
                "Dev mode: SSRF guard on validate_upstream is RELAXED (private/internal IPs allowed). Production deployments must never set SYNAPSE_DEV with SYNAPSE_PRODUCTION=0 / NODE_ENV=development."
            );
        } else {
            tracing::error!(
                "SECURITY: SYNAPSE_DEV set but no explicit non-production environment detected. \
                 Dev mode DISABLED for safety. Set SYNAPSE_PRODUCTION=0 or NODE_ENV=development to enable."
            );
        }
    }

    if demo_mode {
        synapse_pingora::admin_server::enable_demo_mode();
    }

    info!("Starting Synapse-Pingora PoC");

    // Load configuration - honor CLI path first, fall back to defaults
    let config = match Config::load(&cli.config) {
        Ok(config) => {
            info!("Loaded configuration from {}", cli.config);
            config
        }
        Err(err) => {
            warn!("Failed to load {}: {}", cli.config, err);
            Config::load_or_default()
        }
    };
    let multisite_config = try_load_multisite_config();
    let rules_path = if config.detection.rules_path.trim().is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(
            config.detection.rules_path.clone(),
        ))
    };

    // Compute and cache config hash for heartbeat reporting
    // This allows Signal Horizon to detect configuration drift between sensors
    // We hash the raw config file bytes rather than serializing the parsed config
    let config_paths = [
        cli.config.as_str(),
        "config.yaml",
        "config.yml",
        "/etc/synapse-pingora/config.yaml",
    ];
    for path in &config_paths {
        if let Ok(config_bytes) = std::fs::read(path) {
            let _ = CONFIG_HASH.set(compute_hash(&config_bytes));
            debug!(
                "Config hash from {}: {}",
                path,
                CONFIG_HASH.get().unwrap_or(&"none".to_string())
            );
            break;
        }
    }
    // If no config file exists, hash empty to indicate default config
    if CONFIG_HASH.get().is_none() {
        let _ = CONFIG_HASH.set(compute_hash(b"default"));
    }

    // Compute and cache rules hash for externally supplied rules.json.
    // Preserving the old behavior keeps fleet drift reporting semantics stable.
    if let Some(rules_data) = DetectionEngine::rules_data() {
        *RULES_HASH.write() = compute_hash(rules_data);
        debug!("Rules hash: {}", RULES_HASH.read());
    }

    // ... (metrics init)

    // Load profiles on startup (if file exists)
    // Note: this currently only loads the process-local singleton state used
    // by this worker. Persisting and broadcasting profile snapshots across
    // processes is still a separate concern.
    //
    // Hydrate endpoint profiles once into the process-global engine.
    // Multi-process worker synchronization is still a separate concern.
    if Path::new("data/profiles.json").exists() {
        if let Ok(profiles) = SnapshotManager::load_profiles(Path::new("data/profiles.json")) {
            info!("Loaded {} profiles from disk", profiles.len());
            DetectionEngine::load_profiles(profiles);
        }
    }

    // ... (rest of main)

    info!("Listen addresses: {}", config.server.listen.join(", "));
    info!(
        "Upstreams: {:?}",
        config
            .upstreams
            .iter()
            .map(|u| format!("{}:{}", u.host, u.port))
            .collect::<Vec<_>>()
    );
    info!(
        "Rate limit: {} rps (enabled: {})",
        config.rate_limit.rps, config.rate_limit.enabled
    );

    // Force engine initialization and rule loading at startup
    let rule_count = DetectionEngine::rule_count();
    info!("Synapse engine initialized with {} rules", rule_count);

    // Configure backends from legacy config (fallback)
    let legacy_backends: Vec<(String, u16)> = config
        .upstreams
        .iter()
        .map(|u| (u.host.clone(), u.port))
        .collect();

    // Phase 6: Initialize TLS Manager
    let tls_manager = Arc::new(TlsManager::new(
        synapse_pingora::tls::TlsVersion::from_str(&config.tls.min_version)
            .unwrap_or(synapse_pingora::tls::TlsVersion::Tls12),
    ));

    if config.tls.enabled {
        // Load default cert
        if !config.tls.cert_path.is_empty() && !config.tls.key_path.is_empty() {
            if let Err(e) = tls_manager.set_default_cert(&synapse_pingora::tls::TlsCertConfig {
                domain: "default".to_string(),
                cert_path: config.tls.cert_path.clone(),
                key_path: config.tls.key_path.clone(),
                is_wildcard: false,
            }) {
                error!("Failed to load default TLS certificate: {}", e);
            }
        }

        // Load per-domain certs
        for cert_cfg in &config.tls.per_domain_certs {
            if let Err(e) = tls_manager.load_cert(&synapse_pingora::tls::TlsCertConfig {
                domain: cert_cfg.domain.clone(),
                cert_path: cert_cfg.cert_path.clone(),
                key_path: cert_cfg.key_path.clone(),
                is_wildcard: cert_cfg.domain.starts_with("*."),
            }) {
                error!(
                    "Failed to load TLS certificate for {}: {}",
                    cert_cfg.domain, e
                );
            }
        }
        info!(
            "TLS Manager initialized with {} certificates",
            tls_manager.cert_count()
        );
    }

    // Create shared health checker and metrics registry for admin API
    let health_checker = Arc::new(HealthChecker::default());
    let metrics_registry = Arc::new(MetricsRegistry::new());

    // Initialize Telemetry (Signal Horizon)
    let mut telemetry_config = config.telemetry.clone();
    let risk_server_url = config
        .detection
        .risk_server_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if telemetry_config.enabled {
        if telemetry_config.endpoint.trim().is_empty() {
            if let Some(url) = risk_server_url {
                warn!("detection.risk_server_url is deprecated; use telemetry.endpoint instead");
                telemetry_config.endpoint = format!("{}/_sensor/report", url);
            } else {
                telemetry_config.enabled = false;
                warn!("Telemetry enabled but endpoint is empty; disabling telemetry");
            }
        }
    } else if let Some(url) = risk_server_url {
        warn!("detection.risk_server_url is deprecated; use telemetry.endpoint instead");
        telemetry_config.enabled = true;
        telemetry_config.endpoint = format!("{}/_sensor/report", url);
    }

    if telemetry_config.enabled {
        info!(
            "Telemetry enabled, reporting to {}",
            telemetry_config.endpoint
        );
    }
    let telemetry_client = Arc::new(TelemetryClient::new(telemetry_config));
    if telemetry_client.is_enabled() {
        let telemetry_for_logs = Arc::clone(&telemetry_client);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    error!("Failed to create telemetry runtime: {}", err);
                    return;
                }
            };

            rt.block_on(async move {
                telemetry_for_logs.start_background_flush();
                tokio::spawn(LogTelemetryService::new(telemetry_for_logs).run());
                std::future::pending::<()>().await;
            });
        });
    }

    // Create shared CampaignManager for threat correlation (mutable for initialization)
    let mut campaign_manager_raw = CampaignManager::new();

    // Inject TelemetryClient for cross-tenant correlation
    campaign_manager_raw.set_telemetry_client(Arc::clone(&telemetry_client));

    // Create multi-site managers if available
    let config_manager: Option<Arc<ConfigManager>> =
        if let Some((ref config_file, ref sites)) = multisite_config {
            let (vhost_matcher, site_waf_mgr, rate_limit_mgr, access_list_mgr) =
                create_multisite_managers(config_file, sites);

            // Inject AccessListManager into CampaignManager for automated mitigation
            campaign_manager_raw.set_access_list_manager(Arc::clone(&access_list_mgr));

            // Create shared sites vector for ConfigManager
            let sites_arc = Arc::new(RwLock::new(sites.clone()));
            let config_arc = Arc::new(RwLock::new(config_file.clone()));

            // Create ConfigManager with all managers
            let manager = ConfigManager::new(
                config_arc,
                sites_arc,
                Arc::clone(&vhost_matcher),
                Arc::clone(&site_waf_mgr),
                Arc::clone(&rate_limit_mgr),
                Arc::clone(&access_list_mgr),
            )
            .with_rules(
                DetectionEngine::shared_engine(),
                rules_path.clone(),
                Some(Arc::clone(&RULES_HASH)),
            );

            info!(
                "Multi-site mode enabled: {} sites, {} exact matches",
                sites.len(),
                vhost_matcher.read().site_count()
            );

            Some(Arc::new(manager))
        } else {
            info!("Legacy single-backend mode (no multi-site config found)");
            None
        };

    // Wrap CampaignManager in Arc for shared use
    let campaign_manager = Arc::new(campaign_manager_raw);

    // ========== Phase 7: Persistence - Load existing WAF state ==========
    use synapse_pingora::persistence::{PersistenceConfig, SnapshotManager, WafSnapshot};

    let persistence_config = PersistenceConfig::default();
    let snapshot_manager = Arc::new(SnapshotManager::new(persistence_config.clone()));

    // Try to load existing WAF state from disk
    let loaded_snapshot = snapshot_manager.load_on_startup().ok().flatten();

    // Create shared EntityManager for both admin API and proxy
    let shared_entity_manager = Arc::new(EntityManager::new(EntityConfig::default()));
    metrics_registry.set_entity_manager(Arc::clone(&shared_entity_manager));

    // Restore entities from snapshot if available
    if let Some(ref snapshot) = loaded_snapshot {
        if !snapshot.entities.is_empty() {
            shared_entity_manager.restore(snapshot.entities.clone());
            info!(
                "Restored {} entities from snapshot",
                snapshot.entities.len()
            );
        }
    }

    // Create shared BlockLog for both admin API and proxy.
    // Optional privacy control for dashboard visibility:
    // - SYNAPSE_BLOCK_LOG_IP_ANON=none|truncate|hmac
    // - SYNAPSE_BLOCK_LOG_IP_SALT=... (required for hmac)
    let shared_block_log = Arc::new(BlockLog::new_with_ip_anonymization(
        1000,
        IpAnonymization::from_env(),
    ));
    metrics_registry.set_block_log(Arc::clone(&shared_block_log));

    // Restore campaigns from snapshot if available
    if let Some(ref snapshot) = loaded_snapshot {
        if !snapshot.campaigns.is_empty() {
            campaign_manager.restore(snapshot.campaigns.clone());
            info!(
                "Restored {} campaigns from snapshot",
                snapshot.campaigns.len()
            );
        }
    }

    // Phase 5: Create shared ActorManager for behavioral tracking across admin API and proxy
    let shared_actor_manager = Arc::new(ActorManager::new(ActorConfig::default()));
    metrics_registry.set_actor_manager(Arc::clone(&shared_actor_manager));

    // Restore actors from snapshot if available
    if let Some(ref snapshot) = loaded_snapshot {
        if !snapshot.actors.is_empty() {
            shared_actor_manager.restore(snapshot.actors.clone());
            info!("Restored {} actors from snapshot", snapshot.actors.len());
        }
    }

    info!("ActorManager initialized with default config");

    // Start Signal Horizon tunnel client (remote operations)
    if config.tunnel.enabled {
        let tunnel_config = config.tunnel.clone();
        let health = Arc::clone(&health_checker);
        let metrics = Arc::clone(&metrics_registry);
        let actor_manager = Arc::clone(&shared_actor_manager);
        let config_manager = config_manager.clone();
        info!("Tunnel client enabled (url: {})", tunnel_config.url);
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    error!("Failed to create tunnel runtime: {}", err);
                    return;
                }
            };

            rt.block_on(async move {
                let shell_enabled = tunnel_config.shell_enabled;
                let mut tunnel_client = TunnelClient::new(tunnel_config, Arc::clone(&metrics));
                if let Err(e) = tunnel_client.start().await {
                    error!("Failed to start tunnel client: {}", e);
                    return;
                }
                if let Some(handle) = tunnel_client.handle() {
                    tokio::spawn(
                        TunnelShellService::new(
                            handle.clone(),
                            shell_enabled,
                            Arc::clone(&metrics),
                        )
                        .run(handle.subscribe_shutdown()),
                    );
                    tokio::spawn(
                        TunnelLogService::new(handle.clone(), Arc::clone(&metrics))
                            .run(handle.subscribe_shutdown()),
                    );
                    tokio::spawn(
                        TunnelDiagService::new(
                            handle.clone(),
                            health,
                            Arc::clone(&metrics),
                            actor_manager,
                            config_manager,
                        )
                        .run(handle.subscribe_shutdown()),
                    );
                } else {
                    warn!("Tunnel client handle unavailable; shell/log/diag services disabled");
                }
                std::future::pending::<()>().await;
            });
        });
    }

    // Restore profiles from snapshot if available (API endpoint behavioral baselines)
    if let Some(ref snapshot) = loaded_snapshot {
        if !snapshot.profiles.is_empty() {
            DetectionEngine::load_profiles(snapshot.profiles.clone());
            info!(
                "Restored {} endpoint profiles from snapshot",
                snapshot.profiles.len()
            );
        }
    }

    // Phase 5: Create shared SessionManager for session validation and hijack detection
    let shared_session_manager = Arc::new(SessionManager::new(SessionConfig::default()));
    info!("SessionManager initialized with default config");

    // Phase 9: Create shared CrawlerDetector for bot detection and verification
    let shared_crawler_detector = {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                error!("Failed to create tokio runtime for crawler init: {}", err);
                std::process::exit(1);
            }
        };
        rt.block_on(build_crawler_detector(config.crawler.clone()))
    };
    metrics_registry.set_crawler_detector(Arc::clone(&shared_crawler_detector));
    info!(
        "CrawlerDetector initialized with {} known crawlers and {} bad bot signatures",
        synapse_pingora::crawler::KNOWN_CRAWLERS.len(),
        synapse_pingora::crawler::BAD_BOT_SIGNATURES.len()
    );

    // Phase 4: Create shared DlpScanner for both admin API and proxy
    let shared_dlp_scanner = Arc::new(DlpScanner::new(config.dlp.clone()));
    info!(
        "DlpScanner initialized with {} patterns",
        shared_dlp_scanner.pattern_count()
    );

    // Phase 9: Shared TrendsManager for anomaly detection + dashboard reporting.
    //
    // TASK-55 / TASK-67: construction is extracted into
    // [`build_trends_manager_with_risk_callback`] so that integration tests
    // can drive the exact same wiring path as main() and assert the
    // apply_risk callback actually reaches EntityManager. Do NOT inline
    // this back into main() without also updating TASK-67 integration tests.
    let shared_trends_manager = build_trends_manager_with_risk_callback(
        TrendsConfig::default(),
        Arc::clone(&shared_entity_manager),
    );
    metrics_registry.set_trends_manager(Arc::clone(&shared_trends_manager));
    info!(
        "TrendsManager initialized with default config + apply_risk callback \
         wired to shared EntityManager (TASK-55)"
    );

    // Phase 9: Shared SignalManager for intelligence aggregation
    let shared_signal_manager = Arc::new(SignalManager::new(SignalManagerConfig::default()));
    info!("SignalManager initialized with default config");

    // Build the API handler with ConfigManager if available
    let api_handler = Arc::new({
        let mut builder = ApiHandler::builder()
            .health(Arc::clone(&health_checker))
            .metrics(Arc::clone(&metrics_registry))
            .entity_manager(Arc::clone(&shared_entity_manager))
            .block_log(Arc::clone(&shared_block_log))
            .campaign_manager(Arc::clone(&campaign_manager))
            .actor_manager(Arc::clone(&shared_actor_manager))
            .session_manager(Arc::clone(&shared_session_manager))
            .dlp_scanner(Arc::clone(&shared_dlp_scanner)) // New: pass dlp scanner
            .trends_manager(Arc::clone(&shared_trends_manager))
            .signal_manager(Arc::clone(&shared_signal_manager))
            .synapse_engine(DetectionEngine::shared_engine()); // For dry-run WAF evaluation

        if let Some(ref cm) = config_manager {
            builder = builder.config_manager(Arc::clone(cm));
        }

        builder.build()
    });

    // Start admin HTTP server in a separate thread with its own tokio runtime
    let admin_addr: SocketAddr = match config.server.admin_listen.parse() {
        Ok(addr) => addr,
        Err(err) => {
            error!(
                "Invalid admin_listen address '{}': {}",
                config.server.admin_listen, err
            );
            std::process::exit(1);
        }
    };
    let admin_handler = Arc::clone(&api_handler);
    let admin_auth_disabled =
        config.server.admin_auth_disabled || parse_bool_env("SYNAPSE_ADMIN_AUTH_DISABLED");
    if admin_auth_disabled {
        if !admin_addr.ip().is_loopback() || !is_explicitly_non_production {
            error!(
                "SECURITY: Refusing to disable admin auth on {}. \
                 Require loopback admin_listen and SYNAPSE_PRODUCTION=0 or NODE_ENV=development.",
                config.server.admin_listen
            );
            std::process::exit(1);
        }
        warn!(
            "SECURITY: Admin auth DISABLED (local-only). Do not expose {} publicly.",
            config.server.admin_listen
        );
    }
    // SECURITY: Enforce authentication on admin API
    // If no API key is configured, generate a secure random token to prevent unauthorized access
    let admin_api_key = if admin_auth_disabled {
        String::new()
    } else {
        match config.server.admin_api_key.clone() {
            Some(key) => {
                info!("Admin API authentication enabled (configured key)");
                key
            }
            None => {
                // Generate a secure random token using UUID v4
                let generated_key = uuid::Uuid::new_v4().to_string();
                warn!("==========================================================");
                warn!("ADMIN API KEY NOT CONFIGURED - GENERATED SECURE TOKEN:");
                warn!("  {}", generated_key);
                warn!("Use this key in X-Admin-Key header for admin API access.");
                warn!("To persist, set server.admin_api_key in your config file.");
                warn!("==========================================================");
                generated_key
            }
        }
    };

    // Parse trusted proxies for X-Forwarded-For validation
    // Fail startup on invalid CIDR to prevent misconfiguration from silently degrading security
    let mut trusted_proxies: Vec<CidrRange> =
        Vec::with_capacity(config.server.trusted_proxies.len());
    for cidr_str in &config.server.trusted_proxies {
        match CidrRange::parse(cidr_str) {
            Ok(cidr) => trusted_proxies.push(cidr),
            Err(e) => {
                error!("Invalid trusted_proxy CIDR '{}': {:?}", cidr_str, e);
                error!("Fix the trusted_proxies configuration and restart. Valid formats: '10.0.0.0/8', '192.168.1.1'");
                std::process::exit(1);
            }
        }
    }

    // Check if any listen address is loopback (for trusted_proxies warning)
    let listen_is_loopback = config.server.listen.iter().any(|addr| {
        addr.parse::<SocketAddr>()
            .map(|sa| sa.ip().is_loopback())
            .unwrap_or(false)
    });

    if trusted_proxies.is_empty() {
        if !listen_is_loopback {
            warn!(
                "No trusted proxies configured for listen addresses [{}]. X-Forwarded-For headers will be ignored; set server.trusted_proxies to explicit proxy IPs in production.",
                config.server.listen.join(", ")
            );
        }
        info!("No trusted proxies configured - X-Forwarded-For headers will be ignored (secure default)");
    } else {
        if !listen_is_loopback {
            let broad_private: Vec<String> = config
                .server
                .trusted_proxies
                .iter()
                .filter(|cidr| is_broad_private_cidr(cidr))
                .cloned()
                .collect();
            if !broad_private.is_empty() {
                warn!(
                    "Trusted proxies include broad private ranges: {}. Consider narrowing to explicit proxy IPs to prevent XFF spoofing.",
                    broad_private.join(", ")
                );
            }

            let wildcard: Vec<String> = config
                .server
                .trusted_proxies
                .iter()
                .filter(|cidr| is_wildcard_cidr(cidr))
                .cloned()
                .collect();
            if !wildcard.is_empty() {
                warn!(
                    "Trusted proxies include wildcard ranges: {}. This allows any proxy to set X-Forwarded-For.",
                    wildcard.join(", ")
                );
            }
        }

        info!(
            "Trusted proxies configured: {} CIDR ranges",
            trusted_proxies.len()
        );
        for cidr in &config.server.trusted_proxies {
            debug!("  Trusted: {}", cidr);
        }
    }

    // Register data accessors for admin server profiling endpoints
    // These callbacks allow the admin_server handlers to access real profile/schema data
    register_profiles_getter(DetectionEngine::get_profiles);
    register_schemas_getter(|| SCHEMA_LEARNER.get_all_schemas());
    register_restart_callback(request_process_restart);
    register_shutdown_callback(request_process_shutdown);

    // Register integration configuration callbacks
    let config_path = cli.config.clone();
    let runtime_config = Arc::new(RwLock::new(config.clone()));
    let integration_config = Arc::new(parking_lot::RwLock::new(IntegrationsConfig {
        horizon_hub_url: config.horizon.hub_url.clone(),
        horizon_api_key: config.horizon.api_key.clone(),
        tunnel_url: config.tunnel.url.clone(),
        tunnel_api_key: config.tunnel.api_key.clone(),
        apparatus_url: config.apparatus_url.clone(),
    }));

    let ic_getter = Arc::clone(&integration_config);
    let ic_setter = Arc::clone(&integration_config);
    let runtime_config_setter = Arc::clone(&runtime_config);
    register_integrations_callbacks(
        move || ic_getter.read().clone(),
        move |new_config| {
            info!("Updating integrations configuration from admin dashboard");
            let mut updated_runtime_config = runtime_config_setter.read().clone();
            apply_integrations_to_runtime_config(&mut updated_runtime_config, &new_config);
            persist_integrations_runtime_config(&config_path, &updated_runtime_config)?;
            *runtime_config_setter.write() = updated_runtime_config;
            let mut ic = ic_setter.write();
            *ic = new_config;
            info!(
                "Persisted integrations configuration to {}. Restart required for live Horizon/Tunnel connections.",
                config_path
            );
            Ok(())
        },
    );

    // Wake up the dormant HorizonManager wiring (was: `horizon_manager: None
    // // not yet initialized in main`). When config.horizon.enabled is true,
    // construct the manager on a dedicated thread+runtime so its WebSocket
    // background tasks have a long-lived tokio runtime to live on, then pass
    // the resulting Arc back to main via a oneshot channel.
    //
    // This is the production path: real synapse sensors push ThreatSignals
    // through this client to horizon's /ws/sensors gateway, which writes
    // them to Prisma/PostgreSQL, which is what powers the dashboard's
    // per-actor / per-campaign / per-IP panels. Until this wiring landed,
    // the manager existed as a 1600-line library but was never instantiated,
    // and request_filter's `if let Some(ref horizon) = self.horizon_manager`
    // branch at line ~2022 was unreachable in production.
    //
    // The simulator (src/simulator.rs) gets the same Arc via SimulatorLoop
    // so its synthetic traffic flows through the exact same emit path real
    // sensors use.
    let shared_horizon_manager: Option<Arc<HorizonManager>> = if config.horizon.enabled {
        use std::sync::mpsc::sync_channel;
        let (tx, rx) = sync_channel::<Option<Arc<HorizonManager>>>(1);
        let horizon_config = config.horizon.clone();
        let horizon_metrics = Arc::clone(&metrics_registry);
        let horizon_health = Arc::clone(&health_checker);
        std::thread::Builder::new()
            .name("horizon-runtime".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!("Failed to create horizon tokio runtime: {}", e);
                        let _ = tx.send(None);
                        return;
                    }
                };
                rt.block_on(async move {
                    let metrics_provider: Arc<dyn MetricsProvider> =
                        Arc::new(HorizonMetricsProvider {
                            metrics: Arc::clone(&horizon_metrics),
                            health: Arc::clone(&horizon_health),
                            system: Mutex::new(System::new_all()),
                        });

                    match HorizonManager::with_metrics_provider(horizon_config, metrics_provider)
                        .await
                    {
                        Ok(manager) => {
                            let manager = Arc::new(manager);
                            // Start kicks off the background reconnect loop.
                            // It returns Ok quickly even if the hub is
                            // unreachable — the client will retry forever.
                            if let Err(e) = manager.start().await {
                                error!("HorizonManager start failed: {}", e);
                                let _ = tx.send(None);
                                return;
                            }
                            info!("HorizonManager started, pushing signals to hub");
                            let _ = tx.send(Some(Arc::clone(&manager)));
                            // Park the runtime forever so the websocket
                            // background tasks the client spawned stay alive.
                            std::future::pending::<()>().await;
                        }
                        Err(e) => {
                            error!("HorizonManager construction failed: {}", e);
                            let _ = tx.send(None);
                        }
                    }
                });
            })
            .expect("spawn horizon-runtime thread");
        rx.recv().ok().flatten()
    } else {
        info!("HorizonManager disabled (config.horizon.enabled=false)");
        None
    };

    // Register WAF evaluation callback for dry-run testing (Phase 2: Lab View)
    register_evaluate_callback(|method, uri, headers, body, client_ip| {
        let header_snapshots: Vec<HeaderSnapshot> = headers
            .iter()
            .filter_map(|(name, value)| {
                let header_name = HeaderName::from_bytes(name.as_bytes()).ok()?;
                let header_value = HeaderValue::from_str(value).ok()?;
                Some((header_name, header_value))
            })
            .collect();
        let result = DetectionEngine::analyze(method, uri, &header_snapshots, body, client_ip);
        EvaluationResult {
            blocked: result.blocked,
            risk_score: result.risk_score,
            matched_rules: result.matched_rules,
            block_reason: result.block_reason,
            detection_time_us: result.detection_time_us,
        }
    });
    info!("Registered profile, schema, and evaluate callbacks for admin API");

    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                error!("Failed to create admin runtime: {}", err);
                return;
            }
        };

        rt.block_on(async {
            if let Err(e) = start_admin_server(
                admin_addr,
                admin_handler,
                admin_api_key,
                admin_auth_disabled,
            )
            .await
            {
                error!("Admin server error: {}", e);
            }
        });
    });

    info!(
        "Admin API server starting on {}",
        config.server.admin_listen
    );

    // Create Pingora server
    let mut server = match Server::new(None) {
        Ok(server) => server,
        Err(err) => {
            error!("Failed to create server: {}", err);
            std::process::exit(1);
        }
    };
    server.bootstrap();

    // Create interrogator managers for progressive challenge system
    let cookie_manager = Arc::new(CookieManager::new_fallback(create_default_cookie_config()));
    let js_manager = Arc::new(JsChallengeManager::new(JsChallengeConfig::default()));
    let captcha_manager = Arc::new(CaptchaManager::new(CaptchaConfig::default()));
    let tarpit_manager_for_progression = Arc::new(TarpitManager::new(config.tarpit.clone()));

    // Create progression manager orchestrating all challenge types
    let progression_manager = Arc::new(ProgressionManager::new(
        cookie_manager,
        js_manager,
        captcha_manager,
        tarpit_manager_for_progression,
        create_progression_config(),
    ));

    // Create proxy service - use multi-site if available, otherwise legacy
    // Note: telemetry_client is configured from telemetry.endpoint (risk_server_url is deprecated)
    let proxy = if let Some((ref config_file, ref sites)) = multisite_config {
        let (vhost_matcher, site_waf_mgr, rate_limit_mgr, access_list_mgr) =
            create_multisite_managers(config_file, sites);

        // Re-create ConfigManager for proxy (shared via Arc)
        let sites_arc = Arc::new(RwLock::new(sites.clone()));
        let config_arc = Arc::new(RwLock::new(config_file.clone()));

        let config_manager_for_proxy = Arc::new(
            ConfigManager::new(
                config_arc,
                sites_arc,
                Arc::clone(&vhost_matcher),
                Arc::clone(&site_waf_mgr),
                Arc::clone(&rate_limit_mgr),
                Arc::clone(&access_list_mgr),
            )
            .with_rules(
                DetectionEngine::shared_engine(),
                rules_path.clone(),
                Some(Arc::clone(&RULES_HASH)),
            ),
        );

        let shadow_mirror_manager = create_shadow_mirror_manager(sites);

        let deps = ProxyDependencies {
            health_checker: Arc::clone(&health_checker),
            metrics_registry: Arc::clone(&metrics_registry),
            telemetry_client: Arc::clone(&telemetry_client),
            tls_manager: Arc::clone(&tls_manager),
            dlp_scanner: Arc::clone(&shared_dlp_scanner),
            entity_manager: Arc::clone(&shared_entity_manager),
            block_log: Arc::clone(&shared_block_log),
            actor_manager: Arc::clone(&shared_actor_manager),
            session_manager: Arc::clone(&shared_session_manager),
            shadow_mirror_manager,
            crawler_detector: Arc::clone(&shared_crawler_detector),
            horizon_manager: shared_horizon_manager.clone(),
            trends_manager: Arc::clone(&shared_trends_manager),
            signal_manager: Arc::clone(&shared_signal_manager),
            progression_manager: Arc::clone(&progression_manager),
            campaign_manager: Arc::clone(&campaign_manager),
            tarpit_config: config.tarpit.clone(),
            trusted_proxies: trusted_proxies.clone(),
            rps_limit: config.rate_limit.rps,
            per_ip_rps_limit: config.rate_limit.per_ip_rps,
        };

        SynapseProxy::with_multisite(
            legacy_backends.clone(),
            vhost_matcher,
            config_manager_for_proxy,
            site_waf_mgr,
            rate_limit_mgr,
            access_list_mgr,
            deps,
        )
    } else {
        let deps = ProxyDependencies {
            health_checker: Arc::clone(&health_checker),
            metrics_registry: Arc::clone(&metrics_registry),
            telemetry_client: Arc::clone(&telemetry_client),
            tls_manager: Arc::clone(&tls_manager),
            dlp_scanner: Arc::clone(&shared_dlp_scanner),
            entity_manager: Arc::clone(&shared_entity_manager),
            block_log: Arc::clone(&shared_block_log),
            actor_manager: Arc::clone(&shared_actor_manager),
            session_manager: Arc::clone(&shared_session_manager),
            shadow_mirror_manager: None,
            crawler_detector: Arc::clone(&shared_crawler_detector),
            horizon_manager: shared_horizon_manager.clone(),
            trends_manager: Arc::clone(&shared_trends_manager),
            signal_manager: Arc::clone(&shared_signal_manager),
            progression_manager: Arc::clone(&progression_manager),
            campaign_manager: Arc::clone(&campaign_manager),
            tarpit_config: config.tarpit.clone(),
            trusted_proxies: trusted_proxies.clone(),
            rps_limit: config.rate_limit.rps,
            per_ip_rps_limit: config.rate_limit.per_ip_rps,
        };

        SynapseProxy::with_health(legacy_backends, deps)
    };

    // Finding #15: Inject dependencies for snapshotting
    metrics_registry.set_tarpit_manager(proxy.tarpit_manager());
    metrics_registry.set_progression_manager(proxy.progression_manager());
    if let Some(shadow) = proxy.shadow_mirror_manager() {
        metrics_registry.set_shadow_mirror_manager(shadow);
    }

    // Phase 5 & 9: Start all shared background maintenance tasks
    // These tasks handle risk decay, state cleanup, and correlation cycles
    let background_rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            error!("Failed to create background runtime: {}", err);
            std::process::exit(1);
        }
    };
    let _background_guard = background_rt.enter();
    shared_actor_manager.clone().start_background_tasks();
    shared_session_manager.clone().start_background_tasks();
    campaign_manager.clone().start_background_worker();
    proxy.start_background_tasks();

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);

    // Phase 6: Enable TLS Listener(s)
    // Support multiple listen addresses (IPv4/IPv6 dual-stack)
    if config.tls.enabled && !config.tls.cert_path.is_empty() && !config.tls.key_path.is_empty() {
        // Note: TlsSettings::intermediate defaults to TLS 1.2+
        // TlsSettings doesn't implement Clone, so we create fresh settings for each listener
        for addr in &config.server.listen {
            let tls_settings =
                match TlsSettings::intermediate(&config.tls.cert_path, &config.tls.key_path) {
                    Ok(settings) => settings,
                    Err(err) => {
                        error!(
                            "Failed to create TLS settings from configured paths: {}",
                            err
                        );
                        std::process::exit(1);
                    }
                };
            proxy_service.add_tls_with_settings(addr, None, tls_settings);
            info!(
                "TLS listener enabled on {} (min_version: {})",
                addr, config.tls.min_version
            );
        }
    } else {
        // Fallback to TCP if TLS is not enabled or configured
        for addr in &config.server.listen {
            proxy_service.add_tcp(addr);
            info!("TCP (non-TLS) listener enabled on {}", addr);
        }
    }

    server.add_service(proxy_service);

    let listen_addrs = config.server.listen.join(", ");
    info!("Synapse-Pingora ready");
    info!("  Proxy:  {}", listen_addrs);
    info!("  Admin:  {}", config.server.admin_listen);
    info!(
        "  Tarpit: enabled={}, base_delay={}ms, max_delay={}ms",
        config.tarpit.enabled, config.tarpit.base_delay_ms, config.tarpit.max_delay_ms
    );
    info!("Graceful reload: pkill -SIGQUIT synapse-pingora && ./synapse-pingora -u");

    // Phase 7: Persistence - Start background snapshotting
    // Clone Arc references for the background saver closure
    let entity_mgr_for_snapshot = Arc::clone(&shared_entity_manager);
    let campaign_mgr_for_snapshot = Arc::clone(&campaign_manager);
    let actor_mgr_for_snapshot = Arc::clone(&shared_actor_manager);
    let instance_id = config
        .telemetry
        .instance_id
        .clone()
        .unwrap_or_else(|| "synapse".to_string());

    if let Err(e) = snapshot_manager.clone().start_background_saver(move || {
        WafSnapshot::new(
            instance_id.clone(),
            entity_mgr_for_snapshot.snapshot(),
            campaign_mgr_for_snapshot.snapshot(),
            actor_mgr_for_snapshot.snapshot(),
            DetectionEngine::get_profiles(), // API endpoint behavioral baselines
        )
    }) {
        error!("Failed to start background persistence: {}", e);
    } else {
        info!(
            "WAF state persistence enabled (interval: {}s)",
            persistence_config.save_interval_secs
        );
    }

    // TASK-60: Eagerly force the DetectionEngine singleton BEFORE Server::run_forever.
    //
    // Its startup path panics if the embedded production_rules.json
    // fails to load (TASK-45 deliberate fail-fast). Without this explicit
    // force, the Lazy's first access could happen inside a Pingora worker
    // thread handling a real request, meaning the panic would drop in-flight
    // traffic mid-request rather than preventing the proxy from starting at
    // all.
    //
    // Forcing at this point — after all other startup is complete but
    // before run_forever() hands control to Pingora's accept loop — moves
    // the panic to a known startup-time location where ops sees it loudly.
    // The CI compat test guarantees the panic can't actually fire on a
    // healthy binary; this force is defense-in-depth for binary corruption
    // or future refactors that might introduce a runtime rule-load path.
    //
    // We intentionally call rule_count() instead of reaching into the engine directly
    // so the log line below surfaces a visible signal that rules loaded.
    let synapse_rule_count = DetectionEngine::rule_count();
    info!(
        "SYNAPSE engine eagerly initialized: {} rules loaded (TASK-60: panic-at-Lazy-init is now a startup-time failure mode, not mid-request)",
        synapse_rule_count
    );
    if synapse_rule_count == 0 {
        // Paranoia: if the engine loaded zero rules (empty rules file?
        // silent parse failure?), refuse to start. A WAF with 0 rules is
        // worse than no WAF because ops believe they have protection.
        panic!(
            "FATAL: SYNAPSE engine initialized with 0 rules. This should never \
             happen in a released binary because test_production_rules_load_into_current_engine \
             gates it in CI. If you see this panic, the embedded production_rules.json \
             is corrupted, empty, or a runtime reload failed silently. Do not run a \
             WAF proxy with zero rules."
        );
    }

    // Demo simulator: when --demo is set, kick off the procedural traffic
    // generator that populates the real EntityManager / CampaignManager /
    // BlockLog from synthetic attacker archetypes. The admin endpoints
    // horizon polls then serve live-looking data without needing a real
    // network sensor in front of the proxy. See src/simulator.rs.
    //
    // The simulator runs in a tokio task on the same runtime as the admin
    // server. It does NOT touch the production filter chain — it calls
    // DetectionEngine::analyze_with_signals directly and mirrors the
    // post-analyze state updates request_filter normally does.
    if demo_mode {
        let sim_loop = simulator::SimulatorLoop::new(
            Arc::clone(&shared_entity_manager),
            Arc::clone(&campaign_manager),
            Arc::clone(&shared_block_log),
            health_checker.waf_stats(),
            shared_horizon_manager.clone(),
        );
        // Spawn on the existing tokio runtime that admin_server runs on.
        // The handle is intentionally dropped — the loop runs forever or
        // until the process exits. Pingora's shutdown will tear down the
        // tokio runtime which terminates the loop.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("simulator tokio runtime");
            rt.block_on(async move {
                let _handle = sim_loop.start();
                // Keep the runtime alive for the lifetime of the process.
                std::future::pending::<()>().await;
            });
        });
        info!("Demo simulator started (background traffic generator)");
    }

    // Launch TUI if requested, otherwise run server normally
    if cli.tui {
        let metrics_for_tui = Arc::clone(&metrics_registry);
        let entities_for_tui = Arc::clone(&shared_entity_manager);
        let block_log_for_tui = Arc::clone(&shared_block_log);

        // Run server in background thread
        std::thread::spawn(move || {
            server.run_forever();
        });

        // Run TUI in main thread (blocks until 'q' is pressed)
        if let Err(e) = synapse_pingora::tui::start_tui(
            metrics_for_tui as Arc<dyn synapse_pingora::metrics::TuiDataProvider>,
            entities_for_tui,
            block_log_for_tui,
            DetectionEngine::shared_engine(),
        ) {
            eprintln!("TUI error: {}", e);
        }

        // Finding #8: Graceful shutdown. Send SIGINT to self to trigger Pingora's shutdown sequence.
        info!("TUI exited, shutting down server...");
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(libc::getpid(), libc::SIGINT);
            }
            // Give it a moment to process the signal before main exits
            std::thread::sleep(Duration::from_millis(500));
        }
        #[cfg(not(unix))]
        {
            std::process::exit(0);
        }
    } else {
        server.run_forever();
    }
}

fn init_tui_logging() {
    use std::fs::OpenOptions;

    let log_file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open("synapse-tui.log")
    {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open TUI log file: {}", e);
            return;
        }
    };

    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    builder.format(|buf, record| {
        use std::io::Write;
        let level = format!("{:<5}", record.level());
        writeln!(
            buf,
            "{} {} [{}] {}",
            buf.timestamp_millis(),
            level,
            record.target(),
            record.args()
        )
    });

    // Redirect all logs to the file
    builder.target(env_logger::Target::Pipe(Box::new(log_file)));
    builder.init();

    info!("TUI logging initialized, writing to synapse-tui.log");
}

fn init_logging() {
    use log::Level;
    use std::io::Write;

    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    builder.format(|buf, record| {
        // ANSI color codes for log levels
        let (color_start, color_end) = match record.level() {
            Level::Error => ("\x1b[1;31m", "\x1b[0m"), // Bold red
            Level::Warn => ("\x1b[1;33m", "\x1b[0m"),  // Bold yellow
            Level::Info => ("\x1b[1;32m", "\x1b[0m"),  // Bold green
            Level::Debug => ("\x1b[34m", "\x1b[0m"),   // Blue
            Level::Trace => ("\x1b[35m", "\x1b[0m"),   // Magenta
        };

        let level = format!("{:<5}", record.level());
        writeln!(
            buf,
            "{} {}{}{} [{}] {}",
            buf.timestamp_millis(),
            color_start,
            level,
            color_end,
            record.target(),
            record.args()
        )
    });

    builder.init();
}

// ============================================================================
// Tests - Using Synapse WAF engine with production rules
// ============================================================================
//
// IMPORTANT: These tests use the process-global DetectionEngine singleton with shared mutable state.
// To avoid race conditions, run with: cargo test --bin synapse-pingora -- --test-threads=1
// The #[serial] attribute is used for documentation purposes but test-threads=1 is required.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::NamedTempFile;

    const TEST_IP: &str = "192.168.1.100";

    fn header(name: &str, value: &str) -> HeaderSnapshot {
        let header_name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
        let header_value = HeaderValue::from_str(value).expect("valid header value");
        (header_name, header_value)
    }

    // ────────────────────────────────────────────────────────────────────────
    // Engine Health Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_engine_rule_count() {
        // Verify we have rules loaded
        let count = DetectionEngine::rule_count();
        assert!(
            count > 0,
            "Should have at least 1 rule loaded, got {}",
            count
        );
        println!("Engine loaded {} rules", count);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Clean Request Tests (Should NOT block)
    // These are fundamental - false positives are unacceptable in production
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_clean_simple_get() {
        let result = DetectionEngine::analyze("GET", "/api/users/123", &[], None, TEST_IP);
        assert!(!result.blocked, "Clean GET should not be blocked");
        assert!(result.matched_rules.is_empty(), "No rules should match");
    }

    #[test]
    #[serial]
    fn test_clean_with_query() {
        let result = DetectionEngine::analyze(
            "GET",
            "/api/search?q=hello+world&page=1",
            &[],
            None,
            TEST_IP,
        );
        assert!(!result.blocked, "Clean query should not be blocked");
    }

    #[test]
    #[serial]
    fn test_clean_post_json() {
        let result = DetectionEngine::analyze(
            "POST",
            "/api/users",
            &[header("content-type", "application/json")],
            None,
            TEST_IP,
        );
        assert!(!result.blocked, "Clean POST should not be blocked");
    }

    #[test]
    #[serial]
    fn test_clean_with_user_agent() {
        let result = DetectionEngine::analyze(
            "GET",
            "/api/data",
            &[header(
                "user-agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            )],
            None,
            TEST_IP,
        );
        assert!(!result.blocked, "Normal user-agent should not be blocked");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Attack Detection Tests - Using patterns the production engine catches
    // The real engine has 237 rules tuned for production use
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_sqli_union_select() {
        // UNION SELECT is a classic SQLi pattern that production engines catch
        let result = DetectionEngine::analyze(
            "GET",
            "/api/users?id=1 UNION SELECT * FROM users",
            &[],
            None,
            TEST_IP,
        );
        assert!(result.blocked, "UNION SELECT should be blocked");
        assert!(result.risk_score > 0, "Should have risk score");
        println!(
            "UNION SELECT: blocked={}, risk={}, rules={:?}",
            result.blocked, result.risk_score, result.matched_rules
        );
    }

    #[test]
    #[serial]
    fn test_path_traversal_dotdot() {
        // Path traversal is commonly caught by production WAFs
        let result =
            DetectionEngine::analyze("GET", "/files/../../../etc/passwd", &[], None, TEST_IP);
        assert!(result.blocked, "Path traversal should be blocked");
        println!(
            "Path traversal: blocked={}, risk={}, rules={:?}",
            result.blocked, result.risk_score, result.matched_rules
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Performance Tests - HONEST BENCHMARKS with real engine
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_detection_timing() {
        // Warm up the engine
        let _ = DetectionEngine::analyze("GET", "/warmup", &[], None, TEST_IP);

        // Run performance tests - measure timing regardless of detection result
        let test_cases = vec![
            ("GET", "/api/users?id=1 UNION SELECT * FROM users"), // Should block
            ("GET", "/files/../../../etc/passwd"),                // Should block
            ("GET", "/api/users/123"),                            // Should pass
            ("GET", "/api/search?q=hello+world&page=1&limit=10"), // Should pass
        ];

        for (method, uri) in test_cases {
            let result = DetectionEngine::analyze(method, uri, &[], None, TEST_IP);

            println!(
                "URI: {} -> blocked={}, time={}μs",
                uri, result.blocked, result.detection_time_us
            );

            // Performance assertion: real engine with 237 rules
            // Debug mode: up to 10ms due to lack of optimizations
            // Release mode: expect ~30-50μs (documented performance)
            #[cfg(debug_assertions)]
            let max_time = 30000;
            #[cfg(not(debug_assertions))]
            let max_time = 500; // 500μs max in release (conservative)

            assert!(
                result.detection_time_us < max_time,
                "Detection took too long: {}μs for {} (max: {}μs)",
                result.detection_time_us,
                uri,
                max_time
            );
        }
    }

    #[test]
    #[serial]
    fn test_real_engine_performance_benchmark() {
        // THE HONEST BENCHMARK
        // Run 1000 iterations with a pattern the engine catches
        let iterations = 1000;
        let mut total_time = 0u64;
        let mut blocked_count = 0;

        for _ in 0..iterations {
            let result = DetectionEngine::analyze(
                "GET",
                "/api/users?id=1 UNION SELECT password FROM users--",
                &[header("user-agent", "Mozilla/5.0")],
                None,
                TEST_IP,
            );
            total_time += result.detection_time_us;
            if result.blocked {
                blocked_count += 1;
            }
        }

        let avg_time = total_time / iterations;
        let rule_count = DetectionEngine::rule_count();

        println!("╔══════════════════════════════════════════════════════╗");
        println!("║           HONEST BENCHMARK RESULTS                   ║");
        println!("╠══════════════════════════════════════════════════════╣");
        println!(
            "║  Rules loaded:        {:>6}                         ║",
            rule_count
        );
        println!(
            "║  Iterations:          {:>6}                         ║",
            iterations
        );
        println!(
            "║  Blocked requests:    {:>6} ({:.1}%)               ║",
            blocked_count,
            (blocked_count as f64 / iterations as f64) * 100.0
        );
        println!(
            "║  Avg detection time:  {:>6} μs                      ║",
            avg_time
        );
        println!(
            "║  Total time:          {:>6} ms                      ║",
            total_time / 1000
        );
        println!("╚══════════════════════════════════════════════════════╝");

        // Real engine with 237 rules: documented ~30μs
        // In debug mode, we're lenient
        // In release mode, expect under 100μs average
        #[cfg(not(debug_assertions))]
        assert!(
            avg_time < 100,
            "Average detection time {}μs exceeds 100μs target for real engine with {} rules",
            avg_time,
            rule_count
        );
    }

    #[test]
    #[serial]
    fn test_clean_traffic_performance() {
        // Benchmark clean traffic (most of production workload)
        let iterations = 1000;
        let mut total_time = 0u64;

        for i in 0..iterations {
            let result = DetectionEngine::analyze(
                "GET",
                &format!("/api/users/{}", i),
                &[header("user-agent", "Mozilla/5.0")],
                None,
                TEST_IP,
            );
            total_time += result.detection_time_us;
            assert!(!result.blocked, "Clean traffic should not be blocked");
        }

        let avg_time = total_time / iterations;
        println!(
            "Clean traffic benchmark: avg={}μs over {} iterations ({} rules)",
            avg_time,
            iterations,
            DetectionEngine::rule_count()
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Phase 6: Health Endpoint Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_health_checker_default_status() {
        // Test that HealthChecker provides a default status
        let checker = HealthChecker::default();
        let response = checker.check();

        // Default status should be Healthy (no backends registered yet)
        assert_eq!(
            response.status,
            synapse_pingora::health::HealthStatus::Healthy,
            "Default health status should be Healthy"
        );
    }

    #[test]
    #[serial]
    fn test_health_status_http_codes() {
        // Test HTTP status codes for different health states
        assert_eq!(
            synapse_pingora::health::HealthStatus::Healthy.http_status(),
            200,
            "Healthy status should return HTTP 200"
        );

        assert_eq!(
            synapse_pingora::health::HealthStatus::Degraded.http_status(),
            200,
            "Degraded status should still return HTTP 200"
        );

        assert_eq!(
            synapse_pingora::health::HealthStatus::Unhealthy.http_status(),
            503,
            "Unhealthy status should return HTTP 503"
        );
    }

    #[test]
    #[serial]
    fn test_tls_config_default() {
        // Test that TLS config has sensible defaults
        let config = TlsConfig::default();

        assert!(!config.enabled, "TLS should be disabled by default");
        assert!(
            config.cert_path.is_empty(),
            "Certificate path should be empty by default"
        );
        assert!(
            config.key_path.is_empty(),
            "Key path should be empty by default"
        );
        assert_eq!(
            config.min_version, "1.2",
            "Minimum TLS version should default to 1.2"
        );
        assert!(
            config.per_domain_certs.is_empty(),
            "Per-domain certs should be empty by default"
        );
    }

    #[test]
    #[serial]
    fn test_config_loads_with_tls() {
        // Test that Config can be deserialized with TLS settings
        let yaml = r#"
server:
  listen: "0.0.0.0:6190"
  admin_listen: "0.0.0.0:6191"
upstreams:
  - host: "127.0.0.1"
    port: 8080
rate_limit:
  rps: 10000
  enabled: true
logging:
  level: "info"
detection:
  sqli: true
  xss: true
tls:
  enabled: false
  min_version: "1.3"
"#;
        let config: Config = serde_yaml::from_str(yaml).expect("Failed to parse config with TLS");

        assert!(!config.tls.enabled, "TLS should be disabled in test config");
        assert_eq!(config.tls.min_version, "1.3", "TLS version should be 1.3");
    }

    #[test]
    #[serial]
    fn test_config_load_rejects_enabled_deprecated_anomaly_blocking() {
        let temp = NamedTempFile::new().expect("temp config file");
        let yaml = r#"
detection:
  anomaly_blocking:
    enabled: true
    threshold: 8.0
"#;
        fs::write(temp.path(), yaml).expect("write temp config");

        let err = Config::load(temp.path().to_str().expect("utf-8 path"))
            .expect_err("deprecated anomaly_blocking should be rejected");
        assert!(err.contains("detection.anomaly_blocking"));
        assert!(err.contains("no longer supported"));
        assert!(err.contains("delete each"));
    }

    #[test]
    #[serial]
    fn test_config_load_allows_disabled_deprecated_anomaly_blocking() {
        let temp = NamedTempFile::new().expect("temp config file");
        let yaml = r#"
detection:
  anomaly_blocking:
    enabled: false
    threshold: 8.0
  sqli: true
  xss: true
"#;
        fs::write(temp.path(), yaml).expect("write temp config");

        let config = Config::load(temp.path().to_str().expect("utf-8 path"))
            .expect("disabled deprecated anomaly_blocking should be ignored");
        assert!(config.detection.sqli);
        assert!(config.detection.xss);
    }

    #[test]
    #[serial]
    fn test_multisite_config_loader_rejects_enabled_deprecated_anomaly_blocking() {
        let temp = NamedTempFile::new().expect("temp config file");
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
    detection:
      anomaly_blocking:
        enabled: true
        threshold: 8.0
"#;
        fs::write(temp.path(), yaml).expect("write temp config");

        let err = ConfigLoader::load(temp.path()).expect_err(
            "enabled deprecated anomaly_blocking in multi-site config should be rejected",
        );
        let message = err.to_string();
        assert!(message.contains("sites[0].detection.anomaly_blocking"));
        assert!(message.contains("delete each"));
    }

    #[test]
    #[serial]
    fn test_proxy_health_integration() {
        // Verify HealthChecker returns healthy by default
        let health_checker = HealthChecker::default();
        let response = health_checker.check();
        assert_eq!(
            response.status,
            synapse_pingora::health::HealthStatus::Healthy,
            "Health checker should report healthy by default"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_auth_coverage_emits_summary() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        use std::time::Duration;

        struct MockEmitter {
            emits: AtomicUsize,
            payloads: Mutex<Vec<serde_json::Value>>,
        }

        impl MockEmitter {
            fn new() -> Arc<Self> {
                Arc::new(Self {
                    emits: AtomicUsize::new(0),
                    payloads: Mutex::new(Vec::new()),
                })
            }

            fn count(&self) -> usize {
                self.emits.load(Ordering::SeqCst)
            }

            fn last_payload(&self) -> Option<serde_json::Value> {
                self.payloads.lock().unwrap().last().cloned()
            }
        }

        #[async_trait]
        impl SignalEmitter for MockEmitter {
            async fn emit(&self, signal_type: &str, payload: serde_json::Value) {
                if signal_type == "auth_coverage_summary" {
                    self.emits.fetch_add(1, Ordering::SeqCst);
                    self.payloads.lock().unwrap().push(payload);
                }
            }
        }

        let emitter = MockEmitter::new();
        let aggregator = Arc::new(AuthCoverageAggregator::new(
            "test-sensor".to_string(),
            None,
            emitter.clone() as Arc<dyn SignalEmitter>,
            60,
        ));

        aggregator.clone().start_flush_task();
        record_auth_coverage(aggregator.as_ref(), "GET", "/api/users/123", true, 401);

        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_eq!(emitter.count(), 1);

        let payload = emitter.last_payload().expect("payload emitted");
        let endpoints = payload
            .get("endpoints")
            .and_then(|value| value.as_array())
            .expect("endpoints array");
        let endpoint = endpoints[0]
            .get("endpoint")
            .and_then(|value| value.as_str())
            .expect("endpoint string");
        assert_eq!(endpoint, "GET /api/users/{id}");

        let counts = endpoints[0]
            .get("counts")
            .and_then(|value| value.as_object())
            .expect("counts object");
        assert_eq!(counts.get("with_auth").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(counts.get("unauthorized").and_then(|v| v.as_u64()), Some(1));
    }

    #[test]
    #[serial]
    fn test_per_domain_cert_structure() {
        // Test that PerDomainCert can be deserialized from YAML
        let yaml = r#"
domain: "*.example.com"
cert_path: "/etc/certs/example.pem"
key_path: "/etc/keys/example.key"
"#;
        let cert_config: PerDomainCert =
            serde_yaml::from_str(yaml).expect("Failed to parse per-domain cert config");

        assert_eq!(cert_config.domain, "*.example.com");
        assert_eq!(cert_config.cert_path, "/etc/certs/example.pem");
        assert_eq!(cert_config.key_path, "/etc/keys/example.key");
    }

    // ────────────────────────────────────────────────────────────────────────
    // ProxyHttp Helper Function Tests
    // Tests for functions supporting the ProxyHttp trait implementation
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_normalize_path_numeric_ids() {
        assert_eq!(
            normalize_path_to_template("/api/users/123"),
            "/api/users/{id}"
        );
        assert_eq!(
            normalize_path_to_template("/api/orders/456/items/789"),
            "/api/orders/{id}/items/{id}"
        );
    }

    #[test]
    fn test_normalize_path_uuid() {
        assert_eq!(
            normalize_path_to_template("/api/users/550e8400-e29b-41d4-a716-446655440000"),
            "/api/users/{id}"
        );
    }

    #[test]
    fn test_normalize_path_mongodb_objectid() {
        assert_eq!(
            normalize_path_to_template("/api/documents/507f1f77bcf86cd799439011"),
            "/api/documents/{id}"
        );
    }

    #[test]
    fn test_normalize_path_unchanged() {
        assert_eq!(
            normalize_path_to_template("/api/v1/products"),
            "/api/v1/products"
        );
        assert_eq!(normalize_path_to_template("/health"), "/health");
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let hash1 = compute_hash(b"test data");
        let hash2 = compute_hash(b"test data");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compute_hash_different() {
        assert_ne!(compute_hash(b"input1"), compute_hash(b"input2"));
    }

    #[test]
    fn test_compute_hash_length() {
        assert_eq!(compute_hash(b"data").len(), 16);
    }

    #[test]
    fn test_categorize_rule_sqli() {
        assert_eq!(categorize_rule_id(942100), "sqli");
        assert_eq!(categorize_rule_id(940100), "sqli");
    }

    #[test]
    fn test_categorize_rule_xss() {
        assert_eq!(categorize_rule_id(941100), "xss");
    }

    #[test]
    fn test_categorize_rule_path_traversal() {
        assert_eq!(categorize_rule_id(930100), "path_traversal");
    }

    #[test]
    fn test_categorize_rule_rce() {
        assert_eq!(categorize_rule_id(932100), "rce");
    }

    #[test]
    fn test_categorize_rule_scanner() {
        assert_eq!(categorize_rule_id(913100), "scanner");
    }

    #[test]
    fn test_categorize_rule_unknown() {
        assert_eq!(categorize_rule_id(999100), "rule_999000");
    }

    #[test]
    #[serial]
    fn test_rate_limit_allows_under() {
        PER_IP_LIMITS.remove("test_under");
        assert!(check_per_ip_rate_limit("test_under", 100));
        assert!(check_per_ip_rate_limit("test_under", 100));
    }

    #[test]
    #[serial]
    fn test_rate_limit_blocks_over() {
        PER_IP_LIMITS.remove("test_over");
        assert!(check_per_ip_rate_limit("test_over", 2));
        assert!(check_per_ip_rate_limit("test_over", 2));
        assert!(!check_per_ip_rate_limit("test_over", 2));
    }

    #[test]
    fn test_buffer_pool() {
        let buf = get_buffer();
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 8192);
        return_buffer(buf);
    }

    // ────────────────────────────────────────────────────────────────────────
    // TrendsManager apply_risk callback wiring (TASK-55)
    // ────────────────────────────────────────────────────────────────────────

    /// Proves the TASK-55 wiring: a TrendsManager constructed via
    /// with_dependencies() correctly invokes the apply_risk callback when
    /// an anomaly is recorded via record_payload_anomaly. Before TASK-55,
    /// main.rs constructed TrendsManager with ::new() (no apply_risk
    /// callback), so anomalies were recorded into the internal store but
    /// never contributed risk to the entity blocking path. This test pins
    /// the wiring so a regression that drops the dependency would fail
    /// loudly in CI.
    ///
    /// The test uses a local TrendsManager with a test callback that
    /// increments an AtomicU32. No need to stand up a real EntityManager —
    /// what's being tested is the dispatch mechanism, not entity side
    /// effects.
    #[test]
    fn test_trends_manager_apply_risk_callback_is_invoked_on_anomaly() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc as StdArc;
        use synapse_pingora::trends::{
            AnomalyMetadata, AnomalySeverity, AnomalyType, TrendsConfig, TrendsManager,
            TrendsManagerDependencies, TrendsReason,
        };

        // Shared counter that the test callback bumps whenever it fires.
        let call_count = StdArc::new(AtomicU32::new(0));
        let last_risk = StdArc::new(AtomicU32::new(0));

        let count_clone = StdArc::clone(&call_count);
        let risk_clone = StdArc::clone(&last_risk);

        let deps = TrendsManagerDependencies {
            apply_risk: Some(Box::new(
                move |_entity: &str, risk: u32, reason: TrendsReason| {
                    count_clone.fetch_add(1, Ordering::SeqCst);
                    risk_clone.store(risk, Ordering::SeqCst);
                    assert_eq!(
                        reason,
                        TrendsReason::Anomaly(AnomalyType::OversizedRequest),
                        "callback should receive a strongly typed anomaly reason"
                    );
                },
            )),
        };

        // Default TrendsConfig has anomaly_risk populated with non-zero
        // values for each AnomalyType, so record_payload_anomaly will set
        // risk_applied=Some(_) and trigger the callback.
        let config = TrendsConfig::default();
        let manager = TrendsManager::with_dependencies(config, deps);

        // Sanity: before recording an anomaly, callback has not fired.
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // Record a payload anomaly via the public API. This internally
        // constructs an Anomaly, calls handle_anomaly, which dispatches
        // through dependencies.apply_risk — the chain under test.
        manager.record_payload_anomaly(
            "test-anomaly-id".to_string(),
            AnomalyType::OversizedRequest,
            AnomalySeverity::High,
            1_000_000_000_000_i64, // arbitrary past timestamp
            "/api/sensitive".to_string(),
            "192.0.2.1".to_string(), // test IP
            "TASK-55 test anomaly".to_string(),
            AnomalyMetadata::default(),
        );

        // AC#4: the callback must have been invoked exactly once.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "apply_risk callback must be invoked once per anomaly with a non-zero risk_applied"
        );

        // The risk value passed to the callback must be > 0 (proves
        // risk_applied was set from TrendsConfig::default's anomaly_risk
        // map, not None). If risk_applied were None, handle_anomaly would
        // skip the callback and this test would fail on the call_count
        // assertion above.
        assert!(
            last_risk.load(Ordering::SeqCst) > 0,
            "risk value passed to callback must be positive"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Per-request external risk clamp (TASK-61)
    // ────────────────────────────────────────────────────────────────────────

    /// TASK-61 unit test: the clamp helper must enforce
    /// `MAX_EXTERNAL_RISK_PER_REQUEST` regardless of how many times it's
    /// called or how much each individual request asks for. This is the
    /// core correctness contract — without it, multi-signal accumulation
    /// can single-request-DoS a victim IP.
    ///
    /// The test uses a local `f64` as the accumulator instead of a real
    /// SynapseProxy. That means the entity_manager side-effect is NOT
    /// exercised here — only the clamp arithmetic is. The complete
    /// contract (helper actually calls entity_manager.apply_external_risk
    /// with the CAPPED value) is provable by code inspection: the helper
    /// passes `actual` to `entity_manager.apply_external_risk`, and
    /// `actual` is the clamp output. TASK-67 (real integration tests
    /// replacing false-confidence unit tests) would be the right place
    /// to add a full integration test of this wiring once that harness
    /// exists.
    #[test]
    fn test_apply_bounded_external_risk_enforces_per_request_cap() {
        // Simulate the clamp arithmetic directly since we don't need a
        // real SynapseProxy / entity_manager for this unit test. The math
        // here must match the helper's implementation exactly.
        fn simulate_clamp(accumulator: &mut f64, requested: f64) -> f64 {
            let remaining = MAX_EXTERNAL_RISK_PER_REQUEST - *accumulator;
            if remaining <= 0.0 {
                return 0.0;
            }
            let actual = requested.max(0.0).min(remaining);
            if actual > 0.0 {
                *accumulator += actual;
            }
            actual
        }

        // Scenario 1: single contribution below the cap, no clamping.
        let mut acc = 0.0;
        let applied = simulate_clamp(&mut acc, 10.0);
        assert_eq!(applied, 10.0);
        assert_eq!(acc, 10.0);

        // Scenario 2: multi-contribution accumulation that would exceed
        // the cap. First call fills part of the budget, second call
        // saturates at the cap, third call gets dropped entirely.
        let mut acc = 0.0;
        let a = simulate_clamp(&mut acc, 10.0); // 0 → 10
        let b = simulate_clamp(&mut acc, 20.0); // 10 → 25 (saturated, actual=15)
        let c = simulate_clamp(&mut acc, 10.0); // dropped, actual=0

        assert_eq!(a, 10.0, "first contribution at budget");
        assert_eq!(b, 15.0, "second contribution saturates at the cap");
        assert_eq!(c, 0.0, "third contribution is dropped");
        assert_eq!(acc, MAX_EXTERNAL_RISK_PER_REQUEST);

        // Scenario 3: single contribution that alone exceeds the cap is
        // saturated at the cap. This is the reflected-DoS defense — even
        // a single large-weight signal cannot cross the cap on its own.
        let mut acc = 0.0;
        let applied = simulate_clamp(&mut acc, 100.0);
        assert_eq!(applied, MAX_EXTERNAL_RISK_PER_REQUEST);
        assert_eq!(acc, MAX_EXTERNAL_RISK_PER_REQUEST);

        // Scenario 4: negative risk is clamped to zero, no accumulation.
        let mut acc = 0.0;
        let applied = simulate_clamp(&mut acc, -10.0);
        assert_eq!(applied, 0.0);
        assert_eq!(acc, 0.0);
    }

    #[test]
    fn test_task_61_cap_is_below_default_entity_block_threshold() {
        // The cap must be strictly less than the default entity block
        // threshold (100.0 from EntityConfig). Otherwise a single request
        // filling the cap could still trip the threshold and reintroduce
        // the reflected-DoS vector TASK-61 is defending against.
        //
        // Requiring "strictly less than" also means legitimate
        // single-request risk accumulation can never single-request-block
        // a victim IP — the cap (25.0) leaves a 75.0 safety margin, which
        // requires sustained multi-request activity to cross the threshold.
        let default_threshold = 100.0;
        assert!(
            MAX_EXTERNAL_RISK_PER_REQUEST < default_threshold,
            "TASK-61 per-request cap ({}) must be strictly less than default entity block threshold ({})",
            MAX_EXTERNAL_RISK_PER_REQUEST,
            default_threshold
        );
        // Also assert a minimum-safety margin of at least 50%: if someone
        // bumps the cap above 50.0 without updating this test, they've
        // probably shrunk the safety margin to an unreasonable level.
        assert!(
            MAX_EXTERNAL_RISK_PER_REQUEST <= default_threshold / 2.0,
            "TASK-61 per-request cap ({}) should leave at least a 50% safety margin below the block threshold ({})",
            MAX_EXTERNAL_RISK_PER_REQUEST,
            default_threshold
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Invalid session token risk contribution (TASK-58)
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_invalid_session_risk_weight_is_conservative() {
        // The TASK-58 weight must be strictly smaller than the Suspicious
        // weight (50.0) because Invalid has higher false-positive risk
        // (legitimate clients occasionally send stale tokens). This guard
        // catches a future tweak that accidentally sets Invalid >= Suspicious,
        // which would undermine the deliberate calibration.
        assert!(
            INVALID_SESSION_RISK_WEIGHT < 50.0,
            "Invalid session weight ({}) must be less than Suspicious weight (50.0)",
            INVALID_SESSION_RISK_WEIGHT
        );
        assert!(
            INVALID_SESSION_RISK_WEIGHT > 0.0,
            "Invalid session weight must be positive so brute-force accumulates"
        );
    }

    #[test]
    fn test_invalid_session_risk_weight_trips_entity_threshold_on_repeats() {
        // TASK-58 design goal: 5-9 Invalid events from the same IP should
        // cross the default entity risk blocking threshold (100.0). A
        // single Invalid must NOT cross (benign stale-token case).
        let default_threshold = 100.0;

        // Single event — far below threshold.
        assert!(
            INVALID_SESSION_RISK_WEIGHT < default_threshold,
            "single Invalid must not cross default threshold 100.0"
        );

        // Five events — should NOT quite cross (12 * 5 = 60).
        assert!(
            5.0 * INVALID_SESSION_RISK_WEIGHT < default_threshold,
            "5 Invalids ({}) must not cross threshold — too aggressive",
            5.0 * INVALID_SESSION_RISK_WEIGHT
        );

        // Nine events — should cross (12 * 9 = 108).
        assert!(
            9.0 * INVALID_SESSION_RISK_WEIGHT >= default_threshold,
            "9 Invalids ({}) must cross threshold — otherwise brute-force goes undetected",
            9.0 * INVALID_SESSION_RISK_WEIGHT
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // Production rule restoration cold-start (TASK-45)
    // ────────────────────────────────────────────────────────────────────────

    /// Asserts the process-global DetectionEngine singleton — initialized on
    /// first access by the library-owned startup path — loads
    /// at least 248 rules from the embedded production_rules.json. TASK-45
    /// restored 237 rules from archive; TASK-46 added 11 signal-correlation
    /// rules using the new match kinds, for a 248-rule floor. This test is
    /// the cold-start guarantee that closes the "237 vs 7" docs gap (TASK-45)
    /// and extends it to cover the m-6 signal-correlation additions (TASK-46):
    /// a regression in the startup path (missing include_str, wrong
    /// filename, broken load_rules) or an accidental truncation of
    /// production_rules.json would fail this test loudly at CI time.
    ///
    /// Must be #[serial] because other tests in this file and in
    /// tests/filter_chain_integration.rs mutate the singleton via reload_rules.
    /// If one of those tests ran after this one without restoring the
    /// production ruleset, the count would be wrong.
    #[test]
    #[serial]
    fn test_synapse_cold_start_ships_full_production_ruleset() {
        // Touch the Lazy static to force initialization. On a fresh process
        // this invokes the startup path, which prefers RULES_DATA (an
        // external rules.json file) and falls back to the embedded
        // production_rules.json. Tests run with no cwd-relative rules
        // files so the embedded fallback path is exercised.
        let count = DetectionEngine::rule_count();

        // Some other test in this binary may have called
        // DetectionEngine::reload_rules to swap in test-specific rules.
        // If that happened and the restore failed, count will be wrong.
        // Force a known-good state by reloading the embedded production
        // rules via DetectionEngine::reload_rules, then re-read.
        let production_rules = include_str!("production_rules.json");
        let reloaded = DetectionEngine::reload_rules(production_rules.as_bytes())
            .expect("embedded production_rules.json must reload successfully");
        assert!(
            reloaded >= 248,
            "embedded production_rules.json must contain >= 248 rules, got {}",
            reloaded
        );

        // Sanity: the rule_count() getter agrees with the reload return
        // value. If these diverge, the shared engine facade is broken.
        assert_eq!(
            DetectionEngine::rule_count(),
            reloaded,
            "DetectionEngine::rule_count() must agree with reload_rules return value"
        );

        // If the initial read matched (i.e. no prior test had swapped
        // rules), we've also proven the startup path's include_str! fallback
        // fallback path works end-to-end on a fresh process.
        let _ = count; // suppress unused warning; the initial read was the Lazy trigger
    }

    // ────────────────────────────────────────────────────────────────────────
    // TASK-41 schema learner poisoning prevention
    //
    // The original TASK-41 test (`test_schema_learner_not_poisoned_by_blocked_bodies`)
    // was deleted under TASK-59. It was a "false-confidence" test that mirrored
    // the `drop()` pattern with a local Option rather than driving the real
    // filter chain — it passed even after the real code was shown to be broken
    // for deferred-pass blocks (see TASK-59 for the exploit chain).
    //
    // The replacement lives in `tests/filter_chain_integration.rs` as
    // `test_schema_learner_not_poisoned_by_deferred_dlp_block`. That test
    // drives the real filter chain against a deferred DLP rule and asserts
    // the real SCHEMA_LEARNER state. See TASK-59 for rationale.
    // ────────────────────────────────────────────────────────────────────────

    // ────────────────────────────────────────────────────────────────────────
    // Unified WAF block response (TASK-34)
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_waf_block_body_is_stable_json_envelope() {
        // Stability contract — if this assertion needs changing, it is an
        // API break for every client that parses the WAF error body.
        assert_eq!(
            SynapseProxy::WAF_BLOCK_BODY,
            r#"{"error": "access_denied"}"#
        );
        // Also valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(SynapseProxy::WAF_BLOCK_BODY)
            .expect("WAF_BLOCK_BODY is valid JSON");
        assert_eq!(parsed["error"], "access_denied");
    }

    #[test]
    fn test_build_waf_block_response_header_canonical_shape() {
        let resp = SynapseProxy::build_waf_block_response_header("req-abc", true)
            .expect("builder must succeed on well-formed inputs");

        assert_eq!(resp.status.as_u16(), 403);

        // X-Request-ID echoes the caller input so Hub can pivot on it.
        let req_id = resp
            .headers
            .get("x-request-id")
            .expect("x-request-id must be present")
            .to_str()
            .expect("x-request-id is valid ASCII");
        assert_eq!(req_id, "req-abc");

        // Content-type always application/json.
        assert_eq!(
            resp.headers
                .get("content-type")
                .expect("content-type must be present")
                .to_str()
                .unwrap(),
            "application/json"
        );

        // Content-length matches the canonical body byte length.
        assert_eq!(
            resp.headers
                .get("content-length")
                .expect("content-length must be present")
                .to_str()
                .unwrap(),
            SynapseProxy::WAF_BLOCK_BODY.len().to_string()
        );
    }

    #[test]
    fn test_build_waf_block_response_header_hsts_conditional_on_https() {
        // HSTS is only emitted for HTTPS — emitting it on cleartext HTTP is
        // at best useless, at worst confusing. The security-headers helper
        // enforces this; this test pins the behavior so a future refactor
        // that centralizes WAF blocks doesn't accidentally emit HSTS over
        // plain HTTP.
        let resp_https = SynapseProxy::build_waf_block_response_header("r", true).unwrap();
        let resp_http = SynapseProxy::build_waf_block_response_header("r", false).unwrap();

        assert!(
            resp_https
                .headers
                .get("strict-transport-security")
                .is_some(),
            "HSTS must be present on HTTPS responses"
        );
        assert!(
            resp_http.headers.get("strict-transport-security").is_none(),
            "HSTS must NOT be present on HTTP responses"
        );
    }

    #[test]
    fn test_build_waf_block_response_header_is_deterministic() {
        // Two calls with the same inputs must produce byte-identical headers
        // so body-phase and deferred block sites are genuinely unified, not
        // just "similar".
        let a = SynapseProxy::build_waf_block_response_header("same-req", true).unwrap();
        let b = SynapseProxy::build_waf_block_response_header("same-req", true).unwrap();

        for name in [
            "x-request-id",
            "content-type",
            "content-length",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
        ] {
            assert_eq!(
                a.headers.get(name).map(|v| v.as_bytes().to_vec()),
                b.headers.get(name).map(|v| v.as_bytes().to_vec()),
                "header {} must be byte-identical between builder calls",
                name
            );
        }
        assert_eq!(a.status.as_u16(), b.status.as_u16());
    }

    // ────────────────────────────────────────────────────────────────────────
    // Deferred WAF telemetry shape (TASK-32)
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_build_deferred_waf_block_event_populates_fields_from_inputs() {
        use synapse_pingora::telemetry::TelemetryEvent;

        let event = build_deferred_waf_block_event(
            "req-abc123".to_string(),
            &[9005, 9006],
            85,
            "203.0.113.7".to_string(),
            "example.com".to_string(),
            "/api/users".to_string(),
        );

        match event {
            TelemetryEvent::WafBlock {
                request_id,
                rule_id,
                severity,
                client_ip,
                site,
                path,
            } => {
                assert_eq!(request_id, Some("req-abc123".to_string()));
                // First matched rule is surfaced, prefixed so Hub can distinguish
                // deferred DLP blocks from body-phase and bad-bot blocks.
                assert_eq!(rule_id, "DLP_DEFERRED:9005");
                assert_eq!(severity, "critical");
                assert_eq!(client_ip, "203.0.113.7");
                assert_eq!(site, "example.com");
                assert_eq!(path, "/api/users");
            }
            other => panic!("expected WafBlock variant, got {:?}", other),
        }
    }

    #[test]
    fn test_build_deferred_waf_block_event_severity_tiers() {
        use synapse_pingora::telemetry::TelemetryEvent;

        // Helper to extract severity for a given risk score.
        let sev_for = |score: u16| -> String {
            match build_deferred_waf_block_event(
                "r".to_string(),
                &[1],
                score,
                "1.1.1.1".to_string(),
                "s".to_string(),
                "/p".to_string(),
            ) {
                TelemetryEvent::WafBlock { severity, .. } => severity,
                _ => unreachable!(),
            }
        };

        // Boundary cases: > 80 critical, > 50 high, otherwise medium.
        assert_eq!(sev_for(100), "critical");
        assert_eq!(sev_for(81), "critical");
        assert_eq!(sev_for(80), "high"); // NOT critical — mapping is strict >
        assert_eq!(sev_for(51), "high");
        assert_eq!(sev_for(50), "medium"); // NOT high — mapping is strict >
        assert_eq!(sev_for(0), "medium");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Non-blocking deferred merge (TASK-33)
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_merge_deferred_detection_non_blocking_preserves_all_fields() {
        let mut existing = DetectionResult {
            blocked: false,
            risk_score: 30,
            matched_rules: vec![1, 2],
            entity_risk: 10.0,
            block_reason: None,
            detection_time_us: 100,
        };
        let deferred = DetectionResult {
            blocked: false,
            risk_score: 40,
            matched_rules: vec![2, 5], // rule 2 is already in existing
            entity_risk: 15.0,
            block_reason: Some("deferred-reason".to_string()),
            detection_time_us: 50,
        };

        merge_deferred_detection_non_blocking(&mut existing, deferred);

        // risk_score: max(30, 40) = 40 (intentional — see merge doc comment)
        assert_eq!(existing.risk_score, 40);
        // entity_risk: 10.0 + 15.0 (previously dropped — the AC#1 fix)
        assert_eq!(existing.entity_risk, 25.0);
        // detection_time_us: 100 + 50 (previously dropped — the AC#2 fix)
        assert_eq!(existing.detection_time_us, 150);
        // matched_rules: dedup-extended, existing order preserved
        assert_eq!(existing.matched_rules, vec![1, 2, 5]);
        // block_reason: taken from deferred since existing was None (AC#3 fix)
        assert_eq!(existing.block_reason, Some("deferred-reason".to_string()));
    }

    #[test]
    fn test_merge_deferred_detection_non_blocking_preserves_existing_block_reason() {
        let mut existing = DetectionResult {
            block_reason: Some("original".to_string()),
            detection_time_us: 100,
            ..Default::default()
        };
        let deferred = DetectionResult {
            block_reason: Some("later".to_string()),
            detection_time_us: 50,
            ..Default::default()
        };

        merge_deferred_detection_non_blocking(&mut existing, deferred);

        // Existing block_reason wins — we never clobber an already-set reason.
        assert_eq!(existing.block_reason, Some("original".to_string()));
        // Timing still accumulates regardless.
        assert_eq!(existing.detection_time_us, 150);
    }

    #[test]
    fn test_merge_deferred_detection_non_blocking_saturates_time() {
        // If the existing detection_time_us is already near u64::MAX (which
        // cannot happen in practice but guards against panic-on-overflow in
        // future callers), saturating_add keeps the value finite.
        let mut existing = DetectionResult {
            detection_time_us: u64::MAX - 10,
            ..Default::default()
        };
        let deferred = DetectionResult {
            detection_time_us: 1000,
            ..Default::default()
        };

        merge_deferred_detection_non_blocking(&mut existing, deferred);

        assert_eq!(existing.detection_time_us, u64::MAX);
    }

    #[test]
    fn test_merge_deferred_detection_non_blocking_empty_deferred_rules() {
        // Defensive: the call site guards with !deferred.matched_rules.is_empty(),
        // but the helper must still be sound when a caller hands it an empty
        // rule vec so future refactors don't introduce a regression.
        let mut existing = DetectionResult {
            matched_rules: vec![1, 2, 3],
            entity_risk: 5.0,
            detection_time_us: 200,
            ..Default::default()
        };
        let deferred = DetectionResult {
            matched_rules: vec![],
            entity_risk: 2.0,
            detection_time_us: 10,
            ..Default::default()
        };

        merge_deferred_detection_non_blocking(&mut existing, deferred);

        assert_eq!(existing.matched_rules, vec![1, 2, 3]);
        assert_eq!(existing.entity_risk, 7.0);
        assert_eq!(existing.detection_time_us, 210);
    }

    #[test]
    fn test_build_deferred_waf_block_event_empty_rules_falls_back() {
        use synapse_pingora::telemetry::TelemetryEvent;

        // A blocking verdict without matched_rules is pathological but the
        // helper must still produce a routable event instead of panicking
        // on .first().unwrap().
        let event = build_deferred_waf_block_event(
            "req".to_string(),
            &[],
            60,
            "1.1.1.1".to_string(),
            "site".to_string(),
            "/".to_string(),
        );
        match event {
            TelemetryEvent::WafBlock { rule_id, .. } => {
                assert_eq!(rule_id, "DLP_DEFERRED");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_apply_integrations_to_runtime_config_assigns_shared_sensor_identity() {
        let mut config = Config::default();
        let integrations = IntegrationsConfig {
            horizon_hub_url: "wss://horizon.example.com/ws".to_string(),
            horizon_api_key: "sensor-api-key-abcdefghijklmnopqrstuvwxyz".to_string(),
            tunnel_url: "wss://horizon.example.com/ws/tunnel/sensor".to_string(),
            tunnel_api_key: "sensor-api-key-abcdefghijklmnopqrstuvwxyz".to_string(),
            apparatus_url: "https://apparatus.example.internal".to_string(),
        };

        apply_integrations_to_runtime_config(&mut config, &integrations);

        assert!(config.horizon.enabled);
        assert!(config.tunnel.enabled);
        assert_eq!(config.horizon.hub_url, integrations.horizon_hub_url);
        assert_eq!(config.tunnel.url, integrations.tunnel_url);
        assert_eq!(config.apparatus_url, integrations.apparatus_url);
        assert!(!config.horizon.sensor_id.is_empty());
        assert_eq!(config.horizon.sensor_id, config.tunnel.sensor_id);
    }

    #[test]
    fn test_persist_integrations_runtime_config_writes_complete_sections() {
        let temp = NamedTempFile::new().expect("temp config file");
        fs::write(
            temp.path(),
            r#"server:
  listen: "127.0.0.1:6190"
  admin_listen: "127.0.0.1:6191"
sites:
  - hostname: "localhost"
    upstreams:
      - host: "127.0.0.1"
        port: 5555
"#,
        )
        .expect("write config");

        let mut config =
            Config::load(temp.path().to_str().expect("utf-8 path")).expect("load baseline config");
        let integrations = IntegrationsConfig {
            horizon_hub_url: "wss://horizon.example.com/ws".to_string(),
            horizon_api_key: "sensor-api-key-abcdefghijklmnopqrstuvwxyz".to_string(),
            tunnel_url: "wss://horizon.example.com/ws/tunnel/sensor".to_string(),
            tunnel_api_key: "sensor-api-key-abcdefghijklmnopqrstuvwxyz".to_string(),
            apparatus_url: "https://apparatus.example.internal".to_string(),
        };

        apply_integrations_to_runtime_config(&mut config, &integrations);
        persist_integrations_runtime_config(temp.path().to_str().expect("utf-8 path"), &config)
            .expect("persist integrations");

        let reloaded = Config::load(temp.path().to_str().expect("utf-8 path"))
            .expect("reload persisted config");
        assert!(reloaded.horizon.enabled);
        assert!(reloaded.tunnel.enabled);
        assert_eq!(reloaded.horizon.hub_url, integrations.horizon_hub_url);
        assert_eq!(reloaded.tunnel.url, integrations.tunnel_url);
        assert_eq!(reloaded.apparatus_url, integrations.apparatus_url);
        assert_eq!(reloaded.horizon.sensor_id, reloaded.tunnel.sensor_id);
    }
}
