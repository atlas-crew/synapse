//! Synapse-Pingora PoC
//!
//! A proof-of-concept integrating the Synapse detection engine with Cloudflare's
//! Pingora proxy framework. Pure Rust, no Node.js.
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
//!                     │  libsynapse     │
//!                     │  • 237+ Rules   │
//!                     │  • Actor Track  │
//!                     │  • Risk Scoring │
//!                     │  • Cred Stuffing│
//!                     └─────────────────┘
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use synapse::{Action as SynapseAction, Header as SynapseHeader, Request as SynapseRequest, Synapse, Verdict as SynapseVerdict};
use log::{debug, info, warn, error};
use once_cell::sync::Lazy;
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_limits::rate::Rate;
use pingora_proxy::{ProxyHttp, Session};
use serde::Deserialize;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

// Admin API imports
use synapse_pingora::admin_server::start_admin_server;
use synapse_pingora::api::ApiHandler;
use synapse_pingora::health::HealthChecker;
use synapse_pingora::metrics::MetricsRegistry;

// Phase 3: Fingerprinting (Feature Migration from risk-server)
use synapse_pingora::fingerprint::{
    ClientFingerprint, HttpHeaders, extract_client_fingerprint,
};

// Phase 3: Entity Tracking (Feature Migration from risk-server)
use synapse_pingora::entity::{
    EntityManager, EntityConfig, BlockDecision,
};

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            upstreams: vec![UpstreamConfig::default()],
            rate_limit: RateLimitConfig::default(),
            logging: LoggingConfig::default(),
            detection: DetectionConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_admin_listen")]
    pub admin_listen: String,
    #[serde(default)]
    pub workers: usize,
}

fn default_listen() -> String {
    "0.0.0.0:6190".to_string()
}

fn default_admin_listen() -> String {
    "0.0.0.0:6191".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            admin_listen: default_admin_listen(),
            workers: 0,
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
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_rps() -> usize {
    10000
}

fn default_enabled() -> bool {
    true
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rps: default_rps(),
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
}

fn default_action() -> String {
    "block".to_string()
}

fn default_block_status() -> u16 {
    403
}

fn default_rules_path() -> String {
    // Default rules path relative to the binary
    "../risk-server/libsynapse/rules.json".to_string()
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
        }
    }
}

impl Config {
    /// Load configuration from YAML file
    pub fn load(path: &str) -> Result<Self, String> {
        if !Path::new(path).exists() {
            return Err(format!("Config file not found: {}", path));
        }

        let contents = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        serde_yaml::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))
    }

    /// Try to load config from default locations, fall back to defaults
    pub fn load_or_default() -> Self {
        let paths = ["config.yaml", "config.yml", "/etc/synapse-pingora/config.yaml"];

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

// ============================================================================
// Detection Engine (Real libsynapse)
// ============================================================================

/// Result of detection analysis
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// Whether the request should be blocked
    pub blocked: bool,
    /// Risk score from the engine (0-100 or higher for extended range)
    pub risk_score: u16,
    /// IDs of matched rules
    pub matched_rules: Vec<u32>,
    /// Entity (IP) cumulative risk
    pub entity_risk: f64,
    /// Block reason (if blocked)
    pub block_reason: Option<String>,
    /// Detection time in microseconds
    pub detection_time_us: u64,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            blocked: false,
            risk_score: 0,
            matched_rules: Vec::new(),
            entity_risk: 0.0,
            block_reason: None,
            detection_time_us: 0,
        }
    }
}

impl From<SynapseVerdict> for DetectionResult {
    fn from(verdict: SynapseVerdict) -> Self {
        Self {
            blocked: verdict.action == SynapseAction::Block,
            risk_score: verdict.risk_score,
            matched_rules: verdict.matched_rules,
            entity_risk: verdict.entity_risk,
            block_reason: verdict.block_reason,
            detection_time_us: 0, // Set by caller
        }
    }
}

/// Global rules data, loaded once at startup and shared across threads
static RULES_DATA: Lazy<Option<Vec<u8>>> = Lazy::new(|| {
    // Try multiple paths for rules.json
    let rules_paths = [
        "../risk-server/libsynapse/rules.json",
        "rules.json",
        "/etc/synapse-pingora/rules.json",
    ];

    for path in &rules_paths {
        if Path::new(path).exists() {
            match fs::read(path) {
                Ok(rules_json) => {
                    info!("Found rules at {} ({} bytes)", path, rules_json.len());
                    return Some(rules_json);
                }
                Err(e) => {
                    warn!("Failed to read rules from {}: {}", path, e);
                }
            }
        }
    }

    warn!("No rules.json found, will use minimal embedded rules");
    None
});

// Thread-local Synapse engine instance (Engine uses RefCell, so !Sync)
// Each Pingora worker thread gets its own instance.
thread_local! {
    static SYNAPSE: std::cell::RefCell<Synapse> = std::cell::RefCell::new(create_synapse_engine());
}

/// Create a new Synapse engine with rules
fn create_synapse_engine() -> Synapse {
    let mut synapse = Synapse::new();

    // Load from pre-loaded rules data or minimal rules
    if let Some(ref rules_json) = *RULES_DATA {
        match synapse.load_rules(rules_json) {
            Ok(count) => {
                debug!("Thread loaded {} rules", count);
            }
            Err(e) => {
                warn!("Failed to parse rules: {}", e);
            }
        }
    } else {
        // Load minimal embedded rules
        let minimal_rules = include_str!("minimal_rules.json");
        if let Err(e) = synapse.load_rules(minimal_rules.as_bytes()) {
            warn!("Failed to load minimal rules: {}", e);
        }
    }

    synapse
}

/// Get the global rule count (from first instance)
static RULE_COUNT: Lazy<usize> = Lazy::new(|| {
    SYNAPSE.with(|s| s.borrow().rule_count())
});

/// The Synapse detection engine wrapper
pub struct DetectionEngine;

impl DetectionEngine {
    /// Analyze a request using the real libsynapse engine.
    /// Returns a DetectionResult with timing information.
    #[inline]
    pub fn analyze(method: &str, uri: &str, headers: &[(String, String)], client_ip: &str) -> DetectionResult {
        let start = Instant::now();

        // Build libsynapse Request
        let synapse_headers: Vec<SynapseHeader> = headers
            .iter()
            .map(|(name, value)| SynapseHeader::new(name, value))
            .collect();

        let request = SynapseRequest {
            method,
            path: uri,
            query: None, // Extracted from path by libsynapse
            headers: synapse_headers,
            body: None,
            client_ip,
            is_static: false,
        };

        // Run the real detection engine (thread-local)
        let verdict = SYNAPSE.with(|s| s.borrow().analyze(&request));

        let elapsed = start.elapsed();

        DetectionResult {
            detection_time_us: elapsed.as_micros() as u64,
            ..verdict.into()
        }
    }

    /// Get the number of loaded rules (for diagnostics)
    pub fn rule_count() -> usize {
        *RULE_COUNT
    }
}

// ============================================================================
// Pingora Proxy Implementation
// ============================================================================

/// Per-request context flowing through all Pingora hooks
pub struct RequestContext {
    /// Start time for the request (for logging)
    request_start: Instant,
    /// Detection result from request_filter
    detection: Option<DetectionResult>,
    /// Backend index for round-robin
    backend_idx: usize,
    /// Client IP (extracted from headers or connection)
    client_ip: Option<String>,
    /// Total body size seen (for body inspection)
    body_bytes_seen: usize,
    /// Phase 3: Client fingerprint (JA4 + JA4H)
    fingerprint: Option<ClientFingerprint>,
    /// Phase 3: Entity risk from Pingora entity tracking
    entity_risk: f64,
    /// Phase 3: Entity block decision from Pingora
    entity_blocked: Option<BlockDecision>,
}

/// Rate limiter for early_request_filter
#[allow(dead_code)]
static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(std::time::Duration::from_secs(1)));
static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// The Synapse WAF Proxy
pub struct SynapseProxy {
    /// Backend servers for round-robin selection
    backends: Vec<(String, u16)>,
    /// Round-robin counter
    backend_counter: AtomicUsize,
    /// Requests per second limit for rate limiting
    rps_limit: usize,
    /// Phase 3: Thread-safe entity manager for per-IP tracking
    entity_manager: Arc<EntityManager>,
}

impl SynapseProxy {
    pub fn new(backends: Vec<(String, u16)>, rps_limit: usize) -> Self {
        Self {
            backends,
            backend_counter: AtomicUsize::new(0),
            rps_limit,
            entity_manager: Arc::new(EntityManager::new(EntityConfig::default())),
        }
    }

    pub fn with_entity_config(backends: Vec<(String, u16)>, rps_limit: usize, entity_config: EntityConfig) -> Self {
        Self {
            backends,
            backend_counter: AtomicUsize::new(0),
            rps_limit,
            entity_manager: Arc::new(EntityManager::new(entity_config)),
        }
    }

    /// Select next backend using round-robin
    fn next_backend(&self) -> (String, u16, usize) {
        let idx = self.backend_counter.fetch_add(1, Ordering::Relaxed) % self.backends.len();
        let backend = &self.backends[idx];
        (backend.0.clone(), backend.1, idx)
    }

    /// Extract client IP from headers or connection
    fn get_client_ip(session: &Session) -> Option<String> {
        // Check X-Forwarded-For first
        if let Some(xff) = session.req_header().headers.get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                // Take the first IP from comma-separated list
                return Some(s.split(',').next().unwrap_or(s).trim().to_string());
            }
        }

        // Check X-Real-IP
        if let Some(xri) = session.req_header().headers.get("x-real-ip") {
            if let Ok(s) = xri.to_str() {
                return Some(s.to_string());
            }
        }

        // Fall back to connection peer address
        session.client_addr().map(|addr| addr.to_string())
    }

    /// Extract headers as Vec for detection engine
    fn extract_headers(session: &Session) -> Vec<(String, String)> {
        session
            .req_header()
            .headers
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|v| (name.to_string(), v.to_string()))
            })
            .collect()
    }
}

#[async_trait]
impl ProxyHttp for SynapseProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            request_start: Instant::now(),
            detection: None,
            backend_idx: 0,
            client_ip: None,
            body_bytes_seen: 0,
            fingerprint: None,
            entity_risk: 0.0,
            entity_blocked: None,
        }
    }

    /// Early request filter - runs before TLS, used for rate limiting
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Extract client IP early
        ctx.client_ip = Self::get_client_ip(session);

        // Simple rate limiting check
        let count = REQUEST_COUNT.fetch_add(1, Ordering::Relaxed);

        // Reset counter periodically (simplified - real implementation would use proper windowing)
        if count > self.rps_limit * 2 {
            REQUEST_COUNT.store(0, Ordering::Relaxed);
        }

        // Check if over limit
        if count > self.rps_limit {
            warn!(
                "Rate limit exceeded for {:?}, count: {}",
                ctx.client_ip, count
            );
            // In a real implementation, we'd send a 429 response here
            // For this PoC, we just log and continue
        }

        Ok(())
    }

    /// Main request filter - runs detection engine
    /// Returns Ok(true) if we handled the request (blocked)
    /// Returns Ok(false) to continue to upstream
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        let req_header = session.req_header();

        // Extract request info for detection
        let method = req_header.method.as_str();
        let uri = req_header.uri.to_string();
        let headers = Self::extract_headers(session);
        let client_ip = ctx.client_ip.as_deref().unwrap_or("0.0.0.0");

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

        let http_headers = HttpHeaders {
            headers: &headers,
            method,
            http_version: http_version_str,
        };

        let fingerprint = extract_client_fingerprint(ja4_header, &http_headers);

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

        // Run detection using the real libsynapse engine
        let result = DetectionEngine::analyze(method, &uri, &headers, client_ip);

        // Phase 3: Entity tracking - touch entity and apply risk from matched rules
        // This tracks per-IP state for risk accumulation and blocking decisions
        if self.entity_manager.is_enabled() {
            // Touch entity with fingerprint for correlation
            let ja4_str = fingerprint.ja4.as_ref().map(|j| j.raw.as_str());
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
                    client_ip,
                    rule_id,
                    base_risk,
                    true, // enable repeat offender multiplier
                ) {
                    ctx.entity_risk = risk_result.new_risk;
                    debug!(
                        "Entity {} rule {} risk: base={:.1} x{:.2} = {:.1}, total={:.1}",
                        client_ip, rule_id, risk_result.base_risk, risk_result.multiplier,
                        risk_result.final_risk, risk_result.new_risk
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
        }

        info!(
            "Detection complete: blocked={}, risk={}, entity_risk={:.1}, rules={:?}, time={}μs, uri={}",
            result.blocked,
            result.risk_score,
            ctx.entity_risk,
            result.matched_rules,
            result.detection_time_us,
            uri
        );

        if result.blocked {
            // Clone block_reason before moving result
            let block_reason = result.block_reason.clone().unwrap_or_else(|| "rule_match".to_string());

            // Log the block
            warn!(
                "BLOCKED: {} from {} - risk={}, rules={:?}, reason={}",
                uri,
                client_ip,
                result.risk_score,
                result.matched_rules,
                block_reason
            );

            // Store result for logging hook
            ctx.detection = Some(result);

            // Send 403 response
            let resp = ResponseHeader::build(403, None)?;
            session.write_response_header(Box::new(resp), true).await?;
            session
                .write_response_body(
                    Some(Bytes::from(format!(
                        "{{\"error\": \"blocked\", \"reason\": \"{}\"}}",
                        block_reason
                    ))),
                    true,
                )
                .await?;

            // Return true = we handled the request
            return Ok(true);
        }

        ctx.detection = Some(result);

        // Return false = continue to upstream
        Ok(false)
    }

    /// Request body filter - inspect request body chunks
    ///
    /// This hook is called for each chunk of the request body.
    /// Currently just logs body size for visibility.
    ///
    /// TODO: Future DLP scanning integration:
    /// - Scan for sensitive data patterns (SSN, credit cards, API keys)
    /// - Check for data exfiltration attempts
    /// - Apply content-type specific validation
    /// - Integrate with external DLP service
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if let Some(ref body_chunk) = body {
            let chunk_size = body_chunk.len();
            ctx.body_bytes_seen += chunk_size;

            debug!(
                "Body chunk: {} bytes (total: {} bytes, eos: {})",
                chunk_size, ctx.body_bytes_seen, end_of_stream
            );

            // TODO: DLP scanning would go here
            // Example future implementation:
            // ```
            // if dlp_enabled {
            //     let dlp_result = DlpScanner::scan(body_chunk);
            //     if dlp_result.contains_sensitive_data {
            //         return Err(Error::new(ErrorType::Custom("DLP violation")));
            //     }
            // }
            // ```
        }

        if end_of_stream && ctx.body_bytes_seen > 0 {
            info!(
                "Request body complete: {} bytes from {:?}",
                ctx.body_bytes_seen, ctx.client_ip
            );
        }

        Ok(())
    }

    /// Select upstream backend (round-robin)
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let (host, port, idx) = self.next_backend();
        ctx.backend_idx = idx;

        info!("Routing to backend {}:{} (index {})", host, port, idx);

        let peer = HttpPeer::new((&host as &str, port), false, String::new());
        Ok(Box::new(peer))
    }

    /// Modify request headers before sending to upstream
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Add Synapse headers for visibility
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
            upstream_request.insert_header("X-JA4H-Fingerprint-Pingora", &fp.ja4h.raw)?;

            // JA4 fingerprint (only if X-JA4-Fingerprint header was provided)
            if let Some(ref ja4) = fp.ja4 {
                upstream_request.insert_header("X-JA4-Fingerprint-Pingora", &ja4.raw)?;
            }

            // Combined fingerprint hash (for entity correlation)
            upstream_request.insert_header("X-Fingerprint-Combined-Pingora", &fp.combined_hash)?;
        }

        // Phase 3: Add entity tracking headers for dual-running validation
        // These headers allow risk-server to compare its entity tracking with Pingora's
        upstream_request.insert_header(
            "X-Entity-Risk-Pingora",
            format!("{:.1}", ctx.entity_risk),
        )?;

        if let Some(ref block_decision) = ctx.entity_blocked {
            upstream_request.insert_header(
                "X-Entity-Blocked-Pingora",
                if block_decision.blocked { "true" } else { "false" },
            )?;
            if let Some(ref reason) = block_decision.reason {
                upstream_request.insert_header("X-Entity-Block-Reason-Pingora", reason)?;
            }
        }

        Ok(())
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

        info!(
            "ACCESS: {} {} status={} total={}μs detection={}μs blocked={} entity_risk={:.1} entity_blocked={} backend={} fp={}",
            session.req_header().method,
            session.req_header().uri,
            status,
            total_time.as_micros(),
            detection_time,
            blocked,
            ctx.entity_risk,
            entity_blocked,
            ctx.backend_idx,
            fp_hash
        );
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

fn main() {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Starting Synapse-Pingora PoC");

    // Load configuration
    let config = Config::load_or_default();

    info!("Listen address: {}", config.server.listen);
    info!(
        "Upstreams: {:?}",
        config
            .upstreams
            .iter()
            .map(|u| format!("{}:{}", u.host, u.port))
            .collect::<Vec<_>>()
    );
    info!("Rate limit: {} rps (enabled: {})", config.rate_limit.rps, config.rate_limit.enabled);

    // Force engine initialization and rule loading at startup
    let rule_count = DetectionEngine::rule_count();
    info!("Synapse engine initialized with {} rules", rule_count);

    // Configure backends from config
    let backends: Vec<(String, u16)> = config
        .upstreams
        .iter()
        .map(|u| (u.host.clone(), u.port))
        .collect();

    // Create shared health checker and metrics registry for admin API
    let health_checker = Arc::new(HealthChecker::default());
    let metrics_registry = Arc::new(MetricsRegistry::new());

    // Build the API handler
    let api_handler = Arc::new(
        ApiHandler::builder()
            .health(Arc::clone(&health_checker))
            .metrics(Arc::clone(&metrics_registry))
            .build()
    );

    // Start admin HTTP server in a separate thread with its own tokio runtime
    let admin_addr: SocketAddr = config.server.admin_listen.parse()
        .expect("Invalid admin_listen address");
    let admin_handler = Arc::clone(&api_handler);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create admin runtime");

        rt.block_on(async {
            if let Err(e) = start_admin_server(admin_addr, admin_handler).await {
                error!("Admin server error: {}", e);
            }
        });
    });

    info!("Admin API server starting on {}", config.server.admin_listen);

    // Create Pingora server
    let mut server = Server::new(None).expect("Failed to create server");
    server.bootstrap();

    // Create and configure the proxy service
    let proxy = SynapseProxy::new(backends, config.rate_limit.rps);

    let mut proxy_service = pingora_proxy::http_proxy_service(&server.configuration, proxy);
    proxy_service.add_tcp(&config.server.listen);

    server.add_service(proxy_service);

    info!("Synapse-Pingora ready");
    info!("  Proxy:  {}", config.server.listen);
    info!("  Admin:  {}", config.server.admin_listen);
    info!("Graceful reload: pkill -SIGQUIT synapse-pingora && ./synapse-pingora -u");
    server.run_forever();
}

// ============================================================================
// Tests - Using REAL libsynapse engine with production rules
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IP: &str = "192.168.1.100";

    // ────────────────────────────────────────────────────────────────────────
    // Engine Health Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_engine_rule_count() {
        // Verify we have rules loaded
        let count = DetectionEngine::rule_count();
        assert!(count > 0, "Should have at least 1 rule loaded, got {}", count);
        println!("Engine loaded {} rules", count);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Clean Request Tests (Should NOT block)
    // These are fundamental - false positives are unacceptable in production
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_clean_simple_get() {
        let result = DetectionEngine::analyze("GET", "/api/users/123", &[], TEST_IP);
        assert!(!result.blocked, "Clean GET should not be blocked");
        assert!(result.matched_rules.is_empty(), "No rules should match");
    }

    #[test]
    fn test_clean_with_query() {
        let result = DetectionEngine::analyze(
            "GET",
            "/api/search?q=hello+world&page=1",
            &[],
            TEST_IP,
        );
        assert!(!result.blocked, "Clean query should not be blocked");
    }

    #[test]
    fn test_clean_post_json() {
        let result = DetectionEngine::analyze(
            "POST",
            "/api/users",
            &[("content-type".to_string(), "application/json".to_string())],
            TEST_IP,
        );
        assert!(!result.blocked, "Clean POST should not be blocked");
    }

    #[test]
    fn test_clean_with_user_agent() {
        let result = DetectionEngine::analyze(
            "GET",
            "/api/data",
            &[("user-agent".to_string(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64)".to_string())],
            TEST_IP,
        );
        assert!(!result.blocked, "Normal user-agent should not be blocked");
    }

    // ────────────────────────────────────────────────────────────────────────
    // Attack Detection Tests - Using patterns the production engine catches
    // The real engine has 237 rules tuned for production use
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_sqli_union_select() {
        // UNION SELECT is a classic SQLi pattern that production engines catch
        let result = DetectionEngine::analyze(
            "GET",
            "/api/users?id=1 UNION SELECT * FROM users",
            &[],
            TEST_IP,
        );
        assert!(result.blocked, "UNION SELECT should be blocked");
        assert!(result.risk_score > 0, "Should have risk score");
        println!("UNION SELECT: blocked={}, risk={}, rules={:?}",
            result.blocked, result.risk_score, result.matched_rules);
    }

    #[test]
    fn test_path_traversal_dotdot() {
        // Path traversal is commonly caught by production WAFs
        let result = DetectionEngine::analyze(
            "GET",
            "/files/../../../etc/passwd",
            &[],
            TEST_IP,
        );
        assert!(result.blocked, "Path traversal should be blocked");
        println!("Path traversal: blocked={}, risk={}, rules={:?}",
            result.blocked, result.risk_score, result.matched_rules);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Performance Tests - HONEST BENCHMARKS with real engine
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_detection_timing() {
        // Warm up the engine
        let _ = DetectionEngine::analyze("GET", "/warmup", &[], TEST_IP);

        // Run performance tests - measure timing regardless of detection result
        let test_cases = vec![
            ("GET", "/api/users?id=1 UNION SELECT * FROM users"),  // Should block
            ("GET", "/files/../../../etc/passwd"),                  // Should block
            ("GET", "/api/users/123"),                              // Should pass
            ("GET", "/api/search?q=hello+world&page=1&limit=10"),   // Should pass
        ];

        for (method, uri) in test_cases {
            let result = DetectionEngine::analyze(method, uri, &[], TEST_IP);

            println!("URI: {} -> blocked={}, time={}μs", uri, result.blocked, result.detection_time_us);

            // Performance assertion: real engine with 237 rules
            // Debug mode: up to 10ms due to lack of optimizations
            // Release mode: expect ~30-50μs (documented performance)
            #[cfg(debug_assertions)]
            let max_time = 10000;
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
                &[("user-agent".to_string(), "Mozilla/5.0".to_string())],
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
        println!("║  Rules loaded:        {:>6}                         ║", rule_count);
        println!("║  Iterations:          {:>6}                         ║", iterations);
        println!("║  Blocked requests:    {:>6} ({:.1}%)               ║",
            blocked_count, (blocked_count as f64 / iterations as f64) * 100.0);
        println!("║  Avg detection time:  {:>6} μs                      ║", avg_time);
        println!("║  Total time:          {:>6} ms                      ║", total_time / 1000);
        println!("╚══════════════════════════════════════════════════════╝");

        // Real engine with 237 rules: documented ~30μs
        // In debug mode, we're lenient
        // In release mode, expect under 100μs average
        #[cfg(not(debug_assertions))]
        assert!(
            avg_time < 100,
            "Average detection time {}μs exceeds 100μs target for real engine with {} rules",
            avg_time, rule_count
        );
    }

    #[test]
    fn test_clean_traffic_performance() {
        // Benchmark clean traffic (most of production workload)
        let iterations = 1000;
        let mut total_time = 0u64;

        for i in 0..iterations {
            let result = DetectionEngine::analyze(
                "GET",
                &format!("/api/users/{}", i),
                &[("user-agent".to_string(), "Mozilla/5.0".to_string())],
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
}
