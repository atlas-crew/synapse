//! Core types for the WAF engine.

use std::collections::HashMap;

use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};

use crate::dlp::DlpMatch;
use crate::fingerprint::ClientFingerprint;
use crate::profiler::ValidationResult;

/// HTTP request to analyze.
#[derive(Debug, Clone, Default)]
pub struct Request<'a> {
    /// HTTP method (GET, POST, etc.)
    pub method: &'a str,
    /// Request path including query string
    pub path: &'a str,
    /// Query string (if separate from path)
    pub query: Option<&'a str>,
    /// Request headers
    pub headers: Vec<Header<'a>>,
    /// Request body
    pub body: Option<&'a [u8]>,
    /// Client IP address
    pub client_ip: &'a str,
    /// Whether this is static content
    pub is_static: bool,
    /// JA4/JA4H client fingerprint, if computed for this connection.
    pub fingerprint: Option<&'a ClientFingerprint>,
    /// DLP scanner matches for the request body. Empty slice when absent —
    /// populated only for the post-DLP deferred evaluation pass.
    pub dlp_matches: Option<&'a [DlpMatch]>,
    /// Schema validation result against the learned baseline, if available.
    pub schema_result: Option<&'a ValidationResult>,
}

/// HTTP header key-value pair.
#[derive(Debug, Clone)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

impl<'a> Header<'a> {
    pub fn new(name: &'a str, value: &'a str) -> Self {
        Self { name, value }
    }
}

/// Analysis result.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Recommended action
    pub action: Action,
    /// Combined risk score (0-1000 for extended range, 0-100 for default)
    pub risk_score: u16,
    /// IDs of matched rules
    pub matched_rules: Vec<u32>,
    /// Entity (IP) cumulative risk score (0.0-max_risk)
    pub entity_risk: f64,
    /// Whether the entity is blocked (risk or rule-based)
    pub entity_blocked: bool,
    /// Reason for blocking (if entity_blocked is true)
    pub block_reason: Option<String>,
    /// Per-rule risk contributions for explainability
    pub risk_contributions: Vec<RiskContribution>,

    // Anomaly detection fields
    /// Endpoint template (e.g., "/api/users/{id}")
    pub endpoint_template: Option<String>,
    /// Aggregate endpoint risk score (0-100)
    pub endpoint_risk: Option<f32>,
    /// Per-request anomaly score (-10 to +10)
    pub anomaly_score: Option<f64>,
    /// Adjusted blocking threshold used for this request
    pub adjusted_threshold: Option<f64>,
    /// Anomaly signals detected for observability
    pub anomaly_signals: Vec<AnomalySignal>,

    // Timeout fields
    /// Whether evaluation timed out (partial result)
    pub timed_out: bool,
    /// Number of rules evaluated before timeout (if timed_out)
    pub rules_evaluated: Option<u32>,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            action: Action::Allow,
            risk_score: 0,
            matched_rules: Vec::new(),
            entity_risk: 0.0,
            entity_blocked: false,
            block_reason: None,
            risk_contributions: Vec::new(),
            endpoint_template: None,
            endpoint_risk: None,
            anomaly_score: None,
            adjusted_threshold: None,
            anomaly_signals: Vec::new(),
            timed_out: false,
            rules_evaluated: None,
        }
    }
}

/// Action recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Action {
    Allow = 0,
    Block = 1,
}

/// Per-rule risk contribution for explainability.
#[derive(Debug, Clone)]
pub struct RiskContribution {
    /// Rule ID that contributed risk.
    pub rule_id: u32,
    /// Base risk from rule.effective_risk().
    pub base_risk: f64,
    /// Repeat offender multiplier (1.0 = first match).
    pub multiplier: f64,
    /// Final risk after multiplier: base_risk * multiplier.
    pub final_risk: f64,
}

impl RiskContribution {
    /// Create a new risk contribution.
    #[inline]
    pub fn new(rule_id: u32, base_risk: f64, multiplier: f64) -> Self {
        Self {
            rule_id,
            base_risk,
            multiplier,
            final_risk: base_risk * multiplier,
        }
    }
}

/// Anomaly signal detected during request analysis.
#[derive(Debug, Clone)]
pub struct AnomalySignal {
    /// Type of anomaly signal
    pub signal_type: AnomalySignalType,
    /// Severity score (0-100)
    pub severity: f32,
    /// Human-readable detail
    pub detail: String,
}

impl AnomalySignal {
    /// Convert to AnomalyType for entity tracking.
    pub fn to_anomaly_type(&self) -> AnomalyType {
        match self.signal_type {
            AnomalySignalType::PayloadSize => AnomalyType::OversizedRequest,
            AnomalySignalType::RequestRate => AnomalyType::VelocitySpike,
            AnomalySignalType::ErrorRate => AnomalyType::TimingAnomaly,
            AnomalySignalType::ParameterAnomaly => AnomalyType::Custom,
            AnomalySignalType::ContentTypeAnomaly => AnomalyType::Custom,
            AnomalySignalType::TimingAnomaly => AnomalyType::TimingAnomaly,
            AnomalySignalType::SchemaViolation => AnomalyType::Custom,
        }
    }
}

/// Types of anomaly signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalySignalType {
    /// Request payload size outside normal distribution
    PayloadSize,
    /// Request rate exceeds baseline
    RequestRate,
    /// Error rate spike detected
    ErrorRate,
    /// Unexpected parameters in request
    ParameterAnomaly,
    /// Unexpected content type
    ContentTypeAnomaly,
    /// Request timing pattern anomaly
    TimingAnomaly,
    /// Schema validation violation
    SchemaViolation,
}

/// Modes for behavioral anomaly blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BlockingMode {
    /// Only log anomalies, never block.
    #[default]
    Learning,
    /// Block requests that exceed the anomaly threshold.
    Enforcement,
}

/// Risk calculation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    /// Maximum risk score (default: 100.0, can be 1000.0 for extended range).
    pub max_risk: f64,
    /// Whether to apply repeat offender multipliers.
    pub enable_repeat_multipliers: bool,
    /// Custom anomaly risk overrides (type -> risk).
    pub anomaly_risk_overrides: HashMap<AnomalyType, f64>,
    /// Threshold for anomaly-based blocking (0 = disabled, default: 10.0)
    pub anomaly_blocking_threshold: f64,
    /// Behavioral blocking mode
    pub blocking_mode: BlockingMode,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            max_risk: 100.0,
            enable_repeat_multipliers: true,
            anomaly_risk_overrides: HashMap::new(),
            anomaly_blocking_threshold: 10.0,
            blocking_mode: BlockingMode::Learning, // Default to safe mode
        }
    }
}

impl RiskConfig {
    /// Create config with extended risk range (1000).
    pub fn with_extended_range() -> Self {
        Self {
            max_risk: 1000.0,
            ..Default::default()
        }
    }

    /// Get risk for anomaly type (override or default).
    #[inline]
    pub fn anomaly_risk(&self, anomaly_type: AnomalyType) -> f64 {
        self.anomaly_risk_overrides
            .get(&anomaly_type)
            .copied()
            .unwrap_or_else(|| anomaly_type.default_risk())
    }

    /// Set custom risk for an anomaly type.
    pub fn set_anomaly_risk(&mut self, anomaly_type: AnomalyType, risk: f64) {
        self.anomaly_risk_overrides.insert(anomaly_type, risk);
    }

    /// Reset anomaly type to default risk.
    pub fn reset_anomaly_risk(&mut self, anomaly_type: AnomalyType) {
        self.anomaly_risk_overrides.remove(&anomaly_type);
    }
}

/// Anomaly risk contribution for explainability.
///
/// Tracks anomaly-based risk applied to an entity.
#[derive(Debug, Clone)]
pub struct AnomalyContribution {
    /// Anomaly type that contributed risk.
    pub anomaly_type: AnomalyType,
    /// Risk score applied.
    pub risk: f64,
    /// Optional custom reason.
    pub reason: Option<String>,
    /// Timestamp when applied (ms since epoch).
    pub applied_at: u64,
}

impl AnomalyContribution {
    /// Create a new anomaly contribution.
    pub fn new(anomaly_type: AnomalyType, risk: f64, reason: Option<String>, now: u64) -> Self {
        Self {
            anomaly_type,
            risk,
            reason,
            applied_at: now,
        }
    }
}

/// Calculate repeat offender multiplier based on match count.
///
/// Multiplier tiers:
/// - 1 match: 1.0x (no boost)
/// - 2-5 matches: 1.25x
/// - 6-10 matches: 1.5x
/// - 11+ matches: 2.0x
///
/// # Arguments
/// * `match_count` - Number of times the rule has matched for this entity
///
/// # Returns
/// Multiplier to apply to base risk
#[inline]
pub fn repeat_multiplier(match_count: u32) -> f64 {
    match match_count {
        0 | 1 => 1.0,
        2..=5 => 1.25,
        6..=10 => 1.5,
        _ => 2.0,
    }
}

/// Anomaly types for behavioral risk scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AnomalyType {
    /// Device fingerprint changed for same IP.
    FingerprintChange = 0,
    /// Same session token used from multiple IPs.
    SessionSharing = 1,
    /// Auth token reused after expiration.
    TokenReuse = 2,
    /// Sudden spike in request velocity.
    VelocitySpike = 3,
    /// Suspicious rotation pattern (IPs, user agents).
    RotationPattern = 4,
    /// Request timing anomaly.
    TimingAnomaly = 5,
    /// Geographic impossibility (too fast travel).
    ImpossibleTravel = 6,
    /// Request body exceeds normal size.
    OversizedRequest = 7,
    /// Response body exceeds normal size.
    OversizedResponse = 8,
    /// Sudden bandwidth consumption spike.
    BandwidthSpike = 9,
    /// Large responses, small requests (data theft).
    ExfiltrationPattern = 10,
    /// Large requests, small responses (file upload).
    UploadPattern = 11,
    /// Custom anomaly with explicit risk.
    Custom = 255,
}

impl AnomalyType {
    /// Default risk score for each anomaly type.
    #[inline]
    pub const fn default_risk(self) -> f64 {
        match self {
            AnomalyType::SessionSharing => 50.0,
            AnomalyType::ExfiltrationPattern => 40.0,
            AnomalyType::TokenReuse => 40.0,
            AnomalyType::RotationPattern => 35.0,
            AnomalyType::UploadPattern => 35.0,
            AnomalyType::FingerprintChange => 30.0,
            AnomalyType::BandwidthSpike => 25.0,
            AnomalyType::ImpossibleTravel => 25.0,
            AnomalyType::OversizedRequest => 20.0,
            AnomalyType::OversizedResponse => 15.0,
            AnomalyType::VelocitySpike => 15.0,
            AnomalyType::TimingAnomaly => 10.0,
            AnomalyType::Custom => 0.0,
        }
    }

    /// Get the name of this anomaly type.
    pub const fn name(self) -> &'static str {
        match self {
            AnomalyType::FingerprintChange => "fingerprint_change",
            AnomalyType::SessionSharing => "session_sharing",
            AnomalyType::TokenReuse => "token_reuse",
            AnomalyType::VelocitySpike => "velocity_spike",
            AnomalyType::RotationPattern => "rotation_pattern",
            AnomalyType::TimingAnomaly => "timing_anomaly",
            AnomalyType::ImpossibleTravel => "impossible_travel",
            AnomalyType::OversizedRequest => "oversized_request",
            AnomalyType::OversizedResponse => "oversized_response",
            AnomalyType::BandwidthSpike => "bandwidth_spike",
            AnomalyType::ExfiltrationPattern => "exfiltration_pattern",
            AnomalyType::UploadPattern => "upload_pattern",
            AnomalyType::Custom => "custom",
        }
    }
}

/// Internal evaluation context (converted from Request).
#[derive(Debug)]
pub struct EvalContext<'a> {
    pub ip: &'a str,
    pub method: &'a str,
    pub url: &'a str,
    pub headers: HashMap<String, &'a str>,
    pub args: Vec<String>,
    pub arg_entries: Vec<ArgEntry>,
    pub body_text: Option<&'a str>,
    pub raw_body: Option<&'a [u8]>,
    pub is_static: bool,
    pub json_text: Option<String>,
    /// JA4/JA4H fingerprint for `ja4`/`ja4h` match kinds. `None` when not yet computed.
    pub fingerprint: Option<&'a ClientFingerprint>,
    /// DLP scanner matches for the `dlp_violation` match kind. Empty slice
    /// during body-phase evaluation; populated for the deferred post-DLP pass.
    pub dlp_matches: &'a [DlpMatch],
    /// Schema validation result for the `schema_violation` match kind.
    pub schema_result: Option<&'a ValidationResult>,
    /// Deadline for rule evaluation (prevents DoS via complex regexes)
    pub deadline: Option<std::time::Instant>,
}

#[derive(Debug, Clone)]
pub struct ArgEntry {
    pub key: String,
    pub value: String,
}

impl<'a> EvalContext<'a> {
    /// Convert a Request to an EvalContext.
    pub fn from_request(req: &'a Request<'a>) -> Self {
        // Build headers map (lowercase keys)
        let mut headers = HashMap::new();
        for h in &req.headers {
            headers.insert(h.name.to_ascii_lowercase(), h.value);
        }

        // Parse query string into args and arg_entries
        let (mut args, mut arg_entries) = parse_query_args(req.path, req.query);

        // Extract body text
        let body_text = req.body.and_then(|b| std::str::from_utf8(b).ok());

        // Parse body args if content-type is x-www-form-urlencoded
        if let Some(text) = body_text {
            if headers
                .get("content-type")
                .map(|ct| ct.contains("application/x-www-form-urlencoded"))
                .unwrap_or(false)
            {
                // Parse body as query string and append to existing args
                let (body_args, body_entries) = parse_query_args("", Some(text));
                args.extend(body_args);
                arg_entries.extend(body_entries);
            }
        }

        // Try to parse JSON
        let json_text = body_text.and_then(|text| {
            if headers
                .get("content-type")
                .map(|ct| ct.contains("application/json"))
                .unwrap_or(false)
            {
                // Attempt to parse JSON and flatten into args
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                    flatten_json(&value, &mut args, &mut arg_entries);
                }

                // Just store the raw JSON for pattern matching
                Some(text.to_string())
            } else {
                None
            }
        });

        // Handle Multipart/Form-Data
        if let Some(raw_body) = req.body {
            if let Some(content_type) = headers.get("content-type") {
                if content_type.contains("multipart/form-data") {
                    if let Some(boundary) = extract_multipart_boundary(content_type) {
                        let (mp_args, mp_entries) = parse_multipart(raw_body, &boundary);
                        args.extend(mp_args);
                        arg_entries.extend(mp_entries);
                    }
                }
            }
        }

        Self {
            ip: req.client_ip,
            method: req.method,
            url: req.path,
            headers,
            args,
            arg_entries,
            body_text,
            raw_body: req.body,
            is_static: req.is_static,
            json_text,
            fingerprint: req.fingerprint,
            dlp_matches: req.dlp_matches.unwrap_or(&[]),
            schema_result: req.schema_result,
            deadline: None,
        }
    }

    /// Creates an EvalContext with a deadline for timeout protection.
    pub fn from_request_with_deadline(req: &'a Request<'a>, deadline: std::time::Instant) -> Self {
        let mut ctx = Self::from_request(req);
        ctx.deadline = Some(deadline);
        ctx
    }

    /// Checks if the evaluation deadline has been exceeded.
    #[inline]
    pub fn is_deadline_exceeded(&self) -> bool {
        self.deadline
            .map(|d| std::time::Instant::now() >= d)
            .unwrap_or(false)
    }
}

fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    content_type
        .split(';')
        .map(|p| p.trim())
        .find_map(|p| {
            let (key, value) = p.split_once('=')?;
            if key.trim().eq_ignore_ascii_case("boundary") {
                Some(value.trim().trim_matches('"').to_string())
            } else {
                None
            }
        })
        .filter(|b| !b.is_empty())
}

fn parse_multipart(raw_body: &[u8], boundary: &str) -> (Vec<String>, Vec<ArgEntry>) {
    let mut args = Vec::new();
    let mut entries = Vec::new();

    // Naive implementation: search for boundary and Content-Disposition
    let body_str = String::from_utf8_lossy(raw_body);
    let marker = format!("--{}", boundary);

    for part in body_str.split(&marker) {
        // Each part has headers \r\n\r\n body \r\n
        let part = part.trim_matches('\r').trim_matches('\n');
        if part.is_empty() || part == "--" {
            continue;
        }

        if let Some((headers, body)) = part.split_once("\r\n\r\n") {
            // Extract name from Content-Disposition
            // Content-Disposition: form-data; name="fieldName"
            let name = headers
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-disposition"))
                .and_then(|l| {
                    l.split(';')
                        .find(|p| p.trim().starts_with("name="))
                        .map(|p| {
                            p.trim()
                                .trim_start_matches("name=")
                                .trim_matches('"')
                                .to_string()
                        })
                });

            if let Some(key) = name {
                let value = body.trim_end_matches("\r\n").to_string();
                args.push(value.clone());
                entries.push(ArgEntry { key, value });
            }
        }
    }

    (args, entries)
}

/// Maximum JSON nesting depth to prevent stack overflow attacks
const MAX_JSON_DEPTH: usize = 32;
/// Maximum total elements to extract from JSON to prevent memory exhaustion
const MAX_JSON_ELEMENTS: usize = 1000;

fn flatten_json(value: &serde_json::Value, args: &mut Vec<String>, entries: &mut Vec<ArgEntry>) {
    let mut element_count = 0usize;
    flatten_json_recursive(value, args, entries, 0, &mut element_count);
}

fn flatten_json_recursive(
    value: &serde_json::Value,
    args: &mut Vec<String>,
    entries: &mut Vec<ArgEntry>,
    depth: usize,
    element_count: &mut usize,
) {
    // Guard: prevent stack overflow from deeply nested JSON
    if depth > MAX_JSON_DEPTH {
        return;
    }
    // Guard: prevent memory exhaustion from large JSON
    if *element_count >= MAX_JSON_ELEMENTS {
        return;
    }

    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                *element_count += 1;
                if *element_count >= MAX_JSON_ELEMENTS {
                    return;
                }
                match v {
                    serde_json::Value::String(s) => {
                        args.push(s.clone());
                        entries.push(ArgEntry {
                            key: k.clone(),
                            value: s.clone(),
                        });
                    }
                    serde_json::Value::Number(n) => {
                        let s = n.to_string();
                        args.push(s.clone());
                        entries.push(ArgEntry {
                            key: k.clone(),
                            value: s,
                        });
                    }
                    serde_json::Value::Bool(b) => {
                        let s = b.to_string();
                        args.push(s.clone());
                        entries.push(ArgEntry {
                            key: k.clone(),
                            value: s,
                        });
                    }
                    _ => flatten_json_recursive(v, args, entries, depth + 1, element_count),
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                *element_count += 1;
                if *element_count >= MAX_JSON_ELEMENTS {
                    return;
                }
                flatten_json_recursive(v, args, entries, depth + 1, element_count);
            }
        }
        _ => {}
    }
}

fn parse_query_args(path: &str, query: Option<&str>) -> (Vec<String>, Vec<ArgEntry>) {
    let mut args = Vec::new();
    let mut arg_entries = Vec::new();

    // Get query string from path or explicit query param
    let query_str = if let Some(q) = query {
        q
    } else if let Some(idx) = path.find('?') {
        &path[idx + 1..]
    } else {
        return (args, arg_entries);
    };

    for pair in query_str.split('&') {
        if pair.is_empty() {
            continue;
        }

        // Add raw value to args
        args.push(pair.to_string());

        // Parse key=value and decode (handling + as space for form encoding)
        if let Some((key, value)) = pair.split_once('=') {
            let key_fixed = key.replace('+', " ");
            let value_fixed = value.replace('+', " ");
            let decoded_key = percent_decode_str(&key_fixed)
                .decode_utf8_lossy()
                .to_string();
            let decoded_value = percent_decode_str(&value_fixed)
                .decode_utf8_lossy()
                .to_string();
            arg_entries.push(ArgEntry {
                key: decoded_key,
                value: decoded_value,
            });
        } else {
            let pair_fixed = pair.replace('+', " ");
            let decoded_key = percent_decode_str(&pair_fixed)
                .decode_utf8_lossy()
                .to_string();
            arg_entries.push(ArgEntry {
                key: decoded_key,
                value: String::new(),
            });
        }
    }
    (args, arg_entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_args() {
        let (args, entries) = parse_query_args("/api/users?id=1&name=test", None);
        assert_eq!(args.len(), 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "id");
        assert_eq!(entries[0].value, "1");
        assert_eq!(entries[1].key, "name");
        assert_eq!(entries[1].value, "test");
    }

    #[test]
    fn test_eval_context_from_request() {
        let req = Request {
            method: "POST",
            path: "/api/login?username=admin",
            headers: vec![Header::new("Content-Type", "application/json")],
            body: Some(b"{\"password\": \"test\"}"),
            client_ip: "192.168.1.1",
            ..Default::default()
        };

        let ctx = EvalContext::from_request(&req);
        assert_eq!(ctx.method, "POST");
        assert_eq!(ctx.ip, "192.168.1.1");
        // 2 entries: username from query + password from JSON body (flattened)
        assert_eq!(ctx.arg_entries.len(), 2);
        assert!(ctx.json_text.is_some());
    }

    #[test]
    fn test_anomaly_type_default_risk() {
        assert_eq!(AnomalyType::SessionSharing.default_risk(), 50.0);
        assert_eq!(AnomalyType::ImpossibleTravel.default_risk(), 25.0);
        assert_eq!(AnomalyType::Custom.default_risk(), 0.0);
    }
}
