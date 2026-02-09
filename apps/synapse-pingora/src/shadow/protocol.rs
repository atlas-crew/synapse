//! Shadow mirroring protocol and payload definitions.
//!
//! Defines the JSON payload format sent to honeypot endpoints.
//!
//! # Security
//!
//! Headers are sanitized before being sent to honeypots to prevent credential leakage.
//! Sensitive headers (Authorization, Cookie, etc.) are stripped automatically.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Headers that contain sensitive credentials and must be stripped before mirroring.
/// These headers could expose user credentials if forwarded to honeypot systems.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "x-csrf-token",
    "x-xsrf-token",
];

/// Sanitizes headers by removing sensitive credential headers.
///
/// This prevents credential leakage when forwarding requests to honeypot systems.
/// Headers are matched case-insensitively.
pub fn sanitize_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(key, _)| {
            let lower_key = key.to_lowercase();
            !SENSITIVE_HEADERS.contains(&lower_key.as_str())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Checks if a header name is considered sensitive.
pub fn is_sensitive_header(name: &str) -> bool {
    SENSITIVE_HEADERS.contains(&name.to_lowercase().as_str())
}

/// JSON payload sent to honeypot endpoints.
///
/// Contains all relevant request context for threat analysis:
/// - Client identification (IP, fingerprints)
/// - Risk assessment (score, matched rules, campaign correlation)
/// - Full request details (method, URI, headers, body)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorPayload {
    /// Unique request identifier (UUID v4)
    pub request_id: String,

    /// Timestamp of original request (RFC 3339)
    pub timestamp: String,

    /// Source IP address of the client
    pub source_ip: String,

    /// JA4 TLS fingerprint (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4_fingerprint: Option<String>,

    /// JA4H HTTP fingerprint (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4h_fingerprint: Option<String>,

    /// Risk score that triggered mirroring (0-100)
    pub risk_score: f32,

    /// IDs of rules that matched this request
    pub matched_rules: Vec<String>,

    /// Campaign ID if correlated to a known threat campaign
    #[serde(skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,

    /// HTTP method (GET, POST, etc.)
    pub method: String,

    /// Request URI (path + query string)
    pub uri: String,

    /// Request headers (filtered based on configuration)
    pub headers: HashMap<String, String>,

    /// Request body (if include_body enabled and within max size)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// WAF site/vhost name that processed the request
    pub site_name: String,

    /// Synapse sensor ID for multi-sensor deployments
    pub sensor_id: String,

    /// Version of the mirror payload protocol
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
}

fn default_protocol_version() -> String {
    "1.0".to_string()
}

impl MirrorPayload {
    /// Creates a new MirrorPayload with required fields.
    pub fn new(
        request_id: String,
        source_ip: String,
        risk_score: f32,
        method: String,
        uri: String,
        site_name: String,
        sensor_id: String,
    ) -> Self {
        Self {
            request_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_ip,
            ja4_fingerprint: None,
            ja4h_fingerprint: None,
            risk_score,
            matched_rules: Vec::new(),
            campaign_id: None,
            method,
            uri,
            headers: HashMap::new(),
            body: None,
            site_name,
            sensor_id,
            protocol_version: default_protocol_version(),
        }
    }

    /// Sets the JA4 TLS fingerprint.
    pub fn with_ja4(mut self, fingerprint: Option<String>) -> Self {
        self.ja4_fingerprint = fingerprint;
        self
    }

    /// Sets the JA4H HTTP fingerprint.
    pub fn with_ja4h(mut self, fingerprint: Option<String>) -> Self {
        self.ja4h_fingerprint = fingerprint;
        self
    }

    /// Sets the matched rules.
    pub fn with_rules(mut self, rules: Vec<String>) -> Self {
        self.matched_rules = rules;
        self
    }

    /// Sets the campaign ID.
    pub fn with_campaign(mut self, campaign_id: Option<String>) -> Self {
        self.campaign_id = campaign_id;
        self
    }

    /// Sets the request headers after sanitizing sensitive credentials.
    ///
    /// Automatically strips Authorization, Cookie, and other credential headers
    /// to prevent leaking user credentials to honeypot systems.
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = sanitize_headers(&headers);
        self
    }

    /// Sets the request headers without sanitization.
    ///
    /// # Safety
    /// This method bypasses header sanitization. Only use this when headers
    /// have already been sanitized or when intentionally including all headers
    /// (e.g., for internal testing honeypots).
    pub fn with_headers_unsanitized(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = headers;
        self
    }

    /// Sets the request body.
    pub fn with_body(mut self, body: Option<String>) -> Self {
        self.body = body;
        self
    }

    /// Serializes the payload to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Serializes the payload to a JSON string.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert(
            "Authorization".to_string(),
            "Bearer secret-token".to_string(),
        );
        headers.insert("Cookie".to_string(), "session=abc123".to_string());
        headers.insert("X-Api-Key".to_string(), "api-key-value".to_string());
        headers.insert("User-Agent".to_string(), "test-agent".to_string());
        headers.insert("X-Request-ID".to_string(), "req-123".to_string());

        let sanitized = sanitize_headers(&headers);

        // Safe headers should be preserved
        assert!(sanitized.contains_key("Content-Type"));
        assert!(sanitized.contains_key("User-Agent"));
        assert!(sanitized.contains_key("X-Request-ID"));

        // Sensitive headers should be removed
        assert!(!sanitized.contains_key("Authorization"));
        assert!(!sanitized.contains_key("Cookie"));
        assert!(!sanitized.contains_key("X-Api-Key"));

        assert_eq!(sanitized.len(), 3);
    }

    #[test]
    fn test_sanitize_headers_case_insensitive() {
        let mut headers = HashMap::new();
        headers.insert("AUTHORIZATION".to_string(), "Bearer token".to_string());
        headers.insert("cookie".to_string(), "session=xyz".to_string());
        headers.insert("X-API-KEY".to_string(), "key".to_string());

        let sanitized = sanitize_headers(&headers);
        assert!(sanitized.is_empty());
    }

    #[test]
    fn test_is_sensitive_header() {
        assert!(is_sensitive_header("authorization"));
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("COOKIE"));
        assert!(is_sensitive_header("x-api-key"));
        assert!(is_sensitive_header("X-CSRF-Token"));

        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("User-Agent"));
        assert!(!is_sensitive_header("X-Request-ID"));
    }

    #[test]
    fn test_with_headers_sanitizes() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("Authorization".to_string(), "Bearer secret".to_string());

        let payload = MirrorPayload::new(
            "test".to_string(),
            "10.0.0.1".to_string(),
            50.0,
            "POST".to_string(),
            "/api".to_string(),
            "site".to_string(),
            "sensor".to_string(),
        )
        .with_headers(headers);

        assert!(payload.headers.contains_key("Content-Type"));
        assert!(!payload.headers.contains_key("Authorization"));
    }

    #[test]
    fn test_new_payload() {
        let payload = MirrorPayload::new(
            "test-uuid".to_string(),
            "192.168.1.100".to_string(),
            55.0,
            "POST".to_string(),
            "/api/login".to_string(),
            "example.com".to_string(),
            "sensor-01".to_string(),
        );

        assert_eq!(payload.request_id, "test-uuid");
        assert_eq!(payload.source_ip, "192.168.1.100");
        assert_eq!(payload.risk_score, 55.0);
        assert_eq!(payload.method, "POST");
        assert_eq!(payload.uri, "/api/login");
        assert_eq!(payload.site_name, "example.com");
        assert_eq!(payload.sensor_id, "sensor-01");
        assert_eq!(payload.protocol_version, "1.0");
        assert!(payload.ja4_fingerprint.is_none());
        assert!(payload.matched_rules.is_empty());
    }

    #[test]
    fn test_builder_pattern() {
        let payload = MirrorPayload::new(
            "test-uuid".to_string(),
            "10.0.0.1".to_string(),
            60.0,
            "GET".to_string(),
            "/admin".to_string(),
            "admin.example.com".to_string(),
            "sensor-02".to_string(),
        )
        .with_ja4(Some("t13d1516h2_abc123".to_string()))
        .with_ja4h(Some("ge11cn20enus_xyz789".to_string()))
        .with_rules(vec!["sqli-001".to_string(), "xss-002".to_string()])
        .with_campaign(Some("campaign-12345".to_string()));

        assert_eq!(
            payload.ja4_fingerprint,
            Some("t13d1516h2_abc123".to_string())
        );
        assert_eq!(
            payload.ja4h_fingerprint,
            Some("ge11cn20enus_xyz789".to_string())
        );
        assert_eq!(payload.matched_rules.len(), 2);
        assert_eq!(payload.campaign_id, Some("campaign-12345".to_string()));
    }

    #[test]
    fn test_json_serialization() {
        let payload = MirrorPayload::new(
            "test-uuid".to_string(),
            "192.168.1.1".to_string(),
            45.0,
            "POST".to_string(),
            "/api/data".to_string(),
            "api.example.com".to_string(),
            "sensor-01".to_string(),
        );

        let json = payload.to_json_string().unwrap();
        assert!(json.contains("\"request_id\":\"test-uuid\""));
        assert!(json.contains("\"source_ip\":\"192.168.1.1\""));
        assert!(json.contains("\"risk_score\":45.0"));
    }

    #[test]
    fn test_json_deserialization() {
        let json = r#"{
            "request_id": "abc123",
            "timestamp": "2024-01-15T12:00:00Z",
            "source_ip": "10.0.0.1",
            "risk_score": 50.0,
            "matched_rules": ["rule-1"],
            "method": "GET",
            "uri": "/test",
            "headers": {},
            "site_name": "test.com",
            "sensor_id": "sensor-1",
            "protocol_version": "1.0"
        }"#;

        let payload: MirrorPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.request_id, "abc123");
        assert_eq!(payload.source_ip, "10.0.0.1");
        assert_eq!(payload.risk_score, 50.0);
    }

    #[test]
    fn test_optional_fields_skip_serialization() {
        let payload = MirrorPayload::new(
            "test".to_string(),
            "10.0.0.1".to_string(),
            50.0,
            "GET".to_string(),
            "/".to_string(),
            "site".to_string(),
            "sensor".to_string(),
        );

        let json = payload.to_json_string().unwrap();
        // Optional None fields should not appear in JSON
        assert!(!json.contains("ja4_fingerprint"));
        assert!(!json.contains("ja4h_fingerprint"));
        assert!(!json.contains("campaign_id"));
        assert!(!json.contains("body"));
    }
}
