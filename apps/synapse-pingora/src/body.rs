//! Request/Response Body Inspection Module
//!
//! Provides functionality for inspecting HTTP request and response bodies,
//! including content-type detection, parsing, and anomaly detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, instrument};

/// Errors that can occur during body inspection
#[derive(Debug, Error)]
pub enum BodyError {
    #[error("payload too large: {size} bytes exceeds limit of {limit} bytes")]
    PayloadTooLarge { size: usize, limit: usize },

    #[error("parse error: {message}")]
    ParseError {
        message: String,
        content_type: ContentType,
    },

    #[error("inspection timeout after {elapsed:?}")]
    Timeout { elapsed: Duration, limit: Duration },

    #[error("max parse depth exceeded: {depth} > {limit}")]
    MaxDepthExceeded { depth: usize, limit: usize },
}

pub type BodyResult<T> = Result<T, BodyError>;

/// Detected content type of HTTP body
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Json,
    Xml,
    FormUrlencoded,
    Multipart,
    PlainText,
    Html,
    Binary,
    #[default]
    Unknown,
}

impl ContentType {
    pub fn from_header(header: &str) -> Self {
        let lower = header.to_lowercase();
        let mime = lower.split(';').next().unwrap_or("").trim();
        match mime {
            "application/json" | "text/json" => Self::Json,
            "application/xml" | "text/xml" => Self::Xml,
            "application/x-www-form-urlencoded" => Self::FormUrlencoded,
            m if m.starts_with("multipart/") => Self::Multipart,
            "text/plain" => Self::PlainText,
            "text/html" => Self::Html,
            "application/octet-stream" => Self::Binary,
            _ => Self::Unknown,
        }
    }

    pub fn detect_from_body(body: &[u8]) -> Self {
        if body.is_empty() {
            return Self::Unknown;
        }
        let trimmed: Vec<u8> = body
            .iter()
            .skip_while(|&&b| b.is_ascii_whitespace())
            .copied()
            .collect();
        if trimmed.is_empty() {
            return Self::Unknown;
        }
        let first = trimmed[0];
        if first == b'{' || first == b'[' {
            return Self::Json;
        }
        if first == b'<' {
            if let Ok(s) = std::str::from_utf8(&trimmed) {
                let lower = s.to_lowercase();
                if lower.starts_with("<!doctype html") || lower.starts_with("<html") {
                    return Self::Html;
                }
                return Self::Xml;
            }
        }
        if let Ok(s) = std::str::from_utf8(body) {
            if s.contains('=') && (s.contains('&') || !s.contains(' ')) {
                return Self::FormUrlencoded;
            }
            return Self::PlainText;
        }
        Self::Binary
    }

    pub const fn is_text(&self) -> bool {
        matches!(
            self,
            Self::Json | Self::Xml | Self::FormUrlencoded | Self::PlainText | Self::Html
        )
    }
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "application/json"),
            Self::Xml => write!(f, "application/xml"),
            Self::FormUrlencoded => write!(f, "application/x-www-form-urlencoded"),
            Self::Multipart => write!(f, "multipart/form-data"),
            Self::PlainText => write!(f, "text/plain"),
            Self::Html => write!(f, "text/html"),
            Self::Binary => write!(f, "application/octet-stream"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Parsed body structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ParsedBody {
    Json(serde_json::Value),
    Form(HashMap<String, Vec<String>>),
    Text(String),
    Binary { size: usize, hash: String },
}

/// Detected anomaly in body content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyAnomaly {
    pub anomaly_type: AnomalyType,
    pub severity: f32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    OversizedPayload,
    MalformedContent,
    ContentTypeMismatch,
    NullBytesInText,
    ControlCharacters,
    DuplicateKeys,
}

impl BodyAnomaly {
    pub fn new(anomaly_type: AnomalyType, severity: f32, description: impl Into<String>) -> Self {
        Self {
            anomaly_type,
            severity: severity.clamp(0.0, 1.0),
            description: description.into(),
        }
    }
}

/// Configuration for body inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyConfig {
    pub max_body_size: usize,
    pub max_parse_depth: usize,
    pub timeout: Duration,
    pub detect_anomalies: bool,
    pub large_payload_threshold: usize,
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            max_body_size: 10 * 1024 * 1024,
            max_parse_depth: 32,
            timeout: Duration::from_secs(5),
            detect_anomalies: true,
            large_payload_threshold: 1024 * 1024,
        }
    }
}

/// Result of body inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectionResult {
    pub content_type: ContentType,
    pub declared_content_type: Option<ContentType>,
    pub body_size: usize,
    pub parsed_structure: Option<ParsedBody>,
    pub anomalies: Vec<BodyAnomaly>,
    pub processing_time: Duration,
    pub parse_success: bool,
    pub parse_error: Option<String>,
}

impl InspectionResult {
    pub fn has_anomalies(&self) -> bool {
        !self.anomalies.is_empty()
    }

    pub fn max_severity(&self) -> f32 {
        self.anomalies
            .iter()
            .map(|a| a.severity)
            .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or(0.0)
    }
}

/// Main body inspection engine
#[derive(Debug)]
pub struct BodyInspector {
    config: BodyConfig,
}

impl BodyInspector {
    pub fn new(config: BodyConfig) -> Self {
        Self { config }
    }

    #[instrument(skip(self, body), fields(body_len = body.len()))]
    pub fn inspect(
        &self,
        body: &[u8],
        content_type_header: Option<&str>,
    ) -> BodyResult<InspectionResult> {
        let start = Instant::now();
        if body.len() > self.config.max_body_size {
            return Err(BodyError::PayloadTooLarge {
                size: body.len(),
                limit: self.config.max_body_size,
            });
        }

        let declared = content_type_header.map(ContentType::from_header);
        let detected = ContentType::detect_from_body(body);
        let content_type = declared.unwrap_or(detected);

        let (parsed, parse_success, parse_error) = self.parse_body(body, content_type);
        let mut anomalies = Vec::new();
        if self.config.detect_anomalies {
            self.detect_anomalies(body, content_type, declared, detected, &mut anomalies);
        }

        debug!(
            ?content_type,
            body_size = body.len(),
            "body inspection complete"
        );
        Ok(InspectionResult {
            content_type,
            declared_content_type: declared,
            body_size: body.len(),
            parsed_structure: parsed,
            anomalies,
            processing_time: start.elapsed(),
            parse_success,
            parse_error,
        })
    }

    fn parse_body(
        &self,
        body: &[u8],
        content_type: ContentType,
    ) -> (Option<ParsedBody>, bool, Option<String>) {
        if body.is_empty() {
            return (None, true, None);
        }
        match content_type {
            ContentType::Json => self.parse_json(body),
            ContentType::FormUrlencoded => self.parse_form(body),
            ContentType::PlainText | ContentType::Html => self.parse_text(body),
            _ => (Some(self.parse_binary(body)), true, None),
        }
    }

    fn parse_json(&self, body: &[u8]) -> (Option<ParsedBody>, bool, Option<String>) {
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(e) => return (None, false, Some(e.to_string())),
        };

        // Parse with depth limit to prevent stack overflow from deeply nested payloads
        match self.parse_json_with_depth_limit(text, self.config.max_parse_depth) {
            Ok(value) => (Some(ParsedBody::Json(value)), true, None),
            Err(e) => (None, false, Some(e)),
        }
    }

    /// Parse JSON with a maximum nesting depth limit.
    ///
    /// This prevents stack overflow attacks from payloads with extreme nesting depth.
    fn parse_json_with_depth_limit(
        &self,
        text: &str,
        max_depth: usize,
    ) -> Result<serde_json::Value, String> {
        use serde_json::Value;

        let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;

        // Check depth after parsing (serde_json has a default recursion limit of 128,
        // but we enforce a stricter limit for security)
        if self.check_json_depth(&value, 0, max_depth) {
            Ok(value)
        } else {
            Err(format!("JSON nesting depth exceeds limit of {}", max_depth))
        }
    }

    /// Recursively check if JSON depth exceeds the limit.
    fn check_json_depth(
        &self,
        value: &serde_json::Value,
        current_depth: usize,
        max_depth: usize,
    ) -> bool {
        if current_depth > max_depth {
            return false;
        }

        match value {
            serde_json::Value::Array(arr) => arr
                .iter()
                .all(|v| self.check_json_depth(v, current_depth + 1, max_depth)),
            serde_json::Value::Object(obj) => obj
                .values()
                .all(|v| self.check_json_depth(v, current_depth + 1, max_depth)),
            _ => true,
        }
    }

    fn parse_form(&self, body: &[u8]) -> (Option<ParsedBody>, bool, Option<String>) {
        let text = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(e) => return (None, false, Some(e.to_string())),
        };
        let mut form: HashMap<String, Vec<String>> = HashMap::new();
        for pair in text.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            form.entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }
        (Some(ParsedBody::Form(form)), true, None)
    }

    fn parse_text(&self, body: &[u8]) -> (Option<ParsedBody>, bool, Option<String>) {
        match std::str::from_utf8(body) {
            Ok(s) => (Some(ParsedBody::Text(s.to_string())), true, None),
            Err(e) => (None, false, Some(e.to_string())),
        }
    }

    fn parse_binary(&self, body: &[u8]) -> ParsedBody {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        ParsedBody::Binary {
            size: body.len(),
            hash: format!("{:016x}", hasher.finish()),
        }
    }

    fn detect_anomalies(
        &self,
        body: &[u8],
        content_type: ContentType,
        declared: Option<ContentType>,
        detected: ContentType,
        anomalies: &mut Vec<BodyAnomaly>,
    ) {
        if body.len() > self.config.large_payload_threshold {
            anomalies.push(BodyAnomaly::new(
                AnomalyType::OversizedPayload,
                0.3,
                "large payload",
            ));
        }
        if let Some(decl) = declared {
            if decl != detected && detected != ContentType::Unknown {
                anomalies.push(BodyAnomaly::new(
                    AnomalyType::ContentTypeMismatch,
                    0.6,
                    "content type mismatch",
                ));
            }
        }
        if content_type.is_text() && body.contains(&0u8) {
            anomalies.push(BodyAnomaly::new(
                AnomalyType::NullBytesInText,
                0.8,
                "null bytes in text",
            ));
        }
    }
}

impl Default for BodyInspector {
    fn default() -> Self {
        Self::new(BodyConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_detection() {
        assert_eq!(
            ContentType::from_header("application/json"),
            ContentType::Json
        );
        assert_eq!(ContentType::from_header("text/html"), ContentType::Html);
        assert_eq!(
            ContentType::detect_from_body(br#"{"key": "value"}"#),
            ContentType::Json
        );
        assert_eq!(ContentType::detect_from_body(b"<html>"), ContentType::Html);
    }

    #[test]
    fn test_inspector_json() {
        let inspector = BodyInspector::default();
        let body = br#"{"test": "value"}"#;
        let result = inspector.inspect(body, Some("application/json")).unwrap();
        assert_eq!(result.content_type, ContentType::Json);
        assert!(result.parse_success);
    }

    #[test]
    fn test_inspector_size_limit() {
        let mut config = BodyConfig::default();
        config.max_body_size = 10;
        let inspector = BodyInspector::new(config);
        let body = b"this is way too large";
        let result = inspector.inspect(body, None);
        assert!(matches!(result, Err(BodyError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_json_depth_limit_within_limit() {
        let mut config = BodyConfig::default();
        config.max_parse_depth = 4;
        let inspector = BodyInspector::new(config);

        // Depth 3: {"a": {"b": {"c": "value"}}}
        let body = br#"{"a": {"b": {"c": "value"}}}"#;
        let result = inspector.inspect(body, Some("application/json")).unwrap();
        assert!(result.parse_success);
    }

    #[test]
    fn test_json_depth_limit_exceeded() {
        let mut config = BodyConfig::default();
        config.max_parse_depth = 2;
        let inspector = BodyInspector::new(config);

        // Depth 3: {"a": {"b": {"c": "value"}}} - exceeds limit of 2
        let body = br#"{"a": {"b": {"c": "value"}}}"#;
        let result = inspector.inspect(body, Some("application/json")).unwrap();
        assert!(!result.parse_success);
        assert!(result.parse_error.unwrap().contains("depth"));
    }

    #[test]
    fn test_json_array_depth_limit() {
        let mut config = BodyConfig::default();
        config.max_parse_depth = 3;
        let inspector = BodyInspector::new(config);

        // Depth 4: [[[[1]]]] - exceeds limit of 3
        let body = br#"[[[[1]]]]"#;
        let result = inspector.inspect(body, Some("application/json")).unwrap();
        assert!(!result.parse_success);
    }

    #[test]
    fn test_json_mixed_depth_limit() {
        let mut config = BodyConfig::default();
        config.max_parse_depth = 3;
        let inspector = BodyInspector::new(config);

        // Mix of arrays and objects at depth 3 - within limit
        let body = br#"{"arr": [{"key": "value"}]}"#;
        let result = inspector.inspect(body, Some("application/json")).unwrap();
        assert!(result.parse_success);
    }
}
