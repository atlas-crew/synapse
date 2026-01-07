//! Data Loss Prevention (DLP) module for synapse-pingora WAF proxy.
//!
//! This module provides pattern-based detection and protection against sensitive data
//! leakage in HTTP request and response bodies and headers.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

/// DLP-specific errors.
#[derive(Debug, Error)]
pub enum DlpError {
    #[error("invalid CIDR '{cidr}': {reason}")]
    InvalidPattern { cidr: String, reason: String },

    #[error("configuration error: {0}")]
    ConfigError(String),
}

/// Result type alias for DLP operations.
pub type DlpResult<T> = Result<T, DlpError>;

/// Types of sensitive data patterns that can be detected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    Ssn,
    CreditCard,
    ApiKey,
    Email,
    PhoneNumber,
    AwsAccessKey,
    PrivateKey,
    JwtToken,
    Custom(String),
}

impl std::fmt::Display for PatternType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternType::Ssn => write!(f, "SSN"),
            PatternType::CreditCard => write!(f, "CreditCard"),
            PatternType::ApiKey => write!(f, "ApiKey"),
            PatternType::Email => write!(f, "Email"),
            PatternType::PhoneNumber => write!(f, "PhoneNumber"),
            PatternType::AwsAccessKey => write!(f, "AwsAccessKey"),
            PatternType::PrivateKey => write!(f, "PrivateKey"),
            PatternType::JwtToken => write!(f, "JwtToken"),
            PatternType::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

/// Severity level for DLP matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    #[default]
    Medium,
    High,
    Critical,
}

/// Action to take when a DLP pattern is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    #[default]
    Log,
    Block,
    Mask,
    Alert,
}

/// Location where a DLP match was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchLocation {
    RequestBody { offset: usize, length: usize },
    ResponseBody { offset: usize, length: usize },
    Header { name: String },
}

/// A DLP pattern definition.
#[derive(Debug, Clone)]
pub struct DlpPattern {
    pub id: String,
    pub pattern_type: PatternType,
    pub description: String,
    regex: Regex,
    pub severity: Severity,
    pub preview_chars: usize,
    pub enabled: bool,
}

impl DlpPattern {
    /// Create a new DLP pattern with a regex string.
    pub fn new(
        id: impl Into<String>,
        pattern_type: PatternType,
        regex_pattern: &str,
        description: impl Into<String>,
        severity: Severity,
    ) -> DlpResult<Self> {
        let regex = Regex::new(regex_pattern).map_err(|e| DlpError::InvalidPattern {
            cidr: regex_pattern.to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            id: id.into(),
            pattern_type,
            description: description.into(),
            regex,
            severity,
            preview_chars: 4,
            enabled: true,
        })
    }

    pub fn with_preview_chars(mut self, chars: usize) -> Self {
        self.preview_chars = chars;
        self
    }

    pub fn matches(&self, input: &str) -> bool {
        self.enabled && self.regex.is_match(input)
    }

    pub fn find_all(&self, input: &str) -> Vec<(usize, usize, String)> {
        if !self.enabled {
            return Vec::new();
        }
        self.regex
            .find_iter(input)
            .map(|m| (m.start(), m.end(), m.as_str().to_string()))
            .collect()
    }

    pub fn mask_value(&self, value: &str) -> String {
        let len = value.len();
        if len <= self.preview_chars {
            return "*".repeat(len);
        }
        let visible = &value[len - self.preview_chars..];
        format!("{}{}", "*".repeat(len - self.preview_chars), visible)
    }
}

/// Represents a detected DLP pattern match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpMatch {
    pub pattern_id: String,
    pub pattern_type: PatternType,
    pub location: MatchLocation,
    pub severity: Severity,
    pub masked_preview: String,
    pub original_length: usize,
    pub detected_at: u64,
}

impl DlpMatch {
    pub fn new(pattern: &DlpPattern, location: MatchLocation, original_value: &str) -> Self {
        Self {
            pattern_id: pattern.id.clone(),
            pattern_type: pattern.pattern_type.clone(),
            location,
            severity: pattern.severity,
            masked_preview: pattern.mask_value(original_value),
            original_length: original_value.len(),
            detected_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Configuration for DLP scanning.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    #[serde(default)]
    pub enabled_patterns: Vec<PatternType>,
    #[serde(default)]
    pub default_action: DlpAction,
    #[serde(default)]
    pub pattern_actions: HashMap<String, DlpAction>,
    #[serde(default)]
    pub max_body_size: usize,
    #[serde(default)]
    pub scan_requests: bool,
    #[serde(default)]
    pub scan_responses: bool,
    #[serde(default)]
    pub scan_headers: bool,
    #[serde(default)]
    pub min_action_severity: Severity,
}

impl DlpConfig {
    pub fn new() -> Self {
        Self {
            enabled: true,
            enabled_patterns: vec![PatternType::Ssn, PatternType::CreditCard, PatternType::ApiKey],
            default_action: DlpAction::Log,
            max_body_size: 1024 * 1024,
            scan_requests: true,
            scan_responses: true,
            scan_headers: true,
            ..Default::default()
        }
    }

    pub fn get_action(&self, pattern_id: &str) -> DlpAction {
        self.pattern_actions
            .get(pattern_id)
            .copied()
            .unwrap_or(self.default_action)
    }
}

/// DLP scanner for detecting sensitive data patterns.
pub struct DlpScanner {
    patterns: Vec<Arc<DlpPattern>>,
    config: DlpConfig,
}

impl DlpScanner {
    pub fn new(config: DlpConfig) -> DlpResult<Self> {
        let patterns = Self::default_patterns()?;
        Ok(Self { patterns, config })
    }

    fn default_patterns() -> DlpResult<Vec<Arc<DlpPattern>>> {
        let patterns = vec![
            DlpPattern::new("ssn-us", PatternType::Ssn, r"\b\d{3}-\d{2}-\d{4}\b", "US SSN", Severity::Critical)?,
            DlpPattern::new("cc-visa", PatternType::CreditCard, r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "Visa", Severity::Critical)?,
            DlpPattern::new("api-key", PatternType::ApiKey, r#"(?i)(api[_-]?key|apikey)['"]?\s*[:=]\s*['"]?[\w-]{20,}"#, "API Key", Severity::High)?,
            DlpPattern::new("email", PatternType::Email, r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email", Severity::Low)?,
            DlpPattern::new("aws-key", PatternType::AwsAccessKey, r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b", "AWS Key", Severity::Critical)?,
            DlpPattern::new("jwt", PatternType::JwtToken, r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "JWT", Severity::High)?,
        ];
        Ok(patterns.into_iter().map(Arc::new).collect())
    }

    pub fn scan_body(&self, body: &[u8], is_request: bool) -> Vec<DlpMatch> {
        if !self.config.enabled {
            return Vec::new();
        }
        if (is_request && !self.config.scan_requests) || (!is_request && !self.config.scan_responses) {
            return Vec::new();
        }
        if body.len() > self.config.max_body_size {
            debug!(body_size = body.len(), "Body exceeds max scan size");
            return Vec::new();
        }

        let body_str = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        self.scan_text(body_str, is_request)
    }

    fn scan_text(&self, text: &str, is_request: bool) -> Vec<DlpMatch> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            if !pattern.enabled {
                continue;
            }
            if !self.config.enabled_patterns.is_empty()
                && !self.config.enabled_patterns.contains(&pattern.pattern_type)
            {
                continue;
            }
            for (start, end, value) in pattern.find_all(text) {
                let location = if is_request {
                    MatchLocation::RequestBody { offset: start, length: end - start }
                } else {
                    MatchLocation::ResponseBody { offset: start, length: end - start }
                };
                let dlp_match = DlpMatch::new(pattern, location, &value);
                if dlp_match.severity >= self.config.min_action_severity {
                    warn!(pattern_id = %pattern.id, severity = ?pattern.severity, "DLP match detected");
                    matches.push(dlp_match);
                }
            }
        }
        matches
    }

    pub fn scan_headers(&self, headers: &[(String, String)]) -> Vec<DlpMatch> {
        if !self.config.enabled || !self.config.scan_headers {
            return Vec::new();
        }
        let mut matches = Vec::new();
        for (name, value) in headers {
            for pattern in &self.patterns {
                if !pattern.enabled {
                    continue;
                }
                if pattern.matches(value) {
                    let dlp_match = DlpMatch::new(pattern, MatchLocation::Header { name: name.clone() }, value);
                    if dlp_match.severity >= self.config.min_action_severity {
                        matches.push(dlp_match);
                    }
                }
            }
        }
        matches
    }

    pub fn get_action_for_matches(&self, matches: &[DlpMatch]) -> DlpAction {
        if matches.is_empty() {
            return DlpAction::Log;
        }
        let mut max_action = self.config.default_action;
        for m in matches {
            let action = self.config.get_action(&m.pattern_id);
            if action == DlpAction::Block {
                return DlpAction::Block;
            }
            if action == DlpAction::Mask && max_action != DlpAction::Block {
                max_action = DlpAction::Mask;
            }
        }
        max_action
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DlpConfig {
        DlpConfig {
            enabled: true,
            enabled_patterns: vec![PatternType::Ssn, PatternType::CreditCard, PatternType::Email],
            default_action: DlpAction::Log,
            scan_requests: true,
            scan_responses: true,
            scan_headers: true,
            max_body_size: 1024 * 1024,
            min_action_severity: Severity::Info,
            ..Default::default()
        }
    }

    #[test]
    fn test_ssn_detection() {
        let scanner = DlpScanner::new(test_config()).unwrap();
        let body = b"My SSN is 123-45-6789";
        let matches = scanner.scan_body(body, true);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_type, PatternType::Ssn);
    }

    #[test]
    fn test_credit_card_detection() {
        let scanner = DlpScanner::new(test_config()).unwrap();
        let body = b"Card: 4111-1111-1111-1111";
        let matches = scanner.scan_body(body, true);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_type, PatternType::CreditCard);
    }

    #[test]
    fn test_email_detection() {
        let scanner = DlpScanner::new(test_config()).unwrap();
        let body = b"Contact: user@example.com";
        let matches = scanner.scan_body(body, false);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].pattern_type, PatternType::Email);
    }

    #[test]
    fn test_masking() {
        let pattern = DlpPattern::new("test", PatternType::Ssn, r"\d{3}-\d{2}-\d{4}", "Test", Severity::High).unwrap();
        let masked = pattern.mask_value("123-45-6789");
        assert_eq!(masked, "*******6789");
    }

    #[test]
    fn test_disabled_scanner() {
        let mut config = test_config();
        config.enabled = false;
        let scanner = DlpScanner::new(config).unwrap();
        let body = b"SSN: 123-45-6789";
        let matches = scanner.scan_body(body, true);
        assert!(matches.is_empty());
    }
}
