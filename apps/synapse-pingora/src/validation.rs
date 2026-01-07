//! Input validation for configuration mutation requests.
//!
//! This module provides comprehensive validation for all configuration parameters
//! that can be mutated at runtime, including hostnames, upstreams, CIDR ranges,
//! WAF settings, and rate limits.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use thiserror::Error;

/// Validation errors for configuration mutation requests.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Invalid hostname format or content.
    #[error("invalid hostname '{value}': {reason}")]
    InvalidHostname { value: String, reason: String },

    /// Invalid upstream address format.
    #[error("invalid upstream '{value}': {reason}")]
    InvalidUpstream { value: String, reason: String },

    /// Invalid CIDR notation.
    #[error("invalid CIDR '{value}': {reason}")]
    InvalidCidr { value: String, reason: String },

    /// Invalid WAF configuration parameter.
    #[error("invalid WAF config: {reason}")]
    InvalidWafConfig { reason: String },

    /// Invalid rate limit configuration.
    #[error("invalid rate limit: {reason}")]
    InvalidRateLimit { reason: String },

    /// Security violation detected in input.
    #[error("security violation: {reason}")]
    SecurityViolation { reason: String },
}

/// Result type for validation operations.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Maximum hostname length per RFC 1123.
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum label length within a hostname.
const MAX_LABEL_LENGTH: usize = 63;

/// Maximum requests per second for rate limiting.
const MAX_RPS: u64 = 1_000_000;

/// Maximum burst size for rate limiting.
const MAX_BURST: u64 = 10_000_000;

/// Validates a hostname according to RFC 1123 with wildcard support.
pub fn validate_hostname(hostname: &str) -> ValidationResult<()> {
    if hostname.is_empty() {
        return Err(ValidationError::InvalidHostname {
            value: hostname.to_string(),
            reason: "hostname cannot be empty".to_string(),
        });
    }

    if hostname.len() > MAX_HOSTNAME_LENGTH {
        return Err(ValidationError::InvalidHostname {
            value: hostname.to_string(),
            reason: format!("hostname exceeds maximum length of {} characters", MAX_HOSTNAME_LENGTH),
        });
    }

    let labels: Vec<&str> = hostname.split('.').collect();

    for (i, label) in labels.iter().enumerate() {
        validate_hostname_label(hostname, label, i == 0)?;
    }

    Ok(())
}

fn validate_hostname_label(hostname: &str, label: &str, is_first: bool) -> ValidationResult<()> {
    if label.is_empty() {
        return Err(ValidationError::InvalidHostname {
            value: hostname.to_string(),
            reason: "empty label in hostname".to_string(),
        });
    }

    // Allow wildcard as first label only
    if label == "*" {
        if is_first {
            return Ok(());
        } else {
            return Err(ValidationError::InvalidHostname {
                value: hostname.to_string(),
                reason: "wildcard (*) is only allowed as the first label".to_string(),
            });
        }
    }

    if label.len() > MAX_LABEL_LENGTH {
        return Err(ValidationError::InvalidHostname {
            value: hostname.to_string(),
            reason: format!("label '{}' exceeds maximum length of {} characters", label, MAX_LABEL_LENGTH),
        });
    }

    if label.starts_with('-') || label.ends_with('-') {
        return Err(ValidationError::InvalidHostname {
            value: hostname.to_string(),
            reason: format!("label '{}' cannot start or end with a hyphen", label),
        });
    }

    for ch in label.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            return Err(ValidationError::InvalidHostname {
                value: hostname.to_string(),
                reason: format!("label '{}' contains invalid character '{}'", label, ch),
            });
        }
    }

    Ok(())
}

/// Validates an upstream address in `host:port` format.
pub fn validate_upstream(upstream: &str) -> ValidationResult<()> {
    if upstream.is_empty() {
        return Err(ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "upstream cannot be empty".to_string(),
        });
    }

    if upstream.contains('/') {
        return Err(ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "upstream cannot contain path components".to_string(),
        });
    }

    let (host, port_str) = if upstream.starts_with('[') {
        // IPv6 format: [::1]:port
        let bracket_end = upstream.find(']').ok_or_else(|| ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "malformed IPv6 address".to_string(),
        })?;
        let colon_pos = upstream[bracket_end..].find(':').map(|p| p + bracket_end);
        match colon_pos {
            Some(pos) => (&upstream[1..bracket_end], &upstream[pos + 1..]),
            None => return Err(ValidationError::InvalidUpstream {
                value: upstream.to_string(),
                reason: "missing port number".to_string(),
            }),
        }
    } else {
        upstream.rsplit_once(':').ok_or_else(|| ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "missing port number (expected host:port format)".to_string(),
        })?
    };

    let port: u16 = port_str.parse().map_err(|_| ValidationError::InvalidUpstream {
        value: upstream.to_string(),
        reason: format!("invalid port number '{}'", port_str),
    })?;

    if port == 0 {
        return Err(ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "port must be between 1 and 65535".to_string(),
        });
    }

    if host.is_empty() {
        return Err(ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: "host cannot be empty".to_string(),
        });
    }

    // Try parsing as IP, otherwise validate as hostname
    if IpAddr::from_str(host).is_err() {
        validate_hostname(host).map_err(|e| ValidationError::InvalidUpstream {
            value: upstream.to_string(),
            reason: format!("invalid host: {}", e),
        })?;
    }

    Ok(())
}

/// Validates a CIDR notation string for IPv4 or IPv6.
pub fn validate_cidr(cidr: &str) -> ValidationResult<()> {
    if cidr.is_empty() {
        return Err(ValidationError::InvalidCidr {
            value: cidr.to_string(),
            reason: "CIDR cannot be empty".to_string(),
        });
    }

    let (address, prefix_str) = cidr.split_once('/').ok_or_else(|| ValidationError::InvalidCidr {
        value: cidr.to_string(),
        reason: "CIDR must be in format 'address/prefix'".to_string(),
    })?;

    let prefix: u8 = prefix_str.parse().map_err(|_| ValidationError::InvalidCidr {
        value: cidr.to_string(),
        reason: format!("invalid prefix length '{}'", prefix_str),
    })?;

    if let Ok(_addr) = Ipv4Addr::from_str(address) {
        if prefix > 32 {
            return Err(ValidationError::InvalidCidr {
                value: cidr.to_string(),
                reason: format!("IPv4 prefix length must be 0-32, got {}", prefix),
            });
        }
        return Ok(());
    }

    if let Ok(_addr) = Ipv6Addr::from_str(address) {
        if prefix > 128 {
            return Err(ValidationError::InvalidCidr {
                value: cidr.to_string(),
                reason: format!("IPv6 prefix length must be 0-128, got {}", prefix),
            });
        }
        return Ok(());
    }

    Err(ValidationError::InvalidCidr {
        value: cidr.to_string(),
        reason: format!("'{}' is not a valid IPv4 or IPv6 address", address),
    })
}

/// Validates a WAF threshold value.
pub fn validate_waf_threshold(threshold: f64) -> ValidationResult<()> {
    if threshold.is_nan() {
        return Err(ValidationError::InvalidWafConfig {
            reason: "threshold cannot be NaN".to_string(),
        });
    }

    if threshold.is_infinite() {
        return Err(ValidationError::InvalidWafConfig {
            reason: "threshold cannot be infinite".to_string(),
        });
    }

    if !(0.0..=1.0).contains(&threshold) {
        return Err(ValidationError::InvalidWafConfig {
            reason: format!("threshold must be between 0.0 and 1.0, got {}", threshold),
        });
    }

    Ok(())
}

/// Validates rate limit configuration.
pub fn validate_rate_limit(rps: u64, burst: u64) -> ValidationResult<()> {
    if rps == 0 {
        return Err(ValidationError::InvalidRateLimit {
            reason: "requests_per_second must be positive".to_string(),
        });
    }

    if rps > MAX_RPS {
        return Err(ValidationError::InvalidRateLimit {
            reason: format!("requests_per_second must be <= {}, got {}", MAX_RPS, rps),
        });
    }

    if burst == 0 {
        return Err(ValidationError::InvalidRateLimit {
            reason: "burst must be positive".to_string(),
        });
    }

    if burst > MAX_BURST {
        return Err(ValidationError::InvalidRateLimit {
            reason: format!("burst must be <= {}, got {}", MAX_BURST, burst),
        });
    }

    if burst < rps {
        return Err(ValidationError::InvalidRateLimit {
            reason: format!("burst ({}) must be >= requests_per_second ({})", burst, rps),
        });
    }

    Ok(())
}

/// Validates a WAF rule ID (pattern: [A-Z]{2,5}\d{4,6}).
pub fn validate_rule_id(rule_id: &str) -> ValidationResult<()> {
    if rule_id.is_empty() {
        return Err(ValidationError::InvalidWafConfig {
            reason: "rule ID cannot be empty".to_string(),
        });
    }

    let letter_count = rule_id.chars().take_while(|c| c.is_ascii_uppercase()).count();
    let digit_part = &rule_id[letter_count..];
    let digit_count = digit_part.len();

    if !(2..=5).contains(&letter_count) {
        return Err(ValidationError::InvalidWafConfig {
            reason: format!("rule ID must start with 2-5 uppercase letters, found {}", letter_count),
        });
    }

    if !(4..=6).contains(&digit_count) {
        return Err(ValidationError::InvalidWafConfig {
            reason: format!("rule ID must end with 4-6 digits, found {}", digit_count),
        });
    }

    if !digit_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::InvalidWafConfig {
            reason: "rule ID must end with digits only".to_string(),
        });
    }

    Ok(())
}

/// Checks for path traversal attempts in input.
pub fn check_path_traversal(input: &str) -> ValidationResult<()> {
    let traversal_patterns = ["../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e\\"];
    let input_lower = input.to_lowercase();

    for pattern in &traversal_patterns {
        if input_lower.contains(pattern) {
            return Err(ValidationError::SecurityViolation {
                reason: format!("path traversal detected: '{}'", pattern),
            });
        }
    }

    let sensitive_paths = ["/etc/passwd", "/etc/shadow", "/proc/", "/dev/"];
    for path in &sensitive_paths {
        if input_lower.contains(path) {
            return Err(ValidationError::SecurityViolation {
                reason: format!("access to sensitive path detected: '{}'", path),
            });
        }
    }

    Ok(())
}

/// Checks for shell injection attempts in input.
pub fn check_shell_injection(input: &str) -> ValidationResult<()> {
    let injection_patterns = [";", "&&", "||", "|", "`", "$(", "${", ">", "<"];

    for pattern in &injection_patterns {
        if input.contains(pattern) {
            return Err(ValidationError::SecurityViolation {
                reason: format!("potential shell injection: '{}' character found", pattern),
            });
        }
    }

    let dangerous_commands = ["rm ", "chmod ", "wget ", "curl ", "nc ", "/bin/sh", "/bin/bash"];
    let input_lower = input.to_lowercase();
    for cmd in &dangerous_commands {
        if input_lower.contains(cmd) {
            return Err(ValidationError::SecurityViolation {
                reason: format!("dangerous command detected: '{}'", cmd.trim()),
            });
        }
    }

    Ok(())
}

/// Checks for null byte injection in input.
pub fn check_null_bytes(input: &str) -> ValidationResult<()> {
    if input.contains('\0') {
        return Err(ValidationError::SecurityViolation {
            reason: "null byte detected in input".to_string(),
        });
    }

    if input.to_lowercase().contains("%00") {
        return Err(ValidationError::SecurityViolation {
            reason: "URL-encoded null byte detected in input".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_hostnames() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("www.example.com").is_ok());
        assert!(validate_hostname("api.v2.example.com").is_ok());
        assert!(validate_hostname("*.example.com").is_ok());
        assert!(validate_hostname("server1.example.com").is_ok());
    }

    #[test]
    fn test_invalid_hostnames() {
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("-example.com").is_err());
        assert!(validate_hostname("example-.com").is_err());
        assert!(validate_hostname("example.*.com").is_err());
        assert!(validate_hostname("example_test.com").is_err());
    }

    #[test]
    fn test_valid_upstreams() {
        assert!(validate_upstream("127.0.0.1:8080").is_ok());
        assert!(validate_upstream("backend.local:443").is_ok());
        assert!(validate_upstream("[::1]:8080").is_ok());
    }

    #[test]
    fn test_invalid_upstreams() {
        assert!(validate_upstream("127.0.0.1").is_err());
        assert!(validate_upstream("127.0.0.1:0").is_err());
        assert!(validate_upstream("127.0.0.1:70000").is_err());
        assert!(validate_upstream("127.0.0.1:8080/api").is_err());
    }

    #[test]
    fn test_valid_cidr() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("10.0.0.0/8").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());
    }

    #[test]
    fn test_invalid_cidr() {
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("192.168.1.0").is_err());
        assert!(validate_cidr("not-an-ip/24").is_err());
    }

    #[test]
    fn test_waf_threshold() {
        assert!(validate_waf_threshold(0.0).is_ok());
        assert!(validate_waf_threshold(0.5).is_ok());
        assert!(validate_waf_threshold(1.0).is_ok());
        assert!(validate_waf_threshold(-0.1).is_err());
        assert!(validate_waf_threshold(1.1).is_err());
        assert!(validate_waf_threshold(f64::NAN).is_err());
    }

    #[test]
    fn test_rate_limit() {
        assert!(validate_rate_limit(100, 200).is_ok());
        assert!(validate_rate_limit(100, 100).is_ok());
        assert!(validate_rate_limit(0, 100).is_err());
        assert!(validate_rate_limit(200, 100).is_err());
    }

    #[test]
    fn test_rule_id() {
        assert!(validate_rule_id("XSS1234").is_ok());
        assert!(validate_rule_id("SQLI123456").is_ok());
        assert!(validate_rule_id("X1234").is_err());
        assert!(validate_rule_id("xss1234").is_err());
    }

    #[test]
    fn test_security_checks() {
        assert!(check_path_traversal("safe-input").is_ok());
        assert!(check_path_traversal("../../../etc/passwd").is_err());
        assert!(check_shell_injection("safe-input").is_ok());
        assert!(check_shell_injection("; rm -rf /").is_err());
        assert!(check_null_bytes("safe-input").is_ok());
        assert!(check_null_bytes("file%00.txt").is_err());
    }
}
