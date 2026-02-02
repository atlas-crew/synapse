//! SNI vs Host Header Validation
//!
//! Prevents domain fronting attacks by validating that the TLS SNI (Server Name
//! Indication) matches the HTTP Host header.
//!
//! # Domain Fronting Attack
//!
//! Domain fronting abuses CDNs and reverse proxies by:
//! 1. Setting TLS SNI to an allowlisted domain (e.g., `cdn.example.com`)
//! 2. Setting Host header to a hidden destination (e.g., `malicious.c2.com`)
//! 3. The proxy uses Host for routing, bypassing network-level blocks
//!
//! # Validation Modes
//!
//! - `Strict`: SNI must exactly match Host header (case-insensitive)
//! - `SubdomainAllowed`: SNI can match Host or be a subdomain of Host
//! - `DomainOnly`: Base domains must match (e.g., `api.example.com` matches `example.com`)
//! - `LogOnly`: Log mismatches but don't block (audit mode)
//! - `Disabled`: No validation (not recommended)

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// SNI validation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SniValidationMode {
    /// SNI must exactly match Host header (case-insensitive)
    Strict,
    /// SNI can match Host or be a subdomain of Host
    SubdomainAllowed,
    /// Base domains must match (ignoring subdomains)
    #[default]
    DomainOnly,
    /// Log mismatches but don't block
    LogOnly,
    /// No validation
    Disabled,
}

/// Result of SNI validation
#[derive(Debug, Clone)]
pub struct SniValidationResult {
    /// Whether the validation passed
    pub valid: bool,
    /// The SNI hostname (from TLS handshake)
    pub sni: Option<String>,
    /// The Host header value
    pub host: Option<String>,
    /// Reason for failure (if invalid)
    pub reason: Option<String>,
    /// Validation mode used
    pub mode: SniValidationMode,
}

impl SniValidationResult {
    /// Create a passed result
    pub fn pass(sni: Option<String>, host: Option<String>, mode: SniValidationMode) -> Self {
        Self {
            valid: true,
            sni,
            host,
            reason: None,
            mode,
        }
    }

    /// Create a failed result
    pub fn fail(
        sni: Option<String>,
        host: Option<String>,
        reason: String,
        mode: SniValidationMode,
    ) -> Self {
        Self {
            valid: false,
            sni,
            host,
            reason: Some(reason),
            mode,
        }
    }

    /// Create a skipped result (validation disabled or not applicable)
    pub fn skip(reason: &str) -> Self {
        Self {
            valid: true,
            sni: None,
            host: None,
            reason: Some(reason.to_string()),
            mode: SniValidationMode::Disabled,
        }
    }
}

/// Configuration for SNI validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniValidationConfig {
    /// Whether SNI validation is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Validation mode
    #[serde(default)]
    pub mode: SniValidationMode,
    /// Domains to exclude from validation (e.g., internal health checks)
    #[serde(default)]
    pub excluded_domains: Vec<String>,
    /// Whether to require SNI (block if not present)
    #[serde(default)]
    pub require_sni: bool,
    /// Header name to read SNI from (when TLS is terminated upstream)
    /// Default: "x-tls-sni"
    #[serde(default = "default_sni_header")]
    pub sni_header: String,
}

fn default_sni_header() -> String {
    "x-tls-sni".to_string()
}

impl Default for SniValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: SniValidationMode::DomainOnly,
            excluded_domains: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "health".to_string(),
            ],
            require_sni: false,
            sni_header: default_sni_header(),
        }
    }
}

impl SniValidationConfig {
    /// Get the header name to read SNI from
    pub fn sni_header(&self) -> &str {
        &self.sni_header
    }
}

/// SNI validator
pub struct SniValidator {
    config: SniValidationConfig,
    excluded_domains_lower: Vec<String>,
}

impl SniValidator {
    /// Create a new validator with the given configuration
    pub fn new(config: SniValidationConfig) -> Self {
        let excluded_domains_lower = config
            .excluded_domains
            .iter()
            .map(|d| d.to_lowercase())
            .collect();

        Self {
            config,
            excluded_domains_lower,
        }
    }

    /// Create a disabled validator
    pub fn disabled() -> Self {
        Self::new(SniValidationConfig {
            enabled: false,
            ..Default::default()
        })
    }

    /// Validate SNI against Host header
    ///
    /// # Arguments
    /// * `sni` - SNI hostname from TLS ClientHello (None if not TLS or no SNI)
    /// * `host_header` - Host header from HTTP request (None if not present)
    /// * `is_tls` - Whether the connection is TLS
    pub fn validate(
        &self,
        sni: Option<&str>,
        host_header: Option<&str>,
        is_tls: bool,
    ) -> SniValidationResult {
        // Skip validation if disabled
        if !self.config.enabled {
            return SniValidationResult::skip("validation disabled");
        }

        // Skip validation for non-TLS connections
        if !is_tls {
            return SniValidationResult::skip("not TLS connection");
        }

        let mode = self.config.mode;

        // Log-only mode
        if mode == SniValidationMode::LogOnly {
            if !self.compare_sni_host(sni, host_header, mode) {
                warn!(
                    "SNI/Host mismatch (log only): sni={:?}, host={:?}",
                    sni, host_header
                );
            }
            return SniValidationResult::pass(
                sni.map(String::from),
                host_header.map(String::from),
                mode,
            );
        }

        // Disabled mode
        if mode == SniValidationMode::Disabled {
            return SniValidationResult::skip("mode disabled");
        }

        // Get normalized values
        let sni_lower = sni.map(|s| normalize_hostname(s));
        let host_lower = host_header.map(|h| normalize_hostname(h));

        // Check for excluded domains
        if let Some(ref host) = host_lower {
            if self.is_excluded(host) {
                debug!("Skipping SNI validation for excluded domain: {}", host);
                return SniValidationResult::pass(
                    sni_lower,
                    host_lower,
                    mode,
                );
            }
        }

        // Require SNI if configured
        if self.config.require_sni && sni.is_none() {
            return SniValidationResult::fail(
                None,
                host_lower,
                "SNI required but not present".to_string(),
                mode,
            );
        }

        // If no SNI, allow (unless require_sni is set)
        if sni.is_none() {
            return SniValidationResult::pass(None, host_lower, mode);
        }

        // If no Host header, this is suspicious
        if host_header.is_none() {
            return SniValidationResult::fail(
                sni_lower,
                None,
                "Host header required but not present".to_string(),
                mode,
            );
        }

        // Perform comparison based on mode
        if self.compare_sni_host(sni, host_header, mode) {
            SniValidationResult::pass(sni_lower, host_lower, mode)
        } else {
            SniValidationResult::fail(
                sni_lower,
                host_lower,
                format!(
                    "SNI ({}) does not match Host ({}) in {:?} mode",
                    sni.unwrap_or("none"),
                    host_header.unwrap_or("none"),
                    mode
                ),
                mode,
            )
        }
    }

    /// Compare SNI and Host based on validation mode
    fn compare_sni_host(
        &self,
        sni: Option<&str>,
        host: Option<&str>,
        mode: SniValidationMode,
    ) -> bool {
        let (sni, host) = match (sni, host) {
            (Some(s), Some(h)) => (normalize_hostname(s), normalize_hostname(h)),
            (None, _) | (_, None) => return true, // Already handled above
        };

        match mode {
            SniValidationMode::Strict => sni == host,
            SniValidationMode::SubdomainAllowed => {
                sni == host || sni.ends_with(&format!(".{}", host))
            }
            SniValidationMode::DomainOnly => {
                let sni_base = extract_base_domain(&sni);
                let host_base = extract_base_domain(&host);
                sni_base == host_base
            }
            SniValidationMode::LogOnly | SniValidationMode::Disabled => true,
        }
    }

    /// Check if a domain is in the exclusion list
    fn is_excluded(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.excluded_domains_lower
            .iter()
            .any(|excluded| domain_lower == *excluded || domain_lower.ends_with(&format!(".{}", excluded)))
    }

    /// Get the current configuration
    pub fn config(&self) -> &SniValidationConfig {
        &self.config
    }

    /// Extract SNI from request headers.
    /// Looks for the configured SNI header (default: x-tls-sni).
    pub fn extract_sni_from_headers(&self, headers: &[(String, String)]) -> Option<String> {
        let sni_header_lower = self.config.sni_header.to_lowercase();
        for (name, value) in headers {
            if name.to_lowercase() == sni_header_lower {
                return Some(value.clone());
            }
        }
        None
    }

    /// Validate SNI using headers from a request.
    /// Extracts SNI from the configured header and Host from headers.
    pub fn validate_from_headers(
        &self,
        headers: &[(String, String)],
        is_tls: bool,
    ) -> SniValidationResult {
        let sni = self.extract_sni_from_headers(headers);
        let host = headers
            .iter()
            .find(|(name, _)| name.to_lowercase() == "host")
            .map(|(_, v)| v.as_str());

        self.validate(sni.as_deref(), host, is_tls)
    }
}

/// Normalize a hostname by:
/// - Converting to lowercase
/// - Removing port if present
/// - Trimming whitespace
fn normalize_hostname(hostname: &str) -> String {
    let normalized = hostname.trim().to_lowercase();
    // Remove port if present (e.g., "example.com:443" -> "example.com")
    if let Some(idx) = normalized.find(':') {
        normalized[..idx].to_string()
    } else {
        normalized
    }
}

/// Extract the base domain from a hostname.
/// e.g., "api.sub.example.com" -> "example.com"
/// e.g., "example.co.uk" -> "example.co.uk" (handles common TLDs)
fn extract_base_domain(hostname: &str) -> String {
    let parts: Vec<&str> = hostname.split('.').collect();

    if parts.len() <= 2 {
        return hostname.to_string();
    }

    // Handle common two-part TLDs (co.uk, com.au, etc.)
    let two_part_tlds = [
        "co.uk", "co.nz", "co.jp", "co.kr", "co.za", "co.in",
        "com.au", "com.br", "com.cn", "com.mx", "com.sg",
        "net.au", "net.nz",
        "org.uk", "org.au",
        "gov.uk", "gov.au",
        "ac.uk", "ac.jp",
    ];

    let suffix = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if two_part_tlds.contains(&suffix.as_str()) && parts.len() > 2 {
        // Return domain + two-part TLD
        format!(
            "{}.{}.{}",
            parts[parts.len() - 3],
            parts[parts.len() - 2],
            parts[parts.len() - 1]
        )
    } else {
        // Return last two parts
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_validator() -> SniValidator {
        SniValidator::new(SniValidationConfig::default())
    }

    fn strict_validator() -> SniValidator {
        SniValidator::new(SniValidationConfig {
            enabled: true,
            mode: SniValidationMode::Strict,
            ..Default::default()
        })
    }

    fn subdomain_validator() -> SniValidator {
        SniValidator::new(SniValidationConfig {
            enabled: true,
            mode: SniValidationMode::SubdomainAllowed,
            ..Default::default()
        })
    }

    #[test]
    fn test_disabled_validation() {
        let validator = SniValidator::disabled();
        let result = validator.validate(Some("attacker.com"), Some("victim.com"), true);
        assert!(result.valid);
    }

    #[test]
    fn test_non_tls_skipped() {
        let validator = default_validator();
        let result = validator.validate(Some("example.com"), Some("other.com"), false);
        assert!(result.valid);
        assert!(result.reason.unwrap().contains("not TLS"));
    }

    #[test]
    fn test_strict_mode_exact_match() {
        let validator = strict_validator();

        // Exact match passes
        let result = validator.validate(Some("example.com"), Some("example.com"), true);
        assert!(result.valid);

        // Case-insensitive match passes
        let result = validator.validate(Some("Example.COM"), Some("example.com"), true);
        assert!(result.valid);

        // Subdomain fails in strict mode
        let result = validator.validate(Some("api.example.com"), Some("example.com"), true);
        assert!(!result.valid);
    }

    #[test]
    fn test_subdomain_allowed_mode() {
        let validator = subdomain_validator();

        // Exact match passes
        let result = validator.validate(Some("example.com"), Some("example.com"), true);
        assert!(result.valid);

        // Subdomain of host passes
        let result = validator.validate(Some("api.example.com"), Some("example.com"), true);
        assert!(result.valid);

        // Different domain fails
        let result = validator.validate(Some("api.other.com"), Some("example.com"), true);
        assert!(!result.valid);
    }

    #[test]
    fn test_domain_only_mode() {
        let validator = default_validator(); // DomainOnly is default

        // Same base domain passes
        let result = validator.validate(Some("api.example.com"), Some("www.example.com"), true);
        assert!(result.valid);

        // Different base domain fails
        let result = validator.validate(Some("api.attacker.com"), Some("www.example.com"), true);
        assert!(!result.valid);
    }

    #[test]
    fn test_excluded_domains() {
        let validator = SniValidator::new(SniValidationConfig {
            enabled: true,
            mode: SniValidationMode::Strict,
            excluded_domains: vec!["internal.local".to_string()],
            ..Default::default()
        });

        // Excluded domain skips validation even with mismatch
        let result = validator.validate(Some("other.com"), Some("internal.local"), true);
        assert!(result.valid);
    }

    #[test]
    fn test_port_normalization() {
        let validator = strict_validator();

        // Port is stripped from Host header
        let result = validator.validate(Some("example.com"), Some("example.com:443"), true);
        assert!(result.valid);
    }

    #[test]
    fn test_missing_host_header() {
        let validator = strict_validator();

        let result = validator.validate(Some("example.com"), None, true);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("Host header required"));
    }

    #[test]
    fn test_require_sni() {
        let validator = SniValidator::new(SniValidationConfig {
            enabled: true,
            require_sni: true,
            ..Default::default()
        });

        let result = validator.validate(None, Some("example.com"), true);
        assert!(!result.valid);
        assert!(result.reason.unwrap().contains("SNI required"));
    }

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("api.example.com"), "example.com");
        assert_eq!(
            extract_base_domain("deep.nested.example.com"),
            "example.com"
        );
        assert_eq!(extract_base_domain("example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("api.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn test_domain_fronting_detection() {
        let validator = default_validator();

        // Classic domain fronting: SNI=cdn.example.com, Host=attacker.com
        let result = validator.validate(Some("cdn.example.com"), Some("attacker.com"), true);
        assert!(!result.valid);

        // Legitimate use: different subdomains of same domain
        let result = validator.validate(Some("cdn.example.com"), Some("api.example.com"), true);
        assert!(result.valid);
    }

    #[test]
    fn test_log_only_mode() {
        let validator = SniValidator::new(SniValidationConfig {
            enabled: true,
            mode: SniValidationMode::LogOnly,
            ..Default::default()
        });

        // Log-only mode passes even with mismatch
        let result = validator.validate(Some("attacker.com"), Some("victim.com"), true);
        assert!(result.valid);
    }

    #[test]
    fn test_normalize_hostname() {
        assert_eq!(normalize_hostname("Example.COM"), "example.com");
        assert_eq!(normalize_hostname("example.com:443"), "example.com");
        assert_eq!(normalize_hostname("  example.com  "), "example.com");
    }

    #[test]
    fn test_extract_sni_from_headers() {
        let validator = default_validator();

        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("x-tls-sni".to_string(), "sni.example.com".to_string()),
        ];

        let sni = validator.extract_sni_from_headers(&headers);
        assert_eq!(sni, Some("sni.example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_case_insensitive() {
        let validator = default_validator();

        let headers = vec![
            ("X-TLS-SNI".to_string(), "sni.example.com".to_string()),
        ];

        let sni = validator.extract_sni_from_headers(&headers);
        assert_eq!(sni, Some("sni.example.com".to_string()));
    }

    #[test]
    fn test_validate_from_headers() {
        let validator = default_validator();

        // Matching domains
        let headers = vec![
            ("host".to_string(), "api.example.com".to_string()),
            ("x-tls-sni".to_string(), "www.example.com".to_string()),
        ];
        let result = validator.validate_from_headers(&headers, true);
        assert!(result.valid);

        // Mismatched domains
        let headers = vec![
            ("host".to_string(), "api.example.com".to_string()),
            ("x-tls-sni".to_string(), "attacker.com".to_string()),
        ];
        let result = validator.validate_from_headers(&headers, true);
        assert!(!result.valid);
    }

    #[test]
    fn test_custom_sni_header() {
        let validator = SniValidator::new(SniValidationConfig {
            enabled: true,
            mode: SniValidationMode::Strict,
            sni_header: "x-forwarded-tls-sni".to_string(),
            ..Default::default()
        });

        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("x-forwarded-tls-sni".to_string(), "example.com".to_string()),
        ];

        let sni = validator.extract_sni_from_headers(&headers);
        assert_eq!(sni, Some("example.com".to_string()));
    }
}
