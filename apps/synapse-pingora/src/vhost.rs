//! Virtual host matching for multi-site routing.
//!
//! This module provides hostname-based routing with support for exact matches
//! and wildcard patterns (e.g., `*.example.com`).

use std::collections::HashMap;
use regex::Regex;
use tracing::{debug, warn};

/// Configuration for a single virtual host site.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Hostname pattern (exact or wildcard like `*.example.com`)
    pub hostname: String,
    /// Upstream backend addresses
    pub upstreams: Vec<String>,
    /// Whether TLS is enabled for this site
    pub tls_enabled: bool,
    /// Path to TLS certificate (if TLS enabled)
    pub tls_cert: Option<String>,
    /// Path to TLS private key (if TLS enabled)
    pub tls_key: Option<String>,
    /// WAF threshold override (0-100, None uses global default)
    pub waf_threshold: Option<u8>,
    /// Whether WAF is enabled for this site
    pub waf_enabled: bool,
}

impl Default for SiteConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            upstreams: Vec::new(),
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            waf_threshold: None,
            waf_enabled: true,
        }
    }
}

/// Compiled wildcard pattern for hostname matching.
#[derive(Debug)]
struct WildcardPattern {
    /// Original pattern string
    pattern: String,
    /// Compiled regex for matching
    regex: Regex,
    /// Reference to site config
    site_index: usize,
}

/// Virtual host matcher with O(1) exact matching and wildcard fallback.
///
/// Security features:
/// - Limits wildcard complexity (max 3 wildcards, 253 char limit)
/// - Sanitizes host headers (rejects null bytes, invalid chars)
/// - Case-insensitive matching via pre-normalization
#[derive(Debug)]
pub struct VhostMatcher {
    /// Exact hostname -> site index mapping (O(1) lookup)
    exact_matches: HashMap<String, usize>,
    /// Wildcard patterns checked in order
    wildcard_patterns: Vec<WildcardPattern>,
    /// All site configurations
    sites: Vec<SiteConfig>,
    /// Default site index (if any)
    default_site: Option<usize>,
}

impl VhostMatcher {
    /// Maximum allowed wildcards in a pattern (prevents ReDoS).
    const MAX_WILDCARDS: usize = 3;
    /// Maximum hostname length per RFC 1035.
    const MAX_HOSTNAME_LEN: usize = 253;

    /// Creates a new VhostMatcher from site configurations.
    ///
    /// # Errors
    /// Returns an error if:
    /// - A wildcard pattern has too many wildcards
    /// - A hostname exceeds the maximum length
    /// - A wildcard pattern fails to compile
    pub fn new(sites: Vec<SiteConfig>) -> Result<Self, VhostError> {
        let mut exact_matches = HashMap::new();
        let mut wildcard_patterns = Vec::new();
        let mut default_site = None;

        for (index, site) in sites.iter().enumerate() {
            // Validate hostname length
            if site.hostname.len() > Self::MAX_HOSTNAME_LEN {
                return Err(VhostError::HostnameTooLong {
                    hostname: site.hostname.clone(),
                    max_len: Self::MAX_HOSTNAME_LEN,
                });
            }

            // Normalize hostname to lowercase
            let normalized = site.hostname.to_lowercase();

            // Check if this is a wildcard pattern
            if normalized.contains('*') {
                // Validate wildcard count
                let wildcard_count = normalized.matches('*').count();
                if wildcard_count > Self::MAX_WILDCARDS {
                    return Err(VhostError::TooManyWildcards {
                        pattern: site.hostname.clone(),
                        count: wildcard_count,
                        max: Self::MAX_WILDCARDS,
                    });
                }

                // Convert wildcard pattern to regex
                let regex_pattern = Self::wildcard_to_regex(&normalized);
                let regex = Regex::new(&regex_pattern).map_err(|e| VhostError::InvalidPattern {
                    pattern: site.hostname.clone(),
                    reason: e.to_string(),
                })?;

                wildcard_patterns.push(WildcardPattern {
                    pattern: normalized,
                    regex,
                    site_index: index,
                });
            } else if normalized == "_" || normalized == "default" {
                // Special default site marker
                default_site = Some(index);
            } else {
                // Exact match
                exact_matches.insert(normalized, index);
            }
        }

        // Sort wildcards by specificity (more specific patterns first)
        wildcard_patterns.sort_by(|a, b| {
            // More segments = more specific
            let a_segments = a.pattern.matches('.').count();
            let b_segments = b.pattern.matches('.').count();
            b_segments.cmp(&a_segments)
        });

        Ok(Self {
            exact_matches,
            wildcard_patterns,
            sites,
            default_site,
        })
    }

    /// Converts a wildcard pattern to a regex pattern.
    fn wildcard_to_regex(pattern: &str) -> String {
        let mut regex = String::from("^");
        for ch in pattern.chars() {
            match ch {
                '*' => regex.push_str("[a-z0-9-]*"),
                '.' => regex.push_str("\\."),
                '-' => regex.push('-'),
                c if c.is_ascii_alphanumeric() => regex.push(c),
                _ => regex.push_str(&regex::escape(&ch.to_string())),
            }
        }
        regex.push('$');
        regex
    }

    /// Sanitizes and validates a host header value.
    ///
    /// # Security
    /// - Rejects null bytes
    /// - Rejects non-ASCII characters
    /// - Strips port numbers
    /// - Normalizes to lowercase
    pub fn sanitize_host(host: &str) -> Result<String, VhostError> {
        // Reject null bytes (potential injection)
        if host.contains('\0') {
            return Err(VhostError::InvalidHost {
                host: host.to_string(),
                reason: "contains null byte".to_string(),
            });
        }

        // Reject non-printable or non-ASCII characters
        if !host.chars().all(|c| c.is_ascii() && !c.is_control()) {
            return Err(VhostError::InvalidHost {
                host: host.to_string(),
                reason: "contains invalid characters".to_string(),
            });
        }

        // Strip port number if present
        let hostname = host.split(':').next().unwrap_or(host);

        // Validate hostname characters (RFC 1123)
        if !hostname.is_empty() && !Self::is_valid_hostname(hostname) {
            return Err(VhostError::InvalidHost {
                host: host.to_string(),
                reason: "invalid hostname characters".to_string(),
            });
        }

        Ok(hostname.to_lowercase())
    }

    /// Validates that a hostname contains only valid DNS characters.
    fn is_valid_hostname(hostname: &str) -> bool {
        hostname.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '.'
        }) && !hostname.starts_with('-') && !hostname.ends_with('-')
    }

    /// Matches a host header to a site configuration.
    ///
    /// # Arguments
    /// * `host` - The raw Host header value
    ///
    /// # Returns
    /// The matching site configuration, or None if no match found.
    pub fn match_host(&self, host: &str) -> Option<&SiteConfig> {
        // Sanitize the host header
        let hostname = match Self::sanitize_host(host) {
            Ok(h) => h,
            Err(e) => {
                warn!("Invalid host header: {}", e);
                return self.default_site.map(|i| &self.sites[i]);
            }
        };

        // Try exact match first (O(1))
        if let Some(&index) = self.exact_matches.get(&hostname) {
            debug!("Exact match for host '{}' -> site {}", hostname, index);
            return Some(&self.sites[index]);
        }

        // Try wildcard patterns (O(n) where n = wildcard count)
        for pattern in &self.wildcard_patterns {
            if pattern.regex.is_match(&hostname) {
                debug!(
                    "Wildcard match for host '{}' -> pattern '{}' -> site {}",
                    hostname, pattern.pattern, pattern.site_index
                );
                return Some(&self.sites[pattern.site_index]);
            }
        }

        // Fall back to default site
        if let Some(index) = self.default_site {
            debug!("Using default site for host '{}'", hostname);
            return Some(&self.sites[index]);
        }

        debug!("No match found for host '{}'", hostname);
        None
    }

    /// Returns all configured sites.
    pub fn sites(&self) -> &[SiteConfig] {
        &self.sites
    }

    /// Returns the number of configured sites.
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }
}

/// Errors that can occur during vhost matching.
#[derive(Debug, thiserror::Error)]
pub enum VhostError {
    #[error("hostname '{hostname}' exceeds maximum length of {max_len}")]
    HostnameTooLong { hostname: String, max_len: usize },

    #[error("pattern '{pattern}' has {count} wildcards, max is {max}")]
    TooManyWildcards { pattern: String, count: usize, max: usize },

    #[error("invalid pattern '{pattern}': {reason}")]
    InvalidPattern { pattern: String, reason: String },

    #[error("invalid host header '{host}': {reason}")]
    InvalidHost { host: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_site(hostname: &str) -> SiteConfig {
        SiteConfig {
            hostname: hostname.to_string(),
            upstreams: vec!["127.0.0.1:8080".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_exact_match() {
        let sites = vec![
            make_site("example.com"),
            make_site("api.example.com"),
        ];
        let matcher = VhostMatcher::new(sites).unwrap();

        assert!(matcher.match_host("example.com").is_some());
        assert!(matcher.match_host("api.example.com").is_some());
        assert!(matcher.match_host("other.com").is_none());
    }

    #[test]
    fn test_case_insensitive() {
        let sites = vec![make_site("Example.COM")];
        let matcher = VhostMatcher::new(sites).unwrap();

        assert!(matcher.match_host("example.com").is_some());
        assert!(matcher.match_host("EXAMPLE.COM").is_some());
        assert!(matcher.match_host("Example.Com").is_some());
    }

    #[test]
    fn test_wildcard_match() {
        let sites = vec![
            make_site("*.example.com"),
            make_site("example.com"),
        ];
        let matcher = VhostMatcher::new(sites).unwrap();

        assert!(matcher.match_host("example.com").is_some());
        assert!(matcher.match_host("api.example.com").is_some());
        assert!(matcher.match_host("www.example.com").is_some());
        assert!(matcher.match_host("other.com").is_none());
    }

    #[test]
    fn test_port_stripping() {
        let sites = vec![make_site("example.com")];
        let matcher = VhostMatcher::new(sites).unwrap();

        assert!(matcher.match_host("example.com:8080").is_some());
        assert!(matcher.match_host("example.com:443").is_some());
    }

    #[test]
    fn test_default_site() {
        let sites = vec![
            make_site("example.com"),
            make_site("_"),
        ];
        let matcher = VhostMatcher::new(sites).unwrap();

        assert!(matcher.match_host("example.com").is_some());
        assert!(matcher.match_host("unknown.com").is_some()); // Falls back to default
    }

    #[test]
    fn test_sanitize_null_byte() {
        let result = VhostMatcher::sanitize_host("example\0.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_non_ascii() {
        let result = VhostMatcher::sanitize_host("例え.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_too_many_wildcards() {
        let sites = vec![make_site("*.*.*.*")];
        let result = VhostMatcher::new(sites);
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_too_long() {
        let long_hostname = "a".repeat(300);
        let sites = vec![make_site(&long_hostname)];
        let result = VhostMatcher::new(sites);
        assert!(result.is_err());
    }

    #[test]
    fn test_wildcard_specificity() {
        let sites = vec![
            make_site("*.example.com"),
            make_site("*.api.example.com"),
        ];
        let matcher = VhostMatcher::new(sites).unwrap();

        // More specific pattern should match first
        let site = matcher.match_host("v1.api.example.com").unwrap();
        assert_eq!(site.hostname, "*.api.example.com");
    }
}
