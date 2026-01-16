//! Configuration loading and validation for Synapse-Pingora.
//!
//! This module handles YAML configuration parsing with security validations
//! including file size limits, path validation, and schema verification.

use crate::trap::TrapConfig;
use crate::vhost::SiteConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Maximum configuration file size (10MB).
const MAX_CONFIG_SIZE: u64 = 10 * 1024 * 1024;

/// Global server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// HTTP listen address (default: 0.0.0.0:80)
    #[serde(default = "default_http_addr")]
    pub http_addr: String,
    /// HTTPS listen address (default: 0.0.0.0:443)
    #[serde(default = "default_https_addr")]
    pub https_addr: String,
    /// Number of worker threads (0 = auto-detect)
    #[serde(default)]
    pub workers: usize,
    /// Graceful shutdown timeout in seconds
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
    /// Global WAF threshold (0-100)
    #[serde(default = "default_waf_threshold")]
    pub waf_threshold: u8,
    /// Whether WAF is globally enabled
    #[serde(default = "default_true")]
    pub waf_enabled: bool,
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Honeypot trap endpoint configuration
    #[serde(default)]
    pub trap_config: Option<TrapConfig>,
}

fn default_http_addr() -> String {
    "0.0.0.0:80".to_string()
}

fn default_https_addr() -> String {
    "0.0.0.0:443".to_string()
}

fn default_shutdown_timeout() -> u64 {
    30
}

fn default_waf_threshold() -> u8 {
    70
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            http_addr: default_http_addr(),
            https_addr: default_https_addr(),
            workers: 0,
            shutdown_timeout_secs: default_shutdown_timeout(),
            waf_threshold: default_waf_threshold(),
            waf_enabled: true,
            log_level: default_log_level(),
            trap_config: None,
        }
    }
}

/// Rate limiting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second limit
    pub rps: u32,
    /// Whether rate limiting is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Burst capacity (defaults to rps * 2)
    pub burst: Option<u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rps: 10000,
            enabled: true,
            burst: None,
        }
    }
}

/// Upstream backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Backend host
    pub host: String,
    /// Backend port
    pub port: u16,
    /// Weight for load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Whether this backend is healthy
    #[serde(skip)]
    pub healthy: bool,
}

fn default_weight() -> u32 {
    1
}

/// TLS configuration for a site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file (PEM format)
    pub cert_path: String,
    /// Path to private key file (PEM format)
    pub key_path: String,
    /// Minimum TLS version (1.2 or 1.3)
    #[serde(default = "default_min_tls")]
    pub min_version: String,
}

fn default_min_tls() -> String {
    "1.2".to_string()
}

/// Access control configuration for a site.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlConfig {
    /// List of CIDR ranges to allow
    #[serde(default)]
    pub allow: Vec<String>,
    /// List of CIDR ranges to deny
    #[serde(default)]
    pub deny: Vec<String>,
    /// Default action if no rule matches (allow or deny)
    #[serde(default)]
    pub default_action: String,
}

/// Header manipulation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderConfig {
    /// Headers to add/set/remove on the request
    #[serde(default)]
    pub request: HeaderOps,
    /// Headers to add/set/remove on the response
    #[serde(default)]
    pub response: HeaderOps,
}

/// Header operations (add, set, remove).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderOps {
    /// Headers to add (appends if already exists)
    #[serde(default)]
    pub add: std::collections::HashMap<String, String>,
    /// Headers to set (replaces if already exists)
    #[serde(default)]
    pub set: std::collections::HashMap<String, String>,
    /// Headers to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Site-specific WAF configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteWafConfig {
    /// Whether WAF is enabled for this site
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Risk threshold (0-100)
    pub threshold: Option<u8>,
    /// Rule overrides (rule_id -> action)
    #[serde(default)]
    pub rule_overrides: std::collections::HashMap<String, String>,
}

impl Default for SiteWafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: None,
            rule_overrides: std::collections::HashMap::new(),
        }
    }
}

/// Site configuration from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteYamlConfig {
    /// Hostname or wildcard pattern
    pub hostname: String,
    /// Upstream backends
    pub upstreams: Vec<UpstreamConfig>,
    /// TLS configuration (optional)
    pub tls: Option<TlsConfig>,
    /// WAF configuration (optional)
    pub waf: Option<SiteWafConfig>,
    /// Rate limiting configuration (optional)
    pub rate_limit: Option<RateLimitConfig>,
    /// Access control (optional)
    pub access_control: Option<AccessControlConfig>,
    /// Header manipulation (optional)
    pub headers: Option<HeaderConfig>,
}

/// Profiler configuration for endpoint behavior learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilerConfig {
    /// Whether profiling is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of endpoint profiles to maintain
    #[serde(default = "default_max_profiles")]
    pub max_profiles: usize,
    /// Maximum number of learned schemas to maintain
    #[serde(default = "default_max_schemas")]
    pub max_schemas: usize,
    /// Minimum samples required before validating against profile
    #[serde(default = "default_min_samples")]
    pub min_samples_for_validation: u32,
}

fn default_max_profiles() -> usize {
    1000
}

fn default_max_schemas() -> usize {
    500
}

fn default_min_samples() -> u32 {
    100
}

impl Default for ProfilerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_profiles: default_max_profiles(),
            max_schemas: default_max_schemas(),
            min_samples_for_validation: default_min_samples(),
        }
    }
}

/// Complete configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFile {
    /// Global server settings
    #[serde(default)]
    pub server: GlobalConfig,
    /// Site configurations
    pub sites: Vec<SiteYamlConfig>,
    /// Global rate limiting
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// Profiler configuration
    #[serde(default)]
    pub profiler: ProfilerConfig,
}

/// Errors that can occur during configuration loading.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration file not found: {path}")]
    NotFound { path: String },

    #[error("configuration file too large: {size} bytes (max {max} bytes)")]
    FileTooLarge { size: u64, max: u64 },

    #[error("failed to read configuration: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to parse configuration: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("TLS certificate not found: {path}")]
    CertNotFound { path: String },

    #[error("TLS key not found: {path}")]
    KeyNotFound { path: String },

    #[error("duplicate hostname: {hostname}")]
    DuplicateHostname { hostname: String },

    #[error("invalid TLS version: {version} (must be 1.2 or 1.3)")]
    InvalidTlsVersion { version: String },

    #[error("path traversal detected in: {path}")]
    PathTraversal { path: String },
}

/// Check if a path contains path traversal sequences.
///
/// Detects:
/// - Literal `..` sequences
/// - URL-encoded variants: `%2e%2e`, `%2E%2E`, mixed case
/// - Double-URL-encoded: `%252e%252e`
/// - Backslash variants: `..\`, `..\\`
fn contains_path_traversal(path: &str) -> bool {
    // Check literal parent directory reference
    if path.contains("..") {
        return true;
    }

    // Check URL-encoded variants (case-insensitive)
    let path_lower = path.to_lowercase();
    if path_lower.contains("%2e%2e") || path_lower.contains("%2e.") || path_lower.contains(".%2e") {
        return true;
    }

    // Check double-URL-encoded
    if path_lower.contains("%252e") {
        return true;
    }

    // Check for null bytes (path truncation attack)
    if path.contains('\0') || path_lower.contains("%00") {
        return true;
    }

    false
}

/// Configuration loader with security validations.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Loads configuration from a YAML file.
    ///
    /// # Security
    /// - Enforces 10MB file size limit
    /// - Validates TLS certificate/key paths exist
    /// - Checks for path traversal attempts
    /// - Validates hostnames for duplicates
    pub fn load<P: AsRef<Path>>(path: P) -> Result<ConfigFile, ConfigError> {
        let path = path.as_ref();
        info!("Loading configuration from: {}", path.display());

        // Check file exists
        if !path.exists() {
            return Err(ConfigError::NotFound {
                path: path.display().to_string(),
            });
        }

        // Check file size (security: prevent memory exhaustion)
        let metadata = fs::metadata(path)?;
        if metadata.len() > MAX_CONFIG_SIZE {
            return Err(ConfigError::FileTooLarge {
                size: metadata.len(),
                max: MAX_CONFIG_SIZE,
            });
        }

        // Read and parse
        let contents = fs::read_to_string(path)?;
        let config: ConfigFile = serde_yaml::from_str(&contents)?;

        // Validate
        Self::validate(&config)?;

        info!(
            "Loaded configuration with {} sites",
            config.sites.len()
        );
        Ok(config)
    }

    /// Validates the configuration.
    fn validate(config: &ConfigFile) -> Result<(), ConfigError> {
        let mut hostnames = HashSet::new();

        for site in &config.sites {
            // Check for duplicate hostnames
            let normalized = site.hostname.to_lowercase();
            if !hostnames.insert(normalized.clone()) {
                return Err(ConfigError::DuplicateHostname {
                    hostname: site.hostname.clone(),
                });
            }

            // Validate upstreams
            if site.upstreams.is_empty() {
                return Err(ConfigError::ValidationError(format!(
                    "site '{}' has no upstreams configured",
                    site.hostname
                )));
            }

            // Validate TLS configuration
            if let Some(tls) = &site.tls {
                Self::validate_tls(tls)?;
            }

            // Validate WAF threshold
            if let Some(waf) = &site.waf {
                if let Some(threshold) = waf.threshold {
                    if threshold > 100 {
                        return Err(ConfigError::ValidationError(format!(
                            "site '{}' has invalid WAF threshold {} (must be 0-100)",
                            site.hostname, threshold
                        )));
                    }
                }
            }

            // Validate rate limit
            if let Some(rl) = &site.rate_limit {
                if rl.rps == 0 && rl.enabled {
                    warn!(
                        "Site '{}' has rate limiting enabled with 0 RPS",
                        site.hostname
                    );
                }
            }
        }

        // Validate global settings
        if config.server.waf_threshold > 100 {
            return Err(ConfigError::ValidationError(format!(
                "global WAF threshold {} is invalid (must be 0-100)",
                config.server.waf_threshold
            )));
        }

        Ok(())
    }

    /// Validates TLS configuration paths.
    fn validate_tls(tls: &TlsConfig) -> Result<(), ConfigError> {
        // Check for path traversal (including URL-encoded variants)
        if contains_path_traversal(&tls.cert_path) {
            return Err(ConfigError::PathTraversal {
                path: tls.cert_path.clone(),
            });
        }
        if contains_path_traversal(&tls.key_path) {
            return Err(ConfigError::PathTraversal {
                path: tls.key_path.clone(),
            });
        }

        // Check cert exists
        if !Path::new(&tls.cert_path).exists() {
            return Err(ConfigError::CertNotFound {
                path: tls.cert_path.clone(),
            });
        }

        // Check key exists
        if !Path::new(&tls.key_path).exists() {
            return Err(ConfigError::KeyNotFound {
                path: tls.key_path.clone(),
            });
        }

        // Validate TLS version
        match tls.min_version.as_str() {
            "1.2" | "1.3" => {}
            _ => {
                return Err(ConfigError::InvalidTlsVersion {
                    version: tls.min_version.clone(),
                });
            }
        }

        debug!(
            "Validated TLS config: cert={}, key=[REDACTED]",
            tls.cert_path
        );
        Ok(())
    }

    /// Converts YAML site configs to internal SiteConfig format.
    pub fn to_site_configs(config: &ConfigFile) -> Vec<SiteConfig> {
        config
            .sites
            .iter()
            .map(|site| SiteConfig {
                hostname: site.hostname.clone(),
                upstreams: site
                    .upstreams
                    .iter()
                    .map(|u| format!("{}:{}", u.host, u.port))
                    .collect(),
                tls_enabled: site.tls.is_some(),
                tls_cert: site.tls.as_ref().map(|t| t.cert_path.clone()),
                tls_key: site.tls.as_ref().map(|t| t.key_path.clone()),
                waf_threshold: site.waf.as_ref().and_then(|w| w.threshold),
                waf_enabled: site.waf.as_ref().map(|w| w.enabled).unwrap_or(true),
                access_control: site.access_control.clone(),
                headers: site.headers.clone(),
                shadow_mirror: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_load_minimal_config() {
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
"#;
        let file = create_temp_config(yaml);
        let config = ConfigLoader::load(file.path()).unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].hostname, "example.com");
    }

    #[test]
    fn test_load_full_config() {
        let yaml = r#"
server:
  http_addr: "0.0.0.0:8080"
  https_addr: "0.0.0.0:8443"
  workers: 4
  waf_threshold: 80
  log_level: debug

rate_limit:
  rps: 5000
  enabled: true

sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
        weight: 2
    waf:
      enabled: true
      threshold: 60
"#;
        let file = create_temp_config(yaml);
        let config = ConfigLoader::load(file.path()).unwrap();

        assert_eq!(config.server.http_addr, "0.0.0.0:8080");
        assert_eq!(config.server.workers, 4);
        assert_eq!(config.rate_limit.rps, 5000);
        assert_eq!(config.sites[0].waf.as_ref().unwrap().threshold, Some(60));
    }

    #[test]
    fn test_duplicate_hostname() {
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8081
"#;
        let file = create_temp_config(yaml);
        let result = ConfigLoader::load(file.path());
        assert!(matches!(result, Err(ConfigError::DuplicateHostname { .. })));
    }

    #[test]
    fn test_no_upstreams() {
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams: []
"#;
        let file = create_temp_config(yaml);
        let result = ConfigLoader::load(file.path());
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_invalid_waf_threshold() {
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
    waf:
      threshold: 150
"#;
        let file = create_temp_config(yaml);
        let result = ConfigLoader::load(file.path());
        assert!(matches!(result, Err(ConfigError::ValidationError(_))));
    }

    #[test]
    fn test_file_not_found() {
        let result = ConfigLoader::load("/nonexistent/config.yaml");
        assert!(matches!(result, Err(ConfigError::NotFound { .. })));
    }

    #[test]
    fn test_default_values() {
        let config = GlobalConfig::default();
        assert_eq!(config.http_addr, "0.0.0.0:80");
        assert_eq!(config.https_addr, "0.0.0.0:443");
        assert_eq!(config.waf_threshold, 70);
        assert!(config.waf_enabled);
    }

    #[test]
    fn test_to_site_configs() {
        let yaml = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
    waf:
      enabled: true
      threshold: 80
"#;
        let file = create_temp_config(yaml);
        let config = ConfigLoader::load(file.path()).unwrap();
        let sites = ConfigLoader::to_site_configs(&config);

        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].hostname, "example.com");
        assert_eq!(sites[0].waf_threshold, Some(80));
        assert!(sites[0].waf_enabled);
    }

    #[test]
    fn test_path_traversal_detection() {
        use super::contains_path_traversal;

        // Literal parent directory references
        assert!(contains_path_traversal(".."));
        assert!(contains_path_traversal("../etc/passwd"));
        assert!(contains_path_traversal("/path/../secret"));
        assert!(contains_path_traversal("path/to/../../root"));

        // URL-encoded variants
        assert!(contains_path_traversal("%2e%2e"));
        assert!(contains_path_traversal("%2E%2E"));
        assert!(contains_path_traversal("%2e."));
        assert!(contains_path_traversal(".%2e"));

        // Double-URL-encoded
        assert!(contains_path_traversal("%252e%252e"));
        assert!(contains_path_traversal("path/%252e%252e/file"));

        // Null byte injection
        assert!(contains_path_traversal("\x00"));
        assert!(contains_path_traversal("path\x00/file"));
        assert!(contains_path_traversal("%00"));
        assert!(contains_path_traversal("path/%00/file"));

        // Clean paths
        assert!(!contains_path_traversal("/path/to/file"));
        assert!(!contains_path_traversal("certs/server.pem"));
        assert!(!contains_path_traversal("/etc/nginx/ssl/cert.pem"));
        assert!(!contains_path_traversal("./relative/path")); // Single dot is OK
    }
}
