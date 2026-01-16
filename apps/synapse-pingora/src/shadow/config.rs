//! Shadow mirroring configuration.
//!
//! Defines the `ShadowMirrorConfig` struct for per-site shadow mirroring settings.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for shadow mirroring suspicious traffic to honeypots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowMirrorConfig {
    /// Enable shadow mirroring for this site
    #[serde(default)]
    pub enabled: bool,

    /// Minimum risk score to trigger mirroring (default: 40)
    #[serde(default = "default_min_risk_score")]
    pub min_risk_score: f32,

    /// Maximum risk score - above this we block, no need to mirror (default: 70)
    #[serde(default = "default_max_risk_score")]
    pub max_risk_score: f32,

    /// Honeypot/canary endpoint URLs (load balanced)
    #[serde(default)]
    pub honeypot_urls: Vec<String>,

    /// Sampling rate 0.0-1.0 (default: 1.0 = 100%)
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f32,

    /// Per-IP rate limit (requests per minute)
    #[serde(default = "default_per_ip_rate_limit")]
    pub per_ip_rate_limit: u32,

    /// Request timeout for honeypot delivery in seconds (default: 5s)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// HMAC secret for payload signing (prevents honeypot spoofing)
    /// Load from environment variable for security
    #[serde(default)]
    pub hmac_secret: Option<String>,

    /// Include request body in mirror (default: true)
    #[serde(default = "default_include_body")]
    pub include_body: bool,

    /// Maximum body size to mirror in bytes (default: 1MB)
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Additional headers to include in mirror
    #[serde(default = "default_include_headers")]
    pub include_headers: Vec<String>,
}

fn default_min_risk_score() -> f32 {
    40.0
}

fn default_max_risk_score() -> f32 {
    70.0
}

fn default_sampling_rate() -> f32 {
    1.0
}

fn default_per_ip_rate_limit() -> u32 {
    10
}

fn default_timeout_secs() -> u64 {
    5
}

fn default_include_body() -> bool {
    true
}

fn default_max_body_size() -> usize {
    1024 * 1024 // 1MB
}

fn default_include_headers() -> Vec<String> {
    vec![
        "User-Agent".to_string(),
        "Referer".to_string(),
        "Origin".to_string(),
        "Accept".to_string(),
        "Accept-Language".to_string(),
        "Accept-Encoding".to_string(),
    ]
}

impl Default for ShadowMirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_risk_score: default_min_risk_score(),
            max_risk_score: default_max_risk_score(),
            honeypot_urls: Vec::new(),
            sampling_rate: default_sampling_rate(),
            per_ip_rate_limit: default_per_ip_rate_limit(),
            timeout_secs: default_timeout_secs(),
            hmac_secret: None,
            include_body: default_include_body(),
            max_body_size: default_max_body_size(),
            include_headers: default_include_headers(),
        }
    }
}

impl ShadowMirrorConfig {
    /// Returns the timeout as a Duration.
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), ShadowConfigError> {
        if self.enabled && self.honeypot_urls.is_empty() {
            return Err(ShadowConfigError::NoHoneypotUrls);
        }

        if self.min_risk_score >= self.max_risk_score {
            return Err(ShadowConfigError::InvalidRiskRange {
                min: self.min_risk_score,
                max: self.max_risk_score,
            });
        }

        if self.sampling_rate < 0.0 || self.sampling_rate > 1.0 {
            return Err(ShadowConfigError::InvalidSamplingRate(self.sampling_rate));
        }

        // Validate honeypot URLs
        for url in &self.honeypot_urls {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(ShadowConfigError::InvalidHoneypotUrl(url.clone()));
            }
        }

        Ok(())
    }
}

/// Errors from shadow mirror configuration validation.
#[derive(Debug, thiserror::Error)]
pub enum ShadowConfigError {
    #[error("shadow mirroring enabled but no honeypot URLs configured")]
    NoHoneypotUrls,

    #[error("invalid risk score range: min ({min}) must be less than max ({max})")]
    InvalidRiskRange { min: f32, max: f32 },

    #[error("invalid sampling rate: {0} (must be 0.0-1.0)")]
    InvalidSamplingRate(f32),

    #[error("invalid honeypot URL: {0} (must start with http:// or https://)")]
    InvalidHoneypotUrl(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ShadowMirrorConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.min_risk_score, 40.0);
        assert_eq!(config.max_risk_score, 70.0);
        assert_eq!(config.sampling_rate, 1.0);
        assert_eq!(config.per_ip_rate_limit, 10);
        assert!(config.include_body);
    }

    #[test]
    fn test_validate_disabled_without_urls() {
        let config = ShadowMirrorConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_enabled_without_urls() {
        let mut config = ShadowMirrorConfig::default();
        config.enabled = true;
        assert!(matches!(
            config.validate(),
            Err(ShadowConfigError::NoHoneypotUrls)
        ));
    }

    #[test]
    fn test_validate_invalid_risk_range() {
        let mut config = ShadowMirrorConfig::default();
        config.min_risk_score = 70.0;
        config.max_risk_score = 40.0;
        assert!(matches!(
            config.validate(),
            Err(ShadowConfigError::InvalidRiskRange { .. })
        ));
    }

    #[test]
    fn test_validate_invalid_sampling_rate() {
        let mut config = ShadowMirrorConfig::default();
        config.sampling_rate = 1.5;
        assert!(matches!(
            config.validate(),
            Err(ShadowConfigError::InvalidSamplingRate(_))
        ));
    }

    #[test]
    fn test_validate_invalid_honeypot_url() {
        let mut config = ShadowMirrorConfig::default();
        config.enabled = true;
        config.honeypot_urls = vec!["not-a-url".to_string()];
        assert!(matches!(
            config.validate(),
            Err(ShadowConfigError::InvalidHoneypotUrl(_))
        ));
    }

    #[test]
    fn test_validate_valid_config() {
        let mut config = ShadowMirrorConfig::default();
        config.enabled = true;
        config.honeypot_urls = vec!["https://honeypot.example.com/mirror".to_string()];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timeout_duration() {
        let config = ShadowMirrorConfig::default();
        assert_eq!(config.timeout(), Duration::from_secs(5));
    }
}
