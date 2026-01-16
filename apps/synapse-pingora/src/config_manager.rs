//! Centralized configuration manager with coordinated updates.
//!
//! This module provides atomic configuration mutations that coordinate updates
//! across VhostMatcher, SiteWafManager, RateLimitManager, and AccessListManager.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::access::AccessListManager;
use crate::config::{AccessControlConfig, ConfigFile};
use crate::ratelimit::RateLimitManager;
use crate::site_waf::SiteWafManager;
use crate::validation::{validate_hostname, validate_upstream, validate_cidr, validate_waf_threshold, validate_rate_limit, ValidationError};
use crate::vhost::{SiteConfig, VhostMatcher};

// ─────────────────────────────────────────────────────────────────────────────
// Request Types
// ─────────────────────────────────────────────────────────────────────────────

/// Request to create a new site configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSiteRequest {
    pub hostname: String,
    pub upstreams: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf: Option<SiteWafRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessListRequest>,
}

/// Request to update an existing site configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateSiteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waf: Option<SiteWafRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessListRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shadow_mirror: Option<crate::shadow::ShadowMirrorConfig>,
}

/// WAF configuration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteWafRequest {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_overrides: Option<HashMap<String, bool>>,
}

/// Rate limiting configuration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRequest {
    pub requests_per_second: u64,
    pub burst: u64,
}

/// IP access list configuration request.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessListRequest {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response Types
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a configuration mutation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResult {
    pub applied: bool,
    pub persisted: bool,
    pub rebuild_required: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl MutationResult {
    fn new() -> Self {
        Self {
            applied: false,
            persisted: false,
            rebuild_required: false,
            warnings: Vec::new(),
        }
    }

    fn with_applied(mut self) -> Self {
        self.applied = true;
        self
    }

    fn with_persisted(mut self) -> Self {
        self.persisted = true;
        self
    }

    fn with_rebuild(mut self) -> Self {
        self.rebuild_required = true;
        self
    }

    fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }
}

/// Detailed site configuration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteDetailResponse {
    pub hostname: String,
    pub upstreams: Vec<String>,
    pub tls_enabled: bool,
    pub waf: Option<SiteWafResponse>,
    pub rate_limit: Option<RateLimitResponse>,
    pub access_list: Option<AccessListResponse>,
    pub shadow_mirror: Option<crate::shadow::ShadowMirrorConfig>,
}

/// WAF configuration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteWafResponse {
    pub enabled: bool,
    pub threshold: u8,
    pub rule_overrides: HashMap<String, String>,
}

/// Rate limit configuration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResponse {
    pub requests_per_second: u32,
    pub burst: u32,
}

/// Access list configuration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListResponse {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during configuration operations.
#[derive(Debug, thiserror::Error)]
pub enum ConfigManagerError {
    #[error("site not found: {0}")]
    SiteNotFound(String),

    #[error("site already exists: {0}")]
    SiteExists(String),

    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("persistence error: {0}")]
    Persistence(String),

    #[error("rebuild error: {0}")]
    RebuildError(String),

    #[error("at least one upstream is required")]
    NoUpstreams,
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigManager
// ─────────────────────────────────────────────────────────────────────────────

/// Centralized configuration manager that coordinates updates across all runtime managers.
pub struct ConfigManager {
    config: Arc<RwLock<ConfigFile>>,
    sites: Arc<RwLock<Vec<SiteConfig>>>,
    vhost: Arc<RwLock<VhostMatcher>>,
    waf: Arc<RwLock<SiteWafManager>>,
    rate_limiter: Arc<RwLock<RateLimitManager>>,
    access_lists: Arc<RwLock<AccessListManager>>,
    config_path: Option<PathBuf>,
}

impl ConfigManager {
    /// Creates a new ConfigManager with references to all runtime managers.
    pub fn new(
        config: Arc<RwLock<ConfigFile>>,
        sites: Arc<RwLock<Vec<SiteConfig>>>,
        vhost: Arc<RwLock<VhostMatcher>>,
        waf: Arc<RwLock<SiteWafManager>>,
        rate_limiter: Arc<RwLock<RateLimitManager>>,
        access_lists: Arc<RwLock<AccessListManager>>,
    ) -> Self {
        Self {
            config,
            sites,
            vhost,
            waf,
            rate_limiter,
            access_lists,
            config_path: None,
        }
    }

    /// Enables configuration persistence to the specified file path.
    pub fn with_persistence(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CRUD Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Creates a new site configuration.
    pub fn create_site(&self, req: CreateSiteRequest) -> Result<MutationResult, ConfigManagerError> {
        let mut result = MutationResult::new();

        // Validate hostname
        validate_hostname(&req.hostname)?;

        // Validate upstreams
        if req.upstreams.is_empty() {
            return Err(ConfigManagerError::NoUpstreams);
        }
        for upstream in &req.upstreams {
            validate_upstream(upstream)?;
        }

        // Validate WAF threshold if provided
        if let Some(ref waf) = req.waf {
            if let Some(threshold) = waf.threshold {
                validate_waf_threshold(threshold)?;
            }
        }

        // Validate rate limit if provided
        if let Some(ref rl) = req.rate_limit {
            validate_rate_limit(rl.requests_per_second, rl.burst)?;
        }

        // Validate CIDR in access list if provided
        if let Some(ref al) = req.access_list {
            for cidr in al.allow.iter().chain(al.deny.iter()) {
                validate_cidr(cidr)?;
            }
        }

        // Check for duplicate hostname
        {
            let sites = self.sites.read();
            if sites.iter().any(|s| s.hostname.to_lowercase() == req.hostname.to_lowercase()) {
                return Err(ConfigManagerError::SiteExists(req.hostname.clone()));
            }
        }

        // Build site config
        let site_config = SiteConfig {
            hostname: req.hostname.clone(),
            upstreams: req.upstreams.clone(),
            tls_enabled: false,
            tls_cert: None,
            tls_key: None,
            waf_threshold: req.waf.as_ref().and_then(|w| w.threshold.map(|t| (t * 100.0) as u8)),
            waf_enabled: req.waf.as_ref().map(|w| w.enabled).unwrap_or(true),
            access_control: req.access_list.as_ref().map(|access_list| AccessControlConfig {
                allow: access_list.allow.clone(),
                deny: access_list.deny.clone(),
                default_action: "allow".to_string(),
            }),
            headers: None,
            shadow_mirror: None,
        };

        // Apply changes
        {
            let mut sites = self.sites.write();
            let site_id = sites.len();
            sites.push(site_config);

            // Update managers
            let mut waf = self.waf.write();

            if let Some(waf_req) = &req.waf {
                let rule_overrides = waf_req.rule_overrides.as_ref()
                    .map(|overrides| {
                        overrides.iter().map(|(rule_id, _enabled)| {
                            (rule_id.clone(), crate::site_waf::RuleOverride {
                                rule_id: rule_id.clone(),
                                action: crate::site_waf::WafAction::Block,
                                threshold: None,
                                enabled: *_enabled,
                            })
                        }).collect()
                    })
                    .unwrap_or_default();

                let waf_config = crate::site_waf::SiteWafConfig {
                    enabled: waf_req.enabled,
                    threshold: waf_req.threshold.map(|t| (t * 100.0) as u8).unwrap_or(70),
                    rule_overrides,
                    custom_block_page: None,
                    default_action: crate::site_waf::WafAction::Block,
                };
                waf.add_site(&req.hostname, waf_config);
            }

            if let Some(rl_req) = &req.rate_limit {
                let rl_config = crate::ratelimit::RateLimitConfig {
                    rps: rl_req.requests_per_second as u32,
                    burst: rl_req.burst as u32,
                    enabled: true,
                    window_secs: 1,
                };
                self.rate_limiter.write().add_site(&req.hostname, rl_config);
            }

            if let Some(al_req) = &req.access_list {
                let mut access_list = crate::access::AccessList::allow_all();

                for cidr in &al_req.allow {
                    if let Err(e) = access_list.allow(cidr) {
                        warn!("failed to add allow rule '{}': {}", cidr, e);
                    }
                }

                for cidr in &al_req.deny {
                    if let Err(e) = access_list.deny(cidr) {
                        warn!("failed to add deny rule '{}': {}", cidr, e);
                    }
                }

                self.access_lists.write().add_site(&req.hostname, access_list);
            }

            info!(hostname = %req.hostname, site_id = site_id, "created new site");
        }

        result = result.with_applied();

        // Rebuild VhostMatcher
        self.rebuild_vhost()?;
        result = result.with_rebuild();

        // Persist if enabled
        if self.config_path.is_some() {
            match self.persist_config() {
                Ok(()) => result = result.with_persisted(),
                Err(e) => {
                    result.add_warning(format!("failed to persist config: {}", e));
                    warn!(error = %e, "failed to persist config after create_site");
                }
            }
        }

        Ok(result)
    }

    /// Retrieves detailed information about a site.
    pub fn get_site(&self, hostname: &str) -> Result<SiteDetailResponse, ConfigManagerError> {
        let sites = self.sites.read();
        let waf = self.waf.read();

        let site = sites
            .iter()
            .find(|s| s.hostname.to_lowercase() == hostname.to_lowercase())
            .ok_or_else(|| ConfigManagerError::SiteNotFound(hostname.to_string()))?;

        let waf_config = waf.get_config(hostname);
        let waf_response = Some(SiteWafResponse {
            enabled: waf_config.enabled,
            threshold: waf_config.threshold,
            rule_overrides: waf_config.rule_overrides.iter()
                .map(|(k, v)| (k.clone(), format!("{:?}", v.action)))
                .collect(),
        });

        Ok(SiteDetailResponse {
            hostname: site.hostname.clone(),
            upstreams: site.upstreams.clone(),
            tls_enabled: site.tls_enabled,
            waf: waf_response,
            rate_limit: None,
            access_list: None,
            shadow_mirror: site.shadow_mirror.clone(),
        })
    }

    /// Lists all configured site hostnames.
    pub fn list_sites(&self) -> Vec<String> {
        let sites = self.sites.read();
        sites.iter().map(|s| s.hostname.clone()).collect()
    }

    /// Returns full site info for all sites (for API response).
    pub fn get_sites_info(&self) -> Vec<crate::api::SiteInfo> {
        let sites = self.sites.read();
        sites.iter().map(|s| crate::api::SiteInfo {
            hostname: s.hostname.clone(),
            upstreams: s.upstreams.clone(),
            tls_enabled: s.tls_enabled,
            waf_enabled: s.waf_enabled,
        }).collect()
    }

    /// Updates an existing site configuration.
    pub fn update_site(&self, hostname: &str, req: UpdateSiteRequest) -> Result<MutationResult, ConfigManagerError> {
        let mut result = MutationResult::new();

        // Validate upstreams if provided
        if let Some(ref upstreams) = req.upstreams {
            if upstreams.is_empty() {
                return Err(ConfigManagerError::NoUpstreams);
            }
            for upstream in upstreams {
                validate_upstream(upstream)?;
            }
        }

        // Validate WAF threshold if provided
        if let Some(ref waf) = req.waf {
            if let Some(threshold) = waf.threshold {
                validate_waf_threshold(threshold)?;
            }
        }

        // Validate rate limit if provided
        if let Some(ref rl) = req.rate_limit {
            validate_rate_limit(rl.requests_per_second, rl.burst)?;
        }

        // Validate CIDR in access list if provided
        if let Some(ref al) = req.access_list {
            for cidr in al.allow.iter().chain(al.deny.iter()) {
                validate_cidr(cidr)?;
            }
        }

        // Apply changes
        {
            let mut sites = self.sites.write();
            let mut waf = self.waf.write();

            let (_site_id, site) = sites
                .iter_mut()
                .enumerate()
                .find(|(_, s)| s.hostname.to_lowercase() == hostname.to_lowercase())
                .ok_or_else(|| ConfigManagerError::SiteNotFound(hostname.to_string()))?;

            // Update upstreams
            if let Some(upstreams) = req.upstreams {
                site.upstreams = upstreams;
                debug!(hostname = %hostname, "updated upstreams");
            }

            // Update WAF
            if let Some(waf_req) = req.waf {
                site.waf_enabled = waf_req.enabled;
                site.waf_threshold = waf_req.threshold.map(|t| (t * 100.0) as u8);

                let rule_overrides = waf_req.rule_overrides.as_ref()
                    .map(|overrides| {
                        overrides.iter().map(|(rule_id, _enabled)| {
                            (rule_id.clone(), crate::site_waf::RuleOverride {
                                rule_id: rule_id.clone(),
                                action: crate::site_waf::WafAction::Block,
                                threshold: None,
                                enabled: *_enabled,
                            })
                        }).collect()
                    })
                    .unwrap_or_default();

                if let Some(config) = waf.get_config_mut(hostname) {
                    config.enabled = waf_req.enabled;
                    config.threshold = waf_req.threshold.map(|t| (t * 100.0) as u8).unwrap_or(70);
                    config.rule_overrides = rule_overrides;
                } else {
                    let waf_config = crate::site_waf::SiteWafConfig {
                        enabled: waf_req.enabled,
                        threshold: waf_req.threshold.map(|t| (t * 100.0) as u8).unwrap_or(70),
                        rule_overrides,
                        custom_block_page: None,
                        default_action: crate::site_waf::WafAction::Block,
                    };
                    waf.add_site(hostname, waf_config);
                }
                debug!(hostname = %hostname, "updated WAF config");
            }

            // Update rate limit
            if let Some(rl_req) = req.rate_limit {
                let rl_config = crate::ratelimit::RateLimitConfig {
                    rps: rl_req.requests_per_second as u32,
                    burst: rl_req.burst as u32,
                    enabled: true,
                    window_secs: 1,
                };
                self.rate_limiter.write().add_site(hostname, rl_config);
                debug!(hostname = %hostname, "updated rate limit config");
            }

            // Update access list
            if let Some(al_req) = req.access_list {
                site.access_control = Some(AccessControlConfig {
                    allow: al_req.allow.clone(),
                    deny: al_req.deny.clone(),
                    default_action: "allow".to_string(),
                });
                let mut access_list = crate::access::AccessList::allow_all();

                for cidr in &al_req.allow {
                    if let Err(e) = access_list.allow(cidr) {
                        warn!("failed to add allow rule '{}': {}", cidr, e);
                    }
                }

                for cidr in &al_req.deny {
                    if let Err(e) = access_list.deny(cidr) {
                        warn!("failed to add deny rule '{}': {}", cidr, e);
                    }
                }

                self.access_lists.write().add_site(hostname, access_list);
                debug!(hostname = %hostname, "updated access list config");
            }

            // Update shadow mirror config
            if let Some(shadow_mirror_config) = req.shadow_mirror {
                site.shadow_mirror = Some(shadow_mirror_config);
                debug!(hostname = %hostname, "updated shadow mirror config");
            }

            info!(hostname = %hostname, "updated site configuration");
        }

        result = result.with_applied();

        // Persist if enabled
        if self.config_path.is_some() {
            match self.persist_config() {
                Ok(()) => result = result.with_persisted(),
                Err(e) => {
                    result.add_warning(format!("failed to persist config: {}", e));
                    warn!(error = %e, "failed to persist config after update_site");
                }
            }
        }

        Ok(result)
    }

    /// Deletes a site configuration.
    pub fn delete_site(&self, hostname: &str) -> Result<MutationResult, ConfigManagerError> {
        let mut result = MutationResult::new();

        {
            let mut sites = self.sites.write();

            let _site_id = sites
                .iter()
                .position(|s| s.hostname.to_lowercase() == hostname.to_lowercase())
                .ok_or_else(|| ConfigManagerError::SiteNotFound(hostname.to_string()))?;

            sites.remove(_site_id);
            // Note: WAF, rate_limiter, and access_lists don't have remove_site methods,
            // so they will retain the site configuration but it won't be matched during lookups

            info!(hostname = %hostname, "deleted site");
        }

        result = result.with_applied();

        // Rebuild VhostMatcher
        self.rebuild_vhost()?;
        result = result.with_rebuild();

        // Persist if enabled
        if self.config_path.is_some() {
            match self.persist_config() {
                Ok(()) => result = result.with_persisted(),
                Err(e) => {
                    result.add_warning(format!("failed to persist config: {}", e));
                    warn!(error = %e, "failed to persist config after delete_site");
                }
            }
        }

        Ok(result)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Partial Update Operations
    // ─────────────────────────────────────────────────────────────────────────

    /// Updates only the WAF configuration for a site.
    pub fn update_site_waf(&self, hostname: &str, waf_req: SiteWafRequest) -> Result<MutationResult, ConfigManagerError> {
        self.update_site(hostname, UpdateSiteRequest {
            waf: Some(waf_req),
            ..Default::default()
        })
    }

    /// Updates only the rate limit configuration for a site.
    pub fn update_site_rate_limit(&self, hostname: &str, rate_limit: RateLimitRequest) -> Result<MutationResult, ConfigManagerError> {
        self.update_site(hostname, UpdateSiteRequest {
            rate_limit: Some(rate_limit),
            ..Default::default()
        })
    }

    /// Updates only the access list configuration for a site.
    pub fn update_site_access_list(&self, hostname: &str, access_list: AccessListRequest) -> Result<MutationResult, ConfigManagerError> {
        self.update_site(hostname, UpdateSiteRequest {
            access_list: Some(access_list),
            ..Default::default()
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn rebuild_vhost(&self) -> Result<(), ConfigManagerError> {
        let sites = self.sites.read();
        let new_vhost = VhostMatcher::new(sites.clone())
            .map_err(|e| ConfigManagerError::RebuildError(e.to_string()))?;

        let mut vhost = self.vhost.write();
        *vhost = new_vhost;

        debug!("rebuilt VhostMatcher with {} sites", sites.len());
        Ok(())
    }

    fn persist_config(&self) -> Result<(), ConfigManagerError> {
        let path = self.config_path.as_ref()
            .ok_or_else(|| ConfigManagerError::Persistence("no config path configured".to_string()))?;

        let config = self.config.read();
        let yaml = serde_yaml::to_string(&*config)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to serialize config: {}", e)))?;

        std::fs::write(path, yaml)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to write config: {}", e)))?;

        info!(path = %path.display(), "persisted configuration");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutation_result_builder() {
        let result = MutationResult::new()
            .with_applied()
            .with_rebuild();

        assert!(result.applied);
        assert!(result.rebuild_required);
        assert!(!result.persisted);
    }

    #[test]
    fn test_create_site_request_serialization() {
        let req = CreateSiteRequest {
            hostname: "api.example.com".to_string(),
            upstreams: vec!["10.0.0.1:8080".to_string()],
            waf: Some(SiteWafRequest {
                enabled: true,
                threshold: Some(0.7),
                rule_overrides: None,
            }),
            rate_limit: None,
            access_list: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("api.example.com"));
        assert!(json.contains("10.0.0.1:8080"));
    }

    #[test]
    fn test_update_site_request_default() {
        let req = UpdateSiteRequest::default();
        assert!(req.upstreams.is_none());
        assert!(req.waf.is_none());
        assert!(req.rate_limit.is_none());
        assert!(req.access_list.is_none());
    }

    #[test]
    fn test_site_detail_response_serialization() {
        let response = SiteDetailResponse {
            hostname: "api.example.com".to_string(),
            upstreams: vec!["10.0.0.1:8080".to_string()],
            tls_enabled: false,
            waf: Some(SiteWafResponse {
                enabled: true,
                threshold: 70,
                rule_overrides: HashMap::new(),
            }),
            rate_limit: Some(RateLimitResponse {
                requests_per_second: 100,
                burst: 200,
            }),
            access_list: None,
            shadow_mirror: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("api.example.com"));
        assert!(json.contains("\"threshold\":70"));
    }
}
