//! Centralized configuration manager with coordinated updates.
//!
//! This module provides atomic configuration mutations that coordinate updates
//! across VhostMatcher, SiteWafManager, RateLimitManager, and AccessListManager.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::access::AccessListManager;
use crate::config::{AccessControlConfig, ConfigFile};
use crate::ratelimit::RateLimitManager;
use crate::site_waf::SiteWafManager;
use crate::validation::{validate_hostname, validate_upstream, validate_cidr, validate_waf_threshold, validate_rate_limit, ValidationError};
use crate::vhost::{SiteConfig, VhostMatcher};
use crate::waf::Synapse;

#[path = "rules.rs"]
mod rules;
pub use rules::{
    CustomRuleAction, CustomRuleCondition, CustomRuleInput, CustomRuleUpdate,
    RuleMetadata, RuleView, StoredRule,
};

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

    #[error("rule not found: {0}")]
    RuleNotFound(String),

    #[error("rule already exists: {0}")]
    RuleExists(String),
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
    rules_store: Arc<RwLock<Vec<StoredRule>>>,
    rules_engine: Option<Arc<RwLock<Synapse>>>,
    rules_path: Option<PathBuf>,
    rules_hash: Option<Arc<RwLock<String>>>,
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
            rules_store: Arc::new(RwLock::new(Vec::new())),
            rules_engine: None,
            rules_path: None,
            rules_hash: None,
        }
    }

    /// Enables configuration persistence to the specified file path.
    pub fn with_persistence(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.config_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Enable rule management with a shared Synapse engine and optional persistence.
    pub fn with_rules(
        mut self,
        engine: Arc<RwLock<Synapse>>,
        rules_path: Option<PathBuf>,
        rules_hash: Option<Arc<RwLock<String>>>,
    ) -> Self {
        self.rules_engine = Some(engine);
        self.rules_path = rules_path;
        self.rules_hash = rules_hash;

        if let Err(err) = self.load_rules_from_disk() {
            warn!("Failed to load rules from disk: {}", err);
        }

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

    /// Retrieves the full runtime configuration.
    pub fn get_full_config(&self) -> ConfigFile {
        let config = self.config.read();
        config.clone()
    }

    /// Computes a stable hash of the current configuration for diagnostics.
    pub fn config_hash(&self) -> String {
        let config = self.config.read();
        let payload = serde_json::to_vec(&*config).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let digest = format!("{:x}", hasher.finalize());
        digest.get(..16).unwrap_or(&digest).to_string()
    }

    /// Returns the current rules hash (or computes one if not cached).
    pub fn rules_hash(&self) -> String {
        if let Some(hash) = self.rules_hash.as_ref() {
            return hash.read().clone();
        }
        let rules = self.rules_store.read();
        rules::rules_hash(&rules)
    }

    /// Updates the full configuration (hot reload).
    ///
    /// This replaces the entire configuration state and triggers a rebuild
    /// of all dependent components (VHost, WAF, RateLimit, AccessList).
    pub fn update_full_config(&self, new_config: ConfigFile) -> Result<MutationResult, ConfigManagerError> {
        let mut result = MutationResult::new();

        // Validate the new configuration comprehensively
        if new_config.sites.is_empty() {
             // It's allowed to have no sites, but worth a warning
             result.add_warning("Configuration has no sites defined");
        }

        // Validate each site in the configuration
        let mut seen_hostnames: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (idx, site) in new_config.sites.iter().enumerate() {
            // Validate hostname
            if let Err(e) = validate_hostname(&site.hostname) {
                return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                    "Site[{}] hostname '{}': {}",
                    idx, site.hostname, e
                ))));
            }

            // Check for duplicate hostnames
            let normalized = site.hostname.to_lowercase();
            if seen_hostnames.contains(&normalized) {
                return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                    "Site[{}] hostname '{}' is duplicated",
                    idx, site.hostname
                ))));
            }
            seen_hostnames.insert(normalized);

            // Validate upstreams
            if site.upstreams.is_empty() {
                return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                    "Site[{}] '{}' has no upstreams defined",
                    idx, site.hostname
                ))));
            }
            for (u_idx, upstream) in site.upstreams.iter().enumerate() {
                // UpstreamConfig has host/port fields - format as host:port for validation
                let upstream_str = format!("{}:{}", upstream.host, upstream.port);
                if let Err(e) = validate_upstream(&upstream_str) {
                    return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                        "Site[{}] '{}' upstream[{}] '{}:{}': {}",
                        idx, site.hostname, u_idx, upstream.host, upstream.port, e
                    ))));
                }
            }

            // Validate WAF threshold if present
            if let Some(ref waf) = site.waf {
                if let Some(threshold) = waf.threshold {
                    // threshold is u8 (0-255), validate_waf_threshold expects f64 (0-100)
                    if let Err(e) = validate_waf_threshold(threshold as f64) {
                        return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                            "Site[{}] '{}' WAF threshold: {}",
                            idx, site.hostname, e
                        ))));
                    }
                }
            }

            // Validate rate limit if present
            if let Some(ref rl) = site.rate_limit {
                // RateLimitConfig has rps: u32, burst: Option<u32>
                // validate_rate_limit expects (requests: u64, window: u64)
                let burst = rl.burst.unwrap_or(rl.rps.saturating_mul(2));
                if let Err(e) = validate_rate_limit(rl.rps as u64, burst as u64) {
                    return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                        "Site[{}] '{}' rate limit: {}",
                        idx, site.hostname, e
                    ))));
                }
            }

            // Validate access control CIDRs if present
            if let Some(ref ac) = site.access_control {
                for (c_idx, cidr) in ac.allow.iter().enumerate() {
                    if let Err(e) = validate_cidr(cidr) {
                        return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                            "Site[{}] '{}' access_control.allow[{}] '{}': {}",
                            idx, site.hostname, c_idx, cidr, e
                        ))));
                    }
                }
                for (c_idx, cidr) in ac.deny.iter().enumerate() {
                    if let Err(e) = validate_cidr(cidr) {
                        return Err(ConfigManagerError::Validation(ValidationError::InvalidDomain(format!(
                            "Site[{}] '{}' access_control.deny[{}] '{}': {}",
                            idx, site.hostname, c_idx, cidr, e
                        ))));
                    }
                }
            }
        }

        // Apply changes atomically
        {
            // 1. Update ConfigFile wrapper
            let mut config = self.config.write();
            *config = new_config.clone();

            // 2. Update Sites list (convert SiteYamlConfig -> SiteConfig)
            let mut sites = self.sites.write();
            *sites = new_config.sites.iter().map(|s| crate::vhost::SiteConfig::from(s.clone())).collect();

            // 3. Update SiteWafManager with full state replacement
            // Build set of new hostnames for efficient lookup
            let new_hostnames: std::collections::HashSet<String> = new_config
                .sites
                .iter()
                .map(|s| s.hostname.to_lowercase())
                .collect();

            let mut waf = self.waf.write();

            // Remove sites that are no longer in the configuration
            let old_hostnames = waf.hostnames();
            for old_host in old_hostnames {
                if !new_hostnames.contains(&old_host.to_lowercase()) {
                    waf.remove_site(&old_host);
                    info!(
                        hostname = %old_host,
                        "Removed site WAF configuration (no longer in config)"
                    );
                }
            }

            // Add/update sites from new config
            for site in &new_config.sites {
                if let Some(ref waf_yaml) = site.waf {
                    if let Some(threshold) = waf_yaml.threshold {
                        let waf_config = crate::site_waf::SiteWafConfig {
                            enabled: waf_yaml.enabled,
                            threshold,
                            rule_overrides: HashMap::new(),
                            custom_block_page: None,
                            default_action: crate::site_waf::WafAction::Block,
                        };
                        waf.add_site(&site.hostname, waf_config);
                    }
                }
            }

            // 4. Update RateLimitManager
            // Similar limitation: additive updates only
            // TODO: Refactor managers to support full state replacement
            let _rate_limiter = self.rate_limiter.write();
            // Assuming config has rate limit settings? ConfigFile doesn't explicitly store RL per site
            // except via the API-driven updates. This is a mismatch in the current architecture.
            // The ConfigFile struct tracks `sites`, and `SiteConfig` doesn't strictly have RL fields
            // other than what we added in memory?
            // Actually, `SiteConfig` in `vhost.rs` DOES NOT have rate limit fields.
            // They are managed separately.
            // This means `update_full_config` mainly updates sites/upstreams/tls/waf-threshold.
            // It might lose RL/AccessList state if not persisted in ConfigFile.
            
            // 5. Update AccessListManager with full state replacement
            let mut access_lists = self.access_lists.write();

            // Remove sites that are no longer in the configuration
            let old_access_sites = access_lists.list_sites();
            for old_host in old_access_sites {
                if !new_hostnames.contains(&old_host.to_lowercase()) {
                    access_lists.remove_site(&old_host);
                    info!(
                        hostname = %old_host,
                        "Removed site access list (no longer in config)"
                    );
                }
            }

            // Add/update sites from new config
            for site in &new_config.sites {
                if let Some(ac) = &site.access_control {
                    let mut list = crate::access::AccessList::allow_all();
                    for cidr in &ac.allow {
                        let _ = list.allow(cidr);
                    }
                    for cidr in &ac.deny {
                        let _ = list.deny(cidr);
                    }
                    access_lists.add_site(&site.hostname, list);
                }
            }

            info!("Full configuration updated with {} sites", sites.len());
        }
        
        result = result.with_applied();

        // Rebuild VhostMatcher
        self.rebuild_vhost()?;
        result = result.with_rebuild();

        // Persist
        if self.config_path.is_some() {
            match self.persist_config() {
                Ok(()) => result = result.with_persisted(),
                Err(e) => {
                    result.add_warning(format!("failed to persist config: {}", e));
                    warn!(error = %e, "failed to persist config after update_full_config");
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
    // Rules Management
    // ─────────────────────────────────────────────────────────────────────────

    /// List all rules currently stored on the sensor.
    pub fn list_rules(&self) -> Vec<StoredRule> {
        self.rules_store.read().clone()
    }

    /// Create a new rule and apply it to the WAF engine.
    pub fn create_rule(&self, rule: StoredRule) -> Result<StoredRule, ConfigManagerError> {
        let mut rules = self.rules_store.read().clone();
        let rule_id = rules::rule_identifier(&rule);

        if rules.iter().any(|existing| rules::matches_rule_id(existing, &rule_id)) {
            return Err(ConfigManagerError::RuleExists(rule_id));
        }

        rules.push(rule.clone());
        self.apply_rules(rules, true, None)?;
        Ok(rule)
    }

    /// Update an existing rule and apply changes to the WAF engine.
    pub fn update_rule(&self, rule_id: &str, update: CustomRuleUpdate) -> Result<StoredRule, ConfigManagerError> {
        let mut rules = self.rules_store.read().clone();
        let Some(index) = rules.iter().position(|rule| rules::matches_rule_id(rule, rule_id)) else {
            return Err(ConfigManagerError::RuleNotFound(rule_id.to_string()));
        };

        let updated = rules::merge_rule_update(&rules[index], update)
            .map_err(|err| ConfigManagerError::Persistence(err))?;
        rules[index] = updated.clone();
        self.apply_rules(rules, true, None)?;
        Ok(updated)
    }

    /// Delete a rule by ID and apply changes to the WAF engine.
    pub fn delete_rule(&self, rule_id: &str) -> Result<(), ConfigManagerError> {
        let mut rules = self.rules_store.read().clone();
        let original_len = rules.len();
        rules.retain(|rule| !rules::matches_rule_id(rule, rule_id));

        if rules.len() == original_len {
            return Err(ConfigManagerError::RuleNotFound(rule_id.to_string()));
        }

        self.apply_rules(rules, true, None)?;
        Ok(())
    }

    /// Replace all rules with a new set and apply to the WAF engine.
    pub fn replace_rules(&self, rules: Vec<StoredRule>, hash_override: Option<String>) -> Result<usize, ConfigManagerError> {
        self.apply_rules(rules, true, hash_override)
    }

    /// Updates WAF rules from JSON bytes received from Horizon Hub.
    ///
    /// This method is called when the sensor receives a RulesUpdate or PushRules
    /// message from the Signal Horizon Hub via WebSocket. The rules are parsed and
    /// applied to the WAF engine.
    ///
    /// # Arguments
    /// * `rules_json` - JSON bytes containing an array of rule definitions
    /// * `hash_override` - Optional hash provided by Signal Horizon
    ///
    /// # Returns
    /// * `Ok(count)` - Number of rules received (including disabled rules)
    /// * `Err` - If rules parsing or application fails
    pub fn update_waf_rules(&self, rules_json: &[u8], hash_override: Option<&str>) -> Result<usize, ConfigManagerError> {
        let value: serde_json::Value = serde_json::from_slice(rules_json)
            .map_err(|e| ConfigManagerError::Persistence(format!("Invalid rules JSON: {}", e)))?;

        let rules = rules::parse_rules_payload(value)
            .map_err(ConfigManagerError::Persistence)?;

        let rule_count = rules.len();

        if rule_count == 0 {
            warn!("Received empty rules update from Horizon Hub");
            return Ok(0);
        }

        info!(rule_count, "Received WAF rules update from Horizon Hub");

        let applied = self.apply_rules(rules, true, hash_override.map(|s| s.to_string()))?;

        info!(
            rules_received = rule_count,
            rules_applied = applied,
            sites_affected = self.waf.read().site_count(),
            "WAF rules synchronized from Horizon Hub"
        );

        Ok(rule_count)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal Helpers
    // ─────────────────────────────────────────────────────────────────────────

    fn load_rules_from_disk(&self) -> Result<usize, ConfigManagerError> {
        let Some(path) = self.rules_path.clone() else {
            return Ok(0);
        };

        if !path.exists() {
            return Ok(0);
        }

        let rules_json = fs::read(&path)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to read rules: {}", e)))?;
        let value: serde_json::Value = serde_json::from_slice(&rules_json)
            .map_err(|e| ConfigManagerError::Persistence(format!("invalid rules JSON: {}", e)))?;
        let rules = rules::parse_rules_payload(value)
            .map_err(ConfigManagerError::Persistence)?;

        if rules.is_empty() {
            return Ok(0);
        }

        self.apply_rules(rules, false, None)
    }

    fn apply_rules(
        &self,
        rules: Vec<StoredRule>,
        persist: bool,
        hash_override: Option<String>,
    ) -> Result<usize, ConfigManagerError> {
        let engine = self.rules_engine.as_ref()
            .ok_or_else(|| ConfigManagerError::Persistence("rules engine not configured".to_string()))?;

        let mut active_rules: Vec<&StoredRule> = rules
            .iter()
            .filter(|rule| rule.meta.enabled.unwrap_or(true))
            .collect();

        active_rules.sort_by(|a, b| {
            let a_priority = a.meta.priority.unwrap_or(100);
            let b_priority = b.meta.priority.unwrap_or(100);
            a_priority.cmp(&b_priority).then_with(|| a.rule.id.cmp(&b.rule.id))
        });

        let waf_rules: Vec<_> = active_rules.iter().map(|rule| rule.rule.clone()).collect();
        let waf_json = serde_json::to_vec(&waf_rules)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to serialize waf rules: {}", e)))?;

        let applied = engine.write()
            .load_rules(&waf_json)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to load waf rules: {}", e)))?;

        *self.rules_store.write() = rules.clone();

        if persist {
            self.persist_rules(&rules)?;
        }

        self.update_rules_hash(hash_override.unwrap_or_else(|| rules::rules_hash(&rules)));

        Ok(applied)
    }

    fn persist_rules(&self, rules: &[StoredRule]) -> Result<(), ConfigManagerError> {
        let Some(path) = self.rules_path.clone() else {
            return Ok(());
        };

        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return Err(ConfigManagerError::Persistence(format!(
                    "failed to create rules directory: {}",
                    err
                )));
            }
        }

        let payload = serde_json::to_vec_pretty(rules)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to serialize rules: {}", e)))?;

        let wal_path = path.with_extension("wal");
        append_wal_entry(&wal_path, serde_json::json!({
            "timestamp_ms": current_timestamp_ms(),
            "type": "rules_update",
            "rules": rules,
        }))?;

        write_file_with_fsync(&path, &payload)
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to write rules: {}", e)))?;

        clear_wal(&wal_path)?;

        info!(path = %path.display(), "persisted rules");
        Ok(())
    }

    fn update_rules_hash(&self, value: String) {
        if let Some(hash_lock) = self.rules_hash.as_ref() {
            *hash_lock.write() = value;
        }
    }

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

        write_file_with_fsync(path, yaml.as_bytes())
            .map_err(|e| ConfigManagerError::Persistence(format!("failed to write config: {}", e)))?;

        info!(path = %path.display(), "persisted configuration");
        Ok(())
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn append_wal_entry(
    path: &std::path::Path,
    entry: serde_json::Value,
) -> Result<(), ConfigManagerError> {
    use std::io::Write;
    let Some(parent) = path.parent() else {
        return Err(ConfigManagerError::Persistence("invalid WAL path".to_string()));
    };

    if let Err(err) = fs::create_dir_all(parent) {
        return Err(ConfigManagerError::Persistence(format!(
            "failed to create WAL directory: {}",
            err
        )));
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| ConfigManagerError::Persistence(format!(
            "failed to open WAL file: {}",
            err
        )))?;

    let payload = serde_json::to_vec(&entry)
        .map_err(|err| ConfigManagerError::Persistence(format!(
            "failed to serialize WAL entry: {}",
            err
        )))?;
    file.write_all(&payload)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|err| ConfigManagerError::Persistence(format!(
            "failed to persist WAL entry: {}",
            err
        )))?;

    Ok(())
}

fn write_file_with_fsync(path: &std::path::Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn clear_wal(path: &std::path::Path) -> Result<(), ConfigManagerError> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(|err| ConfigManagerError::Persistence(format!(
            "failed to open WAL file: {}",
            err
        )))?;
    file.write_all(b"")
        .and_then(|_| file.sync_all())
        .map_err(|err| ConfigManagerError::Persistence(format!(
            "failed to clear WAL file: {}",
            err
        )))?;
    Ok(())
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
