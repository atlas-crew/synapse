//! Per-site WAF configuration management.
//!
//! This module provides granular WAF policy control with per-site settings,
//! rule overrides, and custom block pages.

use ahash::RandomState;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

/// Default block page HTML template.
const DEFAULT_BLOCK_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            backdrop-filter: blur(10px);
            max-width: 500px;
        }
        h1 { color: #e94560; margin-bottom: 1rem; }
        p { color: #aaa; line-height: 1.6; }
        .code {
            font-family: monospace;
            background: rgba(0,0,0,0.3);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            margin-top: 1rem;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Access Denied</h1>
        <p>Your request has been blocked by the security system.</p>
        <p>If you believe this is an error, please contact support.</p>
        <div class="code">
            Request ID: {{REQUEST_ID}}<br>
            Reason: {{REASON}}
        </div>
    </div>
</body>
</html>"#;

/// Actions that can be taken for a rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    /// Block the request
    Block,
    /// Log but allow the request
    Log,
    /// Allow without logging
    Allow,
    /// Present a challenge (e.g., CAPTCHA)
    Challenge,
}

impl Default for WafAction {
    fn default() -> Self {
        WafAction::Block
    }
}

/// Rule override configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOverride {
    /// Rule ID to override
    pub rule_id: String,
    /// Action to take (overrides default)
    pub action: WafAction,
    /// Custom threshold for this rule (0-100)
    pub threshold: Option<u8>,
    /// Whether this override is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Per-site WAF configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteWafConfig {
    /// Whether WAF is enabled for this site
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Risk threshold for blocking (0-100)
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    /// Rule-specific overrides
    #[serde(default)]
    pub rule_overrides: HashMap<String, RuleOverride>,
    /// Custom block page HTML (optional)
    pub custom_block_page: Option<String>,
    /// Default action when threshold exceeded
    #[serde(default)]
    pub default_action: WafAction,
}

fn default_threshold() -> u8 {
    70
}

impl Default for SiteWafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_threshold(),
            rule_overrides: HashMap::new(),
            custom_block_page: None,
            default_action: WafAction::Block,
        }
    }
}

impl SiteWafConfig {
    /// Creates a new WAF config with the specified threshold.
    ///
    /// # Security (SEC-007)
    /// Threshold is clamped to range [1, 100] - zero is not allowed as it would
    /// effectively bypass WAF protection.
    pub fn with_threshold(threshold: u8) -> Self {
        Self {
            threshold: threshold.clamp(1, 100),
            ..Default::default()
        }
    }

    /// Creates a disabled WAF config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Adds a rule override.
    pub fn add_override(&mut self, rule_id: &str, action: WafAction, threshold: Option<u8>) {
        self.rule_overrides.insert(
            rule_id.to_string(),
            RuleOverride {
                rule_id: rule_id.to_string(),
                action,
                threshold,
                enabled: true,
            },
        );
    }

    /// Gets the action for a specific rule.
    pub fn get_rule_action(&self, rule_id: &str) -> WafAction {
        if let Some(override_config) = self.rule_overrides.get(rule_id) {
            if override_config.enabled {
                return override_config.action;
            }
        }
        self.default_action
    }

    /// Gets the threshold for a specific rule.
    pub fn get_rule_threshold(&self, rule_id: &str) -> u8 {
        if let Some(override_config) = self.rule_overrides.get(rule_id) {
            if override_config.enabled {
                if let Some(threshold) = override_config.threshold {
                    return threshold;
                }
            }
        }
        self.threshold
    }

    /// Determines if a request should be blocked based on risk score and rule.
    pub fn should_block(&self, risk_score: u8, rule_id: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }

        let threshold = rule_id
            .map(|id| self.get_rule_threshold(id))
            .unwrap_or(self.threshold);

        let action = rule_id
            .map(|id| self.get_rule_action(id))
            .unwrap_or(self.default_action);

        match action {
            WafAction::Allow => false,
            WafAction::Log => false, // Log but don't block
            WafAction::Block | WafAction::Challenge => risk_score >= threshold,
        }
    }

    /// Renders the block page with placeholders replaced.
    pub fn render_block_page(&self, request_id: &str, reason: &str) -> String {
        let template = self
            .custom_block_page
            .as_deref()
            .unwrap_or(DEFAULT_BLOCK_PAGE);

        let safe_request_id = escape_html(request_id);
        let safe_reason = escape_html(reason);

        template
            .replace("{{REQUEST_ID}}", &safe_request_id)
            .replace("{{REASON}}", &safe_reason)
    }
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

/// Manager for multiple site WAF configurations.
///
/// # Performance (PERF-P2-2)
/// Uses ahash::RandomState for 2-3x faster HashMap operations.
#[derive(Debug)]
pub struct SiteWafManager {
    /// Site hostname -> WAF config mapping (using fast ahash)
    configs: HashMap<String, SiteWafConfig, RandomState>,
    /// Default WAF config for unmatched sites
    default_config: SiteWafConfig,
}

impl Default for SiteWafManager {
    fn default() -> Self {
        Self {
            configs: HashMap::with_hasher(RandomState::new()),
            default_config: SiteWafConfig::default(),
        }
    }
}

impl SiteWafManager {
    /// Creates a new manager with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a manager with a custom default config.
    pub fn with_default(default_config: SiteWafConfig) -> Self {
        Self {
            configs: HashMap::with_hasher(RandomState::new()),
            default_config,
        }
    }

    /// Adds a site-specific WAF configuration.
    ///
    /// # Security (SEC-011)
    /// Logs structured audit events when WAF is disabled for security compliance.
    pub fn add_site(&mut self, hostname: &str, config: SiteWafConfig) {
        let normalized = hostname.to_lowercase();

        // SEC-011: Structured audit logging for WAF state changes
        let existing_enabled = self.configs.get(&normalized).map(|c| c.enabled);

        if !config.enabled {
            let audit_event = serde_json::json!({
                "event": "waf_state_change",
                "hostname": hostname,
                "old_state": existing_enabled.map(|e| if e { "enabled" } else { "disabled" }),
                "new_state": "disabled",
                "threshold": config.threshold,
                "timestamp": Utc::now().to_rfc3339(),
                "severity": "warning"
            });
            warn!(
                target: "security_audit",
                "WAF disabled for site '{}' - requests will not be analyzed. Audit: {}",
                hostname,
                audit_event
            );
        } else if existing_enabled == Some(false) {
            // WAF being re-enabled
            let audit_event = serde_json::json!({
                "event": "waf_state_change",
                "hostname": hostname,
                "old_state": "disabled",
                "new_state": "enabled",
                "threshold": config.threshold,
                "timestamp": Utc::now().to_rfc3339(),
                "severity": "info"
            });
            info!(
                target: "security_audit",
                "WAF enabled for site '{}'. Audit: {}",
                hostname,
                audit_event
            );
        }

        self.configs.insert(normalized, config);
    }

    /// Gets the WAF config for a site, falling back to default.
    pub fn get_config(&self, hostname: &str) -> &SiteWafConfig {
        let normalized = hostname.to_lowercase();
        self.configs
            .get(&normalized)
            .unwrap_or(&self.default_config)
    }

    /// Gets a mutable reference to a site's WAF config.
    pub fn get_config_mut(&mut self, hostname: &str) -> Option<&mut SiteWafConfig> {
        let normalized = hostname.to_lowercase();
        self.configs.get_mut(&normalized)
    }

    /// Checks if a request should be blocked for a site.
    pub fn should_block(&self, hostname: &str, risk_score: u8, rule_id: Option<&str>) -> bool {
        let config = self.get_config(hostname);
        config.should_block(risk_score, rule_id)
    }

    /// Gets the block page for a site.
    pub fn get_block_page(&self, hostname: &str, request_id: &str, reason: &str) -> String {
        let config = self.get_config(hostname);
        config.render_block_page(request_id, reason)
    }

    /// Returns the number of configured sites.
    pub fn site_count(&self) -> usize {
        self.configs.len()
    }

    /// Iterates over all site configurations.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &SiteWafConfig)> {
        self.configs.iter()
    }

    /// Updates the default configuration.
    pub fn set_default(&mut self, config: SiteWafConfig) {
        self.default_config = config;
    }

    /// Returns the default configuration.
    pub fn default_config(&self) -> &SiteWafConfig {
        &self.default_config
    }

    /// Removes a site configuration.
    pub fn remove_site(&mut self, hostname: &str) -> Option<SiteWafConfig> {
        let normalized = hostname.to_lowercase();
        self.configs.remove(&normalized)
    }

    /// Retains only sites matching the predicate.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&str, &SiteWafConfig) -> bool,
    {
        self.configs.retain(|k, v| f(k.as_str(), v));
    }

    /// Returns all site hostnames.
    pub fn hostnames(&self) -> Vec<String> {
        self.configs.keys().cloned().collect()
    }

    /// Clears all site configurations, keeping only the default.
    pub fn clear(&mut self) {
        self.configs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SiteWafConfig::default();
        assert!(config.enabled);
        assert_eq!(config.threshold, 70);
        assert_eq!(config.default_action, WafAction::Block);
    }

    #[test]
    fn test_disabled_config() {
        let config = SiteWafConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_should_block_enabled() {
        let config = SiteWafConfig::with_threshold(70);

        // Should block when score >= threshold
        assert!(config.should_block(80, None));
        assert!(config.should_block(70, None));

        // Should not block when score < threshold
        assert!(!config.should_block(69, None));
        assert!(!config.should_block(50, None));
    }

    #[test]
    fn test_should_block_disabled() {
        let config = SiteWafConfig::disabled();

        // Should never block when disabled
        assert!(!config.should_block(100, None));
        assert!(!config.should_block(0, None));
    }

    #[test]
    fn test_rule_override_action() {
        let mut config = SiteWafConfig::default();
        config.add_override("rule-123", WafAction::Log, None);

        // Override should change action to Log (non-blocking)
        assert_eq!(config.get_rule_action("rule-123"), WafAction::Log);

        // Unoverridden rules use default
        assert_eq!(config.get_rule_action("rule-456"), WafAction::Block);
    }

    #[test]
    fn test_rule_override_threshold() {
        let mut config = SiteWafConfig::with_threshold(70);
        config.add_override("rule-123", WafAction::Block, Some(90));

        // Override should change threshold
        assert_eq!(config.get_rule_threshold("rule-123"), 90);

        // Unoverridden rules use default
        assert_eq!(config.get_rule_threshold("rule-456"), 70);
    }

    #[test]
    fn test_rule_override_blocking() {
        let mut config = SiteWafConfig::with_threshold(70);
        config.add_override("rule-123", WafAction::Block, Some(90));

        // Score 80 should block with default threshold (70)
        assert!(config.should_block(80, Some("rule-456")));

        // Score 80 should NOT block with overridden threshold (90)
        assert!(!config.should_block(80, Some("rule-123")));

        // Score 95 should block with overridden threshold
        assert!(config.should_block(95, Some("rule-123")));
    }

    #[test]
    fn test_allow_action() {
        let mut config = SiteWafConfig::with_threshold(70);
        config.add_override("rule-123", WafAction::Allow, None);

        // Allow action should never block
        assert!(!config.should_block(100, Some("rule-123")));
    }

    #[test]
    fn test_render_block_page() {
        let config = SiteWafConfig::default();
        let page = config.render_block_page("abc123", "SQL Injection");

        assert!(page.contains("abc123"));
        assert!(page.contains("SQL Injection"));
        assert!(page.contains("Access Denied"));
    }

    #[test]
    fn test_custom_block_page() {
        let mut config = SiteWafConfig::default();
        config.custom_block_page = Some("Custom: {{REQUEST_ID}} - {{REASON}}".to_string());

        let page = config.render_block_page("xyz789", "<script>alert(1)</script>");
        assert_eq!(
            page,
            "Custom: xyz789 - &lt;script&gt;alert(1)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_render_block_page_escapes_html() {
        let config = SiteWafConfig::default();
        let page = config.render_block_page("req-1", "<img src=x onerror=alert(1)>");

        assert!(!page.contains("<img"));
        assert!(page.contains("&lt;img src=x onerror=alert(1)&gt;"));
    }

    #[test]
    fn test_site_waf_manager() {
        let mut manager = SiteWafManager::new();

        manager.add_site("example.com", SiteWafConfig::with_threshold(80));
        manager.add_site("api.example.com", SiteWafConfig::with_threshold(60));

        assert_eq!(manager.site_count(), 2);

        // Site-specific configs
        assert_eq!(manager.get_config("example.com").threshold, 80);
        assert_eq!(manager.get_config("api.example.com").threshold, 60);

        // Unknown site gets default
        assert_eq!(manager.get_config("unknown.com").threshold, 70);
    }

    #[test]
    fn test_manager_case_insensitive() {
        let mut manager = SiteWafManager::new();
        manager.add_site("Example.COM", SiteWafConfig::with_threshold(80));

        assert_eq!(manager.get_config("example.com").threshold, 80);
        assert_eq!(manager.get_config("EXAMPLE.COM").threshold, 80);
    }

    #[test]
    fn test_manager_should_block() {
        let mut manager = SiteWafManager::new();
        manager.add_site("strict.com", SiteWafConfig::with_threshold(50));
        manager.add_site("lenient.com", SiteWafConfig::with_threshold(90));

        // Score 70 should block on strict but not lenient
        assert!(manager.should_block("strict.com", 70, None));
        assert!(!manager.should_block("lenient.com", 70, None));
    }

    #[test]
    fn test_manager_get_block_page() {
        let mut manager = SiteWafManager::new();

        let mut config = SiteWafConfig::default();
        config.custom_block_page = Some("Site blocked: {{REASON}}".to_string());
        manager.add_site("custom.com", config);

        let page = manager.get_block_page("custom.com", "123", "Attack");
        assert!(page.contains("Site blocked: Attack"));

        let default_page = manager.get_block_page("other.com", "456", "Test");
        assert!(default_page.contains("Access Denied"));
    }

    #[test]
    fn test_waf_action_default() {
        let action = WafAction::default();
        assert_eq!(action, WafAction::Block);
    }

    #[test]
    fn test_manager_iter() {
        let mut manager = SiteWafManager::new();
        manager.add_site("site1.com", SiteWafConfig::with_threshold(60));
        manager.add_site("site2.com", SiteWafConfig::with_threshold(80));

        let sites: Vec<_> = manager.iter().collect();
        assert_eq!(sites.len(), 2);
    }

    #[test]
    fn test_set_default_config() {
        let mut manager = SiteWafManager::new();
        manager.set_default(SiteWafConfig::with_threshold(50));

        assert_eq!(manager.default_config().threshold, 50);
        assert_eq!(manager.get_config("unknown.com").threshold, 50);
    }

    #[test]
    fn test_threshold_capped_at_100() {
        let config = SiteWafConfig::with_threshold(150);
        assert_eq!(config.threshold, 100);
    }

    #[test]
    fn test_threshold_clamped_to_minimum_1() {
        // SEC-007: Zero threshold should be clamped to 1
        let config = SiteWafConfig::with_threshold(0);
        assert_eq!(config.threshold, 1);
    }

    #[test]
    fn test_disabled_override() {
        let mut config = SiteWafConfig::default();
        let override_config = RuleOverride {
            rule_id: "rule-123".to_string(),
            action: WafAction::Allow,
            threshold: Some(90),
            enabled: false, // Disabled
        };
        config
            .rule_overrides
            .insert("rule-123".to_string(), override_config);

        // Disabled override should fall back to default
        assert_eq!(config.get_rule_action("rule-123"), WafAction::Block);
        assert_eq!(config.get_rule_threshold("rule-123"), 70);
    }
}
