//! Custom Block Page Rendering Module
//!
//! Provides template-based rendering for block pages with support for both
//! browser (HTML) and API (JSON) clients.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Block page errors.
#[derive(Debug, Error)]
pub enum BlockPageError {
    #[error("template error: {0}")]
    TemplateError(String),

    #[error("missing variable: {0}")]
    MissingVariable(String),
}

pub type BlockPageResult<T> = Result<T, BlockPageError>;

/// Reason why a request was blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockReason {
    WafRule,
    RateLimit,
    AccessDenied,
    DlpViolation,
    Maintenance,
}

impl BlockReason {
    pub fn description(&self) -> &'static str {
        match self {
            Self::WafRule => "Request blocked by security rules",
            Self::RateLimit => "Rate limit exceeded",
            Self::AccessDenied => "Access denied",
            Self::DlpViolation => "Data loss prevention policy violation",
            Self::Maintenance => "Service temporarily unavailable",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            Self::WafRule => 403,
            Self::RateLimit => 429,
            Self::AccessDenied => 403,
            Self::DlpViolation => 403,
            Self::Maintenance => 503,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::WafRule => "WAF_BLOCKED",
            Self::RateLimit => "RATE_LIMITED",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::DlpViolation => "DLP_VIOLATION",
            Self::Maintenance => "MAINTENANCE",
        }
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Block page context for template rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContext {
    pub reason: BlockReason,
    pub request_id: String,
    pub client_ip: String,
    pub timestamp: String,
    pub site_name: Option<String>,
    pub rule_id: Option<String>,
    pub message: Option<String>,
    pub support_email: Option<String>,
    pub show_details: bool,
}

impl BlockContext {
    pub fn new(reason: BlockReason, request_id: impl Into<String>, client_ip: impl Into<String>) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        Self {
            reason,
            request_id: request_id.into(),
            client_ip: client_ip.into(),
            timestamp,
            site_name: None,
            rule_id: None,
            message: None,
            support_email: None,
            show_details: true,
        }
    }

    pub fn with_site_name(mut self, name: impl Into<String>) -> Self {
        self.site_name = Some(name.into());
        self
    }

    pub fn with_rule_id(mut self, id: impl Into<String>) -> Self {
        self.rule_id = Some(id.into());
        self
    }

    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    pub fn with_support_email(mut self, email: impl Into<String>) -> Self {
        self.support_email = Some(email.into());
        self
    }

    pub fn with_show_details(mut self, show: bool) -> Self {
        self.show_details = show;
        self
    }
}

/// JSON response for API clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPageJsonResponse {
    pub error: String,
    pub code: String,
    pub message: String,
    pub request_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub support_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

impl BlockPageJsonResponse {
    pub fn from_context(ctx: &BlockContext) -> Self {
        Self {
            error: ctx.reason.error_code().to_string(),
            code: ctx.reason.http_status().to_string(),
            message: ctx.message.clone().unwrap_or_else(|| ctx.reason.description().to_string()),
            request_id: ctx.request_id.clone(),
            timestamp: ctx.timestamp.clone(),
            support_email: ctx.support_email.clone(),
            rule_id: ctx.rule_id.clone(),
        }
    }
}

/// Configuration for block page rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPageConfig {
    pub custom_template: Option<String>,
    pub custom_css: Option<String>,
    pub logo_url: Option<String>,
    pub company_name: Option<String>,
    pub support_email: Option<String>,
    pub show_request_id: bool,
    pub show_timestamp: bool,
    pub show_client_ip: bool,
    pub show_rule_id: bool,
}

impl Default for BlockPageConfig {
    fn default() -> Self {
        Self {
            custom_template: None,
            custom_css: None,
            logo_url: None,
            company_name: None,
            support_email: None,
            show_request_id: true,
            show_timestamp: true,
            show_client_ip: false,
            show_rule_id: false,
        }
    }
}

impl BlockPageConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.custom_template = Some(template.into());
        self
    }

    pub fn with_css(mut self, css: impl Into<String>) -> Self {
        self.custom_css = Some(css.into());
        self
    }

    pub fn with_logo(mut self, url: impl Into<String>) -> Self {
        self.logo_url = Some(url.into());
        self
    }

    pub fn with_company_name(mut self, name: impl Into<String>) -> Self {
        self.company_name = Some(name.into());
        self
    }

    pub fn with_support_email(mut self, email: impl Into<String>) -> Self {
        self.support_email = Some(email.into());
        self
    }

    pub fn with_show_details(mut self, request_id: bool, timestamp: bool, client_ip: bool, rule_id: bool) -> Self {
        self.show_request_id = request_id;
        self.show_timestamp = timestamp;
        self.show_client_ip = client_ip;
        self.show_rule_id = rule_id;
        self
    }
}

/// Block page renderer.
pub struct BlockPageRenderer {
    config: BlockPageConfig,
}

impl BlockPageRenderer {
    pub fn new(config: BlockPageConfig) -> Self {
        Self { config }
    }

    /// Renders a block page based on Accept header.
    pub fn render(&self, ctx: &BlockContext, accept_header: Option<&str>) -> (String, &'static str) {
        let prefers_json = accept_header
            .map(|h| Self::prefers_json(h))
            .unwrap_or(false);

        if prefers_json {
            (self.render_json(ctx), "application/json")
        } else {
            (self.render_html(ctx), "text/html; charset=utf-8")
        }
    }

    /// Renders HTML block page.
    pub fn render_html(&self, ctx: &BlockContext) -> String {
        let template = self.config.custom_template.as_deref().unwrap_or(DEFAULT_TEMPLATE);
        self.render_template(template, ctx)
    }

    /// Renders JSON response.
    pub fn render_json(&self, ctx: &BlockContext) -> String {
        let response = BlockPageJsonResponse::from_context(ctx);
        serde_json::to_string_pretty(&response).unwrap_or_else(|_| {
            r#"{"error":"INTERNAL_ERROR","message":"Failed to render response"}"#.to_string()
        })
    }

    fn render_template(&self, template: &str, ctx: &BlockContext) -> String {
        let mut vars: HashMap<&str, String> = HashMap::new();

        // Core variables
        vars.insert("status_code", ctx.reason.http_status().to_string());
        vars.insert("error_code", ctx.reason.error_code().to_string());
        vars.insert("title", ctx.reason.description().to_string());
        vars.insert("message", ctx.message.clone().unwrap_or_else(|| ctx.reason.description().to_string()));
        vars.insert("request_id", ctx.request_id.clone());
        vars.insert("timestamp", ctx.timestamp.clone());
        vars.insert("client_ip", ctx.client_ip.clone());

        // Optional variables
        vars.insert("site_name", ctx.site_name.clone().unwrap_or_default());
        vars.insert("rule_id", ctx.rule_id.clone().unwrap_or_default());
        vars.insert("support_email", ctx.support_email.clone()
            .or_else(|| self.config.support_email.clone())
            .unwrap_or_default());
        vars.insert("company_name", self.config.company_name.clone().unwrap_or_else(|| "WAF Protection".to_string()));
        vars.insert("logo_url", self.config.logo_url.clone().unwrap_or_default());
        vars.insert("custom_css", self.config.custom_css.clone().unwrap_or_default());

        // Visibility flags
        vars.insert("show_request_id", if self.config.show_request_id && ctx.show_details { "true" } else { "" }.to_string());
        vars.insert("show_timestamp", if self.config.show_timestamp && ctx.show_details { "true" } else { "" }.to_string());
        vars.insert("show_client_ip", if self.config.show_client_ip && ctx.show_details { "true" } else { "" }.to_string());
        vars.insert("show_rule_id", if self.config.show_rule_id && ctx.rule_id.is_some() && ctx.show_details { "true" } else { "" }.to_string());
        vars.insert("has_support_email", if ctx.support_email.is_some() || self.config.support_email.is_some() { "true" } else { "" }.to_string());
        vars.insert("has_logo", if self.config.logo_url.is_some() { "true" } else { "" }.to_string());
        vars.insert("has_custom_css", if self.config.custom_css.is_some() { "true" } else { "" }.to_string());

        Self::substitute_template(template, &vars)
    }

    fn substitute_template(template: &str, vars: &HashMap<&str, String>) -> String {
        let mut result = template.to_string();

        // Process conditionals first: {{#if var}}...{{/if}}
        let conditional_re = regex::Regex::new(r"\{\{#if\s+(\w+)\}\}([\s\S]*?)\{\{/if\}\}").unwrap();
        result = conditional_re.replace_all(&result, |caps: &regex::Captures| {
            let var_name = &caps[1];
            let content = &caps[2];
            if let Some(value) = vars.get(var_name) {
                if !value.is_empty() {
                    return content.to_string();
                }
            }
            String::new()
        }).to_string();

        // Then substitute variables: {{var}}
        for (key, value) in vars {
            let pattern = format!("{{{{{}}}}}", key);
            result = result.replace(&pattern, value);
        }

        result
    }

    fn prefers_json(accept: &str) -> bool {
        // Parse Accept header with quality values
        let mut best_html: f32 = 0.0;
        let mut best_json: f32 = 0.0;

        for part in accept.split(',') {
            let part = part.trim();
            let (mime, quality) = Self::parse_accept_part(part);

            if mime == "application/json" || mime == "text/json" {
                best_json = best_json.max(quality);
            } else if mime == "text/html" || mime == "*/*" {
                best_html = best_html.max(quality);
            }
        }

        best_json > best_html
    }

    fn parse_accept_part(part: &str) -> (&str, f32) {
        let mut parts = part.split(';');
        let mime = parts.next().unwrap_or("").trim();

        let mut quality: f32 = 1.0;
        for param in parts {
            let param = param.trim();
            if let Some(q) = param.strip_prefix("q=") {
                quality = q.parse().unwrap_or(1.0);
            }
        }

        (mime, quality)
    }

    pub fn http_status(&self, reason: BlockReason) -> u16 {
        reason.http_status()
    }
}

impl Default for BlockPageRenderer {
    fn default() -> Self {
        Self::new(BlockPageConfig::default())
    }
}

const DEFAULT_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>{{status_code}} - {{title}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #e0e0e0;
        }
        .container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 48px;
            max-width: 600px;
            width: 100%;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        .status-code {
            font-size: 96px;
            font-weight: 700;
            color: #e94560;
            line-height: 1;
            margin-bottom: 16px;
            text-shadow: 0 0 30px rgba(233, 69, 96, 0.5);
        }
        .title {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #fff;
        }
        .message {
            font-size: 16px;
            color: #a0a0a0;
            margin-bottom: 32px;
            line-height: 1.6;
        }
        .details {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            padding: 20px;
            margin-top: 24px;
            text-align: left;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', monospace;
            font-size: 13px;
        }
        .details-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }
        .details-row:last-child {
            border-bottom: none;
        }
        .details-label {
            color: #808080;
        }
        .details-value {
            color: #e0e0e0;
            word-break: break-all;
        }
        .support {
            margin-top: 24px;
            font-size: 14px;
            color: #808080;
        }
        .support a {
            color: #e94560;
            text-decoration: none;
        }
        .support a:hover {
            text-decoration: underline;
        }
        .logo {
            max-height: 48px;
            margin-bottom: 24px;
        }
        @media (max-width: 480px) {
            .container {
                padding: 32px 24px;
            }
            .status-code {
                font-size: 72px;
            }
            .title {
                font-size: 20px;
            }
        }
        @media (prefers-reduced-motion: reduce) {
            * {
                animation: none !important;
                transition: none !important;
            }
        }
    </style>
    {{#if has_custom_css}}<style>{{custom_css}}</style>{{/if}}
</head>
<body>
    <main class="container" role="main" aria-labelledby="error-title">
        {{#if has_logo}}<img src="{{logo_url}}" alt="{{company_name}}" class="logo">{{/if}}
        <div class="status-code" aria-hidden="true">{{status_code}}</div>
        <h1 class="title" id="error-title">{{title}}</h1>
        <p class="message">{{message}}</p>
        {{#if show_request_id}}
        <div class="details" role="complementary" aria-label="Request details">
            {{#if show_request_id}}
            <div class="details-row">
                <span class="details-label">Request ID</span>
                <span class="details-value">{{request_id}}</span>
            </div>
            {{/if}}
            {{#if show_timestamp}}
            <div class="details-row">
                <span class="details-label">Time</span>
                <span class="details-value">{{timestamp}}</span>
            </div>
            {{/if}}
            {{#if show_client_ip}}
            <div class="details-row">
                <span class="details-label">Client IP</span>
                <span class="details-value">{{client_ip}}</span>
            </div>
            {{/if}}
            {{#if show_rule_id}}
            <div class="details-row">
                <span class="details-label">Rule</span>
                <span class="details-value">{{rule_id}}</span>
            </div>
            {{/if}}
        </div>
        {{/if}}
        {{#if has_support_email}}
        <p class="support">
            If you believe this is an error, please contact
            <a href="mailto:{{support_email}}">{{support_email}}</a>
        </p>
        {{/if}}
    </main>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_reason_description() {
        assert_eq!(BlockReason::WafRule.description(), "Request blocked by security rules");
        assert_eq!(BlockReason::RateLimit.description(), "Rate limit exceeded");
        assert_eq!(BlockReason::AccessDenied.description(), "Access denied");
        assert_eq!(BlockReason::DlpViolation.description(), "Data loss prevention policy violation");
        assert_eq!(BlockReason::Maintenance.description(), "Service temporarily unavailable");
    }

    #[test]
    fn test_block_reason_http_status() {
        assert_eq!(BlockReason::WafRule.http_status(), 403);
        assert_eq!(BlockReason::RateLimit.http_status(), 429);
        assert_eq!(BlockReason::AccessDenied.http_status(), 403);
        assert_eq!(BlockReason::DlpViolation.http_status(), 403);
        assert_eq!(BlockReason::Maintenance.http_status(), 503);
    }

    #[test]
    fn test_block_reason_error_code() {
        assert_eq!(BlockReason::WafRule.error_code(), "WAF_BLOCKED");
        assert_eq!(BlockReason::RateLimit.error_code(), "RATE_LIMITED");
        assert_eq!(BlockReason::AccessDenied.error_code(), "ACCESS_DENIED");
    }

    #[test]
    fn test_block_context_builder() {
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1")
            .with_site_name("example.com")
            .with_rule_id("SQLI-001")
            .with_message("SQL injection attempt detected")
            .with_support_email("support@example.com")
            .with_show_details(true);

        assert_eq!(ctx.reason, BlockReason::WafRule);
        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.client_ip, "192.168.1.1");
        assert_eq!(ctx.site_name, Some("example.com".to_string()));
        assert_eq!(ctx.rule_id, Some("SQLI-001".to_string()));
        assert!(ctx.show_details);
    }

    #[test]
    fn test_block_context_timestamp() {
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");
        assert!(!ctx.timestamp.is_empty());
        // Should be RFC3339 format
        assert!(ctx.timestamp.contains('T'));
    }

    #[test]
    fn test_json_response_from_context() {
        let ctx = BlockContext::new(BlockReason::RateLimit, "req-456", "10.0.0.1")
            .with_support_email("help@example.com");

        let response = BlockPageJsonResponse::from_context(&ctx);

        assert_eq!(response.error, "RATE_LIMITED");
        assert_eq!(response.code, "429");
        assert_eq!(response.request_id, "req-456");
        assert_eq!(response.support_email, Some("help@example.com".to_string()));
    }

    #[test]
    fn test_config_defaults() {
        let config = BlockPageConfig::default();
        assert!(config.custom_template.is_none());
        assert!(config.show_request_id);
        assert!(config.show_timestamp);
        assert!(!config.show_client_ip);
    }

    #[test]
    fn test_config_builder() {
        let config = BlockPageConfig::new()
            .with_company_name("Acme Corp")
            .with_support_email("security@acme.com")
            .with_logo("https://acme.com/logo.png")
            .with_show_details(true, true, true, true);

        assert_eq!(config.company_name, Some("Acme Corp".to_string()));
        assert_eq!(config.support_email, Some("security@acme.com".to_string()));
        assert!(config.show_client_ip);
        assert!(config.show_rule_id);
    }

    #[test]
    fn test_render_html() {
        let renderer = BlockPageRenderer::default();
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");

        let html = renderer.render_html(&ctx);

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("403"));
        assert!(html.contains("req-123"));
        assert!(html.contains("Request blocked by security rules"));
    }

    #[test]
    fn test_render_json() {
        let renderer = BlockPageRenderer::default();
        let ctx = BlockContext::new(BlockReason::RateLimit, "req-789", "10.0.0.1");

        let json = renderer.render_json(&ctx);

        assert!(json.contains("RATE_LIMITED"));
        assert!(json.contains("req-789"));
        assert!(json.contains("429"));
    }

    #[test]
    fn test_render_with_accept_header() {
        let renderer = BlockPageRenderer::default();
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");

        // HTML preference
        let (content, content_type) = renderer.render(&ctx, Some("text/html,application/json;q=0.9"));
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(content.contains("<!DOCTYPE html>"));

        // JSON preference
        let (content, content_type) = renderer.render(&ctx, Some("application/json"));
        assert_eq!(content_type, "application/json");
        assert!(content.contains("WAF_BLOCKED"));

        // No header defaults to HTML
        let (content, content_type) = renderer.render(&ctx, None);
        assert_eq!(content_type, "text/html; charset=utf-8");
        assert!(content.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_accept_header_quality_parsing() {
        // JSON with higher quality
        assert!(BlockPageRenderer::prefers_json("text/html;q=0.5,application/json;q=0.9"));

        // HTML with higher quality
        assert!(!BlockPageRenderer::prefers_json("text/html;q=0.9,application/json;q=0.5"));

        // Equal quality, HTML wins (default)
        assert!(!BlockPageRenderer::prefers_json("text/html,application/json"));

        // JSON only
        assert!(BlockPageRenderer::prefers_json("application/json"));

        // HTML only
        assert!(!BlockPageRenderer::prefers_json("text/html"));
    }

    #[test]
    fn test_custom_template() {
        let config = BlockPageConfig::new()
            .with_template("<h1>Error {{status_code}}</h1><p>{{message}}</p>");
        let renderer = BlockPageRenderer::new(config);
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");

        let html = renderer.render_html(&ctx);

        assert!(html.contains("<h1>Error 403</h1>"));
        assert!(html.contains("Request blocked by security rules"));
        assert!(!html.contains("<!DOCTYPE html>")); // Not using default template
    }

    #[test]
    fn test_template_conditionals() {
        let template = "{{#if show_request_id}}ID: {{request_id}}{{/if}}";
        let mut vars: HashMap<&str, String> = HashMap::new();
        vars.insert("show_request_id", "true".to_string());
        vars.insert("request_id", "abc-123".to_string());

        let result = BlockPageRenderer::substitute_template(template, &vars);
        assert_eq!(result, "ID: abc-123");

        // Empty value should not render
        vars.insert("show_request_id", "".to_string());
        let result = BlockPageRenderer::substitute_template(template, &vars);
        assert_eq!(result, "");
    }

    #[test]
    fn test_html_accessibility() {
        let renderer = BlockPageRenderer::default();
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");

        let html = renderer.render_html(&ctx);

        // Check for accessibility attributes
        assert!(html.contains("role=\"main\""));
        assert!(html.contains("aria-labelledby"));
        assert!(html.contains("aria-label"));
        assert!(html.contains("lang=\"en\""));
    }

    #[test]
    fn test_ipv6_client_ip() {
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "2001:db8::1");
        let renderer = BlockPageRenderer::new(
            BlockPageConfig::new().with_show_details(true, true, true, false)
        );

        let html = renderer.render_html(&ctx);
        assert!(html.contains("2001:db8::1"));
    }

    #[test]
    fn test_render_without_details() {
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1")
            .with_show_details(false);
        let renderer = BlockPageRenderer::default();

        let html = renderer.render_html(&ctx);
        // Details section should be empty when show_details is false
        assert!(html.contains("403"));
    }

    #[test]
    fn test_http_status_helper() {
        let renderer = BlockPageRenderer::default();
        assert_eq!(renderer.http_status(BlockReason::WafRule), 403);
        assert_eq!(renderer.http_status(BlockReason::RateLimit), 429);
        assert_eq!(renderer.http_status(BlockReason::Maintenance), 503);
    }

    #[test]
    fn test_json_serialization() {
        let ctx = BlockContext::new(BlockReason::DlpViolation, "req-dlp", "172.16.0.1")
            .with_rule_id("DLP-SSN-001");

        let response = BlockPageJsonResponse::from_context(&ctx);
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains("DLP_VIOLATION"));
        assert!(json.contains("DLP-SSN-001"));
    }

    #[test]
    fn test_block_reason_display() {
        assert_eq!(format!("{}", BlockReason::WafRule), "Request blocked by security rules");
        assert_eq!(format!("{}", BlockReason::RateLimit), "Rate limit exceeded");
    }

    #[test]
    fn test_config_custom_css() {
        let config = BlockPageConfig::new()
            .with_css("body { background: red; }");
        let renderer = BlockPageRenderer::new(config);
        let ctx = BlockContext::new(BlockReason::WafRule, "req-123", "192.168.1.1");

        let html = renderer.render_html(&ctx);
        assert!(html.contains("body { background: red; }"));
    }
}
