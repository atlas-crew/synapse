//! Synapse-Pingora: High-performance WAF proxy using Cloudflare Pingora.
//!
//! This library provides multi-site reverse proxy capabilities with integrated
//! WAF detection using the libsynapse engine.
//!
//! # Modules
//!
//! - [`vhost`] - Virtual host matching for multi-site routing
//! - [`config`] - Configuration loading and validation
//! - [`tls`] - TLS certificate management with SNI support
//! - [`health`] - Health check endpoint for monitoring
//! - [`site_waf`] - Per-site WAF configuration management

pub mod config;
pub mod health;
pub mod site_waf;
pub mod tls;
pub mod vhost;

// Re-export commonly used types
pub use config::{ConfigFile, ConfigLoader, GlobalConfig};
pub use health::{HealthChecker, HealthResponse, HealthStatus};
pub use site_waf::{SiteWafConfig, SiteWafManager, WafAction};
pub use tls::{TlsManager, TlsVersion};
pub use vhost::{SiteConfig, VhostMatcher};
