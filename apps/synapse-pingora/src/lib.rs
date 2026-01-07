//! Synapse-Pingora: High-performance WAF proxy using Cloudflare Pingora.
//!
//! This library provides multi-site reverse proxy capabilities with integrated
//! WAF detection using the libsynapse engine.
//!
//! # Phase 1 Modules (Core Features)
//!
//! - [`vhost`] - Virtual host matching for multi-site routing
//! - [`config`] - Configuration loading and validation
//! - [`tls`] - TLS certificate management with SNI support
//! - [`health`] - Health check endpoint for monitoring
//! - [`site_waf`] - Per-site WAF configuration management
//!
//! # Phase 2 Modules (Management Features)
//!
//! - [`metrics`] - Prometheus metrics endpoint
//! - [`reload`] - Configuration hot-reload via SIGHUP
//! - [`access`] - CIDR-based allow/deny access lists
//! - [`ratelimit`] - Per-site rate limiting with token bucket
//! - [`api`] - Management HTTP API
//!
//! # Phase 4 Modules (Advanced Features)
//!
//! - [`dlp`] - Data Loss Prevention body scanning
//! - [`body`] - Request/response body inspection
//! - [`telemetry`] - Signal Horizon telemetry integration
//! - [`block_page`] - Custom block page rendering
//! - [`shutdown`] - Graceful shutdown orchestration
//!
//! # Phase 5 Modules (Configuration Management)
//!
//! - [`validation`] - Input validation for API mutations
//! - [`config_manager`] - Centralized configuration CRUD operations

// Phase 1: Core Features
pub mod config;
pub mod health;
pub mod site_waf;
pub mod tls;
pub mod vhost;

// Phase 2: Management Features
pub mod access;
pub mod api;
pub mod metrics;
pub mod ratelimit;
pub mod reload;

// Phase 4: Advanced Features
pub mod block_page;
pub mod body;
pub mod dlp;
pub mod shutdown;
pub mod telemetry;

// Phase 5: Configuration Management
pub mod config_manager;
pub mod validation;

// Re-export commonly used types from Phase 1
pub use config::{ConfigFile, ConfigLoader, GlobalConfig};
pub use health::{HealthChecker, HealthResponse, HealthStatus};
pub use site_waf::{SiteWafConfig, SiteWafManager, WafAction};
pub use tls::{TlsManager, TlsVersion};
pub use vhost::{SiteConfig, VhostMatcher};

// Re-export commonly used types from Phase 2
pub use access::{AccessList, AccessListManager, AccessDecision};
pub use api::{ApiHandler, ApiResponse};
pub use metrics::MetricsRegistry;
pub use ratelimit::{RateLimitConfig, RateLimitManager, RateLimitDecision};
pub use reload::{ConfigReloader, ReloadResult};

// Re-export commonly used types from Phase 4
pub use block_page::{BlockContext, BlockPageConfig, BlockPageRenderer, BlockReason};
pub use body::{BodyConfig, BodyInspector, ContentType, InspectionResult};
pub use dlp::{DlpConfig, DlpMatch, DlpScanner, PatternType, Severity as DlpSeverity};
pub use shutdown::{ShutdownConfig, ShutdownController, ShutdownHandle, ShutdownState};
pub use telemetry::{TelemetryClient, TelemetryConfig, TelemetryEvent};

// Re-export commonly used types from Phase 5
pub use config_manager::{
    ConfigManager, CreateSiteRequest, UpdateSiteRequest, SiteWafRequest,
    RateLimitRequest, AccessListRequest, MutationResult, SiteDetailResponse,
    ConfigManagerError,
};
pub use validation::{ValidationError, ValidationResult};
