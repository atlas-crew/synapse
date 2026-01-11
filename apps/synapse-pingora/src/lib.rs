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
//! # Phase 3 Modules (Feature Migration from risk-server)
//!
//! - [`fingerprint`] - JA4/JA4H TLS and HTTP fingerprinting
//! - [`entity`] - Per-IP entity tracking with risk scoring and decay
//! - [`tarpit`] - Progressive response delays for slow-drip defense
//! - [`dlp`] - Data Loss Prevention with 23 sensitive data patterns

// Phase 1: Core Features
pub mod config;
pub mod config_manager;
pub mod health;
pub mod site_waf;
pub mod tls;
pub mod vhost;

// Phase 2: Management Features
pub mod access;
pub mod admin_server;
pub mod api;
pub mod metrics;
pub mod ratelimit;
pub mod reload;

// Phase 3: Feature Migration from risk-server
pub mod fingerprint;
pub mod entity;
pub mod tarpit;
pub mod dlp;

// Phase 6: Security Hardening
pub mod validation;

// Phase 7: Persistence
pub mod persistence;

// Phase 3: Telemetry (Alerting)
pub mod telemetry;

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

// Re-export commonly used types from Phase 3
pub use fingerprint::{
    Ja4Fingerprint, Ja4hFingerprint, ClientFingerprint,
    Ja4Protocol, Ja4SniType, Ja4Analysis, Ja4hAnalysis,
    HttpHeaders,
    parse_ja4_from_header, generate_ja4h, extract_client_fingerprint,
    analyze_ja4, analyze_ja4h,
};
pub use entity::{
    EntityConfig, EntityState, EntityManager,
    BlockDecision, RiskApplication, EntitySnapshot, EntityMetrics,
};
pub use tarpit::{
    TarpitConfig, TarpitState, TarpitStats,
    TarpitManager, TarpitDecision,
};
pub use dlp::{
    DlpConfig, DlpScanner, DlpMatch, DlpStats, ScanResult,
    SensitiveDataType, PatternSeverity,
    validate_credit_card, validate_ssn, validate_phone, validate_iban,
};

// Re-export validation utilities
pub use validation::{
    ValidationError, ValidationResult,
    validate_domain_name, validate_certificate_file, validate_private_key_file,
    validate_tls_config,
};
