//! Data Loss Prevention (DLP) Module
//!
//! Scans response bodies for PII and sensitive data patterns.
//! Supports PCI-DSS, GDPR, HIPAA, and SOC2 compliance requirements.
//!
//! # Phase 4 Module (Feature Migration from risk-server)
//!
//! ## Features
//! - 22 sensitive data patterns (credit cards, SSN, API keys, etc.)
//! - Luhn algorithm validation for credit cards
//! - SSN and IBAN format validation
//! - Compiled regex patterns with lazy_static
//! - Thread-safe concurrent scanning
//!
//! ## Feature Flags
//! - `ENABLE_PINGORA_DLP=true`: Enable Pingora DLP scanning
//!
//! ## Dual-Running Mode
//! Headers injected for comparison:
//! - `X-DLP-Violations-Pingora`: Count of DLP matches
//! - `X-DLP-Types-Pingora`: Comma-separated list of matched types
//!
//! @see apps/risk-server/src/profiler/sensitive-data.ts (TypeScript reference)

mod scanner;

pub use scanner::{
    // Configuration
    DlpConfig,
    // Pattern types
    SensitiveDataType,
    PatternSeverity,
    // Match result
    DlpMatch,
    // Scan result
    ScanResult,
    // Statistics
    DlpStats,
    // Scanner
    DlpScanner,
    // Validators
    validate_credit_card,
    validate_ssn,
    validate_iban,
};
