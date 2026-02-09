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
//! - Streaming scanner for large payloads
//! - Configurable redaction modes (mask, hash, full)
//! - Custom keyword detection
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
mod stream;

// Streaming scanner
pub use stream::{StreamingError, StreamingScanner};

// Configuration
pub use scanner::{DlpConfig, DlpConfigError, RedactionConfigBuilder, RedactionMode};

// Pattern types
pub use scanner::{PatternSeverity, SensitiveDataType};

// Match and scan results
pub use scanner::{DlpMatch, DlpStats, DlpViolation, ScanResult};

// Scanner
pub use scanner::DlpScanner;

// Validators (for testing and custom validation)
pub use scanner::{validate_credit_card, validate_iban, validate_phone, validate_ssn};
