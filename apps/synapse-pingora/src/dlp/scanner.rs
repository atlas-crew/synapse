//! DLP Scanner Implementation
//!
//! Thread-safe scanner for detecting sensitive data in response bodies.
//!
//! Performance optimizations:
//! - Aho-Corasick automaton for single-pass multi-pattern matching
//! - Configurable inspection depth cap to bound scan time
//! - Content-type filtering to skip binary payloads

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use lazy_static::lazy_static;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Sensitive data type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SensitiveDataType {
    CreditCard,
    Ssn,
    Email,
    Phone,
    ApiKey,
    Password,
    Iban,
    IpAddress,
    AwsKey,
    PrivateKey,
    Jwt,
    MedicalRecord,
    Custom,
}

impl SensitiveDataType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreditCard => "credit_card",
            Self::Ssn => "ssn",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::ApiKey => "api_key",
            Self::Password => "password",
            Self::Iban => "iban",
            Self::IpAddress => "ip_address",
            Self::AwsKey => "aws_key",
            Self::PrivateKey => "private_key",
            Self::Jwt => "jwt",
            Self::MedicalRecord => "medical_record",
            Self::Custom => "custom",
        }
    }
}

/// Pattern severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl PatternSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// A matched sensitive data pattern
#[derive(Debug, Clone)]
pub struct DlpMatch {
    pub pattern_name: &'static str,
    pub data_type: SensitiveDataType,
    pub severity: PatternSeverity,
    pub masked_value: String,
    /// Start position in the scanned content (local to scan call)
    pub start: usize,
    /// End position in the scanned content (local to scan call)
    pub end: usize,
    /// Absolute offset in the original stream (set by StreamingScanner)
    /// None for non-streaming scans
    pub stream_offset: Option<usize>,
}

/// Result of a DLP scan
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scanned: bool,
    pub has_matches: bool,
    pub matches: Vec<DlpMatch>,
    pub match_count: usize,
    pub scan_time_us: u64,
    pub content_length: usize,
    /// True if content was truncated to max_body_inspection_bytes
    pub truncated: bool,
    /// Original content length before truncation (0 if not truncated)
    pub original_length: usize,
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            scanned: false,
            has_matches: false,
            matches: Vec::new(),
            match_count: 0,
            scan_time_us: 0,
            content_length: 0,
            truncated: false,
            original_length: 0,
        }
    }
}

/// DLP scanner statistics
#[derive(Debug, Clone)]
pub struct DlpStats {
    pub total_scans: u64,
    pub total_matches: u64,
    pub matches_by_type: HashMap<SensitiveDataType, u64>,
    pub matches_by_severity: HashMap<PatternSeverity, u64>,
}

/// A recorded DLP violation for audit/monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpViolation {
    pub timestamp: u64,
    pub pattern_name: String,
    pub data_type: String,
    pub severity: String,
    pub masked_value: String,
    pub client_ip: Option<String>,
    pub path: String,
}

/// Redaction mode for sensitive data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RedactionMode {
    /// Mask all characters (e.g., "**********")
    Full,
    /// Show partial characters (e.g., "****-1234") - Default
    Partial,
    /// Replace with hash (e.g., "sha256:...")
    Hash,
    /// No redaction (dangerous, debug only)
    None,
}

impl Default for RedactionMode {
    fn default() -> Self {
        Self::Partial
    }
}

/// Error type for DLP configuration validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpConfigError {
    /// Hash mode requires a salt to be configured
    HashModeRequiresSalt,
    /// Custom keyword is empty
    EmptyCustomKeyword,
    /// Custom keyword exceeds maximum length (1024 chars)
    CustomKeywordTooLong(usize),
    /// Too many custom keywords (max 1000)
    TooManyCustomKeywords(usize),
}

impl std::fmt::Display for DlpConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashModeRequiresSalt => {
                write!(f, "RedactionMode::Hash requires hash_salt to be configured")
            }
            Self::EmptyCustomKeyword => write!(f, "custom_keywords contains empty string"),
            Self::CustomKeywordTooLong(len) => {
                write!(f, "custom keyword exceeds max length 1024: {} chars", len)
            }
            Self::TooManyCustomKeywords(count) => {
                write!(f, "too many custom keywords (max 1000): {}", count)
            }
        }
    }
}

impl std::error::Error for DlpConfigError {}

/// Builder for RedactionConfig with common presets
#[derive(Debug, Clone, Default)]
pub struct RedactionConfigBuilder {
    default_mode: RedactionMode,
    per_type: HashMap<SensitiveDataType, RedactionMode>,
    hash_salt: Option<String>,
}

impl RedactionConfigBuilder {
    /// Create a new builder with default partial redaction
    pub fn new() -> Self {
        Self::default()
    }

    /// Preset: Mask all data types with full redaction
    pub fn mask_all() -> Self {
        Self {
            default_mode: RedactionMode::Full,
            per_type: HashMap::new(),
            hash_salt: None,
        }
    }

    /// Preset: Hash PII (SSN, medical records), mask credentials
    pub fn hash_pii_mask_credentials(salt: String) -> Self {
        let mut per_type = HashMap::new();
        per_type.insert(SensitiveDataType::Ssn, RedactionMode::Hash);
        per_type.insert(SensitiveDataType::MedicalRecord, RedactionMode::Hash);
        per_type.insert(SensitiveDataType::CreditCard, RedactionMode::Hash);
        per_type.insert(SensitiveDataType::Iban, RedactionMode::Hash);
        // Credentials use partial for debugging
        per_type.insert(SensitiveDataType::Password, RedactionMode::Full);
        per_type.insert(SensitiveDataType::ApiKey, RedactionMode::Partial);
        per_type.insert(SensitiveDataType::AwsKey, RedactionMode::Partial);
        Self {
            default_mode: RedactionMode::Partial,
            per_type,
            hash_salt: Some(salt),
        }
    }

    /// Set the default redaction mode for types not explicitly configured
    pub fn with_default(mut self, mode: RedactionMode) -> Self {
        self.default_mode = mode;
        self
    }

    /// Set redaction mode for a specific data type
    pub fn with_type(mut self, data_type: SensitiveDataType, mode: RedactionMode) -> Self {
        self.per_type.insert(data_type, mode);
        self
    }

    /// Set the hash salt (required if any type uses RedactionMode::Hash)
    pub fn with_salt(mut self, salt: String) -> Self {
        self.hash_salt = Some(salt);
        self
    }

    /// Build the redaction configuration
    pub fn build(self) -> (HashMap<SensitiveDataType, RedactionMode>, Option<String>) {
        (self.per_type, self.hash_salt)
    }
}

/// DLP configuration
#[derive(Debug, Clone, Deserialize)]
pub struct DlpConfig {
    pub enabled: bool,
    /// Maximum body size to accept for scanning (reject if larger)
    pub max_scan_size: usize,
    /// Maximum matches before stopping scan
    pub max_matches: usize,
    /// Only scan text-based content types
    pub scan_text_only: bool,
    /// Maximum bytes to inspect for DLP patterns (truncate if larger).
    /// This bounds scan time for large payloads. Default 8KB.
    /// Content beyond this limit is not scanned but the request continues.
    pub max_body_inspection_bytes: usize,
    /// Fast mode: Skip low-priority patterns (email, phone, IPv4) for better performance.
    /// Only scans critical patterns: credit cards, SSN, AWS keys, API keys, passwords, private keys, JWT, IBAN, medical records.
    /// Reduces scan time by ~30-40% for typical payloads.
    pub fast_mode: bool,
    /// List of custom keywords to detect (e.g., project codenames)
    pub custom_keywords: Option<Vec<String>>,
    /// Redaction settings per data type
    #[serde(default)]
    pub redaction: HashMap<SensitiveDataType, RedactionMode>,
    /// Salt for hash-based redaction (REQUIRED if any type uses RedactionMode::Hash)
    /// Should be a cryptographically random string, at least 32 bytes
    pub hash_salt: Option<String>,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_scan_size: 5 * 1024 * 1024, // 5MB max (reject if larger)
            max_matches: 100,               // Stop after 100 matches
            scan_text_only: true,
            max_body_inspection_bytes: 8 * 1024, // 8KB inspection cap for performance
            fast_mode: false,                    // Disabled by default for comprehensive scanning
            custom_keywords: None,
            redaction: HashMap::new(),
            hash_salt: None,
        }
    }
}

impl DlpConfig {
    /// Validate the configuration
    /// Returns error if:
    /// - Any data type uses Hash mode but no salt is configured
    /// - Custom keywords contain empty strings or exceed length limits
    pub fn validate(&self) -> Result<(), DlpConfigError> {
        // Check if hash mode is used without salt
        let uses_hash = self.redaction.values().any(|m| *m == RedactionMode::Hash);
        if uses_hash && self.hash_salt.is_none() {
            return Err(DlpConfigError::HashModeRequiresSalt);
        }

        // Validate custom keywords
        if let Some(keywords) = &self.custom_keywords {
            if keywords.len() > 1000 {
                return Err(DlpConfigError::TooManyCustomKeywords(keywords.len()));
            }
            for kw in keywords {
                if kw.is_empty() {
                    return Err(DlpConfigError::EmptyCustomKeyword);
                }
                if kw.len() > 1024 {
                    return Err(DlpConfigError::CustomKeywordTooLong(kw.len()));
                }
            }
        }

        Ok(())
    }

    /// Get the maximum pattern length for overlap calculation
    /// Returns the longest pattern that could span chunk boundaries
    pub fn max_pattern_length(&self) -> usize {
        // Longest built-in patterns:
        // - Private key headers: ~60 chars
        // - JWT tokens: can be very long (1000+)
        // - IBAN: 34 chars
        // - Custom keywords: up to 1024 chars
        let builtin_max = 100; // Conservative estimate for most patterns
        let custom_max = self
            .custom_keywords
            .as_ref()
            .map(|kws| kws.iter().map(|k| k.len()).max().unwrap_or(0))
            .unwrap_or(0);
        builtin_max.max(custom_max)
    }
}

/// Internal pattern definition
struct Pattern {
    name: &'static str,
    data_type: SensitiveDataType,
    severity: PatternSeverity,
    regex: &'static Regex,
    validator: Option<fn(&str) -> bool>,
}

// ============================================================================
// Validators
// ============================================================================

/// Validate credit card using Luhn algorithm (zero-allocation implementation)
pub fn validate_credit_card(number: &str) -> bool {
    let mut sum = 0u32;
    let mut digit_count = 0usize;
    let mut has_nonzero = false;
    let mut is_even = false;

    // Process digits from right to left without allocation
    for c in number.chars().rev() {
        if !c.is_ascii_digit() {
            continue;
        }

        let mut digit = c.to_digit(10).unwrap_or(0);
        digit_count += 1;

        if digit != 0 {
            has_nonzero = true;
        }

        if is_even {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }

        sum += digit;
        is_even = !is_even;
    }

    // Valid card: 13-19 digits, not all zeros, Luhn checksum passes
    digit_count >= 13 && digit_count <= 19 && has_nonzero && sum % 10 == 0
}

/// Validate SSN format (zero-allocation implementation)
///
/// Validates against SSA rules including:
/// - Invalid area numbers (000, 666, 900-999 reserved for ITIN)
/// - Invalid group numbers (00)
/// - Invalid serial numbers (0000)
/// - Advertising SSNs (987-65-4320 through 987-65-4329 used in commercials)
pub fn validate_ssn(ssn: &str) -> bool {
    // Parse digits in-place without allocation
    let mut area: u32 = 0;
    let mut group: u32 = 0;
    let mut serial: u32 = 0;
    let mut digit_count = 0;

    for c in ssn.chars() {
        if let Some(d) = c.to_digit(10) {
            match digit_count {
                0..=2 => area = area * 10 + d,
                3..=4 => group = group * 10 + d,
                5..=8 => serial = serial * 10 + d,
                _ => return false, // Too many digits
            }
            digit_count += 1;
        }
    }

    // Must have exactly 9 digits
    if digit_count != 9 {
        return false;
    }

    // Area cannot be 000, 666, or 900-999 (ITIN range)
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Group cannot be 00
    if group == 0 {
        return false;
    }

    // Serial cannot be 0000
    if serial == 0 {
        return false;
    }

    // Reject advertising SSNs used in commercials (987-65-4320 to 987-65-4329)
    if area == 987 && group == 65 && (4320..=4329).contains(&serial) {
        return false;
    }

    true
}

/// Validate US phone number format (zero-allocation implementation)
///
/// Reduces false positives by checking:
/// - Must be 10 or 11 digits (with country code)
/// - If 11 digits, must start with 1
/// - Area code cannot be N11 (e.g., 411, 911 - service codes)
pub fn validate_phone(phone: &str) -> bool {
    // Parse digits in-place without allocation
    // Max 11 digits (with country code)
    let mut digits = [0u8; 11];
    let mut digit_count = 0;

    for c in phone.chars() {
        if let Some(d) = c.to_digit(10) {
            if digit_count >= 11 {
                return false; // Too many digits
            }
            digits[digit_count] = d as u8;
            digit_count += 1;
        }
    }

    // Must be 10 or 11 digits
    if digit_count != 10 && digit_count != 11 {
        return false;
    }

    // If 11 digits, must start with country code 1
    if digit_count == 11 && digits[0] != 1 {
        return false;
    }

    // Get area code (skip country code if present)
    let area_start = if digit_count == 11 { 1 } else { 0 };
    let area_code: u32 = (digits[area_start] as u32) * 100
        + (digits[area_start + 1] as u32) * 10
        + (digits[area_start + 2] as u32);

    // Area code cannot be 0xx or 1xx
    if area_code < 200 {
        return false;
    }

    // Area code cannot be N11 (service codes like 411, 911)
    if area_code % 100 == 11 {
        return false;
    }

    true
}

/// Country-specific IBAN lengths (ISO 13616)
const IBAN_LENGTHS: &[(&str, usize)] = &[
    ("AL", 28),
    ("AD", 24),
    ("AT", 20),
    ("AZ", 28),
    ("BH", 22),
    ("BY", 28),
    ("BE", 16),
    ("BA", 20),
    ("BR", 29),
    ("BG", 22),
    ("CR", 22),
    ("HR", 21),
    ("CY", 28),
    ("CZ", 24),
    ("DK", 18),
    ("DO", 28),
    ("TL", 23),
    ("EE", 20),
    ("FO", 18),
    ("FI", 18),
    ("FR", 27),
    ("GE", 22),
    ("DE", 22),
    ("GI", 23),
    ("GR", 27),
    ("GL", 18),
    ("GT", 28),
    ("HU", 28),
    ("IS", 26),
    ("IQ", 23),
    ("IE", 22),
    ("IL", 23),
    ("IT", 27),
    ("JO", 30),
    ("KZ", 20),
    ("XK", 20),
    ("KW", 30),
    ("LV", 21),
    ("LB", 28),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("MK", 19),
    ("MT", 31),
    ("MR", 27),
    ("MU", 30),
    ("MC", 27),
    ("MD", 24),
    ("ME", 22),
    ("NL", 18),
    ("NO", 15),
    ("PK", 24),
    ("PS", 29),
    ("PL", 28),
    ("PT", 25),
    ("QA", 29),
    ("RO", 24),
    ("SM", 27),
    ("SA", 24),
    ("RS", 22),
    ("SC", 31),
    ("SK", 24),
    ("SI", 19),
    ("ES", 24),
    ("SE", 24),
    ("CH", 21),
    ("TN", 24),
    ("TR", 26),
    ("UA", 29),
    ("AE", 23),
    ("GB", 22),
    ("VA", 22),
    ("VG", 24),
];

/// Validate IBAN format using mod-97 check with country-specific length validation
/// (zero-allocation implementation)
///
/// Uses in-place character iteration and direct mod-97 computation without
/// building intermediate strings. Letters are converted to their numeric
/// representation (A=10, B=11, etc.) and processed directly in the modulo chain.
pub fn validate_iban(iban: &str) -> bool {
    // First pass: count length, extract first 4 chars, validate basic format
    // Store first 4 characters (country code + check digits) as bytes for later
    let mut first_four = [0u8; 4];
    let mut first_four_idx = 0;
    let mut total_len = 0;

    for c in iban.chars() {
        if c.is_whitespace() {
            continue;
        }
        let upper = c.to_ascii_uppercase();

        if total_len < 4 {
            // Validate format: first 2 must be letters, next 2 must be digits
            match total_len {
                0 | 1 => {
                    if !upper.is_ascii_alphabetic() {
                        return false;
                    }
                }
                2 | 3 => {
                    if !upper.is_ascii_digit() {
                        return false;
                    }
                }
                _ => {}
            }
            first_four[first_four_idx] = upper as u8;
            first_four_idx += 1;
        }
        total_len += 1;
    }

    // IBAN must be 15-34 characters (after removing whitespace)
    if total_len < 15 || total_len > 34 {
        return false;
    }

    // Validate country-specific length if known
    // Country code is first two characters
    let country_code = [first_four[0], first_four[1]];
    for &(code, expected_len) in IBAN_LENGTHS.iter() {
        if code.as_bytes() == &country_code {
            if total_len != expected_len {
                return false;
            }
            break;
        }
    }

    // Second pass: compute mod-97 directly
    // IBAN validation rearranges: BBAN (chars 4+) followed by country+check (chars 0-3)
    // We process each character, converting letters to their numeric value (A=10..Z=35)
    // For letters (2 digits), we do: remainder = (remainder * 100 + value) % 97
    // For digits (1 digit), we do: remainder = (remainder * 10 + digit) % 97
    let mut remainder: u64 = 0;
    let mut char_idx = 0;

    // Process BBAN first (skip first 4 characters)
    for c in iban.chars() {
        if c.is_whitespace() {
            continue;
        }
        char_idx += 1;
        if char_idx <= 4 {
            continue; // Skip country code and check digits
        }

        let upper = c.to_ascii_uppercase();
        if upper.is_ascii_alphabetic() {
            // A=10, B=11, ..., Z=35 (two digits, so multiply by 100)
            let value = (upper as u64) - ('A' as u64) + 10;
            remainder = (remainder * 100 + value) % 97;
        } else if let Some(d) = upper.to_digit(10) {
            remainder = (remainder * 10 + d as u64) % 97;
        }
    }

    // Now process the first 4 characters (country code + check digits)
    for &byte in &first_four {
        let c = byte as char;
        if c.is_ascii_alphabetic() {
            let value = (c as u64) - ('A' as u64) + 10;
            remainder = (remainder * 100 + value) % 97;
        } else if let Some(d) = c.to_digit(10) {
            remainder = (remainder * 10 + d as u64) % 97;
        }
    }

    remainder == 1
}

// ============================================================================
// Compiled Patterns
// ============================================================================

lazy_static! {
    // Credit Cards - handle mixed separators (spaces, dashes, or none)
    // Pattern allows any combination: "1234 5678-9012 3456" or "1234-5678 9012-3456"
    static ref RE_VISA: Regex = Regex::new(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
        .expect("RE_VISA is a valid regex pattern");
    static ref RE_MASTERCARD: Regex = Regex::new(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
        .expect("RE_MASTERCARD is a valid regex pattern");
    static ref RE_AMEX: Regex = Regex::new(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b")
        .expect("RE_AMEX is a valid regex pattern");
    static ref RE_DISCOVER: Regex = Regex::new(r"\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
        .expect("RE_DISCOVER is a valid regex pattern");

    // SSN
    static ref RE_SSN_FORMATTED: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
        .expect("RE_SSN_FORMATTED is a valid regex pattern");
    // Note: Using \b instead of lookaround (not supported by Rust regex)
    // The SSN validator filters out false positives anyway
    static ref RE_SSN_UNFORMATTED: Regex = Regex::new(r"\b\d{9}\b")
        .expect("RE_SSN_UNFORMATTED is a valid regex pattern");

    // Email - length limits prevent ReDoS via catastrophic backtracking
    static ref RE_EMAIL: Regex = Regex::new(r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,10}\b")
        .expect("RE_EMAIL is a valid regex pattern");

    // Phone
    static ref RE_US_PHONE: Regex = Regex::new(r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b")
        .expect("RE_US_PHONE is a valid regex pattern");
    static ref RE_INTL_PHONE: Regex = Regex::new(r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}")
        .expect("RE_INTL_PHONE is a valid regex pattern");

    // AWS
    static ref RE_AWS_ACCESS_KEY: Regex = Regex::new(r"\b(AKIA[0-9A-Z]{16})\b")
        .expect("RE_AWS_ACCESS_KEY is a valid regex pattern");
    static ref RE_AWS_SECRET_KEY: Regex = Regex::new(r"\b([a-zA-Z0-9+/]{40})\b")
        .expect("RE_AWS_SECRET_KEY is a valid regex pattern");
    static ref RE_AWS_SESSION_TOKEN: Regex = Regex::new(r#"(?i)aws.{0,10}session.{0,10}token.{0,5}['"]?([A-Za-z0-9/+=]{100,})"#)
        .expect("RE_AWS_SESSION_TOKEN is a valid regex pattern");

    // API Keys
    static ref RE_GENERIC_API_KEY: Regex = Regex::new(r"(?i)\b(?:api[_-]?key|apikey)[\s]*[=:]\s*['\x22]?([a-zA-Z0-9_-]{20,})['\x22]?")
        .expect("RE_GENERIC_API_KEY is a valid regex pattern");
    static ref RE_GITHUB_TOKEN: Regex = Regex::new(r"\b(gh[ps]_[a-zA-Z0-9]{36,})\b")
        .expect("RE_GITHUB_TOKEN is a valid regex pattern");
    static ref RE_GITHUB_FINE_GRAINED_PAT: Regex = Regex::new(r"\b(github_pat_[a-zA-Z0-9_]{22,})\b")
        .expect("RE_GITHUB_FINE_GRAINED_PAT is a valid regex pattern");
    static ref RE_STRIPE_KEY: Regex = Regex::new(r"\b((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,})\b")
        .expect("RE_STRIPE_KEY is a valid regex pattern");
    static ref RE_GOOGLE_API_KEY: Regex = Regex::new(r"AIza[a-zA-Z0-9_-]{35}")
        .expect("RE_GOOGLE_API_KEY is a valid regex pattern");

    // Passwords
    static ref RE_PASSWORD_URL: Regex = Regex::new(r"(?i)\b(?:password|passwd|pwd)=([^\s&]+)")
        .expect("RE_PASSWORD_URL is a valid regex pattern");
    static ref RE_PASSWORD_JSON: Regex = Regex::new(r#"(?i)"(?:password|passwd|pwd)"\s*:\s*"([^"]+)""#)
        .expect("RE_PASSWORD_JSON is a valid regex pattern");

    // IBAN
    static ref RE_IBAN: Regex = Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
        .expect("RE_IBAN is a valid regex pattern");

    // IP Address
    static ref RE_IPV4: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        .expect("RE_IPV4 is a valid regex pattern");

    // Private Keys
    static ref RE_RSA_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----")
        .expect("RE_RSA_PRIVATE_KEY is a valid regex pattern");
    static ref RE_EC_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----")
        .expect("RE_EC_PRIVATE_KEY is a valid regex pattern");

    // JWT - minimum segment lengths reduce false positives on base64 data
    static ref RE_JWT: Regex = Regex::new(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,})\b")
        .expect("RE_JWT is a valid regex pattern");

    // Medical Record
    static ref RE_MEDICAL_RECORD: Regex = Regex::new(r"(?i)\b(?:MRN|medical[_\s-]?record[_\s-]?(?:number|#|num))[\s:]*([A-Z0-9]{6,})")
        .expect("RE_MEDICAL_RECORD is a valid regex pattern");

    /// All patterns for scanning
    static ref PATTERNS: Vec<Pattern> = vec![
        // Credit Cards
        Pattern { name: "Visa Card", data_type: SensitiveDataType::CreditCard, severity: PatternSeverity::Critical, regex: &RE_VISA, validator: Some(validate_credit_card) },
        Pattern { name: "MasterCard", data_type: SensitiveDataType::CreditCard, severity: PatternSeverity::Critical, regex: &RE_MASTERCARD, validator: Some(validate_credit_card) },
        Pattern { name: "American Express", data_type: SensitiveDataType::CreditCard, severity: PatternSeverity::Critical, regex: &RE_AMEX, validator: Some(validate_credit_card) },
        Pattern { name: "Discover Card", data_type: SensitiveDataType::CreditCard, severity: PatternSeverity::Critical, regex: &RE_DISCOVER, validator: Some(validate_credit_card) },

        // SSN
        Pattern { name: "SSN (formatted)", data_type: SensitiveDataType::Ssn, severity: PatternSeverity::Critical, regex: &RE_SSN_FORMATTED, validator: Some(validate_ssn) },
        Pattern { name: "SSN (unformatted)", data_type: SensitiveDataType::Ssn, severity: PatternSeverity::Critical, regex: &RE_SSN_UNFORMATTED, validator: Some(validate_ssn) },

        // Email
        Pattern { name: "Email Address", data_type: SensitiveDataType::Email, severity: PatternSeverity::Medium, regex: &RE_EMAIL, validator: None },

        // Phone
        Pattern { name: "US Phone Number", data_type: SensitiveDataType::Phone, severity: PatternSeverity::Medium, regex: &RE_US_PHONE, validator: Some(validate_phone) },
        Pattern { name: "International Phone", data_type: SensitiveDataType::Phone, severity: PatternSeverity::Medium, regex: &RE_INTL_PHONE, validator: None },

        // AWS
        Pattern { name: "AWS Access Key", data_type: SensitiveDataType::AwsKey, severity: PatternSeverity::Critical, regex: &RE_AWS_ACCESS_KEY, validator: None },
        Pattern { name: "AWS Secret Key", data_type: SensitiveDataType::AwsKey, severity: PatternSeverity::Critical, regex: &RE_AWS_SECRET_KEY, validator: None },
        Pattern { name: "AWS Session Token", data_type: SensitiveDataType::AwsKey, severity: PatternSeverity::Critical, regex: &RE_AWS_SESSION_TOKEN, validator: None },

        // API Keys
        Pattern { name: "Generic API Key", data_type: SensitiveDataType::ApiKey, severity: PatternSeverity::High, regex: &RE_GENERIC_API_KEY, validator: None },
        Pattern { name: "GitHub Token", data_type: SensitiveDataType::ApiKey, severity: PatternSeverity::Critical, regex: &RE_GITHUB_TOKEN, validator: None },
        Pattern { name: "GitHub Fine-grained PAT", data_type: SensitiveDataType::ApiKey, severity: PatternSeverity::Critical, regex: &RE_GITHUB_FINE_GRAINED_PAT, validator: None },
        Pattern { name: "Stripe API Key", data_type: SensitiveDataType::ApiKey, severity: PatternSeverity::Critical, regex: &RE_STRIPE_KEY, validator: None },
        Pattern { name: "Google API Key", data_type: SensitiveDataType::ApiKey, severity: PatternSeverity::High, regex: &RE_GOOGLE_API_KEY, validator: None },

        // Passwords
        Pattern { name: "Password in URL", data_type: SensitiveDataType::Password, severity: PatternSeverity::Critical, regex: &RE_PASSWORD_URL, validator: None },
        Pattern { name: "Password in JSON", data_type: SensitiveDataType::Password, severity: PatternSeverity::Critical, regex: &RE_PASSWORD_JSON, validator: None },

        // IBAN
        Pattern { name: "IBAN", data_type: SensitiveDataType::Iban, severity: PatternSeverity::High, regex: &RE_IBAN, validator: Some(validate_iban) },

        // IP Address
        Pattern { name: "IPv4 Address", data_type: SensitiveDataType::IpAddress, severity: PatternSeverity::Low, regex: &RE_IPV4, validator: None },

        // Private Keys
        Pattern { name: "RSA Private Key", data_type: SensitiveDataType::PrivateKey, severity: PatternSeverity::Critical, regex: &RE_RSA_PRIVATE_KEY, validator: None },
        Pattern { name: "EC Private Key", data_type: SensitiveDataType::PrivateKey, severity: PatternSeverity::Critical, regex: &RE_EC_PRIVATE_KEY, validator: None },

        // JWT
        Pattern { name: "JWT Token", data_type: SensitiveDataType::Jwt, severity: PatternSeverity::High, regex: &RE_JWT, validator: None },

        // Medical Record
        Pattern { name: "Medical Record Number", data_type: SensitiveDataType::MedicalRecord, severity: PatternSeverity::Critical, regex: &RE_MEDICAL_RECORD, validator: None },
    ];

    // ========================================================================
    // Aho-Corasick Prefilter Automaton
    // ========================================================================
    //
    // For patterns with reliable literal prefixes, we use Aho-Corasick for
    // single-pass multi-pattern detection. This is O(n) in content length
    // regardless of pattern count, vs O(n * patterns) for sequential regex.
    //
    // Strategy: AC finds candidate regions, then we validate with full regex.

    /// Literal prefixes for Aho-Corasick prefiltering.
    /// Each entry: (literal_prefix, pattern_index_in_PATTERNS)
    ///
    /// PATTERNS order (for reference):
    ///  0: Visa, 1: MasterCard, 2: Amex, 3: Discover
    ///  4: SSN formatted, 5: SSN unformatted
    ///  6: Email, 7: US Phone, 8: Intl Phone
    ///  9: AWS Access Key, 10: AWS Secret Key, 11: AWS Session Token
    /// 12: Generic API Key, 13: GitHub Token, 14: GitHub Fine-grained PAT
    /// 15: Stripe API Key, 16: Google API Key
    /// 17: Password URL, 18: Password JSON
    /// 19: IBAN, 20: IPv4
    /// 21: RSA Private Key, 22: EC Private Key
    /// 23: JWT Token, 24: Medical Record
    static ref AC_PREFIXES: Vec<(&'static str, usize)> = vec![
        // Credit cards (indices 0-3): digit prefixes
        ("4", 0),      // Visa starts with 4
        ("51", 1), ("52", 1), ("53", 1), ("54", 1), ("55", 1), // MasterCard 51-55
        ("34", 2), ("37", 2), // Amex 34, 37
        ("6011", 3), ("65", 3), // Discover

        // AWS keys (indices 9-11)
        ("AKIA", 9),   // AWS Access Key (index 9)
        ("aws", 11), ("AWS", 11), // AWS Session Token (index 11)

        // API Keys (indices 12-16)
        ("api_key", 12), ("api-key", 12), ("apikey", 12), ("API_KEY", 12), // Generic API Key (12)
        ("ghp_", 13), ("ghs_", 13), // GitHub Token (13)
        ("github_pat_", 14), // GitHub Fine-grained PAT (14)
        ("sk_live_", 15), ("sk_test_", 15), ("pk_live_", 15), ("pk_test_", 15), ("rk_live_", 15), // Stripe (15)
        ("AIza", 16), // Google API Key (16)

        // Passwords (indices 17-18)
        ("password=", 17), ("passwd=", 17), ("pwd=", 17), // Password in URL (17)
        ("\"password\"", 18), ("\"passwd\"", 18), ("\"pwd\"", 18), // Password in JSON (18)

        // Private Keys (indices 21-22)
        ("-----BEGIN RSA PRIVATE KEY", 21),
        ("-----BEGIN PRIVATE KEY", 21),
        ("-----BEGIN EC PRIVATE KEY", 22),

        // JWT (index 23)
        ("eyJ", 23),

        // Email (index 6) - All emails contain @
        ("@", 6),
    ];

    /// Pre-computed bitmask of pattern indices covered by Aho-Corasick prefiltering.
    /// Each bit position corresponds to a PATTERNS index. If bit N is set, pattern N
    /// has a literal prefix in AC_PREFIXES and can be skipped if AC finds no matches.
    static ref AC_COVERED_MASK: u32 = {
        let mut mask: u32 = 0;
        for &(_, idx) in AC_PREFIXES.iter() {
            mask |= 1 << idx;
        }
        mask
    };

    // ========================================================================
    // RegexSet for Non-AC Patterns (Single-Pass Prefilter)
    // ========================================================================
    //
    // Patterns without reliable literal prefixes for Aho-Corasick are grouped
    // into a RegexSet for single-pass matching. This is O(n) vs O(n * patterns)
    // for sequential regex execution.
    //
    // When RegexSet matches, we only run the individual pattern regex + validator.

    /// Pattern indices that are NOT covered by Aho-Corasick prefiltering.
    /// These patterns will use RegexSet for single-pass detection.
    ///
    /// Non-AC patterns:
    ///  4: SSN formatted, 5: SSN unformatted
    ///  7: US Phone, 8: Intl Phone
    /// 10: AWS Secret Key
    /// 19: IBAN, 20: IPv4
    /// 24: Medical Record
    static ref NON_AC_PATTERN_INDICES: Vec<usize> = vec![4, 5, 7, 8, 10, 19, 20, 24];

    /// Pre-computed bitmask of pattern indices handled by RegexSet (non-AC patterns).
    /// Each bit position corresponds to a PATTERNS index.
    static ref NON_AC_PATTERN_MASK: u32 = {
        let mut mask: u32 = 0;
        for &idx in NON_AC_PATTERN_INDICES.iter() {
            mask |= 1 << idx;
        }
        mask
    };

    /// RegexSet for non-AC patterns - single pass detects which patterns have potential matches
    static ref NON_AC_REGEX_SET: RegexSet = RegexSet::new(&[
        // Index 0 -> Pattern 4: SSN formatted
        r"\b\d{3}-\d{2}-\d{4}\b",
        // Index 1 -> Pattern 5: SSN unformatted
        r"\b\d{9}\b",
        // Index 2 -> Pattern 7: US Phone
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        // Index 3 -> Pattern 8: International Phone
        r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
        // Index 4 -> Pattern 10: AWS Secret Key
        r"\b[a-zA-Z0-9+/]{40}\b",
        // Index 5 -> Pattern 19: IBAN
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        // Index 6 -> Pattern 20: IPv4
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        // Index 7 -> Pattern 24: Medical Record
        r"(?i)\b(?:MRN|medical[_\s-]?record[_\s-]?(?:number|#|num))[\s:]*[A-Z0-9]{6,}",
    ]).expect("Failed to build non-AC RegexSet");

    /// Binary content types that should be skipped for DLP scanning
    static ref SKIP_CONTENT_TYPES: Vec<&'static str> = vec![
        "image/",
        "audio/",
        "video/",
        "application/octet-stream",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-tar",
        "application/pdf",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
        "font/",
        "model/",
    ];
}

// ============================================================================
// DLP Scanner
// ============================================================================

/// Thread-safe DLP scanner
pub struct DlpScanner {
    config: DlpConfig,
    total_scans: AtomicU64,
    total_matches: AtomicU64,
    automaton: AhoCorasick,
    // Map automaton pattern ID to (is_custom, original_index)
    // If is_custom is false, original_index refers to PATTERNS index
    // If is_custom is true, original_index refers to custom_keywords index
    pattern_map: Vec<(bool, usize)>,
    /// Recent violations buffer (limited to last 100)
    recent_violations: Arc<RwLock<VecDeque<DlpViolation>>>,
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self::new(DlpConfig::default())
    }
}

impl DlpScanner {
    /// Create a new DLP scanner with the given configuration.
    ///
    /// # Panics
    /// Panics if configuration validation fails (e.g., Hash mode without salt).
    /// Use `try_new` for fallible construction.
    pub fn new(config: DlpConfig) -> Self {
        Self::try_new(config).expect("DLP config validation failed")
    }

    /// Create a new DLP scanner with validation.
    /// Returns error if configuration is invalid.
    pub fn try_new(config: DlpConfig) -> Result<Self, DlpConfigError> {
        // Validate configuration
        config.validate()?;

        // Force lazy_static initialization to validate all patterns at construction time.
        let pattern_count = PATTERNS.len();

        // Build combined patterns list for Aho-Corasick
        // 1. Standard prefixes
        let mut patterns = Vec::new();
        let mut pattern_map = Vec::new();

        for (prefix, idx) in AC_PREFIXES.iter() {
            patterns.push(prefix.to_string());
            pattern_map.push((false, *idx));
        }

        // 2. Custom keywords
        if let Some(keywords) = &config.custom_keywords {
            for (i, keyword) in keywords.iter().enumerate() {
                patterns.push(keyword.clone());
                pattern_map.push((true, i));
            }
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .expect("Failed to build Aho-Corasick automaton");

        log::debug!(
            "DLP scanner initialized with {} standard patterns and {} custom keywords",
            pattern_count,
            config
                .custom_keywords
                .as_ref()
                .map(|k| k.len())
                .unwrap_or(0)
        );

        Ok(Self {
            config,
            total_scans: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
            automaton,
            pattern_map,
            recent_violations: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        })
    }

    /// Check if scanner is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record violations from a scan result
    pub fn record_violations(&self, result: &ScanResult, client_ip: Option<&str>, path: &str) {
        if !result.has_matches {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut violations = match self.recent_violations.try_write() {
            Ok(guard) => guard,
            Err(_) => {
                // Best-effort capture. Avoid blocking in async contexts.
                return;
            }
        };

        for m in &result.matches {
            if violations.len() >= 100 {
                violations.pop_front();
            }

            violations.push_back(DlpViolation {
                timestamp: now,
                pattern_name: m.pattern_name.to_string(),
                data_type: m.data_type.as_str().to_string(),
                severity: m.severity.as_str().to_string(),
                masked_value: m.masked_value.clone(),
                client_ip: client_ip.map(|s| s.to_string()),
                path: path.to_string(),
            });
        }
    }

    /// Get recent violations
    pub async fn get_recent_violations(&self) -> Vec<DlpViolation> {
        let violations = self.recent_violations.read().await;
        violations.iter().cloned().rev().collect()
    }

    /// Scan content for sensitive data with optimizations:
    /// - Inspection depth cap (truncation for large payloads)
    /// - Aho-Corasick prefiltering for patterns with literal prefixes
    #[must_use = "scan results contain sensitive data findings that should be processed"]
    pub fn scan(&self, content: &str) -> ScanResult {
        if !self.config.enabled {
            return ScanResult::default();
        }

        let start = Instant::now();
        let original_length = content.len();

        // Check max size (hard limit - reject entirely)
        if original_length > self.config.max_scan_size {
            return ScanResult {
                scanned: false,
                content_length: original_length,
                ..Default::default()
            };
        }

        // Apply inspection depth cap (soft limit - truncate and continue)
        let (scan_content, truncated) = if original_length > self.config.max_body_inspection_bytes {
            // Find a safe truncation point (don't cut in middle of UTF-8 char)
            let mut truncate_at = self.config.max_body_inspection_bytes;
            while truncate_at > 0 && !content.is_char_boundary(truncate_at) {
                truncate_at -= 1;
            }
            log::debug!(
                "DLP: Truncating {} bytes to {} for inspection",
                original_length,
                truncate_at
            );
            (&content[..truncate_at], true)
        } else {
            (content, false)
        };

        let content_length = scan_content.len();
        let mut matches = Vec::new();

        // Phase 1: Use Aho-Corasick to find candidate positions for patterns with literal prefixes
        // This is O(n) single-pass vs O(n * patterns) for sequential regex
        // Using u32 bitset instead of HashSet to eliminate heap allocation (25 patterns fit in 32 bits)
        let mut ac_candidates: u32 = 0;
        for ac_match in self.automaton.find_iter(scan_content) {
            let pattern_id = ac_match.pattern().as_usize();
            if let Some((is_custom, idx)) = self.pattern_map.get(pattern_id) {
                if *is_custom {
                    // Direct match for custom keyword
                    if matches.len() < self.config.max_matches {
                        if let Some(keywords) = self.config.custom_keywords.as_ref() {
                            if let Some(_keyword) = keywords.get(*idx) {
                                matches.push(DlpMatch {
                                    pattern_name: "Custom Keyword",
                                    data_type: SensitiveDataType::Custom,
                                    severity: PatternSeverity::High,
                                    masked_value: "***".to_string(), // Simple mask for custom keywords
                                    start: ac_match.start(),
                                    end: ac_match.end(),
                                    stream_offset: None,
                                });
                            }
                        }
                    }
                } else {
                    // Candidate for standard pattern
                    ac_candidates |= 1 << idx;
                }
            }
        }

        // Phase 1b: Use RegexSet to find candidates for non-AC patterns (SSN, Phone, IBAN, IPv4, etc.)
        // This is O(n) single-pass for all non-AC patterns combined
        // Using u32 bitset instead of HashSet to eliminate heap allocation
        let regex_set_matches = NON_AC_REGEX_SET.matches(scan_content);
        let mut non_ac_candidates: u32 = 0;
        for (set_idx, &pattern_idx) in NON_AC_PATTERN_INDICES.iter().enumerate() {
            if regex_set_matches.matched(set_idx) {
                non_ac_candidates |= 1 << pattern_idx;
            }
        }

        // Phase 2: Scan with patterns - only scan patterns that have candidates from prefilters
        // AC_COVERED_MASK and NON_AC_PATTERN_MASK are pre-computed lazy_static u32 bitmasks

        // Fast mode skips low-priority patterns: Email(6), US Phone(7), Intl Phone(8), IPv4(20)
        const FAST_MODE_SKIP_PATTERNS: [usize; 4] = [6, 7, 8, 20];

        'outer: for (pattern_idx, pattern) in PATTERNS.iter().enumerate() {
            // Early exit if we've hit max matches
            if matches.len() >= self.config.max_matches {
                break 'outer;
            }

            // Fast mode: skip low-priority patterns (email, phone, IPv4)
            if self.config.fast_mode && FAST_MODE_SKIP_PATTERNS.contains(&pattern_idx) {
                continue;
            }

            let pattern_bit = 1u32 << pattern_idx;

            // Skip patterns covered by AC if AC didn't find any candidates
            // Using bitwise: check if pattern is in AC_COVERED_MASK but not in ac_candidates
            if (*AC_COVERED_MASK & pattern_bit) != 0 && (ac_candidates & pattern_bit) == 0 {
                continue;
            }

            // Skip non-AC patterns if RegexSet didn't find any candidates
            // Using bitwise: check if pattern is in NON_AC_PATTERN_MASK but not in non_ac_candidates
            if (*NON_AC_PATTERN_MASK & pattern_bit) != 0 && (non_ac_candidates & pattern_bit) == 0 {
                continue;
            }

            for m in pattern.regex.find_iter(scan_content) {
                // Check limit before processing each match
                if matches.len() >= self.config.max_matches {
                    break 'outer;
                }

                let matched_value = m.as_str();

                // Apply validator if present
                if let Some(validator) = pattern.validator {
                    if !validator(matched_value) {
                        continue;
                    }
                }

                let masked = self.mask_value(matched_value, pattern.data_type);

                matches.push(DlpMatch {
                    pattern_name: pattern.name,
                    data_type: pattern.data_type,
                    severity: pattern.severity,
                    masked_value: masked,
                    start: m.start(),
                    end: m.end(),
                    stream_offset: None,
                });
            }
        }

        let scan_time_us = start.elapsed().as_micros() as u64;
        let match_count = matches.len();

        // Update stats
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        self.total_matches
            .fetch_add(match_count as u64, Ordering::Relaxed);

        ScanResult {
            scanned: true,
            has_matches: !matches.is_empty(),
            matches,
            match_count,
            scan_time_us,
            content_length,
            truncated,
            original_length: if truncated { original_length } else { 0 },
        }
    }

    /// Scan bytes as UTF-8 text
    #[must_use = "scan results contain sensitive data findings that should be processed"]
    pub fn scan_bytes(&self, data: &[u8]) -> ScanResult {
        match std::str::from_utf8(data) {
            Ok(content) => self.scan(content),
            Err(_) => ScanResult::default(),
        }
    }

    /// Check if content type should be scanned.
    /// Returns false for binary types (images, audio, video, archives, etc.)
    /// Returns true for text-based types that may contain sensitive data.
    pub fn is_scannable_content_type(&self, content_type: &str) -> bool {
        let ct_lower = content_type.to_lowercase();

        // First check skip list (binary types)
        for skip_type in SKIP_CONTENT_TYPES.iter() {
            if ct_lower.starts_with(skip_type) || ct_lower.contains(skip_type) {
                return false;
            }
        }

        // Check for multipart/form-data with file uploads (skip files, scan form fields)
        // For now, skip all multipart to avoid scanning uploaded file contents
        if ct_lower.starts_with("multipart/") {
            return false;
        }

        // Scannable text types
        let text_types = [
            "text/",
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
            "application/javascript",
            "application/ld+json",
        ];

        text_types
            .iter()
            .any(|t| ct_lower.starts_with(t) || ct_lower.contains(t))
    }

    /// Quick check if content type should skip DLP entirely (binary content)
    pub fn should_skip_content_type(&self, content_type: &str) -> bool {
        !self.is_scannable_content_type(content_type)
    }

    /// Mask a sensitive value for logging
    fn mask_value(&self, value: &str, data_type: SensitiveDataType) -> String {
        let mode = self
            .config
            .redaction
            .get(&data_type)
            .copied()
            .unwrap_or_default();

        match mode {
            RedactionMode::None => return value.to_string(),
            RedactionMode::Hash => {
                // Use configured salt (validated at construction time if Hash mode is used)
                let salt = self.config.hash_salt.as_deref().unwrap_or("");
                let mut hasher = Sha256::new();
                hasher.update(salt.as_bytes());
                hasher.update(value.as_bytes());
                return format!("sha256:{:x}", hasher.finalize());
            }
            RedactionMode::Full => return "*".repeat(value.len().min(20)),
            RedactionMode::Partial => {} // Fall through to partial masking logic
        }

        match data_type {
            SensitiveDataType::CreditCard => {
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("****-****-****-{}", &digits[digits.len() - 4..])
                } else {
                    "****-****-****-****".to_string()
                }
            }
            SensitiveDataType::Ssn => {
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("***-**-{}", &digits[digits.len() - 4..])
                } else {
                    "***-**-****".to_string()
                }
            }
            SensitiveDataType::Email => {
                if let Some(at_idx) = value.find('@') {
                    let (local, domain) = value.split_at(at_idx);
                    let prefix = if local.len() >= 3 { &local[..3] } else { local };
                    format!("{}***{}", prefix, domain)
                } else {
                    "***@***.***".to_string()
                }
            }
            SensitiveDataType::Phone => {
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 4 {
                    format!("***-***-{}", &digits[digits.len() - 4..])
                } else {
                    "***-***-****".to_string()
                }
            }
            SensitiveDataType::Iban => {
                if value.len() >= 6 {
                    format!("{}************{}", &value[..2], &value[value.len() - 4..])
                } else {
                    "**************".to_string()
                }
            }
            SensitiveDataType::Jwt => "eyJ***.eyJ***.***".to_string(),
            SensitiveDataType::PrivateKey => "[PRIVATE KEY REDACTED]".to_string(),
            SensitiveDataType::AwsKey | SensitiveDataType::ApiKey => {
                if value.len() >= 4 {
                    format!("{}...{}", &value[..4], &value[value.len() - 4..])
                } else {
                    "********".to_string()
                }
            }
            SensitiveDataType::Password => "********".to_string(),
            SensitiveDataType::IpAddress => {
                // Mask middle octets
                let parts: Vec<&str> = value.split('.').collect();
                if parts.len() == 4 {
                    format!("{}.***.***.{}", parts[0], parts[3])
                } else {
                    "***.***.***.***".to_string()
                }
            }
            SensitiveDataType::MedicalRecord => "MRN: ********".to_string(),
            SensitiveDataType::Custom => "***".to_string(),
        }
    }

    /// Get scanner statistics
    pub fn stats(&self) -> DlpStats {
        DlpStats {
            total_scans: self.total_scans.load(Ordering::Relaxed),
            total_matches: self.total_matches.load(Ordering::Relaxed),
            matches_by_type: HashMap::new(), // Would need per-type counters for this
            matches_by_severity: HashMap::new(),
        }
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        PATTERNS.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ────────────────────────────────────────────────────────────────────────
    // Luhn Validation Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_luhn_valid_visa() {
        assert!(validate_credit_card("4532015112830366"));
        assert!(validate_credit_card("4532-0151-1283-0366"));
        assert!(validate_credit_card("4532 0151 1283 0366"));
    }

    #[test]
    fn test_luhn_valid_mastercard() {
        assert!(validate_credit_card("5425233430109903"));
    }

    #[test]
    fn test_luhn_valid_amex() {
        assert!(validate_credit_card("374245455400126"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!validate_credit_card("1234567890123456"));
        assert!(!validate_credit_card("0000000000000000"));
        assert!(!validate_credit_card("12345")); // Too short
    }

    // ────────────────────────────────────────────────────────────────────────
    // SSN Validation Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_ssn_valid() {
        assert!(validate_ssn("123-45-6789"));
        assert!(validate_ssn("123456789"));
    }

    #[test]
    fn test_ssn_invalid_area() {
        assert!(!validate_ssn("000-45-6789")); // Area 000
        assert!(!validate_ssn("666-45-6789")); // Area 666
        assert!(!validate_ssn("900-45-6789")); // Area 900+
    }

    #[test]
    fn test_ssn_invalid_group() {
        assert!(!validate_ssn("123-00-6789")); // Group 00
    }

    #[test]
    fn test_ssn_invalid_serial() {
        assert!(!validate_ssn("123-45-0000")); // Serial 0000
    }

    #[test]
    fn test_ssn_advertising_numbers() {
        // SSNs 987-65-4320 through 987-65-4329 are used in advertising/commercials
        // Note: These are also rejected by area >= 900 rule (ITIN range)
        // but we have explicit checks for documentation/defense-in-depth
        assert!(!validate_ssn("987-65-4320"));
        assert!(!validate_ssn("987-65-4325"));
        assert!(!validate_ssn("987-65-4329"));
        // All 9xx area codes are ITIN range and should be rejected
        assert!(!validate_ssn("987-65-4319"));
        assert!(!validate_ssn("987-65-4330"));
        assert!(!validate_ssn("900-12-3456"));
        assert!(!validate_ssn("999-99-9999"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Phone Validation Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_phone_valid() {
        assert!(validate_phone("212-555-1234"));
        assert!(validate_phone("(212) 555-1234"));
        assert!(validate_phone("1-212-555-1234"));
        assert!(validate_phone("12125551234"));
        assert!(validate_phone("2125551234"));
    }

    #[test]
    fn test_phone_invalid_length() {
        assert!(!validate_phone("555-1234")); // Too short
        assert!(!validate_phone("212-555-12345")); // Too long
    }

    #[test]
    fn test_phone_invalid_area_code() {
        assert!(!validate_phone("012-555-1234")); // 0xx area code
        assert!(!validate_phone("112-555-1234")); // 1xx area code
    }

    #[test]
    fn test_phone_service_codes() {
        // N11 codes are service numbers, not valid phone numbers
        assert!(!validate_phone("411-555-1234")); // Directory assistance
        assert!(!validate_phone("911-555-1234")); // Emergency
        assert!(!validate_phone("611-555-1234")); // Repair service
    }

    // ────────────────────────────────────────────────────────────────────────
    // IBAN Validation Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_iban_valid_de() {
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn test_iban_valid_gb() {
        assert!(validate_iban("GB82WEST12345698765432"));
    }

    #[test]
    fn test_iban_valid_with_spaces() {
        assert!(validate_iban("DE89 3704 0044 0532 0130 00"));
    }

    #[test]
    fn test_iban_invalid_checksum() {
        assert!(!validate_iban("DE00370400440532013000")); // Wrong check digits
    }

    #[test]
    fn test_iban_too_short() {
        assert!(!validate_iban("DE89370400")); // Too short
    }

    // ────────────────────────────────────────────────────────────────────────
    // Scanner Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_scanner_creation() {
        let scanner = DlpScanner::default();
        assert!(scanner.is_enabled());
        assert_eq!(scanner.pattern_count(), 25); // 24 base + 1 GitHub Fine-grained PAT
    }

    #[test]
    fn test_scanner_disabled() {
        let config = DlpConfig {
            enabled: false,
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);
        let result = scanner.scan("4532015112830366");
        assert!(!result.scanned);
    }

    #[test]
    fn test_scan_credit_card() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("My card is 4532015112830366");

        assert!(result.scanned);
        assert!(result.has_matches);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::CreditCard);
        assert_eq!(result.matches[0].severity, PatternSeverity::Critical);
    }

    #[test]
    fn test_scan_ssn() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("SSN: 123-45-6789");

        assert!(result.has_matches);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::Ssn);
    }

    #[test]
    fn test_scan_email() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("Contact: user@example.com");

        assert!(result.has_matches);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::Email);
        assert_eq!(result.matches[0].severity, PatternSeverity::Medium);
    }

    #[test]
    fn test_scan_jwt() {
        let scanner = DlpScanner::default();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let result = scanner.scan(&format!("Token: {}", jwt));

        assert!(result.has_matches);
        let jwt_match = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::Jwt);
        assert!(jwt_match.is_some());
    }

    #[test]
    fn test_scan_aws_key() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");

        assert!(result.has_matches);
        let aws_match = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::AwsKey);
        assert!(aws_match.is_some());
    }

    #[test]
    fn test_scan_github_token() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        assert!(result.has_matches);
        let gh_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "GitHub Token");
        assert!(gh_match.is_some());
    }

    #[test]
    fn test_scan_github_fine_grained_pat() {
        let scanner = DlpScanner::default();
        let result = scanner
            .scan("GITHUB_TOKEN=github_pat_11ABCDEFG0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        assert!(result.has_matches);
        let gh_match = result
            .matches
            .iter()
            .find(|m| m.pattern_name == "GitHub Fine-grained PAT");
        assert!(gh_match.is_some(), "Should detect GitHub fine-grained PAT");
    }

    #[test]
    fn test_scan_stripe_keys() {
        let scanner = DlpScanner::default();

        // Secret key
        let result = scanner.scan("STRIPE_SECRET_KEY=sk_live_51ABCdefGHI123456789012345");
        assert!(result.has_matches, "Should detect Stripe secret key");

        // Publishable key
        let result = scanner.scan("STRIPE_PK=pk_test_51ABCdefGHI123456789012345");
        assert!(result.has_matches, "Should detect Stripe publishable key");

        // Restricted key (new)
        let result = scanner.scan("STRIPE_RK=rk_live_51ABCdefGHI123456789012345");
        assert!(result.has_matches, "Should detect Stripe restricted key");
    }

    #[test]
    fn test_scan_private_key() {
        let scanner = DlpScanner::default();
        let key =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let result = scanner.scan(key);

        assert!(result.has_matches);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::PrivateKey);
    }

    #[test]
    fn test_scan_password_in_url() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("https://api.example.com/login?password=secret123");

        assert!(result.has_matches);
        let pwd_match = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::Password);
        assert!(pwd_match.is_some());
    }

    #[test]
    fn test_scan_password_in_json() {
        let scanner = DlpScanner::default();
        let result = scanner.scan(r#"{"username": "admin", "password": "secret123"}"#);

        assert!(result.has_matches);
        let pwd_match = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::Password);
        assert!(pwd_match.is_some());
    }

    #[test]
    fn test_scan_no_matches() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("This is just normal text with no sensitive data.");

        assert!(result.scanned);
        assert!(!result.has_matches);
        assert_eq!(result.match_count, 0);
    }

    #[test]
    fn test_scan_multiple_matches() {
        let scanner = DlpScanner::default();
        let content = "Card: 4532015112830366, SSN: 123-45-6789, Email: test@example.com";
        let result = scanner.scan(content);

        assert!(result.has_matches);
        assert!(result.match_count >= 3);
    }

    #[test]
    fn test_masking() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("4532015112830366");

        assert!(result.has_matches);
        assert!(result.matches[0].masked_value.contains("****"));
        assert!(result.matches[0].masked_value.ends_with("0366"));
    }

    #[test]
    fn test_content_type_detection() {
        let scanner = DlpScanner::default();

        assert!(scanner.is_scannable_content_type("text/html"));
        assert!(scanner.is_scannable_content_type("application/json"));
        assert!(scanner.is_scannable_content_type("application/xml"));
        assert!(!scanner.is_scannable_content_type("image/png"));
        assert!(!scanner.is_scannable_content_type("application/octet-stream"));
    }

    #[test]
    fn test_stats() {
        let scanner = DlpScanner::default();
        scanner.scan("Card: 4532015112830366");
        scanner.scan("No sensitive data here");

        let stats = scanner.stats();
        assert_eq!(stats.total_scans, 2);
        assert!(stats.total_matches >= 1);
    }

    #[test]
    fn test_custom_keywords() {
        let config = DlpConfig {
            enabled: true,
            custom_keywords: Some(vec!["ProjectX".to_string(), "InternalID-123".to_string()]),
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        let result = scanner.scan("Confidential: ProjectX launch date is soon.");
        assert!(result.has_matches);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::Custom);

        let result2 = scanner.scan("User ID: InternalID-123");
        assert!(result2.has_matches);
        assert_eq!(result2.matches[0].data_type, SensitiveDataType::Custom);
    }

    #[test]
    fn test_redaction_modes() {
        let mut redaction = HashMap::new();
        redaction.insert(SensitiveDataType::CreditCard, RedactionMode::Full);
        redaction.insert(SensitiveDataType::Email, RedactionMode::Hash);

        let config = DlpConfig {
            enabled: true,
            redaction,
            hash_salt: Some("test-salt-for-hashing".to_string()), // Required for Hash mode
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        let result = scanner.scan("Card: 4532015112830366, Email: test@example.com");

        // Full redaction for card
        let card = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::CreditCard)
            .unwrap();
        assert!(card.masked_value.chars().all(|c| c == '*'));
        assert!(!card.masked_value.contains("0366")); // No partial reveal

        // Hash redaction for email
        let email = result
            .matches
            .iter()
            .find(|m| m.data_type == SensitiveDataType::Email)
            .unwrap();
        assert!(email.masked_value.starts_with("sha256:"));
        assert!(!email.masked_value.contains("test@example.com"));
    }

    // ────────────────────────────────────────────────────────────────────────
    // Performance Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_performance() {
        // Use a scanner with high inspection cap to test full 100KB scan
        let config = DlpConfig {
            enabled: true,
            max_scan_size: 5 * 1024 * 1024,
            max_matches: 100,
            scan_text_only: true,
            max_body_inspection_bytes: 200 * 1024, // 200KB cap for this test
            fast_mode: false,
            ..Default::default()
        };
        let scanner = DlpScanner::new(config);

        // Generate 100KB of content with some sensitive data
        let mut content = String::with_capacity(100_000);
        for i in 0..1000 {
            content.push_str(&format!("Line {}: This is normal text content.\n", i));
            if i % 100 == 0 {
                content.push_str("Credit card: 4532015112830366\n");
            }
        }

        let result = scanner.scan(&content);

        // Should complete in reasonable time
        // Debug mode: up to 75ms (allows for 24 patterns + system load), Release mode: under 5ms
        #[cfg(debug_assertions)]
        let max_time_us = 75_000;
        #[cfg(not(debug_assertions))]
        let max_time_us = 5_000;

        assert!(
            result.scan_time_us < max_time_us,
            "Scan took {}μs, expected < {}μs for 100KB",
            result.scan_time_us,
            max_time_us
        );
        assert!(result.match_count >= 10); // At least 10 credit cards
    }

    #[test]
    fn test_truncation() {
        // Default scanner with 8KB cap
        let scanner = DlpScanner::default();

        // Generate 20KB of content with credit card at the start
        let mut content = String::from("Credit card: 4532015112830366\n");
        for _ in 0..500 {
            content.push_str("Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n");
        }

        let result = scanner.scan(&content);

        // Should be truncated and still find the credit card
        assert!(result.truncated);
        assert!(result.original_length > result.content_length);
        assert!(result.has_matches);
        assert_eq!(result.match_count, 1);
    }

    #[test]
    fn test_fast_mode() {
        // Content with both critical and low-priority patterns
        let content = r#"
            Critical data:
            Credit card: 4532015112830366
            SSN: 123-45-6789
            AWS Key: AKIAIOSFODNN7EXAMPLE

            Low-priority data (skipped in fast mode):
            Email: user@example.com
            Phone: (555) 123-4567
            IP: 192.168.1.1
        "#;

        // Normal scanner should find all matches
        let normal_scanner = DlpScanner::default();
        let normal_result = normal_scanner.scan(content);

        // Fast mode scanner should skip email, phone, IP
        let fast_config = DlpConfig {
            fast_mode: true,
            ..Default::default()
        };
        let fast_scanner = DlpScanner::new(fast_config);
        let fast_result = fast_scanner.scan(content);

        // Normal mode finds more patterns (includes email, phone, IP)
        assert!(
            normal_result.match_count > fast_result.match_count,
            "Normal mode ({}) should find more matches than fast mode ({})",
            normal_result.match_count,
            fast_result.match_count
        );

        // Fast mode should still find critical patterns (credit card, SSN, AWS key)
        assert!(
            fast_result.match_count >= 3,
            "Fast mode should find at least 3 critical matches, found {}",
            fast_result.match_count
        );

        // Verify fast mode doesn't find email/phone/IP
        let fast_types: Vec<_> = fast_result.matches.iter().map(|m| m.data_type).collect();
        assert!(
            !fast_types.contains(&SensitiveDataType::Email),
            "Fast mode should not detect emails"
        );
        assert!(
            !fast_types.contains(&SensitiveDataType::Phone),
            "Fast mode should not detect phone numbers"
        );
        assert!(
            !fast_types.contains(&SensitiveDataType::IpAddress),
            "Fast mode should not detect IP addresses"
        );
    }
}
