//! DLP Scanner Implementation
//!
//! Thread-safe scanner for detecting sensitive data in response bodies.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Sensitive data type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        }
    }
}

/// Pattern severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    pub pattern_name: String,
    pub data_type: SensitiveDataType,
    pub severity: PatternSeverity,
    pub masked_value: String,
    pub start: usize,
    pub end: usize,
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

/// DLP configuration
#[derive(Debug, Clone)]
pub struct DlpConfig {
    pub enabled: bool,
    pub max_scan_size: usize,
    pub max_matches: usize,
    pub scan_text_only: bool,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_scan_size: 5 * 1024 * 1024, // 5MB max
            max_matches: 100, // Stop after 100 matches
            scan_text_only: true,
        }
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

/// Validate SSN format
///
/// Validates against SSA rules including:
/// - Invalid area numbers (000, 666, 900-999 reserved for ITIN)
/// - Invalid group numbers (00)
/// - Invalid serial numbers (0000)
/// - Advertising SSNs (987-65-4320 through 987-65-4329 used in commercials)
pub fn validate_ssn(ssn: &str) -> bool {
    // Remove all non-digits
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();

    if digits.len() != 9 {
        return false;
    }

    let area: u32 = digits[0..3].parse().unwrap_or(0);
    let group: u32 = digits[3..5].parse().unwrap_or(0);
    let serial: u32 = digits[5..9].parse().unwrap_or(0);

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

/// Validate US phone number format
///
/// Reduces false positives by checking:
/// - Must be 10 or 11 digits (with country code)
/// - If 11 digits, must start with 1
/// - Area code cannot be N11 (e.g., 411, 911 - service codes)
pub fn validate_phone(phone: &str) -> bool {
    // Extract only digits
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();

    // Must be 10 or 11 digits
    if digits.len() != 10 && digits.len() != 11 {
        return false;
    }

    // If 11 digits, must start with country code 1
    if digits.len() == 11 && !digits.starts_with('1') {
        return false;
    }

    // Get area code (skip country code if present)
    let area_start = if digits.len() == 11 { 1 } else { 0 };
    let area_code: u32 = digits[area_start..area_start + 3].parse().unwrap_or(0);

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
    ("AL", 28), ("AD", 24), ("AT", 20), ("AZ", 28), ("BH", 22),
    ("BY", 28), ("BE", 16), ("BA", 20), ("BR", 29), ("BG", 22),
    ("CR", 22), ("HR", 21), ("CY", 28), ("CZ", 24), ("DK", 18),
    ("DO", 28), ("TL", 23), ("EE", 20), ("FO", 18), ("FI", 18),
    ("FR", 27), ("GE", 22), ("DE", 22), ("GI", 23), ("GR", 27),
    ("GL", 18), ("GT", 28), ("HU", 28), ("IS", 26), ("IQ", 23),
    ("IE", 22), ("IL", 23), ("IT", 27), ("JO", 30), ("KZ", 20),
    ("XK", 20), ("KW", 30), ("LV", 21), ("LB", 28), ("LI", 21),
    ("LT", 20), ("LU", 20), ("MK", 19), ("MT", 31), ("MR", 27),
    ("MU", 30), ("MC", 27), ("MD", 24), ("ME", 22), ("NL", 18),
    ("NO", 15), ("PK", 24), ("PS", 29), ("PL", 28), ("PT", 25),
    ("QA", 29), ("RO", 24), ("SM", 27), ("SA", 24), ("RS", 22),
    ("SC", 31), ("SK", 24), ("SI", 19), ("ES", 24), ("SE", 24),
    ("CH", 21), ("TN", 24), ("TR", 26), ("UA", 29), ("AE", 23),
    ("GB", 22), ("VA", 22), ("VG", 24),
];

/// Validate IBAN format using mod-97 check with country-specific length validation
pub fn validate_iban(iban: &str) -> bool {
    // Remove spaces and convert to uppercase
    let cleaned: String = iban
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();

    // IBAN must be 15-34 characters
    if cleaned.len() < 15 || cleaned.len() > 34 {
        return false;
    }

    // Must start with 2 letters followed by 2 digits
    let chars: Vec<char> = cleaned.chars().collect();
    if chars.len() < 4 {
        return false;
    }
    if !chars[0].is_ascii_alphabetic() || !chars[1].is_ascii_alphabetic() {
        return false;
    }
    if !chars[2].is_ascii_digit() || !chars[3].is_ascii_digit() {
        return false;
    }

    // Validate country-specific length if known
    let country_code: String = chars[0..2].iter().collect();
    if let Some(&(_, expected_len)) = IBAN_LENGTHS.iter().find(|(c, _)| *c == country_code) {
        if cleaned.len() != expected_len {
            return false;
        }
    }

    // Move first 4 characters to end
    let rearranged = format!("{}{}", &cleaned[4..], &cleaned[0..4]);

    // Convert letters to numbers (A=10, B=11, etc.)
    let mut numeric_string = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_alphabetic() {
            let value = c as u32 - 'A' as u32 + 10;
            numeric_string.push_str(&value.to_string());
        } else {
            numeric_string.push(c);
        }
    }

    // Calculate mod 97 using chunked approach (handles large numbers)
    let mut remainder: u64 = 0;
    for c in numeric_string.chars() {
        let digit = c.to_digit(10).unwrap_or(0) as u64;
        remainder = (remainder * 10 + digit) % 97;
    }

    remainder == 1
}

// ============================================================================
// Compiled Patterns
// ============================================================================

lazy_static! {
    // Credit Cards
    static ref RE_VISA: Regex = Regex::new(r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap();
    static ref RE_MASTERCARD: Regex = Regex::new(r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap();
    static ref RE_AMEX: Regex = Regex::new(r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b").unwrap();
    static ref RE_DISCOVER: Regex = Regex::new(r"\b6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap();

    // SSN
    static ref RE_SSN_FORMATTED: Regex = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap();
    // Note: Using \b instead of lookaround (not supported by Rust regex)
    // The SSN validator filters out false positives anyway
    static ref RE_SSN_UNFORMATTED: Regex = Regex::new(r"\b\d{9}\b").unwrap();

    // Email - length limits prevent ReDoS via catastrophic backtracking
    static ref RE_EMAIL: Regex = Regex::new(r"\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,10}\b").unwrap();

    // Phone
    static ref RE_US_PHONE: Regex = Regex::new(r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b").unwrap();
    static ref RE_INTL_PHONE: Regex = Regex::new(r"\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}").unwrap();

    // AWS
    static ref RE_AWS_ACCESS_KEY: Regex = Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap();
    static ref RE_AWS_SECRET_KEY: Regex = Regex::new(r"\b([a-zA-Z0-9+/]{40})\b").unwrap();
    static ref RE_AWS_SESSION_TOKEN: Regex = Regex::new(r#"(?i)aws.{0,10}session.{0,10}token.{0,5}['"]?([A-Za-z0-9/+=]{100,})"#).unwrap();

    // API Keys
    static ref RE_GENERIC_API_KEY: Regex = Regex::new(r"(?i)\b(?:api[_-]?key|apikey)[\s]*[=:]\s*['\x22]?([a-zA-Z0-9_-]{20,})['\x22]?").unwrap();
    static ref RE_GITHUB_TOKEN: Regex = Regex::new(r"\b(gh[ps]_[a-zA-Z0-9]{36,})\b").unwrap();
    static ref RE_GITHUB_FINE_GRAINED_PAT: Regex = Regex::new(r"\b(github_pat_[a-zA-Z0-9_]{22,})\b").unwrap();
    static ref RE_STRIPE_KEY: Regex = Regex::new(r"\b((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{24,})\b").unwrap();
    static ref RE_GOOGLE_API_KEY: Regex = Regex::new(r"AIza[a-zA-Z0-9_-]{35}").unwrap();

    // Passwords
    static ref RE_PASSWORD_URL: Regex = Regex::new(r"(?i)\b(?:password|passwd|pwd)=([^\s&]+)").unwrap();
    static ref RE_PASSWORD_JSON: Regex = Regex::new(r#"(?i)"(?:password|passwd|pwd)"\s*:\s*"([^"]+)""#).unwrap();

    // IBAN
    static ref RE_IBAN: Regex = Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap();

    // IP Address
    static ref RE_IPV4: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();

    // Private Keys
    static ref RE_RSA_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----").unwrap();
    static ref RE_EC_PRIVATE_KEY: Regex = Regex::new(r"-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----").unwrap();

    // JWT - minimum segment lengths reduce false positives on base64 data
    static ref RE_JWT: Regex = Regex::new(r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{20,})\b").unwrap();

    // Medical Record
    static ref RE_MEDICAL_RECORD: Regex = Regex::new(r"(?i)\b(?:MRN|medical[_\s-]?record[_\s-]?(?:number|#|num))[\s:]*([A-Z0-9]{6,})").unwrap();

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
}

// ============================================================================
// DLP Scanner
// ============================================================================

/// Thread-safe DLP scanner
pub struct DlpScanner {
    config: DlpConfig,
    total_scans: AtomicU64,
    total_matches: AtomicU64,
}

impl Default for DlpScanner {
    fn default() -> Self {
        Self::new(DlpConfig::default())
    }
}

impl DlpScanner {
    /// Create a new DLP scanner with the given configuration.
    ///
    /// This validates all regex patterns at construction time to fail fast
    /// if any pattern is invalid. Panics if pattern compilation fails.
    pub fn new(config: DlpConfig) -> Self {
        // Force lazy_static initialization to validate all patterns at construction time.
        // This ensures we fail fast rather than on first scan if a pattern is invalid.
        let pattern_count = PATTERNS.len();
        log::debug!("DLP scanner initialized with {} patterns", pattern_count);

        Self {
            config,
            total_scans: AtomicU64::new(0),
            total_matches: AtomicU64::new(0),
        }
    }

    /// Check if scanner is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Scan content for sensitive data
    pub fn scan(&self, content: &str) -> ScanResult {
        if !self.config.enabled {
            return ScanResult::default();
        }

        let start = Instant::now();
        let content_length = content.len();

        // Check max size
        if content_length > self.config.max_scan_size {
            return ScanResult {
                scanned: false,
                content_length,
                ..Default::default()
            };
        }

        let mut matches = Vec::new();

        // Scan with each pattern - use labeled break to exit both loops when limit reached
        'outer: for pattern in PATTERNS.iter() {
            // Early exit if we've hit max matches
            if matches.len() >= self.config.max_matches {
                break 'outer;
            }

            for m in pattern.regex.find_iter(content) {
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
                    pattern_name: pattern.name.to_string(),
                    data_type: pattern.data_type,
                    severity: pattern.severity,
                    masked_value: masked,
                    start: m.start(),
                    end: m.end(),
                });
            }
        }

        let scan_time_us = start.elapsed().as_micros() as u64;
        let match_count = matches.len();

        // Update stats
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        self.total_matches.fetch_add(match_count as u64, Ordering::Relaxed);

        ScanResult {
            scanned: true,
            has_matches: !matches.is_empty(),
            matches,
            match_count,
            scan_time_us,
            content_length,
        }
    }

    /// Scan bytes as UTF-8 text
    pub fn scan_bytes(&self, data: &[u8]) -> ScanResult {
        match std::str::from_utf8(data) {
            Ok(content) => self.scan(content),
            Err(_) => ScanResult::default(),
        }
    }

    /// Check if content type is text-based (should be scanned)
    pub fn is_scannable_content_type(&self, content_type: &str) -> bool {
        let text_types = [
            "text/",
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
            "application/javascript",
            "application/ld+json",
        ];

        let ct_lower = content_type.to_lowercase();
        text_types.iter().any(|t| ct_lower.contains(t))
    }

    /// Mask a sensitive value for logging
    fn mask_value(&self, value: &str, data_type: SensitiveDataType) -> String {
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
        let jwt_match = result.matches.iter().find(|m| m.data_type == SensitiveDataType::Jwt);
        assert!(jwt_match.is_some());
    }

    #[test]
    fn test_scan_aws_key() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");

        assert!(result.has_matches);
        let aws_match = result.matches.iter().find(|m| m.data_type == SensitiveDataType::AwsKey);
        assert!(aws_match.is_some());
    }

    #[test]
    fn test_scan_github_token() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        assert!(result.has_matches);
        let gh_match = result.matches.iter().find(|m| m.pattern_name == "GitHub Token");
        assert!(gh_match.is_some());
    }

    #[test]
    fn test_scan_github_fine_grained_pat() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("GITHUB_TOKEN=github_pat_11ABCDEFG0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

        assert!(result.has_matches);
        let gh_match = result.matches.iter().find(|m| m.pattern_name == "GitHub Fine-grained PAT");
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
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let result = scanner.scan(key);

        assert!(result.has_matches);
        assert_eq!(result.matches[0].data_type, SensitiveDataType::PrivateKey);
    }

    #[test]
    fn test_scan_password_in_url() {
        let scanner = DlpScanner::default();
        let result = scanner.scan("https://api.example.com/login?password=secret123");

        assert!(result.has_matches);
        let pwd_match = result.matches.iter().find(|m| m.data_type == SensitiveDataType::Password);
        assert!(pwd_match.is_some());
    }

    #[test]
    fn test_scan_password_in_json() {
        let scanner = DlpScanner::default();
        let result = scanner.scan(r#"{"username": "admin", "password": "secret123"}"#);

        assert!(result.has_matches);
        let pwd_match = result.matches.iter().find(|m| m.data_type == SensitiveDataType::Password);
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

    // ────────────────────────────────────────────────────────────────────────
    // Performance Tests
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_performance() {
        let scanner = DlpScanner::default();

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
}
