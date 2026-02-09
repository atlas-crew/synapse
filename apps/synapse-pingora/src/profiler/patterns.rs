//! Pattern detection for string values.
//!
//! Uses lazy_static regexes for efficient pattern matching of common
//! string formats like UUIDs, emails, dates, URLs, and IP addresses.
//!
//! ## Performance
//! - Pattern matching: ~100-500ns per string
//! - Regex compilation: Once at first use (lazy)

use once_cell::sync::Lazy;
use regex::Regex;

use crate::profiler::schema_types::PatternType;

// ============================================================================
// Pattern Regexes (compiled once, reused)
// ============================================================================

/// UUID pattern: 8-4-4-4-12 hexadecimal format
/// Matches: 550e8400-e29b-41d4-a716-446655440000
static UUID_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        .expect("UUID regex compilation failed")
});

/// Email pattern: basic email format
/// Matches: user@example.com, name.last@sub.domain.org
static EMAIL_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").expect("Email regex compilation failed")
});

/// ISO 8601 datetime pattern
/// Matches: 2024-01-15T10:30:00, 2024-01-15T10:30:00Z, 2024-01-15T10:30:00+05:00
static ISO_DATE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}").expect("ISO date regex compilation failed")
});

/// URL pattern: HTTP/HTTPS URLs
/// Matches: http://example.com, https://api.example.com/path?query=1
static URL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^https?://[^\s]+$").expect("URL regex compilation failed"));

/// IPv4 address pattern
/// Matches: 192.168.1.1, 10.0.0.255
static IPV4_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").expect("IPv4 regex compilation failed")
});

/// IPv6 address pattern (simplified)
/// Matches: 2001:0db8:85a3:0000:0000:8a2e:0370:7334, ::1
static IPV6_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
        .expect("IPv6 regex compilation failed")
});

/// JWT pattern: three base64url segments separated by dots
/// Matches: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
static JWT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
        .expect("JWT regex compilation failed")
});

/// MongoDB ObjectId pattern: 24 hexadecimal characters
/// Matches: 507f1f77bcf86cd799439011
static OBJECT_ID_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{24}$").expect("ObjectId regex compilation failed"));

/// Generic hex string pattern: 16+ hexadecimal characters
/// Matches: abcdef1234567890abcdef, 0123456789abcdef0123456789abcdef
static HEX_STRING_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-fA-F]{16,}$").expect("Hex string regex compilation failed"));

/// Phone number pattern (various formats)
/// Matches: +1-555-123-4567, (555) 123-4567, 555.123.4567
static PHONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$",
    )
    .expect("Phone regex compilation failed")
});

/// Credit card pattern (basic format, 13-19 digits with optional separators)
/// Note: This is for pattern detection only, not validation
static CREDIT_CARD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{1,4}$")
        .expect("Credit card regex compilation failed")
});

// ============================================================================
// Pattern Detection
// ============================================================================

/// Detect pattern type from a string value.
///
/// Checks patterns in order of specificity:
/// 1. UUID (most specific format)
/// 2. ObjectId (24 hex chars)
/// 3. JWT (three base64 segments)
/// 4. Email
/// 5. ISO Date
/// 6. URL
/// 7. IPv4
/// 8. IPv6
/// 9. Phone
/// 10. Credit Card
/// 11. Hex String (generic fallback for hex)
///
/// Returns None if no pattern matches.
///
/// ## Performance
/// Average: ~200ns for non-matching strings
/// Worst case: ~1us when checking all patterns
#[inline]
pub fn detect_pattern(value: &str) -> Option<PatternType> {
    // Short-circuit for empty or very short strings
    if value.len() < 3 {
        return None;
    }

    // Check length-specific patterns first (faster rejection)
    let len = value.len();

    // UUID is exactly 36 chars
    if len == 36 && UUID_PATTERN.is_match(value) {
        return Some(PatternType::Uuid);
    }

    // ObjectId is exactly 24 hex chars
    if len == 24 && OBJECT_ID_PATTERN.is_match(value) {
        return Some(PatternType::ObjectId);
    }

    // JWT typically > 50 chars and contains dots
    if len > 50 && value.contains('.') && JWT_PATTERN.is_match(value) {
        return Some(PatternType::Jwt);
    }

    // Email detection (contains @)
    if value.contains('@') && EMAIL_PATTERN.is_match(value) {
        return Some(PatternType::Email);
    }

    // ISO date detection (starts with digit, contains T)
    if value.starts_with(|c: char| c.is_ascii_digit()) {
        if value.contains('T') && ISO_DATE_PATTERN.is_match(value) {
            return Some(PatternType::IsoDate);
        }

        // IPv4 detection (4 dot-separated octets)
        if value.contains('.') && !value.contains(':') && IPV4_PATTERN.is_match(value) {
            return Some(PatternType::Ipv4);
        }

        // Credit card detection
        if len >= 13 && len <= 19 && CREDIT_CARD_PATTERN.is_match(value) {
            return Some(PatternType::CreditCard);
        }
    }

    // Phone number detection (can start with + or digit)
    if len >= 7 && len <= 20 {
        let first_char = value.chars().next();
        if matches!(first_char, Some('+') | Some('('))
            || value.starts_with(|c: char| c.is_ascii_digit())
        {
            if PHONE_PATTERN.is_match(value) {
                return Some(PatternType::Phone);
            }
        }
    }

    // URL detection (starts with http)
    if value.starts_with("http") && URL_PATTERN.is_match(value) {
        return Some(PatternType::Url);
    }

    // IPv6 detection (contains colons, hex digits)
    if value.contains(':') && IPV6_PATTERN.is_match(value) {
        return Some(PatternType::Ipv6);
    }

    // Generic hex string (16+ hex chars, no separators)
    if len >= 16 && HEX_STRING_PATTERN.is_match(value) {
        return Some(PatternType::HexString);
    }

    None
}

/// Check if a value matches a specific pattern.
#[inline]
pub fn matches_pattern(value: &str, pattern: PatternType) -> bool {
    match pattern {
        PatternType::Uuid => UUID_PATTERN.is_match(value),
        PatternType::Email => EMAIL_PATTERN.is_match(value),
        PatternType::IsoDate => ISO_DATE_PATTERN.is_match(value),
        PatternType::Url => URL_PATTERN.is_match(value),
        PatternType::Ipv4 => IPV4_PATTERN.is_match(value),
        PatternType::Ipv6 => IPV6_PATTERN.is_match(value),
        PatternType::Jwt => JWT_PATTERN.is_match(value),
        PatternType::ObjectId => OBJECT_ID_PATTERN.is_match(value),
        PatternType::HexString => HEX_STRING_PATTERN.is_match(value),
        PatternType::Phone => PHONE_PATTERN.is_match(value),
        PatternType::CreditCard => CREDIT_CARD_PATTERN.is_match(value),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_detection() {
        assert_eq!(
            detect_pattern("550e8400-e29b-41d4-a716-446655440000"),
            Some(PatternType::Uuid)
        );
        assert_eq!(
            detect_pattern("550E8400-E29B-41D4-A716-446655440000"),
            Some(PatternType::Uuid)
        );
        assert_eq!(detect_pattern("not-a-uuid"), None);
        // 32 hex chars without dashes matches HexString (16+ hex chars)
        assert_eq!(
            detect_pattern("550e8400e29b41d4a716446655440000"),
            Some(PatternType::HexString)
        );
    }

    #[test]
    fn test_email_detection() {
        assert_eq!(detect_pattern("user@example.com"), Some(PatternType::Email));
        assert_eq!(
            detect_pattern("name.last@sub.domain.org"),
            Some(PatternType::Email)
        );
        assert_eq!(detect_pattern("invalid-email"), None);
        assert_eq!(detect_pattern("@nodomain"), None);
    }

    #[test]
    fn test_iso_date_detection() {
        assert_eq!(
            detect_pattern("2024-01-15T10:30:00"),
            Some(PatternType::IsoDate)
        );
        assert_eq!(
            detect_pattern("2024-01-15T10:30:00Z"),
            Some(PatternType::IsoDate)
        );
        assert_eq!(
            detect_pattern("2024-01-15T10:30:00+05:00"),
            Some(PatternType::IsoDate)
        );
        // Date only without time - doesn't match our ISO date pattern (requires T separator)
        assert!(!matches_pattern("2024-01-15", PatternType::IsoDate));
    }

    #[test]
    fn test_url_detection() {
        assert_eq!(detect_pattern("http://example.com"), Some(PatternType::Url));
        assert_eq!(
            detect_pattern("https://api.example.com/path?query=1"),
            Some(PatternType::Url)
        );
        assert_eq!(detect_pattern("ftp://example.com"), None); // Not HTTP(S)
        assert_eq!(detect_pattern("example.com"), None); // No protocol
    }

    #[test]
    fn test_ipv4_detection() {
        assert_eq!(detect_pattern("192.168.1.1"), Some(PatternType::Ipv4));
        assert_eq!(detect_pattern("10.0.0.255"), Some(PatternType::Ipv4));
        assert_eq!(detect_pattern("256.1.1.1"), Some(PatternType::Ipv4)); // Invalid but matches format
                                                                          // Missing octet - doesn't match IPv4 pattern
        assert!(!matches_pattern("192.168.1", PatternType::Ipv4));
    }

    #[test]
    fn test_ipv6_detection() {
        assert_eq!(
            detect_pattern("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some(PatternType::Ipv6)
        );
        assert_eq!(detect_pattern("::1"), Some(PatternType::Ipv6));
        assert_eq!(detect_pattern("fe80::1"), Some(PatternType::Ipv6));
    }

    #[test]
    fn test_jwt_detection() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert_eq!(detect_pattern(jwt), Some(PatternType::Jwt));
        assert_eq!(detect_pattern("not.a.jwt"), None); // Too short
    }

    #[test]
    fn test_object_id_detection() {
        assert_eq!(
            detect_pattern("507f1f77bcf86cd799439011"),
            Some(PatternType::ObjectId)
        );
        assert_eq!(
            detect_pattern("507F1F77BCF86CD799439011"),
            Some(PatternType::ObjectId)
        );
        // 23 hex chars - too short for ObjectId (24), but matches HexString (16+)
        assert_eq!(
            detect_pattern("507f1f77bcf86cd79943901"),
            Some(PatternType::HexString)
        );
    }

    #[test]
    fn test_hex_string_detection() {
        assert_eq!(
            detect_pattern("abcdef1234567890"),
            Some(PatternType::HexString)
        );
        assert_eq!(
            detect_pattern("0123456789abcdef0123456789abcdef"),
            Some(PatternType::HexString)
        );
        assert_eq!(detect_pattern("abcdef12345678"), None); // 14 chars, too short
        assert_eq!(detect_pattern("ghijkl1234567890"), None); // Non-hex chars
    }

    #[test]
    fn test_phone_detection() {
        // Phone numbers have separators that prevent them from matching other patterns
        assert_eq!(detect_pattern("+1-555-1234567"), Some(PatternType::Phone));
        // These formats may conflict with other pattern checks, test the specific matcher
        assert!(matches_pattern("+1-555-123-4567", PatternType::Phone));
        assert!(matches_pattern("(555) 123-4567", PatternType::Phone));
        assert!(matches_pattern("555.123.4567", PatternType::Phone));
    }

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern(
            "550e8400-e29b-41d4-a716-446655440000",
            PatternType::Uuid
        ));
        assert!(!matches_pattern("not-a-uuid", PatternType::Uuid));

        assert!(matches_pattern("user@example.com", PatternType::Email));
        assert!(!matches_pattern("invalid", PatternType::Email));
    }

    #[test]
    fn test_empty_and_short_strings() {
        assert_eq!(detect_pattern(""), None);
        assert_eq!(detect_pattern("ab"), None);
        assert_eq!(detect_pattern("abc"), None);
    }

    #[test]
    fn test_pattern_priority() {
        // UUID should take priority over hex string
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(detect_pattern(uuid), Some(PatternType::Uuid));

        // ObjectId should take priority over generic hex
        let object_id = "507f1f77bcf86cd799439011";
        assert_eq!(detect_pattern(object_id), Some(PatternType::ObjectId));
    }

    #[test]
    fn test_credit_card_detection() {
        // Note: These are formatted patterns for detection, not real card numbers
        assert!(matches_pattern(
            "4111-1111-1111-1111",
            PatternType::CreditCard
        ));
        assert!(matches_pattern("4111111111111111", PatternType::CreditCard));
    }
}
