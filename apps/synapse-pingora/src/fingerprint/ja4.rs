//! JA4+ TLS/HTTP Fingerprinting Implementation
//!
//! Port of risk-server/src/fingerprint/ja4.ts to Rust for high-performance
//! fingerprint generation in the proxy layer.
//!
//! ## Performance Targets
//! - JA4 parsing: <5μs
//! - JA4H generation: <10μs
//! - Combined fingerprint: <15μs

use once_cell::sync::Lazy;
use regex::Regex;
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
use http::header::{HeaderName, HeaderValue};

// ============================================================================
// Types
// ============================================================================

/// Protocol type for JA4 fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ja4Protocol {
    TCP,
    QUIC,
}

impl std::fmt::Display for Ja4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ja4Protocol::TCP => write!(f, "TCP"),
            Ja4Protocol::QUIC => write!(f, "QUIC"),
        }
    }
}

/// SNI type for JA4 fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ja4SniType {
    Domain,
    IP,
    None,
}

impl std::fmt::Display for Ja4SniType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ja4SniType::Domain => write!(f, "Domain"),
            Ja4SniType::IP => write!(f, "IP"),
            Ja4SniType::None => write!(f, "None"),
        }
    }
}

/// JA4 TLS fingerprint (from ClientHello)
///
/// Note: In dual-running mode, JA4 is provided via X-JA4-Fingerprint header
/// from upstream TLS terminator. In native Pingora mode, JA4 can be calculated
/// directly from ClientHello (requires TLS access).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Fingerprint {
    /// Full fingerprint string (e.g., t13d1516h2_8daaf6152771_e5627efa2ab1)
    pub raw: String,

    // Parsed components for filtering
    /// Transport protocol (TCP or QUIC)
    pub protocol: Ja4Protocol,
    /// TLS version (10=1.0, 11=1.1, 12=1.2, 13=1.3)
    pub tls_version: u8,
    /// SNI type (Domain, IP, or None)
    pub sni_type: Ja4SniType,
    /// Number of cipher suites offered
    pub cipher_count: u8,
    /// Number of extensions offered
    pub ext_count: u8,
    /// ALPN protocol (h1, h2, h3, etc.)
    pub alpn: String,
    /// First 12 chars of SHA256 of sorted cipher suites
    pub cipher_hash: String,
    /// First 12 chars of SHA256 of sorted extensions
    pub ext_hash: String,
}

/// JA4H HTTP fingerprint (from HTTP headers)
///
/// Can be generated directly from HTTP request - no external dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4hFingerprint {
    /// Full fingerprint string (e.g., ge11cnrn_a1b2c3d4e5f6_000000000000)
    pub raw: String,

    // Parsed components
    /// HTTP method code (ge, po, pu, de, he, op, pa, co, tr)
    pub method: String,
    /// HTTP version (10, 11, 20, 30)
    pub http_version: u8,
    /// Whether Cookie header is present
    pub has_cookie: bool,
    /// Whether Referer header is present
    pub has_referer: bool,
    /// First 2 chars of Accept-Language or "00"
    pub accept_lang: String,
    /// First 12 chars of SHA256 of sorted header names
    pub header_hash: String,
    /// First 12 chars of SHA256 of sorted cookie names
    pub cookie_hash: String,
}

/// Combined client fingerprint (JA4 + JA4H)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFingerprint {
    /// JA4 TLS fingerprint (None if not available)
    pub ja4: Option<Ja4Fingerprint>,
    /// JA4H HTTP fingerprint (always available)
    pub ja4h: Ja4hFingerprint,
    /// Combined hash: SHA256(ja4 + ja4h) first 16 chars
    pub combined_hash: String,
}

/// JA4 analysis result
#[derive(Debug, Clone)]
pub struct Ja4Analysis {
    pub fingerprint: Ja4Fingerprint,
    pub suspicious: bool,
    pub issues: Vec<String>,
    pub estimated_client: String,
}

/// JA4H analysis result
#[derive(Debug, Clone)]
pub struct Ja4hAnalysis {
    pub fingerprint: Ja4hFingerprint,
    pub suspicious: bool,
    pub issues: Vec<String>,
}

// ============================================================================
// Constants
// ============================================================================

/// Pre-compiled JA4 regex for performance (case-insensitive)
static JA4_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)^([tq])(\d{2})([di]?)([0-9a-f]{2})([0-9a-f]{2})([a-z0-9]{2})_([0-9a-f]{12})_([0-9a-f]{12})$")
        .expect("JA4 regex should compile")
});

/// Pre-compiled JA4H validation regex
static JA4H_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-z]{2}\d{2}[cn][rn][a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
        .expect("JA4H regex should compile")
});

/// HTTP method to 2-char code mapping
static METHOD_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("GET", "ge");
    m.insert("POST", "po");
    m.insert("PUT", "pu");
    m.insert("DELETE", "de");
    m.insert("HEAD", "he");
    m.insert("OPTIONS", "op");
    m.insert("PATCH", "pa");
    m.insert("CONNECT", "co");
    m.insert("TRACE", "tr");
    m
});

/// ALPN code to protocol name mapping
static ALPN_MAP: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("h1", "http/1.1");
    m.insert("h2", "h2");
    m.insert("h3", "h3");
    m.insert("00", "unknown");
    m
});

/// Headers to exclude from JA4H header hash
static EXCLUDED_HEADERS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut s = HashSet::new();
    s.insert("cookie");
    s.insert("referer");
    // Also exclude pseudo-headers and connection-specific
    s.insert(":method");
    s.insert(":path");
    s.insert(":scheme");
    s.insert(":authority");
    s.insert("host");
    s.insert("content-length");
    s.insert("content-type");
    s
});

// ============================================================================
// JA4 Parsing (from X-JA4-Fingerprint header)
// ============================================================================

/// Parse JA4 fingerprint from X-JA4-Fingerprint header
///
/// The header is set by upstream TLS terminator (nginx, HAProxy, Thunder)
/// that has access to the raw TLS ClientHello.
///
/// Format: t13d1516h2_8daaf6152771_e5627efa2ab1
///         │││ │ │ │  │              │
///         │││ │ │ │  │              └─ Extension hash
///         │││ │ │ │  └─ Cipher hash
///         │││ │ │ └─ ALPN (h2 = HTTP/2)
///         │││ │ └─ Extension count (hex)
///         │││ └─ Cipher count (hex)
///         ││└─ SNI present (d=domain, i=IP, empty=none)
///         │└─ TLS version (13 = 1.3)
///         └─ Protocol (t=TCP, q=QUIC)
///
/// Returns None on invalid input for safety (never panics).
pub fn parse_ja4_from_header(header: Option<&str>) -> Option<Ja4Fingerprint> {
    let header = header?;

    // Normalize: trim whitespace, reject overly long inputs (security)
    let normalized = header.trim();
    if normalized.is_empty() || normalized.len() > 100 {
        return None;
    }

    // Use pre-compiled regex for performance
    let caps = JA4_REGEX.captures(normalized)?;

    // Extract capture groups
    let protocol_char = caps.get(1)?.as_str();
    let version_str = caps.get(2)?.as_str();
    let sni_char = caps.get(3).map(|m| m.as_str()).unwrap_or("");
    let cipher_count_str = caps.get(4)?.as_str();
    let ext_count_str = caps.get(5)?.as_str();
    let alpn_str = caps.get(6)?.as_str();
    let cipher_hash = caps.get(7)?.as_str();
    let ext_hash = caps.get(8)?.as_str();

    // Parse numeric values
    let tls_version = version_str.parse::<u8>().ok()?;
    let cipher_count = u8::from_str_radix(cipher_count_str, 16).ok()?;
    let ext_count = u8::from_str_radix(ext_count_str, 16).ok()?;

    // Validate TLS version range
    if tls_version < 10 || tls_version > 13 {
        return None;
    }

    // Validate hash lengths
    if cipher_hash.len() != 12 || ext_hash.len() != 12 {
        return None;
    }

    // Map values
    let protocol = if protocol_char.to_lowercase() == "q" {
        Ja4Protocol::QUIC
    } else {
        Ja4Protocol::TCP
    };

    let sni_type = match sni_char {
        "d" => Ja4SniType::Domain,
        "i" => Ja4SniType::IP,
        _ => Ja4SniType::None,
    };

    let alpn = ALPN_MAP
        .get(alpn_str.to_lowercase().as_str())
        .copied()
        .unwrap_or(alpn_str)
        .to_string();

    Some(Ja4Fingerprint {
        raw: normalized.to_lowercase(),
        protocol,
        tls_version,
        sni_type,
        cipher_count,
        ext_count,
        alpn,
        cipher_hash: cipher_hash.to_lowercase(),
        ext_hash: ext_hash.to_lowercase(),
    })
}

// ============================================================================
// JA4H Generation (from HTTP request)
// ============================================================================

/// HTTP headers representation for JA4H generation
pub struct HttpHeaders<'a> {
    /// All headers as (name, value) pairs
    pub headers: &'a [(HeaderName, HeaderValue)],
    /// HTTP method (GET, POST, etc.)
    pub method: &'a str,
    /// HTTP version string ("1.0", "1.1", "2.0", "3.0")
    pub http_version: &'a str,
}

/// Generate JA4H fingerprint from HTTP request headers
///
/// Format: {method}{version}{cookie}{referer}{accept_lang}_{header_hash}_{cookie_hash}
/// Example: ge11cnrn_a1b2c3d4e5f6_000000000000
///          │ │ ││││  │              │
///          │ │ ││││  │              └─ Cookie hash (no cookies = zeros)
///          │ │ ││││  └─ Header hash
///          │ │ │││└─ Accept-Language (none)
///          │ │ ││└─ Referer (none)
///          │ │ │└─ Cookie (no)
///          │ │ └─
///          │ └─ HTTP 1.1
///          └─ GET
pub fn generate_ja4h(request: &HttpHeaders<'_>) -> Ja4hFingerprint {
    // 1. Method (2 chars)
    let method = METHOD_MAP
        .get(request.method.to_uppercase().as_str())
        .copied()
        .unwrap_or("xx")
        .to_string();

    // 2. HTTP version (10, 11, 20, 30)
    let http_version = get_http_version(request.http_version);

    // 3. Find Cookie and Referer headers
    let mut cookie_value: Option<&str> = None;
    let mut referer_value: Option<&str> = None;
    let mut accept_lang_value: Option<&str> = None;

    for (name, value) in request.headers.iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        match name.as_str() {
            "cookie" => cookie_value = Some(value_str),
            "referer" => referer_value = Some(value_str),
            "accept-language" => accept_lang_value = Some(value_str),
            _ => {}
        }
    }

    let has_cookie = cookie_value.is_some();
    let has_referer = referer_value.is_some();
    let cookie_flag = if has_cookie { "c" } else { "n" };
    let referer_flag = if has_referer { "r" } else { "n" };

    // 5. Accept-Language (first 2 chars of first language, or "00")
    let accept_lang = extract_accept_lang(accept_lang_value);

    // 6. Header hash (sorted header names, excluding cookie/referer)
    let header_hash = hash_headers(request.headers);

    // 7. Cookie hash (sorted cookie names, or zeros if no cookies)
    let cookie_hash = if let Some(cookies) = cookie_value {
        hash_cookies(cookies)
    } else {
        "000000000000".to_string()
    };

    // Construct fingerprint
    let raw = format!(
        "{}{}{}{}{}_{}_{}",
        method, http_version, cookie_flag, referer_flag, accept_lang, header_hash, cookie_hash
    );

    Ja4hFingerprint {
        raw,
        method,
        http_version,
        has_cookie,
        has_referer,
        accept_lang,
        header_hash,
        cookie_hash,
    }
}

/// Get HTTP version code from version string
fn get_http_version(version: &str) -> u8 {
    match version {
        "2.0" | "2" => 20,
        "3.0" | "3" => 30,
        "1.0" => 10,
        _ => 11, // Default to HTTP/1.1
    }
}

/// Extract Accept-Language first 2 chars
///
/// Examples:
///   "en-US,en;q=0.9" -> "en"
///   "fr-FR,fr;q=0.9,en;q=0.8" -> "fr"
///   None -> "00"
fn extract_accept_lang(header: Option<&str>) -> String {
    let Some(value) = header else {
        return "00".to_string();
    };

    if value.is_empty() {
        return "00".to_string();
    }

    // Get first language, strip quality and region
    let first_lang = value
        .split(',')
        .next()
        .and_then(|s| s.split(';').next())
        .and_then(|s| s.split('-').next())
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();

    if first_lang.len() < 2 {
        return "00".to_string();
    }

    first_lang[..2].to_string()
}

/// Hash header names for JA4H
///
/// - Exclude cookie, referer, and pseudo-headers
/// - Sort alphabetically
/// - Join with commas
/// - SHA256, take first 12 chars
fn hash_headers(headers: &[(HeaderName, HeaderValue)]) -> String {
    let mut names: Vec<&str> = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !EXCLUDED_HEADERS.contains(*name))
        .collect();

    if names.is_empty() {
        return "000000000000".to_string();
    }

    names.sort();
    sha256_first12(&names.join(","))
}

/// Hash cookie names for JA4H
///
/// - Parse cookie header
/// - Extract cookie names (before =)
/// - Sort alphabetically
/// - Join with commas
/// - SHA256, take first 12 chars
fn hash_cookies(cookie_header: &str) -> String {
    let mut cookie_names: Vec<String> = cookie_header
        .split(';')
        .filter_map(|c| {
            let name = c.split('=').next()?.trim().to_lowercase();
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })
        .collect();

    if cookie_names.is_empty() {
        return "000000000000".to_string();
    }

    cookie_names.sort();
    sha256_first12(&cookie_names.join(","))
}

// ============================================================================
// Combined Fingerprint
// ============================================================================

/// Extract complete client fingerprint (JA4 + JA4H)
///
/// Uses streaming hash to avoid string concatenation overhead.
pub fn extract_client_fingerprint(
    ja4_header: Option<&str>,
    request: &HttpHeaders<'_>,
) -> ClientFingerprint {
    let ja4 = parse_ja4_from_header(ja4_header);
    let ja4h = generate_ja4h(request);

    // Combined hash: SHA256(ja4.raw + ja4h.raw), first 16 chars
    let mut hasher = Sha256::new();
    if let Some(ref fp) = ja4 {
        hasher.update(fp.raw.as_bytes());
    }
    hasher.update(ja4h.raw.as_bytes());
    let result = hasher.finalize();
    let combined_hash = hex::encode(&result[..8]); // 16 hex chars = 8 bytes

    ClientFingerprint {
        ja4,
        ja4h,
        combined_hash,
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// SHA256 hash, first 12 hex characters
pub fn sha256_first12(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..6]) // 12 hex chars = 6 bytes
}

/// Check if JA4 fingerprint is valid format
pub fn is_valid_ja4(fingerprint: &str) -> bool {
    parse_ja4_from_header(Some(fingerprint)).is_some()
}

/// Check if JA4H fingerprint is valid format
pub fn is_valid_ja4h(fingerprint: &str) -> bool {
    JA4H_REGEX.is_match(&fingerprint.to_lowercase())
}

/// Compare two fingerprints for equality (case-insensitive)
pub fn fingerprints_match(fp1: Option<&str>, fp2: Option<&str>) -> bool {
    match (fp1, fp2) {
        (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
        _ => false,
    }
}

/// Check if fingerprint matches a pattern (supports wildcards)
///
/// Patterns:
///   t13* - Any TLS 1.3 TCP fingerprint
///   t12d* - TLS 1.2 with domain SNI
///   *_8daaf6152771_* - Specific cipher hash
pub fn matches_pattern(fingerprint: &str, pattern: &str) -> bool {
    if fingerprint.is_empty() || pattern.is_empty() {
        return false;
    }

    // Convert pattern to regex
    let escaped = regex::escape(pattern);
    let regex_pattern = escaped.replace(r"\*", ".*");

    match Regex::new(&format!("^(?i){}$", regex_pattern)) {
        Ok(re) => re.is_match(fingerprint),
        Err(_) => false,
    }
}

// ============================================================================
// Analysis
// ============================================================================

/// Analyze JA4 fingerprint for suspicious characteristics
pub fn analyze_ja4(fingerprint: &Ja4Fingerprint) -> Ja4Analysis {
    let mut issues = Vec::new();

    // Check for old TLS versions
    if fingerprint.tls_version < 12 {
        issues.push(format!(
            "Outdated TLS version: 1.{}",
            fingerprint.tls_version - 10
        ));
    }

    // Check for missing ALPN with TLS 1.3 (unusual for browsers)
    if fingerprint.tls_version >= 13 && fingerprint.alpn == "unknown" {
        issues.push("Missing ALPN with TLS 1.3 (unusual for browsers)".to_string());
    }

    // Very few ciphers might indicate a script/bot
    if fingerprint.cipher_count < 5 {
        issues.push(format!(
            "Low cipher count: {} (typical browsers offer 10+)",
            fingerprint.cipher_count
        ));
    }

    // Very few extensions might indicate a script/bot
    if fingerprint.ext_count < 5 {
        issues.push(format!(
            "Low extension count: {} (typical browsers have 10+)",
            fingerprint.ext_count
        ));
    }

    let estimated_client = estimate_client_from_ja4(fingerprint);

    Ja4Analysis {
        fingerprint: fingerprint.clone(),
        suspicious: !issues.is_empty(),
        issues,
        estimated_client,
    }
}

/// Estimate client type from JA4 fingerprint
fn estimate_client_from_ja4(fingerprint: &Ja4Fingerprint) -> String {
    // Modern browsers typically use TLS 1.3 with HTTP/2 and many ciphers/extensions
    if fingerprint.tls_version >= 13 && fingerprint.alpn == "h2" && fingerprint.cipher_count >= 10 {
        return "modern-browser".to_string();
    }

    // TLS 1.2 with HTTP/2 is still common
    if fingerprint.tls_version == 12 && fingerprint.alpn == "h2" {
        return "browser".to_string();
    }

    // HTTP/1.1 only with TLS 1.2+ could be API client or script
    if fingerprint.alpn == "http/1.1" && fingerprint.tls_version >= 12 {
        return "api-client".to_string();
    }

    // Old TLS or minimal ciphers/extensions suggests script or legacy client
    if fingerprint.tls_version < 12 || fingerprint.cipher_count < 5 || fingerprint.ext_count < 5 {
        return "bot-or-script".to_string();
    }

    "unknown".to_string()
}

/// Analyze JA4H fingerprint for suspicious characteristics
pub fn analyze_ja4h(fingerprint: &Ja4hFingerprint) -> Ja4hAnalysis {
    let mut issues = Vec::new();

    // No Accept-Language is unusual for browsers
    if fingerprint.accept_lang == "00" {
        issues.push("No Accept-Language header (unusual for browsers)".to_string());
    }

    // HTTP/1.0 is very rare in modern usage
    if fingerprint.http_version == 10 {
        issues.push("HTTP/1.0 (very rare, possibly script)".to_string());
    }

    Ja4hAnalysis {
        fingerprint: fingerprint.clone(),
        suspicious: !issues.is_empty(),
        issues,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (HeaderName, HeaderValue) {
        let header_name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
        let header_value = HeaderValue::from_str(value).expect("valid header value");
        (header_name, header_value)
    }

    // ==================== JA4 Parsing Tests ====================

    #[test]
    fn test_parse_ja4_valid_tcp_tls13() {
        let result = parse_ja4_from_header(Some("t13d1516h2_8daaf6152771_e5627efa2ab1"));
        assert!(result.is_some());
        let fp = result.unwrap();
        assert_eq!(fp.protocol, Ja4Protocol::TCP);
        assert_eq!(fp.tls_version, 13);
        assert_eq!(fp.sni_type, Ja4SniType::Domain);
        assert_eq!(fp.cipher_count, 0x15); // 21 decimal
        assert_eq!(fp.ext_count, 0x16); // 22 decimal
        assert_eq!(fp.alpn, "h2");
        assert_eq!(fp.cipher_hash, "8daaf6152771");
        assert_eq!(fp.ext_hash, "e5627efa2ab1");
    }

    #[test]
    fn test_parse_ja4_valid_quic_tls13() {
        let result = parse_ja4_from_header(Some("q13d0a0bh3_1234567890ab_abcdef123456"));
        assert!(result.is_some());
        let fp = result.unwrap();
        assert_eq!(fp.protocol, Ja4Protocol::QUIC);
        assert_eq!(fp.tls_version, 13);
        assert_eq!(fp.sni_type, Ja4SniType::Domain);
        assert_eq!(fp.alpn, "h3");
    }

    #[test]
    fn test_parse_ja4_valid_tls12_ip_sni() {
        let result = parse_ja4_from_header(Some("t12i0c10h1_aabbccddeeff_112233445566"));
        assert!(result.is_some());
        let fp = result.unwrap();
        assert_eq!(fp.tls_version, 12);
        assert_eq!(fp.sni_type, Ja4SniType::IP);
        assert_eq!(fp.alpn, "http/1.1");
    }

    #[test]
    fn test_parse_ja4_valid_no_sni() {
        let result = parse_ja4_from_header(Some("t130510h2_aabbccddeeff_112233445566"));
        assert!(result.is_some());
        let fp = result.unwrap();
        assert_eq!(fp.sni_type, Ja4SniType::None);
    }

    #[test]
    fn test_parse_ja4_invalid_format() {
        assert!(parse_ja4_from_header(Some("invalid")).is_none());
        assert!(parse_ja4_from_header(Some("")).is_none());
        assert!(parse_ja4_from_header(None).is_none());
        assert!(parse_ja4_from_header(Some("t13d1516h2_short_hash")).is_none());
    }

    #[test]
    fn test_parse_ja4_too_long() {
        let long_input = "a".repeat(200);
        assert!(parse_ja4_from_header(Some(&long_input)).is_none());
    }

    #[test]
    fn test_parse_ja4_case_insensitive() {
        let result1 = parse_ja4_from_header(Some("T13D1516H2_8DAAF6152771_E5627EFA2AB1"));
        let result2 = parse_ja4_from_header(Some("t13d1516h2_8daaf6152771_e5627efa2ab1"));
        assert!(result1.is_some());
        assert!(result2.is_some());
        // Both should normalize to lowercase
        assert_eq!(result1.unwrap().raw, result2.unwrap().raw);
    }

    // ==================== JA4H Generation Tests ====================

    #[test]
    fn test_generate_ja4h_basic() {
        let headers = vec![
            header("Accept", "text/html"),
            header("User-Agent", "Mozilla/5.0"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = generate_ja4h(&request);

        assert_eq!(result.method, "ge");
        assert_eq!(result.http_version, 11);
        assert!(!result.has_cookie);
        assert!(!result.has_referer);
        assert_eq!(result.accept_lang, "00");
        assert_eq!(result.cookie_hash, "000000000000");
    }

    #[test]
    fn test_generate_ja4h_with_cookie() {
        let headers = vec![
            header("Cookie", "session=abc123; user=test"),
            header("Accept", "text/html"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "POST",
            http_version: "2.0",
        };

        let result = generate_ja4h(&request);

        assert_eq!(result.method, "po");
        assert_eq!(result.http_version, 20);
        assert!(result.has_cookie);
        assert!(!result.has_referer);
        assert_ne!(result.cookie_hash, "000000000000");
    }

    #[test]
    fn test_generate_ja4h_with_referer() {
        let headers = vec![
            header("Referer", "https://example.com"),
            header("Accept", "text/html"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = generate_ja4h(&request);

        assert!(!result.has_cookie);
        assert!(result.has_referer);
    }

    #[test]
    fn test_generate_ja4h_accept_language() {
        let headers = vec![
            header("Accept-Language", "en-US,en;q=0.9,fr;q=0.8"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = generate_ja4h(&request);
        assert_eq!(result.accept_lang, "en");
    }

    #[test]
    fn test_generate_ja4h_french_language() {
        let headers = vec![
            header("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = generate_ja4h(&request);
        assert_eq!(result.accept_lang, "fr");
    }

    #[test]
    fn test_generate_ja4h_http_versions() {
        for (version, expected) in [("1.0", 10), ("1.1", 11), ("2.0", 20), ("3.0", 30)] {
            let headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
            let request = HttpHeaders {
                headers: &headers,
                method: "GET",
                http_version: version,
            };
            let result = generate_ja4h(&request);
            assert_eq!(result.http_version, expected, "Failed for version {}", version);
        }
    }

    #[test]
    fn test_generate_ja4h_all_methods() {
        let methods = [
            ("GET", "ge"),
            ("POST", "po"),
            ("PUT", "pu"),
            ("DELETE", "de"),
            ("HEAD", "he"),
            ("OPTIONS", "op"),
            ("PATCH", "pa"),
            ("CONNECT", "co"),
            ("TRACE", "tr"),
        ];

        for (method, expected) in methods {
            let headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
            let request = HttpHeaders {
                headers: &headers,
                method,
                http_version: "1.1",
            };
            let result = generate_ja4h(&request);
            assert_eq!(result.method, expected, "Failed for method {}", method);
        }
    }

    // ==================== Combined Fingerprint Tests ====================

    #[test]
    fn test_extract_client_fingerprint_with_ja4() {
        let headers = vec![
            header("Accept", "text/html"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = extract_client_fingerprint(
            Some("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            &request,
        );

        assert!(result.ja4.is_some());
        assert_eq!(result.combined_hash.len(), 16);
    }

    #[test]
    fn test_extract_client_fingerprint_without_ja4() {
        let headers = vec![
            header("Accept", "text/html"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = extract_client_fingerprint(None, &request);

        assert!(result.ja4.is_none());
        assert_eq!(result.combined_hash.len(), 16);
    }

    // ==================== Utility Function Tests ====================

    #[test]
    fn test_sha256_first12() {
        let result = sha256_first12("test");
        assert_eq!(result.len(), 12);
        // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015...
        assert_eq!(result, "9f86d081884c");
    }

    #[test]
    fn test_is_valid_ja4() {
        assert!(is_valid_ja4("t13d1516h2_8daaf6152771_e5627efa2ab1"));
        assert!(!is_valid_ja4("invalid"));
        assert!(!is_valid_ja4(""));
    }

    #[test]
    fn test_is_valid_ja4h() {
        assert!(is_valid_ja4h("ge11cnrn_a1b2c3d4e5f6_000000000000"));
        assert!(!is_valid_ja4h("invalid"));
        assert!(!is_valid_ja4h(""));
    }

    #[test]
    fn test_fingerprints_match() {
        assert!(fingerprints_match(Some("ABC"), Some("abc")));
        assert!(fingerprints_match(Some("abc"), Some("ABC")));
        assert!(!fingerprints_match(Some("abc"), Some("def")));
        assert!(!fingerprints_match(None, Some("abc")));
        assert!(!fingerprints_match(Some("abc"), None));
        assert!(!fingerprints_match(None, None));
    }

    #[test]
    fn test_matches_pattern() {
        // Prefix wildcard
        assert!(matches_pattern("t13d1516h2_8daaf6152771_e5627efa2ab1", "t13*"));
        assert!(!matches_pattern("t12d1516h2_8daaf6152771_e5627efa2ab1", "t13*"));

        // Middle wildcard
        assert!(matches_pattern("t13d1516h2_8daaf6152771_e5627efa2ab1", "*_8daaf6152771_*"));

        // Suffix wildcard
        assert!(matches_pattern("t13d1516h2_8daaf6152771_e5627efa2ab1", "*e5627efa2ab1"));
    }

    // ==================== Analysis Tests ====================

    #[test]
    fn test_analyze_ja4_modern_browser() {
        let fp = Ja4Fingerprint {
            raw: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
            protocol: Ja4Protocol::TCP,
            tls_version: 13,
            sni_type: Ja4SniType::Domain,
            cipher_count: 15,
            ext_count: 16,
            alpn: "h2".to_string(),
            cipher_hash: "8daaf6152771".to_string(),
            ext_hash: "e5627efa2ab1".to_string(),
        };

        let analysis = analyze_ja4(&fp);
        assert!(!analysis.suspicious);
        assert_eq!(analysis.estimated_client, "modern-browser");
    }

    #[test]
    fn test_analyze_ja4_suspicious_bot() {
        let fp = Ja4Fingerprint {
            raw: "t100302h1_8daaf6152771_e5627efa2ab1".to_string(),
            protocol: Ja4Protocol::TCP,
            tls_version: 10,
            sni_type: Ja4SniType::None,
            cipher_count: 3,
            ext_count: 2,
            alpn: "http/1.1".to_string(),
            cipher_hash: "8daaf6152771".to_string(),
            ext_hash: "e5627efa2ab1".to_string(),
        };

        let analysis = analyze_ja4(&fp);
        assert!(analysis.suspicious);
        assert!(!analysis.issues.is_empty());
        assert_eq!(analysis.estimated_client, "bot-or-script");
    }

    #[test]
    fn test_analyze_ja4h_normal() {
        let fp = Ja4hFingerprint {
            raw: "ge11cren_a1b2c3d4e5f6_aabbccddeeff".to_string(),
            method: "ge".to_string(),
            http_version: 11,
            has_cookie: true,
            has_referer: true,
            accept_lang: "en".to_string(),
            header_hash: "a1b2c3d4e5f6".to_string(),
            cookie_hash: "aabbccddeeff".to_string(),
        };

        let analysis = analyze_ja4h(&fp);
        assert!(!analysis.suspicious);
        assert!(analysis.issues.is_empty());
    }

    #[test]
    fn test_analyze_ja4h_suspicious() {
        let fp = Ja4hFingerprint {
            raw: "ge10nn00_a1b2c3d4e5f6_000000000000".to_string(),
            method: "ge".to_string(),
            http_version: 10,
            has_cookie: false,
            has_referer: false,
            accept_lang: "00".to_string(),
            header_hash: "a1b2c3d4e5f6".to_string(),
            cookie_hash: "000000000000".to_string(),
        };

        let analysis = analyze_ja4h(&fp);
        assert!(analysis.suspicious);
        assert!(analysis.issues.iter().any(|i| i.contains("HTTP/1.0")));
        assert!(analysis.issues.iter().any(|i| i.contains("Accept-Language")));
    }

    // ==================== Performance Benchmark Hints ====================

    #[test]
    fn test_ja4_parsing_performance() {
        // This test verifies that parsing is fast by running many iterations
        let input = "t13d1516h2_8daaf6152771_e5627efa2ab1";
        let start = std::time::Instant::now();

        for _ in 0..10000 {
            let _ = parse_ja4_from_header(Some(input));
        }

        let elapsed = start.elapsed();
        // Should complete 10K parses in under 500ms in debug mode (50μs each)
        // Note: Release builds are ~5x faster, but tests run in debug by default
        assert!(elapsed.as_millis() < 500, "JA4 parsing too slow: {:?}", elapsed);
    }

    #[test]
    fn test_ja4h_generation_performance() {
        let headers = vec![
            header("Accept", "text/html"),
            header("User-Agent", "Mozilla/5.0"),
            header("Accept-Language", "en-US"),
            header("Cookie", "session=abc; user=test"),
        ];
        let request = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let start = std::time::Instant::now();

        for _ in 0..10000 {
            let _ = generate_ja4h(&request);
        }

        let elapsed = start.elapsed();
        // Should complete 10K generations in under 200ms (20μs each) in release mode
        // Debug mode is ~5x slower, so allow 1000ms
        #[cfg(debug_assertions)]
        let max_time_ms = 1000;
        #[cfg(not(debug_assertions))]
        let max_time_ms = 200;

        assert!(elapsed.as_millis() < max_time_ms, "JA4H generation too slow: {:?}", elapsed);
    }
}
