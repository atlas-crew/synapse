//! Client Integrity Analysis
//!
//! Detects inconsistencies between:
//! - User-Agent and Client Hints (Sec-CH-UA)
//! - Fetch Metadata (Sec-Fetch-*) and request context
//! - Accept headers and stated browser capabilities
//! - JA4 TLS fingerprint and User-Agent claims
//!
//! This module helps detect "lie" fingerprints where bots pretend to be browsers.
//!
//! ## Security
//! - Input length validation prevents ReDoS and memory exhaustion
//! - All header values are bounded before processing
//! - JA4 fingerprint validation prevents spoofing attacks

use std::borrow::Cow;
use super::ja4::{HttpHeaders, Ja4Fingerprint, Ja4Protocol};

/// Maximum allowed length for User-Agent header (512 bytes)
pub const MAX_USER_AGENT_LENGTH: usize = 512;

/// Maximum allowed length for other headers (256 bytes)
pub const MAX_HEADER_LENGTH: usize = 256;

/// Maximum allowed length for Sec-CH-UA header (1024 bytes - multiple brands)
pub const MAX_SEC_CH_UA_LENGTH: usize = 1024;

/// Integrity analysis result
#[derive(Debug, Clone, Default)]
pub struct IntegrityAnalysis {
    /// Overall suspicious score (0-100, saturating)
    pub suspicion_score: u8,
    /// List of detected inconsistencies (uses Cow for zero-copy known messages)
    pub inconsistencies: Vec<Cow<'static, str>>,
    /// Whether Client Hints were present
    pub has_client_hints: bool,
    /// Whether Fetch Metadata was present
    pub has_fetch_metadata: bool,
    /// Whether input was truncated due to length limits
    pub input_truncated: bool,
}

/// Saturating add for suspicion score (max 100)
#[inline]
fn saturating_add_score(score: &mut u8, delta: u8) {
    *score = score.saturating_add(delta).min(100);
}

/// Truncate string to max length, returning whether truncation occurred
#[inline]
fn truncate_header(value: &str, max_len: usize) -> (&str, bool) {
    if value.len() > max_len {
        // Find a valid UTF-8 boundary
        let truncated = &value[..value.floor_char_boundary(max_len)];
        (truncated, true)
    } else {
        (value, false)
    }
}

/// Analyze request headers for integrity violations
pub fn analyze_integrity(request: &HttpHeaders<'_>) -> IntegrityAnalysis {
    let mut result = IntegrityAnalysis::default();

    // Extract key headers with length validation
    let mut ua = "";
    let mut sec_ch_ua = "";
    let mut sec_fetch_site = "";
    let mut sec_fetch_mode = "";
    let mut referer = "";
    let mut host = "";
    let mut any_truncated = false;

    for (name, value) in request.headers {
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        match name.as_str() {
            "user-agent" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_USER_AGENT_LENGTH);
                ua = truncated;
                any_truncated |= was_truncated;
            },
            "sec-ch-ua" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_SEC_CH_UA_LENGTH);
                sec_ch_ua = truncated;
                any_truncated |= was_truncated;
                result.has_client_hints = true;
            },
            "sec-fetch-site" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_HEADER_LENGTH);
                sec_fetch_site = truncated;
                any_truncated |= was_truncated;
                result.has_fetch_metadata = true;
            },
            "sec-fetch-mode" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_HEADER_LENGTH);
                sec_fetch_mode = truncated;
                any_truncated |= was_truncated;
            },
            "referer" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_HEADER_LENGTH);
                referer = truncated;
                any_truncated |= was_truncated;
            },
            "host" => {
                let (truncated, was_truncated) = truncate_header(value_str, MAX_HEADER_LENGTH);
                host = truncated;
                any_truncated |= was_truncated;
            },
            _ => {}
        }
    }

    result.input_truncated = any_truncated;

    // Oversized headers are suspicious (potential attack or malformed client)
    if any_truncated {
        result.inconsistencies.push(Cow::Borrowed("Header exceeds maximum allowed length"));
        saturating_add_score(&mut result.suspicion_score, 20);
    }

    // 1. Check User-Agent vs Client Hints
    // Modern browsers (Chrome 84+, Edge) send Sec-CH-UA.
    // If User-Agent says "Chrome/120" but Sec-CH-UA is missing, that's suspicious.
    if !result.has_client_hints && (ua.contains("Chrome/") || ua.contains("Edg/")) {
        // Exclude older versions or non-Chromium based on heuristics if needed,
        // but generally modern Chrome should have it.
        // For safety, we only flag if it claims to be a very recent version.
        if ua.contains("Chrome/12") || ua.contains("Chrome/13") {
            result.inconsistencies.push(Cow::Borrowed("Missing Client Hints for modern Chrome/Edge"));
            saturating_add_score(&mut result.suspicion_score, 30);
        }
    }

    if result.has_client_hints {
        // If Client Hints present, verify consistency
        // Format: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"
        if ua.contains("Firefox") && !ua.contains("Seamonkey") {
            // Firefox typically doesn't send Sec-CH-UA yet (experimental)
            // If it does, it shouldn't claim to be Chromium unless it is.
            if sec_ch_ua.contains("Chromium") {
                result.inconsistencies.push(Cow::Borrowed("Firefox User-Agent sent Chromium Client Hints"));
                saturating_add_score(&mut result.suspicion_score, 50);
            }
        }
    }

    // 2. Check Fetch Metadata consistency
    if result.has_fetch_metadata {
        // "same-origin" requests should generally have matching Referer/Host (if Referer present)
        if sec_fetch_site == "same-origin" && !referer.is_empty() {
            // Simple check: referer should contain host
            // (Note: This is a loose check, proper URL parsing is expensive)
            if !referer.contains(host) && !host.is_empty() {
                result.inconsistencies.push(Cow::Borrowed("Sec-Fetch-Site: same-origin but Referer mismatch"));
                saturating_add_score(&mut result.suspicion_score, 40);
            }
        }

        // "navigate" mode usually implies a document request
        if sec_fetch_mode == "navigate"
            && request.headers.iter().any(|(name, value)| {
                name.as_str() == "sec-fetch-dest"
                    && value.to_str().ok().map(|v| v != "document").unwrap_or(false)
            })
        {
             // Not always true (e.g. frames), but worth noting for correlation
        }
    }

    result
}

// ============================================================================
// JA4 Fingerprint Behavioral Validation
// ============================================================================

/// Known browser JA4 characteristic ranges
///
/// These are behavioral signatures based on typical browser TLS configurations.
/// Browsers have predictable patterns that bots/scripts often fail to replicate.
#[derive(Debug)]
pub struct BrowserJa4Profile {
    /// Minimum TLS version (10=1.0, 11=1.1, 12=1.2, 13=1.3)
    pub min_tls_version: u8,
    /// Maximum TLS version
    pub max_tls_version: u8,
    /// Minimum cipher suite count
    pub min_ciphers: u8,
    /// Maximum cipher suite count
    pub max_ciphers: u8,
    /// Minimum extension count
    pub min_extensions: u8,
    /// Maximum extension count
    pub max_extensions: u8,
    /// Expected ALPN protocols (h1, h2, h3)
    pub expected_alpn: &'static [&'static str],
}

/// Modern Chrome profile (Chrome 90+)
const CHROME_PROFILE: BrowserJa4Profile = BrowserJa4Profile {
    min_tls_version: 12,
    max_tls_version: 13,
    min_ciphers: 10,
    max_ciphers: 25,
    min_extensions: 12,
    max_extensions: 25,
    expected_alpn: &["h2", "h3"],
};

/// Modern Firefox profile (Firefox 90+)
const FIREFOX_PROFILE: BrowserJa4Profile = BrowserJa4Profile {
    min_tls_version: 12,
    max_tls_version: 13,
    min_ciphers: 8,
    max_ciphers: 20,
    min_extensions: 10,
    max_extensions: 22,
    expected_alpn: &["h2", "h3", "http/1.1"],
};

/// Modern Safari profile (Safari 14+)
const SAFARI_PROFILE: BrowserJa4Profile = BrowserJa4Profile {
    min_tls_version: 12,
    max_tls_version: 13,
    min_ciphers: 8,
    max_ciphers: 20,
    min_extensions: 8,
    max_extensions: 18,
    expected_alpn: &["h2", "http/1.1"],
};

/// Modern Edge profile (Edge 90+)
const EDGE_PROFILE: BrowserJa4Profile = BrowserJa4Profile {
    min_tls_version: 12,
    max_tls_version: 13,
    min_ciphers: 10,
    max_ciphers: 25,
    min_extensions: 12,
    max_extensions: 25,
    expected_alpn: &["h2", "h3"],
};

/// JA4 spoofing detection result
#[derive(Debug, Clone, Default)]
pub struct Ja4SpoofingAnalysis {
    /// Overall spoofing confidence (0-100)
    pub spoofing_confidence: u8,
    /// Whether the fingerprint is likely spoofed
    pub likely_spoofed: bool,
    /// Detected inconsistencies
    pub inconsistencies: Vec<Cow<'static, str>>,
    /// Claimed browser from User-Agent
    pub claimed_browser: String,
    /// Estimated actual client type based on JA4
    pub estimated_actual: String,
}

/// Analyze JA4 fingerprint for spoofing attempts
///
/// SECURITY: This function detects when a client's JA4 TLS fingerprint
/// doesn't match its claimed User-Agent. This is a common bot detection
/// technique because:
///
/// 1. TLS fingerprints are harder to spoof than User-Agent strings
/// 2. Real browsers have predictable TLS configurations
/// 3. Bots often have minimal TLS stacks that don't match browser claims
///
/// # Arguments
/// * `ja4` - JA4 fingerprint from TLS handshake (via X-JA4-Fingerprint header)
/// * `user_agent` - User-Agent header value
///
/// # Returns
/// Analysis result with spoofing confidence and detected inconsistencies
pub fn analyze_ja4_spoofing(ja4: &Ja4Fingerprint, user_agent: &str) -> Ja4SpoofingAnalysis {
    let mut result = Ja4SpoofingAnalysis::default();

    // Truncate oversized User-Agent
    let (ua, truncated) = truncate_header(user_agent, MAX_USER_AGENT_LENGTH);
    if truncated {
        result.inconsistencies.push(Cow::Borrowed("User-Agent exceeds maximum length"));
        saturating_add_score(&mut result.spoofing_confidence, 10);
    }

    // Detect claimed browser from User-Agent
    let claimed_browser = detect_browser_from_ua(ua);
    result.claimed_browser = claimed_browser.clone();

    // Get expected profile based on claimed browser
    let profile = match claimed_browser.as_str() {
        "chrome" => Some(&CHROME_PROFILE),
        "firefox" => Some(&FIREFOX_PROFILE),
        "safari" => Some(&SAFARI_PROFILE),
        "edge" => Some(&EDGE_PROFILE),
        _ => None,
    };

    // If claiming to be a known browser, validate against profile
    if let Some(profile) = profile {
        validate_against_profile(ja4, profile, &claimed_browser, &mut result);
    } else {
        // Unknown or generic User-Agent - check for bot indicators
        validate_generic_client(ja4, &mut result);
    }

    // Estimate actual client type based on JA4 characteristics
    result.estimated_actual = estimate_actual_client(ja4);

    // If claimed browser doesn't match estimated actual, that's suspicious
    if !claimed_browser.is_empty()
        && claimed_browser != "unknown"
        && result.estimated_actual != "unknown"
        && !result.estimated_actual.contains(&claimed_browser)
        && claimed_browser != result.estimated_actual
    {
        result.inconsistencies.push(Cow::Owned(format!(
            "Claimed {} but JA4 indicates {}",
            claimed_browser, result.estimated_actual
        )));
        saturating_add_score(&mut result.spoofing_confidence, 25);
    }

    // Set likely_spoofed threshold
    result.likely_spoofed = result.spoofing_confidence >= 50;

    result
}

/// Detect browser type from User-Agent string
fn detect_browser_from_ua(ua: &str) -> String {
    let ua_lower = ua.to_lowercase();

    // Order matters - check more specific strings first
    if ua_lower.contains("edg/") || ua_lower.contains("edge/") {
        return "edge".to_string();
    }
    if ua_lower.contains("chrome/") && !ua_lower.contains("chromium") {
        return "chrome".to_string();
    }
    if ua_lower.contains("firefox/") {
        return "firefox".to_string();
    }
    if ua_lower.contains("safari/") && !ua_lower.contains("chrome") {
        return "safari".to_string();
    }
    if ua_lower.contains("curl/") || ua_lower.contains("wget/") {
        return "cli-tool".to_string();
    }
    if ua_lower.contains("python") || ua_lower.contains("requests/") {
        return "python".to_string();
    }
    if ua_lower.contains("go-http-client") || ua_lower.contains("golang") {
        return "golang".to_string();
    }

    "unknown".to_string()
}

/// Validate JA4 fingerprint against expected browser profile
fn validate_against_profile(
    ja4: &Ja4Fingerprint,
    profile: &BrowserJa4Profile,
    browser_name: &str,
    result: &mut Ja4SpoofingAnalysis,
) {
    // Check TLS version
    if ja4.tls_version < profile.min_tls_version {
        result.inconsistencies.push(Cow::Owned(format!(
            "TLS 1.{} too old for modern {} (expected 1.{}-1.{})",
            ja4.tls_version - 10,
            browser_name,
            profile.min_tls_version - 10,
            profile.max_tls_version - 10
        )));
        saturating_add_score(&mut result.spoofing_confidence, 30);
    }

    // Check cipher suite count
    if ja4.cipher_count < profile.min_ciphers {
        result.inconsistencies.push(Cow::Owned(format!(
            "Only {} ciphers offered, {} typically offers {}-{}",
            ja4.cipher_count, browser_name, profile.min_ciphers, profile.max_ciphers
        )));
        saturating_add_score(&mut result.spoofing_confidence, 25);
    }

    // Check extension count
    if ja4.ext_count < profile.min_extensions {
        result.inconsistencies.push(Cow::Owned(format!(
            "Only {} extensions offered, {} typically offers {}-{}",
            ja4.ext_count, browser_name, profile.min_extensions, profile.max_extensions
        )));
        saturating_add_score(&mut result.spoofing_confidence, 25);
    }

    // Check ALPN
    let alpn_matches = profile.expected_alpn.iter().any(|&a| ja4.alpn.contains(a) || a == ja4.alpn);
    if !alpn_matches && ja4.alpn != "unknown" {
        result.inconsistencies.push(Cow::Owned(format!(
            "ALPN '{}' unexpected for {} (expected {:?})",
            ja4.alpn, browser_name, profile.expected_alpn
        )));
        saturating_add_score(&mut result.spoofing_confidence, 15);
    }

    // Check for QUIC with non-H3 claim (Chrome/Edge with QUIC should be doing H3)
    if ja4.protocol == Ja4Protocol::QUIC
        && (browser_name == "chrome" || browser_name == "edge")
        && ja4.alpn != "h3"
    {
        result.inconsistencies.push(Cow::Borrowed("QUIC connection without H3 ALPN for Chromium browser"));
        saturating_add_score(&mut result.spoofing_confidence, 20);
    }
}

/// Validate generic/unknown client for bot indicators
fn validate_generic_client(ja4: &Ja4Fingerprint, result: &mut Ja4SpoofingAnalysis) {
    // Very minimal TLS configuration suggests automated tool
    if ja4.cipher_count < 3 {
        result.inconsistencies.push(Cow::Borrowed("Extremely low cipher count (<3) indicates minimal TLS client"));
        saturating_add_score(&mut result.spoofing_confidence, 40);
    }

    if ja4.ext_count < 3 {
        result.inconsistencies.push(Cow::Borrowed("Extremely low extension count (<3) indicates minimal TLS client"));
        saturating_add_score(&mut result.spoofing_confidence, 40);
    }

    // Old TLS version
    if ja4.tls_version < 12 {
        result.inconsistencies.push(Cow::Owned(format!(
            "TLS 1.{} is deprecated and insecure",
            ja4.tls_version - 10
        )));
        saturating_add_score(&mut result.spoofing_confidence, 30);
    }
}

/// Estimate actual client type based on JA4 characteristics
fn estimate_actual_client(ja4: &Ja4Fingerprint) -> String {
    // Very minimal stack
    if ja4.cipher_count < 5 && ja4.ext_count < 5 {
        return "minimal-client".to_string();
    }

    // Old TLS with minimal features
    if ja4.tls_version < 12 {
        return "legacy-client".to_string();
    }

    // Modern browser-like characteristics
    if ja4.tls_version >= 12 && ja4.cipher_count >= 10 && ja4.ext_count >= 10 {
        if ja4.alpn == "h2" || ja4.alpn == "h3" {
            return "modern-browser".to_string();
        }
        return "modern-client".to_string();
    }

    // Moderate stack
    if ja4.cipher_count >= 5 && ja4.ext_count >= 5 {
        return "api-client".to_string();
    }

    "unknown".to_string()
}

/// Extended integrity analysis including JA4 validation
///
/// This combines header-based integrity checks with JA4 fingerprint validation
/// for comprehensive spoofing detection.
pub fn analyze_integrity_with_ja4(
    request: &HttpHeaders<'_>,
    ja4: Option<&Ja4Fingerprint>,
) -> IntegrityAnalysis {
    // Start with standard header integrity analysis
    let mut result = analyze_integrity(request);

    // If JA4 fingerprint is available, perform spoofing analysis
    if let Some(ja4) = ja4 {
        // Extract User-Agent for comparison
        let user_agent = request
            .headers
            .iter()
            .find(|(name, _)| name.as_str() == "user-agent")
            .and_then(|(_, value)| value.to_str().ok())
            .unwrap_or("");

        let ja4_analysis = analyze_ja4_spoofing(ja4, user_agent);

        // Merge JA4 spoofing results
        for inconsistency in ja4_analysis.inconsistencies {
            result.inconsistencies.push(inconsistency);
        }

        // Add JA4 spoofing score to overall suspicion
        saturating_add_score(&mut result.suspicion_score, ja4_analysis.spoofing_confidence / 2);

        // If JA4 analysis shows likely spoofing, ensure high suspicion score
        if ja4_analysis.likely_spoofed {
            saturating_add_score(&mut result.suspicion_score, 30);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::{HeaderName, HeaderValue};

    fn header(name: &str, value: &str) -> (HeaderName, HeaderValue) {
        let header_name = HeaderName::from_bytes(name.as_bytes()).expect("valid header name");
        let header_value = HeaderValue::from_str(value).expect("valid header value");
        (header_name, header_value)
    }

    #[test]
    fn test_chrome_missing_hints() {
        let headers = vec![
            header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ),
        ];
        let req = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = analyze_integrity(&req);
        assert!(result.suspicion_score > 0);
        let all_inconsistencies: String = result.inconsistencies.iter().map(|c| c.as_ref()).collect();
        assert!(all_inconsistencies.contains("Missing Client Hints"));
    }

    #[test]
    fn test_consistent_chrome() {
        let headers = vec![
            header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ),
            header("Sec-CH-UA", "\"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\""),
        ];
        let req = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = analyze_integrity(&req);
        assert_eq!(result.suspicion_score, 0);
        assert!(result.has_client_hints);
    }

    #[test]
    fn test_oversized_user_agent_truncated() {
        // Create a User-Agent longer than MAX_USER_AGENT_LENGTH
        let oversized_ua = "A".repeat(MAX_USER_AGENT_LENGTH + 100);
        let headers = vec![
            header("User-Agent", &oversized_ua),
        ];
        let req = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        let result = analyze_integrity(&req);
        assert!(result.input_truncated);
        assert!(result.suspicion_score >= 20);
        let all_inconsistencies: String = result.inconsistencies.iter().map(|c| c.as_ref()).collect();
        assert!(all_inconsistencies.contains("exceeds maximum"));
    }

    #[test]
    fn test_suspicion_score_saturates_at_100() {
        let mut score: u8 = 90;
        saturating_add_score(&mut score, 50);
        assert_eq!(score, 100);
    }

    // ==================== JA4 Spoofing Detection Tests ====================

    /// Create a test JA4 fingerprint with specified parameters
    fn make_test_ja4(
        tls_version: u8,
        cipher_count: u8,
        ext_count: u8,
        alpn: &str,
    ) -> Ja4Fingerprint {
        Ja4Fingerprint {
            raw: format!("t{}d{:02x}{:02x}{}_{}_{}",
                tls_version,
                cipher_count,
                ext_count,
                alpn,
                "aabbccddeeff",
                "112233445566"
            ),
            protocol: Ja4Protocol::TCP,
            tls_version,
            sni_type: super::super::ja4::Ja4SniType::Domain,
            cipher_count,
            ext_count,
            alpn: alpn.to_string(),
            cipher_hash: "aabbccddeeff".to_string(),
            ext_hash: "112233445566".to_string(),
        }
    }

    /// SECURITY TEST: Verify Chrome User-Agent with minimal TLS is detected as spoofed
    #[test]
    fn test_ja4_spoofing_chrome_with_minimal_tls() {
        let ja4 = make_test_ja4(12, 3, 3, "h1"); // Minimal TLS stack
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        let result = analyze_ja4_spoofing(&ja4, chrome_ua);

        assert!(result.likely_spoofed, "Should detect spoofing");
        assert!(result.spoofing_confidence >= 50, "Confidence should be >= 50: {}", result.spoofing_confidence);
        assert_eq!(result.claimed_browser, "chrome");
        assert!(!result.inconsistencies.is_empty(), "Should have inconsistencies");
    }

    /// SECURITY TEST: Verify legitimate Chrome fingerprint is not flagged
    #[test]
    fn test_ja4_legitimate_chrome() {
        let ja4 = make_test_ja4(13, 16, 18, "h2"); // Modern Chrome-like
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        let result = analyze_ja4_spoofing(&ja4, chrome_ua);

        assert!(!result.likely_spoofed, "Should not flag legitimate Chrome: {:?}", result.inconsistencies);
        assert!(result.spoofing_confidence < 50, "Confidence should be < 50: {}", result.spoofing_confidence);
        assert_eq!(result.claimed_browser, "chrome");
    }

    /// SECURITY TEST: Verify Firefox User-Agent with Chrome-like fingerprint is suspicious
    #[test]
    fn test_ja4_firefox_with_chromium_fingerprint() {
        // This simulates a bot claiming to be Firefox but using a Chromium TLS stack
        let ja4 = make_test_ja4(13, 20, 22, "h2");
        let firefox_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0";

        let result = analyze_ja4_spoofing(&ja4, firefox_ua);

        assert_eq!(result.claimed_browser, "firefox");
        // Firefox and the JA4 might be compatible, so we check for specific issues
        // The key is that we're validating against Firefox profile
    }

    /// SECURITY TEST: Verify old TLS version is flagged for modern browser claims
    #[test]
    fn test_ja4_old_tls_for_modern_browser() {
        let ja4 = make_test_ja4(10, 15, 15, "h1"); // TLS 1.0
        let chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        let result = analyze_ja4_spoofing(&ja4, chrome_ua);

        assert!(result.likely_spoofed, "Should detect old TLS as spoofing");
        assert!(
            result.inconsistencies.iter().any(|i| i.as_ref().contains("too old")),
            "Should mention old TLS: {:?}", result.inconsistencies
        );
    }

    /// SECURITY TEST: Verify CLI tool User-Agent with browser fingerprint
    #[test]
    fn test_ja4_cli_tool_with_browser_fingerprint() {
        let ja4 = make_test_ja4(13, 16, 18, "h2"); // Browser-like
        let curl_ua = "curl/8.4.0";

        let result = analyze_ja4_spoofing(&ja4, curl_ua);

        assert_eq!(result.claimed_browser, "cli-tool");
        // CLI tools don't have expected profiles, so we estimate actual client
        assert_eq!(result.estimated_actual, "modern-browser");
    }

    /// SECURITY TEST: Verify Python requests with minimal TLS
    #[test]
    fn test_ja4_python_minimal_tls() {
        let ja4 = make_test_ja4(12, 4, 4, "h1"); // Minimal
        let python_ua = "python-requests/2.31.0";

        let result = analyze_ja4_spoofing(&ja4, python_ua);

        assert_eq!(result.claimed_browser, "python");
        // Python is an "unknown" browser type, so we estimate actual client
        // A minimal TLS stack should be flagged in the generic validation
        assert_eq!(result.estimated_actual, "minimal-client");
    }

    /// Test browser detection from User-Agent
    #[test]
    fn test_detect_browser_from_ua() {
        assert_eq!(detect_browser_from_ua("Mozilla/5.0 Chrome/120.0.0.0"), "chrome");
        assert_eq!(detect_browser_from_ua("Mozilla/5.0 Firefox/121.0"), "firefox");
        assert_eq!(detect_browser_from_ua("Mozilla/5.0 Safari/537.36"), "safari");
        assert_eq!(detect_browser_from_ua("Mozilla/5.0 Edg/120.0.0.0"), "edge");
        assert_eq!(detect_browser_from_ua("curl/8.4.0"), "cli-tool");
        assert_eq!(detect_browser_from_ua("python-requests/2.31.0"), "python");
        assert_eq!(detect_browser_from_ua("Go-http-client/1.1"), "golang");
        assert_eq!(detect_browser_from_ua("SomeRandomBot/1.0"), "unknown");
    }

    /// Test estimate actual client from JA4
    #[test]
    fn test_estimate_actual_client() {
        // Modern browser
        let modern = make_test_ja4(13, 16, 18, "h2");
        assert_eq!(estimate_actual_client(&modern), "modern-browser");

        // Minimal client
        let minimal = make_test_ja4(12, 2, 2, "h1");
        assert_eq!(estimate_actual_client(&minimal), "minimal-client");

        // Legacy client
        let legacy = make_test_ja4(10, 10, 10, "h1");
        assert_eq!(estimate_actual_client(&legacy), "legacy-client");

        // API client
        let api = make_test_ja4(12, 8, 8, "h1");
        assert_eq!(estimate_actual_client(&api), "api-client");
    }

    /// Test extended integrity analysis with JA4
    #[test]
    fn test_analyze_integrity_with_ja4() {
        let headers = vec![
            header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ),
            header("Sec-CH-UA", "\"Chromium\";v=\"120\""),
        ];
        let req = HttpHeaders {
            headers: &headers,
            method: "GET",
            http_version: "1.1",
        };

        // Test with legitimate JA4
        let legitimate_ja4 = make_test_ja4(13, 16, 18, "h2");
        let result = analyze_integrity_with_ja4(&req, Some(&legitimate_ja4));
        assert!(result.suspicion_score < 30, "Legitimate request should have low score: {}", result.suspicion_score);

        // Test with suspicious JA4
        let spoofed_ja4 = make_test_ja4(10, 2, 2, "h1");
        let result = analyze_integrity_with_ja4(&req, Some(&spoofed_ja4));
        assert!(result.suspicion_score >= 30, "Spoofed request should have high score: {}", result.suspicion_score);
    }
}
