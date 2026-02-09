//! Main crawler detection engine.
//!
//! ## Security
//! - Input length validation prevents ReDoS attacks
//! - DNS failure policy prevents fail-open vulnerabilities
//! - Stats map size limits prevent memory exhaustion

use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use super::bad_bots::{BadBotSeverity, BadBotSignature, BAD_BOT_SIGNATURES};
use super::cache::VerificationCache;
use super::config::{CrawlerConfig, DnsFailurePolicy};
use super::dns_resolver::{DnsError, DnsResolver};
use super::known_crawlers::{CrawlerDefinition, KNOWN_CRAWLERS};

/// Maximum allowed length for User-Agent string (512 bytes)
pub const MAX_USER_AGENT_LENGTH: usize = 512;

/// Trait for crawler detection, enabling mock implementations for testing.
///
/// This trait abstracts the crawler detection functionality so that:
/// - Production code uses `CrawlerDetector` with real DNS verification
/// - Test code can use mock implementations without network calls
#[async_trait::async_trait]
pub trait CrawlerDetection: Send + Sync {
    /// Verify a request's crawler status.
    async fn verify(&self, user_agent: &str, client_ip: IpAddr) -> CrawlerVerificationResult;

    /// Check if the detector is enabled.
    fn is_enabled(&self) -> bool;

    /// Check if bad bots should be blocked.
    fn should_block_bad_bots(&self) -> bool;

    /// Get statistics snapshot.
    fn stats(&self) -> CrawlerStatsSnapshot;
}

/// Exclusion list for generic bot patterns to prevent false positives.
/// Maps signature name to list of crawler names that should be excluded.
/// This is handled in code (not regex) to prevent ReDoS attacks.
fn get_exclusions(signature_name: &str) -> &'static [&'static str] {
    match signature_name {
        "GenericBot" => &[
            "googlebot",
            "bingbot",
            "yandexbot",
            "baiduspider",
            "facebookexternalhit",
            "twitterbot",
            "linkedinbot",
            "applebot",
            "pinterestbot",
            "slackbot",
            "discordbot",
        ],
        "GenericCrawler" => &["googlebot", "bingbot", "yandexbot", "baiduspider", "slurp"],
        "GenericSpider" => &["googlebot", "bingbot", "yandexbot", "baiduspider", "slurp"],
        "PythonUrllib" => &["googlebot"],
        _ => &[],
    }
}

/// Method used for crawler verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Verified via DNS reverse+forward lookup
    Dns,
    /// Verified via IP range check
    IpRange,
    /// Not verified (UA match only)
    Unverified,
}

/// Result of crawler verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerVerificationResult {
    /// Is this a known crawler
    pub is_crawler: bool,
    /// Crawler name if matched
    pub crawler_name: Option<String>,
    /// Was the crawler verified
    pub verified: bool,
    /// How was it verified
    pub verification_method: VerificationMethod,
    /// Did the user agent match a crawler pattern
    pub user_agent_match: bool,
    /// Did the reverse DNS match
    pub reverse_dns_match: bool,
    /// Did the IP range match (if applicable)
    pub ip_range_match: bool,
    /// Is this request suspicious (e.g., UA spoofing)
    pub suspicious: bool,
    /// Reasons for suspicion (uses Cow for zero-copy known messages)
    pub suspicion_reasons: Vec<Cow<'static, str>>,
    /// Bad bot match if any
    pub bad_bot_match: Option<String>,
    /// Bad bot severity if matched
    pub bad_bot_severity: Option<BadBotSeverity>,
    /// Whether input was rejected due to length limits
    pub input_rejected: bool,
    /// Risk penalty applied due to DNS failure policy
    pub dns_failure_penalty: u32,
}

impl Default for CrawlerVerificationResult {
    fn default() -> Self {
        Self {
            is_crawler: false,
            crawler_name: None,
            verified: false,
            verification_method: VerificationMethod::Unverified,
            user_agent_match: false,
            reverse_dns_match: false,
            ip_range_match: false,
            suspicious: false,
            suspicion_reasons: Vec::new(),
            bad_bot_match: None,
            bad_bot_severity: None,
            input_rejected: false,
            dns_failure_penalty: 0,
        }
    }
}

/// Statistics for crawler detection.
pub struct CrawlerStats {
    pub total_verifications: AtomicU64,
    pub verified_crawlers: AtomicU64,
    pub unverified_crawlers: AtomicU64,
    pub bad_bots: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub dns_successes: AtomicU64,
    pub dns_failures: AtomicU64,
    pub dns_rate_limited: AtomicU64,
    pub input_rejected: AtomicU64,
    /// Per-crawler name counts (bounded by max_stats_entries)
    pub by_crawler_name: DashMap<String, u64>,
    /// Per-bad-bot signature counts (bounded by max_stats_entries)
    pub by_bad_bot: DashMap<String, u64>,
}

impl CrawlerStats {
    pub fn new() -> Self {
        Self {
            total_verifications: AtomicU64::new(0),
            verified_crawlers: AtomicU64::new(0),
            unverified_crawlers: AtomicU64::new(0),
            bad_bots: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            dns_successes: AtomicU64::new(0),
            dns_failures: AtomicU64::new(0),
            dns_rate_limited: AtomicU64::new(0),
            input_rejected: AtomicU64::new(0),
            by_crawler_name: DashMap::new(),
            by_bad_bot: DashMap::new(),
        }
    }
}

impl Default for CrawlerStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of crawler stats for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerStatsSnapshot {
    pub total_verifications: u64,
    pub verified_crawlers: u64,
    pub unverified_crawlers: u64,
    pub bad_bots: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub dns_successes: u64,
    pub dns_failures: u64,
    pub dns_rate_limited: u64,
    pub input_rejected: u64,
}

impl From<&CrawlerStats> for CrawlerStatsSnapshot {
    fn from(stats: &CrawlerStats) -> Self {
        Self {
            total_verifications: stats.total_verifications.load(Ordering::Relaxed),
            verified_crawlers: stats.verified_crawlers.load(Ordering::Relaxed),
            unverified_crawlers: stats.unverified_crawlers.load(Ordering::Relaxed),
            bad_bots: stats.bad_bots.load(Ordering::Relaxed),
            cache_hits: stats.cache_hits.load(Ordering::Relaxed),
            cache_misses: stats.cache_misses.load(Ordering::Relaxed),
            dns_successes: stats.dns_successes.load(Ordering::Relaxed),
            dns_failures: stats.dns_failures.load(Ordering::Relaxed),
            dns_rate_limited: stats.dns_rate_limited.load(Ordering::Relaxed),
            input_rejected: stats.input_rejected.load(Ordering::Relaxed),
        }
    }
}

/// Compiled regex pattern with associated crawler definition.
struct CompiledCrawlerPattern {
    ua_regex: Regex,
    dns_regex: Regex,
    definition: &'static CrawlerDefinition,
}

/// Compiled regex pattern with associated bad bot signature.
struct CompiledBadBotPattern {
    regex: Regex,
    signature: &'static BadBotSignature,
}

/// Main crawler detection engine.
pub struct CrawlerDetector {
    config: CrawlerConfig,
    cache: VerificationCache,
    dns: Option<DnsResolver>,
    stats: CrawlerStats,
    crawler_patterns: Vec<CompiledCrawlerPattern>,
    bad_bot_patterns: Vec<CompiledBadBotPattern>,
}

impl CrawlerDetector {
    /// Create a new crawler detector.
    pub async fn new(config: CrawlerConfig) -> Result<Self, String> {
        // Validate configuration
        config.validate()?;

        // Compile crawler patterns
        let mut crawler_patterns = Vec::new();
        for def in KNOWN_CRAWLERS {
            let ua_regex = Regex::new(def.user_agent_pattern)
                .map_err(|e| format!("Invalid UA pattern for {}: {}", def.name, e))?;
            let dns_regex = Regex::new(def.reverse_dns_pattern)
                .map_err(|e| format!("Invalid DNS pattern for {}: {}", def.name, e))?;
            crawler_patterns.push(CompiledCrawlerPattern {
                ua_regex,
                dns_regex,
                definition: def,
            });
        }

        // Compile bad bot patterns
        let mut bad_bot_patterns = Vec::new();
        for sig in BAD_BOT_SIGNATURES {
            let regex = Regex::new(sig.pattern)
                .map_err(|e| format!("Invalid bad bot pattern for {}: {}", sig.name, e))?;
            bad_bot_patterns.push(CompiledBadBotPattern {
                regex,
                signature: sig,
            });
        }

        // Create DNS resolver if verification is enabled (with rate limiting)
        let dns = if config.verify_legitimate_crawlers {
            Some(
                DnsResolver::new(config.dns_timeout_ms, config.max_concurrent_dns_lookups)
                    .await
                    .map_err(|e| format!("Failed to create DNS resolver: {}", e))?,
            )
        } else {
            None
        };

        let cache = VerificationCache::new(&config);

        Ok(Self {
            config,
            cache,
            dns,
            stats: CrawlerStats::new(),
            crawler_patterns,
            bad_bot_patterns,
        })
    }

    /// Create a disabled crawler detector when initialization fails.
    pub fn disabled() -> Self {
        let mut config = CrawlerConfig::default();
        config.enabled = false;
        config.verify_legitimate_crawlers = false;
        config.block_bad_bots = false;

        Self {
            cache: VerificationCache::new(&config),
            dns: None,
            stats: CrawlerStats::new(),
            crawler_patterns: Vec::new(),
            bad_bot_patterns: Vec::new(),
            config,
        }
    }

    /// Verify a request's crawler status.
    ///
    /// ## Security
    /// - Validates user_agent length to prevent ReDoS
    /// - Applies DNS failure policy for fail-secure behavior
    /// - Bounds stats map sizes to prevent memory exhaustion
    pub async fn verify(&self, user_agent: &str, client_ip: IpAddr) -> CrawlerVerificationResult {
        self.stats
            .total_verifications
            .fetch_add(1, Ordering::Relaxed);

        // Security: Validate input length to prevent ReDoS
        if user_agent.len() > MAX_USER_AGENT_LENGTH {
            self.stats.input_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                ip = %client_ip,
                ua_len = user_agent.len(),
                "Rejected oversized User-Agent (max {})",
                MAX_USER_AGENT_LENGTH
            );
            return CrawlerVerificationResult {
                suspicious: true,
                input_rejected: true,
                suspicion_reasons: vec![Cow::Borrowed("User-Agent exceeds maximum allowed length")],
                ..Default::default()
            };
        }

        // Check cache first
        let cache_key = VerificationCache::cache_key(user_agent, client_ip);
        if let Some(cached) = self.cache.get_verification(&cache_key) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let mut result = CrawlerVerificationResult::default();

        // Check for bad bots first
        if let Some(bad_bot) = self.check_bad_bot(user_agent) {
            self.stats.bad_bots.fetch_add(1, Ordering::Relaxed);
            // Bound stats map size to prevent memory exhaustion from novel bot names
            self.record_bad_bot_stat(bad_bot.name);

            result.bad_bot_match = Some(bad_bot.name.to_string());
            result.bad_bot_severity = Some(bad_bot.severity);
            result.suspicious = true;
            // Note: We don't expose the matched bot name in the result to prevent info disclosure
            result
                .suspicion_reasons
                .push(Cow::Borrowed("Matched known malicious bot signature"));

            // Cache and return immediately for bad bots
            self.cache.put_verification(cache_key, result.clone());
            return result;
        }

        // Check for known crawler UA match
        let crawler_match = self.match_crawler_ua(user_agent);
        if let Some(pattern) = crawler_match {
            result.is_crawler = true;
            result.crawler_name = Some(pattern.definition.name.to_string());
            result.user_agent_match = true;

            // Verify if required
            if pattern.definition.verification_required && self.config.verify_legitimate_crawlers {
                result = self.verify_crawler(result, pattern, client_ip).await;
            } else {
                result.verified = !pattern.definition.verification_required;
                result.verification_method = VerificationMethod::Unverified;
                self.stats
                    .unverified_crawlers
                    .fetch_add(1, Ordering::Relaxed);
            }

            // Bound stats map size
            self.record_crawler_stat(pattern.definition.name);
        }

        // Cache result
        self.cache.put_verification(cache_key, result.clone());
        result
    }

    /// Record crawler stat with bounded map size
    fn record_crawler_stat(&self, name: &str) {
        if self.stats.by_crawler_name.len() < self.config.max_stats_entries {
            *self
                .stats
                .by_crawler_name
                .entry(name.to_string())
                .or_insert(0) += 1;
        } else if self.stats.by_crawler_name.contains_key(name) {
            // Update existing entry even if at capacity
            *self
                .stats
                .by_crawler_name
                .entry(name.to_string())
                .or_insert(0) += 1;
        }
        // Otherwise drop the stat to prevent unbounded growth
    }

    /// Record bad bot stat with bounded map size
    fn record_bad_bot_stat(&self, name: &str) {
        if self.stats.by_bad_bot.len() < self.config.max_stats_entries {
            *self.stats.by_bad_bot.entry(name.to_string()).or_insert(0) += 1;
        } else if self.stats.by_bad_bot.contains_key(name) {
            *self.stats.by_bad_bot.entry(name.to_string()).or_insert(0) += 1;
        }
    }

    /// Match user agent against crawler patterns.
    fn match_crawler_ua(&self, user_agent: &str) -> Option<&CompiledCrawlerPattern> {
        self.crawler_patterns
            .iter()
            .find(|p| p.ua_regex.is_match(user_agent))
    }

    /// Verify a crawler via DNS.
    ///
    /// ## Security
    /// - Applies DnsFailurePolicy for fail-secure behavior
    /// - Does not expose internal details in suspicion reasons
    async fn verify_crawler(
        &self,
        mut result: CrawlerVerificationResult,
        pattern: &CompiledCrawlerPattern,
        client_ip: IpAddr,
    ) -> CrawlerVerificationResult {
        let dns = match &self.dns {
            Some(d) => d,
            None => {
                result.verification_method = VerificationMethod::Unverified;
                return result;
            }
        };

        // Check IP range first if available
        if let Some(ranges) = pattern.definition.ip_ranges {
            if self.check_ip_ranges(client_ip, ranges) {
                result.verified = true;
                result.ip_range_match = true;
                result.verification_method = VerificationMethod::IpRange;
                self.stats.verified_crawlers.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        // DNS verification
        match dns.verify_ip(client_ip).await {
            Ok((verified, hostname)) => {
                self.stats.dns_successes.fetch_add(1, Ordering::Relaxed);

                if let Some(ref hostname) = hostname {
                    result.reverse_dns_match = pattern.dns_regex.is_match(hostname);

                    if verified && result.reverse_dns_match {
                        result.verified = true;
                        result.verification_method = VerificationMethod::Dns;
                        self.stats.verified_crawlers.fetch_add(1, Ordering::Relaxed);
                    } else {
                        // UA claims crawler but DNS doesn't match - suspicious!
                        // Log details internally but don't expose hostname in result
                        tracing::warn!(
                            ip = %client_ip,
                            claimed_crawler = %pattern.definition.name,
                            hostname = %hostname,
                            "Crawler verification failed: DNS hostname mismatch"
                        );
                        result.suspicious = true;
                        result
                            .suspicion_reasons
                            .push(Cow::Borrowed("Crawler claim could not be verified via DNS"));
                        self.stats
                            .unverified_crawlers
                            .fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    tracing::warn!(
                        ip = %client_ip,
                        claimed_crawler = %pattern.definition.name,
                        "Crawler verification failed: no PTR record"
                    );
                    result.suspicious = true;
                    result.suspicion_reasons.push(Cow::Borrowed(
                        "Crawler claim could not be verified: no reverse DNS",
                    ));
                    self.stats
                        .unverified_crawlers
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(DnsError::RateLimited) => {
                self.stats.dns_rate_limited.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(ip = %client_ip, "DNS verification rate limited");
                // Apply DNS failure policy
                self.apply_dns_failure_policy(&mut result, pattern.definition.name);
            }
            Err(e) => {
                self.stats.dns_failures.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(ip = %client_ip, error = %e, "DNS verification failed");
                // Apply DNS failure policy instead of silently continuing
                self.apply_dns_failure_policy(&mut result, pattern.definition.name);
            }
        }

        result
    }

    /// Apply DNS failure policy to a verification result.
    ///
    /// This is called when DNS verification fails (timeout, rate limited, etc.)
    /// and determines how to handle the request based on configuration.
    fn apply_dns_failure_policy(
        &self,
        result: &mut CrawlerVerificationResult,
        _crawler_name: &str,
    ) {
        match self.config.dns_failure_policy {
            DnsFailurePolicy::Allow => {
                // Fail-open: allow but log
                tracing::debug!("DNS failure policy: allowing unverified crawler");
                self.stats
                    .unverified_crawlers
                    .fetch_add(1, Ordering::Relaxed);
            }
            DnsFailurePolicy::ApplyRiskPenalty => {
                // Fail-cautious: apply risk penalty
                result.dns_failure_penalty = self.config.dns_failure_risk_penalty;
                result.suspicion_reasons.push(Cow::Borrowed(
                    "DNS verification unavailable - temporary penalty applied",
                ));
                self.stats
                    .unverified_crawlers
                    .fetch_add(1, Ordering::Relaxed);
            }
            DnsFailurePolicy::Block => {
                // Fail-secure: mark as suspicious for blocking
                result.suspicious = true;
                result
                    .suspicion_reasons
                    .push(Cow::Borrowed("DNS verification required but unavailable"));
                self.stats
                    .unverified_crawlers
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Check if IP is in any of the given CIDR ranges.
    fn check_ip_ranges(&self, ip: IpAddr, ranges: &[&str]) -> bool {
        for range in ranges {
            if let Ok(network) = range.parse::<ipnet::IpNet>() {
                if network.contains(&ip) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if user agent matches a bad bot signature.
    ///
    /// ## Security
    /// Exclusion logic is handled in code (not regex) to prevent ReDoS attacks
    /// from complex negative lookaheads.
    pub fn check_bad_bot(&self, user_agent: &str) -> Option<&'static BadBotSignature> {
        let ua_lower = user_agent.to_lowercase();

        self.bad_bot_patterns
            .iter()
            .find(|p| {
                // Check if pattern matches
                if !p.regex.is_match(user_agent) {
                    return false;
                }

                // Check exclusions (handled in code to avoid ReDoS)
                let exclusions = get_exclusions(p.signature.name);
                for excluded in exclusions {
                    if ua_lower.contains(excluded) {
                        return false;
                    }
                }

                true
            })
            .map(|p| p.signature)
    }

    /// Get statistics snapshot.
    pub fn stats(&self) -> CrawlerStatsSnapshot {
        CrawlerStatsSnapshot::from(&self.stats)
    }

    /// Check if the detector is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the configuration.
    pub fn config(&self) -> &CrawlerConfig {
        &self.config
    }

    /// Check if bad bots should be blocked.
    pub fn should_block_bad_bots(&self) -> bool {
        self.config.block_bad_bots
    }
}

/// Implement the CrawlerDetection trait for CrawlerDetector
#[async_trait::async_trait]
impl CrawlerDetection for CrawlerDetector {
    async fn verify(&self, user_agent: &str, client_ip: IpAddr) -> CrawlerVerificationResult {
        // Delegate to the inherent method
        CrawlerDetector::verify(self, user_agent, client_ip).await
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    fn should_block_bad_bots(&self) -> bool {
        self.config.block_bad_bots
    }

    fn stats(&self) -> CrawlerStatsSnapshot {
        CrawlerStatsSnapshot::from(&self.stats)
    }
}

/// Mock crawler detector for testing (doesn't perform actual DNS lookups)
#[cfg(test)]
pub struct MockCrawlerDetector {
    pub enabled: bool,
    pub block_bad_bots: bool,
    pub results: std::collections::HashMap<String, CrawlerVerificationResult>,
}

#[cfg(test)]
impl MockCrawlerDetector {
    pub fn new() -> Self {
        Self {
            enabled: true,
            block_bad_bots: true,
            results: std::collections::HashMap::new(),
        }
    }

    pub fn with_result(mut self, user_agent: &str, result: CrawlerVerificationResult) -> Self {
        self.results.insert(user_agent.to_string(), result);
        self
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl CrawlerDetection for MockCrawlerDetector {
    async fn verify(&self, user_agent: &str, _client_ip: IpAddr) -> CrawlerVerificationResult {
        self.results.get(user_agent).cloned().unwrap_or_default()
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn should_block_bad_bots(&self) -> bool {
        self.block_bad_bots
    }

    fn stats(&self) -> CrawlerStatsSnapshot {
        CrawlerStatsSnapshot {
            total_verifications: 0,
            verified_crawlers: 0,
            unverified_crawlers: 0,
            bad_bots: 0,
            cache_hits: 0,
            cache_misses: 0,
            dns_successes: 0,
            dns_failures: 0,
            dns_rate_limited: 0,
            input_rejected: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bad_bot_detection() {
        let ua = "sqlmap/1.0";
        for sig in BAD_BOT_SIGNATURES {
            let regex = Regex::new(sig.pattern).unwrap();
            if regex.is_match(ua) {
                assert_eq!(sig.name, "SQLMap");
                assert_eq!(sig.severity, BadBotSeverity::High);
                return;
            }
        }
        panic!("SQLMap not detected");
    }

    #[test]
    fn test_crawler_pattern_matching() {
        let ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
        for def in KNOWN_CRAWLERS {
            let regex = Regex::new(def.user_agent_pattern).unwrap();
            if regex.is_match(ua) {
                assert_eq!(def.name, "Googlebot");
                return;
            }
        }
        panic!("Googlebot not detected");
    }

    #[test]
    fn test_normal_ua_not_detected() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

        for sig in BAD_BOT_SIGNATURES {
            let regex = Regex::new(sig.pattern).unwrap();
            // Skip the empty UA check which would match anything
            if sig.pattern == "^$" {
                continue;
            }
            assert!(
                !regex.is_match(ua),
                "Normal UA matched bad bot: {}",
                sig.name
            );
        }
    }
}
