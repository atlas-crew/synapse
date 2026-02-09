//! Cookie Challenge Manager
//!
//! Implements silent tracking cookies for actor correlation. The cookie challenge
//! is the softest form of challenge - it doesn't require any user interaction but
//! allows correlation of requests from the same actor across sessions.
//!
//! # Cookie Format
//!
//! The cookie value follows the format: `{timestamp}.{actor_id_hash}.{hmac_signature}`
//!
//! - `timestamp`: Unix epoch seconds when cookie was issued
//! - `actor_id_hash`: SHA256 hash of actor ID (first 16 hex chars)
//! - `hmac_signature`: HMAC-SHA256 signature over timestamp and actor_id_hash
//!
//! # Security Properties
//!
//! - Cookies are signed with HMAC-SHA256 to prevent tampering
//! - Actor ID is hashed to prevent direct exposure
//! - Timestamps enable expiration checking
//! - HttpOnly and Secure flags prevent XSS and MITM attacks

use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tracing::error;

use super::{ChallengeResponse, Interrogator, ValidationResult};

type HmacSha256 = Hmac<Sha256>;

/// A cookie challenge instance
#[derive(Debug, Clone)]
pub struct CookieChallenge {
    /// Name of the cookie
    pub cookie_name: String,
    /// Value of the cookie (timestamp.hash.signature)
    pub cookie_value: String,
    /// Actor ID this cookie is for
    pub actor_id: String,
    /// When the cookie was created (unix timestamp secs)
    pub created_at: u64,
    /// When the cookie expires (unix timestamp secs)
    pub expires_at: u64,
}

/// Configuration for cookie challenges
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Name of the tracking cookie (default: "__tx_verify")
    pub cookie_name: String,
    /// Cookie max age in seconds (default: 86400 = 1 day)
    pub cookie_max_age_secs: u64,
    /// HMAC secret key (MUST be provided, 32 bytes)
    pub secret_key: [u8; 32],
    /// Only send cookie over HTTPS (default: true)
    pub secure_only: bool,
    /// Prevent JavaScript access to cookie (default: true)
    pub http_only: bool,
    /// SameSite attribute (default: "Strict")
    pub same_site: String,
}

/// Error returned when CookieManager construction fails
#[derive(Debug, Clone, PartialEq)]
pub enum CookieError {
    /// Secret key is all zeros (insecure)
    InvalidSecretKey,
}

impl std::fmt::Display for CookieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CookieError::InvalidSecretKey => {
                write!(f, "Secret key must not be all zeros")
            }
        }
    }
}

impl std::error::Error for CookieError {}

/// Statistics for cookie challenge operations
#[derive(Debug, Default)]
pub struct CookieStats {
    /// Total cookies issued
    pub cookies_issued: AtomicU64,
    /// Successfully validated cookies
    pub cookies_validated: AtomicU64,
    /// Invalid cookies (bad signature, wrong format)
    pub cookies_invalid: AtomicU64,
    /// Expired cookies
    pub cookies_expired: AtomicU64,
    /// Actors correlated via cookie
    pub actors_correlated: AtomicU64,
}

impl CookieStats {
    /// Create a snapshot of current stats
    pub fn snapshot(&self) -> CookieStatsSnapshot {
        CookieStatsSnapshot {
            cookies_issued: self.cookies_issued.load(Ordering::Relaxed),
            cookies_validated: self.cookies_validated.load(Ordering::Relaxed),
            cookies_invalid: self.cookies_invalid.load(Ordering::Relaxed),
            cookies_expired: self.cookies_expired.load(Ordering::Relaxed),
            actors_correlated: self.actors_correlated.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cookie stats for serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct CookieStatsSnapshot {
    pub cookies_issued: u64,
    pub cookies_validated: u64,
    pub cookies_invalid: u64,
    pub cookies_expired: u64,
    pub actors_correlated: u64,
}

/// Thread-safe cookie challenge manager
#[derive(Debug)]
pub struct CookieManager {
    /// Active challenges by actor ID
    challenges: DashMap<String, CookieChallenge>,
    /// Configuration
    config: CookieConfig,
    /// Statistics
    stats: CookieStats,
}

impl CookieManager {
    /// Create a new cookie manager with the given configuration
    ///
    /// # Errors
    ///
    /// Returns `CookieError::InvalidSecretKey` if the secret key is all zeros.
    pub fn new(config: CookieConfig) -> Result<Self, CookieError> {
        // Validate secret key is not all zeros
        if config.secret_key == [0u8; 32] {
            return Err(CookieError::InvalidSecretKey);
        }

        Ok(Self {
            challenges: DashMap::new(),
            config,
            stats: CookieStats::default(),
        })
    }

    /// Create a new cookie manager with a best-effort fallback for invalid secrets.
    ///
    /// This avoids panicking on invalid keys and logs a warning instead.
    pub fn new_fallback(mut config: CookieConfig) -> Self {
        if config.secret_key == [0u8; 32] {
            error!("CookieManager secret key invalid; forcing non-zero fallback key");
            config.secret_key[0] = 1;
        }

        Self {
            challenges: DashMap::new(),
            config,
            stats: CookieStats::default(),
        }
    }

    /// Create a new cookie manager without validating the secret key.
    ///
    /// # Safety
    ///
    /// This should only be used in tests. Using a weak secret key in production
    /// allows attackers to forge valid cookies.
    #[cfg(test)]
    pub fn new_unchecked(config: CookieConfig) -> Self {
        Self {
            challenges: DashMap::new(),
            config,
            stats: CookieStats::default(),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &CookieConfig {
        &self.config
    }

    /// Generate a tracking cookie for an actor
    pub fn generate_tracking_cookie(&self, actor_id: &str) -> CookieChallenge {
        let now = now_secs();
        let expires_at = now + self.config.cookie_max_age_secs;

        // Hash the actor ID
        let actor_hash = self.hash_actor_id(actor_id);

        // Create signature over timestamp.actor_hash
        let data_to_sign = format!("{}.{}", now, actor_hash);
        let signature = self.sign_data(&data_to_sign);

        // Cookie value: timestamp.actor_hash.signature
        let cookie_value = format!("{}.{}.{}", now, actor_hash, signature);

        let challenge = CookieChallenge {
            cookie_name: self.config.cookie_name.clone(),
            cookie_value,
            actor_id: actor_id.to_string(),
            created_at: now,
            expires_at,
        };

        // Store challenge for later validation
        self.challenges
            .insert(actor_id.to_string(), challenge.clone());
        self.stats.cookies_issued.fetch_add(1, Ordering::Relaxed);

        challenge
    }

    /// Validate a cookie value for an actor
    pub fn validate_cookie(&self, actor_id: &str, cookie_value: &str) -> ValidationResult {
        // Parse cookie: timestamp.actor_hash.signature
        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.len() != 3 {
            self.stats.cookies_invalid.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid("Invalid cookie format".to_string());
        }

        let timestamp: u64 = match parts[0].parse() {
            Ok(ts) => ts,
            Err(_) => {
                self.stats.cookies_invalid.fetch_add(1, Ordering::Relaxed);
                return ValidationResult::Invalid("Invalid timestamp".to_string());
            }
        };
        let actor_hash = parts[1];
        let signature = parts[2];

        // Check expiration
        let now = now_secs();
        if timestamp + self.config.cookie_max_age_secs < now {
            self.stats.cookies_expired.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Expired;
        }

        // Verify actor hash matches (constant-time to prevent timing attacks)
        let expected_hash = self.hash_actor_id(actor_id);
        if !constant_time_eq(actor_hash.as_bytes(), expected_hash.as_bytes()) {
            self.stats.cookies_invalid.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid("Actor mismatch".to_string());
        }

        // Verify signature (constant-time to prevent timing attacks)
        let data_to_verify = format!("{}.{}", timestamp, actor_hash);
        let expected_sig = self.sign_data(&data_to_verify);
        if !constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
            self.stats.cookies_invalid.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid("Invalid signature".to_string());
        }

        self.stats.cookies_validated.fetch_add(1, Ordering::Relaxed);
        ValidationResult::Valid
    }

    /// Correlate cookie to actor - extract actor_id from valid cookie
    ///
    /// This uses timing-safe comparison to find the actor whose hash matches.
    /// Note: This is O(n) where n is number of tracked actors. For large scale,
    /// consider maintaining a reverse lookup table.
    pub fn correlate_actor(&self, cookie_value: &str) -> Option<String> {
        // Parse cookie: timestamp.actor_hash.signature
        let parts: Vec<&str> = cookie_value.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let timestamp: u64 = parts[0].parse().ok()?;
        let actor_hash = parts[1];
        let signature = parts[2];

        // Check expiration
        let now = now_secs();
        if timestamp + self.config.cookie_max_age_secs < now {
            return None;
        }

        // Search for actor with matching hash (constant-time comparison)
        for entry in self.challenges.iter() {
            let challenge = entry.value();
            let expected_hash = self.hash_actor_id(&challenge.actor_id);

            if constant_time_eq(actor_hash.as_bytes(), expected_hash.as_bytes()) {
                // Verify signature (constant-time)
                let data_to_verify = format!("{}.{}", timestamp, actor_hash);
                let expected_sig = self.sign_data(&data_to_verify);
                if constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
                    self.stats.actors_correlated.fetch_add(1, Ordering::Relaxed);
                    return Some(challenge.actor_id.clone());
                }
            }
        }

        None
    }

    /// Get statistics
    pub fn stats(&self) -> &CookieStats {
        &self.stats
    }

    /// Get number of tracked challenges
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Check if no challenges are tracked
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }

    /// Remove expired challenges
    pub fn cleanup_expired(&self) -> usize {
        let now = now_secs();
        let mut removed = 0;

        self.challenges.retain(|_, challenge| {
            if challenge.expires_at < now {
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }

    /// Clear all challenges
    pub fn clear(&self) {
        self.challenges.clear();
    }

    // --- Private helpers ---

    /// Hash actor ID using SHA256, return first 16 hex chars
    fn hash_actor_id(&self, actor_id: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(actor_id.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..8]) // First 8 bytes = 16 hex chars
    }

    /// Sign data using HMAC-SHA256, return hex signature
    fn sign_data(&self, data: &str) -> String {
        let mut mac = match HmacSha256::new_from_slice(&self.config.secret_key) {
            Ok(mac) => mac,
            Err(err) => {
                error!("Failed to initialize HMAC for cookie signature: {}", err);
                return String::new();
            }
        };
        mac.update(data.as_bytes());
        let result = mac.finalize();
        hex::encode(&result.into_bytes()[..16]) // First 16 bytes = 32 hex chars
    }
}

impl Interrogator for CookieManager {
    fn name(&self) -> &'static str {
        "cookie"
    }

    fn challenge_level(&self) -> u8 {
        1
    }

    fn generate_challenge(&self, actor_id: &str) -> ChallengeResponse {
        let challenge = self.generate_tracking_cookie(actor_id);
        ChallengeResponse::Cookie {
            name: challenge.cookie_name,
            value: challenge.cookie_value,
            max_age: self.config.cookie_max_age_secs,
            http_only: self.config.http_only,
            secure: self.config.secure_only,
        }
    }

    fn validate_response(&self, actor_id: &str, response: &str) -> ValidationResult {
        self.validate_cookie(actor_id, response)
    }

    fn should_escalate(&self, _actor_id: &str) -> bool {
        // Cookie challenges don't escalate on their own - they are silent
        false
    }
}

/// Get current time in seconds since Unix epoch
#[inline]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Constant-time equality comparison to prevent timing attacks
#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CookieConfig {
        CookieConfig {
            cookie_name: "__test_cookie".to_string(),
            cookie_max_age_secs: 3600, // 1 hour
            secret_key: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
                0x1d, 0x1e, 0x1f, 0x20,
            ],
            secure_only: true,
            http_only: true,
            same_site: "Strict".to_string(),
        }
    }

    #[test]
    fn test_reject_zero_secret_key() {
        let config = CookieConfig {
            secret_key: [0u8; 32],
            ..test_config()
        };
        let result = CookieManager::new(config);
        assert_eq!(result.unwrap_err(), CookieError::InvalidSecretKey);
    }

    #[test]
    fn test_cookie_generation() {
        let manager = CookieManager::new(test_config()).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        assert_eq!(challenge.cookie_name, "__test_cookie");
        assert_eq!(challenge.actor_id, "actor_123");
        assert!(challenge.expires_at > challenge.created_at);

        // Cookie format: timestamp.hash.signature
        let parts: Vec<&str> = challenge.cookie_value.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].parse::<u64>().is_ok()); // timestamp
        assert_eq!(parts[1].len(), 16); // hash (16 hex chars)
        assert_eq!(parts[2].len(), 32); // signature (32 hex chars)
    }

    #[test]
    fn test_cookie_validation_success() {
        let manager = CookieManager::new(test_config()).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        let result = manager.validate_cookie("actor_123", &challenge.cookie_value);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_cookie_validation_wrong_actor() {
        let manager = CookieManager::new(test_config()).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        // Try to validate with different actor
        let result = manager.validate_cookie("actor_456", &challenge.cookie_value);
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_cookie_validation_tampered_signature() {
        let manager = CookieManager::new(test_config()).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        // Tamper with the signature
        let parts: Vec<&str> = challenge.cookie_value.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0], parts[1], "0000000000000000000000000000000"
        );

        let result = manager.validate_cookie("actor_123", &tampered);
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_cookie_validation_invalid_format() {
        let manager = CookieManager::new(test_config()).unwrap();

        let result = manager.validate_cookie("actor_123", "invalid_cookie");
        assert!(matches!(result, ValidationResult::Invalid(_)));

        let result = manager.validate_cookie("actor_123", "only.two.parts");
        // This will fail due to signature validation, not format
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_cookie_validation_expired() {
        let config = CookieConfig {
            cookie_max_age_secs: 0, // Immediate expiration
            ..test_config()
        };
        let manager = CookieManager::new(config).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        // Sleep at least 1 second to ensure expiration (cookies use second precision)
        std::thread::sleep(std::time::Duration::from_secs(1));

        let result = manager.validate_cookie("actor_123", &challenge.cookie_value);
        assert_eq!(result, ValidationResult::Expired);
    }

    #[test]
    fn test_actor_correlation() {
        let manager = CookieManager::new(test_config()).unwrap();
        let challenge = manager.generate_tracking_cookie("actor_123");

        // Should correlate back to original actor
        let correlated = manager.correlate_actor(&challenge.cookie_value);
        assert_eq!(correlated, Some("actor_123".to_string()));

        // Invalid cookie should not correlate
        let correlated = manager.correlate_actor("invalid_cookie");
        assert_eq!(correlated, None);
    }

    #[test]
    fn test_hmac_consistency() {
        let manager = CookieManager::new(test_config()).unwrap();

        // Same actor should get same hash
        let hash1 = manager.hash_actor_id("actor_123");
        let hash2 = manager.hash_actor_id("actor_123");
        assert_eq!(hash1, hash2);

        // Different actors should get different hashes
        let hash3 = manager.hash_actor_id("actor_456");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_interrogator_trait() {
        let manager = CookieManager::new(test_config()).unwrap();

        assert_eq!(manager.name(), "cookie");
        assert_eq!(manager.challenge_level(), 1);
        assert!(!manager.should_escalate("actor_123"));

        // Generate challenge via trait
        let response = manager.generate_challenge("actor_123");
        match response {
            ChallengeResponse::Cookie {
                name,
                value,
                max_age,
                http_only,
                secure,
            } => {
                assert_eq!(name, "__test_cookie");
                assert!(!value.is_empty());
                assert_eq!(max_age, 3600);
                assert!(http_only);
                assert!(secure);
            }
            _ => panic!("Expected Cookie response"),
        }
    }

    #[test]
    fn test_stats_tracking() {
        let manager = CookieManager::new(test_config()).unwrap();

        // Generate cookies
        manager.generate_tracking_cookie("actor_1");
        manager.generate_tracking_cookie("actor_2");
        let challenge = manager.generate_tracking_cookie("actor_3");

        let stats = manager.stats().snapshot();
        assert_eq!(stats.cookies_issued, 3);

        // Validate
        manager.validate_cookie("actor_3", &challenge.cookie_value);
        let stats = manager.stats().snapshot();
        assert_eq!(stats.cookies_validated, 1);

        // Invalid
        manager.validate_cookie("actor_3", "invalid");
        let stats = manager.stats().snapshot();
        assert_eq!(stats.cookies_invalid, 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let config = CookieConfig {
            cookie_max_age_secs: 0, // Immediate expiration
            ..test_config()
        };
        let manager = CookieManager::new(config).unwrap();

        manager.generate_tracking_cookie("actor_1");
        manager.generate_tracking_cookie("actor_2");
        assert_eq!(manager.len(), 2);

        // Sleep at least 1 second to ensure expiration (cookies use second precision)
        std::thread::sleep(std::time::Duration::from_secs(1));

        let removed = manager.cleanup_expired();
        assert_eq!(removed, 2);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_different_secrets_produce_different_signatures() {
        let config1 = CookieConfig {
            secret_key: [0x01; 32],
            ..test_config()
        };
        let config2 = CookieConfig {
            secret_key: [0x02; 32],
            ..test_config()
        };

        let manager1 = CookieManager::new(config1).unwrap();
        let manager2 = CookieManager::new(config2).unwrap();

        let challenge1 = manager1.generate_tracking_cookie("actor_123");
        let challenge2 = manager2.generate_tracking_cookie("actor_123");

        // Signatures should differ
        let parts1: Vec<&str> = challenge1.cookie_value.split('.').collect();
        let parts2: Vec<&str> = challenge2.cookie_value.split('.').collect();

        assert_eq!(parts1[1], parts2[1]); // Hash should be same
        assert_ne!(parts1[2], parts2[2]); // Signature should differ
    }
}
