//! JavaScript Proof-of-Work Challenge Manager
//!
//! Implements a computational proof-of-work challenge that requires client-side
//! JavaScript execution. This helps distinguish real browsers from simple bots
//! that don't execute JavaScript.
//!
//! # PoW Mechanism
//!
//! The client must find a nonce such that `SHA256(prefix + nonce)` has the
//! required number of leading hex zeros (difficulty). This is computationally
//! expensive for clients but cheap to verify server-side.
//!
//! # Challenge Flow
//!
//! 1. Server generates challenge with random prefix and difficulty
//! 2. Server returns HTML page with embedded JavaScript solver
//! 3. Client JavaScript computes SHA256 hashes until solution found
//! 4. Client submits form with nonce
//! 5. Server verifies solution
//!
//! # Security Properties
//!
//! - Each challenge has unique prefix (no precomputation attacks)
//! - Challenges expire after TTL (no replay attacks)
//! - Max attempts prevent infinite retries
//! - Difficulty can be tuned for security/UX balance

use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

use super::{ChallengeResponse, Interrogator, ValidationResult};

/// A JavaScript PoW challenge instance
#[derive(Debug, Clone)]
pub struct JsChallenge {
    /// Unique challenge ID
    pub challenge_id: String,
    /// Actor this challenge is for
    pub actor_id: String,
    /// Number of leading hex zeros required
    pub difficulty: u32,
    /// Random prefix for PoW computation
    pub prefix: String,
    /// When challenge was created (unix timestamp ms)
    pub created_at: u64,
    /// When challenge expires (unix timestamp ms)
    pub expires_at: u64,
    /// Expected hash prefix (leading zeros)
    pub expected_hash_prefix: String,
}

/// Configuration for JavaScript challenges
#[derive(Debug, Clone)]
pub struct JsChallengeConfig {
    /// Number of leading hex zeros required (default: 4)
    /// Higher = harder, each +1 roughly doubles computation time
    pub difficulty: u32,
    /// Challenge time-to-live in seconds (default: 300 = 5 min)
    pub challenge_ttl_secs: u64,
    /// Maximum validation attempts per actor (default: 3)
    pub max_attempts: u32,
    /// Background cleanup interval in seconds (default: 60)
    pub cleanup_interval_secs: u64,
    /// Challenge page title
    pub page_title: String,
    /// Challenge page message
    pub page_message: String,
}

impl Default for JsChallengeConfig {
    fn default() -> Self {
        Self {
            difficulty: 4, // 4 leading hex zeros = ~65K iterations average
            challenge_ttl_secs: 300,
            max_attempts: 3,
            cleanup_interval_secs: 60,
            page_title: "Verifying your browser".to_string(),
            page_message: "Please wait while we verify your browser...".to_string(),
        }
    }
}

/// Statistics for JavaScript challenge operations
#[derive(Debug, Default)]
pub struct JsChallengeStats {
    /// Total challenges issued
    pub challenges_issued: AtomicU64,
    /// Successfully passed challenges
    pub challenges_passed: AtomicU64,
    /// Failed challenges (wrong solution)
    pub challenges_failed: AtomicU64,
    /// Expired challenges
    pub challenges_expired: AtomicU64,
    /// Max attempts exceeded
    pub max_attempts_exceeded: AtomicU64,
}

impl JsChallengeStats {
    /// Create a snapshot of current stats
    pub fn snapshot(&self) -> JsChallengeStatsSnapshot {
        JsChallengeStatsSnapshot {
            challenges_issued: self.challenges_issued.load(Ordering::Relaxed),
            challenges_passed: self.challenges_passed.load(Ordering::Relaxed),
            challenges_failed: self.challenges_failed.load(Ordering::Relaxed),
            challenges_expired: self.challenges_expired.load(Ordering::Relaxed),
            max_attempts_exceeded: self.max_attempts_exceeded.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of JS challenge stats for serialization
#[derive(Debug, Clone, serde::Serialize)]
pub struct JsChallengeStatsSnapshot {
    pub challenges_issued: u64,
    pub challenges_passed: u64,
    pub challenges_failed: u64,
    pub challenges_expired: u64,
    pub max_attempts_exceeded: u64,
}

/// Thread-safe JavaScript challenge manager
pub struct JsChallengeManager {
    /// Active challenges by actor ID
    challenges: DashMap<String, JsChallenge>,
    /// Attempt counts by actor ID
    attempt_counts: DashMap<String, u32>,
    /// Configuration
    config: JsChallengeConfig,
    /// Statistics
    stats: JsChallengeStats,
    /// Shutdown signal for background tasks
    shutdown: Arc<Notify>,
    /// Shutdown flag to check if shutdown was requested
    shutdown_flag: Arc<AtomicBool>,
}

impl JsChallengeManager {
    /// Create a new JS challenge manager with the given configuration
    pub fn new(config: JsChallengeConfig) -> Self {
        Self {
            challenges: DashMap::new(),
            attempt_counts: DashMap::new(),
            config,
            stats: JsChallengeStats::default(),
            shutdown: Arc::new(Notify::new()),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &JsChallengeConfig {
        &self.config
    }

    /// Generate a PoW challenge for an actor
    pub fn generate_pow_challenge(&self, actor_id: &str) -> JsChallenge {
        let now = now_ms();
        let expires_at = now + (self.config.challenge_ttl_secs * 1000);

        // Generate random prefix (16 hex chars)
        let prefix = generate_random_hex(16);

        // Generate unique challenge ID
        let challenge_id = generate_random_hex(32);

        // Expected hash prefix is `difficulty` zeros
        let expected_hash_prefix = "0".repeat(self.config.difficulty as usize);

        let challenge = JsChallenge {
            challenge_id,
            actor_id: actor_id.to_string(),
            difficulty: self.config.difficulty,
            prefix,
            created_at: now,
            expires_at,
            expected_hash_prefix,
        };

        // Store challenge
        self.challenges.insert(actor_id.to_string(), challenge.clone());
        self.stats.challenges_issued.fetch_add(1, Ordering::Relaxed);

        challenge
    }

    /// Validate a PoW solution
    pub fn validate_pow(&self, actor_id: &str, nonce: &str) -> ValidationResult {
        // SECURITY: Validate nonce length to prevent memory exhaustion attacks.
        // Valid nonces are numeric strings; even 2^64 is only 20 digits.
        // Allow up to 32 chars to be safe with potential future formats.
        const MAX_NONCE_LENGTH: usize = 32;
        if nonce.len() > MAX_NONCE_LENGTH {
            return ValidationResult::Invalid(format!(
                "Nonce too long ({} > {} chars)",
                nonce.len(),
                MAX_NONCE_LENGTH
            ));
        }

        // Validate nonce is numeric (expected from JS client)
        if !nonce.chars().all(|c| c.is_ascii_digit()) {
            return ValidationResult::Invalid("Nonce must be numeric".to_string());
        }

        // Get challenge for actor
        let challenge = match self.challenges.get(actor_id) {
            Some(c) => c.clone(),
            None => return ValidationResult::NotFound,
        };

        // Check expiration
        let now = now_ms();
        if challenge.expires_at < now {
            self.challenges.remove(actor_id);
            self.stats.challenges_expired.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Expired;
        }

        // Increment attempt count
        let attempts = {
            let mut entry = self.attempt_counts.entry(actor_id.to_string()).or_insert(0);
            *entry += 1;
            *entry
        };

        // Check max attempts
        if attempts > self.config.max_attempts {
            self.stats
                .max_attempts_exceeded
                .fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid(format!(
                "Max attempts ({}) exceeded",
                self.config.max_attempts
            ));
        }

        // Verify PoW: SHA256(prefix + nonce) must have required leading zeros
        let data = format!("{}{}", challenge.prefix, nonce);
        let hash = compute_sha256_hex(&data);

        if hash.starts_with(&challenge.expected_hash_prefix) {
            // Success - remove challenge and attempts
            self.challenges.remove(actor_id);
            self.attempt_counts.remove(actor_id);
            self.stats.challenges_passed.fetch_add(1, Ordering::Relaxed);
            ValidationResult::Valid
        } else {
            self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
            ValidationResult::Invalid(format!(
                "Hash {} does not have {} leading zeros",
                &hash[..8],
                self.config.difficulty
            ))
        }
    }

    /// Generate the challenge HTML page
    pub fn generate_challenge_page(&self, challenge: &JsChallenge) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
        }}
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 1rem auto;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .progress {{
            margin: 1rem 0;
            color: #666;
            font-size: 0.9rem;
        }}
        .error {{
            color: #e53e3e;
            margin-top: 1rem;
        }}
        noscript {{
            color: #e53e3e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>{message}</h2>
        <div class="spinner" id="spinner"></div>
        <div class="progress" id="progress">Computing challenge...</div>
        <noscript>
            <p class="error">JavaScript is required to complete this verification.</p>
        </noscript>
        <form id="challengeForm" method="GET" style="display: none;">
            <input type="hidden" name="synapse_challenge" value="js">
            <input type="hidden" name="challenge_id" value="{challenge_id}">
            <input type="hidden" name="synapse_nonce" id="synapse_nonce" value="">
        </form>
    </div>
    <script>
        (function() {{
            const PREFIX = '{prefix}';
            const DIFFICULTY = {difficulty};
            const EXPECTED_PREFIX = '{expected_prefix}';

            let nonce = 0;
            let startTime = Date.now();
            let lastUpdate = startTime;

            // SHA-256 implementation using Web Crypto API
            async function sha256(message) {{
                const msgBuffer = new TextEncoder().encode(message);
                const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
                const hashArray = Array.from(new Uint8Array(hashBuffer));
                return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            }}

            async function solve() {{
                const progressEl = document.getElementById('progress');

                while (true) {{
                    const data = PREFIX + nonce.toString();
                    const hash = await sha256(data);

                    // Update progress every 100ms
                    const now = Date.now();
                    if (now - lastUpdate > 100) {{
                        const elapsed = ((now - startTime) / 1000).toFixed(1);
                        progressEl.textContent = `Computed ${{nonce.toLocaleString()}} hashes (${{elapsed}}s)...`;
                        lastUpdate = now;
                    }}

                    if (hash.startsWith(EXPECTED_PREFIX)) {{
                        // Found solution!
                        document.getElementById('synapse_nonce').value = nonce.toString();
                        document.getElementById('spinner').style.display = 'none';
                        progressEl.textContent = 'Verification complete! Redirecting...';
                        document.getElementById('challengeForm').submit();
                        return;
                    }}

                    nonce++;

                    // Yield to browser every 1000 iterations for responsiveness
                    if (nonce % 1000 === 0) {{
                        await new Promise(resolve => setTimeout(resolve, 0));
                    }}
                }}
            }}

            // Start solving
            solve().catch(err => {{
                document.getElementById('spinner').style.display = 'none';
                document.getElementById('progress').innerHTML =
                    '<span class="error">Verification failed: ' + err.message + '</span>';
            }});
        }})();
    </script>
</body>
</html>"#,
            title = self.config.page_title,
            message = self.config.page_message,
            challenge_id = challenge.challenge_id,
            prefix = challenge.prefix,
            difficulty = challenge.difficulty,
            expected_prefix = challenge.expected_hash_prefix,
        )
    }

    /// Get attempt count for an actor
    pub fn get_attempts(&self, actor_id: &str) -> u32 {
        self.attempt_counts
            .get(actor_id)
            .map(|v| *v)
            .unwrap_or(0)
    }

    /// Check if actor has active challenge
    pub fn has_challenge(&self, actor_id: &str) -> bool {
        self.challenges.contains_key(actor_id)
    }

    /// Get active challenge for actor
    pub fn get_challenge(&self, actor_id: &str) -> Option<JsChallenge> {
        self.challenges.get(actor_id).map(|c| c.clone())
    }

    /// Start background cleanup task.
    ///
    /// Spawns a background task that periodically removes expired challenges.
    /// The task will exit cleanly when `shutdown()` is called.
    pub fn start_cleanup(self: Arc<Self>) {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.cleanup_interval_secs);
        let shutdown = self.shutdown.clone();
        let shutdown_flag = self.shutdown_flag.clone();

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Check shutdown flag before running cleanup
                        if shutdown_flag.load(Ordering::Relaxed) {
                            log::info!("JS challenge manager cleanup task shutting down (flag)");
                            break;
                        }
                        manager.cleanup_expired();
                    }
                    _ = shutdown.notified() => {
                        log::info!("JS challenge manager cleanup task shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Signal shutdown for background tasks.
    ///
    /// This method signals the background cleanup task to stop.
    /// The task will exit after completing any in-progress work.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
    }

    /// Remove expired challenges
    pub fn cleanup_expired(&self) -> usize {
        let now = now_ms();
        let mut removed = 0;

        self.challenges.retain(|_, challenge| {
            if challenge.expires_at < now {
                removed += 1;
                false
            } else {
                true
            }
        });

        // Also clean up attempt counts for actors without challenges
        let actor_ids: Vec<String> = self.attempt_counts.iter().map(|e| e.key().clone()).collect();
        for actor_id in actor_ids {
            if !self.challenges.contains_key(&actor_id) {
                self.attempt_counts.remove(&actor_id);
            }
        }

        removed
    }

    /// Get statistics
    pub fn stats(&self) -> &JsChallengeStats {
        &self.stats
    }

    /// Get number of active challenges
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Check if no challenges are active
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }

    /// Clear all challenges
    pub fn clear(&self) {
        self.challenges.clear();
        self.attempt_counts.clear();
    }
}

impl Interrogator for JsChallengeManager {
    fn name(&self) -> &'static str {
        "js_challenge"
    }

    fn challenge_level(&self) -> u8 {
        2
    }

    fn generate_challenge(&self, actor_id: &str) -> ChallengeResponse {
        let challenge = self.generate_pow_challenge(actor_id);
        let html = self.generate_challenge_page(&challenge);
        ChallengeResponse::JsChallenge {
            html,
            expected_solution: challenge.expected_hash_prefix.clone(),
            expires_at: challenge.expires_at,
        }
    }

    fn validate_response(&self, actor_id: &str, response: &str) -> ValidationResult {
        self.validate_pow(actor_id, response)
    }

    fn should_escalate(&self, actor_id: &str) -> bool {
        self.get_attempts(actor_id) >= self.config.max_attempts
    }
}

/// Get current time in milliseconds since Unix epoch
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Compute SHA256 hash of data, return hex string
fn compute_sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Generate random hex string of given length using cryptographically secure random
fn generate_random_hex(len: usize) -> String {
    // Calculate number of bytes needed (2 hex chars per byte)
    let byte_len = (len + 1) / 2;
    let mut bytes = vec![0u8; byte_len];
    getrandom::getrandom(&mut bytes).expect("Failed to get random bytes");

    let mut result = hex::encode(&bytes);
    result.truncate(len);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JsChallengeConfig {
        JsChallengeConfig {
            difficulty: 2, // Low difficulty for fast tests
            challenge_ttl_secs: 300,
            max_attempts: 3,
            cleanup_interval_secs: 60,
            page_title: "Test Challenge".to_string(),
            page_message: "Testing...".to_string(),
        }
    }

    #[test]
    fn test_challenge_generation() {
        let manager = JsChallengeManager::new(test_config());
        let challenge = manager.generate_pow_challenge("actor_123");

        assert_eq!(challenge.actor_id, "actor_123");
        assert_eq!(challenge.difficulty, 2);
        assert_eq!(challenge.prefix.len(), 16);
        assert_eq!(challenge.challenge_id.len(), 32);
        assert_eq!(challenge.expected_hash_prefix, "00");
        assert!(challenge.expires_at > challenge.created_at);
    }

    #[test]
    fn test_pow_verification_valid() {
        let manager = JsChallengeManager::new(test_config());
        let challenge = manager.generate_pow_challenge("actor_123");

        // Find valid nonce (brute force - okay for low difficulty)
        let mut nonce = 0u64;
        loop {
            let data = format!("{}{}", challenge.prefix, nonce);
            let hash = compute_sha256_hex(&data);
            if hash.starts_with(&challenge.expected_hash_prefix) {
                break;
            }
            nonce += 1;
            if nonce > 100_000 {
                panic!("Could not find solution in reasonable time");
            }
        }

        let result = manager.validate_pow("actor_123", &nonce.to_string());
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_pow_verification_invalid() {
        let manager = JsChallengeManager::new(test_config());
        manager.generate_pow_challenge("actor_123");

        // Use invalid nonce (very unlikely to work)
        let result = manager.validate_pow("actor_123", "invalid_nonce");
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_pow_verification_not_found() {
        let manager = JsChallengeManager::new(test_config());

        // No challenge generated
        let result = manager.validate_pow("actor_123", "12345");
        assert_eq!(result, ValidationResult::NotFound);
    }

    #[test]
    fn test_pow_verification_expired() {
        let config = JsChallengeConfig {
            challenge_ttl_secs: 0, // Immediate expiration
            ..test_config()
        };
        let manager = JsChallengeManager::new(config);
        manager.generate_pow_challenge("actor_123");

        // Sleep to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = manager.validate_pow("actor_123", "12345");
        assert_eq!(result, ValidationResult::Expired);
    }

    #[test]
    fn test_max_attempts() {
        let manager = JsChallengeManager::new(test_config());
        manager.generate_pow_challenge("actor_123");

        // Make 3 attempts (max)
        for _ in 0..3 {
            let _ = manager.validate_pow("actor_123", "99999999");
        }

        // 4th attempt should fail with max attempts
        let result = manager.validate_pow("actor_123", "99999999");
        assert!(matches!(result, ValidationResult::Invalid(msg) if msg.contains("Max attempts")));
    }

    #[test]
    fn test_attempt_counting() {
        let manager = JsChallengeManager::new(test_config());
        manager.generate_pow_challenge("actor_123");

        assert_eq!(manager.get_attempts("actor_123"), 0);

        manager.validate_pow("actor_123", "99999999");
        assert_eq!(manager.get_attempts("actor_123"), 1);

        manager.validate_pow("actor_123", "99999999");
        assert_eq!(manager.get_attempts("actor_123"), 2);
    }

    #[test]
    fn test_should_escalate() {
        let manager = JsChallengeManager::new(test_config());
        manager.generate_pow_challenge("actor_123");

        assert!(!manager.should_escalate("actor_123"));

        // Make max attempts
        for _ in 0..3 {
            let _ = manager.validate_pow("actor_123", "99999999");
        }

        assert!(manager.should_escalate("actor_123"));
    }

    #[test]
    fn test_challenge_page_generation() {
        let manager = JsChallengeManager::new(test_config());
        let challenge = manager.generate_pow_challenge("actor_123");
        let html = manager.generate_challenge_page(&challenge);

        assert!(html.contains("Test Challenge")); // Page title
        assert!(html.contains("Testing...")); // Message
        assert!(html.contains(&challenge.prefix)); // Prefix in JS
        assert!(html.contains(&challenge.challenge_id)); // Challenge ID in form
        assert!(html.contains("sha256")); // Uses sha256
    }

    #[test]
    fn test_sha256_computation() {
        // Known SHA256 test vector
        let hash = compute_sha256_hex("test");
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_cleanup_expired() {
        let config = JsChallengeConfig {
            challenge_ttl_secs: 0, // Immediate expiration
            ..test_config()
        };
        let manager = JsChallengeManager::new(config);

        manager.generate_pow_challenge("actor_1");
        manager.generate_pow_challenge("actor_2");
        assert_eq!(manager.len(), 2);

        std::thread::sleep(std::time::Duration::from_millis(10));

        let removed = manager.cleanup_expired();
        assert_eq!(removed, 2);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_interrogator_trait() {
        let manager = JsChallengeManager::new(test_config());

        assert_eq!(manager.name(), "js_challenge");
        assert_eq!(manager.challenge_level(), 2);

        // Generate challenge via trait
        let response = manager.generate_challenge("actor_123");
        match response {
            ChallengeResponse::JsChallenge {
                html,
                expected_solution,
                expires_at,
            } => {
                assert!(!html.is_empty());
                assert_eq!(expected_solution, "00");
                assert!(expires_at > now_ms());
            }
            _ => panic!("Expected JsChallenge response"),
        }
    }

    #[test]
    fn test_stats_tracking() {
        let manager = JsChallengeManager::new(test_config());

        // Generate challenges
        manager.generate_pow_challenge("actor_1");
        manager.generate_pow_challenge("actor_2");

        let stats = manager.stats().snapshot();
        assert_eq!(stats.challenges_issued, 2);

        // Failed validation (numeric nonce that won't solve PoW)
        manager.validate_pow("actor_1", "99999999");
        let stats = manager.stats().snapshot();
        assert_eq!(stats.challenges_failed, 1);
    }

    #[test]
    fn test_random_hex_generation() {
        let hex1 = generate_random_hex(16);
        let hex2 = generate_random_hex(16);

        assert_eq!(hex1.len(), 16);
        assert_eq!(hex2.len(), 16);
        // Very unlikely to be the same
        assert_ne!(hex1, hex2);

        // Should be valid hex
        assert!(hex1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_has_challenge() {
        let manager = JsChallengeManager::new(test_config());

        assert!(!manager.has_challenge("actor_123"));

        manager.generate_pow_challenge("actor_123");
        assert!(manager.has_challenge("actor_123"));

        manager.clear();
        assert!(!manager.has_challenge("actor_123"));
    }

    #[test]
    fn test_successful_validation_clears_state() {
        let config = JsChallengeConfig {
            difficulty: 4, // Higher difficulty to ensure "99999999" won't accidentally pass
            ..test_config()
        };
        let manager = JsChallengeManager::new(config);
        let challenge = manager.generate_pow_challenge("actor_123");

        // Make some failed attempts - verify they actually fail
        let result1 = manager.validate_pow("actor_123", "99999999");
        assert!(matches!(result1, ValidationResult::Invalid(_)));
        let result2 = manager.validate_pow("actor_123", "99999998");
        assert!(matches!(result2, ValidationResult::Invalid(_)));
        assert_eq!(manager.get_attempts("actor_123"), 2);
        assert!(manager.has_challenge("actor_123"));

        // Find valid solution (need 4 leading zeros)
        let mut nonce = 0u64;
        loop {
            let data = format!("{}{}", challenge.prefix, nonce);
            let hash = compute_sha256_hex(&data);
            if hash.starts_with("0000") {
                break;
            }
            nonce += 1;
        }

        // Successful validation
        let result = manager.validate_pow("actor_123", &nonce.to_string());
        assert_eq!(result, ValidationResult::Valid);

        // State should be cleared
        assert!(!manager.has_challenge("actor_123"));
        assert_eq!(manager.get_attempts("actor_123"), 0);
    }
}
