//! CAPTCHA Challenge Manager
//!
//! Provides human verification through simple math challenges.
//! Uses secure session tokens with HMAC for validation.

use crate::interrogator::ValidationResult;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Configuration for CAPTCHA manager
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// Secret key for HMAC signing
    pub secret: String,
    /// Challenge expiration in seconds
    pub expiry_secs: u64,
    /// Maximum number of challenges to track
    pub max_challenges: usize,
    /// Cleanup interval in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            secret: "default_captcha_secret_change_me".to_string(),
            expiry_secs: 300, // 5 minutes
            max_challenges: 10_000,
            cleanup_interval_secs: 60,
        }
    }
}

/// A CAPTCHA challenge
#[derive(Debug, Clone)]
pub struct CaptchaChallenge {
    /// Session ID for this challenge
    pub session_id: String,
    /// The question to display
    pub question: String,
    /// HTML page with the challenge
    pub html: String,
}

/// Internal challenge state
#[derive(Debug, Clone)]
struct ChallengeState {
    actor_id: String,
    expected_answer: i32,
    created_at: u64,
}

/// Statistics for CAPTCHA manager
#[derive(Debug, Default)]
pub struct CaptchaStats {
    pub challenges_issued: AtomicU64,
    pub challenges_validated: AtomicU64,
    pub challenges_passed: AtomicU64,
    pub challenges_failed: AtomicU64,
    pub challenges_expired: AtomicU64,
}

impl CaptchaStats {
    pub fn snapshot(&self) -> CaptchaStatsSnapshot {
        CaptchaStatsSnapshot {
            challenges_issued: self.challenges_issued.load(Ordering::Relaxed),
            challenges_validated: self.challenges_validated.load(Ordering::Relaxed),
            challenges_passed: self.challenges_passed.load(Ordering::Relaxed),
            challenges_failed: self.challenges_failed.load(Ordering::Relaxed),
            challenges_expired: self.challenges_expired.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CaptchaStatsSnapshot {
    pub challenges_issued: u64,
    pub challenges_validated: u64,
    pub challenges_passed: u64,
    pub challenges_failed: u64,
    pub challenges_expired: u64,
}

/// CAPTCHA challenge manager
pub struct CaptchaManager {
    config: CaptchaConfig,
    /// Maps session_id -> ChallengeState
    challenges: DashMap<String, ChallengeState>,
    stats: CaptchaStats,
    last_cleanup: AtomicU64,
}

impl CaptchaManager {
    pub fn new(config: CaptchaConfig) -> Self {
        Self {
            config,
            challenges: DashMap::new(),
            stats: CaptchaStats::default(),
            last_cleanup: AtomicU64::new(now_ms()),
        }
    }

    /// Issue a new CAPTCHA challenge
    pub fn issue_challenge(&self, actor_id: &str) -> CaptchaChallenge {
        self.maybe_cleanup();

        // Generate random numbers for math challenge using cryptographically secure random
        let (a, b) = generate_math_operands();
        let expected_answer = a + b;
        let question = format!("What is {} + {}?", a, b);

        // Generate session ID with HMAC signature
        let timestamp = now_ms();
        let session_data = format!("{}:{}:{}", actor_id, timestamp, expected_answer);
        let signature = hmac_sign(&self.config.secret, &session_data);
        let session_id = format!("{}:{}", timestamp, &signature[..16]);

        // Store the challenge
        self.challenges.insert(
            session_id.clone(),
            ChallengeState {
                actor_id: actor_id.to_string(),
                expected_answer,
                created_at: timestamp,
            },
        );

        self.stats.challenges_issued.fetch_add(1, Ordering::Relaxed);

        // Generate HTML
        let html = self.generate_html(&session_id, &question);

        CaptchaChallenge {
            session_id,
            question,
            html,
        }
    }

    /// Validate a CAPTCHA response
    ///
    /// Expected response format: "session_id:answer"
    /// Note: session_id format is "{timestamp}:{signature}" so we split from the right
    pub fn validate_response(&self, actor_id: &str, response: &str) -> ValidationResult {
        self.stats.challenges_validated.fetch_add(1, Ordering::Relaxed);

        // Parse response - split from right since session_id contains colon
        let Some(last_colon_idx) = response.rfind(':') else {
            self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid("Invalid response format".to_string());
        };

        let session_id = &response[..last_colon_idx];
        let answer_str = response[last_colon_idx + 1..].trim();

        // Look up challenge
        let challenge = match self.challenges.get(session_id) {
            Some(c) => c.clone(),
            None => {
                self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
                return ValidationResult::NotFound;
            }
        };

        // Verify actor matches
        if challenge.actor_id != actor_id {
            self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Invalid("Actor mismatch".to_string());
        }

        // Check expiration
        let now = now_ms();
        let expiry_ms = self.config.expiry_secs * 1000;
        if now - challenge.created_at > expiry_ms {
            self.challenges.remove(session_id);
            self.stats.challenges_expired.fetch_add(1, Ordering::Relaxed);
            return ValidationResult::Expired;
        }

        // Parse and validate answer
        let answer: i32 = match answer_str.parse() {
            Ok(a) => a,
            Err(_) => {
                self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
                return ValidationResult::Invalid("Invalid answer format".to_string());
            }
        };

        if answer == challenge.expected_answer {
            // Remove used challenge (one-time use)
            self.challenges.remove(session_id);
            self.stats.challenges_passed.fetch_add(1, Ordering::Relaxed);
            ValidationResult::Valid
        } else {
            self.stats.challenges_failed.fetch_add(1, Ordering::Relaxed);
            ValidationResult::Invalid("Incorrect answer".to_string())
        }
    }

    /// Get stats
    pub fn stats(&self) -> &CaptchaStats {
        &self.stats
    }

    /// Clean up expired challenges
    fn maybe_cleanup(&self) {
        let now = now_ms();
        let last = self.last_cleanup.load(Ordering::Relaxed);
        let cleanup_interval_ms = self.config.cleanup_interval_secs * 1000;

        if now - last < cleanup_interval_ms {
            return;
        }

        if self
            .last_cleanup
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let expiry_ms = self.config.expiry_secs * 1000;
        self.challenges.retain(|_, state| now - state.created_at < expiry_ms);
    }

    fn generate_html(&self, session_id: &str, question: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        }}
        .container {{
            background: rgba(255, 255, 255, 0.95);
            padding: 2.5rem;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 400px;
            width: 90%;
        }}
        h2 {{
            color: #1a1a2e;
            margin-bottom: 0.5rem;
            font-size: 1.5rem;
        }}
        p {{
            color: #666;
            margin-bottom: 1.5rem;
            font-size: 0.9rem;
        }}
        .challenge {{
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
        }}
        .question {{
            font-size: 1.25rem;
            color: #333;
            font-weight: 600;
            margin-bottom: 1rem;
        }}
        input[type="text"] {{
            width: 100%;
            padding: 0.75rem 1rem;
            font-size: 1.25rem;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            text-align: center;
            transition: border-color 0.2s;
        }}
        input[type="text"]:focus {{
            outline: none;
            border-color: #667eea;
        }}
        button {{
            width: 100%;
            padding: 0.875rem 1.5rem;
            font-size: 1rem;
            font-weight: 600;
            color: white;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.2s;
        }}
        button:hover {{
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }}
        button:active {{ transform: translateY(0); }}
        .footer {{
            margin-top: 1.5rem;
            font-size: 0.75rem;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Human Verification Required</h2>
        <p>Please solve this simple math problem to continue.</p>
        <form method="POST" action="/__captcha/verify">
            <input type="hidden" name="session" value="{session_id}">
            <div class="challenge">
                <div class="question">{question}</div>
                <input type="text" name="answer" autocomplete="off" autofocus required
                       placeholder="Enter your answer" pattern="[0-9]+" inputmode="numeric">
            </div>
            <button type="submit">Verify</button>
        </form>
        <p class="footer">Synapse Security Gateway</p>
    </div>
</body>
</html>"#,
            session_id = session_id,
            question = question
        )
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

/// Generate random math operands (1-20) using cryptographically secure random
fn generate_math_operands() -> (i32, i32) {
    let mut bytes = [0u8; 2];
    getrandom::getrandom(&mut bytes).expect("Failed to get random bytes");
    // Map bytes to range 1..=20
    let a = (bytes[0] % 20) as i32 + 1;
    let b = (bytes[1] % 20) as i32 + 1;
    (a, b)
}

/// Generate HMAC signature for session data
fn hmac_sign(secret: &str, data: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> CaptchaManager {
        CaptchaManager::new(CaptchaConfig {
            secret: "test_secret".to_string(),
            expiry_secs: 300,
            max_challenges: 100,
            cleanup_interval_secs: 60,
        })
    }

    #[test]
    fn test_issue_challenge() {
        let manager = test_manager();
        let challenge = manager.issue_challenge("actor_1");

        assert!(!challenge.session_id.is_empty());
        assert!(challenge.question.contains("+"));
        assert!(challenge.html.contains("Verification Required"));
    }

    #[test]
    fn test_validate_correct_answer() {
        let manager = test_manager();

        // Issue challenge
        let challenge = manager.issue_challenge("actor_1");

        // Extract expected answer from question (e.g., "What is 5 + 3?")
        let parts: Vec<&str> = challenge.question.split_whitespace().collect();
        let a: i32 = parts[2].parse().unwrap();
        let b: i32 = parts[4].trim_end_matches('?').parse().unwrap();
        let answer = a + b;

        // Validate
        let response = format!("{}:{}", challenge.session_id, answer);
        let result = manager.validate_response("actor_1", &response);
        assert_eq!(result, ValidationResult::Valid);
    }

    #[test]
    fn test_validate_wrong_answer() {
        let manager = test_manager();
        let challenge = manager.issue_challenge("actor_1");

        let response = format!("{}:9999", challenge.session_id);
        let result = manager.validate_response("actor_1", &response);
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_validate_wrong_actor() {
        let manager = test_manager();
        let challenge = manager.issue_challenge("actor_1");

        let response = format!("{}:42", challenge.session_id);
        let result = manager.validate_response("actor_2", &response);
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_validate_invalid_format() {
        let manager = test_manager();
        let result = manager.validate_response("actor_1", "invalid_format");
        assert!(matches!(result, ValidationResult::Invalid(_)));
    }

    #[test]
    fn test_validate_not_found() {
        let manager = test_manager();
        let result = manager.validate_response("actor_1", "nonexistent:42");
        assert_eq!(result, ValidationResult::NotFound);
    }

    #[test]
    fn test_challenge_one_time_use() {
        let manager = test_manager();
        let challenge = manager.issue_challenge("actor_1");

        let parts: Vec<&str> = challenge.question.split_whitespace().collect();
        let a: i32 = parts[2].parse().unwrap();
        let b: i32 = parts[4].trim_end_matches('?').parse().unwrap();
        let answer = a + b;

        let response = format!("{}:{}", challenge.session_id, answer);

        // First validation should succeed
        let result1 = manager.validate_response("actor_1", &response);
        assert_eq!(result1, ValidationResult::Valid);

        // Second validation should fail (challenge consumed)
        let result2 = manager.validate_response("actor_1", &response);
        assert_eq!(result2, ValidationResult::NotFound);
    }
}
