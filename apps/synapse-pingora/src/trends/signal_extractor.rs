//! Signal extraction from HTTP requests.

use sha2::{Digest, Sha256};

use super::types::{
    AuthTokenMetadata, BehavioralMetadata, DeviceMetadata, JwtClaims, NetworkMetadata, Signal,
    SignalCategory, SignalMetadata, SignalType,
};

/// Signal extractor for HTTP requests.
pub struct SignalExtractor;

impl SignalExtractor {
    /// Extract all signals from request context.
    pub fn extract(
        entity_id: &str,
        session_id: Option<&str>,
        user_agent: Option<&str>,
        authorization: Option<&str>,
        client_ip: Option<&str>,
        ja4: Option<&str>,
        ja4h: Option<&str>,
        last_request_time: Option<i64>,
    ) -> Vec<Signal> {
        let mut signals = Vec::new();
        let now = chrono::Utc::now().timestamp_millis();

        // Network signals
        if let Some(ip) = client_ip {
            signals.push(Signal {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                category: SignalCategory::Network,
                signal_type: SignalType::Ip,
                value: ip.to_string(),
                entity_id: entity_id.to_string(),
                session_id: session_id.map(String::from),
                metadata: SignalMetadata::Network(NetworkMetadata {
                    ip: ip.to_string(),
                    ja4: ja4.map(String::from),
                    ja4h: ja4h.map(String::from),
                    ..Default::default()
                }),
            });
        }

        // JA4 fingerprint signal
        if let Some(ja4_fp) = ja4 {
            signals.push(Signal {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                category: SignalCategory::Network,
                signal_type: SignalType::Ja4,
                value: ja4_fp.to_string(),
                entity_id: entity_id.to_string(),
                session_id: session_id.map(String::from),
                metadata: SignalMetadata::Network(NetworkMetadata {
                    ip: client_ip.unwrap_or("").to_string(),
                    ja4: Some(ja4_fp.to_string()),
                    ja4h: ja4h.map(String::from),
                    ..Default::default()
                }),
            });
        }

        // JA4H fingerprint signal
        if let Some(ja4h_fp) = ja4h {
            signals.push(Signal {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                category: SignalCategory::Network,
                signal_type: SignalType::Ja4h,
                value: ja4h_fp.to_string(),
                entity_id: entity_id.to_string(),
                session_id: session_id.map(String::from),
                metadata: SignalMetadata::Network(NetworkMetadata {
                    ip: client_ip.unwrap_or("").to_string(),
                    ja4: ja4.map(String::from),
                    ja4h: Some(ja4h_fp.to_string()),
                    ..Default::default()
                }),
            });
        }

        // Device signals from User-Agent
        if let Some(ua) = user_agent {
            signals.push(Signal {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                category: SignalCategory::Device,
                signal_type: SignalType::HttpFingerprint,
                value: Self::hash_value(ua),
                entity_id: entity_id.to_string(),
                session_id: session_id.map(String::from),
                metadata: SignalMetadata::Device(DeviceMetadata {
                    user_agent: ua.to_string(),
                    ..Default::default()
                }),
            });
        }

        // Auth token signals
        if let Some(auth) = authorization {
            if let Some(signal) = Self::extract_auth_signal(auth, entity_id, session_id, now) {
                signals.push(signal);
            }
        }

        // Behavioral signals
        if let Some(last_time) = last_request_time {
            let time_delta = now - last_time;
            signals.push(Signal {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: now,
                category: SignalCategory::Behavioral,
                signal_type: SignalType::Timing,
                value: format!("delta_{}", time_delta),
                entity_id: entity_id.to_string(),
                session_id: session_id.map(String::from),
                metadata: SignalMetadata::Behavioral(BehavioralMetadata {
                    time_since_last_request: Some(time_delta),
                    ..Default::default()
                }),
            });
        }

        signals
    }

    /// Extract auth token signal from Authorization header.
    fn extract_auth_signal(
        auth: &str,
        entity_id: &str,
        session_id: Option<&str>,
        timestamp: i64,
    ) -> Option<Signal> {
        let (token_type, token) = if auth.starts_with("Bearer ") {
            (SignalType::Bearer, &auth[7..])
        } else if auth.starts_with("Basic ") {
            (SignalType::Basic, &auth[6..])
        } else {
            (SignalType::CustomAuth, auth)
        };

        // Check if it looks like a JWT
        let (signal_type, jwt_claims) = if token.matches('.').count() == 2 {
            // Likely a JWT
            let claims = Self::parse_jwt_claims(token);
            (SignalType::Jwt, claims)
        } else {
            (token_type, None)
        };

        let token_hash = Self::hash_value(token);

        Some(Signal {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp,
            category: SignalCategory::AuthToken,
            signal_type,
            value: token_hash.clone(),
            entity_id: entity_id.to_string(),
            session_id: session_id.map(String::from),
            metadata: SignalMetadata::AuthToken(AuthTokenMetadata {
                header_name: "Authorization".to_string(),
                token_prefix: Some(auth.split_whitespace().next().unwrap_or("").to_string()),
                token_hash,
                jwt_claims,
            }),
        })
    }

    /// Parse JWT claims (basic parsing, no verification).
    fn parse_jwt_claims(token: &str) -> Option<JwtClaims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode payload (second part)
        let payload = match base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1],
        ) {
            Ok(bytes) => bytes,
            Err(_) => return None,
        };

        let json: serde_json::Value = match serde_json::from_slice(&payload) {
            Ok(v) => v,
            Err(_) => return None,
        };

        Some(JwtClaims {
            sub: json.get("sub").and_then(|v| v.as_str()).map(String::from),
            iss: json.get("iss").and_then(|v| v.as_str()).map(String::from),
            exp: json.get("exp").and_then(|v| v.as_i64()),
            iat: json.get("iat").and_then(|v| v.as_i64()),
            aud: json.get("aud").and_then(|v| v.as_str()).map(String::from),
        })
    }

    /// Hash a value using SHA-256.
    fn hash_value(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip_signal() {
        let signals = SignalExtractor::extract(
            "entity-1",
            None,
            None,
            None,
            Some("192.168.1.100"),
            None,
            None,
            None,
        );

        assert!(!signals.is_empty());
        let ip_signal = signals
            .iter()
            .find(|s| s.signal_type == SignalType::Ip)
            .unwrap();
        assert_eq!(ip_signal.value, "192.168.1.100");
    }

    #[test]
    fn test_extract_ja4_signal() {
        let signals = SignalExtractor::extract(
            "entity-1",
            None,
            None,
            None,
            Some("192.168.1.100"),
            Some("t13d1516h2_abc123"),
            None,
            None,
        );

        let ja4_signal = signals
            .iter()
            .find(|s| s.signal_type == SignalType::Ja4)
            .unwrap();
        assert_eq!(ja4_signal.value, "t13d1516h2_abc123");
    }

    #[test]
    fn test_extract_bearer_token() {
        let signals = SignalExtractor::extract(
            "entity-1",
            None,
            None,
            Some("Bearer my-secret-token"),
            None,
            None,
            None,
            None,
        );

        let auth_signal = signals
            .iter()
            .find(|s| s.category == SignalCategory::AuthToken)
            .unwrap();
        assert_eq!(auth_signal.signal_type, SignalType::Bearer);

        // Value should be a hash, not the raw token
        assert!(!auth_signal.value.contains("my-secret-token"));
    }

    #[test]
    fn test_extract_timing_signal() {
        let now = chrono::Utc::now().timestamp_millis();
        let signals = SignalExtractor::extract(
            "entity-1",
            None,
            None,
            None,
            None,
            None,
            None,
            Some(now - 5000), // 5 seconds ago
        );

        let timing_signal = signals
            .iter()
            .find(|s| s.signal_type == SignalType::Timing)
            .unwrap();
        assert!(timing_signal.value.starts_with("delta_"));
    }
}
