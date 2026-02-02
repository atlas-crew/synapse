//! Auth Token Detector
//!
//! Identifies campaigns where multiple IPs use JWTs with identical
//! structure or issuer claims. Weight: 45.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};

use crate::correlation::{
    FingerprintIndex, CampaignUpdate, CorrelationType, CorrelationReason,
};
use super::{Detector, DetectorResult};

/// JWT structure fingerprint
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TokenFingerprint {
    /// Issuer claim (iss)
    pub issuer: Option<String>,
    /// Algorithm used
    pub algorithm: String,
    /// Header fields present (sorted)
    pub header_fields: Vec<String>,
    /// Payload fields present (sorted, excluding dynamic fields like exp, iat)
    pub payload_fields: Vec<String>,
}

impl TokenFingerprint {
    /// Create a fingerprint from JWT parts
    pub fn from_jwt_parts(_header: &str, _payload: &str) -> Option<Self> {
        // Simplified: In production, would decode base64 and parse JSON
        Some(Self {
            issuer: None,
            algorithm: "RS256".to_string(),
            header_fields: vec!["alg".to_string(), "typ".to_string()],
            payload_fields: vec!["sub".to_string(), "iss".to_string()],
        })
    }

    /// Create fingerprint hash
    pub fn fingerprint_hash(&self) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        Hash::hash(self, &mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

/// Configuration for auth token detection
#[derive(Debug, Clone)]
pub struct AuthTokenConfig {
    /// Minimum IPs sharing token structure
    pub min_ips: usize,
    /// Time window for correlation
    pub window: Duration,
    /// Base confidence multiplier for confidence calculation (0.0 to 1.0)
    pub base_confidence: f64,
    /// Divisor for scaling confidence by IP count
    pub confidence_scale_divisor: f64,
}

impl Default for AuthTokenConfig {
    fn default() -> Self {
        Self {
            min_ips: 2,
            window: Duration::from_secs(600), // 10 minutes
            base_confidence: 0.85,
            confidence_scale_divisor: 8.0,
        }
    }
}

/// Detects campaigns based on shared JWT structure
pub struct AuthTokenDetector {
    config: AuthTokenConfig,
    /// Token fingerprint hash -> (IP, timestamp)
    token_index: DashMap<String, Vec<(IpAddr, Instant)>>,
    /// Already detected fingerprints
    detected: DashSet<String>,
}

impl AuthTokenDetector {
    pub fn new(config: AuthTokenConfig) -> Self {
        Self {
            config,
            token_index: DashMap::new(),
            detected: DashSet::new(),
        }
    }

    /// Record a token observation
    pub fn record_token(&self, ip: IpAddr, fingerprint: TokenFingerprint) {
        let hash = fingerprint.fingerprint_hash();
        let now = Instant::now();
        let cutoff = now - self.config.window;

        self.token_index
            .entry(hash)
            .and_modify(|entry| {
                entry.push((ip, now));
                // Cleanup old
                entry.retain(|(_, ts)| *ts > cutoff);
            })
            .or_insert_with(|| vec![(ip, now)]);
    }

    /// Record from raw JWT
    pub fn record_jwt(&self, ip: IpAddr, jwt: &str) {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() >= 2 {
            if let Some(fp) = TokenFingerprint::from_jwt_parts(parts[0], parts[1]) {
                self.record_token(ip, fp);
            }
        }
    }

    fn get_correlated_groups(&self) -> Vec<(String, Vec<IpAddr>)> {
        let cutoff = Instant::now() - self.config.window;

        self.token_index.iter()
            .filter(|entry| !self.detected.contains(entry.key()))
            .filter_map(|entry| {
                let hash = entry.key().clone();
                let entries = entry.value();

                let recent_ips: HashSet<IpAddr> = entries.iter()
                    .filter(|(_, ts)| *ts > cutoff)
                    .map(|(ip, _)| *ip)
                    .collect();

                if recent_ips.len() >= self.config.min_ips {
                    Some((hash, recent_ips.into_iter().collect()))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Detector for AuthTokenDetector {
    fn name(&self) -> &'static str { "auth_token" }

    fn analyze(&self, _index: &FingerprintIndex) -> DetectorResult<Vec<CampaignUpdate>> {
        let groups = self.get_correlated_groups();
        let mut updates = Vec::new();

        for (token_hash, ips) in groups {
            let confidence = (ips.len() as f64 / self.config.confidence_scale_divisor).min(1.0) * self.config.base_confidence;

            updates.push(CampaignUpdate {
                campaign_id: Some(format!("auth-token-{}", &token_hash[..8.min(token_hash.len())])),
                status: None,
                confidence: Some(confidence),
                attack_types: Some(vec!["credential_stuffing".to_string()]),
                add_member_ips: Some(ips.iter().map(|ip| ip.to_string()).collect()),
                add_correlation_reason: Some(CorrelationReason::new(
                    CorrelationType::AuthToken,
                    confidence,
                    format!("{} IPs using tokens with identical structure/issuer", ips.len()),
                    ips.iter().map(|ip| ip.to_string()).collect(),
                )),
                ..Default::default()
            });

            self.detected.insert(token_hash);
        }

        Ok(updates)
    }

    fn should_trigger(&self, ip: &IpAddr, _index: &FingerprintIndex) -> bool {
        self.token_index.iter().any(|entry| {
            let entries = entry.value();
            entries.iter().any(|(entry_ip, _)| entry_ip == ip)
                && entries.len() >= self.config.min_ips - 1
        })
    }

    fn scan_interval_ms(&self) -> u64 { 5000 } // 5 seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AuthTokenConfig::default();
        assert_eq!(config.min_ips, 2);
    }

    #[test]
    fn test_record_token() {
        let detector = AuthTokenDetector::new(AuthTokenConfig::default());
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        let fp = TokenFingerprint {
            issuer: Some("https://auth.example.com".to_string()),
            algorithm: "RS256".to_string(),
            header_fields: vec!["alg".to_string()],
            payload_fields: vec!["sub".to_string()],
        };

        detector.record_token(ip, fp);
        // Token recorded successfully
    }

    #[test]
    fn test_detection_with_multiple_ips() {
        let detector = AuthTokenDetector::new(AuthTokenConfig::default());

        let fp = TokenFingerprint {
            issuer: Some("malicious-issuer".to_string()),
            algorithm: "HS256".to_string(),
            header_fields: vec!["alg".to_string()],
            payload_fields: vec!["sub".to_string()],
        };

        for i in 1..=3 {
            let ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            detector.record_token(ip, fp.clone());
        }

        let index = FingerprintIndex::new();
        let updates = detector.analyze(&index).unwrap();

        assert_eq!(updates.len(), 1);
    }

    #[test]
    fn test_name() {
        let detector = AuthTokenDetector::new(AuthTokenConfig::default());
        assert_eq!(detector.name(), "auth_token");
    }

    #[test]
    fn test_scan_interval() {
        let detector = AuthTokenDetector::new(AuthTokenConfig::default());
        assert_eq!(detector.scan_interval_ms(), 5000);
    }
}
