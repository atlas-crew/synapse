//! Block event logging for dashboard visibility.
//! Maintains a circular buffer of recent WAF block events.

use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use serde::Serialize;
use sha2::Sha256;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Configurable anonymization strategies for `BlockEvent.client_ip`.
#[derive(Debug, Clone)]
pub enum IpAnonymization {
    /// Store the raw IP string (existing behavior).
    None,
    /// Mask IPv4 to /24 and IPv6 to /64 (e.g. `1.2.3.0`, `2001:db8::`).
    Truncate,
    /// HMAC-SHA256 of the parsed IP bytes with a caller-provided secret key.
    /// Stored as `anon:<hex>` (truncated for display).
    HmacSha256 { key: Vec<u8> },
}

impl IpAnonymization {
    /// Load from env:
    /// - `SYNAPSE_BLOCK_LOG_IP_ANON` = `none|truncate|hmac` (or `1|true|yes|on` for truncate)
    /// - `SYNAPSE_BLOCK_LOG_IP_SALT` = secret key for `hmac` mode
    pub fn from_env() -> Self {
        let mode = std::env::var("SYNAPSE_BLOCK_LOG_IP_ANON")
            .unwrap_or_else(|_| "none".to_string())
            .trim()
            .to_lowercase();

        match mode.as_str() {
            "" | "0" | "false" | "no" | "off" | "none" => Self::None,
            "1" | "true" | "yes" | "y" | "on" | "truncate" | "trunc" | "mask" => Self::Truncate,
            "hmac" | "hash" => {
                let salt = std::env::var("SYNAPSE_BLOCK_LOG_IP_SALT").unwrap_or_default();
                let key = salt.into_bytes();
                if key.is_empty() {
                    warn!(
                        "SYNAPSE_BLOCK_LOG_IP_ANON=hmac but SYNAPSE_BLOCK_LOG_IP_SALT unset/empty; falling back to truncate"
                    );
                    Self::Truncate
                } else {
                    Self::HmacSha256 { key }
                }
            }
            other => {
                warn!(
                    "Unknown SYNAPSE_BLOCK_LOG_IP_ANON value '{}'; defaulting to none",
                    other
                );
                Self::None
            }
        }
    }
}

/// A WAF block event for dashboard display
#[derive(Debug, Clone, Serialize)]
pub struct BlockEvent {
    pub timestamp: u64,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub risk_score: u16,
    pub matched_rules: Vec<u32>,
    pub block_reason: String,
    pub fingerprint: Option<String>,
}

impl BlockEvent {
    /// Create a new block event with the current timestamp
    pub fn new(
        client_ip: String,
        method: String,
        path: String,
        risk_score: u16,
        matched_rules: Vec<u32>,
        block_reason: String,
        fingerprint: Option<String>,
    ) -> Self {
        Self {
            timestamp: now_ms(),
            client_ip,
            method,
            path,
            risk_score,
            matched_rules,
            block_reason,
            fingerprint,
        }
    }
}

/// Circular buffer for recent block events
pub struct BlockLog {
    events: RwLock<VecDeque<BlockEvent>>,
    max_size: usize,
    ip_anonymization: IpAnonymization,
}

impl BlockLog {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
            ip_anonymization: IpAnonymization::None,
        }
    }

    pub fn new_with_ip_anonymization(max_size: usize, ip_anonymization: IpAnonymization) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
            ip_anonymization,
        }
    }

    pub fn record(&self, mut event: BlockEvent) {
        event.client_ip = anonymize_ip(&self.ip_anonymization, &event.client_ip);

        // If a panic occurs mid-write, the buffer may be partially updated.
        // This is acceptable for metrics and avoids poisoning the lock.
        let mut events = self.events.write();
        if events.len() >= self.max_size {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn recent(&self, limit: usize) -> Vec<BlockEvent> {
        let events = self.events.read();
        let take = limit.min(events.len());
        events.iter().rev().take(take).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.write().clear();
    }
}

impl Default for BlockLog {
    fn default() -> Self {
        Self::new(1000)
    }
}

fn anonymize_ip(strategy: &IpAnonymization, raw: &str) -> String {
    match strategy {
        IpAnonymization::None => raw.to_string(),
        IpAnonymization::Truncate => match parse_ip_like(raw) {
            Some(ip) => truncate_ip(ip).to_string(),
            None => "redacted".to_string(),
        },
        IpAnonymization::HmacSha256 { key } => match parse_ip_like(raw) {
            Some(ip) => hmac_ip(key, ip),
            None => "redacted".to_string(),
        },
    }
}

fn parse_ip_like(raw: &str) -> Option<IpAddr> {
    // Prefer first entry if XFF-like lists leak in.
    let first = raw.split(',').next()?.trim();

    if let Ok(sa) = first.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    first.parse::<IpAddr>().ok()
}

fn truncate_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let mut oct = v4.octets();
            oct[3] = 0;
            IpAddr::V4(Ipv4Addr::from(oct))
        }
        IpAddr::V6(v6) => {
            // Keep /64, zero the lower 64 bits.
            let mut oct = v6.octets();
            for b in &mut oct[8..] {
                *b = 0;
            }
            IpAddr::V6(Ipv6Addr::from(oct))
        }
    }
}

fn hmac_ip(key: &[u8], ip: IpAddr) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    match ip {
        IpAddr::V4(v4) => mac.update(&v4.octets()),
        IpAddr::V6(v6) => mac.update(&v6.octets()),
    }
    let digest = mac.finalize().into_bytes();
    // UI-friendly length; still collision-resistant enough for dashboard use.
    format!("anon:{}", hex::encode(&digest[..16]))
}

/// Get current time in milliseconds since Unix epoch.
#[inline]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_log_new() {
        let log = BlockLog::new(100);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_block_log_record() {
        let log = BlockLog::new(100);
        let event = BlockEvent::new(
            "192.168.1.1".to_string(),
            "GET".to_string(),
            "/admin".to_string(),
            75,
            vec![1001, 1002],
            "Risk threshold exceeded".to_string(),
            None,
        );
        log.record(event);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());
    }

    #[test]
    fn test_block_log_recent() {
        let log = BlockLog::new(100);

        for i in 0..5 {
            let event = BlockEvent::new(
                format!("192.168.1.{}", i),
                "GET".to_string(),
                "/path".to_string(),
                50,
                vec![],
                "Test".to_string(),
                None,
            );
            log.record(event);
        }

        let recent = log.recent(3);
        assert_eq!(recent.len(), 3);
        // Most recent first (reverse order)
        assert_eq!(recent[0].client_ip, "192.168.1.4");
        assert_eq!(recent[1].client_ip, "192.168.1.3");
        assert_eq!(recent[2].client_ip, "192.168.1.2");
    }

    #[test]
    fn test_block_log_circular() {
        let log = BlockLog::new(3);

        for i in 0..5 {
            let event = BlockEvent::new(
                format!("192.168.1.{}", i),
                "GET".to_string(),
                "/path".to_string(),
                50,
                vec![],
                "Test".to_string(),
                None,
            );
            log.record(event);
        }

        // Should only have last 3
        assert_eq!(log.len(), 3);
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].client_ip, "192.168.1.4");
        assert_eq!(recent[2].client_ip, "192.168.1.2");
    }

    #[test]
    fn test_block_log_default() {
        let log = BlockLog::default();
        assert!(log.is_empty());
        // Default capacity is 1000
    }

    #[test]
    fn test_block_log_clear() {
        let log = BlockLog::new(100);

        for i in 0..5 {
            let event = BlockEvent::new(
                format!("192.168.1.{}", i),
                "GET".to_string(),
                "/path".to_string(),
                50,
                vec![],
                "Test".to_string(),
                None,
            );
            log.record(event);
        }

        assert_eq!(log.len(), 5);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_block_log_lock_survives_panic() {
        use std::sync::{Arc, Barrier};
        let log = Arc::new(BlockLog::new(10));
        let barrier = Arc::new(Barrier::new(2));

        // Panic while holding the lock to ensure future access is still possible
        let log_clone = log.clone();
        let barrier_clone = barrier.clone();
        let handle = std::thread::spawn(move || {
            let _lock = log_clone.events.write();
            barrier_clone.wait();
            panic!("Intentional panic while holding lock");
        });
        barrier.wait();
        let _ = handle.join();

        let event = BlockEvent::new(
            "1.1.1.1".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        );
        log.record(event);
        assert_eq!(log.len(), 1);
        assert_eq!(log.recent(1)[0].client_ip, "1.1.1.1");
    }

    #[test]
    fn test_ip_anonymization_truncate_ipv4() {
        let log = BlockLog::new_with_ip_anonymization(10, IpAnonymization::Truncate);
        log.record(BlockEvent::new(
            "192.168.1.123".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        ));
        assert_eq!(log.recent(1)[0].client_ip, "192.168.1.0");
    }

    #[test]
    fn test_ip_anonymization_truncate_ipv6() {
        let log = BlockLog::new_with_ip_anonymization(10, IpAnonymization::Truncate);
        log.record(BlockEvent::new(
            "2001:db8::1".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        ));
        // /64 truncation
        assert_eq!(log.recent(1)[0].client_ip, "2001:db8::");
    }

    #[test]
    fn test_ip_anonymization_hmac_stable() {
        let log = BlockLog::new_with_ip_anonymization(
            10,
            IpAnonymization::HmacSha256 {
                key: b"unit-test-salt".to_vec(),
            },
        );

        log.record(BlockEvent::new(
            "1.2.3.4".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        ));
        let a = log.recent(1)[0].client_ip.clone();
        assert!(a.starts_with("anon:"));

        log.record(BlockEvent::new(
            "1.2.3.4".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        ));
        let b = log.recent(1)[0].client_ip.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_ip_anonymization_non_ip_redacts() {
        let log = BlockLog::new_with_ip_anonymization(10, IpAnonymization::Truncate);
        log.record(BlockEvent::new(
            "not-an-ip".to_string(),
            "GET".to_string(),
            "/".to_string(),
            10,
            vec![],
            "test".to_string(),
            None,
        ));
        assert_eq!(log.recent(1)[0].client_ip, "redacted");
    }
}
