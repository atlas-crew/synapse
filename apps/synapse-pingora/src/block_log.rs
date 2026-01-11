//! Block event logging for dashboard visibility.
//! Maintains a circular buffer of recent WAF block events.

use std::collections::VecDeque;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;

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
}

impl BlockLog {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
        }
    }

    pub fn record(&self, event: BlockEvent) {
        let mut events = self.events.write().unwrap();
        if events.len() >= self.max_size {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn recent(&self, limit: usize) -> Vec<BlockEvent> {
        let events = self.events.read().unwrap();
        let take = limit.min(events.len());
        events.iter().rev().take(take).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.events.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }
}

impl Default for BlockLog {
    fn default() -> Self {
        Self::new(1000)
    }
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
}
