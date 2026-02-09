//! Blocklist cache for fast IP and fingerprint lookups.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Type of block entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockType {
    Ip,
    Fingerprint,
}

/// A blocklist entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlocklistEntry {
    pub block_type: BlockType,
    pub indicator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// An incremental blocklist update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlocklistUpdate {
    pub action: BlocklistAction,
    pub block_type: BlockType,
    pub indicator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Blocklist update action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlocklistAction {
    Add,
    Remove,
}

/// High-performance blocklist cache with O(1) lookups.
///
/// Uses DashMap for lock-free concurrent access.
pub struct BlocklistCache {
    /// IP blocklist
    ips: DashMap<String, BlocklistEntry>,
    /// Fingerprint blocklist
    fingerprints: DashMap<String, BlocklistEntry>,
    /// Current sequence ID from hub
    sequence_id: AtomicU64,
}

impl Default for BlocklistCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocklistCache {
    /// Create a new empty blocklist cache.
    pub fn new() -> Self {
        Self {
            ips: DashMap::new(),
            fingerprints: DashMap::new(),
            sequence_id: AtomicU64::new(0),
        }
    }

    /// Check if an IP is blocked.
    ///
    /// This is an O(1) lookup.
    #[inline]
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        self.ips.contains_key(ip)
    }

    /// Check if a fingerprint is blocked.
    ///
    /// This is an O(1) lookup.
    #[inline]
    pub fn is_fingerprint_blocked(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains_key(fingerprint)
    }

    /// Check if either IP or fingerprint is blocked.
    #[inline]
    pub fn is_blocked(&self, ip: Option<&str>, fingerprint: Option<&str>) -> bool {
        if let Some(ip) = ip {
            if self.is_ip_blocked(ip) {
                return true;
            }
        }
        if let Some(fp) = fingerprint {
            if self.is_fingerprint_blocked(fp) {
                return true;
            }
        }
        false
    }

    /// Get an IP block entry.
    pub fn get_ip(&self, ip: &str) -> Option<BlocklistEntry> {
        self.ips.get(ip).map(|r| r.value().clone())
    }

    /// Get a fingerprint block entry.
    pub fn get_fingerprint(&self, fingerprint: &str) -> Option<BlocklistEntry> {
        self.fingerprints
            .get(fingerprint)
            .map(|r| r.value().clone())
    }

    /// Add a blocklist entry.
    pub fn add(&self, entry: BlocklistEntry) {
        match entry.block_type {
            BlockType::Ip => {
                self.ips.insert(entry.indicator.clone(), entry);
            }
            BlockType::Fingerprint => {
                self.fingerprints.insert(entry.indicator.clone(), entry);
            }
        }
    }

    /// Remove a blocklist entry.
    pub fn remove(&self, block_type: BlockType, indicator: &str) {
        match block_type {
            BlockType::Ip => {
                self.ips.remove(indicator);
            }
            BlockType::Fingerprint => {
                self.fingerprints.remove(indicator);
            }
        }
    }

    /// Load a full blocklist snapshot from the hub.
    pub fn load_snapshot(&self, entries: Vec<BlocklistEntry>, sequence_id: u64) {
        // Clear existing entries
        self.ips.clear();
        self.fingerprints.clear();

        // Load new entries
        for entry in entries {
            self.add(entry);
        }

        self.sequence_id.store(sequence_id, Ordering::SeqCst);
    }

    /// Apply incremental updates from the hub.
    pub fn apply_updates(&self, updates: Vec<BlocklistUpdate>, sequence_id: u64) {
        for update in updates {
            match update.action {
                BlocklistAction::Add => {
                    self.add(BlocklistEntry {
                        block_type: update.block_type,
                        indicator: update.indicator,
                        expires_at: None,
                        source: update.source.unwrap_or_else(|| "hub".to_string()),
                        reason: update.reason,
                        created_at: None,
                    });
                }
                BlocklistAction::Remove => {
                    self.remove(update.block_type, &update.indicator);
                }
            }
        }

        self.sequence_id.store(sequence_id, Ordering::SeqCst);
    }

    /// Get the total blocklist size.
    pub fn size(&self) -> usize {
        self.ips.len() + self.fingerprints.len()
    }

    /// Get the IP blocklist size.
    pub fn ip_count(&self) -> usize {
        self.ips.len()
    }

    /// Get the fingerprint blocklist size.
    pub fn fingerprint_count(&self) -> usize {
        self.fingerprints.len()
    }

    /// Get the current sequence ID.
    pub fn sequence_id(&self) -> u64 {
        self.sequence_id.load(Ordering::SeqCst)
    }

    /// Clear all entries.
    pub fn clear(&self) {
        self.ips.clear();
        self.fingerprints.clear();
        self.sequence_id.store(0, Ordering::SeqCst);
    }

    /// Get all IP entries.
    pub fn all_ips(&self) -> Vec<BlocklistEntry> {
        self.ips.iter().map(|r| r.value().clone()).collect()
    }

    /// Get all fingerprint entries.
    pub fn all_fingerprints(&self) -> Vec<BlocklistEntry> {
        self.fingerprints
            .iter()
            .map(|r| r.value().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_blocking() {
        let cache = BlocklistCache::new();

        cache.add(BlocklistEntry {
            block_type: BlockType::Ip,
            indicator: "192.168.1.100".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(cache.is_ip_blocked("192.168.1.100"));
        assert!(!cache.is_ip_blocked("192.168.1.101"));
    }

    #[test]
    fn test_fingerprint_blocking() {
        let cache = BlocklistCache::new();

        cache.add(BlocklistEntry {
            block_type: BlockType::Fingerprint,
            indicator: "t13d1516h2_abc123".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(cache.is_fingerprint_blocked("t13d1516h2_abc123"));
        assert!(!cache.is_fingerprint_blocked("t13d1516h2_def456"));
    }

    #[test]
    fn test_is_blocked_combined() {
        let cache = BlocklistCache::new();

        cache.add(BlocklistEntry {
            block_type: BlockType::Ip,
            indicator: "10.0.0.1".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(cache.is_blocked(Some("10.0.0.1"), None));
        assert!(cache.is_blocked(Some("10.0.0.1"), Some("fp123")));
        assert!(!cache.is_blocked(Some("10.0.0.2"), Some("fp123")));
        assert!(!cache.is_blocked(None, None));
    }

    #[test]
    fn test_load_snapshot() {
        let cache = BlocklistCache::new();

        // Add some initial entries
        cache.add(BlocklistEntry {
            block_type: BlockType::Ip,
            indicator: "old-ip".to_string(),
            expires_at: None,
            source: "old".to_string(),
            reason: None,
            created_at: None,
        });

        // Load snapshot (should replace)
        cache.load_snapshot(
            vec![BlocklistEntry {
                block_type: BlockType::Ip,
                indicator: "new-ip".to_string(),
                expires_at: None,
                source: "snapshot".to_string(),
                reason: None,
                created_at: None,
            }],
            42,
        );

        assert!(!cache.is_ip_blocked("old-ip"));
        assert!(cache.is_ip_blocked("new-ip"));
        assert_eq!(cache.sequence_id(), 42);
    }

    #[test]
    fn test_apply_updates() {
        let cache = BlocklistCache::new();

        cache.apply_updates(
            vec![
                BlocklistUpdate {
                    action: BlocklistAction::Add,
                    block_type: BlockType::Ip,
                    indicator: "10.0.0.1".to_string(),
                    source: Some("hub".to_string()),
                    reason: None,
                },
                BlocklistUpdate {
                    action: BlocklistAction::Add,
                    block_type: BlockType::Fingerprint,
                    indicator: "fp1".to_string(),
                    source: None,
                    reason: Some("malicious".to_string()),
                },
            ],
            100,
        );

        assert!(cache.is_ip_blocked("10.0.0.1"));
        assert!(cache.is_fingerprint_blocked("fp1"));
        assert_eq!(cache.size(), 2);
        assert_eq!(cache.sequence_id(), 100);

        // Remove update
        cache.apply_updates(
            vec![BlocklistUpdate {
                action: BlocklistAction::Remove,
                block_type: BlockType::Ip,
                indicator: "10.0.0.1".to_string(),
                source: None,
                reason: None,
            }],
            101,
        );

        assert!(!cache.is_ip_blocked("10.0.0.1"));
        assert_eq!(cache.size(), 1);
    }
}
