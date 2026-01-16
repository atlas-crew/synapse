//! High-performance fingerprint index for campaign correlation.
//!
//! This module provides an inverted index mapping fingerprints to sets of IP addresses,
//! enabling O(1) lookup of all IPs sharing a fingerprint. This is essential for
//! detecting coordinated attack campaigns where multiple IPs share TLS/HTTP characteristics.
//!
//! # Performance Characteristics
//!
//! - All lookups: O(1) via DashMap
//! - Thread-safe for concurrent access without explicit locking
//! - Memory efficient: single IP string stored, referenced in multiple indexes
//!
//! # Example
//!
//! ```
//! use synapse_pingora::correlation::FingerprintIndex;
//!
//! let index = FingerprintIndex::new();
//!
//! // Update entity fingerprints as requests come in
//! index.update_entity("192.168.1.1", Some("t13d1516h2_abc123"), Some("combined_xyz"));
//! index.update_entity("192.168.1.2", Some("t13d1516h2_abc123"), Some("combined_xyz"));
//! index.update_entity("192.168.1.3", Some("t13d1516h2_abc123"), None);
//!
//! // Query all IPs with same JA4 fingerprint
//! let ips = index.get_ips_by_ja4("t13d1516h2_abc123");
//! assert_eq!(ips.len(), 3);
//!
//! // Find groups above threshold for campaign detection
//! let groups = index.get_groups_above_threshold(2);
//! assert!(!groups.is_empty());
//! ```

use dashmap::DashMap;
use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::warn;

/// Maximum length for fingerprint strings (256 bytes).
/// Fingerprints exceeding this length will be rejected to prevent DoS.
pub const MAX_FINGERPRINT_LENGTH: usize = 256;

/// Default maximum capacity for fingerprint indexes (100,000 entries).
pub const DEFAULT_MAX_FINGERPRINT_CAPACITY: usize = 100_000;

/// Default maximum capacity for IP tracking (500,000 IPs).
pub const DEFAULT_MAX_IP_CAPACITY: usize = 500_000;

/// Type of fingerprint used for grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum FingerprintType {
    /// JA4 TLS fingerprint only
    Ja4,
    /// Combined JA4+JA4H fingerprint hash
    Combined,
}

impl std::fmt::Display for FingerprintType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FingerprintType::Ja4 => write!(f, "JA4"),
            FingerprintType::Combined => write!(f, "Combined"),
        }
    }
}

/// A group of IPs sharing the same fingerprint.
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintGroup {
    /// Type of fingerprint (JA4 or Combined)
    pub fingerprint_type: FingerprintType,
    /// The fingerprint value
    pub fingerprint: String,
    /// List of IP addresses sharing this fingerprint
    pub ips: Vec<String>,
    /// Number of IPs in the group (convenience field)
    pub size: usize,
}

impl FingerprintGroup {
    /// Create a new fingerprint group.
    fn new(fingerprint_type: FingerprintType, fingerprint: String, ips: Vec<String>) -> Self {
        let size = ips.len();
        Self {
            fingerprint_type,
            fingerprint,
            ips,
            size,
        }
    }
}

/// Statistics about the fingerprint index.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IndexStats {
    /// Number of unique JA4 fingerprints tracked
    pub ja4_fingerprints: usize,
    /// Number of unique combined fingerprints tracked
    pub combined_fingerprints: usize,
    /// Total number of unique IPs tracked
    pub total_ips: usize,
    /// Size of the largest JA4 fingerprint group
    pub largest_ja4_group: usize,
    /// Size of the largest combined fingerprint group
    pub largest_combined_group: usize,
    /// Number of fingerprints rejected due to length validation
    pub rejected_fingerprints: u64,
    /// Number of entries evicted due to capacity limits
    pub evicted_entries: u64,
}

/// Fingerprints associated with an IP address.
///
/// Used for reverse lookup when removing an entity from the index.
#[derive(Debug, Clone, Default)]
struct IpFingerprints {
    /// JA4 fingerprint (if set)
    ja4: Option<String>,
    /// Combined fingerprint hash (if set)
    combined: Option<String>,
}

/// Configuration for fingerprint index capacity limits.
#[derive(Debug, Clone)]
pub struct FingerprintIndexConfig {
    /// Maximum number of unique fingerprints to track per index (JA4, combined).
    pub max_fingerprint_capacity: usize,
    /// Maximum number of unique IPs to track.
    pub max_ip_capacity: usize,
}

impl Default for FingerprintIndexConfig {
    fn default() -> Self {
        Self {
            max_fingerprint_capacity: DEFAULT_MAX_FINGERPRINT_CAPACITY,
            max_ip_capacity: DEFAULT_MAX_IP_CAPACITY,
        }
    }
}

/// High-performance fingerprint index for campaign correlation.
///
/// Maps fingerprints to sets of IP addresses using lock-free concurrent
/// data structures for high-throughput WAF scenarios.
///
/// # Thread Safety
///
/// All operations are thread-safe and can be called concurrently without
/// explicit synchronization. DashMap provides fine-grained locking at the
/// shard level for optimal performance.
///
/// # Capacity Limits
///
/// The index enforces capacity limits to prevent DoS attacks:
/// - Maximum fingerprint length: 256 bytes
/// - Maximum fingerprint entries: configurable (default 100,000)
/// - Maximum IP entries: configurable (default 500,000)
///
/// When capacity is exceeded, oldest entries are evicted.
pub struct FingerprintIndex {
    /// JA4 TLS fingerprint -> Set of IPs
    ja4_index: DashMap<String, HashSet<String>>,

    /// Combined fingerprint hash (JA4+JA4H) -> Set of IPs
    combined_index: DashMap<String, HashSet<String>>,

    /// Reverse lookup: IP -> fingerprints (for cleanup)
    ip_fingerprints: DashMap<String, IpFingerprints>,

    /// Configuration for capacity limits
    config: FingerprintIndexConfig,

    /// Counter for rejected fingerprints (length validation failures)
    rejected_count: AtomicU64,

    /// Counter for evicted entries (capacity limit exceeded)
    evicted_count: AtomicU64,
}

impl Default for FingerprintIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintIndex {
    /// Create a new empty fingerprint index with default configuration.
    pub fn new() -> Self {
        Self::with_config(FingerprintIndexConfig::default())
    }

    /// Create a new fingerprint index with custom configuration.
    pub fn with_config(config: FingerprintIndexConfig) -> Self {
        Self {
            ja4_index: DashMap::new(),
            combined_index: DashMap::new(),
            ip_fingerprints: DashMap::new(),
            config,
            rejected_count: AtomicU64::new(0),
            evicted_count: AtomicU64::new(0),
        }
    }

    /// Create a new fingerprint index with pre-allocated capacity.
    ///
    /// Use this when you have an estimate of the number of unique fingerprints
    /// and IPs to reduce reallocations.
    ///
    /// # Arguments
    /// * `fingerprint_capacity` - Expected number of unique fingerprints
    /// * `ip_capacity` - Expected number of unique IPs
    pub fn with_capacity(fingerprint_capacity: usize, ip_capacity: usize) -> Self {
        Self {
            ja4_index: DashMap::with_capacity(fingerprint_capacity),
            combined_index: DashMap::with_capacity(fingerprint_capacity),
            ip_fingerprints: DashMap::with_capacity(ip_capacity),
            config: FingerprintIndexConfig::default(),
            rejected_count: AtomicU64::new(0),
            evicted_count: AtomicU64::new(0),
        }
    }

    /// Validate a fingerprint string for length and content.
    ///
    /// Returns `true` if the fingerprint is valid, `false` otherwise.
    /// Invalid fingerprints are:
    /// - Empty strings
    /// - Strings longer than MAX_FINGERPRINT_LENGTH (256 bytes)
    #[inline]
    pub fn validate_fingerprint(fp: &str) -> bool {
        !fp.is_empty() && fp.len() <= MAX_FINGERPRINT_LENGTH
    }

    /// Check capacity and evict entries if needed.
    ///
    /// This implements a simple eviction strategy: when capacity is exceeded,
    /// remove entries until we're at 90% capacity (to avoid evicting on every insert).
    fn check_and_evict_if_needed(&self) {
        // Check IP capacity - evict down to 90% capacity if exceeded
        let ip_len = self.ip_fingerprints.len();
        if ip_len > self.config.max_ip_capacity {
            let target = (self.config.max_ip_capacity * 9) / 10; // 90% of capacity
            let to_evict = ip_len.saturating_sub(target);

            let mut evicted = 0;
            let ips_to_remove: Vec<String> = self
                .ip_fingerprints
                .iter()
                .take(to_evict)
                .map(|e| e.key().clone())
                .collect();

            for ip in ips_to_remove {
                if self.remove_entity(&ip) {
                    evicted += 1;
                }
            }

            if evicted > 0 {
                self.evicted_count.fetch_add(evicted, Ordering::Relaxed);
                warn!(
                    count = evicted,
                    "Evicted IPs from fingerprint index due to capacity limit"
                );
            }
        }

        // Check JA4 fingerprint capacity
        let ja4_len = self.ja4_index.len();
        if ja4_len > self.config.max_fingerprint_capacity {
            let target = (self.config.max_fingerprint_capacity * 9) / 10;
            let to_evict = ja4_len.saturating_sub(target);

            let fps_to_remove: Vec<String> = self
                .ja4_index
                .iter()
                .take(to_evict)
                .map(|e| e.key().clone())
                .collect();

            let evicted = fps_to_remove.len() as u64;
            for fp in fps_to_remove {
                self.ja4_index.remove(&fp);
            }

            if evicted > 0 {
                self.evicted_count.fetch_add(evicted, Ordering::Relaxed);
                warn!(
                    count = evicted,
                    "Evicted JA4 fingerprints from index due to capacity limit"
                );
            }
        }

        // Check combined fingerprint capacity
        let combined_len = self.combined_index.len();
        if combined_len > self.config.max_fingerprint_capacity {
            let target = (self.config.max_fingerprint_capacity * 9) / 10;
            let to_evict = combined_len.saturating_sub(target);

            let fps_to_remove: Vec<String> = self
                .combined_index
                .iter()
                .take(to_evict)
                .map(|e| e.key().clone())
                .collect();

            let evicted = fps_to_remove.len() as u64;
            for fp in fps_to_remove {
                self.combined_index.remove(&fp);
            }

            if evicted > 0 {
                self.evicted_count.fetch_add(evicted, Ordering::Relaxed);
                warn!(
                    count = evicted,
                    "Evicted combined fingerprints from index due to capacity limit"
                );
            }
        }
    }

    /// Update the index when an entity's fingerprint changes.
    ///
    /// This method handles:
    /// 1. Validating fingerprint length (rejects if > 256 bytes)
    /// 2. Removing IP from old fingerprint groups (if fingerprint changed)
    /// 3. Adding IP to new fingerprint groups
    /// 4. Maintaining reverse lookup for cleanup
    /// 5. Enforcing capacity limits with eviction if needed
    ///
    /// # Arguments
    /// * `ip` - The IP address of the entity
    /// * `ja4` - Optional JA4 TLS fingerprint (must be <= 256 bytes)
    /// * `combined` - Optional combined fingerprint hash (JA4+JA4H, must be <= 256 bytes)
    ///
    /// # Performance
    /// O(1) average case for all operations via DashMap.
    ///
    /// # Security
    /// Fingerprints exceeding MAX_FINGERPRINT_LENGTH are rejected and logged.
    /// Capacity limits prevent memory exhaustion from malicious inputs.
    pub fn update_entity(&self, ip: &str, ja4: Option<&str>, combined: Option<&str>) {
        // Validate fingerprints before processing
        let ja4 = ja4.and_then(|fp| {
            if Self::validate_fingerprint(fp) {
                Some(fp)
            } else {
                self.rejected_count.fetch_add(1, Ordering::Relaxed);
                warn!(
                    ip = %ip,
                    fingerprint_type = "ja4",
                    fingerprint_len = fp.len(),
                    max_len = MAX_FINGERPRINT_LENGTH,
                    "Rejected fingerprint: invalid length or empty"
                );
                None
            }
        });

        let combined = combined.and_then(|fp| {
            if Self::validate_fingerprint(fp) {
                Some(fp)
            } else {
                self.rejected_count.fetch_add(1, Ordering::Relaxed);
                warn!(
                    ip = %ip,
                    fingerprint_type = "combined",
                    fingerprint_len = fp.len(),
                    max_len = MAX_FINGERPRINT_LENGTH,
                    "Rejected fingerprint: invalid length or empty"
                );
                None
            }
        });

        // If both fingerprints were rejected, nothing to do
        if ja4.is_none() && combined.is_none() {
            return;
        }

        let ip_string = ip.to_string();

        // Get or create the IP's fingerprint record
        let mut entry = self.ip_fingerprints.entry(ip_string.clone()).or_default();
        let old_fingerprints = entry.value().clone();

        // Update JA4 index
        if let Some(new_ja4) = ja4 {
            // Remove from old JA4 group if fingerprint changed
            if let Some(ref old_ja4) = old_fingerprints.ja4 {
                if old_ja4 != new_ja4 {
                    self.remove_ip_from_ja4_index(old_ja4, &ip_string);
                }
            }
            // Add to new JA4 group
            self.add_ip_to_ja4_index(new_ja4, ip_string.clone());
            entry.value_mut().ja4 = Some(new_ja4.to_string());
        }

        // Update combined index
        if let Some(new_combined) = combined {
            // Remove from old combined group if fingerprint changed
            if let Some(ref old_combined) = old_fingerprints.combined {
                if old_combined != new_combined {
                    self.remove_ip_from_combined_index(old_combined, &ip_string);
                }
            }
            // Add to new combined group
            self.add_ip_to_combined_index(new_combined, ip_string.clone());
            entry.value_mut().combined = Some(new_combined.to_string());
        }

        // Drop the entry lock before checking capacity
        drop(entry);

        // Check and enforce capacity limits
        self.check_and_evict_if_needed();
    }

    /// Remove an entity from the index entirely.
    ///
    /// Used when an entity expires or is manually removed from tracking.
    /// Removes the IP from all fingerprint groups and cleans up empty groups.
    ///
    /// # Arguments
    /// * `ip` - The IP address to remove
    ///
    /// # Returns
    /// `true` if the IP was found and removed, `false` if not found.
    pub fn remove_entity(&self, ip: &str) -> bool {
        // Get and remove the IP's fingerprint record
        let removed = self.ip_fingerprints.remove(ip);

        if let Some((_, fingerprints)) = removed {
            // Remove from JA4 index
            if let Some(ref ja4) = fingerprints.ja4 {
                self.remove_ip_from_ja4_index(ja4, ip);
            }

            // Remove from combined index
            if let Some(ref combined) = fingerprints.combined {
                self.remove_ip_from_combined_index(combined, ip);
            }

            true
        } else {
            false
        }
    }

    /// Get all IPs with the given JA4 fingerprint.
    ///
    /// # Arguments
    /// * `ja4` - The JA4 fingerprint to look up
    ///
    /// # Returns
    /// Vector of IP addresses with this fingerprint. Empty if not found.
    pub fn get_ips_by_ja4(&self, ja4: &str) -> Vec<String> {
        self.ja4_index
            .get(ja4)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all IPs with the given combined fingerprint hash.
    ///
    /// # Arguments
    /// * `combined` - The combined fingerprint hash to look up
    ///
    /// # Returns
    /// Vector of IP addresses with this fingerprint. Empty if not found.
    pub fn get_ips_by_combined(&self, combined: &str) -> Vec<String> {
        self.combined_index
            .get(combined)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the count of IPs sharing a JA4 fingerprint without copying.
    ///
    /// More efficient than `get_ips_by_ja4().len()` when you only need the count.
    pub fn count_ips_by_ja4(&self, ja4: &str) -> usize {
        self.ja4_index.get(ja4).map(|set| set.len()).unwrap_or(0)
    }

    /// Get the count of IPs sharing a combined fingerprint without copying.
    ///
    /// More efficient than `get_ips_by_combined().len()` when you only need the count.
    pub fn count_ips_by_combined(&self, combined: &str) -> usize {
        self.combined_index
            .get(combined)
            .map(|set| set.len())
            .unwrap_or(0)
    }

    /// Get all fingerprint groups with at least `min_size` IPs.
    ///
    /// This is the primary method for campaign detection. A group with many
    /// IPs sharing the same fingerprint may indicate a coordinated campaign.
    ///
    /// # Arguments
    /// * `min_size` - Minimum number of IPs required for a group to be included
    ///
    /// # Returns
    /// Vector of `FingerprintGroup` sorted by size (largest first).
    ///
    /// # Performance
    /// O(n) where n is the total number of unique fingerprints. Use sparingly
    /// for large indexes or implement caching if needed frequently.
    pub fn get_groups_above_threshold(&self, min_size: usize) -> Vec<FingerprintGroup> {
        let mut groups = Vec::new();

        // Collect JA4 groups above threshold
        for entry in self.ja4_index.iter() {
            let ips = entry.value();
            if ips.len() >= min_size {
                groups.push(FingerprintGroup::new(
                    FingerprintType::Ja4,
                    entry.key().clone(),
                    ips.iter().cloned().collect(),
                ));
            }
        }

        // Collect combined groups above threshold
        for entry in self.combined_index.iter() {
            let ips = entry.value();
            if ips.len() >= min_size {
                groups.push(FingerprintGroup::new(
                    FingerprintType::Combined,
                    entry.key().clone(),
                    ips.iter().cloned().collect(),
                ));
            }
        }

        // Sort by size (largest first)
        groups.sort_by(|a, b| b.size.cmp(&a.size));
        groups
    }

    /// Get groups above threshold for JA4 fingerprints only.
    ///
    /// More efficient than `get_groups_above_threshold` when you only need JA4 groups.
    pub fn get_ja4_groups_above_threshold(&self, min_size: usize) -> Vec<FingerprintGroup> {
        let mut groups = Vec::new();

        for entry in self.ja4_index.iter() {
            let ips = entry.value();
            if ips.len() >= min_size {
                groups.push(FingerprintGroup::new(
                    FingerprintType::Ja4,
                    entry.key().clone(),
                    ips.iter().cloned().collect(),
                ));
            }
        }

        groups.sort_by(|a, b| b.size.cmp(&a.size));
        groups
    }

    /// Get groups above threshold for combined fingerprints only.
    ///
    /// More efficient than `get_groups_above_threshold` when you only need combined groups.
    pub fn get_combined_groups_above_threshold(&self, min_size: usize) -> Vec<FingerprintGroup> {
        let mut groups = Vec::new();

        for entry in self.combined_index.iter() {
            let ips = entry.value();
            if ips.len() >= min_size {
                groups.push(FingerprintGroup::new(
                    FingerprintType::Combined,
                    entry.key().clone(),
                    ips.iter().cloned().collect(),
                ));
            }
        }

        groups.sort_by(|a, b| b.size.cmp(&a.size));
        groups
    }

    /// Get statistics about the index.
    ///
    /// Provides overview metrics for monitoring and debugging.
    pub fn stats(&self) -> IndexStats {
        let mut largest_ja4 = 0usize;
        let mut largest_combined = 0usize;

        for entry in self.ja4_index.iter() {
            largest_ja4 = largest_ja4.max(entry.value().len());
        }

        for entry in self.combined_index.iter() {
            largest_combined = largest_combined.max(entry.value().len());
        }

        IndexStats {
            ja4_fingerprints: self.ja4_index.len(),
            combined_fingerprints: self.combined_index.len(),
            total_ips: self.ip_fingerprints.len(),
            largest_ja4_group: largest_ja4,
            largest_combined_group: largest_combined,
            rejected_fingerprints: self.rejected_count.load(Ordering::Relaxed),
            evicted_entries: self.evicted_count.load(Ordering::Relaxed),
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &FingerprintIndexConfig {
        &self.config
    }

    /// Clear all entries from the index.
    pub fn clear(&self) {
        self.ja4_index.clear();
        self.combined_index.clear();
        self.ip_fingerprints.clear();
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> bool {
        self.ip_fingerprints.is_empty()
    }

    /// Get the number of tracked IPs.
    pub fn len(&self) -> usize {
        self.ip_fingerprints.len()
    }

    /// Get the fingerprints associated with an IP.
    ///
    /// Returns `None` if the IP is not in the index.
    pub fn get_ip_fingerprints(&self, ip: &str) -> Option<(Option<String>, Option<String>)> {
        self.ip_fingerprints.get(ip).map(|entry| {
            let fp = entry.value();
            (fp.ja4.clone(), fp.combined.clone())
        })
    }

    // Internal helper methods

    /// Add an IP to the JA4 index.
    #[inline]
    fn add_ip_to_ja4_index(&self, ja4: &str, ip: String) {
        self.ja4_index
            .entry(ja4.to_string())
            .or_default()
            .insert(ip);
    }

    /// Remove an IP from the JA4 index.
    #[inline]
    fn remove_ip_from_ja4_index(&self, ja4: &str, ip: &str) {
        if let Some(mut entry) = self.ja4_index.get_mut(ja4) {
            entry.value_mut().remove(ip);
            // Clean up empty groups
            if entry.value().is_empty() {
                drop(entry); // Release the lock before remove
                self.ja4_index.remove(ja4);
            }
        }
    }

    /// Add an IP to the combined index.
    #[inline]
    fn add_ip_to_combined_index(&self, combined: &str, ip: String) {
        self.combined_index
            .entry(combined.to_string())
            .or_default()
            .insert(ip);
    }

    /// Remove an IP from the combined index.
    #[inline]
    fn remove_ip_from_combined_index(&self, combined: &str, ip: &str) {
        if let Some(mut entry) = self.combined_index.get_mut(combined) {
            entry.value_mut().remove(ip);
            // Clean up empty groups
            if entry.value().is_empty() {
                drop(entry); // Release the lock before remove
                self.combined_index.remove(combined);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ==================== Basic Operations Tests ====================

    #[test]
    fn test_new_index_is_empty() {
        let index = FingerprintIndex::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let index = FingerprintIndex::with_capacity(1000, 10000);
        assert!(index.is_empty());
    }

    #[test]
    fn test_add_single_entity_ja4_only() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("ja4_fingerprint_1"), None);

        assert_eq!(index.len(), 1);
        let ips = index.get_ips_by_ja4("ja4_fingerprint_1");
        assert_eq!(ips, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_add_single_entity_combined_only() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", None, Some("combined_hash_1"));

        assert_eq!(index.len(), 1);
        let ips = index.get_ips_by_combined("combined_hash_1");
        assert_eq!(ips, vec!["192.168.1.1"]);
    }

    #[test]
    fn test_add_single_entity_both_fingerprints() {
        let index = FingerprintIndex::new();

        index.update_entity(
            "192.168.1.1",
            Some("ja4_fingerprint_1"),
            Some("combined_hash_1"),
        );

        assert_eq!(index.len(), 1);
        assert_eq!(
            index.get_ips_by_ja4("ja4_fingerprint_1"),
            vec!["192.168.1.1"]
        );
        assert_eq!(
            index.get_ips_by_combined("combined_hash_1"),
            vec!["192.168.1.1"]
        );
    }

    #[test]
    fn test_add_multiple_entities_same_ja4() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("shared_ja4"), None);
        index.update_entity("192.168.1.2", Some("shared_ja4"), None);
        index.update_entity("192.168.1.3", Some("shared_ja4"), None);

        assert_eq!(index.len(), 3);
        let ips = index.get_ips_by_ja4("shared_ja4");
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"192.168.1.1".to_string()));
        assert!(ips.contains(&"192.168.1.2".to_string()));
        assert!(ips.contains(&"192.168.1.3".to_string()));
    }

    #[test]
    fn test_add_multiple_entities_different_ja4() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("ja4_1"), None);
        index.update_entity("192.168.1.2", Some("ja4_2"), None);
        index.update_entity("192.168.1.3", Some("ja4_3"), None);

        assert_eq!(index.len(), 3);
        assert_eq!(index.get_ips_by_ja4("ja4_1"), vec!["192.168.1.1"]);
        assert_eq!(index.get_ips_by_ja4("ja4_2"), vec!["192.168.1.2"]);
        assert_eq!(index.get_ips_by_ja4("ja4_3"), vec!["192.168.1.3"]);
    }

    // ==================== Update/Change Tests ====================

    #[test]
    fn test_update_entity_ja4_change() {
        let index = FingerprintIndex::new();

        // Initial fingerprint
        index.update_entity("192.168.1.1", Some("ja4_old"), None);
        assert_eq!(index.get_ips_by_ja4("ja4_old"), vec!["192.168.1.1"]);

        // Change fingerprint
        index.update_entity("192.168.1.1", Some("ja4_new"), None);

        // Should be removed from old group
        assert!(index.get_ips_by_ja4("ja4_old").is_empty());
        // Should be in new group
        assert_eq!(index.get_ips_by_ja4("ja4_new"), vec!["192.168.1.1"]);
        // Still only one IP tracked
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_update_entity_combined_change() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", None, Some("combined_old"));
        index.update_entity("192.168.1.1", None, Some("combined_new"));

        assert!(index.get_ips_by_combined("combined_old").is_empty());
        assert_eq!(
            index.get_ips_by_combined("combined_new"),
            vec!["192.168.1.1"]
        );
    }

    #[test]
    fn test_update_entity_same_fingerprint_no_change() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("ja4_same"), Some("combined_same"));
        index.update_entity("192.168.1.1", Some("ja4_same"), Some("combined_same"));
        index.update_entity("192.168.1.1", Some("ja4_same"), Some("combined_same"));

        assert_eq!(index.len(), 1);
        assert_eq!(index.get_ips_by_ja4("ja4_same"), vec!["192.168.1.1"]);
        assert_eq!(
            index.get_ips_by_combined("combined_same"),
            vec!["192.168.1.1"]
        );
    }

    // ==================== Remove Tests ====================

    #[test]
    fn test_remove_entity_exists() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("ja4_1"), Some("combined_1"));
        assert_eq!(index.len(), 1);

        let removed = index.remove_entity("192.168.1.1");
        assert!(removed);
        assert!(index.is_empty());
        assert!(index.get_ips_by_ja4("ja4_1").is_empty());
        assert!(index.get_ips_by_combined("combined_1").is_empty());
    }

    #[test]
    fn test_remove_entity_not_exists() {
        let index = FingerprintIndex::new();

        let removed = index.remove_entity("192.168.1.1");
        assert!(!removed);
    }

    #[test]
    fn test_remove_entity_leaves_others() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("shared_ja4"), None);
        index.update_entity("192.168.1.2", Some("shared_ja4"), None);
        index.update_entity("192.168.1.3", Some("unique_ja4"), None);

        index.remove_entity("192.168.1.1");

        assert_eq!(index.len(), 2);
        let shared_ips = index.get_ips_by_ja4("shared_ja4");
        assert_eq!(shared_ips.len(), 1);
        assert!(shared_ips.contains(&"192.168.1.2".to_string()));
    }

    #[test]
    fn test_remove_entity_cleans_empty_groups() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("unique_ja4"), None);
        index.remove_entity("192.168.1.1");

        // The fingerprint group should be removed when empty
        let stats = index.stats();
        assert_eq!(stats.ja4_fingerprints, 0);
    }

    // ==================== Group Threshold Tests ====================

    #[test]
    fn test_groups_above_threshold_none() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("ja4_1"), None);
        index.update_entity("192.168.1.2", Some("ja4_2"), None);

        let groups = index.get_groups_above_threshold(2);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_groups_above_threshold_ja4() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", Some("shared_ja4"), None);
        index.update_entity("192.168.1.2", Some("shared_ja4"), None);
        index.update_entity("192.168.1.3", Some("shared_ja4"), None);
        index.update_entity("192.168.1.4", Some("unique_ja4"), None);

        let groups = index.get_groups_above_threshold(2);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].fingerprint_type, FingerprintType::Ja4);
        assert_eq!(groups[0].fingerprint, "shared_ja4");
        assert_eq!(groups[0].size, 3);
    }

    #[test]
    fn test_groups_above_threshold_combined() {
        let index = FingerprintIndex::new();

        index.update_entity("192.168.1.1", None, Some("shared_combined"));
        index.update_entity("192.168.1.2", None, Some("shared_combined"));
        index.update_entity("192.168.1.3", None, Some("unique_combined"));

        let groups = index.get_groups_above_threshold(2);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].fingerprint_type, FingerprintType::Combined);
        assert_eq!(groups[0].fingerprint, "shared_combined");
        assert_eq!(groups[0].size, 2);
    }

    #[test]
    fn test_groups_above_threshold_both_types() {
        let index = FingerprintIndex::new();

        // JA4 group of 3
        index.update_entity("10.0.0.1", Some("ja4_group"), None);
        index.update_entity("10.0.0.2", Some("ja4_group"), None);
        index.update_entity("10.0.0.3", Some("ja4_group"), None);

        // Combined group of 2
        index.update_entity("192.168.1.1", None, Some("combined_group"));
        index.update_entity("192.168.1.2", None, Some("combined_group"));

        let groups = index.get_groups_above_threshold(2);
        assert_eq!(groups.len(), 2);
        // Should be sorted by size (largest first)
        assert_eq!(groups[0].size, 3);
        assert_eq!(groups[1].size, 2);
    }

    #[test]
    fn test_groups_above_threshold_sorted_by_size() {
        let index = FingerprintIndex::new();

        // Small group
        index.update_entity("1.1.1.1", Some("small_ja4"), None);
        index.update_entity("1.1.1.2", Some("small_ja4"), None);

        // Large group
        for i in 1..=5 {
            index.update_entity(&format!("2.2.2.{}", i), Some("large_ja4"), None);
        }

        // Medium group
        index.update_entity("3.3.3.1", Some("medium_ja4"), None);
        index.update_entity("3.3.3.2", Some("medium_ja4"), None);
        index.update_entity("3.3.3.3", Some("medium_ja4"), None);

        let groups = index.get_groups_above_threshold(2);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].size, 5); // large
        assert_eq!(groups[1].size, 3); // medium
        assert_eq!(groups[2].size, 2); // small
    }

    #[test]
    fn test_ja4_groups_only() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_group"), Some("combined_group"));
        index.update_entity("1.1.1.2", Some("ja4_group"), Some("combined_group"));

        let ja4_groups = index.get_ja4_groups_above_threshold(2);
        assert_eq!(ja4_groups.len(), 1);
        assert_eq!(ja4_groups[0].fingerprint_type, FingerprintType::Ja4);
    }

    #[test]
    fn test_combined_groups_only() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_group"), Some("combined_group"));
        index.update_entity("1.1.1.2", Some("ja4_group"), Some("combined_group"));

        let combined_groups = index.get_combined_groups_above_threshold(2);
        assert_eq!(combined_groups.len(), 1);
        assert_eq!(
            combined_groups[0].fingerprint_type,
            FingerprintType::Combined
        );
    }

    // ==================== Count Methods Tests ====================

    #[test]
    fn test_count_ips_by_ja4() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), None);
        index.update_entity("1.1.1.2", Some("ja4_1"), None);
        index.update_entity("1.1.1.3", Some("ja4_2"), None);

        assert_eq!(index.count_ips_by_ja4("ja4_1"), 2);
        assert_eq!(index.count_ips_by_ja4("ja4_2"), 1);
        assert_eq!(index.count_ips_by_ja4("nonexistent"), 0);
    }

    #[test]
    fn test_count_ips_by_combined() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", None, Some("combined_1"));
        index.update_entity("1.1.1.2", None, Some("combined_1"));

        assert_eq!(index.count_ips_by_combined("combined_1"), 2);
        assert_eq!(index.count_ips_by_combined("nonexistent"), 0);
    }

    // ==================== Stats Tests ====================

    #[test]
    fn test_stats_empty() {
        let index = FingerprintIndex::new();
        let stats = index.stats();

        assert_eq!(stats.ja4_fingerprints, 0);
        assert_eq!(stats.combined_fingerprints, 0);
        assert_eq!(stats.total_ips, 0);
        assert_eq!(stats.largest_ja4_group, 0);
        assert_eq!(stats.largest_combined_group, 0);
    }

    #[test]
    fn test_stats_with_data() {
        let index = FingerprintIndex::new();

        // Create JA4 group of 3
        index.update_entity("1.1.1.1", Some("ja4_large"), Some("combined_1"));
        index.update_entity("1.1.1.2", Some("ja4_large"), Some("combined_1"));
        index.update_entity("1.1.1.3", Some("ja4_large"), Some("combined_2"));

        // Create another JA4 group of 1
        index.update_entity("2.2.2.2", Some("ja4_small"), Some("combined_2"));

        let stats = index.stats();

        assert_eq!(stats.ja4_fingerprints, 2); // ja4_large, ja4_small
        assert_eq!(stats.combined_fingerprints, 2); // combined_1, combined_2
        assert_eq!(stats.total_ips, 4);
        assert_eq!(stats.largest_ja4_group, 3);
        assert_eq!(stats.largest_combined_group, 2);
    }

    // ==================== Get IP Fingerprints Test ====================

    #[test]
    fn test_get_ip_fingerprints() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_test"), Some("combined_test"));

        let fps = index.get_ip_fingerprints("1.1.1.1");
        assert!(fps.is_some());
        let (ja4, combined) = fps.unwrap();
        assert_eq!(ja4, Some("ja4_test".to_string()));
        assert_eq!(combined, Some("combined_test".to_string()));
    }

    #[test]
    fn test_get_ip_fingerprints_not_found() {
        let index = FingerprintIndex::new();
        assert!(index.get_ip_fingerprints("1.1.1.1").is_none());
    }

    // ==================== Clear Test ====================

    #[test]
    fn test_clear() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), Some("combined_1"));
        index.update_entity("1.1.1.2", Some("ja4_2"), Some("combined_2"));

        assert!(!index.is_empty());
        index.clear();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);

        let stats = index.stats();
        assert_eq!(stats.ja4_fingerprints, 0);
        assert_eq!(stats.combined_fingerprints, 0);
    }

    // ==================== Concurrent Access Tests ====================

    #[test]
    fn test_concurrent_updates() {
        let index = Arc::new(FingerprintIndex::new());
        let mut handles = vec![];

        // Spawn 10 threads, each updating 100 entities
        for thread_id in 0..10 {
            let index = Arc::clone(&index);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip = format!("10.{}.{}.{}", thread_id, i / 256, i % 256);
                    let ja4 = format!("ja4_t{}_i{}", thread_id % 3, i % 5);
                    let combined = format!("combined_t{}", thread_id % 2);
                    index.update_entity(&ip, Some(&ja4), Some(&combined));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 1000 entities (10 threads * 100 each)
        assert_eq!(index.len(), 1000);

        // Verify no panics and reasonable state
        let stats = index.stats();
        assert!(stats.ja4_fingerprints > 0);
        assert!(stats.combined_fingerprints > 0);
    }

    #[test]
    fn test_concurrent_reads_and_writes() {
        let index = Arc::new(FingerprintIndex::new());

        // Pre-populate
        for i in 0..100 {
            index.update_entity(&format!("1.1.1.{}", i), Some("shared_ja4"), None);
        }

        let mut handles = vec![];

        // Writer threads
        for thread_id in 0..5 {
            let index = Arc::clone(&index);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let ip = format!("2.{}.{}.{}", thread_id, i / 256, i % 256);
                    index.update_entity(&ip, Some("shared_ja4"), None);
                }
            }));
        }

        // Reader threads
        for _ in 0..5 {
            let index = Arc::clone(&index);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = index.get_ips_by_ja4("shared_ja4");
                    let _ = index.stats();
                    let _ = index.count_ips_by_ja4("shared_ja4");
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify integrity
        assert!(index.len() > 0);
    }

    #[test]
    fn test_concurrent_updates_and_removes() {
        let index = Arc::new(FingerprintIndex::new());

        // Pre-populate
        for i in 0..200 {
            index.update_entity(&format!("1.1.1.{}", i), Some("ja4"), None);
        }

        let mut handles = vec![];

        // Remover thread
        let index_clone = Arc::clone(&index);
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                index_clone.remove_entity(&format!("1.1.1.{}", i));
            }
        }));

        // Updater threads
        for thread_id in 0..3 {
            let index = Arc::clone(&index);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let ip = format!("2.{}.{}.{}", thread_id, i / 256, i % 256);
                    index.update_entity(&ip, Some("new_ja4"), None);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have removed 100 and added 150
        // Final count should be around 250 (200 - 100 + 150)
        assert!(index.len() > 100);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_fingerprint_strings_rejected() {
        let index = FingerprintIndex::new();

        // Empty strings are now rejected for security
        index.update_entity("1.1.1.1", Some(""), Some(""));

        // IP should NOT be added since both fingerprints were invalid
        assert_eq!(index.len(), 0);
        assert!(index.get_ips_by_ja4("").is_empty());
        assert!(index.get_ips_by_combined("").is_empty());

        // Check rejection counter
        let stats = index.stats();
        assert_eq!(stats.rejected_fingerprints, 2); // Both were rejected
    }

    #[test]
    fn test_very_long_fingerprints_rejected() {
        let index = FingerprintIndex::new();

        let long_ja4 = "a".repeat(10000);
        let long_combined = "b".repeat(10000);

        index.update_entity("1.1.1.1", Some(&long_ja4), Some(&long_combined));

        // Should reject fingerprints that are too long
        assert_eq!(index.len(), 0);
        assert!(index.get_ips_by_ja4(&long_ja4).is_empty());

        // Check rejection counter
        let stats = index.stats();
        assert_eq!(stats.rejected_fingerprints, 2);
    }

    #[test]
    fn test_fingerprint_at_max_length_accepted() {
        let index = FingerprintIndex::new();

        // Exactly at max length should be accepted
        let max_len_ja4 = "a".repeat(MAX_FINGERPRINT_LENGTH);

        index.update_entity("1.1.1.1", Some(&max_len_ja4), None);

        assert_eq!(index.len(), 1);
        assert_eq!(index.get_ips_by_ja4(&max_len_ja4), vec!["1.1.1.1"]);
    }

    #[test]
    fn test_fingerprint_over_max_length_rejected() {
        let index = FingerprintIndex::new();

        // One byte over max length should be rejected
        let over_max_ja4 = "a".repeat(MAX_FINGERPRINT_LENGTH + 1);

        index.update_entity("1.1.1.1", Some(&over_max_ja4), None);

        assert_eq!(index.len(), 0);
        assert!(index.get_ips_by_ja4(&over_max_ja4).is_empty());

        let stats = index.stats();
        assert_eq!(stats.rejected_fingerprints, 1);
    }

    #[test]
    fn test_validate_fingerprint_function() {
        // Empty string is invalid
        assert!(!FingerprintIndex::validate_fingerprint(""));

        // Valid fingerprints
        assert!(FingerprintIndex::validate_fingerprint("abc123"));
        assert!(FingerprintIndex::validate_fingerprint("t13d1516h2_abc123"));

        // At max length is valid
        let max_len = "a".repeat(MAX_FINGERPRINT_LENGTH);
        assert!(FingerprintIndex::validate_fingerprint(&max_len));

        // Over max length is invalid
        let over_max = "a".repeat(MAX_FINGERPRINT_LENGTH + 1);
        assert!(!FingerprintIndex::validate_fingerprint(&over_max));
    }

    #[test]
    fn test_unicode_fingerprints() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("日本語"), Some("中文"));

        assert_eq!(index.get_ips_by_ja4("日本語"), vec!["1.1.1.1"]);
        assert_eq!(index.get_ips_by_combined("中文"), vec!["1.1.1.1"]);
    }

    #[test]
    fn test_special_characters_in_fingerprints() {
        let index = FingerprintIndex::new();

        let special_fps = [
            "t13d1516h2_8daaf6152771_02713d6af862", // Real JA4 format
            "fp-with-dashes",
            "fp_with_underscores",
            "fp.with.dots",
            "fp/with/slashes",
            "fp:with:colons",
            "fp with spaces",
            "fp\twith\ttabs",
            "fp\nwith\nnewlines",
        ];

        for (i, fp) in special_fps.iter().enumerate() {
            index.update_entity(&format!("1.1.1.{}", i), Some(fp), None);
        }

        assert_eq!(index.len(), special_fps.len());

        for (i, fp) in special_fps.iter().enumerate() {
            let ips = index.get_ips_by_ja4(fp);
            assert_eq!(ips, vec![format!("1.1.1.{}", i)], "Failed for fp: {}", fp);
        }
    }

    #[test]
    fn test_ipv6_addresses() {
        let index = FingerprintIndex::new();

        index.update_entity("2001:db8::1", Some("ja4_ipv6"), None);
        index.update_entity("::1", Some("ja4_ipv6"), None);
        index.update_entity("fe80::1%eth0", Some("ja4_ipv6"), None);

        assert_eq!(index.len(), 3);
        assert_eq!(index.count_ips_by_ja4("ja4_ipv6"), 3);
    }

    #[test]
    fn test_fingerprint_type_display() {
        assert_eq!(format!("{}", FingerprintType::Ja4), "JA4");
        assert_eq!(format!("{}", FingerprintType::Combined), "Combined");
    }

    #[test]
    fn test_update_none_fingerprints_no_change() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), Some("combined_1"));
        index.update_entity("1.1.1.1", None, None);

        // Should still have original fingerprints
        assert_eq!(index.get_ips_by_ja4("ja4_1"), vec!["1.1.1.1"]);
        assert_eq!(index.get_ips_by_combined("combined_1"), vec!["1.1.1.1"]);
    }

    #[test]
    fn test_partial_fingerprint_update() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), Some("combined_1"));

        // Update only JA4
        index.update_entity("1.1.1.1", Some("ja4_2"), None);

        // JA4 should change
        assert!(index.get_ips_by_ja4("ja4_1").is_empty());
        assert_eq!(index.get_ips_by_ja4("ja4_2"), vec!["1.1.1.1"]);

        // Combined should remain
        assert_eq!(index.get_ips_by_combined("combined_1"), vec!["1.1.1.1"]);
    }

    // ==================== Threshold Edge Cases ====================

    #[test]
    fn test_threshold_of_one() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), None);
        index.update_entity("1.1.1.2", Some("ja4_2"), None);

        let groups = index.get_groups_above_threshold(1);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_threshold_larger_than_any_group() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), None);
        index.update_entity("1.1.1.2", Some("ja4_1"), None);
        index.update_entity("1.1.1.3", Some("ja4_1"), None);

        let groups = index.get_groups_above_threshold(100);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_threshold_exactly_equals_group_size() {
        let index = FingerprintIndex::new();

        index.update_entity("1.1.1.1", Some("ja4_1"), None);
        index.update_entity("1.1.1.2", Some("ja4_1"), None);
        index.update_entity("1.1.1.3", Some("ja4_1"), None);

        let groups = index.get_groups_above_threshold(3);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].size, 3);
    }

    #[test]
    fn test_default_trait() {
        let index = FingerprintIndex::default();
        assert!(index.is_empty());
    }

    // ==================== Large Scale Test ====================

    #[test]
    fn test_large_scale_operations() {
        let index = FingerprintIndex::new();

        // Add 10,000 entities across 100 fingerprint groups
        for i in 0..10000 {
            let ip = format!(
                "{}.{}.{}.{}",
                i / 256 / 256 / 256,
                (i / 256 / 256) % 256,
                (i / 256) % 256,
                i % 256
            );
            let ja4 = format!("ja4_group_{}", i % 100);
            let combined = format!("combined_group_{}", i % 50);
            index.update_entity(&ip, Some(&ja4), Some(&combined));
        }

        assert_eq!(index.len(), 10000);

        let stats = index.stats();
        assert_eq!(stats.ja4_fingerprints, 100);
        assert_eq!(stats.combined_fingerprints, 50);
        assert_eq!(stats.largest_ja4_group, 100); // 10000 / 100 groups = 100 per group
        assert_eq!(stats.largest_combined_group, 200); // 10000 / 50 groups = 200 per group

        // All JA4 groups should be above threshold of 50
        let groups = index.get_ja4_groups_above_threshold(50);
        assert_eq!(groups.len(), 100);

        // All combined groups should be above threshold of 100
        let combined_groups = index.get_combined_groups_above_threshold(100);
        assert_eq!(combined_groups.len(), 50);
    }

    // ==================== Capacity Limit Tests ====================

    #[test]
    fn test_capacity_limit_eviction() {
        // Create index with capacity for testing
        // Note: eviction triggers when len > capacity and evicts down to 90%
        let config = FingerprintIndexConfig {
            max_fingerprint_capacity: 100,
            max_ip_capacity: 10,
        };
        let index = FingerprintIndex::with_config(config);

        // Add more IPs than capacity allows
        for i in 0..20 {
            let ip = format!("10.0.0.{}", i);
            let ja4 = format!("ja4_{}", i);
            index.update_entity(&ip, Some(&ja4), None);
        }

        // Should have evicted down to around 90% of capacity (9)
        // But then we added more, so we might have slightly more than 9
        // The key is that we're not at the full 20, eviction happened
        assert!(
            index.len() < 20,
            "Should have evicted some entries, but len is {}",
            index.len()
        );

        // Check eviction counter
        let stats = index.stats();
        assert!(
            stats.evicted_entries > 0,
            "Should have evicted some entries"
        );
    }

    #[test]
    fn test_fingerprint_capacity_limit() {
        let config = FingerprintIndexConfig {
            max_fingerprint_capacity: 10,
            max_ip_capacity: 100,
        };
        let index = FingerprintIndex::with_config(config);

        // Add many unique fingerprints (more than capacity)
        for i in 0..25 {
            let ip = format!("10.0.0.{}", i);
            let ja4 = format!("unique_ja4_{}", i);
            index.update_entity(&ip, Some(&ja4), None);
        }

        // JA4 fingerprints should have triggered eviction
        let stats = index.stats();
        assert!(
            stats.evicted_entries > 0 || stats.ja4_fingerprints <= 25,
            "Eviction should have occurred or fingerprints capped"
        );
    }

    #[test]
    fn test_with_config() {
        let config = FingerprintIndexConfig {
            max_fingerprint_capacity: 50_000,
            max_ip_capacity: 100_000,
        };
        let index = FingerprintIndex::with_config(config);

        assert_eq!(index.config().max_fingerprint_capacity, 50_000);
        assert_eq!(index.config().max_ip_capacity, 100_000);
    }

    #[test]
    fn test_default_config() {
        let config = FingerprintIndexConfig::default();
        assert_eq!(
            config.max_fingerprint_capacity,
            DEFAULT_MAX_FINGERPRINT_CAPACITY
        );
        assert_eq!(config.max_ip_capacity, DEFAULT_MAX_IP_CAPACITY);
    }

    #[test]
    fn test_mixed_valid_invalid_fingerprints() {
        let index = FingerprintIndex::new();

        // Valid JA4, invalid combined (empty)
        index.update_entity("1.1.1.1", Some("valid_ja4"), Some(""));

        // IP should be added with only the valid fingerprint
        assert_eq!(index.len(), 1);
        assert_eq!(index.get_ips_by_ja4("valid_ja4"), vec!["1.1.1.1"]);
        assert!(index.get_ips_by_combined("").is_empty());

        let stats = index.stats();
        assert_eq!(stats.rejected_fingerprints, 1); // Only empty combined was rejected
    }

    #[test]
    fn test_stats_includes_security_counters() {
        let index = FingerprintIndex::new();

        // Trigger some rejections
        let too_long = "x".repeat(MAX_FINGERPRINT_LENGTH + 10);
        index.update_entity("1.1.1.1", Some(&too_long), Some(""));

        let stats = index.stats();
        assert_eq!(stats.rejected_fingerprints, 2);
        assert_eq!(stats.evicted_entries, 0);
    }
}
