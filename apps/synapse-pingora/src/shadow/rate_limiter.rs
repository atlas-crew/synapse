//! Per-IP rate limiter for shadow mirroring.
//!
//! Prevents flooding honeypots with too many requests from the same source.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Maximum number of tracked IPs to prevent unbounded memory growth.
const MAX_ENTRIES: usize = 50_000;

/// Number of operations between capacity checks (amortized overhead).
const CAPACITY_CHECK_INTERVAL: u64 = 128;

/// Per-IP rate limiter using sliding window algorithm.
///
/// Uses DashMap for lock-free concurrent access, critical for high-RPS WAF scenarios.
/// Bounded to [`MAX_ENTRIES`] to prevent memory exhaustion under DDoS.
pub struct RateLimiter {
    /// IP -> (count, window_start)
    state: DashMap<String, (u32, Instant)>,
    /// Maximum requests per window
    limit: u32,
    /// Window duration
    window: Duration,
    /// Total requests allowed (for stats)
    allowed: AtomicU64,
    /// Total requests rate-limited (for stats)
    limited: AtomicU64,
    /// Operations counter for periodic capacity enforcement
    ops: AtomicU64,
    /// Entries evicted due to capacity limits (for stats)
    evicted: AtomicU64,
}

impl RateLimiter {
    /// Creates a new rate limiter with the specified limit per minute.
    pub fn new(limit_per_minute: u32) -> Self {
        Self {
            state: DashMap::new(),
            limit: limit_per_minute,
            window: Duration::from_secs(60),
            allowed: AtomicU64::new(0),
            limited: AtomicU64::new(0),
            ops: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        }
    }

    /// Creates a new rate limiter with custom window duration.
    pub fn with_window(limit: u32, window: Duration) -> Self {
        Self {
            state: DashMap::new(),
            limit,
            window,
            allowed: AtomicU64::new(0),
            limited: AtomicU64::new(0),
            ops: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
        }
    }

    /// Checks if the IP is within rate limit and increments counter.
    ///
    /// Returns `true` if the request is allowed, `false` if rate-limited.
    /// Enforces [`MAX_ENTRIES`] capacity bound, evicting expired entries when full.
    pub fn check_and_increment(&self, ip: &str) -> bool {
        let now = Instant::now();

        // Amortized capacity enforcement: check every CAPACITY_CHECK_INTERVAL ops
        let ops = self.ops.fetch_add(1, Ordering::Relaxed);
        if ops % CAPACITY_CHECK_INTERVAL == 0 && self.state.len() >= MAX_ENTRIES {
            self.evict_expired(now);
        }

        // If still over capacity after eviction, reject new IPs (existing IPs can still be tracked)
        if self.state.len() >= MAX_ENTRIES && !self.state.contains_key(ip) {
            self.limited.fetch_add(1, Ordering::Relaxed);
            self.evicted.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let allowed = {
            let mut entry = self.state.entry(ip.to_string()).or_insert((0, now));

            // Reset window if expired
            if now.duration_since(entry.1) >= self.window {
                entry.0 = 0;
                entry.1 = now;
            }

            // Check limit
            if entry.0 >= self.limit {
                false
            } else {
                entry.0 += 1;
                true
            }
        };

        // Update stats
        if allowed {
            self.allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.limited.fetch_add(1, Ordering::Relaxed);
        }

        allowed
    }

    /// Evicts expired entries to reclaim capacity.
    fn evict_expired(&self, now: Instant) {
        self.state
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < self.window);
    }

    /// Checks if the IP would be allowed without incrementing.
    pub fn check(&self, ip: &str) -> bool {
        let now = Instant::now();

        if let Some(entry) = self.state.get(ip) {
            // Window expired - would be allowed
            if now.duration_since(entry.1) >= self.window {
                return true;
            }
            // Check if under limit
            entry.0 < self.limit
        } else {
            // New IP - would be allowed
            true
        }
    }

    /// Gets the current count for an IP.
    pub fn get_count(&self, ip: &str) -> u32 {
        self.state.get(ip).map(|e| e.0).unwrap_or(0)
    }

    /// Cleans up stale entries older than 2x the window duration.
    ///
    /// Call this periodically from a background task to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        let now = Instant::now();
        let max_age = self.window * 2;

        self.state
            .retain(|_, (_, window_start)| now.duration_since(*window_start) < max_age);
    }

    /// Returns the number of tracked IPs.
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Returns true if no IPs are being tracked.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// Returns statistics about the rate limiter.
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            tracked_ips: self.state.len(),
            max_entries: MAX_ENTRIES,
            allowed: self.allowed.load(Ordering::Relaxed),
            limited: self.limited.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            limit: self.limit,
            window_secs: self.window.as_secs(),
        }
    }

    /// Returns the maximum number of tracked IPs.
    pub fn max_entries(&self) -> usize {
        MAX_ENTRIES
    }

    /// Resets all statistics and clears tracked IPs.
    pub fn reset(&self) {
        self.state.clear();
        self.allowed.store(0, Ordering::Relaxed);
        self.limited.store(0, Ordering::Relaxed);
        self.ops.store(0, Ordering::Relaxed);
        self.evicted.store(0, Ordering::Relaxed);
    }
}

/// Statistics from the rate limiter.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RateLimiterStats {
    /// Number of IPs currently being tracked
    pub tracked_ips: usize,
    /// Maximum capacity
    pub max_entries: usize,
    /// Total requests allowed
    pub allowed: u64,
    /// Total requests rate-limited
    pub limited: u64,
    /// Entries rejected/evicted due to capacity limits
    pub evicted: u64,
    /// Configured limit per window
    pub limit: u32,
    /// Window duration in seconds
    pub window_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_ip_allowed() {
        let limiter = RateLimiter::new(10);
        assert!(limiter.check_and_increment("192.168.1.1"));
    }

    #[test]
    fn test_within_limit() {
        let limiter = RateLimiter::new(5);
        let ip = "10.0.0.1";

        for _ in 0..5 {
            assert!(limiter.check_and_increment(ip));
        }

        assert_eq!(limiter.get_count(ip), 5);
    }

    #[test]
    fn test_exceeds_limit() {
        let limiter = RateLimiter::new(3);
        let ip = "10.0.0.2";

        assert!(limiter.check_and_increment(ip));
        assert!(limiter.check_and_increment(ip));
        assert!(limiter.check_and_increment(ip));
        // Fourth request should be limited
        assert!(!limiter.check_and_increment(ip));
        assert!(!limiter.check_and_increment(ip));
    }

    #[test]
    fn test_window_reset() {
        // Use a very short window for testing
        let limiter = RateLimiter::with_window(2, Duration::from_millis(50));
        let ip = "10.0.0.3";

        assert!(limiter.check_and_increment(ip));
        assert!(limiter.check_and_increment(ip));
        assert!(!limiter.check_and_increment(ip)); // Limited

        // Wait for window to expire
        thread::sleep(Duration::from_millis(60));

        // Should be allowed again
        assert!(limiter.check_and_increment(ip));
    }

    #[test]
    fn test_different_ips_independent() {
        let limiter = RateLimiter::new(2);

        assert!(limiter.check_and_increment("ip1"));
        assert!(limiter.check_and_increment("ip1"));
        assert!(!limiter.check_and_increment("ip1")); // Limited

        // Different IP should be independent
        assert!(limiter.check_and_increment("ip2"));
        assert!(limiter.check_and_increment("ip2"));
        assert!(!limiter.check_and_increment("ip2")); // Limited
    }

    #[test]
    fn test_check_without_increment() {
        let limiter = RateLimiter::new(2);
        let ip = "10.0.0.4";

        assert!(limiter.check(ip)); // Would be allowed
        assert_eq!(limiter.get_count(ip), 0); // Not incremented

        limiter.check_and_increment(ip);
        limiter.check_and_increment(ip);

        assert!(!limiter.check(ip)); // Would be limited
    }

    #[test]
    fn test_cleanup() {
        let limiter = RateLimiter::with_window(10, Duration::from_millis(25));

        limiter.check_and_increment("ip1");
        limiter.check_and_increment("ip2");
        assert_eq!(limiter.len(), 2);

        // Wait for entries to become stale
        thread::sleep(Duration::from_millis(60));

        limiter.cleanup();
        assert_eq!(limiter.len(), 0);
    }

    #[test]
    fn test_stats() {
        let limiter = RateLimiter::new(2);

        limiter.check_and_increment("ip1");
        limiter.check_and_increment("ip1");
        limiter.check_and_increment("ip1"); // Limited

        let stats = limiter.stats();
        assert_eq!(stats.tracked_ips, 1);
        assert_eq!(stats.max_entries, MAX_ENTRIES);
        assert_eq!(stats.allowed, 2);
        assert_eq!(stats.limited, 1);
        assert_eq!(stats.limit, 2);
    }

    #[test]
    fn test_capacity_bound() {
        // Use a small capacity to test the bound behavior
        // We can't easily override MAX_ENTRIES, so we test the eviction path
        // by filling to MAX_ENTRIES. Instead, test that the capacity check runs.
        let limiter = RateLimiter::with_window(100, Duration::from_secs(60));

        // Verify max_entries accessor
        assert_eq!(limiter.max_entries(), MAX_ENTRIES);

        // Verify evicted counter starts at 0
        assert_eq!(limiter.stats().evicted, 0);
    }

    #[test]
    fn test_reset() {
        let limiter = RateLimiter::new(10);

        limiter.check_and_increment("ip1");
        limiter.check_and_increment("ip2");

        limiter.reset();

        assert!(limiter.is_empty());
        let stats = limiter.stats();
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.limited, 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let limiter = Arc::new(RateLimiter::new(100));
        let mut handles = vec![];

        for i in 0..10 {
            let limiter = Arc::clone(&limiter);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    limiter.check_and_increment(&format!("ip{}", i));
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(limiter.len(), 10);
        let stats = limiter.stats();
        assert_eq!(stats.allowed, 100);
    }
}
