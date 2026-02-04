//! Thread-safe tarpit manager using DashMap for concurrent access.
//!
//! Implements progressive delay calculation and state tracking for slow-drip defense.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Deserialize;
use tokio::sync::Semaphore;
use parking_lot::Mutex;

use dashmap::DashMap;

// ============================================================================
// LRU Tracker (O(1) amortized eviction)
// ============================================================================

/// Entry in the LRU queue with generation tracking.
#[derive(Debug, Clone)]
struct LruEntry {
    /// The IP address
    key: String,
    /// Generation number for this entry
    generation: u64,
}

/// Thread-safe LRU tracker using a generation-based queue.
struct LruTracker {
    /// FIFO queue of (key, generation) pairs
    queue: VecDeque<LruEntry>,
    /// Current generation for each key
    generations: HashMap<String, u64>,
    /// Counter for assigning unique generations
    next_generation: u64,
}

impl LruTracker {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            generations: HashMap::with_capacity(capacity),
            next_generation: 0,
        }
    }

    /// Touch a key, marking it as recently used.
    fn touch(&mut self, key: &str) -> bool {
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);

        let is_new = !self.generations.contains_key(key);
        self.generations.insert(key.to_string(), generation);
        self.queue.push_back(LruEntry {
            key: key.to_string(),
            generation,
        });

        is_new
    }

    /// Evict the oldest key that is still valid.
    fn evict_oldest(&mut self) -> Option<String> {
        while let Some(entry) = self.queue.pop_front() {
            if let Some(&current_gen) = self.generations.get(&entry.key) {
                if current_gen == entry.generation {
                    self.generations.remove(&entry.key);
                    return Some(entry.key);
                }
            }
        }
        None
    }

    fn remove(&mut self, key: &str) {
        self.generations.remove(key);
    }

    fn clear(&mut self) {
        self.queue.clear();
        self.generations.clear();
        self.next_generation = 0;
    }
}

/// Configuration for tarpit behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct TarpitConfig {
    /// Base delay in milliseconds (default: 1000ms = 1 second).
    pub base_delay_ms: u64,
    /// Maximum delay in milliseconds (default: 30000ms = 30 seconds).
    pub max_delay_ms: u64,
    /// Multiplier for progressive delays (default: 1.5).
    pub progressive_multiplier: f64,
    /// Whether tarpitting is enabled.
    pub enabled: bool,
    /// Maximum number of tarpit states to track (LRU eviction).
    pub max_states: usize,
    /// Decay threshold in milliseconds (reduce level after this idle time).
    pub decay_threshold_ms: u64,
    /// Cleanup threshold in milliseconds (remove state after this idle time).
    pub cleanup_threshold_ms: u64,
    /// Maximum number of concurrent tarpit delays (prevents resource exhaustion).
    /// Default: 1000 - limits how many connections can be simultaneously tarpitted.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tarpits: usize,
}

fn default_max_concurrent() -> usize {
    1000
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 1000,           // 1 second base
            max_delay_ms: 30000,           // 30 seconds max
            progressive_multiplier: 1.5,   // 1.5x per level
            enabled: true,
            max_states: 10_000,
            decay_threshold_ms: 5 * 60 * 1000,    // 5 minutes
            cleanup_threshold_ms: 30 * 60 * 1000, // 30 minutes
            max_concurrent_tarpits: default_max_concurrent(),
        }
    }
}

/// Per-IP tarpit state.
#[derive(Debug, Clone)]
pub struct TarpitState {
    /// IP address.
    pub ip: String,
    /// Current delay level (starts at 1, increases with hits).
    pub delay_level: u32,
    /// Total tarpit hits.
    pub hit_count: u64,
    /// Last tarpit timestamp (ms since epoch).
    pub last_tarpit_at: u64,
    /// Accumulated delay time (ms).
    pub total_delay_ms: u64,
    /// First tarpit timestamp (ms since epoch).
    pub first_tarpit_at: u64,
}

impl TarpitState {
    /// Create a new tarpit state.
    pub fn new(ip: String, now: u64) -> Self {
        Self {
            ip,
            delay_level: 1,
            hit_count: 0,
            last_tarpit_at: now,
            total_delay_ms: 0,
            first_tarpit_at: now,
        }
    }
}

/// Tarpit decision result.
#[derive(Debug, Clone)]
pub struct TarpitDecision {
    /// Delay to apply in milliseconds.
    pub delay_ms: u64,
    /// Current delay level.
    pub level: u32,
    /// Total hits for this IP.
    pub hit_count: u64,
    /// Whether this IP is actively tarpitted (level > 1).
    pub is_tarpitted: bool,
}

/// Tarpit statistics.
#[derive(Debug, Clone)]
pub struct TarpitStats {
    /// Total tracked states.
    pub total_states: usize,
    /// Active tarpits (level > 1).
    pub active_tarpits: usize,
    /// Total hits across all states.
    pub total_hits: u64,
    /// Total delay applied (ms).
    pub total_delay_ms: u64,
    /// States created.
    pub states_created: u64,
    /// States evicted.
    pub states_evicted: u64,
    /// Tarpits rejected due to concurrent capacity limits.
    pub rejected_tarpits: u64,
    /// Available concurrent tarpit slots.
    pub available_slots: usize,
}

/// Thread-safe tarpit manager.
///
/// Uses DashMap for lock-free concurrent access to tarpit states.
/// Uses a semaphore to limit concurrent tarpit delays and prevent resource exhaustion.
pub struct TarpitManager {
    /// Tarpit states by IP address.
    states: DashMap<String, TarpitState>,
    /// Configuration.
    config: TarpitConfig,
    /// LRU tracker for O(1) eviction.
    lru: Mutex<LruTracker>,
    /// Total states created (for metrics).
    total_created: AtomicU64,
    /// Total states evicted (for metrics).
    total_evicted: AtomicU64,
    /// Maximum delay level (calculated from config).
    max_level: u32,
    /// Semaphore to limit concurrent tarpit delays (prevents resource exhaustion).
    delay_semaphore: Arc<Semaphore>,
    /// Counter for rejected tarpits due to capacity limits.
    rejected_tarpits: AtomicU64,
}

impl Default for TarpitManager {
    fn default() -> Self {
        Self::new(TarpitConfig::default())
    }
}

impl TarpitManager {
    /// Create a new tarpit manager with the given configuration.
    pub fn new(config: TarpitConfig) -> Self {
        // Calculate max level: solve for n in base * mult^(n-1) = max
        // n = log(max/base) / log(mult) + 1
        let max_level = if config.progressive_multiplier > 1.0 && config.base_delay_ms > 0 {
            let ratio = config.max_delay_ms as f64 / config.base_delay_ms as f64;
            (ratio.ln() / config.progressive_multiplier.ln()).ceil() as u32 + 1
        } else {
            1
        };

        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_tarpits));

        Self {
            states: DashMap::with_capacity(config.max_states),
            lru: Mutex::new(LruTracker::new(config.max_states)),
            delay_semaphore: semaphore,
            rejected_tarpits: AtomicU64::new(0),
            config,
            total_created: AtomicU64::new(0),
            total_evicted: AtomicU64::new(0),
            max_level,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &TarpitConfig {
        &self.config
    }

    /// Check if tarpitting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the number of tracked states.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Calculate delay for an IP without incrementing state.
    ///
    /// Use this for read-only delay calculation (e.g., for headers).
    pub fn peek_delay(&self, ip: &str) -> TarpitDecision {
        if !self.config.enabled {
            return TarpitDecision {
                delay_ms: 0,
                level: 0,
                hit_count: 0,
                is_tarpitted: false,
            };
        }

        match self.states.get(ip) {
            Some(entry) => {
                let state = entry.value();
                let delay_ms = self.calculate_delay_for_level(state.delay_level);
                TarpitDecision {
                    delay_ms,
                    level: state.delay_level,
                    hit_count: state.hit_count,
                    is_tarpitted: state.delay_level > 1,
                }
            }
            None => TarpitDecision {
                delay_ms: self.config.base_delay_ms,
                level: 1,
                hit_count: 0,
                is_tarpitted: false,
            },
        }
    }

    /// Calculate and apply tarpit for an IP, incrementing state.
    ///
    /// Returns the delay decision. Use `apply_delay` to actually sleep.
    pub fn tarpit(&self, ip: &str) -> TarpitDecision {
        if !self.config.enabled {
            return TarpitDecision {
                delay_ms: 0,
                level: 0,
                hit_count: 0,
                is_tarpitted: false,
            };
        }

        let now = now_ms();

        // Check capacity and evict if needed
        self.maybe_evict();

        // Touch LRU
        self.lru.lock().touch(ip);

        // Get or create state
        let mut entry = self.states.entry(ip.to_string()).or_insert_with(|| {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            TarpitState::new(ip.to_string(), now)
        });

        let state = entry.value_mut();

        // Apply decay if idle for too long
        self.apply_decay(state, now);

        // Calculate delay for current level
        let delay_ms = self.calculate_delay_for_level(state.delay_level);

        // Update state
        state.hit_count += 1;
        state.last_tarpit_at = now;
        state.total_delay_ms += delay_ms;

        // Increase delay level (progressive), capped at max_level
        state.delay_level = (state.delay_level + 1).min(self.max_level);

        TarpitDecision {
            delay_ms,
            level: state.delay_level,
            hit_count: state.hit_count,
            is_tarpitted: state.delay_level > 1,
        }
    }

    /// Apply tarpit delay asynchronously.
    ///
    /// Uses tokio::time::sleep which releases the worker thread during the delay.
    /// Limited by semaphore to prevent resource exhaustion from too many concurrent delays.
    ///
    /// If the concurrent delay limit is reached, returns a decision with delay_ms=0
    /// to prevent DoS attacks that exploit the tarpit mechanism itself.
    pub async fn apply_delay(&self, ip: &str) -> TarpitDecision {
        let decision = self.tarpit(ip);

        if decision.delay_ms > 0 {
            // Try to acquire a semaphore permit to limit concurrent delays
            match self.delay_semaphore.try_acquire() {
                Ok(permit) => {
                    tokio::time::sleep(tokio::time::Duration::from_millis(decision.delay_ms)).await;
                    // Permit is released when dropped
                    drop(permit);
                }
                Err(_) => {
                    // At capacity - reject this tarpit to prevent resource exhaustion
                    self.rejected_tarpits.fetch_add(1, Ordering::Relaxed);
                    // Return a decision indicating we couldn't apply the delay
                    return TarpitDecision {
                        delay_ms: 0,
                        level: decision.level,
                        hit_count: decision.hit_count,
                        is_tarpitted: decision.is_tarpitted,
                    };
                }
            }
        }

        decision
    }

    /// Returns the number of tarpits rejected due to capacity limits.
    pub fn rejected_count(&self) -> u64 {
        self.rejected_tarpits.load(Ordering::Relaxed)
    }

    /// Returns the number of available tarpit slots.
    pub fn available_slots(&self) -> usize {
        self.delay_semaphore.available_permits()
    }

    /// Check if an IP is actively tarpitted (level > 1).
    pub fn is_tarpitted(&self, ip: &str) -> bool {
        self.states
            .get(ip)
            .map(|entry| entry.value().delay_level > 1)
            .unwrap_or(false)
    }

    /// Get tarpit state for an IP.
    pub fn get_state(&self, ip: &str) -> Option<TarpitState> {
        self.states.get(ip).map(|entry| entry.value().clone())
    }

    /// Reset tarpit state for an IP.
    pub fn reset(&self, ip: &str) -> bool {
        self.states.remove(ip).is_some()
    }

    /// Reset all tarpit states.
    pub fn reset_all(&self) -> usize {
        let count = self.states.len();
        self.states.clear();
        count
    }

    /// Start background tasks (decay, cleanup).
    ///
    /// Spawns a background task that periodically runs maintenance.
    pub fn start_background_tasks(self: Arc<Self>) {
        let manager = self.clone();
        
        tokio::spawn(async move {
            // Run decay every minute
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                manager.decay_all().await;
            }
        });
    }

    /// Run decay on all states with chunked processing to avoid blocking.
    ///
    /// Reduces delay levels for IPs that have been idle and removes expired states.
    pub async fn decay_all(&self) {
        let now = now_ms();
        let decay_threshold = self.config.decay_threshold_ms;
        let cleanup_threshold = self.config.cleanup_threshold_ms;
        
        // Collect actions to perform to avoid holding locks during long iteration.
        // (IP, should_remove)
        let mut actions = Vec::new();

        // 1. Identify states that need decay or cleanup (read-only iteration)
        for entry in self.states.iter() {
            let state = entry.value();
            let idle_time = now.saturating_sub(state.last_tarpit_at);

            if idle_time > cleanup_threshold {
                actions.push((entry.key().clone(), true));
            } else if idle_time > decay_threshold && state.delay_level > 1 {
                actions.push((entry.key().clone(), false));
            }
        }

        // 2. Apply actions in chunks to avoid blocking the executor
        const CHUNK_SIZE: usize = 100;
        for (i, (ip, remove)) in actions.into_iter().enumerate() {
            if remove {
                if self.states.remove(&ip).is_some() {
                    self.total_evicted.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                // Double-check conditions under mutable lock
                if let Some(mut entry) = self.states.get_mut(&ip) {
                    let state = entry.value_mut();
                    let idle_time = now.saturating_sub(state.last_tarpit_at);
                    if idle_time > decay_threshold && state.delay_level > 1 {
                        let decay_periods = (idle_time / decay_threshold) as u32;
                        state.delay_level = state.delay_level.saturating_sub(decay_periods).max(1);
                    }
                }
            }

            // Yield to other tasks every CHUNK_SIZE operations
            if (i + 1) % CHUNK_SIZE == 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    /// Get tarpit statistics.
    pub fn stats(&self) -> TarpitStats {
        let mut total_hits = 0u64;
        let mut total_delay_ms = 0u64;
        let mut active_tarpits = 0usize;

        for entry in self.states.iter() {
            let state = entry.value();
            total_hits += state.hit_count;
            total_delay_ms += state.total_delay_ms;
            if state.delay_level > 1 {
                active_tarpits += 1;
            }
        }

        TarpitStats {
            total_states: self.states.len(),
            active_tarpits,
            total_hits,
            total_delay_ms,
            states_created: self.total_created.load(Ordering::Relaxed),
            states_evicted: self.total_evicted.load(Ordering::Relaxed),
            rejected_tarpits: self.rejected_tarpits.load(Ordering::Relaxed),
            available_slots: self.delay_semaphore.available_permits(),
        }
    }

    // Internal helpers

    /// Calculate delay for a given level.
    fn calculate_delay_for_level(&self, level: u32) -> u64 {
        if level == 0 {
            return 0;
        }

        // delay = base * multiplier^(level-1), capped at max
        let delay = self.config.base_delay_ms as f64
            * self.config.progressive_multiplier.powi(level as i32 - 1);

        (delay as u64).min(self.config.max_delay_ms)
    }

    /// Apply decay to a single state based on idle time.
    fn apply_decay(&self, state: &mut TarpitState, now: u64) {
        let idle_time = now.saturating_sub(state.last_tarpit_at);
        let decay_threshold = self.config.decay_threshold_ms;

        // For each decay_threshold period of inactivity, reduce level by 1
        if idle_time > decay_threshold && state.delay_level > 1 {
            let decay_periods = (idle_time / decay_threshold) as u32;
            state.delay_level = state.delay_level.saturating_sub(decay_periods).max(1);
        }
    }

    /// Maybe evict oldest states if at capacity.
    fn maybe_evict(&self) {
        if self.states.len() < self.config.max_states {
            return;
        }

        // Use LRU tracker for O(1) eviction
        if let Some(ip) = self.lru.lock().evict_oldest() {
            if self.states.remove(&ip).is_some() {
                self.total_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
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
    fn test_tarpit_creation() {
        let manager = TarpitManager::default();
        assert!(manager.is_enabled());
        assert!(manager.is_empty());
    }

    #[test]
    fn test_calculate_delay_for_level() {
        let manager = TarpitManager::default();

        // Level 1: base (1000ms)
        assert_eq!(manager.calculate_delay_for_level(1), 1000);

        // Level 2: 1000 * 1.5 = 1500ms
        assert_eq!(manager.calculate_delay_for_level(2), 1500);

        // Level 3: 1000 * 1.5^2 = 2250ms
        assert_eq!(manager.calculate_delay_for_level(3), 2250);

        // Level 4: 1000 * 1.5^3 = 3375ms
        assert_eq!(manager.calculate_delay_for_level(4), 3375);

        // Higher levels should cap at max (30000ms)
        assert!(manager.calculate_delay_for_level(20) <= 30000);
    }

    #[test]
    fn test_tarpit_progression() {
        let manager = TarpitManager::default();

        // First tarpit: level 1 delay, then level increases to 2
        let d1 = manager.tarpit("192.168.1.1");
        assert_eq!(d1.delay_ms, 1000); // Level 1 delay
        assert_eq!(d1.level, 2);       // Level increased to 2
        assert_eq!(d1.hit_count, 1);
        assert!(d1.is_tarpitted);      // Now tarpitted (level > 1)

        // Second tarpit: level 2 delay, then level increases to 3
        let d2 = manager.tarpit("192.168.1.1");
        assert_eq!(d2.delay_ms, 1500); // Level 2 delay
        assert_eq!(d2.level, 3);
        assert_eq!(d2.hit_count, 2);

        // Third tarpit: level 3 delay
        let d3 = manager.tarpit("192.168.1.1");
        assert_eq!(d3.delay_ms, 2250); // Level 3 delay
        assert_eq!(d3.level, 4);
        assert_eq!(d3.hit_count, 3);
    }

    #[test]
    fn test_peek_delay() {
        let manager = TarpitManager::default();

        // Peek before any tarpit
        let d1 = manager.peek_delay("192.168.1.1");
        assert_eq!(d1.delay_ms, 1000);
        assert_eq!(d1.level, 1);
        assert_eq!(d1.hit_count, 0);
        assert!(!d1.is_tarpitted);

        // Tarpit to increase level
        manager.tarpit("192.168.1.1");

        // Peek should show new level without incrementing
        let d2 = manager.peek_delay("192.168.1.1");
        assert_eq!(d2.level, 2);
        assert_eq!(d2.hit_count, 1);

        // Peek again - should be the same
        let d3 = manager.peek_delay("192.168.1.1");
        assert_eq!(d3.level, 2);
        assert_eq!(d3.hit_count, 1);
    }

    #[test]
    fn test_max_delay_cap() {
        let config = TarpitConfig {
            base_delay_ms: 1000,
            max_delay_ms: 5000,
            progressive_multiplier: 2.0,
            ..Default::default()
        };
        let manager = TarpitManager::new(config);

        // Tarpit many times to reach max
        for _ in 0..20 {
            manager.tarpit("192.168.1.1");
        }

        // Delay should be capped at max
        let decision = manager.peek_delay("192.168.1.1");
        assert!(decision.delay_ms <= 5000);
    }

    #[test]
    fn test_reset() {
        let manager = TarpitManager::default();

        manager.tarpit("192.168.1.1");
        manager.tarpit("192.168.1.1");
        assert!(manager.is_tarpitted("192.168.1.1"));

        let removed = manager.reset("192.168.1.1");
        assert!(removed);
        assert!(!manager.is_tarpitted("192.168.1.1"));

        // Reset non-existent
        assert!(!manager.reset("192.168.1.2"));
    }

    #[test]
    fn test_reset_all() {
        let manager = TarpitManager::default();

        manager.tarpit("192.168.1.1");
        manager.tarpit("192.168.1.2");
        manager.tarpit("192.168.1.3");
        assert_eq!(manager.len(), 3);

        let count = manager.reset_all();
        assert_eq!(count, 3);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_stats() {
        let manager = TarpitManager::default();

        manager.tarpit("192.168.1.1");
        manager.tarpit("192.168.1.1");
        manager.tarpit("192.168.1.2");

        let stats = manager.stats();
        assert_eq!(stats.total_states, 2);
        assert_eq!(stats.total_hits, 3);
        assert!(stats.total_delay_ms > 0);
        assert_eq!(stats.active_tarpits, 2); // Both IPs now have level > 1
    }

    #[test]
    fn test_disabled() {
        let config = TarpitConfig {
            enabled: false,
            ..Default::default()
        };
        let manager = TarpitManager::new(config);

        let decision = manager.tarpit("192.168.1.1");
        assert_eq!(decision.delay_ms, 0);
        assert_eq!(decision.level, 0);
        assert!(!decision.is_tarpitted);
    }

    #[test]
    fn test_lru_eviction() {
        let config = TarpitConfig {
            max_states: 3,
            ..Default::default()
        };
        let manager = TarpitManager::new(config);

        // Add 3 states with small delays to ensure different timestamps
        manager.tarpit("1.1.1.1");
        std::thread::sleep(std::time::Duration::from_millis(2));
        manager.tarpit("2.2.2.2");
        std::thread::sleep(std::time::Duration::from_millis(2));
        manager.tarpit("3.3.3.3");
        assert_eq!(manager.len(), 3);

        // Add 4th - should evict oldest (1.1.1.1)
        manager.tarpit("4.4.4.4");
        assert_eq!(manager.len(), 3);

        // First IP should be evicted (oldest by timestamp)
        assert!(manager.get_state("1.1.1.1").is_none(), "1.1.1.1 should have been evicted as oldest");
        assert!(manager.get_state("4.4.4.4").is_some(), "4.4.4.4 should exist");
    }

    #[test]
    fn test_max_level_calculation() {
        // Default config: base=1000, max=30000, mult=1.5
        // max_level = log(30000/1000) / log(1.5) + 1 = log(30) / log(1.5) + 1 ≈ 8.4 + 1 = 10
        let manager = TarpitManager::default();
        assert!(manager.max_level >= 8 && manager.max_level <= 12);

        // Tarpit many times - level should cap at max_level
        for _ in 0..50 {
            manager.tarpit("192.168.1.1");
        }
        let state = manager.get_state("192.168.1.1").unwrap();
        assert!(state.delay_level <= manager.max_level);
    }

    #[tokio::test]
    async fn test_apply_delay() {
        let config = TarpitConfig {
            base_delay_ms: 10, // Very short for testing
            max_delay_ms: 100,
            ..Default::default()
        };
        let manager = TarpitManager::new(config);

        let start = std::time::Instant::now();
        let decision = manager.apply_delay("192.168.1.1").await;
        let elapsed = start.elapsed();

        // Should have delayed at least the calculated amount (minus some tolerance)
        assert!(elapsed.as_millis() >= decision.delay_ms as u128 - 5);
    }
}
