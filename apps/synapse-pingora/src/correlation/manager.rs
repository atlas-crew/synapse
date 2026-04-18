//! Campaign Correlation Manager
//!
//! Orchestrates fingerprint indexing, campaign detection, and state management.
//! This is the main entry point for the correlation subsystem.
//!
//! # Architecture
//!
//! The `CampaignManager` coordinates three main components:
//! - **FingerprintIndex**: O(1) fingerprint→IPs lookup for efficient correlation
//! - **CampaignStore**: Campaign state storage with thread-safe access
//! - **Detectors**: SharedFingerprintDetector and Ja4RotationDetector for pattern detection
//!
//! # Usage
//!
//! ```rust,ignore
//! use synapse_pingora::correlation::{CampaignManager, ManagerConfig};
//! use std::sync::Arc;
//!
//! // Create manager with custom configuration
//! let config = ManagerConfig {
//!     shared_threshold: 3,
//!     rotation_threshold: 3,
//!     background_scanning: true,
//!     ..Default::default()
//! };
//! let manager = Arc::new(CampaignManager::with_config(config));
//!
//! // Register fingerprints during request processing (fast path)
//! let ip = "192.168.1.100".parse().unwrap();
//! manager.register_ja4(ip, "t13d1516h2_abc123".to_string());
//!
//! // Start background worker for periodic detection
//! let worker = Arc::clone(&manager).start_background_worker();
//! ```
//!
//! # Performance
//!
//! - Registration operations are O(1) and non-blocking for hot path
//! - Detection cycles are run periodically in background, not per-request
//! - All structures use lock-free DashMap for high concurrency

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use parking_lot::RwLock as ParkingLotRwLock;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;

use crate::access::AccessListManager;
use crate::correlation::{
    Campaign, CampaignStatus, CampaignStore, CampaignStoreStats, CampaignUpdate, FingerprintGroup,
    FingerprintIndex, IndexStats,
};
use crate::telemetry::{TelemetryClient, TelemetryEvent};

use crate::correlation::detectors::{
    AttackPayload,
    AttackSequenceConfig,
    // New detectors
    AttackSequenceDetector,
    AuthTokenConfig,
    AuthTokenDetector,
    BehavioralConfig,
    BehavioralSimilarityDetector,
    Detector,
    DetectorError,
    DetectorResult,
    GraphConfig,
    GraphDetector,
    Ja4RotationDetector,
    NetworkProximityConfig,
    NetworkProximityDetector,
    RotationConfig,
    // Fingerprint detectors
    SharedFingerprintDetector,
    TimingConfig,
    TimingCorrelationDetector,
};

// ============================================================================
// Mitigation Rate Limiter (Security: Prevent mass-ban DoS)
// ============================================================================

/// Rate limiter for auto-mitigation to prevent mass-banning attacks.
///
/// Limits the number of IPs that can be banned per time window.
/// If an attacker generates many apparent campaigns, this prevents
/// legitimate users from being incorrectly blocked en masse.
#[derive(Debug)]
pub struct MitigationRateLimiter {
    /// Number of bans in current window.
    bans_in_window: AtomicU64,
    /// Window start time.
    window_start: Mutex<Instant>,
    /// Maximum bans allowed per window.
    max_bans_per_window: u64,
    /// Window duration.
    window_duration: Duration,
    /// Maximum IPs to ban per campaign.
    max_ips_per_campaign: usize,
}

impl MitigationRateLimiter {
    /// Creates a new rate limiter.
    pub fn new(
        max_bans_per_window: u64,
        window_duration: Duration,
        max_ips_per_campaign: usize,
    ) -> Self {
        Self {
            bans_in_window: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
            max_bans_per_window,
            window_duration,
            max_ips_per_campaign,
        }
    }

    /// Attempts to acquire a ban permit.
    ///
    /// Returns Ok(()) if the ban is allowed, Err with reason if rate limited.
    pub async fn try_ban(&self) -> Result<(), String> {
        self.maybe_reset_window().await;

        let current = self.bans_in_window.fetch_add(1, Ordering::SeqCst);
        if current >= self.max_bans_per_window {
            self.bans_in_window.fetch_sub(1, Ordering::SeqCst);
            return Err(format!(
                "Rate limit exceeded: {} bans in {:?} window",
                self.max_bans_per_window, self.window_duration
            ));
        }
        Ok(())
    }

    /// Resets the window if it has expired.
    async fn maybe_reset_window(&self) {
        let mut start = self.window_start.lock().await;

        // Double-check expiration under the lock to prevent multiple resets
        if start.elapsed() >= self.window_duration {
            *start = Instant::now();
            self.bans_in_window.store(0, Ordering::SeqCst);
        }
    }

    /// Returns the maximum IPs that can be banned per campaign.
    pub fn max_ips_per_campaign(&self) -> usize {
        self.max_ips_per_campaign
    }

    /// Returns current ban count in window.
    pub fn current_count(&self) -> u64 {
        self.bans_in_window.load(Ordering::SeqCst)
    }
}

impl Default for MitigationRateLimiter {
    fn default() -> Self {
        Self::new(
            50,                      // Max 50 bans per window
            Duration::from_secs(60), // 1 minute window
            10,                      // Max 10 IPs per campaign
        )
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the campaign manager.
///
/// Controls detector thresholds, timing windows, and background scanning behavior.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Minimum IPs sharing fingerprint to form campaign (shared FP detector).
    ///
    /// Default: 3
    pub shared_threshold: usize,

    /// Time window for rotation detection.
    ///
    /// Default: 60 seconds
    pub rotation_window: Duration,

    /// Minimum fingerprints for rotation detection.
    ///
    /// Default: 3
    pub rotation_threshold: usize,

    /// How often to run full detector scans.
    ///
    /// Default: 5 seconds
    pub scan_interval: Duration,

    /// Enable background scanning.
    ///
    /// When enabled, a background worker periodically runs detection cycles.
    /// Default: true
    pub background_scanning: bool,

    /// Track combined fingerprints (JA4+JA4H) in rotation detector.
    ///
    /// Default: true
    pub track_combined: bool,

    /// Base confidence for shared fingerprint detections.
    ///
    /// Default: 0.85
    pub shared_confidence: f64,

    // ========================================================================
    // Attack Sequence Detector Configuration (weight: 50)
    // ========================================================================
    /// Minimum IPs sharing same payload to trigger detection.
    ///
    /// Default: 2
    pub attack_sequence_min_ips: usize,

    /// Time window for attack sequence correlation.
    ///
    /// Default: 300 seconds (5 minutes)
    pub attack_sequence_window: Duration,

    // ========================================================================
    // Auth Token Detector Configuration (weight: 45)
    // ========================================================================
    /// Minimum IPs sharing token structure to trigger detection.
    ///
    /// Default: 2
    pub auth_token_min_ips: usize,

    /// Time window for auth token correlation.
    ///
    /// Default: 600 seconds (10 minutes)
    pub auth_token_window: Duration,

    // ========================================================================
    // Behavioral Similarity Detector Configuration (weight: 30)
    // ========================================================================
    /// Minimum IPs with same behavior pattern.
    ///
    /// Default: 2
    pub behavioral_min_ips: usize,

    /// Minimum sequence length to consider for behavioral analysis.
    ///
    /// Default: 3
    pub behavioral_min_sequence: usize,

    /// Time window for behavioral pattern observation.
    ///
    /// Default: 300 seconds (5 minutes)
    pub behavioral_window: Duration,

    // ========================================================================
    // Timing Correlation Detector Configuration (weight: 25)
    // ========================================================================
    /// Minimum IPs with synchronized timing.
    ///
    /// Default: 3
    pub timing_min_ips: usize,

    /// Time bucket size for synchronization detection in milliseconds.
    ///
    /// Default: 100ms
    pub timing_bucket_ms: u64,

    /// Minimum requests in same bucket to consider correlated.
    ///
    /// Default: 5
    pub timing_min_bucket_hits: usize,

    /// Time window for timing analysis.
    ///
    /// Default: 60 seconds
    pub timing_window: Duration,

    // ========================================================================
    // Network Proximity Detector Configuration (weight: 15)
    // ========================================================================
    /// Minimum IPs in same network segment.
    ///
    /// Default: 3
    pub network_min_ips: usize,

    /// Enable subnet-based correlation (/24 for IPv4).
    ///
    /// Default: true
    pub network_check_subnet: bool,

    // ========================================================================
    // Graph Correlation Detector Configuration (weight: 20)
    // ========================================================================
    /// Minimum connected component size.
    ///
    /// Default: 3
    pub graph_min_component_size: usize,

    /// Maximum traversal depth.
    ///
    /// Default: 3
    pub graph_max_depth: usize,

    /// Edge TTL.
    ///
    /// Default: 3600 seconds
    pub graph_edge_ttl: Duration,

    // ========================================================================
    // Automated Response Configuration
    // ========================================================================
    /// Enable automated mitigation (blocking) of high-confidence campaigns.
    ///
    /// Default: false
    pub auto_mitigation_enabled: bool,

    /// Confidence threshold for automated mitigation (0.0 - 1.0).
    ///
    /// Default: 0.90
    pub auto_mitigation_threshold: f64,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            shared_threshold: 3,
            rotation_window: Duration::from_secs(60),
            rotation_threshold: 3,
            scan_interval: Duration::from_secs(5),
            background_scanning: true,
            track_combined: true,
            shared_confidence: 0.85,
            // Attack sequence detector (weight: 50)
            attack_sequence_min_ips: 2,
            attack_sequence_window: Duration::from_secs(300),
            // Auth token detector (weight: 45)
            auth_token_min_ips: 2,
            auth_token_window: Duration::from_secs(600),
            // Behavioral similarity detector (weight: 30)
            behavioral_min_ips: 2,
            behavioral_min_sequence: 3,
            behavioral_window: Duration::from_secs(300),
            // Timing correlation detector (weight: 25)
            timing_min_ips: 3,
            timing_bucket_ms: 100,
            timing_min_bucket_hits: 5,
            timing_window: Duration::from_secs(60),
            // Network proximity detector (weight: 15)
            network_min_ips: 3,
            network_check_subnet: true,
            // Graph correlation detector (weight: 20)
            graph_min_component_size: 3,
            graph_max_depth: 3,
            graph_edge_ttl: Duration::from_secs(3600),
            // Automated Response
            auto_mitigation_enabled: false,
            auto_mitigation_threshold: 0.90,
        }
    }
}

impl ManagerConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder method to set shared threshold.
    pub fn with_shared_threshold(mut self, threshold: usize) -> Self {
        self.shared_threshold = threshold;
        self
    }

    /// Builder method to set rotation window.
    pub fn with_rotation_window(mut self, window: Duration) -> Self {
        self.rotation_window = window;
        self
    }

    /// Builder method to set rotation threshold.
    pub fn with_rotation_threshold(mut self, threshold: usize) -> Self {
        self.rotation_threshold = threshold;
        self
    }

    /// Builder method to set scan interval.
    pub fn with_scan_interval(mut self, interval: Duration) -> Self {
        self.scan_interval = interval;
        self
    }

    /// Builder method to enable/disable background scanning.
    pub fn with_background_scanning(mut self, enabled: bool) -> Self {
        self.background_scanning = enabled;
        self
    }

    /// Builder method to enable/disable combined fingerprint tracking.
    pub fn with_track_combined(mut self, enabled: bool) -> Self {
        self.track_combined = enabled;
        self
    }

    /// Builder method to set shared confidence.
    pub fn with_shared_confidence(mut self, confidence: f64) -> Self {
        self.shared_confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Builder method to enable/disable automated mitigation.
    pub fn with_auto_mitigation(mut self, enabled: bool) -> Self {
        self.auto_mitigation_enabled = enabled;
        self
    }

    /// Builder method to set automated mitigation threshold.
    pub fn with_auto_mitigation_threshold(mut self, threshold: f64) -> Self {
        self.auto_mitigation_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Validate the configuration.
    ///
    /// Returns an error message if configuration is invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.shared_threshold < 2 {
            return Err("shared_threshold must be at least 2".to_string());
        }
        if self.rotation_threshold < 2 {
            return Err("rotation_threshold must be at least 2".to_string());
        }
        if self.rotation_window.is_zero() {
            return Err("rotation_window must be positive".to_string());
        }
        if self.scan_interval.is_zero() {
            return Err("scan_interval must be positive".to_string());
        }
        // Security: Auto-mitigation threshold must be high to prevent false positives
        if self.auto_mitigation_enabled && self.auto_mitigation_threshold < 0.7 {
            return Err(
                "auto_mitigation_threshold must be >= 0.7 when auto_mitigation is enabled to prevent false positives"
                    .to_string(),
            );
        }
        // Security: Graph bounds must be reasonable
        if self.graph_min_component_size < 2 {
            return Err("graph_min_component_size must be at least 2".to_string());
        }
        Ok(())
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for the campaign manager.
///
/// Provides observability into manager operations including registration counts,
/// detection cycles, and campaign creation.
#[derive(Debug, Clone, Default)]
pub struct ManagerStats {
    /// Total fingerprints registered since start.
    pub fingerprints_registered: u64,

    /// Total detection cycles run.
    pub detections_run: u64,

    /// Total campaigns created.
    pub campaigns_created: u64,

    /// Last successful scan timestamp.
    pub last_scan: Option<Instant>,

    /// Statistics from the fingerprint index.
    pub index_stats: IndexStats,

    /// Statistics from the campaign store.
    pub campaign_stats: CampaignStoreStats,

    /// Detections count by detector type.
    pub detections_by_type: std::collections::HashMap<String, u64>,
}

// ============================================================================
// Fingerprint Group Cache
// ============================================================================

/// TTL for cached fingerprint groups (100ms).
const GROUP_CACHE_TTL: Duration = Duration::from_millis(100);

/// Cache for fingerprint groups to avoid repeated expensive scans.
///
/// The `get_groups_above_threshold()` method on FingerprintIndex is O(n) and
/// can be called by multiple detectors during a single detection cycle. This
/// cache provides a short-lived (100ms) cached result to amortize the cost.
struct GroupCache {
    /// Cached fingerprint groups.
    groups: Vec<FingerprintGroup>,
    /// Timestamp when the cache was populated.
    cached_at: Instant,
    /// The threshold that was used to generate this cache.
    threshold: usize,
}

impl GroupCache {
    /// Create a new cache entry.
    fn new(groups: Vec<FingerprintGroup>, threshold: usize) -> Self {
        Self {
            groups,
            cached_at: Instant::now(),
            threshold,
        }
    }

    /// Check if the cache is still valid.
    fn is_valid(&self, threshold: usize) -> bool {
        self.threshold == threshold && self.cached_at.elapsed() < GROUP_CACHE_TTL
    }
}

// ============================================================================
// Campaign Manager
// ============================================================================

/// Main orchestrator for campaign correlation.
///
/// Coordinates fingerprint indexing, campaign detection, and state management.
/// This is the entry point for the correlation subsystem.
///
/// # Thread Safety
///
/// All methods are thread-safe and can be called concurrently. The manager uses
/// lock-free data structures (DashMap) and atomic counters for high-performance
/// concurrent access.
///
/// # Registration vs Detection
///
/// - **Registration** (`register_*` methods): Called per-request, must be FAST.
///   Only updates indexes, no detection logic.
/// - **Detection** (`run_detection_cycle`): Called periodically by background
///   worker or on-demand. Processes all detectors and applies campaign updates.
///
/// # Detectors (ordered by weight)
///
/// 1. Attack Sequence (50) - Same attack payloads across actors
/// 2. Auth Token (45) - Same JWT structure/issuer across IPs
/// 3. HTTP Fingerprint (40) - Identical browser fingerprint (JA4H)
/// 4. TLS Fingerprint (35) - Same TLS signature (JA4)
/// 5. Behavioral Similarity (30) - Identical navigation/timing patterns
/// 6. Timing Correlation (25) - Coordinated request timing (botnets)
/// 7. Network Proximity (15) - Same ASN or /24 subnet
pub struct CampaignManager {
    /// Manager configuration.
    config: ManagerConfig,

    /// Fingerprint index for O(1) lookups.
    index: Arc<FingerprintIndex>,

    /// Campaign state storage.
    store: Arc<CampaignStore>,

    /// Access List Manager for automated mitigation (optional).
    access_list_manager: Option<Arc<ParkingLotRwLock<AccessListManager>>>,

    /// Telemetry client for cross-tenant correlation (optional).
    telemetry_client: Option<Arc<TelemetryClient>>,

    // ========================================================================
    // All 7 Detectors (ordered by weight)
    // ========================================================================
    /// Attack sequence detector (weight: 50 - highest signal).
    attack_sequence_detector: AttackSequenceDetector,

    /// Auth token detector (weight: 45).
    auth_token_detector: AuthTokenDetector,

    /// HTTP fingerprint detector (weight: 40).
    http_fingerprint_detector: SharedFingerprintDetector,

    /// TLS fingerprint / JA4 rotation detector (weight: 35).
    tls_fingerprint_detector: Ja4RotationDetector,

    /// Behavioral similarity detector (weight: 30).
    behavioral_detector: BehavioralSimilarityDetector,

    /// Timing correlation detector (weight: 25).
    timing_detector: TimingCorrelationDetector,

    /// Network proximity detector (weight: 15 - lowest signal).
    network_detector: NetworkProximityDetector,

    /// Graph correlation detector (weight: 20).
    graph_detector: GraphDetector,

    /// Internal statistics (atomic counters for thread safety).
    stats_fingerprints_registered: AtomicU64,
    stats_detections_run: AtomicU64,
    stats_campaigns_created: AtomicU64,

    /// Per-detector detection counts.
    stats_detections_by_type: RwLock<std::collections::HashMap<String, u64>>,

    /// Last scan timestamp (protected by RwLock for safe concurrent access).
    last_scan: RwLock<Option<Instant>>,

    /// Flag to signal background worker shutdown.
    shutdown: AtomicBool,

    /// Cache for fingerprint groups (100ms TTL).
    /// Reduces repeated expensive scans during detection cycles.
    group_cache: RwLock<Option<GroupCache>>,

    /// Rate limiter for auto-mitigation to prevent mass-banning.
    mitigation_rate_limiter: MitigationRateLimiter,

    /// Track mitigated campaigns to prevent re-mitigation.
    mitigated_campaigns: dashmap::DashSet<String>,
}

impl CampaignManager {
    /// Create a new campaign manager with default configuration.
    pub fn new() -> Self {
        Self::with_config(ManagerConfig::default())
    }

    /// Create a new campaign manager with custom configuration.
    pub fn with_config(config: ManagerConfig) -> Self {
        // ====================================================================
        // Initialize all 7 detectors from config
        // ====================================================================

        // 1. Attack Sequence Detector (weight: 50)
        let attack_sequence_config = AttackSequenceConfig {
            min_ips: config.attack_sequence_min_ips,
            window: config.attack_sequence_window,
            similarity_threshold: 0.95, // Default similarity threshold
            ..Default::default()
        };
        let attack_sequence_detector = AttackSequenceDetector::new(attack_sequence_config);

        // 2. Auth Token Detector (weight: 45)
        let auth_token_config = AuthTokenConfig {
            min_ips: config.auth_token_min_ips,
            window: config.auth_token_window,
            ..Default::default()
        };
        let auth_token_detector = AuthTokenDetector::new(auth_token_config);

        // 3. HTTP Fingerprint Detector (weight: 40)
        let http_fingerprint_detector = SharedFingerprintDetector::with_config(
            config.shared_threshold,
            config.shared_confidence,
            config.scan_interval.as_millis() as u64,
        );

        // 4. TLS Fingerprint / JA4 Rotation Detector (weight: 35)
        let rotation_config = RotationConfig {
            min_fingerprints: config.rotation_threshold,
            window: config.rotation_window,
            track_combined: config.track_combined,
            ..Default::default()
        };
        let tls_fingerprint_detector = Ja4RotationDetector::new(rotation_config);

        // 5. Behavioral Similarity Detector (weight: 30)
        let behavioral_config = BehavioralConfig {
            min_ips: config.behavioral_min_ips,
            min_sequence_length: config.behavioral_min_sequence,
            window: config.behavioral_window,
            ..Default::default()
        };
        let behavioral_detector = BehavioralSimilarityDetector::new(behavioral_config);

        // 6. Timing Correlation Detector (weight: 25)
        let timing_config = TimingConfig {
            min_ips: config.timing_min_ips,
            bucket_size: Duration::from_millis(config.timing_bucket_ms),
            min_bucket_hits: config.timing_min_bucket_hits,
            window: config.timing_window,
            ..Default::default()
        };
        let timing_detector = TimingCorrelationDetector::new(timing_config);

        // 7. Network Proximity Detector (weight: 15)
        let network_config = NetworkProximityConfig {
            min_ips: config.network_min_ips,
            check_subnet: config.network_check_subnet,
            check_asn: false, // ASN lookup requires external data
            ..Default::default()
        };
        let network_detector = NetworkProximityDetector::new(network_config);

        // 8. Graph Correlation Detector (weight: 20)
        let graph_config = GraphConfig {
            min_component_size: config.graph_min_component_size,
            max_traversal_depth: config.graph_max_depth,
            edge_ttl: config.graph_edge_ttl,
            ..Default::default()
        };
        let graph_detector = GraphDetector::new(graph_config);

        Self {
            config,
            index: Arc::new(FingerprintIndex::new()),
            store: Arc::new(CampaignStore::new()),
            access_list_manager: None,
            telemetry_client: None,
            // All 7 detectors
            attack_sequence_detector,
            auth_token_detector,
            http_fingerprint_detector,
            tls_fingerprint_detector,
            behavioral_detector,
            timing_detector,
            network_detector,
            graph_detector,
            // Statistics
            stats_fingerprints_registered: AtomicU64::new(0),
            stats_detections_run: AtomicU64::new(0),
            stats_campaigns_created: AtomicU64::new(0),
            stats_detections_by_type: RwLock::new(std::collections::HashMap::new()),
            last_scan: RwLock::new(None),
            shutdown: AtomicBool::new(false),
            // Cache for fingerprint groups (starts empty)
            group_cache: RwLock::new(None),
            // Mitigation rate limiter and tracking
            mitigation_rate_limiter: MitigationRateLimiter::default(),
            mitigated_campaigns: dashmap::DashSet::new(),
        }
    }

    /// Set the AccessListManager for automated mitigation.
    pub fn set_access_list_manager(&mut self, manager: Arc<ParkingLotRwLock<AccessListManager>>) {
        self.access_list_manager = Some(manager);
    }

    /// Set the TelemetryClient for cross-tenant correlation.
    pub fn set_telemetry_client(&mut self, client: Arc<TelemetryClient>) {
        self.telemetry_client = Some(client);
    }

    /// Register a JA4 fingerprint for an IP address.
    ///
    /// Called during request processing - must be fast.
    /// Only updates indexes, no detection logic is run.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `fingerprint` - The JA4 TLS fingerprint
    pub fn register_ja4(&self, ip: IpAddr, fingerprint: String) {
        if fingerprint.is_empty() {
            return;
        }

        let ip_str = ip.to_string();

        // Update fingerprint index
        self.index.update_entity(&ip_str, Some(&fingerprint), None);

        // Record in rotation detector (TASK-64: detector stores Arc<str>)
        self.tls_fingerprint_detector
            .record_fingerprint(ip, Arc::from(fingerprint));

        // Increment stats
        self.stats_fingerprints_registered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Register a JA4 fingerprint using Arc<str> to reduce allocations.
    ///
    /// Optimized version for callers who already have an Arc<str> fingerprint.
    /// This avoids cloning the fingerprint string when it's already reference-counted.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `fingerprint` - The JA4 TLS fingerprint as Arc<str>
    pub fn register_ja4_arc(&self, ip: IpAddr, fingerprint: Arc<str>) {
        if fingerprint.is_empty() {
            return;
        }

        let ip_str = ip.to_string();

        // Update fingerprint index (uses &str reference, no allocation needed)
        self.index.update_entity(&ip_str, Some(&fingerprint), None);

        // TASK-64: detector stores Arc<str> directly — no allocation.
        self.tls_fingerprint_detector
            .record_fingerprint(ip, fingerprint);

        // Increment stats
        self.stats_fingerprints_registered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Register a combined (JA4+JA4H) fingerprint for an IP address.
    ///
    /// Combined fingerprints provide higher confidence correlation due to
    /// increased specificity.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `fingerprint` - The combined fingerprint hash
    pub fn register_combined(&self, ip: IpAddr, fingerprint: String) {
        if fingerprint.is_empty() {
            return;
        }

        let ip_str = ip.to_string();

        // Update fingerprint index (combined only)
        self.index.update_entity(&ip_str, None, Some(&fingerprint));

        // Record in rotation detector if tracking combined
        if self.config.track_combined {
            self.tls_fingerprint_detector
                .record_fingerprint(ip, Arc::from(fingerprint));
        }

        // Increment stats
        self.stats_fingerprints_registered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Register a combined fingerprint using Arc<str> to reduce allocations.
    ///
    /// Optimized version for callers who already have an Arc<str> fingerprint.
    /// This avoids cloning the fingerprint string when it's already reference-counted.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `fingerprint` - The combined fingerprint hash as Arc<str>
    pub fn register_combined_arc(&self, ip: IpAddr, fingerprint: Arc<str>) {
        if fingerprint.is_empty() {
            return;
        }

        let ip_str = ip.to_string();

        // Update fingerprint index (combined only, uses &str reference)
        self.index.update_entity(&ip_str, None, Some(&fingerprint));

        // Record in rotation detector if tracking combined
        if self.config.track_combined {
            self.tls_fingerprint_detector
                .record_fingerprint(ip, fingerprint);
        }

        // Increment stats
        self.stats_fingerprints_registered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Register both JA4 and JA4H fingerprints.
    ///
    /// Convenience method for registering both fingerprint types in one call.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `ja4` - Optional JA4 TLS fingerprint
    /// * `ja4h` - Optional JA4H HTTP fingerprint (used in combined hash)
    pub fn register_fingerprints(&self, ip: IpAddr, ja4: Option<Arc<str>>, ja4h: Option<Arc<str>>) {
        // TASK-64: ja4 and ja4h arrive as Arc<str> so the filter-chain hot
        // path never allocates String copies for these fingerprints. The
        // rotation detector stores Arc<str> directly, so refcount bumps
        // replace heap allocations all the way down.
        let ip_str = ip.to_string();
        let mut registered = false;

        // Update fingerprint index (needs &str, Arc<str> derefs transparently)
        let ja4_ref = ja4.as_deref();
        let combined: Option<Arc<str>> = ja4h.as_ref().map(|h| {
            // Combined hash still requires one allocation (the format), but
            // we materialise it as Arc<str> so downstream storage pays no
            // additional allocation.
            Arc::from(format!("{}_{}", ja4.as_deref().unwrap_or(""), h.as_ref()))
        });
        let combined_ref = combined.as_deref();

        self.index.update_entity(&ip_str, ja4_ref, combined_ref);

        // Record JA4 in rotation detector (Arc::clone is a refcount bump)
        if let Some(ref fp) = ja4 {
            if !fp.is_empty() {
                self.tls_fingerprint_detector
                    .record_fingerprint(ip, Arc::clone(fp));
                registered = true;
            }
        }

        // Record combined in rotation detector if tracking
        if self.config.track_combined {
            if let Some(ref fp) = combined {
                if !fp.is_empty() {
                    self.tls_fingerprint_detector
                        .record_fingerprint(ip, Arc::clone(fp));
                    registered = true;
                }
            }
        }

        if registered {
            self.stats_fingerprints_registered
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    // ========================================================================
    // New Detector Registration Methods
    // ========================================================================

    /// Record an attack payload observation for campaign correlation.
    ///
    /// Called when an attack is detected (SQLi, XSS, etc.) to correlate
    /// identical payloads across different IPs. Weight: 50 (highest signal).
    ///
    /// # Arguments
    /// * `ip` - The IP address of the attacker
    /// * `payload_hash` - Hash of the normalized attack payload
    /// * `attack_type` - Classification (sqli, xss, path_traversal, etc.)
    /// * `path` - Target path of the attack
    pub fn record_attack(
        &self,
        ip: IpAddr,
        payload_hash: String,
        attack_type: String,
        path: String,
    ) {
        self.attack_sequence_detector.record_attack(
            ip,
            AttackPayload {
                payload_hash,
                attack_type,
                target_path: path,
                timestamp: std::time::Instant::now(),
            },
        );
    }

    /// Record a JWT token observation for campaign correlation.
    ///
    /// Called when a JWT is seen in request headers. Correlates IPs
    /// using tokens with identical structure or issuer. Weight: 45.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `jwt` - The raw JWT string (header.payload.signature)
    pub fn record_token(&self, ip: IpAddr, jwt: &str) {
        self.auth_token_detector.record_jwt(ip, jwt);
    }

    /// Record a request for behavioral and timing analysis.
    ///
    /// Should be called for every request to build behavioral patterns
    /// and detect timing correlations. Updates multiple detectors:
    /// - Behavioral detector (weight: 30) - navigation patterns
    /// - Timing detector (weight: 25) - request synchronization
    /// - Network detector (weight: 15) - subnet correlation
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path
    pub fn record_request(&self, ip: IpAddr, method: &str, path: &str) {
        self.behavioral_detector.record_request(ip, method, path);
        self.timing_detector.record_request(ip);
        self.network_detector.register_ip(ip);
    }

    /// Record a request with full context for all applicable detectors.
    ///
    /// Convenience method that records data to multiple detectors at once.
    /// Call this during request processing to capture all correlation signals.
    ///
    /// # Arguments
    /// * `ip` - The IP address of the client
    /// * `method` - HTTP method
    /// * `path` - Request path
    /// * `ja4` - Optional JA4 TLS fingerprint
    /// * `jwt` - Optional JWT from Authorization header
    pub fn record_request_full(
        &self,
        ip: IpAddr,
        method: &str,
        path: &str,
        ja4: Option<&str>,
        jwt: Option<&str>,
    ) {
        // Record for behavioral/timing/network
        self.record_request(ip, method, path);

        let ip_id = GraphDetector::ip_id(&ip.to_string());

        // Record JA4 fingerprint
        if let Some(fp) = ja4 {
            if !fp.is_empty() {
                self.register_ja4(ip, fp.to_string());
                // Graph correlation: Link IP to Fingerprint
                self.record_relation(&ip_id, &GraphDetector::fp_id(fp));
            }
        }

        // Record JWT token
        if let Some(token) = jwt {
            if !token.is_empty() {
                self.record_token(ip, token);
                // Graph correlation: Link IP to Token (use hash or prefix for ID)
                // Using first 16 chars of token as ID to avoid sensitive data in graph keys
                let token_id = if token.len() > 16 {
                    &token[..16]
                } else {
                    token
                };
                self.record_relation(&ip_id, &GraphDetector::token_id(token_id));
            }
        }
    }

    /// Record a relationship for graph correlation.
    ///
    /// Records a connection between two entities (e.g., IP and Fingerprint)
    /// to build the correlation graph.
    ///
    /// # Arguments
    /// * `entity_a` - First entity ID (e.g., "ip:1.2.3.4")
    /// * `entity_b` - Second entity ID (e.g., "fp:abc12345")
    pub fn record_relation(&self, entity_a: &str, entity_b: &str) {
        self.graph_detector.record_relation(entity_a, entity_b);
    }

    // ========================================================================
    // Campaign Scoring
    // ========================================================================

    /// Calculate weighted campaign score from all correlation reasons.
    ///
    /// The score is computed as the weighted average of all correlation
    /// reasons, where each reason's contribution is:
    /// `weight * confidence / total_reasons`
    ///
    /// # Arguments
    /// * `campaign` - The campaign to score
    ///
    /// # Returns
    /// A score between 0.0 and 50.0 (max weight * max confidence)
    pub fn calculate_campaign_score(&self, campaign: &Campaign) -> f64 {
        if campaign.correlation_reasons.is_empty() {
            return 0.0;
        }

        let total_weighted: f64 = campaign
            .correlation_reasons
            .iter()
            .map(|r| r.correlation_type.weight() as f64 * r.confidence)
            .sum();

        total_weighted / campaign.correlation_reasons.len() as f64
    }

    /// Run all 7 detectors in parallel and process updates with weighted scoring.
    ///
    /// Called periodically by background worker or on-demand.
    /// Detectors run concurrently for improved performance (~70ms savings at scale):
    /// 1. Attack Sequence (50) - Same attack payloads
    /// 2. Auth Token (45) - Same JWT structure/issuer
    /// 3. HTTP Fingerprint (40) - Identical JA4H
    /// 4. TLS Fingerprint (35) - Same JA4
    /// 5. Behavioral Similarity (30) - Navigation patterns
    /// 6. Timing Correlation (25) - Synchronized requests
    /// 7. Network Proximity (15) - Same ASN/subnet
    ///
    /// # Returns
    /// Number of campaign updates processed.
    ///
    /// # Errors
    /// Returns an error if any detector fails critically.
    pub async fn run_detection_cycle(&self) -> DetectorResult<usize> {
        // Create futures for each detector using trait objects for dynamic dispatch
        // This allows heterogeneous detectors to be run in parallel via join_all
        let detectors: Vec<(&dyn Detector, &'static str)> = vec![
            (
                &self.attack_sequence_detector as &dyn Detector,
                "attack_sequence",
            ),
            (&self.auth_token_detector as &dyn Detector, "auth_token"),
            (
                &self.http_fingerprint_detector as &dyn Detector,
                "http_fingerprint",
            ),
            (
                &self.tls_fingerprint_detector as &dyn Detector,
                "tls_fingerprint",
            ),
            (&self.behavioral_detector as &dyn Detector, "behavioral"),
            (&self.timing_detector as &dyn Detector, "timing"),
            (&self.network_detector as &dyn Detector, "network"),
            (&self.graph_detector as &dyn Detector, "graph"),
        ];

        // Run all detectors in parallel using join_all
        // Each future wraps the synchronous analyze() call
        let detector_futures: Vec<_> = detectors
            .into_iter()
            .map(|(detector, name)| {
                let index = &self.index;
                // Wrap each detector in an async block
                async move {
                    let result = detector.analyze(index);
                    (name, result)
                }
            })
            .collect();

        let results = join_all(detector_futures).await;

        // Process all results and collect updates
        let mut total_updates = 0;
        let mut stats_updates: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();

        for (name, result) in results {
            match result {
                Ok(updates) => {
                    let update_count = updates.len();
                    for update in updates {
                        self.process_campaign_update(update).await;
                        total_updates += 1;
                    }
                    // Collect per-detector stats
                    if update_count > 0 {
                        *stats_updates.entry(name.to_string()).or_insert(0) += update_count as u64;
                    }
                }
                Err(e) => {
                    tracing::warn!("Detector {} failed: {}", name, e);
                }
            }
        }

        // Batch update stats (single lock acquisition)
        if !stats_updates.is_empty() {
            let mut stats = self.stats_detections_by_type.write().await;
            for (name, count) in stats_updates {
                *stats.entry(name).or_insert(0) += count;
            }
        }

        // Update global stats
        self.stats_detections_run.fetch_add(1, Ordering::Relaxed);
        {
            let mut last_scan = self.last_scan.write().await;
            *last_scan = Some(Instant::now());
        }

        Ok(total_updates)
    }

    /// Get fingerprint groups above threshold with caching.
    ///
    /// This method caches the results of `get_groups_above_threshold()` for 100ms
    /// to avoid repeated expensive O(n) scans during a single detection cycle.
    /// Multiple detectors can use the same cached result within the TTL window.
    ///
    /// # Arguments
    /// * `threshold` - Minimum number of IPs required for a group
    ///
    /// # Returns
    /// Vector of fingerprint groups above the threshold.
    pub async fn get_cached_groups(&self, threshold: usize) -> Vec<FingerprintGroup> {
        // Check cache first
        {
            let cache_guard = self.group_cache.read().await;
            if let Some(ref cache) = *cache_guard {
                if cache.is_valid(threshold) {
                    return cache.groups.clone();
                }
            }
        }

        // Cache miss or expired - compute fresh groups
        let groups = self.index.get_groups_above_threshold(threshold);

        // Update cache
        {
            let mut cache_guard = self.group_cache.write().await;
            *cache_guard = Some(GroupCache::new(groups.clone(), threshold));
        }

        groups
    }

    /// Invalidate the fingerprint groups cache.
    ///
    /// Called when significant changes occur that would affect group composition.
    pub async fn invalidate_group_cache(&self) {
        let mut cache_guard = self.group_cache.write().await;
        *cache_guard = None;
    }

    /// Process a campaign update from a detector.
    ///
    /// If the update contains a correlation reason with IPs, we try to:
    /// 1. Find existing campaign for any of those IPs
    /// 2. If found, update the existing campaign
    /// 3. If not found, create a new campaign
    async fn process_campaign_update(&self, update: CampaignUpdate) {
        // Extract IPs from correlation reason if present
        let ips: Vec<String> = update
            .add_correlation_reason
            .as_ref()
            .map(|reason| reason.evidence.clone())
            .unwrap_or_default();

        if ips.is_empty() {
            return;
        }

        // Check if any IP is already in a campaign
        let existing_campaign_id = ips.iter().find_map(|ip| self.store.get_campaign_for_ip(ip));

        // Use a variable to track if we need to check for mitigation
        let mut check_mitigation = false;
        let mut target_campaign_id = String::new();

        match existing_campaign_id {
            Some(campaign_id) => {
                // Update existing campaign
                let _ = self.store.update_campaign(&campaign_id, update);

                // Add any new IPs to the campaign
                for ip in &ips {
                    let _ = self.store.add_actor_to_campaign(&campaign_id, ip);
                }

                check_mitigation = true;
                target_campaign_id = campaign_id;
            }
            None => {
                // Create new campaign
                let confidence = update.confidence.unwrap_or(0.5);

                // Generate a unique ID, retrying if collision occurs (rare edge case)
                // ID collisions can happen if two campaigns are created in the same millisecond
                let mut campaign_id = Campaign::generate_id();
                let mut retry_count = 0;
                while self.store.get_campaign(&campaign_id).is_some() && retry_count < 10 {
                    // Add random suffix to handle collision
                    campaign_id = format!("{}-{:x}", Campaign::generate_id(), fastrand::u32(..));
                    retry_count += 1;
                }

                let mut campaign = Campaign::new(campaign_id.clone(), ips, confidence);

                // Apply update fields to new campaign
                if let Some(status) = update.status {
                    campaign.status = status;
                }
                if let Some(ref attack_types) = update.attack_types {
                    campaign.attack_types = attack_types.clone();
                }
                if let Some(reason) = update.add_correlation_reason {
                    campaign.correlation_reasons.push(reason);
                }
                if let Some(risk_score) = update.risk_score {
                    campaign.risk_score = risk_score;
                }

                // Store the campaign
                if self.store.create_campaign(campaign).is_ok() {
                    self.stats_campaigns_created.fetch_add(1, Ordering::Relaxed);
                    check_mitigation = true;
                    target_campaign_id = campaign_id;
                }
            }
        }

        // Check for automated mitigation if enabled
        if check_mitigation {
            if let Some(campaign) = self.store.get_campaign(&target_campaign_id) {
                // Auto-mitigation (Block)
                if self.config.auto_mitigation_enabled
                    && campaign.confidence >= self.config.auto_mitigation_threshold
                    && campaign.status != CampaignStatus::Resolved
                {
                    self.mitigate_campaign(&campaign).await;
                }

                // Cross-Tenant Reporting (Fleet Intelligence)
                // Report high-confidence campaigns (>= 0.8) to Signal Horizon
                if campaign.confidence >= 0.8 {
                    self.report_campaign(&campaign);
                }
            }
        }
    }

    /// Report a high-confidence campaign to Signal Horizon telemetry.
    fn report_campaign(&self, campaign: &Campaign) {
        if let Some(ref client) = self.telemetry_client {
            // Only report if client is enabled
            if !client.is_enabled() {
                return;
            }

            let event = TelemetryEvent::CampaignReport {
                campaign_id: campaign.id.clone(),
                confidence: campaign.confidence,
                attack_types: campaign
                    .attack_types
                    .iter()
                    .map(|at| format!("{:?}", at))
                    .collect(),
                actor_count: campaign.actor_count,
                correlation_reasons: campaign
                    .correlation_reasons
                    .iter()
                    .map(|r| r.description.clone())
                    .collect(),
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };

            // Fire and forget - runs in background
            let client = Arc::clone(client);
            tokio::spawn(async move {
                if let Err(e) = client.report(event).await {
                    tracing::debug!("Failed to report campaign telemetry: {}", e);
                }
            });
        }
    }

    /// Apply automated mitigation to a high-confidence campaign.
    ///
    /// Adds campaign actors to the deny list via AccessListManager.
    /// Implements rate limiting and batch blocking for safety.
    async fn mitigate_campaign(&self, campaign: &Campaign) {
        // Check if already mitigated
        if self.mitigated_campaigns.contains(&campaign.id) {
            tracing::debug!(campaign_id = %campaign.id, "Campaign already mitigated, skipping");
            return;
        }

        let access_list = match &self.access_list_manager {
            Some(al) => al,
            None => {
                tracing::debug!("No AccessListManager configured, skipping mitigation");
                return;
            }
        };

        // Collect IPs to block (limit per campaign)
        let max_ips = self.mitigation_rate_limiter.max_ips_per_campaign();
        let ips_to_block: Vec<IpAddr> = campaign
            .actors
            .iter()
            .filter_map(|ip_str| ip_str.parse::<IpAddr>().ok())
            .take(max_ips)
            .collect();

        if ips_to_block.is_empty() {
            tracing::debug!(campaign_id = %campaign.id, "No valid IPs to block");
            return;
        }

        // Rate limit check - acquire permits for all IPs
        let mut blocked_count = 0;
        let mut rate_limited = false;

        for ip in &ips_to_block {
            if let Err(reason) = self.mitigation_rate_limiter.try_ban().await {
                tracing::warn!(
                    campaign_id = %campaign.id,
                    reason = %reason,
                    blocked = blocked_count,
                    remaining = ips_to_block.len() - blocked_count,
                    "Mitigation rate limited"
                );
                rate_limited = true;
                break;
            }

            // Add deny rule
            let comment = format!(
                "Campaign {} (confidence: {:.2})",
                campaign.id, campaign.confidence
            );
            {
                let mut al = access_list.write();
                if let Err(e) = al.add_deny_ip(ip, Some(&comment)) {
                    tracing::error!(ip = %ip, error = %e, "Failed to add deny rule");
                    continue;
                }
            }
            blocked_count += 1;
        }

        // Log audit event
        let attack_types: Vec<String> = campaign
            .attack_types
            .iter()
            .map(|at| format!("{:?}", at))
            .collect();
        tracing::info!(
            campaign_id = %campaign.id,
            confidence = campaign.confidence,
            total_actors = campaign.actors.len(),
            blocked = blocked_count,
            rate_limited = rate_limited,
            attack_types = ?attack_types,
            "Auto-mitigation applied"
        );

        // Mark as mitigated
        self.mitigated_campaigns.insert(campaign.id.clone());

        // Report mitigation event to telemetry
        if let Some(ref client) = self.telemetry_client {
            if client.is_enabled() {
                let event = TelemetryEvent::CampaignReport {
                    campaign_id: format!("mitigation:{}", campaign.id),
                    confidence: campaign.confidence,
                    attack_types,
                    actor_count: blocked_count,
                    correlation_reasons: vec![format!(
                        "Auto-mitigation applied: {} IPs blocked",
                        blocked_count
                    )],
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };

                let client = Arc::clone(client);
                tokio::spawn(async move {
                    if let Err(e) = client.report(event).await {
                        tracing::debug!("Failed to report mitigation telemetry: {}", e);
                    }
                });
            }
        }
    }

    /// Check if an IP should trigger immediate detection.
    ///
    /// Used for event-driven detection on new requests. Checks all 7 detectors
    /// to see if any threshold has been reached that warrants immediate analysis.
    ///
    /// # Arguments
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    /// `true` if immediate detection should be triggered.
    pub fn should_trigger_detection(&self, ip: &IpAddr) -> bool {
        // Check detectors in order of weight (short-circuit on first match)
        self.attack_sequence_detector
            .should_trigger(ip, &self.index)
            || self.auth_token_detector.should_trigger(ip, &self.index)
            || self
                .http_fingerprint_detector
                .should_trigger(ip, &self.index)
            || self
                .tls_fingerprint_detector
                .should_trigger(ip, &self.index)
            || self.behavioral_detector.should_trigger(ip, &self.index)
            || self.timing_detector.should_trigger(ip, &self.index)
            || self.network_detector.should_trigger(ip, &self.index)
            || self.graph_detector.should_trigger(ip, &self.index)
    }

    /// Get all active campaigns for API response.
    ///
    /// Returns campaigns with Detected or Active status.
    pub fn get_campaigns(&self) -> Vec<Campaign> {
        self.store.list_active_campaigns()
    }

    /// Get all campaigns (including resolved/dormant).
    pub fn get_all_campaigns(&self) -> Vec<Campaign> {
        self.store.list_campaigns(None)
    }

    /// Create a snapshot of all campaigns for persistence.
    ///
    /// Returns all campaigns regardless of status.
    pub fn snapshot(&self) -> Vec<Campaign> {
        self.store.list_campaigns(None)
    }

    /// Restore campaigns from a snapshot.
    ///
    /// Clears existing state and loads the provided campaigns.
    pub fn restore(&self, campaigns: Vec<Campaign>) {
        // Clear existing state
        self.store.clear();
        self.index.clear();

        // Restore campaigns
        for campaign in campaigns {
            // Re-add IP mappings
            for ip_str in &campaign.actors {
                // Update fingerprint index with a placeholder to re-establish the IP entry
                self.index.update_entity(ip_str, None, None);
            }

            // Create the campaign in the store
            let _ = self.store.create_campaign(campaign);
        }
    }

    /// Get a specific campaign by ID.
    ///
    /// # Arguments
    /// * `id` - The campaign ID to retrieve
    ///
    /// # Returns
    /// The campaign if found, None otherwise.
    pub fn get_campaign(&self, id: &str) -> Option<Campaign> {
        self.store.get_campaign(id)
    }

    /// Get IPs that are members of a campaign.
    ///
    /// # Arguments
    /// * `campaign_id` - The campaign ID to query
    ///
    /// # Returns
    /// Vector of IP addresses in the campaign.
    pub fn get_campaign_actors(&self, campaign_id: &str) -> Vec<IpAddr> {
        self.store
            .get_campaign(campaign_id)
            .map(|campaign| {
                campaign
                    .actors
                    .iter()
                    .filter_map(|ip_str| ip_str.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the correlation graph for a campaign.
    pub fn get_campaign_graph(&self, campaign_id: &str) -> serde_json::Value {
        let ips = self.get_campaign_actors(campaign_id);
        let ips_str: Vec<String> = ips.into_iter().map(|ip| ip.to_string()).collect();

        self.graph_detector.get_cytoscape_data(&ips_str)
    }

    /// Get the correlation graph for a campaign with pagination and identifier hashing.
    /// P1 fix: Supports pagination to prevent memory exhaustion and hashes identifiers
    /// to prevent information disclosure.
    pub fn get_campaign_graph_paginated(
        &self,
        campaign_id: &str,
        limit: Option<usize>,
        offset: Option<usize>,
        hash_identifiers: bool,
    ) -> crate::correlation::detectors::graph::PaginatedGraph {
        use crate::correlation::detectors::graph::GraphExportOptions;

        let ips = self.get_campaign_actors(campaign_id);
        let ips_str: Vec<String> = ips.into_iter().map(|ip| ip.to_string()).collect();

        let options = GraphExportOptions {
            limit,
            offset,
            hash_identifiers,
        };

        self.graph_detector
            .get_cytoscape_data_paginated(&ips_str, options)
    }

    /// Get current statistics.
    ///
    /// Returns a snapshot of manager statistics including index and store stats.
    pub fn stats(&self) -> ManagerStats {
        let last_scan = {
            // Use try_read to avoid blocking; if locked, use None
            self.last_scan
                .try_read()
                .map(|guard| *guard)
                .unwrap_or(None)
        };

        let detections_by_type = self
            .stats_detections_by_type
            .try_read()
            .map(|guard| guard.clone())
            .unwrap_or_default();

        ManagerStats {
            fingerprints_registered: self.stats_fingerprints_registered.load(Ordering::Relaxed),
            detections_run: self.stats_detections_run.load(Ordering::Relaxed),
            campaigns_created: self.stats_campaigns_created.load(Ordering::Relaxed),
            last_scan,
            index_stats: self.index.stats(),
            campaign_stats: self.store.stats(),
            detections_by_type,
        }
    }

    /// Start background detection worker.
    ///
    /// Returns a handle that can be used to await worker completion.
    /// The worker runs detection cycles at the configured interval until
    /// the manager is dropped or shutdown is signaled.
    ///
    /// # Returns
    /// JoinHandle for the background task.
    pub fn start_background_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = self;
        let scan_interval = manager.config.scan_interval;

        tokio::spawn(async move {
            let mut ticker = interval(scan_interval);

            loop {
                ticker.tick().await;

                // Check for shutdown signal
                if manager.shutdown.load(Ordering::Relaxed) {
                    log::info!("Campaign manager background worker shutting down");
                    break;
                }

                // Run detection cycle
                match manager.run_detection_cycle().await {
                    Ok(updates) => {
                        if updates > 0 {
                            log::debug!("Detection cycle processed {} updates", updates);
                        }
                    }
                    Err(e) => {
                        log::warn!("Detection cycle error: {}", e);
                    }
                }
            }
        })
    }

    /// Signal the background worker to shut down.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check if shutdown has been signaled.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Remove an IP from tracking (called when entity is evicted).
    ///
    /// Cleans up the IP from:
    /// - Fingerprint index
    /// - Any associated campaigns
    ///
    /// # Arguments
    /// * `ip` - The IP address to remove
    pub fn remove_ip(&self, ip: &IpAddr) {
        let ip_str = ip.to_string();

        // Remove from fingerprint index
        self.index.remove_entity(&ip_str);

        // Remove from any campaign
        if let Some(campaign_id) = self.store.get_campaign_for_ip(&ip_str) {
            let _ = self.store.remove_actor_from_campaign(&campaign_id, &ip_str);
        }
    }

    /// Get the fingerprint index (for integration with EntityManager).
    ///
    /// Allows direct access to the index for advanced use cases.
    pub fn index(&self) -> &Arc<FingerprintIndex> {
        &self.index
    }

    /// Get the campaign store (for integration).
    ///
    /// Allows direct access to the store for advanced use cases.
    pub fn store(&self) -> &Arc<CampaignStore> {
        &self.store
    }

    /// Get the current configuration.
    pub fn config(&self) -> &ManagerConfig {
        &self.config
    }

    /// Resolve a campaign.
    ///
    /// # Arguments
    /// * `campaign_id` - The campaign ID to resolve
    /// * `reason` - The reason for resolution
    ///
    /// # Returns
    /// Ok(()) if successful, Err if campaign not found or already resolved.
    pub fn resolve_campaign(&self, campaign_id: &str, reason: &str) -> Result<(), DetectorError> {
        self.store
            .resolve_campaign(campaign_id, reason)
            .map_err(|e| DetectorError::DetectionFailed(e.to_string()))
    }

    /// Clear all state (primarily for testing).
    ///
    /// Clears fingerprint index, campaign store, and detector state.
    pub fn clear(&self) {
        self.index.clear();
        self.store.clear();
        self.http_fingerprint_detector.clear_processed();
        self.tls_fingerprint_detector.cleanup_old_observations();
    }
}

impl Default for CampaignManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_test_manager() -> CampaignManager {
        let config = ManagerConfig {
            shared_threshold: 3,
            rotation_threshold: 3,
            rotation_window: Duration::from_secs(60),
            scan_interval: Duration::from_millis(100),
            background_scanning: false,
            ..Default::default()
        };
        CampaignManager::with_config(config)
    }

    fn create_test_ip(last_octet: u8) -> IpAddr {
        format!("192.168.1.{}", last_octet).parse().unwrap()
    }

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_config_default() {
        let config = ManagerConfig::default();

        assert_eq!(config.shared_threshold, 3);
        assert_eq!(config.rotation_threshold, 3);
        assert_eq!(config.rotation_window, Duration::from_secs(60));
        assert_eq!(config.scan_interval, Duration::from_secs(5));
        assert!(config.background_scanning);
        assert!(config.track_combined);
        assert!((config.shared_confidence - 0.85).abs() < 0.001);
    }

    #[test]
    fn test_config_builder() {
        let config = ManagerConfig::new()
            .with_shared_threshold(5)
            .with_rotation_threshold(4)
            .with_rotation_window(Duration::from_secs(120))
            .with_scan_interval(Duration::from_secs(10))
            .with_background_scanning(false)
            .with_track_combined(false)
            .with_shared_confidence(0.9);

        assert_eq!(config.shared_threshold, 5);
        assert_eq!(config.rotation_threshold, 4);
        assert_eq!(config.rotation_window, Duration::from_secs(120));
        assert_eq!(config.scan_interval, Duration::from_secs(10));
        assert!(!config.background_scanning);
        assert!(!config.track_combined);
        assert!((config.shared_confidence - 0.9).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_mitigation_rate_limiter_limits() {
        let limiter = MitigationRateLimiter::new(2, Duration::from_secs(60), 10);

        assert!(limiter.try_ban().await.is_ok());
        assert!(limiter.try_ban().await.is_ok());
        assert!(limiter.try_ban().await.is_err());
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        let config = ManagerConfig::default();
        assert!(config.validate().is_ok());

        // Invalid shared_threshold
        let config = ManagerConfig::new().with_shared_threshold(1);
        assert!(config.validate().is_err());

        // Invalid rotation_threshold
        let config = ManagerConfig::new().with_rotation_threshold(1);
        assert!(config.validate().is_err());

        // Invalid rotation_window
        let config = ManagerConfig {
            rotation_window: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Invalid scan_interval
        let config = ManagerConfig {
            scan_interval: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Auto-mitigation with threshold too low (security risk)
        let config = ManagerConfig {
            auto_mitigation_enabled: true,
            auto_mitigation_threshold: 0.5, // Below 0.7 minimum
            ..Default::default()
        };
        assert!(config.validate().is_err());

        // Auto-mitigation with valid threshold
        let config = ManagerConfig {
            auto_mitigation_enabled: true,
            auto_mitigation_threshold: 0.9,
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        // Auto-mitigation disabled ignores threshold
        let config = ManagerConfig {
            auto_mitigation_enabled: false,
            auto_mitigation_threshold: 0.5, // Would be invalid if enabled
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_confidence_clamping() {
        let config = ManagerConfig::new().with_shared_confidence(1.5);
        assert!((config.shared_confidence - 1.0).abs() < 0.001);

        let config = ManagerConfig::new().with_shared_confidence(-0.5);
        assert!(config.shared_confidence >= 0.0);
    }

    // ========================================================================
    // Registration Flow Tests
    // ========================================================================

    #[test]
    fn test_register_ja4() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.register_ja4(ip, "t13d1516h2_abc123".to_string());

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 1);
        assert_eq!(stats.index_stats.total_ips, 1);
        assert_eq!(stats.index_stats.ja4_fingerprints, 1);
    }

    #[test]
    fn test_register_ja4_empty_skipped() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.register_ja4(ip, "".to_string());

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 0);
        assert_eq!(stats.index_stats.total_ips, 0);
    }

    #[test]
    fn test_register_combined() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.register_combined(ip, "combined_hash_xyz".to_string());

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 1);
        assert_eq!(stats.index_stats.total_ips, 1);
        assert_eq!(stats.index_stats.combined_fingerprints, 1);
    }

    #[test]
    fn test_register_fingerprints_both() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.register_fingerprints(
            ip,
            Some(Arc::from("ja4_test")),
            Some(Arc::from("ja4h_test")),
        );

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 1);
        assert_eq!(stats.index_stats.ja4_fingerprints, 1);
        assert_eq!(stats.index_stats.combined_fingerprints, 1);
    }

    #[test]
    fn test_register_fingerprints_ja4_only() {
        let manager = create_test_manager();
        let ip = create_test_ip(1);

        manager.register_fingerprints(ip, Some(Arc::from("ja4_only")), None);

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 1);
        assert_eq!(stats.index_stats.ja4_fingerprints, 1);
        assert_eq!(stats.index_stats.combined_fingerprints, 0);
    }

    // ========================================================================
    // Detection Cycle Tests
    // ========================================================================

    #[tokio::test]
    async fn test_detection_cycle_empty() {
        let manager = create_test_manager();

        let updates = manager.run_detection_cycle().await.unwrap();

        assert_eq!(updates, 0);
        assert_eq!(manager.stats().detections_run, 1);
    }

    #[tokio::test]
    async fn test_detection_cycle_creates_campaign() {
        let manager = create_test_manager();

        // Register 3 IPs with same fingerprint (threshold)
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "shared_fingerprint".to_string());
        }

        let updates = manager.run_detection_cycle().await.unwrap();

        assert!(updates >= 1);
        assert_eq!(manager.stats().campaigns_created, 1);

        let campaigns = manager.get_campaigns();
        assert_eq!(campaigns.len(), 1);
    }

    #[tokio::test]
    async fn test_detection_cycle_no_duplicate_campaigns() {
        let manager = create_test_manager();

        // Register 3 IPs with same fingerprint
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "shared_fp".to_string());
        }

        // First detection cycle
        manager.run_detection_cycle().await.unwrap();
        let first_count = manager.stats().campaigns_created;

        // Second detection cycle - should not create duplicate
        manager.run_detection_cycle().await.unwrap();
        let second_count = manager.stats().campaigns_created;

        assert_eq!(first_count, second_count);
    }

    // ========================================================================
    // Campaign Retrieval Tests
    // ========================================================================

    #[tokio::test]
    async fn test_get_campaigns() {
        let manager = create_test_manager();

        // Create a campaign
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "test_fp".to_string());
        }
        manager.run_detection_cycle().await.unwrap();

        let campaigns = manager.get_campaigns();
        assert!(!campaigns.is_empty());

        // Verify campaign has the expected actors
        let campaign = &campaigns[0];
        assert_eq!(campaign.actor_count, 3);
    }

    #[tokio::test]
    async fn test_get_campaign_by_id() {
        let manager = create_test_manager();

        // Create a campaign
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "get_by_id_fp".to_string());
        }
        manager.run_detection_cycle().await.unwrap();

        let campaigns = manager.get_campaigns();
        let campaign_id = &campaigns[0].id;

        let retrieved = manager.get_campaign(campaign_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, *campaign_id);

        // Non-existent ID
        let not_found = manager.get_campaign("nonexistent");
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_get_campaign_actors() {
        let manager = create_test_manager();

        // Create a campaign
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "actors_fp".to_string());
        }
        manager.run_detection_cycle().await.unwrap();

        let campaigns = manager.get_campaigns();
        let campaign_id = &campaigns[0].id;

        let actors = manager.get_campaign_actors(campaign_id);
        assert_eq!(actors.len(), 3);

        // Non-existent campaign
        let no_actors = manager.get_campaign_actors("nonexistent");
        assert!(no_actors.is_empty());
    }

    // ========================================================================
    // Stats Tracking Tests
    // ========================================================================

    #[tokio::test]
    async fn test_stats_tracking() {
        let manager = create_test_manager();

        // Initial stats
        let initial = manager.stats();
        assert_eq!(initial.fingerprints_registered, 0);
        assert_eq!(initial.detections_run, 0);
        assert_eq!(initial.campaigns_created, 0);
        assert!(initial.last_scan.is_none());

        // Register some fingerprints
        for i in 1..=5 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "stats_test_fp".to_string());
        }

        let after_register = manager.stats();
        assert_eq!(after_register.fingerprints_registered, 5);
        assert_eq!(after_register.index_stats.total_ips, 5);

        // Run detection
        manager.run_detection_cycle().await.unwrap();

        let after_detect = manager.stats();
        assert_eq!(after_detect.detections_run, 1);
        assert!(after_detect.last_scan.is_some());
        assert!(after_detect.campaigns_created >= 1);
    }

    // ========================================================================
    // Remove IP Cleanup Tests
    // ========================================================================

    #[tokio::test]
    async fn test_remove_ip_cleanup() {
        let manager = create_test_manager();

        // Create a campaign
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "remove_test_fp".to_string());
        }
        manager.run_detection_cycle().await.unwrap();

        // Verify campaign exists
        let campaigns = manager.get_campaigns();
        assert_eq!(campaigns[0].actor_count, 3);

        // Remove one IP
        let ip_to_remove = create_test_ip(1);
        manager.remove_ip(&ip_to_remove);

        // Verify IP was removed from index
        assert_eq!(manager.index.len(), 2);

        // Verify IP was removed from campaign
        let updated_campaigns = manager.get_campaigns();
        assert_eq!(updated_campaigns[0].actor_count, 2);
    }

    // ========================================================================
    // Concurrent Registration Tests
    // ========================================================================

    #[test]
    fn test_concurrent_registration() {
        let manager = Arc::new(create_test_manager());
        let mut handles = vec![];

        // Spawn multiple threads registering fingerprints
        for thread_id in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let ip: IpAddr = format!("10.{}.0.{}", thread_id, i % 256).parse().unwrap();
                    manager.register_ja4(ip, format!("fp_t{}_{}", thread_id, i % 5));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify no panics and reasonable state
        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 1000);
        assert!(stats.index_stats.total_ips > 0);
    }

    // ========================================================================
    // Trigger Detection Logic Tests
    // ========================================================================

    #[test]
    fn test_should_trigger_detection_below_threshold() {
        let manager = create_test_manager();

        // Register only 2 IPs (below threshold of 3)
        for i in 1..=2 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "trigger_test_fp".to_string());
        }

        let ip = create_test_ip(1);
        assert!(!manager.should_trigger_detection(&ip));
    }

    #[test]
    fn test_should_trigger_detection_at_threshold() {
        let manager = create_test_manager();

        // Register 3 IPs (at threshold)
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "trigger_threshold_fp".to_string());
        }

        let ip = create_test_ip(1);
        assert!(manager.should_trigger_detection(&ip));
    }

    // ========================================================================
    // Background Worker Lifecycle Tests
    // ========================================================================

    #[tokio::test]
    async fn test_background_worker_lifecycle() {
        let config = ManagerConfig {
            scan_interval: Duration::from_millis(50),
            background_scanning: true,
            shared_threshold: 3,
            ..Default::default()
        };
        let manager = Arc::new(CampaignManager::with_config(config));

        // Register some fingerprints
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "worker_test_fp".to_string());
        }

        // Start worker
        let worker = Arc::clone(&manager).start_background_worker();

        // Wait for a few cycles
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify detection ran
        let stats = manager.stats();
        assert!(stats.detections_run >= 1);

        // Signal shutdown
        manager.shutdown();

        // Worker should complete
        let timeout = tokio::time::timeout(Duration::from_millis(500), worker).await;
        assert!(timeout.is_ok(), "Worker should shut down gracefully");
    }

    #[tokio::test]
    async fn test_shutdown_flag() {
        let manager = CampaignManager::new();

        assert!(!manager.is_shutdown());

        manager.shutdown();

        assert!(manager.is_shutdown());
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[tokio::test]
    async fn test_full_flow() {
        let manager = create_test_manager();

        // Phase 1: Register fingerprints from multiple IPs
        let fingerprint = "t13d1516h2_full_flow_test";
        for i in 1..=5 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, fingerprint.to_string());
        }

        // Phase 2: Run detection
        let updates = manager.run_detection_cycle().await.unwrap();
        assert!(updates >= 1);

        // Phase 3: Verify campaign was created
        let campaigns = manager.get_campaigns();
        assert_eq!(campaigns.len(), 1);

        let campaign = &campaigns[0];
        assert_eq!(campaign.actor_count, 5);
        assert!(campaign.confidence >= 0.8);
        assert!(!campaign.correlation_reasons.is_empty());

        // Phase 4: Get campaign by ID
        let retrieved = manager.get_campaign(&campaign.id).unwrap();
        assert_eq!(retrieved.actors.len(), 5);

        // Phase 5: Get actors
        let actors = manager.get_campaign_actors(&campaign.id);
        assert_eq!(actors.len(), 5);

        // Phase 6: Remove an IP
        manager.remove_ip(&create_test_ip(1));
        let updated = manager.get_campaign(&campaign.id).unwrap();
        assert_eq!(updated.actors.len(), 4);

        // Phase 7: Verify stats
        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 5);
        assert_eq!(stats.campaigns_created, 1);
        assert_eq!(stats.campaign_stats.total_campaigns, 1);
    }

    #[test]
    fn test_clear() {
        let manager = create_test_manager();

        // Add some data
        for i in 1..=5 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "clear_test_fp".to_string());
        }

        assert_eq!(manager.index.len(), 5);

        // Clear
        manager.clear();

        assert_eq!(manager.index.len(), 0);
        assert!(manager.store.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_campaign() {
        let manager = create_test_manager();

        // Create a campaign
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "resolve_test_fp".to_string());
        }
        manager.run_detection_cycle().await.unwrap();

        let campaigns = manager.get_campaigns();
        let campaign_id = campaigns[0].id.clone();

        // Resolve the campaign
        let result = manager.resolve_campaign(&campaign_id, "Threat mitigated");
        assert!(result.is_ok());

        // Verify campaign is resolved
        let resolved = manager.get_campaign(&campaign_id).unwrap();
        assert_eq!(resolved.status, CampaignStatus::Resolved);

        // Active campaigns should now be empty
        let active = manager.get_campaigns();
        assert!(active.is_empty());
    }

    #[test]
    fn test_index_and_store_access() {
        let manager = create_test_manager();

        // Verify we can access internal components
        let _index = manager.index();
        let _store = manager.store();
        let _config = manager.config();

        // These should not panic
        assert!(manager.index().is_empty());
        assert!(manager.store().is_empty());
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_ipv6_addresses() {
        let manager = create_test_manager();

        let ipv6_1: IpAddr = "2001:db8::1".parse().unwrap();
        let ipv6_2: IpAddr = "2001:db8::2".parse().unwrap();
        let ipv6_3: IpAddr = "2001:db8::3".parse().unwrap();

        manager.register_ja4(ipv6_1, "ipv6_fp".to_string());
        manager.register_ja4(ipv6_2, "ipv6_fp".to_string());
        manager.register_ja4(ipv6_3, "ipv6_fp".to_string());

        let stats = manager.stats();
        assert_eq!(stats.fingerprints_registered, 3);
        assert_eq!(stats.index_stats.total_ips, 3);
    }

    #[test]
    fn test_default_trait() {
        let manager = CampaignManager::default();

        assert!(manager.index.is_empty());
        assert!(manager.store.is_empty());
        assert!(!manager.is_shutdown());
    }

    #[tokio::test]
    async fn test_multiple_fingerprint_groups() {
        let manager = create_test_manager();

        // Group 1: 3 IPs with fingerprint A
        for i in 1..=3 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "group_a_fp".to_string());
        }

        // Group 2: 4 IPs with fingerprint B
        for i in 10..=13 {
            let ip = create_test_ip(i);
            manager.register_ja4(ip, "group_b_fp".to_string());
        }

        manager.run_detection_cycle().await.unwrap();

        let campaigns = manager.get_campaigns();
        assert_eq!(campaigns.len(), 2);

        // Verify both groups created campaigns
        let actor_counts: Vec<usize> = campaigns.iter().map(|c| c.actor_count).collect();
        assert!(actor_counts.contains(&3));
        assert!(actor_counts.contains(&4));
    }
}
