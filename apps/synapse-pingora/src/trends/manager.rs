//! TrendsManager - Coordinator for fingerprint trends and anomaly detection.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use super::anomaly_detector::AnomalyDetector;
use super::config::TrendsConfig;
use super::correlation::{Correlation, CorrelationEngine, CorrelationQueryOptions};
use super::signal_extractor::SignalExtractor;
use super::time_store::{TimeStore, TimeStoreStats};
use super::types::{
    Anomaly, AnomalyMetadata, AnomalyQueryOptions, AnomalySeverity, AnomalyType, Signal,
    SignalCategory, SignalTrend, TrendQueryOptions, TrendsSummary,
};
use crate::geo::{GeoLocation, ImpossibleTravelDetector, LoginEvent, TravelConfig};

/// Stable reason tags passed to external risk callbacks.
///
/// The current tags intentionally preserve the existing callback strings so
/// EntityManager logs and downstream consumers do not see a silent format
/// change while we remove the stringly-typed callback API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrendsReason {
    Anomaly(AnomalyType),
}

impl TrendsReason {
    pub const fn as_tag(self) -> &'static str {
        match self {
            TrendsReason::Anomaly(AnomalyType::FingerprintChange) => {
                "trends_anomaly:Anomaly: fingerprint_change"
            }
            TrendsReason::Anomaly(AnomalyType::SessionSharing) => {
                "trends_anomaly:Anomaly: session_sharing"
            }
            TrendsReason::Anomaly(AnomalyType::VelocitySpike) => {
                "trends_anomaly:Anomaly: velocity_spike"
            }
            TrendsReason::Anomaly(AnomalyType::ImpossibleTravel) => {
                "trends_anomaly:Anomaly: impossible_travel"
            }
            TrendsReason::Anomaly(AnomalyType::TokenReuse) => "trends_anomaly:Anomaly: token_reuse",
            TrendsReason::Anomaly(AnomalyType::RotationPattern) => {
                "trends_anomaly:Anomaly: rotation_pattern"
            }
            TrendsReason::Anomaly(AnomalyType::TimingAnomaly) => {
                "trends_anomaly:Anomaly: timing_anomaly"
            }
            TrendsReason::Anomaly(AnomalyType::Ja4RotationPattern) => {
                "trends_anomaly:Anomaly: ja4_rotation_pattern"
            }
            TrendsReason::Anomaly(AnomalyType::Ja4IpCluster) => {
                "trends_anomaly:Anomaly: ja4_ip_cluster"
            }
            TrendsReason::Anomaly(AnomalyType::Ja4BrowserSpoofing) => {
                "trends_anomaly:Anomaly: ja4_browser_spoofing"
            }
            TrendsReason::Anomaly(AnomalyType::Ja4hChange) => "trends_anomaly:Anomaly: ja4h_change",
            TrendsReason::Anomaly(AnomalyType::OversizedRequest) => {
                "trends_anomaly:Anomaly: oversized_request"
            }
            TrendsReason::Anomaly(AnomalyType::OversizedResponse) => {
                "trends_anomaly:Anomaly: oversized_response"
            }
            TrendsReason::Anomaly(AnomalyType::BandwidthSpike) => {
                "trends_anomaly:Anomaly: bandwidth_spike"
            }
            TrendsReason::Anomaly(AnomalyType::ExfiltrationPattern) => {
                "trends_anomaly:Anomaly: exfiltration_pattern"
            }
            TrendsReason::Anomaly(AnomalyType::UploadPattern) => {
                "trends_anomaly:Anomaly: upload_pattern"
            }
        }
    }
}

/// Callback to apply risk: (entity_id, risk_score, reason)
type RiskCallback = Box<dyn Fn(&str, u32, TrendsReason) + Send + Sync>;

/// Dependencies for the trends manager.
#[derive(Default)]
pub struct TrendsManagerDependencies {
    /// Callback to apply risk to an entity
    pub apply_risk: Option<RiskCallback>,
}

/// High-level trends manager.
pub struct TrendsManager {
    config: TrendsConfig,
    store: RwLock<TimeStore>,
    anomaly_detector: AnomalyDetector,
    correlation_engine: CorrelationEngine,
    anomalies: DashMap<String, Anomaly>,
    recent_signals: DashMap<String, Vec<Signal>>,
    dependencies: TrendsManagerDependencies,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// Impossible travel detector for geographic anomaly detection.
    impossible_travel: RwLock<ImpossibleTravelDetector>,
}

impl TrendsManager {
    /// Create a new trends manager.
    pub fn new(config: TrendsConfig) -> Self {
        let store = TimeStore::new(&config);
        let anomaly_detector = AnomalyDetector::new(config.anomaly_risk.clone());
        let correlation_engine = CorrelationEngine::new();
        let impossible_travel = ImpossibleTravelDetector::new(TravelConfig::default());

        Self {
            config,
            store: RwLock::new(store),
            anomaly_detector,
            correlation_engine,
            anomalies: DashMap::new(),
            recent_signals: DashMap::new(),
            dependencies: TrendsManagerDependencies::default(),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            impossible_travel: RwLock::new(impossible_travel),
        }
    }

    /// Create with dependencies.
    pub fn with_dependencies(
        config: TrendsConfig,
        dependencies: TrendsManagerDependencies,
    ) -> Self {
        let mut manager = Self::new(config);
        manager.dependencies = dependencies;
        manager
    }

    /// Start background anomaly detection.
    ///
    /// # STUB — TASK-66
    ///
    /// This function is currently a stub: the spawned task ticks on an
    /// interval but performs no actual detection work. Real-time
    /// detection via [`Self::record_request`] and
    /// [`Self::record_payload_anomaly`] still fires `handle_anomaly`
    /// (and the `apply_risk` callback) synchronously — that path is
    /// live. What is missing is cross-signal batch analysis over the
    /// TimeStore history (velocity spikes, session sharing, impossible
    /// travel correlated across users, etc.).
    ///
    /// The function is currently NOT invoked from `main.rs` startup,
    /// so calling it from production code is a no-op that only emits a
    /// `warn!` line at boot. Batch detection implementation is tracked
    /// as a follow-up task; until it lands, do not add new callers that
    /// assume this loop performs work.
    pub fn start_background_detection(&self) -> tokio::task::JoinHandle<()> {
        let shutdown = Arc::clone(&self.shutdown);
        let interval_ms = self.config.anomaly_check_interval_ms;

        tracing::warn!(
            interval_ms,
            "TrendsManager::start_background_detection is a STUB (TASK-66): \
             real-time detection via record_request is live, but cross-signal \
             batch detection is not yet implemented. See follow-up task."
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));

            loop {
                interval.tick().await;

                if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }

                // STUB — TASK-66: batch detection would run here.
            }
        })
    }

    // --------------------------------------------------------------------------
    // Signal Recording
    // --------------------------------------------------------------------------

    /// Extract and record signals from request context.
    pub fn record_request(
        &self,
        entity_id: &str,
        session_id: Option<&str>,
        user_agent: Option<&str>,
        authorization: Option<&str>,
        client_ip: Option<&str>,
        ja4: Option<&str>,
        ja4h: Option<&str>,
        last_request_time: Option<i64>,
    ) -> Vec<Signal> {
        if !self.config.enabled {
            return Vec::new();
        }

        let signals = SignalExtractor::extract(
            entity_id,
            session_id,
            user_agent,
            authorization,
            client_ip,
            ja4,
            ja4h,
            last_request_time,
        );

        for signal in &signals {
            self.record_signal(signal.clone());
        }

        signals
    }

    /// Record a single signal.
    pub fn record_signal(&self, signal: Signal) {
        if !self.config.enabled {
            return;
        }

        let entity_id = signal.entity_id.clone();

        // Store in time-series
        {
            let mut store = self.store.write();
            store.record(signal.clone());
        }

        // Track recent signals for real-time anomaly detection
        self.track_recent_signal(&entity_id, signal.clone());

        // Real-time anomaly check
        let recent = self.get_recent_signals(&entity_id);
        if let Some(anomaly) = self.anomaly_detector.check_signal(&signal, &recent) {
            self.handle_anomaly(anomaly);
        }
    }

    /// Record a payload anomaly.
    pub fn record_payload_anomaly(
        &self,
        id: String,
        anomaly_type: AnomalyType,
        severity: AnomalySeverity,
        detected_at: i64,
        template: String,
        entity_id: String,
        description: String,
        metadata: super::types::AnomalyMetadata,
    ) {
        if !self.config.enabled {
            return;
        }

        let mut full_metadata = metadata;
        full_metadata.template = Some(template);
        full_metadata.source = Some("payload_profiler".to_string());

        let anomaly = Anomaly {
            id,
            detected_at,
            category: super::types::SignalCategory::Behavioral,
            anomaly_type,
            severity,
            description,
            signals: Vec::new(),
            entities: vec![entity_id],
            metadata: full_metadata,
            risk_applied: self.config.anomaly_risk.get(&anomaly_type).copied(),
        };

        self.handle_anomaly(anomaly);
    }

    // --------------------------------------------------------------------------
    // Impossible Travel Detection
    // --------------------------------------------------------------------------

    /// Record a login event for impossible travel detection.
    ///
    /// Checks if the user's login pattern indicates geographically impossible travel
    /// (e.g., logging in from NYC then London within 10 minutes).
    ///
    /// # Arguments
    ///
    /// * `user_id` - User identifier (session subject, user ID, or email)
    /// * `timestamp_ms` - Unix timestamp in milliseconds
    /// * `ip` - IP address of the login
    /// * `latitude` - Latitude from GeoIP lookup
    /// * `longitude` - Longitude from GeoIP lookup
    /// * `country` - Country name
    /// * `country_code` - ISO country code
    /// * `city` - Optional city name
    /// * `accuracy_km` - GeoIP accuracy radius in km
    /// * `device_fingerprint` - Optional device fingerprint for correlation
    ///
    /// # Returns
    ///
    /// `true` if an impossible travel alert was generated.
    #[allow(clippy::too_many_arguments)]
    pub fn record_login(
        &self,
        user_id: &str,
        timestamp_ms: u64,
        ip: &str,
        latitude: f64,
        longitude: f64,
        country: &str,
        country_code: &str,
        city: Option<&str>,
        accuracy_km: u32,
        device_fingerprint: Option<&str>,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }

        let location = GeoLocation {
            ip: ip.to_string(),
            latitude,
            longitude,
            city: city.map(String::from),
            country: country.to_string(),
            country_code: country_code.to_string(),
            accuracy_radius_km: accuracy_km,
        };

        let mut event = LoginEvent::new(user_id, timestamp_ms, location);
        if let Some(fp) = device_fingerprint {
            event = event.with_fingerprint(fp);
        }

        let alert = {
            let mut detector = self.impossible_travel.write();
            detector.check_login(&event)
        };

        if let Some(alert) = alert {
            let severity = match alert.severity {
                crate::geo::Severity::Low => AnomalySeverity::Low,
                crate::geo::Severity::Medium => AnomalySeverity::Medium,
                crate::geo::Severity::High => AnomalySeverity::High,
                crate::geo::Severity::Critical => AnomalySeverity::Critical,
            };

            let anomaly = Anomaly {
                id: uuid::Uuid::new_v4().to_string(),
                detected_at: chrono::Utc::now().timestamp_millis(),
                category: SignalCategory::Network, // Geographic anomalies are network-related
                anomaly_type: AnomalyType::ImpossibleTravel,
                severity,
                description: format!(
                    "Impossible travel detected for {}: {} km in {:.2} hours ({:.0} km/h required)",
                    alert.user_id,
                    alert.distance_km as u64,
                    alert.time_diff_hours,
                    if alert.required_speed_kmh < 0.0 {
                        f64::INFINITY
                    } else {
                        alert.required_speed_kmh
                    }
                ),
                signals: Vec::new(),
                entities: vec![ip.to_string()],
                metadata: AnomalyMetadata {
                    previous_value: Some(alert.from_location.ip.clone()),
                    new_value: Some(alert.to_location.ip.clone()),
                    time_delta_ms: Some((alert.to_time - alert.from_time) as i64),
                    time_delta_minutes: Some(alert.time_diff_hours * 60.0),
                    threshold: Some(1000.0), // max speed threshold
                    actual: Some(alert.required_speed_kmh),
                    detection_method: Some("impossible_travel".to_string()),
                    ..Default::default()
                },
                risk_applied: self
                    .config
                    .anomaly_risk
                    .get(&AnomalyType::ImpossibleTravel)
                    .copied(),
            };

            self.handle_anomaly(anomaly);
            return true;
        }

        false
    }

    /// Add a whitelisted travel route for a user.
    ///
    /// Known travel patterns (e.g., home <-> work across countries) can be whitelisted
    /// to prevent false positives.
    pub fn whitelist_travel_route(&self, user_id: &str, country1: &str, country2: &str) {
        let mut detector = self.impossible_travel.write();
        detector.add_whitelist_route(user_id, country1, country2);
    }

    /// Remove a whitelisted travel route.
    pub fn remove_travel_whitelist(&self, user_id: &str, country1: &str, country2: &str) {
        let mut detector = self.impossible_travel.write();
        detector.remove_whitelist_route(user_id, country1, country2);
    }

    /// Get impossible travel detection statistics.
    pub fn travel_stats(&self) -> crate::geo::TravelStats {
        let detector = self.impossible_travel.read();
        detector.stats()
    }

    /// Clear impossible travel history for a user.
    pub fn clear_travel_history(&self, user_id: &str) {
        let mut detector = self.impossible_travel.write();
        detector.clear_user(user_id);
    }

    // --------------------------------------------------------------------------
    // Trend Queries
    // --------------------------------------------------------------------------

    /// Get overall trends summary.
    pub fn get_summary(&self, options: TrendQueryOptions) -> TrendsSummary {
        let store = self.store.read();
        let mut summary = store.get_summary(&options);
        summary.anomaly_count = self.anomalies.len();
        summary
    }

    /// Get detailed trends by type.
    pub fn get_trends(&self, options: TrendQueryOptions) -> Vec<SignalTrend> {
        let store = self.store.read();
        store.get_trends(&options)
    }

    /// Get signals for an entity.
    pub fn get_signals_for_entity(
        &self,
        entity_id: &str,
        options: TrendQueryOptions,
    ) -> Vec<Signal> {
        let store = self.store.read();
        store.get_signals_for_entity(entity_id, &options)
    }

    /// Get all signals matching criteria.
    pub fn get_signals(&self, options: TrendQueryOptions) -> Vec<Signal> {
        let store = self.store.read();
        store.get_signals(&options)
    }

    // --------------------------------------------------------------------------
    // Anomaly Queries
    // --------------------------------------------------------------------------

    /// Get anomalies matching criteria.
    pub fn get_anomalies(&self, options: AnomalyQueryOptions) -> Vec<Anomaly> {
        let mut anomalies: Vec<Anomaly> = self
            .anomalies
            .iter()
            .map(|r| r.value().clone())
            .filter(|a| {
                if let Some(severity) = options.severity {
                    if a.severity != severity {
                        return false;
                    }
                }
                if let Some(ref anomaly_type) = options.anomaly_type {
                    if &a.anomaly_type != anomaly_type {
                        return false;
                    }
                }
                if let Some(ref category) = options.category {
                    if &a.category != category {
                        return false;
                    }
                }
                if let Some(ref entity_id) = options.entity_id {
                    if !a.entities.contains(entity_id) {
                        return false;
                    }
                }
                if let Some(from) = options.from {
                    if a.detected_at < from {
                        return false;
                    }
                }
                if let Some(to) = options.to {
                    if a.detected_at > to {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Sort by detection time (newest first)
        anomalies.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));

        // Apply limit
        if let Some(limit) = options.limit {
            anomalies.truncate(limit);
        }

        anomalies
    }

    /// Get a specific anomaly by ID.
    pub fn get_anomaly(&self, id: &str) -> Option<Anomaly> {
        self.anomalies.get(id).map(|r| r.value().clone())
    }

    /// Get count of active anomalies.
    pub fn active_anomaly_count(&self) -> usize {
        self.anomalies.len()
    }

    // --------------------------------------------------------------------------
    // Correlation Queries
    // --------------------------------------------------------------------------

    /// Get correlations matching criteria.
    pub fn get_correlations(&self, options: CorrelationQueryOptions) -> Vec<Correlation> {
        let signals = self.get_signals(TrendQueryOptions {
            from: options.from,
            to: options.to,
            entity_id: options.entity_id.clone(),
            signal_type: options.signal_type,
            ..Default::default()
        });

        self.correlation_engine
            .find_correlations(&signals, &options)
    }

    /// Get correlations for a specific entity.
    pub fn get_entity_correlations(
        &self,
        entity_id: &str,
        options: CorrelationQueryOptions,
    ) -> Vec<Correlation> {
        let mut opts = options;
        opts.entity_id = Some(entity_id.to_string());
        self.get_correlations(opts)
    }

    // --------------------------------------------------------------------------
    // Statistics
    // --------------------------------------------------------------------------

    /// Get manager statistics.
    pub fn stats(&self) -> TrendsManagerStats {
        let store = self.store.read();
        let store_stats = store.get_stats();

        TrendsManagerStats {
            enabled: self.config.enabled,
            store: store_stats,
            anomaly_count: self.anomalies.len(),
            recent_signals_cached: self.recent_signals.len(),
            bucket_size_ms: self.config.bucket_size_ms,
            retention_hours: self.config.retention_hours,
        }
    }

    /// Get a stats snapshot for API responses.
    pub fn stats_snapshot(&self) -> TrendsStats {
        let stats = self.stats();
        TrendsStats {
            enabled: stats.enabled,
            total_signals: stats.store.total_signals,
            bucket_count: stats.store.bucket_count,
            entity_count: stats.store.entity_count,
            anomaly_count: stats.anomaly_count,
        }
    }

    // --------------------------------------------------------------------------
    // Lifecycle
    // --------------------------------------------------------------------------

    /// Clear all data.
    pub fn clear(&self) {
        let mut store = self.store.write();
        store.clear();
        self.anomalies.clear();
        self.recent_signals.clear();
    }

    /// Cleanup old data.
    pub fn cleanup(&self) {
        {
            let mut store = self.store.write();
            store.cleanup();
        }
        self.cleanup_old_anomalies();
        self.cleanup_recent_signals();
    }

    /// Shutdown the manager.
    pub fn destroy(&self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut store = self.store.write();
        store.destroy();
    }

    /// Check if enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    // --------------------------------------------------------------------------
    // Private
    // --------------------------------------------------------------------------

    fn track_recent_signal(&self, entity_id: &str, signal: Signal) {
        let mut entry = self
            .recent_signals
            .entry(entity_id.to_string())
            .or_insert_with(Vec::new);
        entry.push(signal);

        // Keep only recent signals
        if entry.len() > self.config.max_recent_signals {
            entry.remove(0);
        }
    }

    fn get_recent_signals(&self, entity_id: &str) -> Vec<Signal> {
        self.recent_signals
            .get(entity_id)
            .map(|r| r.value().clone())
            .unwrap_or_default()
    }

    fn handle_anomaly(&self, anomaly: Anomaly) {
        // Dedupe by ID
        if self.anomalies.contains_key(&anomaly.id) {
            return;
        }

        // Apply risk if configured
        if let Some(risk) = anomaly.risk_applied {
            if risk > 0 {
                if let Some(ref apply_risk) = self.dependencies.apply_risk {
                    for entity_id in &anomaly.entities {
                        apply_risk(entity_id, risk, TrendsReason::Anomaly(anomaly.anomaly_type));
                    }
                }
            }
        }

        tracing::info!(
            "Anomaly detected: {} ({:?}) - {}",
            anomaly.anomaly_type,
            anomaly.severity,
            anomaly.description
        );

        self.anomalies.insert(anomaly.id.clone(), anomaly);
    }

    fn cleanup_old_anomalies(&self) {
        let cutoff = chrono::Utc::now().timestamp_millis()
            - (self.config.retention_hours as i64 * 60 * 60 * 1000);

        self.anomalies.retain(|_, v| v.detected_at >= cutoff);

        // Cap at max anomalies
        if self.anomalies.len() > self.config.max_anomalies {
            let mut entries: Vec<_> = self
                .anomalies
                .iter()
                .map(|r| (r.key().clone(), r.value().detected_at))
                .collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1));

            let to_remove: Vec<_> = entries
                .into_iter()
                .skip(self.config.max_anomalies)
                .map(|(k, _)| k)
                .collect();

            for key in to_remove {
                self.anomalies.remove(&key);
            }
        }
    }

    fn cleanup_recent_signals(&self) {
        let cutoff = chrono::Utc::now().timestamp_millis() - 10 * 60 * 1000; // 10 minutes

        self.recent_signals.retain(|_, signals| {
            signals.retain(|s| s.timestamp > cutoff);
            !signals.is_empty()
        });
    }
}

#[cfg(test)]
mod reason_tests {
    use super::TrendsReason;
    use crate::trends::AnomalyType;

    #[test]
    fn test_trends_reason_preserves_existing_risk_tag() {
        let expected_tags = [
            (
                AnomalyType::FingerprintChange,
                "trends_anomaly:Anomaly: fingerprint_change",
            ),
            (
                AnomalyType::SessionSharing,
                "trends_anomaly:Anomaly: session_sharing",
            ),
            (
                AnomalyType::VelocitySpike,
                "trends_anomaly:Anomaly: velocity_spike",
            ),
            (
                AnomalyType::ImpossibleTravel,
                "trends_anomaly:Anomaly: impossible_travel",
            ),
            (
                AnomalyType::TokenReuse,
                "trends_anomaly:Anomaly: token_reuse",
            ),
            (
                AnomalyType::RotationPattern,
                "trends_anomaly:Anomaly: rotation_pattern",
            ),
            (
                AnomalyType::TimingAnomaly,
                "trends_anomaly:Anomaly: timing_anomaly",
            ),
            (
                AnomalyType::Ja4RotationPattern,
                "trends_anomaly:Anomaly: ja4_rotation_pattern",
            ),
            (
                AnomalyType::Ja4IpCluster,
                "trends_anomaly:Anomaly: ja4_ip_cluster",
            ),
            (
                AnomalyType::Ja4BrowserSpoofing,
                "trends_anomaly:Anomaly: ja4_browser_spoofing",
            ),
            (
                AnomalyType::Ja4hChange,
                "trends_anomaly:Anomaly: ja4h_change",
            ),
            (
                AnomalyType::OversizedRequest,
                "trends_anomaly:Anomaly: oversized_request",
            ),
            (
                AnomalyType::OversizedResponse,
                "trends_anomaly:Anomaly: oversized_response",
            ),
            (
                AnomalyType::BandwidthSpike,
                "trends_anomaly:Anomaly: bandwidth_spike",
            ),
            (
                AnomalyType::ExfiltrationPattern,
                "trends_anomaly:Anomaly: exfiltration_pattern",
            ),
            (
                AnomalyType::UploadPattern,
                "trends_anomaly:Anomaly: upload_pattern",
            ),
        ];

        for (variant, expected_tag) in expected_tags {
            assert_eq!(
                TrendsReason::Anomaly(variant).as_tag(),
                expected_tag,
                "tag mapping must stay aligned with the historical reason format"
            );
        }
    }
}

/// Statistics for the trends manager.
#[derive(Debug, Clone)]
pub struct TrendsManagerStats {
    pub enabled: bool,
    pub store: TimeStoreStats,
    pub anomaly_count: usize,
    pub recent_signals_cached: usize,
    pub bucket_size_ms: u64,
    pub retention_hours: u32,
}

/// Lightweight stats snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendsStats {
    pub enabled: bool,
    pub total_signals: usize,
    pub bucket_count: usize,
    pub entity_count: usize,
    pub anomaly_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let config = TrendsConfig::default();
        let manager = TrendsManager::new(config);
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_disabled_manager() {
        let config = TrendsConfig::disabled();
        let manager = TrendsManager::new(config);
        assert!(!manager.is_enabled());

        // Recording should be no-op
        let signals = manager.record_request(
            "entity-1",
            None,
            None,
            None,
            Some("192.168.1.1"),
            None,
            None,
            None,
        );
        assert!(signals.is_empty());
    }

    #[test]
    fn test_record_and_query() {
        let config = TrendsConfig::default();
        let manager = TrendsManager::new(config);

        manager.record_request(
            "entity-1",
            None,
            Some("Mozilla/5.0"),
            None,
            Some("192.168.1.100"),
            Some("t13d1516h2_abc123"),
            None,
            None,
        );

        let stats = manager.stats();
        assert!(stats.store.total_signals > 0);
    }

    #[test]
    fn test_anomaly_query() {
        let config = TrendsConfig::default();
        let manager = TrendsManager::new(config);

        // Initially no anomalies
        let anomalies = manager.get_anomalies(AnomalyQueryOptions::default());
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_cleanup() {
        let config = TrendsConfig::default();
        let manager = TrendsManager::new(config);

        manager.record_request(
            "entity-1",
            None,
            None,
            None,
            Some("192.168.1.1"),
            None,
            None,
            None,
        );

        manager.cleanup();

        // Should still work after cleanup
        let stats = manager.stats();
        assert!(stats.enabled);
    }
}
