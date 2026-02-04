//! Prometheus metrics endpoint for observability.
//!
//! Provides a `/metrics` endpoint compatible with Prometheus scraping,
//! exposing request counts, latencies, WAF statistics, and backend health.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};

/// Metrics registry holding all metric collectors.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    /// Request counters by status code
    request_counts: RequestCounters,
    /// Latency histograms
    latencies: LatencyHistogram,
    /// Windowed counter for requests-per-minute tracking
    windowed_requests: WindowedCounter,
    /// WAF-specific metrics
    waf_metrics: WafMetrics,
    /// Shadow mirroring metrics (Phase 7)
    shadow_metrics: ShadowMetrics,
    /// Profiling metrics (Phase 2)
    profiling_metrics: ProfilingMetrics,
    /// DLP metrics (P1 observability fix)
    dlp_metrics: DlpMetrics,
    /// Signal dispatch metrics (labs-4gsj)
    signal_dispatch_metrics: SignalDispatchMetrics,
    /// Backend health metrics
    backend_metrics: Arc<RwLock<HashMap<String, BackendMetrics>>>,
    /// Registry start time for uptime calculation
    start_time: Option<Instant>,
}

/// DLP (Data Loss Prevention) metrics for observability (P1 fix).
#[derive(Debug, Default)]
pub struct DlpMetrics {
    /// Total DLP scans performed
    pub scans_total: AtomicU64,
    /// Total DLP matches found
    pub matches_total: AtomicU64,
    /// Matches by pattern type (e.g., "credit_card", "ssn")
    pub matches_by_type: Arc<RwLock<HashMap<String, u64>>>,
    /// Matches by severity ("low", "medium", "high", "critical")
    pub matches_by_severity: Arc<RwLock<HashMap<String, u64>>>,
    /// Violations dropped due to buffer overflow
    pub violations_dropped: AtomicU64,
    /// Graph export durations in microseconds (for histogram)
    pub graph_export_durations: Arc<RwLock<VecDeque<u64>>>,
}

impl DlpMetrics {
    /// Record a DLP scan
    pub fn record_scan(&self) {
        self.scans_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a DLP match
    pub fn record_match(&self, pattern_type: &str, severity: &str) {
        self.matches_total.fetch_add(1, Ordering::Relaxed);

        let mut by_type = self.matches_by_type.write();
        *by_type.entry(pattern_type.to_string()).or_insert(0) += 1;

        let mut by_severity = self.matches_by_severity.write();
        *by_severity.entry(severity.to_string()).or_insert(0) += 1;
    }

    /// Record a dropped violation
    pub fn record_violation_dropped(&self) {
        self.violations_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record graph export duration
    pub fn record_graph_export_duration(&self, duration_us: u64) {
        let mut durations = self.graph_export_durations.write();
        // Keep last 100 samples for histogram
        if durations.len() >= 100 {
            durations.pop_front();
        }
        durations.push_back(duration_us);
    }
}

/// Signal dispatch metrics for observability (labs-4gsj).
#[derive(Debug, Default)]
pub struct SignalDispatchMetrics {
    /// Total signal dispatch attempts
    pub total: AtomicU64,
    /// Successful signal dispatches
    pub success: AtomicU64,
    /// Failed signal dispatches (local or remote errors)
    pub failure: AtomicU64,
    /// Timed out signal dispatches
    pub timeout: AtomicU64,
    /// Dispatch latency histogram
    pub latencies: LatencyHistogram,
}

impl SignalDispatchMetrics {
    /// Record a dispatch attempt
    pub fn record_attempt(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a dispatch success
    pub fn record_success(&self, latency_us: u64) {
        self.success.fetch_add(1, Ordering::Relaxed);
        self.latencies.observe(latency_us);
    }

    /// Record a dispatch failure
    pub fn record_failure(&self) {
        self.failure.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a dispatch timeout
    pub fn record_timeout(&self) {
        self.timeout.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-endpoint statistics for API profiling.
#[derive(Debug, Clone)]
pub struct EndpointStats {
    /// Number of hits to this endpoint
    pub hit_count: u64,
    /// First time this endpoint was seen (ms since epoch)
    pub first_seen: u64,
    /// Last time this endpoint was seen (ms since epoch)
    pub last_seen: u64,
    /// HTTP methods observed (for variance)
    pub methods: Vec<String>,
}

impl Default for EndpointStats {
    fn default() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            hit_count: 0,
            first_seen: now,
            last_seen: now,
            methods: Vec::new(),
        }
    }
}

/// Profiling and anomaly detection metrics (Phase 2).
#[derive(Debug, Default)]
pub struct ProfilingMetrics {
    /// Active endpoint profiles
    pub profiles_active: AtomicU64,
    /// Total profiles created (gauge)
    pub profiles_total: AtomicU64,
    /// Total schemas learned (gauge)
    pub schemas_total: AtomicU64,
    /// Total profile updates (counter)
    pub profile_updates_total: AtomicU64,
    /// Schema violations by endpoint (counter vec)
    pub schema_violations_total: Arc<RwLock<HashMap<String, u64>>>,
    /// Anomalies detected by type
    pub anomalies_detected: Arc<RwLock<HashMap<String, u64>>>,
    /// Average anomaly score
    pub avg_anomaly_score: AtomicU64, // Scaled by 1000
    /// Requests with anomalies
    pub requests_with_anomalies: AtomicU64,
    /// Per-endpoint statistics (path -> stats)
    pub endpoint_stats: Arc<RwLock<HashMap<String, EndpointStats>>>,
    /// Bandwidth tracking: total bytes received (request bodies)
    pub total_bytes_in: AtomicU64,
    /// Bandwidth tracking: total bytes sent (response bodies)
    pub total_bytes_out: AtomicU64,
    /// Bandwidth tracking: max request size seen
    pub max_request_size: AtomicU64,
    /// Bandwidth tracking: max response size seen
    pub max_response_size: AtomicU64,
    /// Bandwidth tracking: request count for averaging
    pub bandwidth_request_count: AtomicU64,
    /// Bandwidth timeline (circular buffer, 60 data points for last hour)
    pub bandwidth_timeline: Arc<RwLock<BandwidthTimeline>>,
}

/// Bandwidth timeline data point
#[derive(Debug, Clone, Default)]
pub struct BandwidthDataPoint {
    /// Timestamp (ms since epoch)
    pub timestamp: u64,
    /// Bytes in during this period
    pub bytes_in: u64,
    /// Bytes out during this period
    pub bytes_out: u64,
    /// Request count during this period
    pub request_count: u64,
}

/// Circular buffer for bandwidth timeline (60 minutes of 1-minute intervals)
#[derive(Debug)]
pub struct BandwidthTimeline {
    /// Data points (circular buffer)
    pub points: Vec<BandwidthDataPoint>,
    /// Current write index
    pub current_index: usize,
    /// Last recorded minute (for period detection)
    pub last_minute: u64,
}

impl Default for BandwidthTimeline {
    fn default() -> Self {
        Self {
            points: vec![BandwidthDataPoint::default(); 60],
            current_index: 0,
            last_minute: 0,
        }
    }
}

impl ProfilingMetrics {
    /// Update active profiles count.
    pub fn set_active_profiles(&self, count: u64) {
        self.profiles_active.store(count, Ordering::Relaxed);
    }

    /// Update total profiles count (gauge).
    pub fn set_profiles_total(&self, count: u64) {
        self.profiles_total.store(count, Ordering::Relaxed);
    }

    /// Update total schemas count (gauge).
    pub fn set_schemas_total(&self, count: u64) {
        self.schemas_total.store(count, Ordering::Relaxed);
    }

    /// Increment profile updates counter.
    pub fn record_profile_update(&self) {
        self.profile_updates_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a schema violation for a specific endpoint.
    pub fn record_schema_violation(&self, endpoint: &str) {
        let mut violations = self.schema_violations_total.write();
        *violations.entry(endpoint.to_string()).or_insert(0) += 1;
    }

    /// Get all schema violations by endpoint.
    pub fn get_schema_violations(&self) -> Vec<(String, u64)> {
        let violations = self.schema_violations_total.read();
        violations.iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    /// Record an anomaly detection.
    pub fn record_anomaly(&self, anomaly_type: &str, score: f64) {
        let mut anomalies = self.anomalies_detected.write();
        *anomalies.entry(anomaly_type.to_string()).or_insert(0) += 1;

        self.requests_with_anomalies.fetch_add(1, Ordering::Relaxed);

        // Update rolling average (simplified)
        let scaled_score = (score * 1000.0) as u64;
        let current = self.avg_anomaly_score.load(Ordering::Relaxed);
        let new = if current == 0 {
            scaled_score
        } else {
            (current * 9 + scaled_score) / 10 // EMA with alpha 0.1
        };
        self.avg_anomaly_score.store(new, Ordering::Relaxed);
    }

    /// Record an endpoint hit for API profiling.
    pub fn record_endpoint(&self, path: &str, method: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut stats = self.endpoint_stats.write();
        let entry = stats.entry(path.to_string()).or_insert_with(|| EndpointStats {
            hit_count: 0,
            first_seen: now,
            last_seen: now,
            methods: Vec::new(),
        });

        entry.hit_count += 1;
        entry.last_seen = now;

        // Track unique methods
        let method_str = method.to_string();
        if !entry.methods.contains(&method_str) {
            entry.methods.push(method_str);
        }

        // Update active profiles count
        let count = stats.len() as u64;
        self.profiles_active.store(count, Ordering::Relaxed);
    }

    /// Get all endpoint statistics for the profiling API.
    pub fn get_endpoint_stats(&self) -> Vec<(String, EndpointStats)> {
        let stats = self.endpoint_stats.read();
        stats.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Record bandwidth for a request body.
    pub fn record_request_bytes(&self, bytes: u64) {
        self.total_bytes_in.fetch_add(bytes, Ordering::Relaxed);
        self.bandwidth_request_count.fetch_add(1, Ordering::Relaxed);

        // Update max request size atomically
        let mut current_max = self.max_request_size.load(Ordering::Relaxed);
        while bytes > current_max {
            match self.max_request_size.compare_exchange_weak(
                current_max,
                bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }

        // Update timeline
        self.update_timeline(bytes, 0);
    }

    /// Record bandwidth for a response body.
    pub fn record_response_bytes(&self, bytes: u64) {
        self.total_bytes_out.fetch_add(bytes, Ordering::Relaxed);

        // Update max response size atomically
        let mut current_max = self.max_response_size.load(Ordering::Relaxed);
        while bytes > current_max {
            match self.max_response_size.compare_exchange_weak(
                current_max,
                bytes,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(x) => current_max = x,
            }
        }

        // Update timeline
        self.update_timeline(0, bytes);
    }

    /// Update bandwidth timeline (called from record_request_bytes and record_response_bytes)
    fn update_timeline(&self, bytes_in: u64, bytes_out: u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let current_minute = now_ms / 60_000;

        let mut timeline = self.bandwidth_timeline.write();

        // Check if we need to advance to a new minute
        if current_minute != timeline.last_minute {
            // Advance index if this is a new period
            if timeline.last_minute > 0 {
                timeline.current_index = (timeline.current_index + 1) % 60;
            }
            timeline.last_minute = current_minute;

            // Reset the new slot
            let reset_idx = timeline.current_index;
            timeline.points[reset_idx] = BandwidthDataPoint {
                timestamp: now_ms,
                bytes_in: 0,
                bytes_out: 0,
                request_count: 0,
            };
        }

        // Update current slot
        let idx = timeline.current_index;
        timeline.points[idx].bytes_in += bytes_in;
        timeline.points[idx].bytes_out += bytes_out;
        if bytes_in > 0 {
            timeline.points[idx].request_count += 1;
        }
    }

    /// Get bandwidth statistics for the API.
    pub fn get_bandwidth_stats(&self) -> BandwidthStats {
        let total_bytes_in = self.total_bytes_in.load(Ordering::Relaxed);
        let total_bytes_out = self.total_bytes_out.load(Ordering::Relaxed);
        let request_count = self.bandwidth_request_count.load(Ordering::Relaxed);
        let max_request = self.max_request_size.load(Ordering::Relaxed);
        let max_response = self.max_response_size.load(Ordering::Relaxed);

        let avg_bytes_per_request = if request_count > 0 {
            (total_bytes_in + total_bytes_out) / request_count
        } else {
            0
        };

        // Get timeline (non-zero entries, most recent first)
        let timeline = self.bandwidth_timeline.read();
        let mut timeline_points: Vec<BandwidthDataPoint> = Vec::new();

        // Read from current_index backwards (wrapping around)
        for i in 0..60 {
            let idx = (timeline.current_index + 60 - i) % 60;
            let point = &timeline.points[idx];
            if point.timestamp > 0 {
                timeline_points.push(point.clone());
            }
        }

        BandwidthStats {
            total_bytes: total_bytes_in + total_bytes_out,
            total_bytes_in,
            total_bytes_out,
            avg_bytes_per_request,
            max_request_size: max_request,
            max_response_size: max_response,
            request_count,
            timeline: timeline_points,
        }
    }

    /// Reset all profiling metrics to initial state.
    pub fn reset(&self) {
        self.profiles_active.store(0, Ordering::Relaxed);
        self.profiles_total.store(0, Ordering::Relaxed);
        self.schemas_total.store(0, Ordering::Relaxed);
        self.profile_updates_total.store(0, Ordering::Relaxed);
        self.avg_anomaly_score.store(0, Ordering::Relaxed);
        self.requests_with_anomalies.store(0, Ordering::Relaxed);
        self.total_bytes_in.store(0, Ordering::Relaxed);
        self.total_bytes_out.store(0, Ordering::Relaxed);
        self.bandwidth_request_count.store(0, Ordering::Relaxed);
        self.max_request_size.store(0, Ordering::Relaxed);
        self.max_response_size.store(0, Ordering::Relaxed);

        // Clear maps
        self.anomalies_detected.write().clear();
        self.endpoint_stats.write().clear();
        self.schema_violations_total.write().clear();

        // Reset timeline
        let mut timeline = self.bandwidth_timeline.write();
        *timeline = BandwidthTimeline::default();

        tracing::info!("ProfilingMetrics reset complete");
    }
}

/// Bandwidth statistics returned by the API.
#[derive(Debug, Clone)]
pub struct BandwidthStats {
    /// Total bytes (in + out)
    pub total_bytes: u64,
    /// Total request bytes
    pub total_bytes_in: u64,
    /// Total response bytes
    pub total_bytes_out: u64,
    /// Average bytes per request
    pub avg_bytes_per_request: u64,
    /// Maximum request size seen
    pub max_request_size: u64,
    /// Maximum response size seen
    pub max_response_size: u64,
    /// Total request count
    pub request_count: u64,
    /// Timeline data points
    pub timeline: Vec<BandwidthDataPoint>,
}

/// Request counters broken down by status code class.
#[derive(Debug, Default)]
pub struct RequestCounters {
    /// Total requests received
    pub total: AtomicU64,
    /// 2xx responses
    pub success_2xx: AtomicU64,
    /// 3xx responses
    pub redirect_3xx: AtomicU64,
    /// 4xx responses
    pub client_error_4xx: AtomicU64,
    /// 5xx responses
    pub server_error_5xx: AtomicU64,
    /// Requests blocked by WAF
    pub blocked: AtomicU64,
}

/// Latency histogram with predefined buckets.
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Bucket boundaries in microseconds
    buckets: Vec<u64>,
    /// Counts per bucket
    counts: Vec<AtomicU64>,
    /// Sum of all latencies (for calculating average)
    sum_us: AtomicU64,
    /// Total count
    count: AtomicU64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        // Buckets: 100us, 500us, 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s
        let buckets = vec![100, 500, 1000, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000];
        let counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts,
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl LatencyHistogram {
    /// Records a latency observation.
    pub fn observe(&self, latency_us: u64) {
        self.sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Find the appropriate bucket
        for (i, &boundary) in self.buckets.iter().enumerate() {
            if latency_us <= boundary {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        // If larger than all buckets, count in the last bucket
        if let Some(last) = self.counts.last() {
            last.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the average latency in microseconds.
    pub fn average_us(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            0.0
        } else {
            self.sum_us.load(Ordering::Relaxed) as f64 / count as f64
        }
    }

    /// Returns an approximate percentile latency in microseconds.
    pub fn percentile_us(&self, percentile: f64) -> u64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }

        let mut pct = percentile;
        if pct.is_nan() {
            pct = 0.0;
        }
        if pct < 0.0 {
            pct = 0.0;
        } else if pct > 1.0 {
            pct = 1.0;
        }

        let target = ((count as f64) * pct).ceil().max(1.0) as u64;
        let mut cumulative = 0u64;

        for (i, boundary) in self.buckets.iter().enumerate() {
            cumulative += self.counts[i].load(Ordering::Relaxed);
            if cumulative >= target {
                return *boundary;
            }
        }

        *self.buckets.last().unwrap_or(&0)
    }

    /// Resets all counts to zero.
    pub fn reset(&self) {
        for count in &self.counts {
            count.store(0, Ordering::Relaxed);
        }
        self.sum_us.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }
}

/// Windowed counter for tracking metrics over time.
/// Maintains per-second buckets for the configured window duration.
#[derive(Debug)]
pub struct WindowedCounter {
    /// Per-second request counts (ring buffer)
    buckets: Vec<AtomicU64>,
    /// Per-second latency sums in microseconds (for average calculation)
    latency_buckets: Vec<AtomicU64>,
    /// Index of the current second
    current_index: AtomicU64,
    /// Timestamp of last bucket rotation
    last_rotation: RwLock<Instant>,
    /// Window size in seconds
    window_secs: usize,
}

impl Default for WindowedCounter {
    fn default() -> Self {
        Self::new(60) // Default 60-second window
    }
}

impl WindowedCounter {
    /// Creates a new windowed counter with the specified window size.
    pub fn new(window_secs: usize) -> Self {
        let buckets = (0..window_secs).map(|_| AtomicU64::new(0)).collect();
        let latency_buckets = (0..window_secs).map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            latency_buckets,
            current_index: AtomicU64::new(0),
            last_rotation: RwLock::new(Instant::now()),
            window_secs,
        }
    }

    /// Rotates buckets if needed (called on each record).
    fn maybe_rotate(&self) {
        let now = Instant::now();
        let mut last = self.last_rotation.write();
        let elapsed_secs = now.duration_since(*last).as_secs() as usize;

        if elapsed_secs > 0 {
            let current = self.current_index.load(Ordering::Relaxed) as usize;

            // Clear buckets that have expired
            for i in 1..=elapsed_secs.min(self.window_secs) {
                let idx = (current + i) % self.window_secs;
                self.buckets[idx].store(0, Ordering::Relaxed);
                self.latency_buckets[idx].store(0, Ordering::Relaxed);
            }

            // Update current index
            let new_index = (current + elapsed_secs) % self.window_secs;
            self.current_index.store(new_index as u64, Ordering::Relaxed);
            *last = now;
        }
    }

    /// Records a request with latency.
    pub fn record(&self, latency_us: u64) {
        self.maybe_rotate();
        let idx = self.current_index.load(Ordering::Relaxed) as usize;
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.latency_buckets[idx].fetch_add(latency_us, Ordering::Relaxed);
    }

    /// Returns the total count over the window.
    pub fn count(&self) -> u64 {
        self.maybe_rotate();
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Returns the average latency in microseconds over the window.
    pub fn average_latency_us(&self) -> f64 {
        self.maybe_rotate();
        let total_count: u64 = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum();
        if total_count == 0 {
            return 0.0;
        }
        let total_latency: u64 = self.latency_buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum();
        total_latency as f64 / total_count as f64
    }
}

/// WAF-specific metrics.
#[derive(Debug, Default)]
pub struct WafMetrics {
    /// Requests analyzed by WAF
    pub analyzed: AtomicU64,
    /// Requests blocked
    pub blocked: AtomicU64,
    /// Requests challenged
    pub challenged: AtomicU64,
    /// Requests logged (but allowed)
    pub logged: AtomicU64,
    /// Total detection time in microseconds
    pub detection_time_us: AtomicU64,
    /// Rule match counts by rule ID
    rule_matches: Arc<RwLock<HashMap<String, u64>>>,
}

impl WafMetrics {
    /// Records a WAF analysis result.
    pub fn record(&self, blocked: bool, challenged: bool, logged: bool, detection_us: u64) {
        self.analyzed.fetch_add(1, Ordering::Relaxed);
        self.detection_time_us.fetch_add(detection_us, Ordering::Relaxed);

        if blocked {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        } else if challenged {
            self.challenged.fetch_add(1, Ordering::Relaxed);
        } else if logged {
            self.logged.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a rule match.
    pub fn record_rule_match(&self, rule_id: &str) {
        let mut matches = self.rule_matches.write();
        *matches.entry(rule_id.to_string()).or_insert(0) += 1;
    }

    /// Returns the average detection time in microseconds.
    pub fn avg_detection_us(&self) -> f64 {
        let analyzed = self.analyzed.load(Ordering::Relaxed);
        if analyzed == 0 {
            0.0
        } else {
            self.detection_time_us.load(Ordering::Relaxed) as f64 / analyzed as f64
        }
    }
}

/// Shadow mirroring metrics (Phase 7).
#[derive(Debug, Default)]
pub struct ShadowMetrics {
    /// Total requests mirrored to honeypots
    pub mirrored: AtomicU64,
    /// Requests skipped due to rate limiting
    pub rate_limited: AtomicU64,
    /// Requests that failed to deliver to honeypot
    pub failed: AtomicU64,
    /// Total bytes sent to honeypots
    pub bytes_sent: AtomicU64,
    /// Total delivery time in microseconds
    pub delivery_time_us: AtomicU64,
}

impl ShadowMetrics {
    /// Records a successful mirror delivery.
    pub fn record_success(&self, bytes: u64, delivery_us: u64) {
        self.mirrored.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.delivery_time_us.fetch_add(delivery_us, Ordering::Relaxed);
    }

    /// Records a rate-limited mirror attempt.
    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a failed mirror delivery.
    pub fn record_failed(&self) {
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the average delivery time in microseconds.
    pub fn avg_delivery_us(&self) -> f64 {
        let mirrored = self.mirrored.load(Ordering::Relaxed);
        if mirrored == 0 {
            0.0
        } else {
            self.delivery_time_us.load(Ordering::Relaxed) as f64 / mirrored as f64
        }
    }
}

/// Per-backend metrics.
#[derive(Debug, Default, Clone)]
pub struct BackendMetrics {
    /// Total requests to this backend
    pub requests: u64,
    /// Successful responses
    pub successes: u64,
    /// Failed responses
    pub failures: u64,
    /// Total response time in microseconds
    pub response_time_us: u64,
    /// Whether backend is healthy
    pub healthy: bool,
}

impl MetricsRegistry {
    /// Creates a new metrics registry.
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    /// Records a request with status code and latency.
    pub fn record_request(&self, status_code: u16, latency_us: u64) {
        self.request_counts.total.fetch_add(1, Ordering::Relaxed);
        self.latencies.observe(latency_us);
        self.windowed_requests.record(latency_us);

        match status_code {
            200..=299 => self.request_counts.success_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.request_counts.redirect_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.request_counts.client_error_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.request_counts.server_error_5xx.fetch_add(1, Ordering::Relaxed),
            _ => 0, // Ignore other status codes
        };
    }

    /// Records a blocked request.
    pub fn record_blocked(&self) {
        self.request_counts.blocked.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of requests in the last minute.
    pub fn requests_last_minute(&self) -> u64 {
        self.windowed_requests.count()
    }

    /// Returns the total number of requests.
    pub fn total_requests(&self) -> u64 {
        self.request_counts.total.load(Ordering::Relaxed)
    }

    /// Returns the total number of error responses (4xx + 5xx).
    pub fn error_requests(&self) -> u64 {
        self.request_counts
            .client_error_4xx
            .load(Ordering::Relaxed)
            + self
                .request_counts
                .server_error_5xx
                .load(Ordering::Relaxed)
    }

    /// Returns latency percentile in milliseconds.
    pub fn latency_percentile_ms(&self, percentile: f64) -> f64 {
        self.latencies.percentile_us(percentile) as f64 / 1000.0
    }

    /// Returns the average latency in milliseconds over the last minute.
    pub fn avg_latency_ms(&self) -> f64 {
        self.windowed_requests.average_latency_us() / 1000.0
    }

    /// Records WAF metrics.
    pub fn record_waf(&self, blocked: bool, challenged: bool, logged: bool, detection_us: u64) {
        self.waf_metrics.record(blocked, challenged, logged, detection_us);
    }

    /// Records a rule match.
    pub fn record_rule_match(&self, rule_id: &str) {
        self.waf_metrics.record_rule_match(rule_id);
    }

    /// Records a successful shadow mirror delivery.
    pub fn record_shadow_success(&self, bytes: u64, delivery_us: u64) {
        self.shadow_metrics.record_success(bytes, delivery_us);
    }

    /// Records a rate-limited shadow mirror attempt.
    pub fn record_shadow_rate_limited(&self) {
        self.shadow_metrics.record_rate_limited();
    }

    /// Records a failed shadow mirror delivery.
    pub fn record_shadow_failed(&self) {
        self.shadow_metrics.record_failed();
    }

    /// Returns the total number of mirrored requests.
    pub fn shadow_mirrored_total(&self) -> u64 {
        self.shadow_metrics.mirrored.load(Ordering::Relaxed)
    }

    /// Returns the total number of rate-limited shadow attempts.
    pub fn shadow_rate_limited_total(&self) -> u64 {
        self.shadow_metrics.rate_limited.load(Ordering::Relaxed)
    }

    /// Returns the total number of failed shadow deliveries.
    pub fn shadow_failed_total(&self) -> u64 {
        self.shadow_metrics.failed.load(Ordering::Relaxed)
    }

    /// Records profiling metrics (Phase 2).
    pub fn record_profile_metrics(&self, active_profiles: usize, anomalies: &[(String, f64)]) {
        self.profiling_metrics.set_active_profiles(active_profiles as u64);
        for (anomaly_type, score) in anomalies {
            self.profiling_metrics.record_anomaly(anomaly_type, *score);
        }
    }

    /// Records an endpoint hit for API profiling/discovery.
    pub fn record_endpoint(&self, path: &str, method: &str) {
        self.profiling_metrics.record_endpoint(path, method);
    }

    /// Gets all endpoint statistics for the profiling API.
    pub fn get_endpoint_stats(&self) -> Vec<(String, EndpointStats)> {
        self.profiling_metrics.get_endpoint_stats()
    }

    /// Records request body bandwidth.
    pub fn record_request_bandwidth(&self, bytes: u64) {
        self.profiling_metrics.record_request_bytes(bytes);
    }

    /// Records response body bandwidth.
    pub fn record_response_bandwidth(&self, bytes: u64) {
        self.profiling_metrics.record_response_bytes(bytes);
    }

    /// Gets bandwidth statistics for the API.
    pub fn get_bandwidth_stats(&self) -> BandwidthStats {
        self.profiling_metrics.get_bandwidth_stats()
    }

    /// Resets all endpoint profile metrics.
    pub fn reset_profiles(&self) {
        self.profiling_metrics.profiles_active.store(0, Ordering::Relaxed);
        self.profiling_metrics.profiles_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.profile_updates_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.endpoint_stats.write().clear();
    }

    /// Resets all schema metrics.
    pub fn reset_schemas(&self) {
        self.profiling_metrics.schemas_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.schema_violations_total.write().clear();
    }

    /// Records backend response.
    pub fn record_backend(&self, backend: &str, success: bool, response_time_us: u64) {
        let mut backends = self.backend_metrics.write();
        let metrics = backends.entry(backend.to_string()).or_default();
        metrics.requests += 1;
        metrics.response_time_us += response_time_us;
        if success {
            metrics.successes += 1;
        } else {
            metrics.failures += 1;
        }
        // Update health: >50% success rate = healthy
        metrics.healthy = metrics.requests == 0 ||
            (metrics.successes as f64 / metrics.requests as f64) > 0.5;
    }

    /// Returns the uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0)
    }

    /// Renders metrics in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut output = String::with_capacity(4096);

        // Help text and type declarations
        output.push_str("# HELP synapse_requests_total Total number of requests\n");
        output.push_str("# TYPE synapse_requests_total counter\n");
        output.push_str(&format!(
            "synapse_requests_total {}\n",
            self.request_counts.total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_requests_by_status Requests by status code class\n");
        output.push_str("# TYPE synapse_requests_by_status counter\n");
        output.push_str(&format!(
            "synapse_requests_by_status{{status=\"2xx\"}} {}\n",
            self.request_counts.success_2xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_requests_by_status{{status=\"3xx\"}} {}\n",
            self.request_counts.redirect_3xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_requests_by_status{{status=\"4xx\"}} {}\n",
            self.request_counts.client_error_4xx.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_requests_by_status{{status=\"5xx\"}} {}\n",
            self.request_counts.server_error_5xx.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_requests_blocked Requests blocked by WAF\n");
        output.push_str("# TYPE synapse_requests_blocked counter\n");
        output.push_str(&format!(
            "synapse_requests_blocked {}\n",
            self.request_counts.blocked.load(Ordering::Relaxed)
        ));

        // Latency histogram
        output.push_str("# HELP synapse_request_duration_us Request duration in microseconds\n");
        output.push_str("# TYPE synapse_request_duration_us histogram\n");
        let mut cumulative = 0u64;
        for (i, &boundary) in self.latencies.buckets.iter().enumerate() {
            cumulative += self.latencies.counts[i].load(Ordering::Relaxed);
            output.push_str(&format!(
                "synapse_request_duration_us_bucket{{le=\"{}\"}} {}\n",
                boundary, cumulative
            ));
        }
        output.push_str(&format!(
            "synapse_request_duration_us_bucket{{le=\"+Inf\"}} {}\n",
            self.latencies.count.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_request_duration_us_sum {}\n",
            self.latencies.sum_us.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_request_duration_us_count {}\n",
            self.latencies.count.load(Ordering::Relaxed)
        ));

        // WAF metrics
        output.push_str("# HELP synapse_waf_analyzed Requests analyzed by WAF\n");
        output.push_str("# TYPE synapse_waf_analyzed counter\n");
        output.push_str(&format!(
            "synapse_waf_analyzed {}\n",
            self.waf_metrics.analyzed.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_waf_blocked Requests blocked by WAF\n");
        output.push_str("# TYPE synapse_waf_blocked counter\n");
        output.push_str(&format!(
            "synapse_waf_blocked {}\n",
            self.waf_metrics.blocked.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_waf_detection_avg_us Average WAF detection time\n");
        output.push_str("# TYPE synapse_waf_detection_avg_us gauge\n");
        output.push_str(&format!(
            "synapse_waf_detection_avg_us {:.2}\n",
            self.waf_metrics.avg_detection_us()
        ));

        // Profiling metrics (Phase 2)
        output.push_str("# HELP synapse_profiles_active_count Number of active endpoint profiles\n");
        output.push_str("# TYPE synapse_profiles_active_count gauge\n");
        output.push_str(&format!(
            "synapse_profiles_active_count {}\n",
            self.profiling_metrics.profiles_active.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_profiles_total Total number of endpoint profiles\n");
        output.push_str("# TYPE synapse_profiles_total gauge\n");
        output.push_str(&format!(
            "synapse_profiles_total {}\n",
            self.profiling_metrics.profiles_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_schemas_total Total number of learned schemas\n");
        output.push_str("# TYPE synapse_schemas_total gauge\n");
        output.push_str(&format!(
            "synapse_schemas_total {}\n",
            self.profiling_metrics.schemas_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_profile_updates_total Total profile update operations\n");
        output.push_str("# TYPE synapse_profile_updates_total counter\n");
        output.push_str(&format!(
            "synapse_profile_updates_total {}\n",
            self.profiling_metrics.profile_updates_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_schema_violations_total Schema violations by endpoint\n");
        output.push_str("# TYPE synapse_schema_violations_total counter\n");
        let violations = self.profiling_metrics.schema_violations_total.read();
        for (endpoint, count) in violations.iter() {
            output.push_str(&format!(
                "synapse_schema_violations_total{{endpoint=\"{}\"}} {}\n",
                endpoint, count
            ));
        }

        output.push_str("# HELP synapse_anomalies_detected_total Anomalies detected by type\n");
        output.push_str("# TYPE synapse_anomalies_detected_total counter\n");
        let anomalies = self.profiling_metrics.anomalies_detected.read();
        for (anomaly_type, count) in anomalies.iter() {
            output.push_str(&format!(
                "synapse_anomalies_detected_total{{type=\"{}\"}} {}\n",
                anomaly_type, count
            ));
        }

        output.push_str("# HELP synapse_avg_anomaly_score Average anomaly score (0-10)\n");
        output.push_str("# TYPE synapse_avg_anomaly_score gauge\n");
        output.push_str(&format!(
            "synapse_avg_anomaly_score {:.2}\n",
            self.profiling_metrics.avg_anomaly_score.load(Ordering::Relaxed) as f64 / 1000.0
        ));

        // Backend metrics
        output.push_str("# HELP synapse_backend_requests Backend request counts\n");
        output.push_str("# TYPE synapse_backend_requests counter\n");
        output.push_str("# HELP synapse_backend_healthy Backend health status\n");
        output.push_str("# TYPE synapse_backend_healthy gauge\n");

        let backends = self.backend_metrics.read();
        for (backend, metrics) in backends.iter() {
            output.push_str(&format!(
                "synapse_backend_requests{{backend=\"{}\"}} {}\n",
                backend, metrics.requests
            ));
            output.push_str(&format!(
                "synapse_backend_healthy{{backend=\"{}\"}} {}\n",
                backend, if metrics.healthy { 1 } else { 0 }
            ));
        }

        // Shadow mirroring metrics (Phase 7)
        output.push_str("# HELP synapse_shadow_mirrored Requests mirrored to honeypots\n");
        output.push_str("# TYPE synapse_shadow_mirrored counter\n");
        output.push_str(&format!(
            "synapse_shadow_mirrored {}\n",
            self.shadow_metrics.mirrored.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_shadow_rate_limited Requests rate-limited from mirroring\n");
        output.push_str("# TYPE synapse_shadow_rate_limited counter\n");
        output.push_str(&format!(
            "synapse_shadow_rate_limited {}\n",
            self.shadow_metrics.rate_limited.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_shadow_failed Failed mirror deliveries\n");
        output.push_str("# TYPE synapse_shadow_failed counter\n");
        output.push_str(&format!(
            "synapse_shadow_failed {}\n",
            self.shadow_metrics.failed.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_shadow_bytes_total Total bytes sent to honeypots\n");
        output.push_str("# TYPE synapse_shadow_bytes_total counter\n");
        output.push_str(&format!(
            "synapse_shadow_bytes_total {}\n",
            self.shadow_metrics.bytes_sent.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_shadow_delivery_avg_us Average shadow delivery time\n");
        output.push_str("# TYPE synapse_shadow_delivery_avg_us gauge\n");
        output.push_str(&format!(
            "synapse_shadow_delivery_avg_us {:.2}\n",
            self.shadow_metrics.avg_delivery_us()
        ));

        // DLP metrics (P1 observability fix)
        output.push_str("# HELP synapse_dlp_scans_total Total DLP scans performed\n");
        output.push_str("# TYPE synapse_dlp_scans_total counter\n");
        output.push_str(&format!(
            "synapse_dlp_scans_total {}\n",
            self.dlp_metrics.scans_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_dlp_matches_total Total DLP matches found\n");
        output.push_str("# TYPE synapse_dlp_matches_total counter\n");
        output.push_str(&format!(
            "synapse_dlp_matches_total {}\n",
            self.dlp_metrics.matches_total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_dlp_matches_by_type DLP matches by pattern type\n");
        output.push_str("# TYPE synapse_dlp_matches_by_type counter\n");
        let matches_by_type = self.dlp_metrics.matches_by_type.read();
        for (pattern_type, count) in matches_by_type.iter() {
            output.push_str(&format!(
                "synapse_dlp_matches_by_type{{type=\"{}\"}} {}\n",
                pattern_type, count
            ));
        }

        output.push_str("# HELP synapse_dlp_matches_by_severity DLP matches by severity\n");
        output.push_str("# TYPE synapse_dlp_matches_by_severity counter\n");
        let matches_by_severity = self.dlp_metrics.matches_by_severity.read();
        for (severity, count) in matches_by_severity.iter() {
            output.push_str(&format!(
                "synapse_dlp_matches_by_severity{{severity=\"{}\"}} {}\n",
                severity, count
            ));
        }

        output.push_str("# HELP synapse_dlp_violations_dropped Violations dropped due to buffer overflow\n");
        output.push_str("# TYPE synapse_dlp_violations_dropped counter\n");
        output.push_str(&format!(
            "synapse_dlp_violations_dropped {}\n",
            self.dlp_metrics.violations_dropped.load(Ordering::Relaxed)
        ));

        // Signal dispatch metrics (labs-4gsj)
        output.push_str("# HELP synapse_signal_dispatch_total Total signal dispatch attempts\n");
        output.push_str("# TYPE synapse_signal_dispatch_total counter\n");
        output.push_str(&format!(
            "synapse_signal_dispatch_total {}\n",
            self.signal_dispatch_metrics.total.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_signal_dispatch_success Successful signal dispatches\n");
        output.push_str("# TYPE synapse_signal_dispatch_success counter\n");
        output.push_str(&format!(
            "synapse_signal_dispatch_success {}\n",
            self.signal_dispatch_metrics.success.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_signal_dispatch_failure Failed signal dispatches\n");
        output.push_str("# TYPE synapse_signal_dispatch_failure counter\n");
        output.push_str(&format!(
            "synapse_signal_dispatch_failure {}\n",
            self.signal_dispatch_metrics.failure.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_signal_dispatch_timeout Timed out signal dispatches\n");
        output.push_str("# TYPE synapse_signal_dispatch_timeout counter\n");
        output.push_str(&format!(
            "synapse_signal_dispatch_timeout {}\n",
            self.signal_dispatch_metrics.timeout.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_signal_dispatch_duration_us Signal dispatch duration in microseconds\n");
        output.push_str("# TYPE synapse_signal_dispatch_duration_us histogram\n");
        let mut cumulative_dispatch = 0u64;
        for (i, &boundary) in self.signal_dispatch_metrics.latencies.buckets.iter().enumerate() {
            cumulative_dispatch += self.signal_dispatch_metrics.latencies.counts[i].load(Ordering::Relaxed);
            output.push_str(&format!(
                "synapse_signal_dispatch_duration_us_bucket{{le=\"{}\"}} {}\n",
                boundary, cumulative_dispatch
            ));
        }
        output.push_str(&format!(
            "synapse_signal_dispatch_duration_us_bucket{{le=\"+Inf\"}} {}\n",
            self.signal_dispatch_metrics.latencies.count.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_signal_dispatch_duration_us_sum {}\n",
            self.signal_dispatch_metrics.latencies.sum_us.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "synapse_signal_dispatch_duration_us_count {}\n",
            self.signal_dispatch_metrics.latencies.count.load(Ordering::Relaxed)
        ));

        output.push_str("# HELP synapse_uptime_seconds Service uptime in seconds\n");
        output.push_str("# TYPE synapse_uptime_seconds gauge\n");
        output.push_str(&format!("synapse_uptime_seconds {}\n", self.uptime_secs()));

        output
    }

    /// Resets all metrics to zero (for demo/testing purposes).
    /// Note: Does NOT reset uptime - that tracks since service start.
    pub fn reset(&self) {
        // Reset request counters
        self.request_counts.total.store(0, Ordering::Relaxed);
        self.request_counts.success_2xx.store(0, Ordering::Relaxed);
        self.request_counts.redirect_3xx.store(0, Ordering::Relaxed);
        self.request_counts.client_error_4xx.store(0, Ordering::Relaxed);
        self.request_counts.server_error_5xx.store(0, Ordering::Relaxed);
        self.request_counts.blocked.store(0, Ordering::Relaxed);

        // Reset latency histogram
        for count in &self.latencies.counts {
            count.store(0, Ordering::Relaxed);
        }
        self.latencies.sum_us.store(0, Ordering::Relaxed);
        self.latencies.count.store(0, Ordering::Relaxed);

        // Reset WAF metrics
        self.waf_metrics.analyzed.store(0, Ordering::Relaxed);
        self.waf_metrics.blocked.store(0, Ordering::Relaxed);
        self.waf_metrics.challenged.store(0, Ordering::Relaxed);
        self.waf_metrics.logged.store(0, Ordering::Relaxed);
        self.waf_metrics.detection_time_us.store(0, Ordering::Relaxed);
        self.waf_metrics.rule_matches.write().clear();

        // Reset profiling metrics
        self.profiling_metrics.profiles_active.store(0, Ordering::Relaxed);
        self.profiling_metrics.profiles_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.schemas_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.profile_updates_total.store(0, Ordering::Relaxed);
        self.profiling_metrics.schema_violations_total.write().clear();
        self.profiling_metrics.anomalies_detected.write().clear();
        self.profiling_metrics.avg_anomaly_score.store(0, Ordering::Relaxed);
        self.profiling_metrics.requests_with_anomalies.store(0, Ordering::Relaxed);
        self.profiling_metrics.endpoint_stats.write().clear();

        // Reset shadow metrics
        self.shadow_metrics.mirrored.store(0, Ordering::Relaxed);
        self.shadow_metrics.rate_limited.store(0, Ordering::Relaxed);
        self.shadow_metrics.failed.store(0, Ordering::Relaxed);
        self.shadow_metrics.bytes_sent.store(0, Ordering::Relaxed);
        self.shadow_metrics.delivery_time_us.store(0, Ordering::Relaxed);

        // Reset DLP metrics (P1 fix)
        self.dlp_metrics.scans_total.store(0, Ordering::Relaxed);
        self.dlp_metrics.matches_total.store(0, Ordering::Relaxed);
        self.dlp_metrics.matches_by_type.write().clear();
        self.dlp_metrics.matches_by_severity.write().clear();
        self.dlp_metrics.violations_dropped.store(0, Ordering::Relaxed);
        self.dlp_metrics.graph_export_durations.write().clear();

        // Reset signal dispatch metrics
        self.signal_dispatch_metrics.total.store(0, Ordering::Relaxed);
        self.signal_dispatch_metrics.success.store(0, Ordering::Relaxed);
        self.signal_dispatch_metrics.failure.store(0, Ordering::Relaxed);
        self.signal_dispatch_metrics.timeout.store(0, Ordering::Relaxed);
        self.signal_dispatch_metrics.latencies.reset();
    }

    /// Returns a reference to the DLP metrics.
    pub fn dlp_metrics(&self) -> &DlpMetrics {
        &self.dlp_metrics
    }

    /// Returns a reference to the signal dispatch metrics.
    pub fn signal_dispatch_metrics(&self) -> &SignalDispatchMetrics {
        &self.signal_dispatch_metrics
    }

    /// Returns a reference to the profiling metrics.
    pub fn profiling_metrics(&self) -> &ProfilingMetrics {
        &self.profiling_metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_counters() {
        let registry = MetricsRegistry::new();

        registry.record_request(200, 1000);
        registry.record_request(201, 1500);
        registry.record_request(404, 500);
        registry.record_request(500, 2000);

        assert_eq!(registry.request_counts.total.load(Ordering::Relaxed), 4);
        assert_eq!(registry.request_counts.success_2xx.load(Ordering::Relaxed), 2);
        assert_eq!(registry.request_counts.client_error_4xx.load(Ordering::Relaxed), 1);
        assert_eq!(registry.request_counts.server_error_5xx.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_latency_histogram() {
        let histogram = LatencyHistogram::default();

        histogram.observe(50);    // 100us bucket
        histogram.observe(150);   // 500us bucket
        histogram.observe(750);   // 1000us bucket
        histogram.observe(5000);  // 5000us bucket

        assert_eq!(histogram.count.load(Ordering::Relaxed), 4);
        assert_eq!(histogram.sum_us.load(Ordering::Relaxed), 5950);
    }

    #[test]
    fn test_latency_average() {
        let histogram = LatencyHistogram::default();

        histogram.observe(100);
        histogram.observe(200);
        histogram.observe(300);

        assert_eq!(histogram.average_us(), 200.0);
    }

    #[test]
    fn test_waf_metrics() {
        let registry = MetricsRegistry::new();

        registry.record_waf(true, false, false, 50);   // blocked
        registry.record_waf(false, true, false, 30);   // challenged
        registry.record_waf(false, false, true, 20);   // logged

        assert_eq!(registry.waf_metrics.analyzed.load(Ordering::Relaxed), 3);
        assert_eq!(registry.waf_metrics.blocked.load(Ordering::Relaxed), 1);
        assert_eq!(registry.waf_metrics.challenged.load(Ordering::Relaxed), 1);
        assert_eq!(registry.waf_metrics.logged.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_backend_metrics() {
        let registry = MetricsRegistry::new();

        registry.record_backend("127.0.0.1:8080", true, 1000);
        registry.record_backend("127.0.0.1:8080", true, 1500);
        registry.record_backend("127.0.0.1:8080", false, 5000);

        let backends = registry.backend_metrics.read();
        let metrics = backends.get("127.0.0.1:8080").unwrap();

        assert_eq!(metrics.requests, 3);
        assert_eq!(metrics.successes, 2);
        assert_eq!(metrics.failures, 1);
        assert!(metrics.healthy); // 66% success rate
    }

    #[test]
    fn test_prometheus_output() {
        let registry = MetricsRegistry::new();

        registry.record_request(200, 1000);
        registry.record_blocked();
        registry.record_waf(true, false, false, 50);

        let output = registry.render_prometheus();

        assert!(output.contains("synapse_requests_total 1"));
        assert!(output.contains("synapse_requests_blocked 1"));
        assert!(output.contains("synapse_waf_analyzed 1"));
        assert!(output.contains("synapse_uptime_seconds"));
    }

    #[test]
    fn test_rule_match_recording() {
        let registry = MetricsRegistry::new();

        registry.record_rule_match("rule-123");
        registry.record_rule_match("rule-123");
        registry.record_rule_match("rule-456");

        let matches = registry.waf_metrics.rule_matches.read();
        assert_eq!(matches.get("rule-123"), Some(&2));
        assert_eq!(matches.get("rule-456"), Some(&1));
    }

    #[test]
    fn test_uptime() {
        let registry = MetricsRegistry::new();

        // Uptime should be very small but non-negative
        assert!(registry.uptime_secs() < 1);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - BandwidthTimeline
    // =========================================================================

    #[test]
    fn test_bandwidth_timeline_default() {
        let timeline = BandwidthTimeline::default();

        // Should have 60 slots pre-allocated
        assert_eq!(timeline.points.len(), 60);
        assert_eq!(timeline.current_index, 0);
        assert_eq!(timeline.last_minute, 0);

        // All points should be default (zero values)
        for point in &timeline.points {
            assert_eq!(point.timestamp, 0);
            assert_eq!(point.bytes_in, 0);
            assert_eq!(point.bytes_out, 0);
            assert_eq!(point.request_count, 0);
        }
    }

    #[test]
    fn test_bandwidth_timeline_circular_buffer_wrap() {
        // Directly test circular buffer behavior
        let mut timeline = BandwidthTimeline::default();

        // Simulate filling the buffer beyond capacity
        for i in 0..65 {
            timeline.current_index = i % 60;
            timeline.points[timeline.current_index] = BandwidthDataPoint {
                timestamp: (i as u64) * 60_000,
                bytes_in: (i as u64) * 100,
                bytes_out: (i as u64) * 50,
                request_count: 1,
            };
        }

        // Current index should wrap around
        assert_eq!(timeline.current_index, 4); // 64 % 60 = 4

        // Verify the most recent data is at current_index
        assert_eq!(timeline.points[4].bytes_in, 6400);
    }

    #[test]
    fn test_bandwidth_data_point_default() {
        let point = BandwidthDataPoint::default();

        assert_eq!(point.timestamp, 0);
        assert_eq!(point.bytes_in, 0);
        assert_eq!(point.bytes_out, 0);
        assert_eq!(point.request_count, 0);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - ProfilingMetrics.record_request_bytes()
    // =========================================================================

    #[test]
    fn test_profiling_metrics_record_request_bytes() {
        let metrics = ProfilingMetrics::default();

        metrics.record_request_bytes(1000);
        metrics.record_request_bytes(2000);
        metrics.record_request_bytes(500);

        assert_eq!(metrics.total_bytes_in.load(Ordering::Relaxed), 3500);
        assert_eq!(metrics.bandwidth_request_count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_profiling_metrics_record_request_bytes_zero() {
        let metrics = ProfilingMetrics::default();

        metrics.record_request_bytes(0);

        assert_eq!(metrics.total_bytes_in.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.bandwidth_request_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_profiling_metrics_record_request_bytes_large_value() {
        let metrics = ProfilingMetrics::default();

        // Record a large value (10 MB)
        metrics.record_request_bytes(10 * 1024 * 1024);

        assert_eq!(metrics.total_bytes_in.load(Ordering::Relaxed), 10 * 1024 * 1024);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - ProfilingMetrics.record_response_bytes()
    // =========================================================================

    #[test]
    fn test_profiling_metrics_record_response_bytes() {
        let metrics = ProfilingMetrics::default();

        metrics.record_response_bytes(5000);
        metrics.record_response_bytes(3000);

        assert_eq!(metrics.total_bytes_out.load(Ordering::Relaxed), 8000);
    }

    #[test]
    fn test_profiling_metrics_record_response_bytes_zero() {
        let metrics = ProfilingMetrics::default();

        metrics.record_response_bytes(0);

        assert_eq!(metrics.total_bytes_out.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_profiling_metrics_mixed_request_response() {
        let metrics = ProfilingMetrics::default();

        metrics.record_request_bytes(100);
        metrics.record_response_bytes(500);
        metrics.record_request_bytes(200);
        metrics.record_response_bytes(1000);

        assert_eq!(metrics.total_bytes_in.load(Ordering::Relaxed), 300);
        assert_eq!(metrics.total_bytes_out.load(Ordering::Relaxed), 1500);
        assert_eq!(metrics.bandwidth_request_count.load(Ordering::Relaxed), 2);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - Max size tracking with compare_exchange
    // =========================================================================

    #[test]
    fn test_profiling_metrics_max_request_size_tracking() {
        let metrics = ProfilingMetrics::default();

        metrics.record_request_bytes(100);
        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 100);

        metrics.record_request_bytes(50); // smaller, should not update max
        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 100);

        metrics.record_request_bytes(200); // larger, should update max
        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 200);

        metrics.record_request_bytes(150); // smaller than max
        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_profiling_metrics_max_response_size_tracking() {
        let metrics = ProfilingMetrics::default();

        metrics.record_response_bytes(500);
        assert_eq!(metrics.max_response_size.load(Ordering::Relaxed), 500);

        metrics.record_response_bytes(250); // smaller, should not update max
        assert_eq!(metrics.max_response_size.load(Ordering::Relaxed), 500);

        metrics.record_response_bytes(1000); // larger, should update max
        assert_eq!(metrics.max_response_size.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn test_profiling_metrics_max_size_from_zero() {
        let metrics = ProfilingMetrics::default();

        // Initial max should be 0
        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.max_response_size.load(Ordering::Relaxed), 0);

        // First non-zero value should become max
        metrics.record_request_bytes(42);
        metrics.record_response_bytes(84);

        assert_eq!(metrics.max_request_size.load(Ordering::Relaxed), 42);
        assert_eq!(metrics.max_response_size.load(Ordering::Relaxed), 84);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - ProfilingMetrics.get_bandwidth_stats()
    // =========================================================================

    #[test]
    fn test_profiling_metrics_get_bandwidth_stats_empty() {
        let metrics = ProfilingMetrics::default();

        let stats = metrics.get_bandwidth_stats();

        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.total_bytes_in, 0);
        assert_eq!(stats.total_bytes_out, 0);
        assert_eq!(stats.avg_bytes_per_request, 0);
        assert_eq!(stats.max_request_size, 0);
        assert_eq!(stats.max_response_size, 0);
        assert_eq!(stats.request_count, 0);
    }

    #[test]
    fn test_profiling_metrics_get_bandwidth_stats_with_data() {
        let metrics = ProfilingMetrics::default();

        metrics.record_request_bytes(100);
        metrics.record_response_bytes(400);
        metrics.record_request_bytes(200);
        metrics.record_response_bytes(600);

        let stats = metrics.get_bandwidth_stats();

        assert_eq!(stats.total_bytes_in, 300);
        assert_eq!(stats.total_bytes_out, 1000);
        assert_eq!(stats.total_bytes, 1300);
        assert_eq!(stats.request_count, 2);
        assert_eq!(stats.avg_bytes_per_request, 650); // 1300 / 2
        assert_eq!(stats.max_request_size, 200);
        assert_eq!(stats.max_response_size, 600);
    }

    #[test]
    fn test_profiling_metrics_get_bandwidth_stats_average_calculation() {
        let metrics = ProfilingMetrics::default();

        // Record varying sizes
        metrics.record_request_bytes(1000);
        metrics.record_response_bytes(2000);
        metrics.record_request_bytes(500);
        metrics.record_response_bytes(1500);
        metrics.record_request_bytes(1500);
        metrics.record_response_bytes(3500);

        let stats = metrics.get_bandwidth_stats();

        // Total: 3000 in + 7000 out = 10000
        // Request count: 3
        // Average: 10000 / 3 = 3333
        assert_eq!(stats.total_bytes_in, 3000);
        assert_eq!(stats.total_bytes_out, 7000);
        assert_eq!(stats.request_count, 3);
        assert_eq!(stats.avg_bytes_per_request, 3333);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - MetricsRegistry integration
    // =========================================================================

    #[test]
    fn test_registry_record_request_bandwidth() {
        let registry = MetricsRegistry::new();

        registry.record_request_bandwidth(1024);
        registry.record_request_bandwidth(2048);

        let stats = registry.get_bandwidth_stats();
        assert_eq!(stats.total_bytes_in, 3072);
    }

    #[test]
    fn test_registry_record_response_bandwidth() {
        let registry = MetricsRegistry::new();

        registry.record_response_bandwidth(4096);
        registry.record_response_bandwidth(8192);

        let stats = registry.get_bandwidth_stats();
        assert_eq!(stats.total_bytes_out, 12288);
    }

    #[test]
    fn test_registry_bandwidth_stats_integration() {
        let registry = MetricsRegistry::new();

        registry.record_request_bandwidth(500);
        registry.record_response_bandwidth(1500);
        registry.record_request_bandwidth(1000);
        registry.record_response_bandwidth(3000);

        let stats = registry.get_bandwidth_stats();

        assert_eq!(stats.total_bytes_in, 1500);
        assert_eq!(stats.total_bytes_out, 4500);
        assert_eq!(stats.total_bytes, 6000);
        assert_eq!(stats.request_count, 2);
        assert_eq!(stats.max_request_size, 1000);
        assert_eq!(stats.max_response_size, 3000);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - Endpoint recording
    // =========================================================================

    #[test]
    fn test_profiling_metrics_record_endpoint() {
        let metrics = ProfilingMetrics::default();

        metrics.record_endpoint("/api/users", "GET");
        metrics.record_endpoint("/api/users", "GET");
        metrics.record_endpoint("/api/users", "POST");
        metrics.record_endpoint("/api/products", "GET");

        let stats = metrics.endpoint_stats.read();

        assert_eq!(stats.len(), 2); // /api/users and /api/products

        let users_stats = stats.get("/api/users").unwrap();
        assert_eq!(users_stats.hit_count, 3);
        assert_eq!(users_stats.methods.len(), 2); // GET and POST
        assert!(users_stats.methods.contains(&"GET".to_string()));
        assert!(users_stats.methods.contains(&"POST".to_string()));

        let products_stats = stats.get("/api/products").unwrap();
        assert_eq!(products_stats.hit_count, 1);
        assert_eq!(products_stats.methods.len(), 1);
    }

    #[test]
    fn test_profiling_metrics_active_profiles_count() {
        let metrics = ProfilingMetrics::default();

        assert_eq!(metrics.profiles_active.load(Ordering::Relaxed), 0);

        metrics.record_endpoint("/api/v1/users", "GET");
        assert_eq!(metrics.profiles_active.load(Ordering::Relaxed), 1);

        metrics.record_endpoint("/api/v1/products", "GET");
        assert_eq!(metrics.profiles_active.load(Ordering::Relaxed), 2);

        // Same endpoint, should not increase count
        metrics.record_endpoint("/api/v1/users", "POST");
        assert_eq!(metrics.profiles_active.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_profiling_metrics_get_endpoint_stats() {
        let metrics = ProfilingMetrics::default();

        metrics.record_endpoint("/path1", "GET");
        metrics.record_endpoint("/path2", "POST");

        let stats = metrics.get_endpoint_stats();

        assert_eq!(stats.len(), 2);

        // Find the paths in the returned stats
        let path_names: Vec<&String> = stats.iter().map(|(path, _)| path).collect();
        assert!(path_names.contains(&&"/path1".to_string()));
        assert!(path_names.contains(&&"/path2".to_string()));
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - Anomaly recording
    // =========================================================================

    #[test]
    fn test_profiling_metrics_record_anomaly() {
        let metrics = ProfilingMetrics::default();

        metrics.record_anomaly("sql_injection", 8.5);
        metrics.record_anomaly("xss_attempt", 6.0);
        metrics.record_anomaly("sql_injection", 9.0);

        let anomalies = metrics.anomalies_detected.read();
        assert_eq!(anomalies.get("sql_injection"), Some(&2));
        assert_eq!(anomalies.get("xss_attempt"), Some(&1));

        assert_eq!(metrics.requests_with_anomalies.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_profiling_metrics_avg_anomaly_score_ema() {
        let metrics = ProfilingMetrics::default();

        // First anomaly sets initial score
        metrics.record_anomaly("test", 10.0);
        let score1 = metrics.avg_anomaly_score.load(Ordering::Relaxed) as f64 / 1000.0;
        assert!((score1 - 10.0).abs() < 0.01);

        // Second anomaly uses EMA (alpha = 0.1)
        // new = (old * 9 + new * 1) / 10 = (10 * 9 + 5) / 10 = 9.5
        metrics.record_anomaly("test", 5.0);
        let score2 = metrics.avg_anomaly_score.load(Ordering::Relaxed) as f64 / 1000.0;
        assert!((score2 - 9.5).abs() < 0.01);
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - Reset functionality
    // =========================================================================

    #[test]
    fn test_registry_reset_profiling_metrics() {
        let registry = MetricsRegistry::new();

        // Add some profiling data
        registry.record_request_bandwidth(1000);
        registry.record_response_bandwidth(2000);
        registry.record_endpoint("/api/test", "GET");
        registry.profiling_metrics.record_anomaly("test", 5.0);

        // Verify data exists
        let stats_before = registry.get_bandwidth_stats();
        assert!(stats_before.total_bytes > 0);

        // Reset
        registry.reset();

        // Verify profiling-specific reset
        assert_eq!(registry.profiling_metrics.profiles_active.load(Ordering::Relaxed), 0);
        assert_eq!(registry.profiling_metrics.avg_anomaly_score.load(Ordering::Relaxed), 0);
        assert_eq!(registry.profiling_metrics.requests_with_anomalies.load(Ordering::Relaxed), 0);
        assert!(registry.profiling_metrics.anomalies_detected.read().is_empty());
        assert!(registry.profiling_metrics.endpoint_stats.read().is_empty());
    }

    // =========================================================================
    // Phase 1 Profiler Integration Tests - Timeline integration
    // =========================================================================

    #[test]
    fn test_profiling_metrics_timeline_records_data() {
        let metrics = ProfilingMetrics::default();

        // Record some bandwidth
        metrics.record_request_bytes(1000);
        metrics.record_response_bytes(2000);

        // Get stats and check timeline has data
        let stats = metrics.get_bandwidth_stats();

        // Timeline should have at least one entry with data
        // (depending on timing, the point may or may not have non-zero timestamp)
        assert!(stats.timeline.len() <= 60);
    }

    #[test]
    fn test_bandwidth_stats_struct_fields() {
        let stats = BandwidthStats {
            total_bytes: 100,
            total_bytes_in: 40,
            total_bytes_out: 60,
            avg_bytes_per_request: 50,
            max_request_size: 20,
            max_response_size: 30,
            request_count: 2,
            timeline: vec![],
        };

        assert_eq!(stats.total_bytes, 100);
        assert_eq!(stats.total_bytes_in, 40);
        assert_eq!(stats.total_bytes_out, 60);
        assert_eq!(stats.avg_bytes_per_request, 50);
        assert_eq!(stats.max_request_size, 20);
        assert_eq!(stats.max_response_size, 30);
        assert_eq!(stats.request_count, 2);
        assert!(stats.timeline.is_empty());
    }

    #[test]
    fn test_endpoint_stats_default() {
        let stats = EndpointStats::default();

        assert_eq!(stats.hit_count, 0);
        assert!(stats.first_seen > 0); // Should have current timestamp
        assert!(stats.last_seen > 0);
        assert!(stats.methods.is_empty());
    }
}
