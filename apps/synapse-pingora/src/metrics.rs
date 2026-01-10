//! Prometheus metrics endpoint for observability.
//!
//! Provides a `/metrics` endpoint compatible with Prometheus scraping,
//! exposing request counts, latencies, WAF statistics, and backend health.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Metrics registry holding all metric collectors.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    /// Request counters by status code
    request_counts: RequestCounters,
    /// Latency histograms
    latencies: LatencyHistogram,
    /// WAF-specific metrics
    waf_metrics: WafMetrics,
    /// Profiling metrics (Phase 2)
    profiling_metrics: ProfilingMetrics,
    /// Backend health metrics
    backend_metrics: Arc<RwLock<HashMap<String, BackendMetrics>>>,
    /// Registry start time for uptime calculation
    start_time: Option<Instant>,
}

/// Profiling and anomaly detection metrics (Phase 2).
#[derive(Debug, Default)]
pub struct ProfilingMetrics {
    /// Active endpoint profiles
    pub profiles_active: AtomicU64,
    /// Anomalies detected by type
    pub anomalies_detected: Arc<RwLock<HashMap<String, u64>>>,
    /// Average anomaly score
    pub avg_anomaly_score: AtomicU64, // Scaled by 1000
    /// Requests with anomalies
    pub requests_with_anomalies: AtomicU64,
}

impl ProfilingMetrics {
    /// Update active profiles count.
    pub fn set_active_profiles(&self, count: u64) {
        self.profiles_active.store(count, Ordering::Relaxed);
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

    /// Records WAF metrics.
    pub fn record_waf(&self, blocked: bool, challenged: bool, logged: bool, detection_us: u64) {
        self.waf_metrics.record(blocked, challenged, logged, detection_us);
    }

    /// Records a rule match.
    pub fn record_rule_match(&self, rule_id: &str) {
        self.waf_metrics.record_rule_match(rule_id);
    }

    /// Records profiling metrics (Phase 2).
    pub fn record_profile_metrics(&self, active_profiles: usize, anomalies: &[(String, f64)]) {
        self.profiling_metrics.set_active_profiles(active_profiles as u64);
        for (anomaly_type, score) in anomalies {
            self.profiling_metrics.record_anomaly(anomaly_type, *score);
        }
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

        // Uptime
        output.push_str("# HELP synapse_uptime_seconds Service uptime in seconds\n");
        output.push_str("# TYPE synapse_uptime_seconds gauge\n");
        output.push_str(&format!("synapse_uptime_seconds {}\n", self.uptime_secs()));

        output
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
}
