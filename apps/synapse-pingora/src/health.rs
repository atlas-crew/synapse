//! Health check endpoint for monitoring and load balancer integration.
//!
//! Provides service status reporting compatible with the `/_sensor/status` nginx pattern.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use tracing::debug;

/// Maximum number of recent responses to track per backend.
const MAX_RESPONSE_HISTORY: usize = 100;

/// Health status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Partial degradation
    Degraded,
    /// Service unavailable
    Unhealthy,
}

impl HealthStatus {
    /// Returns the HTTP status code for this health status.
    pub fn http_status(&self) -> u16 {
        match self {
            HealthStatus::Healthy => 200,
            HealthStatus::Degraded => 200, // Still returns 200 but indicates degradation
            HealthStatus::Unhealthy => 503,
        }
    }
}

/// Statistics for a single backend.
#[derive(Debug, Clone)]
pub struct BackendStats {
    /// Total requests sent
    pub total_requests: u64,
    /// Successful responses (2xx, 3xx)
    pub successful_responses: u64,
    /// Failed responses (4xx, 5xx, timeouts)
    pub failed_responses: u64,
    /// Average response time in microseconds
    pub avg_response_time_us: u64,
    /// Recent response times for calculating rolling average
    recent_times: Vec<u64>,
    /// Whether backend is currently healthy
    pub healthy: bool,
}

impl Default for BackendStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            successful_responses: 0,
            failed_responses: 0,
            avg_response_time_us: 0,
            recent_times: Vec::with_capacity(MAX_RESPONSE_HISTORY),
            healthy: true,
        }
    }
}

impl BackendStats {
    /// Records a response and updates statistics.
    pub fn record_response(&mut self, success: bool, response_time_us: u64) {
        self.total_requests += 1;

        if success {
            self.successful_responses += 1;
        } else {
            self.failed_responses += 1;
        }

        // Update rolling average
        if self.recent_times.len() >= MAX_RESPONSE_HISTORY {
            self.recent_times.remove(0);
        }
        self.recent_times.push(response_time_us);

        // Calculate average
        if !self.recent_times.is_empty() {
            self.avg_response_time_us =
                self.recent_times.iter().sum::<u64>() / self.recent_times.len() as u64;
        }

        // Update health based on success rate (>50% success = healthy)
        let success_rate = if self.total_requests > 0 {
            self.successful_responses as f64 / self.total_requests as f64
        } else {
            1.0
        };
        self.healthy = success_rate > 0.5;
    }

    /// Returns the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            100.0
        } else {
            (self.successful_responses as f64 / self.total_requests as f64) * 100.0
        }
    }
}

/// WAF statistics using atomic counters for lock-free updates.
#[derive(Debug, Default)]
pub struct WafStats {
    /// Total requests analyzed
    pub analyzed: AtomicU64,
    /// Requests blocked
    pub blocked: AtomicU64,
    /// Requests allowed
    pub allowed: AtomicU64,
    /// Total detection time in microseconds
    pub total_detection_time_us: AtomicU64,
}

impl WafStats {
    /// Records a WAF analysis result.
    pub fn record(&self, blocked: bool, detection_time_us: u64) {
        self.analyzed.fetch_add(1, Ordering::Relaxed);
        self.total_detection_time_us.fetch_add(detection_time_us, Ordering::Relaxed);

        if blocked {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        } else {
            self.allowed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns the block rate as a percentage.
    pub fn block_rate(&self) -> f64 {
        let analyzed = self.analyzed.load(Ordering::Relaxed);
        if analyzed == 0 {
            0.0
        } else {
            (self.blocked.load(Ordering::Relaxed) as f64 / analyzed as f64) * 100.0
        }
    }

    /// Returns the average detection time in microseconds.
    pub fn avg_detection_time_us(&self) -> u64 {
        let analyzed = self.analyzed.load(Ordering::Relaxed);
        if analyzed == 0 {
            0
        } else {
            self.total_detection_time_us.load(Ordering::Relaxed) / analyzed
        }
    }
}

/// Health check response structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall health status
    pub status: HealthStatus,
    /// Service uptime in seconds
    pub uptime_secs: u64,
    /// Backend health summary
    pub backends: BackendHealthSummary,
    /// WAF statistics summary
    pub waf: WafHealthSummary,
    /// Version information (redacted in production)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Summary of backend health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendHealthSummary {
    /// Number of healthy backends
    pub healthy: usize,
    /// Number of unhealthy backends
    pub unhealthy: usize,
    /// Total number of backends
    pub total: usize,
}

/// Summary of WAF health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafHealthSummary {
    /// Whether WAF is enabled
    pub enabled: bool,
    /// Requests analyzed
    pub analyzed: u64,
    /// Requests blocked
    pub blocked: u64,
    /// Block rate percentage
    pub block_rate_percent: f64,
    /// Average detection time in microseconds
    pub avg_detection_us: u64,
}

/// Health checker with backend and WAF monitoring.
pub struct HealthChecker {
    /// Service start time
    start_time: Instant,
    /// Backend statistics (backend_addr -> stats)
    backend_stats: Arc<RwLock<HashMap<String, BackendStats>>>,
    /// WAF statistics
    waf_stats: Arc<WafStats>,
    /// Whether to include version in response
    include_version: bool,
    /// Service version
    version: String,
}

impl HealthChecker {
    /// Creates a new health checker.
    pub fn new(include_version: bool) -> Self {
        Self {
            start_time: Instant::now(),
            backend_stats: Arc::new(RwLock::new(HashMap::new())),
            waf_stats: Arc::new(WafStats::default()),
            include_version,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Returns a reference to the WAF stats for recording.
    pub fn waf_stats(&self) -> Arc<WafStats> {
        Arc::clone(&self.waf_stats)
    }

    /// Records a backend response.
    pub fn record_backend_response(&self, backend: &str, success: bool, response_time_us: u64) {
        let mut stats = self.backend_stats.write();
        let entry = stats.entry(backend.to_string()).or_default();
        entry.record_response(success, response_time_us);
    }

    /// Registers a backend for health tracking.
    pub fn register_backend(&self, backend: &str) {
        let mut stats = self.backend_stats.write();
        stats.entry(backend.to_string()).or_default();
    }

    /// Generates the health check response.
    pub fn check(&self) -> HealthResponse {
        let uptime = self.start_time.elapsed();

        // Calculate backend health
        let stats = self.backend_stats.read();
        let total = stats.len();
        let healthy = stats.values().filter(|s| s.healthy).count();
        let unhealthy = total - healthy;

        // Calculate WAF health
        let waf_analyzed = self.waf_stats.analyzed.load(Ordering::Relaxed);
        let waf_blocked = self.waf_stats.blocked.load(Ordering::Relaxed);

        // Determine overall status
        let status = if unhealthy == total && total > 0 {
            HealthStatus::Unhealthy
        } else if unhealthy > 0 || self.waf_stats.block_rate() > 50.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        debug!(
            "Health check: status={:?}, backends={}/{} healthy, waf_block_rate={:.1}%",
            status, healthy, total, self.waf_stats.block_rate()
        );

        HealthResponse {
            status,
            uptime_secs: uptime.as_secs(),
            backends: BackendHealthSummary {
                healthy,
                unhealthy,
                total,
            },
            waf: WafHealthSummary {
                enabled: true,
                analyzed: waf_analyzed,
                blocked: waf_blocked,
                block_rate_percent: self.waf_stats.block_rate(),
                avg_detection_us: self.waf_stats.avg_detection_time_us(),
            },
            version: if self.include_version {
                Some(self.version.clone())
            } else {
                None
            },
        }
    }

    /// Returns the uptime duration.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Serializes the health response to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.check()).unwrap_or_else(|_| {
            r#"{"status":"unhealthy","error":"serialization failed"}"#.to_string()
        })
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new(false) // Don't include version by default (security)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_http_codes() {
        assert_eq!(HealthStatus::Healthy.http_status(), 200);
        assert_eq!(HealthStatus::Degraded.http_status(), 200);
        assert_eq!(HealthStatus::Unhealthy.http_status(), 503);
    }

    #[test]
    fn test_backend_stats_recording() {
        let mut stats = BackendStats::default();

        // Record some successful responses
        stats.record_response(true, 100);
        stats.record_response(true, 200);
        stats.record_response(true, 150);

        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.successful_responses, 3);
        assert_eq!(stats.failed_responses, 0);
        assert!(stats.healthy);
        assert_eq!(stats.success_rate(), 100.0);
    }

    #[test]
    fn test_backend_stats_unhealthy() {
        let mut stats = BackendStats::default();

        // Record mostly failures
        stats.record_response(false, 100);
        stats.record_response(false, 200);
        stats.record_response(true, 150);

        assert_eq!(stats.total_requests, 3);
        assert!(!stats.healthy); // <50% success rate
    }

    #[test]
    fn test_waf_stats_recording() {
        let stats = WafStats::default();

        stats.record(true, 100);  // blocked
        stats.record(false, 50);  // allowed
        stats.record(false, 50);  // allowed

        assert_eq!(stats.analyzed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.blocked.load(Ordering::Relaxed), 1);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 2);

        // Block rate should be ~33%
        let rate = stats.block_rate();
        assert!(rate > 33.0 && rate < 34.0);
    }

    #[test]
    fn test_health_checker_initial_state() {
        let checker = HealthChecker::default();
        let response = checker.check();

        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.backends.total, 0);
        assert!(response.version.is_none());
    }

    #[test]
    fn test_health_checker_with_version() {
        let checker = HealthChecker::new(true);
        let response = checker.check();

        assert!(response.version.is_some());
    }

    #[test]
    fn test_health_checker_backend_recording() {
        let checker = HealthChecker::default();

        checker.register_backend("127.0.0.1:8080");
        checker.record_backend_response("127.0.0.1:8080", true, 100);
        checker.record_backend_response("127.0.0.1:8080", true, 200);

        let response = checker.check();
        assert_eq!(response.backends.total, 1);
        assert_eq!(response.backends.healthy, 1);
    }

    #[test]
    fn test_health_checker_degraded() {
        let checker = HealthChecker::default();

        checker.register_backend("127.0.0.1:8080");
        checker.register_backend("127.0.0.1:8081");

        // Make one backend unhealthy
        checker.record_backend_response("127.0.0.1:8080", true, 100);
        checker.record_backend_response("127.0.0.1:8081", false, 100);
        checker.record_backend_response("127.0.0.1:8081", false, 100);

        let response = checker.check();
        assert_eq!(response.status, HealthStatus::Degraded);
        assert_eq!(response.backends.healthy, 1);
        assert_eq!(response.backends.unhealthy, 1);
    }

    #[test]
    fn test_health_checker_unhealthy() {
        let checker = HealthChecker::default();

        checker.register_backend("127.0.0.1:8080");

        // Make backend unhealthy
        checker.record_backend_response("127.0.0.1:8080", false, 100);
        checker.record_backend_response("127.0.0.1:8080", false, 100);

        let response = checker.check();
        assert_eq!(response.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_checker_json() {
        let checker = HealthChecker::default();
        let json = checker.to_json();

        assert!(json.contains("\"status\""));
        assert!(json.contains("\"uptime_secs\""));
        assert!(json.contains("\"backends\""));
        assert!(json.contains("\"waf\""));
    }

    #[test]
    fn test_waf_stats_avg_detection_time() {
        let stats = WafStats::default();

        stats.record(false, 100);
        stats.record(false, 200);
        stats.record(false, 300);

        assert_eq!(stats.avg_detection_time_us(), 200);
    }

    #[test]
    fn test_backend_stats_rolling_average() {
        let mut stats = BackendStats::default();

        // Fill up the history
        for i in 0..MAX_RESPONSE_HISTORY + 10 {
            stats.record_response(true, (i * 10) as u64);
        }

        // Should only keep last MAX_RESPONSE_HISTORY entries
        assert_eq!(stats.recent_times.len(), MAX_RESPONSE_HISTORY);
    }
}
