//! Payload profiling manager - coordinates endpoint and entity tracking.

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

use super::anomaly::{
    PayloadAnomaly, PayloadAnomalyMetadata, PayloadAnomalySeverity, PayloadAnomalyType,
};
use super::config::PayloadConfig;
use super::endpoint_stats::{EndpointPayloadStats, EndpointPayloadStatsSnapshot};
use super::entity_bandwidth::{EntityBandwidth, EntityBandwidthSnapshot};

/// Sort order for endpoint listings.
#[derive(Debug, Clone, Copy)]
pub enum EndpointSortBy {
    RequestBytes,
    ResponseBytes,
    RequestCount,
    LastSeen,
}

/// Summary statistics for the payload profiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSummary {
    pub total_endpoints: usize,
    pub total_entities: usize,
    pub total_requests: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub avg_request_size: f64,
    pub avg_response_size: f64,
    pub active_anomalies: usize,
}

/// Main payload profiling manager.
pub struct PayloadManager {
    config: PayloadConfig,
    /// Per-endpoint statistics
    endpoints: DashMap<String, RwLock<EndpointPayloadStats>>,
    /// Per-entity bandwidth tracking
    entities: DashMap<String, RwLock<EntityBandwidth>>,
    /// Recent anomalies
    anomalies: RwLock<Vec<PayloadAnomaly>>,
    /// Global counters
    total_requests: AtomicU64,
    total_request_bytes: AtomicU64,
    total_response_bytes: AtomicU64,
}

impl PayloadManager {
    /// Create a new payload manager.
    pub fn new(config: PayloadConfig) -> Self {
        Self {
            config,
            endpoints: DashMap::new(),
            entities: DashMap::new(),
            anomalies: RwLock::new(Vec::new()),
            total_requests: AtomicU64::new(0),
            total_request_bytes: AtomicU64::new(0),
            total_response_bytes: AtomicU64::new(0),
        }
    }

    /// Record a request/response pair.
    pub fn record_request(
        &self,
        template: &str,
        entity_id: &str,
        request_bytes: u64,
        response_bytes: u64,
    ) {
        // Update global counters
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_request_bytes
            .fetch_add(request_bytes, Ordering::Relaxed);
        self.total_response_bytes
            .fetch_add(response_bytes, Ordering::Relaxed);

        // Update endpoint stats
        self.record_endpoint(template, request_bytes, response_bytes);

        // Update entity bandwidth
        self.record_entity(entity_id, request_bytes, response_bytes);

        // Check for LRU eviction
        self.maybe_evict();
    }

    fn record_endpoint(&self, template: &str, request_bytes: u64, response_bytes: u64) {
        let entry = self
            .endpoints
            .entry(template.to_string())
            .or_insert_with(|| {
                RwLock::new(EndpointPayloadStats::new(
                    template.to_string(),
                    self.config.window_duration_ms,
                    self.config.max_windows,
                ))
            });
        entry.write().record(request_bytes, response_bytes);
    }

    fn record_entity(&self, entity_id: &str, request_bytes: u64, response_bytes: u64) {
        let entry = self
            .entities
            .entry(entity_id.to_string())
            .or_insert_with(|| {
                RwLock::new(EntityBandwidth::new(
                    entity_id.to_string(),
                    self.config.window_duration_ms,
                    self.config.max_windows,
                ))
            });
        entry.write().record(request_bytes, response_bytes);
    }

    fn maybe_evict(&self) {
        // Simple eviction: remove oldest if over capacity
        if self.endpoints.len() > self.config.max_endpoints {
            // Find entry with lowest access count
            let mut min_access = u64::MAX;
            let mut min_key = None;
            for entry in self.endpoints.iter() {
                let access = entry.value().read().access_count;
                if access < min_access {
                    min_access = access;
                    min_key = Some(entry.key().clone());
                }
            }
            if let Some(key) = min_key {
                self.endpoints.remove(&key);
            }
        }

        if self.entities.len() > self.config.max_entities {
            let mut min_access = u64::MAX;
            let mut min_key = None;
            for entry in self.entities.iter() {
                let access = entry.value().read().access_count;
                if access < min_access {
                    min_access = access;
                    min_key = Some(entry.key().clone());
                }
            }
            if let Some(key) = min_key {
                self.entities.remove(&key);
            }
        }
    }

    /// Check for anomalies across all endpoints and entities.
    pub fn check_anomalies(&self) -> Vec<PayloadAnomaly> {
        let mut detected = Vec::new();

        // Check for oversized payloads
        for entry in self.endpoints.iter() {
            let stats = entry.read();
            if stats.request_count() < self.config.warmup_requests as u64 {
                continue;
            }

            let req_stats = stats.request_stats();
            let resp_stats = stats.response_stats();

            // Check current requests against p99
            let req_threshold = req_stats.p99_bytes * self.config.oversize_threshold;
            let resp_threshold = resp_stats.p99_bytes * self.config.oversize_threshold;

            // We'd need to track individual requests to detect oversized ones
            // For now, detect if max >> p99 (indicating outliers exist)
            if req_stats.max_bytes as f64 > req_threshold
                && req_stats.max_bytes > self.config.min_large_payload_bytes
            {
                detected.push(PayloadAnomaly::new(
                    PayloadAnomalyType::OversizedRequest,
                    PayloadAnomalySeverity::Medium,
                    stats.template.clone(),
                    "unknown".to_string(),
                    format!(
                        "Oversized request detected: {} bytes (p99: {} bytes)",
                        req_stats.max_bytes, req_stats.p99_bytes as u64
                    ),
                    PayloadAnomalyMetadata::Oversize {
                        actual_bytes: req_stats.max_bytes,
                        expected_bytes: req_stats.p99_bytes as u64,
                        threshold: self.config.oversize_threshold,
                        percentile: 99.0,
                    },
                ));
            }

            if resp_stats.max_bytes as f64 > resp_threshold
                && resp_stats.max_bytes > self.config.min_large_payload_bytes
            {
                detected.push(PayloadAnomaly::new(
                    PayloadAnomalyType::OversizedResponse,
                    PayloadAnomalySeverity::Low,
                    stats.template.clone(),
                    "unknown".to_string(),
                    format!(
                        "Oversized response detected: {} bytes (p99: {} bytes)",
                        resp_stats.max_bytes, resp_stats.p99_bytes as u64
                    ),
                    PayloadAnomalyMetadata::Oversize {
                        actual_bytes: resp_stats.max_bytes,
                        expected_bytes: resp_stats.p99_bytes as u64,
                        threshold: self.config.oversize_threshold,
                        percentile: 99.0,
                    },
                ));
            }
        }

        // Check for bandwidth spikes per entity
        for entry in self.entities.iter() {
            let entity = entry.read();
            let current = entity.current_bytes_per_minute();
            let avg = entity.avg_bytes_per_minute();

            if avg > 0 && current as f64 > avg as f64 * self.config.bandwidth_spike_threshold {
                detected.push(PayloadAnomaly::new(
                    PayloadAnomalyType::BandwidthSpike,
                    PayloadAnomalySeverity::High,
                    "".to_string(),
                    entity.entity_id.clone(),
                    format!(
                        "Bandwidth spike: {} bytes/min (avg: {} bytes/min)",
                        current, avg
                    ),
                    PayloadAnomalyMetadata::BandwidthSpike {
                        current_bytes_per_min: current,
                        avg_bytes_per_min: avg,
                        threshold: self.config.bandwidth_spike_threshold,
                    },
                ));
            }

            // Check for exfiltration pattern
            if entity.total_request_count > self.config.warmup_requests as u64 {
                let avg_req = entity.total_request_bytes / entity.total_request_count;
                let avg_resp = entity.total_response_bytes / entity.total_request_count;

                if avg_req > 0 && avg_resp > self.config.min_large_payload_bytes {
                    let ratio = avg_resp as f64 / avg_req as f64;
                    if ratio > self.config.exfiltration_ratio_threshold {
                        detected.push(PayloadAnomaly::new(
                            PayloadAnomalyType::ExfiltrationPattern,
                            PayloadAnomalySeverity::Critical,
                            "".to_string(),
                            entity.entity_id.clone(),
                            format!("Exfiltration pattern: response/request ratio {:.1}x", ratio),
                            PayloadAnomalyMetadata::DataPattern {
                                request_bytes: avg_req,
                                response_bytes: avg_resp,
                                ratio,
                                threshold: self.config.exfiltration_ratio_threshold,
                            },
                        ));
                    }
                }

                // Check for upload pattern
                if avg_resp > 0 && avg_req > self.config.min_large_payload_bytes {
                    let ratio = avg_req as f64 / avg_resp as f64;
                    if ratio > self.config.upload_ratio_threshold {
                        detected.push(PayloadAnomaly::new(
                            PayloadAnomalyType::UploadPattern,
                            PayloadAnomalySeverity::High,
                            "".to_string(),
                            entity.entity_id.clone(),
                            format!("Upload pattern: request/response ratio {:.1}x", ratio),
                            PayloadAnomalyMetadata::DataPattern {
                                request_bytes: avg_req,
                                response_bytes: avg_resp,
                                ratio,
                                threshold: self.config.upload_ratio_threshold,
                            },
                        ));
                    }
                }
            }
        }

        // Store detected anomalies
        {
            let mut anomalies = self.anomalies.write();
            anomalies.extend(detected.clone());
            // Keep only recent anomalies (last 1000)
            let len = anomalies.len();
            if len > 1000 {
                anomalies.drain(0..len - 1000);
            }
        }

        detected
    }

    /// Get summary statistics.
    pub fn get_summary(&self) -> PayloadSummary {
        let total_requests = self.total_requests.load(Ordering::Relaxed);
        let total_request_bytes = self.total_request_bytes.load(Ordering::Relaxed);
        let total_response_bytes = self.total_response_bytes.load(Ordering::Relaxed);

        PayloadSummary {
            total_endpoints: self.endpoints.len(),
            total_entities: self.entities.len(),
            total_requests,
            total_request_bytes,
            total_response_bytes,
            avg_request_size: if total_requests > 0 {
                total_request_bytes as f64 / total_requests as f64
            } else {
                0.0
            },
            avg_response_size: if total_requests > 0 {
                total_response_bytes as f64 / total_requests as f64
            } else {
                0.0
            },
            active_anomalies: self.anomalies.read().len(),
        }
    }

    /// Get statistics for a specific endpoint.
    pub fn get_endpoint_stats(&self, template: &str) -> Option<EndpointPayloadStatsSnapshot> {
        self.endpoints
            .get(template)
            .map(|e| EndpointPayloadStatsSnapshot::from(&*e.read()))
    }

    /// Get bandwidth for a specific entity.
    pub fn get_entity_bandwidth(&self, entity_id: &str) -> Option<EntityBandwidthSnapshot> {
        self.entities
            .get(entity_id)
            .map(|e| EntityBandwidthSnapshot::from(&*e.read()))
    }

    /// List top endpoints by specified metric.
    pub fn list_top_endpoints(
        &self,
        limit: usize,
        sort_by: EndpointSortBy,
    ) -> Vec<EndpointPayloadStatsSnapshot> {
        let mut endpoints: Vec<_> = self
            .endpoints
            .iter()
            .map(|e| EndpointPayloadStatsSnapshot::from(&*e.read()))
            .collect();

        match sort_by {
            EndpointSortBy::RequestBytes => {
                endpoints.sort_by(|a, b| b.request.total_bytes.cmp(&a.request.total_bytes));
            }
            EndpointSortBy::ResponseBytes => {
                endpoints.sort_by(|a, b| b.response.total_bytes.cmp(&a.response.total_bytes));
            }
            EndpointSortBy::RequestCount => {
                endpoints.sort_by(|a, b| b.request_count.cmp(&a.request_count));
            }
            EndpointSortBy::LastSeen => {
                endpoints.sort_by(|a, b| b.last_seen_ms.cmp(&a.last_seen_ms));
            }
        }

        endpoints.truncate(limit);
        endpoints
    }

    /// List top entities by bandwidth.
    pub fn list_top_entities(&self, limit: usize) -> Vec<EntityBandwidthSnapshot> {
        let mut entities: Vec<_> = self
            .entities
            .iter()
            .map(|e| EntityBandwidthSnapshot::from(&*e.read()))
            .collect();

        entities.sort_by(|a, b| {
            let a_total = a.total_request_bytes + a.total_response_bytes;
            let b_total = b.total_request_bytes + b.total_response_bytes;
            b_total.cmp(&a_total)
        });

        entities.truncate(limit);
        entities
    }

    /// Get recent anomalies.
    pub fn get_anomalies(&self, limit: usize) -> Vec<PayloadAnomaly> {
        let anomalies = self.anomalies.read();
        anomalies.iter().rev().take(limit).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_stats() {
        let config = PayloadConfig::default();
        let manager = PayloadManager::new(config);

        manager.record_request("/api/users", "192.168.1.1", 100, 500);
        manager.record_request("/api/users", "192.168.1.1", 150, 600);
        manager.record_request("/api/users", "192.168.1.2", 200, 400);

        let summary = manager.get_summary();
        assert_eq!(summary.total_requests, 3);
        assert_eq!(summary.total_request_bytes, 450);
        assert_eq!(summary.total_response_bytes, 1500);
        assert_eq!(summary.total_endpoints, 1);
        assert_eq!(summary.total_entities, 2);
    }

    #[test]
    fn test_endpoint_stats() {
        let config = PayloadConfig::default();
        let manager = PayloadManager::new(config);

        for i in 0..10 {
            manager.record_request("/api/test", "10.0.0.1", 100 * i, 200 * i);
        }

        let stats = manager.get_endpoint_stats("/api/test").unwrap();
        assert_eq!(stats.template, "/api/test");
        assert_eq!(stats.request_count, 10);
    }

    #[test]
    fn test_entity_bandwidth() {
        let config = PayloadConfig::default();
        let manager = PayloadManager::new(config);

        manager.record_request("/api/a", "1.1.1.1", 1000, 2000);
        manager.record_request("/api/b", "1.1.1.1", 500, 1000);

        let bandwidth = manager.get_entity_bandwidth("1.1.1.1").unwrap();
        assert_eq!(bandwidth.entity_id, "1.1.1.1");
        assert_eq!(bandwidth.total_request_bytes, 1500);
        assert_eq!(bandwidth.total_response_bytes, 3000);
    }
}
