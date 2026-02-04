use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::interval;
use tracing::warn;

use crate::signals::auth_coverage::{
    AuthCoverageSummary, EndpointCounts, EndpointSummary, ResponseClass,
};
use crate::telemetry::SignalEmitter;

/// Edge aggregator - maintains local counts, flushes to Hub periodically
pub struct AuthCoverageAggregator {
    sensor_id: String,
    tenant_id: Option<String>,
    counts: Arc<RwLock<HashMap<String, EndpointCounts>>>,
    emitter: Arc<dyn SignalEmitter>,
    flush_interval: Duration,
}

impl AuthCoverageAggregator {
    pub fn new(
        sensor_id: String,
        tenant_id: Option<String>,
        emitter: Arc<dyn SignalEmitter>,
        flush_interval_secs: u64,
    ) -> Self {
        Self {
            sensor_id,
            tenant_id,
            counts: Arc::new(RwLock::new(HashMap::new())),
            emitter,
            flush_interval: Duration::from_secs(flush_interval_secs),
        }
    }
    
    /// Record a request (called from response filter, must be fast)
    pub fn record(
        &self,
        endpoint: &str,
        response_class: ResponseClass,
        has_auth_header: bool,
    ) {
        let mut counts = self.counts.write().unwrap();
        let entry = counts.entry(endpoint.to_string()).or_default();
        
        entry.total += 1;
        
        match response_class {
            ResponseClass::Success => entry.success += 1,
            ResponseClass::Unauthorized => entry.unauthorized += 1,
            ResponseClass::Forbidden => entry.forbidden += 1,
            _ => entry.other_error += 1,
        }
        
        if has_auth_header {
            entry.with_auth += 1;
        } else {
            entry.without_auth += 1;
        }
    }
    
    /// Start background flush task
    pub fn start_flush_task(self: Arc<Self>) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!("Auth coverage flush task skipped (no Tokio runtime)");
            return;
        };
        let aggregator = self.clone();

        handle.spawn(async move {
            let mut ticker = interval(aggregator.flush_interval);
            
            loop {
                ticker.tick().await;
                aggregator.flush().await;
            }
        });
    }
    
    /// Flush current counts to Hub and reset
    async fn flush(&self) {
        // Swap out current counts atomically
        let counts = {
            let mut guard = self.counts.write().unwrap();
            std::mem::take(&mut *guard)
        };
        
        if counts.is_empty() {
            return; // Nothing to send
        }
        
        let summary = AuthCoverageSummary {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            sensor_id: self.sensor_id.clone(),
            tenant_id: self.tenant_id.clone(),
            endpoints: counts
                .into_iter()
                .map(|(endpoint, counts)| EndpointSummary { endpoint, counts })
                .collect(),
        };
        
        if let Ok(payload) = serde_json::to_value(&summary) {
            self.emitter.emit("auth_coverage_summary", payload).await;
        }
    }
    
    /// Get current endpoint count (for testing/debugging)
    #[cfg(test)]
    pub fn endpoint_count(&self) -> usize {
        self.counts.read().unwrap().len()
    }
    
    /// Force flush (for testing)
    #[cfg(test)]
    pub async fn force_flush(&self) {
        self.flush().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use async_trait::async_trait;
    
    // Mock emitter for testing
    struct MockEmitter {
        emit_count: AtomicUsize,
    }
    
    impl MockEmitter {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                emit_count: AtomicUsize::new(0),
            })
        }
        
        fn count(&self) -> usize {
            self.emit_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SignalEmitter for MockEmitter {
        async fn emit(&self, _signal_type: &str, _payload: serde_json::Value) {
            self.emit_count.fetch_add(1, Ordering::SeqCst);
        }
    }
    
    #[test]
    fn test_record_increments_counts() {
        let emitter = MockEmitter::new();
        let aggregator = AuthCoverageAggregator::new(
            "test-sensor".to_string(),
            None,
            emitter.clone() as Arc<dyn SignalEmitter>, 
            60,
        );
        
        aggregator.record("GET /api/users/{id}", ResponseClass::Success, true);
        aggregator.record("GET /api/users/{id}", ResponseClass::Success, true);
        aggregator.record("GET /api/users/{id}", ResponseClass::Forbidden, true);
        
        assert_eq!(aggregator.endpoint_count(), 1);
    }
    
    #[tokio::test]
    async fn test_flush_clears_counts() {
        let emitter = MockEmitter::new();
        let aggregator = AuthCoverageAggregator::new(
            "test-sensor".to_string(),
            None,
            emitter.clone() as Arc<dyn SignalEmitter>, 
            60,
        );
        
        aggregator.record("GET /api/users/{id}", ResponseClass::Success, true);
        assert_eq!(aggregator.endpoint_count(), 1);
        
        aggregator.flush().await;
        assert_eq!(aggregator.endpoint_count(), 0);
        assert_eq!(emitter.count(), 1);
    }
    
    #[tokio::test]
    async fn test_empty_flush_no_emit() {
        let emitter = MockEmitter::new();
        let aggregator = AuthCoverageAggregator::new(
            "test-sensor".to_string(),
            None,
            emitter.clone() as Arc<dyn SignalEmitter>, 
            60,
        );
        
        aggregator.flush().await;
        assert_eq!(emitter.count(), 0);
    }
}
