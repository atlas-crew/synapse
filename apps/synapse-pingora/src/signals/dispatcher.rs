use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::horizon::{SignalSink, ThreatSignal};
use crate::intelligence::{SignalCategory, SignalManager};
use crate::metrics::MetricsRegistry;

/// SignalDispatcher - coordinates signal dispatch between sinks and local SignalManager.
pub struct SignalDispatcher {
    sinks: Vec<Arc<dyn SignalSink>>,
    signal_manager: Option<Arc<SignalManager>>,
    metrics: Arc<MetricsRegistry>,
    dispatch_semaphore: Arc<Semaphore>,
}

impl SignalDispatcher {
    pub fn new(
        sinks: Vec<Arc<dyn SignalSink>>,
        signal_manager: Option<Arc<SignalManager>>,
        metrics: Arc<MetricsRegistry>,
    ) -> Self {
        Self {
            sinks,
            signal_manager,
            metrics,
            dispatch_semaphore: Arc::new(Semaphore::new(100)), // Limit to 100 concurrent dispatches
        }
    }

    /// Dispatch a signal to all sinks and local SignalManager in parallel.
    pub async fn dispatch(
        &self,
        signal: ThreatSignal,
        category: SignalCategory,
        sensor_id: &str,
        description: Option<String>,
        metadata: serde_json::Value,
    ) -> Result<(), String> {
        // Acquire permit to limit concurrency
        let _permit = self
            .dispatch_semaphore
            .acquire()
            .await
            .map_err(|e| format!("Dispatcher semaphore closed: {}", e))?;

        self.metrics.signal_dispatch_metrics().record_attempt();
        let start = std::time::Instant::now();

        // Prepare sink dispatch tasks
        let mut sink_tasks = Vec::new();
        for sink in &self.sinks {
            let sink_clone = Arc::clone(sink);
            let signal_clone = signal.clone();
            sink_tasks.push(async move { sink_clone.report_signal(signal_clone).await });
        }

        // Combine sink dispatches into a single future
        let sinks_dispatch = async move {
            let mut all_success = true;
            for task in sink_tasks {
                match timeout(Duration::from_millis(500), task).await {
                    Ok(Ok(())) => debug!("Signal dispatched to sink"),
                    Ok(Err(err)) => {
                        warn!("Sink dispatch failed: {}", err);
                        all_success = false;
                    }
                    Err(_) => {
                        warn!("Sink dispatch timed out");
                        all_success = false;
                    }
                }
            }
            all_success
        };

        // Prepare local dispatch task
        let signal_manager = self.signal_manager.clone();
        let signal_type = format!("{:?}", signal.signal_type);
        let entity_id = signal.source_ip.clone();
        let local_metadata = metadata.clone();
        let local_dispatch = async move {
            if let Some(manager) = signal_manager {
                manager.record_event(
                    category,
                    signal_type,
                    entity_id,
                    description,
                    local_metadata,
                );
                true
            } else {
                false
            }
        };

        // Execute in parallel
        let (sinks_success, local_res) = tokio::join!(
            sinks_dispatch,
            timeout(Duration::from_millis(100), local_dispatch)
        );

        let local_success = match local_res {
            Ok(success) => success,
            Err(_) => {
                warn!("Local signal manager dispatch timed out");
                false
            }
        };

        if local_success {
            self.metrics
                .signal_dispatch_metrics()
                .record_success(start.elapsed().as_micros() as u64);

            if sinks_success {
                info!(
                    sensor_id = %sensor_id,
                    signal_type = %format!("{:?}", signal.signal_type),
                    "Signal successfully dispatched to all sinks and Local Manager"
                );
            } else {
                info!(
                    sensor_id = %sensor_id,
                    signal_type = %format!("{:?}", signal.signal_type),
                    "Signal dispatched to Local Manager (partial or complete sink failure)"
                );
            }
            Ok(())
        } else {
            self.metrics.signal_dispatch_metrics().record_failure();
            Err("Local dispatch failure (SignalManager unavailable)".to_string())
        }
    }
}
