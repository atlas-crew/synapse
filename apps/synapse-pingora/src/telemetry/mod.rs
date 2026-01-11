//! Telemetry module for forwarding security events to the Risk Server.
//!
//! Uses a background thread and a bounded channel to buffer events
//! before sending them to the central collector to ensure zero impact
//! on proxy latency.

use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use log::{error, info, warn};
use reqwest::Client;

/// Security event to report to the Risk Server.
#[derive(Debug, Serialize, Clone)]
pub struct SecurityEvent {
    pub sensor_id: String,
    pub timestamp: String,
    pub actor: ActorContext,
    pub signal: SignalContext,
    pub request: RequestContext,
}

#[derive(Debug, Serialize, Clone)]
pub struct ActorContext {
    pub ip: String,
    pub session_id: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SignalContext {
    pub type_: String, // e.g., "sqli_attack", "behavioral_anomaly"
    pub severity: String, // "low", "medium", "high", "critical"
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
pub struct RequestContext {
    pub path: String,
    pub method: String,
    pub user_agent: Option<String>,
}

/// Alert Forwarder Service
pub struct AlertForwarder {
    sender: mpsc::Sender<SecurityEvent>,
}

impl AlertForwarder {
    /// Create and start the background forwarder.
    pub fn new(risk_server_url: String, sensor_id: String) -> Self {
        let (tx, mut rx) = mpsc::channel(1024); // Buffer up to 1024 events
        let client = Client::new();
        let target_url = format!("{}/_sensor/report", risk_server_url);

        info!("Starting Alert Forwarder (Target: {})", target_url);

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // In a real high-scale system, we would batch these.
                // For now, we send 1:1 but async.
                let result = client.post(&target_url)
                    .json(&event)
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await;

                if let Err(e) = result {
                    warn!("Failed to send security alert: {}", e);
                }
            }
        });

        Self { sender: tx }
    }

    /// Submit an event (Non-blocking)
    pub fn send(&self, event: SecurityEvent) {
        // Try to send, drop if channel full (shed load under extreme pressure)
        if let Err(_) = self.sender.try_send(event) {
            warn!("Alert buffer full! Dropping security event.");
        }
    }
}
