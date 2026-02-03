//! Signal Horizon protocol types for sensor ↔ hub communication.

use serde::{Deserialize, Serialize};

// =============================================================================
// Signal Types (Outbound: Sensor → Hub)
// =============================================================================

/// Types of threat signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalType {
    IpThreat,
    FingerprintThreat,
    CampaignIndicator,
    CredentialStuffing,
    RateAnomaly,
    BotSignature,
    ImpossibleTravel,
    TemplateDiscovery,
    SchemaViolation,
}

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A threat signal to report to the hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreatSignal {
    pub signal_type: SignalType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl ThreatSignal {
    /// Create a new threat signal.
    pub fn new(signal_type: SignalType, severity: Severity) -> Self {
        Self {
            signal_type,
            source_ip: None,
            fingerprint: None,
            severity,
            confidence: 1.0,
            event_count: None,
            metadata: None,
        }
    }

    /// Set the source IP.
    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    /// Set the fingerprint.
    pub fn with_fingerprint(mut self, fp: &str) -> Self {
        self.fingerprint = Some(fp.to_string());
        self
    }

    /// Set the confidence score.
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set the event count.
    pub fn with_event_count(mut self, count: u32) -> Self {
        self.event_count = Some(count);
        self
    }

    /// Set metadata.
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

// =============================================================================
// Sensor Messages (Outbound)
// =============================================================================

/// Heartbeat payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatPayload {
    pub timestamp: i64,
    pub status: String,
    pub cpu: f64,
    pub memory: f64,
    pub disk: f64,
    pub requests_last_minute: u64,
    pub avg_latency_ms: f64,
    pub config_hash: String,
    pub rules_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_connections: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocklist_size: Option<usize>,
}

/// Messages from sensor to hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SensorMessage {
    /// Authentication request
    Auth {
        payload: AuthPayload,
    },
    /// Single signal
    Signal {
        payload: ThreatSignal,
    },
    /// Batch of signals
    SignalBatch {
        payload: Vec<ThreatSignal>,
    },
    /// Pong response
    Pong,
    /// Request blocklist sync
    BlocklistSync,
    /// Heartbeat
    Heartbeat {
        payload: HeartbeatPayload,
    },
    /// Command Acknowledgment
    CommandAck {
        payload: CommandAckPayload,
    },
}

/// Authentication payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthPayload {
    pub api_key: String,
    pub sensor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensor_name: Option<String>,
    pub version: String,
}

/// Command Acknowledgment payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandAckPayload {
    pub command_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl SensorMessage {
    /// Convert to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// =============================================================================
// Hub Messages (Inbound)
// =============================================================================

/// Configuration payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Messages from hub to sensor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HubMessage {
    /// Authentication success
    AuthSuccess {
        #[serde(rename = "sensorId")]
        sensor_id: String,
        #[serde(rename = "tenantId")]
        tenant_id: String,
        capabilities: Vec<String>,
    },
    /// Authentication failed
    AuthFailed {
        error: String,
    },
    /// Signal acknowledged
    SignalAck {
        #[serde(rename = "sequenceId")]
        sequence_id: u64,
    },
    /// Batch acknowledged
    BatchAck {
        count: u32,
        #[serde(rename = "sequenceId")]
        sequence_id: u64,
    },
    /// Ping (requires pong response)
    Ping {
        timestamp: i64,
    },
    /// Error from hub
    Error {
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    /// Full blocklist snapshot
    BlocklistSnapshot {
        entries: Vec<super::blocklist::BlocklistEntry>,
        #[serde(rename = "sequenceId")]
        sequence_id: u64,
    },
    /// Incremental blocklist update
    BlocklistUpdate {
        updates: Vec<super::blocklist::BlocklistUpdate>,
        #[serde(rename = "sequenceId")]
        sequence_id: u64,
    },
    /// Configuration update (Legacy/Direct)
    ConfigUpdate {
        config: serde_json::Value,
        version: String,
    },
    /// Rules update
    RulesUpdate {
        rules: serde_json::Value,
        version: String,
    },
    /// Push Config Command (via CommandSender)
    #[serde(rename = "push_config")]
    PushConfig {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: ConfigPayload,
    },
    /// Push Rules Command (via CommandSender)
    #[serde(rename = "push_rules")]
    PushRules {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: serde_json::Value,
    },
    /// Restart Command (via CommandSender)
    #[serde(rename = "restart")]
    Restart {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: serde_json::Value,
    },
    /// Collect Diagnostics Command (via CommandSender)
    #[serde(rename = "collect_diagnostics")]
    CollectDiagnostics {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: serde_json::Value,
    },
    /// Update Command (via CommandSender)
    #[serde(rename = "update")]
    Update {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: serde_json::Value,
    },
    /// Sync Blocklist Command (via CommandSender)
    #[serde(rename = "sync_blocklist")]
    SyncBlocklist {
        #[serde(rename = "commandId")]
        command_id: String,
        payload: serde_json::Value,
    },
}

impl HubMessage {
    /// Parse from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// =============================================================================
// Connection State
// =============================================================================

/// Connection state for the Horizon client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
    Degraded,
    Error,
}

impl ConnectionState {
    /// Get a string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "disconnected",
            ConnectionState::Connecting => "connecting",
            ConnectionState::Authenticating => "authenticating",
            ConnectionState::Connected => "connected",
            ConnectionState::Reconnecting => "reconnecting",
            ConnectionState::Degraded => "degraded",
            ConnectionState::Error => "error",
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_signal_builder() {
        let signal = ThreatSignal::new(SignalType::IpThreat, Severity::High)
            .with_source_ip("192.168.1.100")
            .with_confidence(0.95)
            .with_event_count(50);

        assert_eq!(signal.signal_type, SignalType::IpThreat);
        assert_eq!(signal.severity, Severity::High);
        assert_eq!(signal.source_ip, Some("192.168.1.100".to_string()));
        assert_eq!(signal.confidence, 0.95);
        assert_eq!(signal.event_count, Some(50));
    }

    #[test]
    fn test_sensor_message_serialization() {
        let msg = SensorMessage::Signal {
            payload: ThreatSignal::new(SignalType::BotSignature, Severity::Medium),
        };

        let json = msg.to_json().unwrap();
        assert!(json.contains("\"type\":\"signal\""));
        assert!(json.contains("BOT_SIGNATURE"));
    }

    #[test]
    fn test_hub_message_deserialization() {
        let json = r#"{"type":"auth-success","sensorId":"s1","tenantId":"t1","capabilities":["signals"]}"#;
        let msg = HubMessage::from_json(json).unwrap();

        match msg {
            HubMessage::AuthSuccess {
                sensor_id,
                tenant_id,
                capabilities,
            } => {
                assert_eq!(sensor_id, "s1");
                assert_eq!(tenant_id, "t1");
                assert_eq!(capabilities, vec!["signals"]);
            }
            _ => panic!("Expected AuthSuccess"),
        }
    }

    #[test]
    fn test_hub_message_push_rules_deserialization() {
        let json = r#"{"type":"push_rules","commandId":"cmd-1","payload":{"rules":[]}}"#;
        let msg = HubMessage::from_json(json).unwrap();

        match msg {
            HubMessage::PushRules { command_id, payload } => {
                assert_eq!(command_id, "cmd-1");
                assert!(payload.get("rules").is_some());
            }
            _ => panic!("Expected PushRules"),
        }
    }

    #[test]
    fn test_confidence_clamping() {
        let signal = ThreatSignal::new(SignalType::IpThreat, Severity::Low).with_confidence(1.5);
        assert_eq!(signal.confidence, 1.0);

        let signal = ThreatSignal::new(SignalType::IpThreat, Severity::Low).with_confidence(-0.5);
        assert_eq!(signal.confidence, 0.0);
    }
}
