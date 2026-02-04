//! Tunnel protocol types for Signal Horizon tunnel client.

use serde::{Deserialize, Serialize};

/// Connection state for the tunnel client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting,
    Error,
}

/// Supported tunnel channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelChannel {
    Shell,
    Logs,
    Diag,
    Control,
    Files,
    Update,
}

impl TunnelChannel {
    pub const ALL: [TunnelChannel; 6] = [
        TunnelChannel::Shell,
        TunnelChannel::Logs,
        TunnelChannel::Diag,
        TunnelChannel::Control,
        TunnelChannel::Files,
        TunnelChannel::Update,
    ];
}

/// Metadata included during tunnel authentication.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelAuthMetadata {
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
}

/// Authentication payload for the tunnel client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAuthPayload {
    #[serde(rename = "sensorId")]
    pub sensor_id: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TunnelAuthMetadata>,
}

/// Tunnel authentication message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAuthMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub payload: TunnelAuthPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

/// Envelope for channel-based messages.
#[derive(Debug, Clone)]
pub struct TunnelEnvelope {
    pub channel: TunnelChannel,
    pub session_id: Option<String>,
    pub sequence_id: Option<u64>,
    pub timestamp: Option<i64>,
    pub raw: serde_json::Value,
}

/// Legacy tunnel message structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTunnelMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default, rename = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, rename = "requestId")]
    pub request_id: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub timestamp: Option<String>,
}
