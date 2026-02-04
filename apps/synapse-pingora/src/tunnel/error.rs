//! Error types for Signal Horizon tunnel integration.

use thiserror::Error;

/// Errors from the tunnel client.
#[derive(Debug, Error)]
pub enum TunnelError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Send failed
    #[error("Send failed: {0}")]
    SendFailed(String),

    /// WebSocket error
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Timeout
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Not connected
    #[error("Not connected")]
    NotConnected,

    /// Already connected
    #[error("Already connected")]
    AlreadyConnected,
}

impl From<serde_json::Error> for TunnelError {
    fn from(e: serde_json::Error) -> Self {
        TunnelError::Serialization(e.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for TunnelError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        TunnelError::WebSocket(e.to_string())
    }
}
