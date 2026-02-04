//! Configuration for Signal Horizon tunnel integration.

use serde::{Deserialize, Serialize};

/// Configuration for the Signal Horizon tunnel client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Whether the tunnel client is enabled
    pub enabled: bool,

    /// WebSocket URL for the tunnel gateway (e.g., "wss://horizon.example.com/ws/tunnel/sensor")
    pub url: String,

    /// API key for tunnel authentication (sensor API key)
    pub api_key: String,

    /// Unique sensor identifier
    pub sensor_id: String,

    /// Human-readable sensor name
    pub sensor_name: Option<String>,

    /// Sensor version string
    pub version: String,

    /// Capabilities to advertise to Signal Horizon
    #[serde(default)]
    pub capabilities: Vec<String>,

    /// Heartbeat interval in milliseconds (default: 30000)
    pub heartbeat_interval_ms: u64,

    /// Reconnect delay in milliseconds (default: 5000)
    pub reconnect_delay_ms: u64,

    /// Maximum reconnection attempts (0 = unlimited)
    pub max_reconnect_attempts: u32,

    /// Authentication timeout in milliseconds (default: 10000)
    pub auth_timeout_ms: u64,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            api_key: String::new(),
            sensor_id: String::new(),
            sensor_name: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities: vec![
                "shell".to_string(),
                "dashboard".to_string(),
                "logs".to_string(),
                "diag".to_string(),
                "control".to_string(),
                "files".to_string(),
                "update".to_string(),
            ],
            heartbeat_interval_ms: 30_000,
            reconnect_delay_ms: 5_000,
            max_reconnect_attempts: 0,
            auth_timeout_ms: 10_000,
        }
    }
}

impl TunnelConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), crate::tunnel::TunnelError> {
        if self.enabled {
            if self.url.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "url is required when enabled".to_string(),
                ));
            }
            if self.api_key.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "api_key is required when enabled".to_string(),
                ));
            }
            if self.sensor_id.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "sensor_id is required when enabled".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TunnelConfig::default();
        assert!(!config.enabled);
        assert!(config.url.is_empty());
    }

    #[test]
    fn test_validation() {
        let config = TunnelConfig::default();
        assert!(config.validate().is_ok());

        let config = TunnelConfig {
            enabled: true,
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_err());

        let config = TunnelConfig {
            enabled: true,
            url: "wss://example.com/ws/tunnel/sensor".to_string(),
            api_key: "key".to_string(),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_ok());
    }
}
