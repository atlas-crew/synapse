//! Configuration for Signal Horizon tunnel integration.

use serde::{Deserialize, Serialize};

const MIN_API_KEY_LENGTH: usize = 32;
const MIN_HEARTBEAT_INTERVAL_MS: u64 = 1_000;
const MAX_HEARTBEAT_INTERVAL_MS: u64 = 600_000;
const MIN_RECONNECT_DELAY_MS: u64 = 100;
const MAX_RECONNECT_DELAY_MS: u64 = 300_000;

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

    /// Whether the remote shell service is enabled (default: false)
    #[serde(default)]
    pub shell_enabled: bool,
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
            shell_enabled: false,
        }
    }
}

impl TunnelConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), crate::tunnel::TunnelError> {
        if self.enabled {
            let url = self.url.trim();
            if url.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "url is required when enabled".to_string(),
                ));
            }
            let scheme = url_scheme(url).ok_or_else(|| {
                crate::tunnel::TunnelError::ConfigError(
                    "url must start with ws:// or wss://".to_string(),
                )
            })?;
            if scheme == "ws" && is_production_env() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "non-TLS tunnel url (ws://) is not allowed in production".to_string(),
                ));
            }
            let api_key = self.api_key.trim();
            if api_key.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "api_key is required when enabled".to_string(),
                ));
            }
            if api_key.len() < MIN_API_KEY_LENGTH {
                return Err(crate::tunnel::TunnelError::ConfigError(format!(
                    "api_key must be at least {} characters when enabled",
                    MIN_API_KEY_LENGTH
                )));
            }
            let sensor_id = self.sensor_id.trim();
            if sensor_id.is_empty() {
                return Err(crate::tunnel::TunnelError::ConfigError(
                    "sensor_id is required when enabled".to_string(),
                ));
            }
            if self.heartbeat_interval_ms < MIN_HEARTBEAT_INTERVAL_MS
                || self.heartbeat_interval_ms > MAX_HEARTBEAT_INTERVAL_MS
            {
                return Err(crate::tunnel::TunnelError::ConfigError(format!(
                    "heartbeat_interval_ms must be between {} and {}",
                    MIN_HEARTBEAT_INTERVAL_MS, MAX_HEARTBEAT_INTERVAL_MS
                )));
            }
            if self.reconnect_delay_ms < MIN_RECONNECT_DELAY_MS
                || self.reconnect_delay_ms > MAX_RECONNECT_DELAY_MS
            {
                return Err(crate::tunnel::TunnelError::ConfigError(format!(
                    "reconnect_delay_ms must be between {} and {}",
                    MIN_RECONNECT_DELAY_MS, MAX_RECONNECT_DELAY_MS
                )));
            }
        }
        Ok(())
    }
}

fn url_scheme(url: &str) -> Option<&'static str> {
    let normalized = url.trim().to_ascii_lowercase();
    if normalized.starts_with("wss://") {
        Some("wss")
    } else if normalized.starts_with("ws://") {
        Some("ws")
    } else {
        None
    }
}

fn is_production_env() -> bool {
    if let Ok(value) = std::env::var("SYNAPSE_PRODUCTION") {
        return is_truthy(&value);
    }
    if let Ok(value) = std::env::var("NODE_ENV") {
        return value.eq_ignore_ascii_case("production");
    }
    false
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn clear(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.previous {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn test_default_config() {
        let config = TunnelConfig::default();
        assert!(!config.enabled);
        assert!(config.url.is_empty());
    }

    #[test]
    fn test_validation() {
        let api_key = "a".repeat(MIN_API_KEY_LENGTH);

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
            api_key: api_key.clone(),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    #[serial]
    fn test_production_blocks_ws_url() {
        let _guard = EnvVarGuard::set("SYNAPSE_PRODUCTION", "1");
        let config = TunnelConfig {
            enabled: true,
            url: "ws://example.com/ws/tunnel/sensor".to_string(),
            api_key: "a".repeat(MIN_API_KEY_LENGTH),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    #[serial]
    fn test_production_allows_wss_url() {
        let _guard = EnvVarGuard::set("SYNAPSE_PRODUCTION", "true");
        let config = TunnelConfig {
            enabled: true,
            url: "wss://example.com/ws/tunnel/sensor".to_string(),
            api_key: "a".repeat(MIN_API_KEY_LENGTH),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    #[serial]
    fn test_invalid_scheme_rejected() {
        let _guard = EnvVarGuard::clear("SYNAPSE_PRODUCTION");
        let config = TunnelConfig {
            enabled: true,
            url: "http://example.com/ws/tunnel/sensor".to_string(),
            api_key: "a".repeat(MIN_API_KEY_LENGTH),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_short_api_key() {
        let config = TunnelConfig {
            enabled: true,
            url: "wss://example.com/ws/tunnel/sensor".to_string(),
            api_key: "short".to_string(),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_out_of_range_intervals() {
        let api_key = "a".repeat(MIN_API_KEY_LENGTH);
        let mut config = TunnelConfig {
            enabled: true,
            url: "wss://example.com/ws/tunnel/sensor".to_string(),
            api_key: api_key.clone(),
            sensor_id: "sensor-1".to_string(),
            ..TunnelConfig::default()
        };

        config.heartbeat_interval_ms = MIN_HEARTBEAT_INTERVAL_MS - 1;
        assert!(config.validate().is_err());

        config.heartbeat_interval_ms = MAX_HEARTBEAT_INTERVAL_MS + 1;
        assert!(config.validate().is_err());

        config.heartbeat_interval_ms = MIN_HEARTBEAT_INTERVAL_MS;
        config.reconnect_delay_ms = MIN_RECONNECT_DELAY_MS - 1;
        assert!(config.validate().is_err());

        config.reconnect_delay_ms = MAX_RECONNECT_DELAY_MS + 1;
        assert!(config.validate().is_err());
    }
}
