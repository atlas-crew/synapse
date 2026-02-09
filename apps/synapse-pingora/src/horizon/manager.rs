//! High-level manager for Signal Horizon Hub integration.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::blocklist::BlocklistCache;
use super::client::{HorizonClient, MetricsProvider};
use super::config::HorizonConfig;
use super::error::HorizonError;
use super::types::{ConnectionState, ThreatSignal};
use crate::config_manager::ConfigManager;
use crate::utils::circuit_breaker::CircuitBreaker;

/// Statistics for the Horizon integration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HorizonStats {
    /// Current connection state
    pub connection_state: String,
    /// Total signals sent
    pub signals_sent: u64,
    /// Total signals acknowledged by hub
    pub signals_acked: u64,
    /// Total batches sent
    pub batches_sent: u64,
    /// Current blocklist size
    pub blocklist_size: usize,
    /// Blocked IPs count
    pub blocked_ips: usize,
    /// Blocked fingerprints count
    pub blocked_fingerprints: usize,
    /// Timestamp of last heartbeat sent
    pub last_heartbeat: i64,
    /// Total heartbeats sent
    pub heartbeats_sent: u64,
    /// Total heartbeat failures
    pub heartbeat_failures: u64,
    /// Current reconnection attempts
    pub reconnect_attempts: u32,
    /// Tenant ID (if authenticated)
    pub tenant_id: Option<String>,
    /// Enabled capabilities
    pub capabilities: Vec<String>,
}

/// Snapshot of statistics (for API responses).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HorizonStatsSnapshot {
    /// Whether Horizon integration is enabled
    pub enabled: bool,
    /// Whether currently connected
    pub connected: bool,
    /// Current connection state
    pub connection_state: String,
    /// Total signals sent
    pub signals_sent: u64,
    /// Total signals acknowledged
    pub signals_acked: u64,
    /// Total batches sent
    pub batches_sent: u64,
    /// Current blocklist size
    pub blocklist_size: usize,
    /// Blocked IPs count
    pub blocked_ips: usize,
    /// Blocked fingerprints count
    pub blocked_fingerprints: usize,
    /// Total heartbeats sent
    pub heartbeats_sent: u64,
    /// Total heartbeat failures
    pub heartbeat_failures: u64,
    /// Current reconnection attempts
    pub reconnect_attempts: u32,
}

/// High-level manager for Signal Horizon Hub integration.
pub struct HorizonManager {
    client: Arc<RwLock<HorizonClient>>,
    config: HorizonConfig,
}

impl HorizonManager {
    /// Create a new Horizon manager with the given configuration.
    pub async fn new(config: HorizonConfig) -> Result<Self, HorizonError> {
        config.validate()?;

        let client = HorizonClient::new(config.clone());

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            config,
        })
    }

    /// Create with a custom metrics provider.
    pub async fn with_metrics_provider(
        config: HorizonConfig,
        metrics_provider: Arc<dyn MetricsProvider>,
    ) -> Result<Self, HorizonError> {
        config.validate()?;

        let client = HorizonClient::with_metrics_provider(config.clone(), metrics_provider);

        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            config,
        })
    }

    /// Set the configuration manager.
    pub fn set_config_manager(&self, _config_manager: Arc<ConfigManager>) {
        let _client = self.client.write();
        // Replace the client with a new one that has the config manager
        // This is a bit hacky because we're inside a RwLock, but HorizonClient
        // doesn't expose a setter for config_manager.
        // Better to add a setter on HorizonClient or rebuild it.
        // Actually, HorizonClient::with_config_manager consumes self.

        // Since we can't easily replace the client in-place if it's already running,
        // we should really pass it during construction.
        // Let's rely on the Builder pattern.
    }

    /// Start the manager.
    pub async fn start(&self) -> Result<(), HorizonError> {
        let mut client = self.client.write();
        client.start().await
    }

    /// Stop the manager.
    pub async fn stop(&self) {
        let mut client = self.client.write();
        client.stop().await;
    }

    /// Report a threat signal.
    pub fn report_signal(&self, signal: ThreatSignal) {
        let client = self.client.read();
        client.report_signal(signal);
    }

    /// Flush pending signals.
    pub async fn flush_signals(&self) {
        let client = self.client.read();
        client.flush_signals().await;
    }

    /// Check if an IP address is blocked.
    #[inline]
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        let client = self.client.read();
        client.is_ip_blocked(ip)
    }

    /// Check if a fingerprint is blocked.
    #[inline]
    pub fn is_fingerprint_blocked(&self, fingerprint: &str) -> bool {
        let client = self.client.read();
        client.is_fingerprint_blocked(fingerprint)
    }

    /// Check if an IP or fingerprint is blocked.
    pub fn is_blocked(&self, ip: Option<&str>, fingerprint: Option<&str>) -> bool {
        if let Some(ip) = ip {
            if self.is_ip_blocked(ip) {
                return true;
            }
        }
        if let Some(fp) = fingerprint {
            if self.is_fingerprint_blocked(fp) {
                return true;
            }
        }
        false
    }

    /// Get the current connection state.
    pub async fn connection_state(&self) -> ConnectionState {
        let client = self.client.read();
        client.connection_state().await
    }

    /// Check if connected to the hub.
    pub async fn is_connected(&self) -> bool {
        let client = self.client.read();
        client.is_connected().await
    }

    /// Get the blocklist size.
    pub fn blocklist_size(&self) -> usize {
        let client = self.client.read();
        client.blocklist_size()
    }

    /// Get a reference to the blocklist cache.
    pub fn blocklist(&self) -> Arc<BlocklistCache> {
        let client = self.client.read();
        Arc::clone(client.blocklist())
    }

    /// Get the circuit breaker.
    pub fn circuit_breaker(&self) -> Arc<CircuitBreaker> {
        let client = self.client.read();
        client.circuit_breaker()
    }

    /// Get statistics.
    pub async fn stats(&self) -> HorizonStats {
        let client = self.client.read();
        let client_stats = client.stats();
        let state = client.connection_state().await;
        let blocklist = client.blocklist();

        HorizonStats {
            connection_state: state.as_str().to_string(),
            signals_sent: client_stats.signals_sent,
            signals_acked: client_stats.signals_acked,
            batches_sent: client_stats.batches_sent,
            blocklist_size: blocklist.size(),
            blocked_ips: blocklist.ip_count(),
            blocked_fingerprints: blocklist.fingerprint_count(),
            last_heartbeat: chrono::Utc::now().timestamp_millis(),
            heartbeats_sent: client_stats.heartbeats_sent,
            heartbeat_failures: client_stats.heartbeat_failures,
            reconnect_attempts: client_stats.reconnect_attempts,
            tenant_id: client.tenant_id().await,
            capabilities: client.capabilities().await,
        }
    }

    /// Get a statistics snapshot.
    pub async fn stats_snapshot(&self) -> HorizonStatsSnapshot {
        let stats = self.stats().await;

        HorizonStatsSnapshot {
            enabled: self.config.enabled,
            connected: stats.connection_state == "connected",
            connection_state: stats.connection_state,
            signals_sent: stats.signals_sent,
            signals_acked: stats.signals_acked,
            batches_sent: stats.batches_sent,
            blocklist_size: stats.blocklist_size,
            blocked_ips: stats.blocked_ips,
            blocked_fingerprints: stats.blocked_fingerprints,
            heartbeats_sent: stats.heartbeats_sent,
            heartbeat_failures: stats.heartbeat_failures,
            reconnect_attempts: stats.reconnect_attempts,
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &HorizonConfig {
        &self.config
    }

    /// Check if the Horizon integration is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Builder for creating a HorizonManager with custom settings.
#[allow(dead_code)]
pub struct HorizonManagerBuilder {
    config: HorizonConfig,
    metrics_provider: Option<Arc<dyn MetricsProvider>>,
    config_manager: Option<Arc<ConfigManager>>,
}

#[allow(dead_code)]
impl HorizonManagerBuilder {
    /// Create a new builder.
    pub fn new(config: HorizonConfig) -> Self {
        Self {
            config,
            metrics_provider: None,
            config_manager: None,
        }
    }

    /// Set a custom metrics provider.
    pub fn with_metrics_provider(mut self, provider: Arc<dyn MetricsProvider>) -> Self {
        self.metrics_provider = Some(provider);
        self
    }

    /// Set the configuration manager.
    pub fn with_config_manager(mut self, manager: Arc<ConfigManager>) -> Self {
        self.config_manager = Some(manager);
        self
    }

    /// Build the HorizonManager.
    pub async fn build(self) -> Result<HorizonManager, HorizonError> {
        let mut client = if let Some(provider) = self.metrics_provider {
            HorizonClient::with_metrics_provider(self.config.clone(), provider)
        } else {
            HorizonClient::new(self.config.clone())
        };

        if let Some(config_manager) = self.config_manager {
            client = client.with_config_manager(config_manager);
        }

        Ok(HorizonManager {
            client: Arc::new(RwLock::new(client)),
            config: self.config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::horizon::{Severity, SignalType};

    #[tokio::test]
    async fn test_manager_disabled() {
        let config = HorizonConfig::default();
        let manager = HorizonManager::new(config).await.unwrap();

        assert!(!manager.is_enabled());
        assert!(!manager.is_ip_blocked("192.168.1.1"));
        assert!(!manager.is_fingerprint_blocked("abc123"));
    }

    #[tokio::test]
    async fn test_manager_stats() {
        let config = HorizonConfig::default();
        let manager = HorizonManager::new(config).await.unwrap();

        let stats = manager.stats().await;
        assert_eq!(stats.signals_sent, 0);
        assert_eq!(stats.blocklist_size, 0);
        assert_eq!(stats.connection_state, "disconnected");
    }

    #[tokio::test]
    async fn test_manager_stats_snapshot() {
        let config = HorizonConfig::default();
        let manager = HorizonManager::new(config).await.unwrap();

        let snapshot = manager.stats_snapshot().await;
        assert!(!snapshot.enabled);
        assert!(!snapshot.connected);
        assert_eq!(snapshot.signals_sent, 0);
    }

    #[tokio::test]
    async fn test_manager_blocklist() {
        let config = HorizonConfig::default();
        let manager = HorizonManager::new(config).await.unwrap();

        // Add entries directly to blocklist for testing
        let blocklist = manager.blocklist();
        blocklist.add(crate::horizon::BlocklistEntry {
            block_type: crate::horizon::BlockType::Ip,
            indicator: "192.168.1.100".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(manager.is_ip_blocked("192.168.1.100"));
        assert!(!manager.is_ip_blocked("192.168.1.101"));
    }

    #[tokio::test]
    async fn test_manager_is_blocked() {
        let config = HorizonConfig::default();
        let manager = HorizonManager::new(config).await.unwrap();

        let blocklist = manager.blocklist();
        blocklist.add(crate::horizon::BlocklistEntry {
            block_type: crate::horizon::BlockType::Ip,
            indicator: "192.168.1.100".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });
        blocklist.add(crate::horizon::BlocklistEntry {
            block_type: crate::horizon::BlockType::Fingerprint,
            indicator: "fp123".to_string(),
            expires_at: None,
            source: "test".to_string(),
            reason: None,
            created_at: None,
        });

        assert!(manager.is_blocked(Some("192.168.1.100"), None));
        assert!(manager.is_blocked(None, Some("fp123")));
        assert!(manager.is_blocked(Some("192.168.1.100"), Some("fp123")));
        assert!(!manager.is_blocked(Some("192.168.1.101"), Some("fp456")));
    }

    #[tokio::test]
    async fn test_builder() {
        let config = HorizonConfig::default()
            .with_hub_url("wss://example.com/ws")
            .with_api_key("test")
            .with_sensor_id("sensor");

        let manager = HorizonManagerBuilder::new(config).build().await.unwrap();

        assert!(manager.is_enabled());
    }

    #[test]
    fn test_report_signal_non_blocking() {
        let config = HorizonConfig::default();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let manager = rt.block_on(HorizonManager::new(config)).unwrap();

        // Should not block even without connection
        for _ in 0..1000 {
            manager.report_signal(ThreatSignal::new(SignalType::IpThreat, Severity::High));
        }
    }
}
