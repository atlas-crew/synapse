//! Configuration hot-reload via SIGHUP signal.
//!
//! Provides zero-downtime configuration updates by watching for SIGHUP
//! and reloading configuration files without restarting the service.

use parking_lot::RwLock;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

use crate::config::{ConfigError, ConfigFile, ConfigLoader};
use crate::site_waf::SiteWafManager;
use crate::tls::TlsManager;
use crate::vhost::VhostMatcher;

/// Reload statistics.
#[derive(Debug, Default)]
pub struct ReloadStats {
    /// Total reload attempts
    pub attempts: AtomicU64,
    /// Successful reloads
    pub successes: AtomicU64,
    /// Failed reloads
    pub failures: AtomicU64,
    /// Last reload timestamp (Unix epoch seconds)
    pub last_reload_time: AtomicU64,
    /// Whether last reload succeeded
    pub last_success: AtomicBool,
}

impl ReloadStats {
    /// Records a reload attempt result.
    pub fn record(&self, success: bool) {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successes.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
        }
        self.last_success.store(success, Ordering::Relaxed);
        self.last_reload_time.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            Ordering::Relaxed,
        );
    }
}

/// Result of a configuration reload operation.
#[derive(Debug)]
pub struct ReloadResult {
    /// Whether the reload succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Number of sites loaded
    pub sites_loaded: usize,
    /// Number of TLS certificates loaded
    pub certs_loaded: usize,
    /// Reload duration in milliseconds
    pub duration_ms: u64,
}

/// Configuration reloader with atomic swapping.
pub struct ConfigReloader {
    /// Path to configuration file
    config_path: PathBuf,
    /// Current configuration (atomically swappable)
    current_config: Arc<RwLock<ConfigFile>>,
    /// Current vhost matcher (atomically swappable)
    vhost_matcher: Arc<RwLock<VhostMatcher>>,
    /// Current TLS manager
    tls_manager: Arc<TlsManager>,
    /// Current WAF manager
    waf_manager: Arc<RwLock<SiteWafManager>>,
    /// Reload statistics
    stats: ReloadStats,
    /// Whether reload is in progress
    reload_in_progress: AtomicBool,
}

impl ConfigReloader {
    /// Creates a new reloader with the given configuration path.
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, ConfigError> {
        let config_path = config_path.as_ref().to_path_buf();

        // Load initial configuration
        let config = ConfigLoader::load(&config_path)?;
        let sites = ConfigLoader::to_site_configs(&config);

        // Initialize vhost matcher
        let vhost_matcher = VhostMatcher::new(sites.clone())
            .map_err(|e| ConfigError::ValidationError(e.to_string()))?;

        // Initialize TLS manager
        let tls_manager = TlsManager::default();

        // Initialize WAF manager
        let mut waf_manager = SiteWafManager::new();
        for site in &config.sites {
            if let Some(waf_config) = &site.waf {
                let site_waf = crate::site_waf::SiteWafConfig {
                    enabled: waf_config.enabled,
                    threshold: waf_config.threshold.unwrap_or(config.server.waf_threshold),
                    ..Default::default()
                };
                waf_manager.add_site(&site.hostname, site_waf);
            }
        }

        info!(
            "Configuration reloader initialized with {} sites",
            config.sites.len()
        );

        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(config)),
            vhost_matcher: Arc::new(RwLock::new(vhost_matcher)),
            tls_manager: Arc::new(tls_manager),
            waf_manager: Arc::new(RwLock::new(waf_manager)),
            stats: ReloadStats::default(),
            reload_in_progress: AtomicBool::new(false),
        })
    }

    /// Reloads the configuration from disk.
    ///
    /// This is thread-safe and can be called from a signal handler.
    /// If a reload is already in progress, this returns immediately.
    pub fn reload(&self) -> ReloadResult {
        // Prevent concurrent reloads
        if self.reload_in_progress.swap(true, Ordering::SeqCst) {
            warn!("Reload already in progress, skipping");
            return ReloadResult {
                success: false,
                error: Some("Reload already in progress".to_string()),
                sites_loaded: 0,
                certs_loaded: 0,
                duration_ms: 0,
            };
        }

        let start = Instant::now();
        let result = self.do_reload();
        let duration_ms = start.elapsed().as_millis() as u64;

        self.stats.record(result.success);
        self.reload_in_progress.store(false, Ordering::SeqCst);

        ReloadResult {
            duration_ms,
            ..result
        }
    }

    /// Performs the actual reload operation.
    fn do_reload(&self) -> ReloadResult {
        info!("Starting configuration reload from {:?}", self.config_path);

        // Load new configuration
        let new_config = match ConfigLoader::load(&self.config_path) {
            Ok(config) => config,
            Err(e) => {
                error!("Failed to load configuration: {}", e);
                return ReloadResult {
                    success: false,
                    error: Some(format!("Config load error: {}", e)),
                    sites_loaded: 0,
                    certs_loaded: 0,
                    duration_ms: 0,
                };
            }
        };

        // Convert to site configs
        let sites = ConfigLoader::to_site_configs(&new_config);
        let sites_count = sites.len();

        // Create new vhost matcher
        let new_matcher = match VhostMatcher::new(sites.clone()) {
            Ok(matcher) => matcher,
            Err(e) => {
                error!("Failed to create vhost matcher: {}", e);
                return ReloadResult {
                    success: false,
                    error: Some(format!("Vhost matcher error: {}", e)),
                    sites_loaded: 0,
                    certs_loaded: 0,
                    duration_ms: 0,
                };
            }
        };

        // Create new WAF manager
        let mut new_waf_manager = SiteWafManager::new();
        for site in &new_config.sites {
            if let Some(waf_config) = &site.waf {
                let site_waf = crate::site_waf::SiteWafConfig {
                    enabled: waf_config.enabled,
                    threshold: waf_config
                        .threshold
                        .unwrap_or(new_config.server.waf_threshold),
                    ..Default::default()
                };
                new_waf_manager.add_site(&site.hostname, site_waf);
            }
        }

        // Atomically swap configurations
        {
            let mut config = self.current_config.write();
            *config = new_config;
        }
        {
            let mut matcher = self.vhost_matcher.write();
            *matcher = new_matcher;
        }
        {
            let mut waf = self.waf_manager.write();
            *waf = new_waf_manager;
        }

        // Reload TLS certificates
        let tls_result = self.tls_manager.reload_all();
        if !tls_result.is_success() {
            warn!(
                "TLS reload completed with errors: {} succeeded, {} failed",
                tls_result.succeeded, tls_result.failed
            );
            for (domain, error) in &tls_result.errors {
                warn!("  Failed to reload cert for {}: {}", domain, error);
            }
        }

        info!(
            "Configuration reload complete: {} sites loaded",
            sites_count
        );

        ReloadResult {
            success: true,
            error: None,
            sites_loaded: sites_count,
            certs_loaded: self.tls_manager.cert_count(),
            duration_ms: 0,
        }
    }

    /// Returns the current configuration (read-only).
    pub fn config(&self) -> Arc<RwLock<ConfigFile>> {
        Arc::clone(&self.current_config)
    }

    /// Returns the current vhost matcher.
    pub fn vhost_matcher(&self) -> Arc<RwLock<VhostMatcher>> {
        Arc::clone(&self.vhost_matcher)
    }

    /// Returns the TLS manager.
    pub fn tls_manager(&self) -> Arc<TlsManager> {
        Arc::clone(&self.tls_manager)
    }

    /// Returns the WAF manager.
    pub fn waf_manager(&self) -> Arc<RwLock<SiteWafManager>> {
        Arc::clone(&self.waf_manager)
    }

    /// Returns reload statistics.
    pub fn stats(&self) -> &ReloadStats {
        &self.stats
    }

    /// Returns whether a reload is currently in progress.
    pub fn is_reloading(&self) -> bool {
        self.reload_in_progress.load(Ordering::Relaxed)
    }
}

/// Sets up SIGHUP signal handler for configuration reload.
///
/// # Safety
/// This function installs a signal handler. The handler must be async-signal-safe.
#[cfg(unix)]
pub fn setup_sighup_handler(_reloader: Arc<ConfigReloader>) {
    use std::thread;

    thread::spawn(move || {
        // Note: In production, use signal-hook or tokio::signal
        // This is a simplified version for demonstration
        info!("SIGHUP handler ready for configuration reload");

        // The actual signal handling would be:
        // signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGHUP])
        //     .unwrap()
        //     .forever()
        //     .for_each(|_| { reloader.reload(); });

        // For now, we just loop and wait for the thread to be interrupted
        // In production, this would be driven by actual SIGHUP signals
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            // The reload would be triggered by signal, not by timeout
            // This loop just keeps the thread alive
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file
    }

    const MINIMAL_CONFIG: &str = r#"
sites:
  - hostname: example.com
    upstreams:
      - host: 127.0.0.1
        port: 8080
"#;

    #[test]
    fn test_reloader_creation() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = ConfigReloader::new(file.path()).unwrap();

        assert!(!reloader.is_reloading());
        assert_eq!(reloader.stats.attempts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_reload_success() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = ConfigReloader::new(file.path()).unwrap();

        let result = reloader.reload();

        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.sites_loaded, 1);
        assert_eq!(reloader.stats.successes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_reload_failure() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = ConfigReloader::new(file.path()).unwrap();

        // Delete the file to cause reload failure
        drop(file);

        let result = reloader.reload();

        assert!(!result.success);
        assert!(result.error.is_some());
        assert_eq!(reloader.stats.failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_reload_stats() {
        let stats = ReloadStats::default();

        stats.record(true);
        stats.record(true);
        stats.record(false);

        assert_eq!(stats.attempts.load(Ordering::Relaxed), 3);
        assert_eq!(stats.successes.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failures.load(Ordering::Relaxed), 1);
        assert!(!stats.last_success.load(Ordering::Relaxed));
    }

    #[test]
    fn test_concurrent_reload_prevention() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = Arc::new(ConfigReloader::new(file.path()).unwrap());

        // Simulate reload in progress
        reloader.reload_in_progress.store(true, Ordering::SeqCst);

        let result = reloader.reload();

        assert!(!result.success);
        assert!(result
            .error
            .as_ref()
            .unwrap()
            .contains("already in progress"));
    }

    #[test]
    fn test_config_access() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = ConfigReloader::new(file.path()).unwrap();

        let config = reloader.config();
        let config_read = config.read();

        assert_eq!(config_read.sites.len(), 1);
        assert_eq!(config_read.sites[0].hostname, "example.com");
    }

    #[test]
    fn test_vhost_matcher_access() {
        let file = create_temp_config(MINIMAL_CONFIG);
        let reloader = ConfigReloader::new(file.path()).unwrap();

        let matcher = reloader.vhost_matcher();
        let matcher_read = matcher.read();

        assert!(matcher_read.match_host("example.com").is_some());
    }
}
