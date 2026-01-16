//! Persistence module for saving and loading WAF state.
//!
//! Handles periodic snapshots of:
//! - Learned Endpoint Profiles (ProfileStore)
//! - IP Reputation Data (EntityStore)
//! - Security Event History (ActorStore)

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use log::{error, info};
use tokio::time;

use crate::profiler::EndpointProfile;

/// Configuration for persistence.
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Directory to store snapshots
    pub data_dir: PathBuf,
    /// Interval for saving snapshots (seconds)
    pub save_interval_secs: u64,
    /// Whether to load on startup
    pub load_on_startup: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            save_interval_secs: 60,
            load_on_startup: true,
        }
    }
}

/// Manager for handling state snapshots.
pub struct SnapshotManager {
    config: PersistenceConfig,
}

impl SnapshotManager {
    pub fn new(config: PersistenceConfig) -> Self {
        Self { config }
    }

    /// Start the background saver task.
    ///
    /// # Arguments
    /// * `fetch_profiles` - A closure that returns the current profiles snapshot.
    pub fn start_background_saver<F>(self: Arc<Self>, fetch_profiles: F)
    where
        F: Fn() -> Vec<EndpointProfile> + Send + Sync + 'static,
    {
        let config = self.config.clone();
        
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(config.save_interval_secs));
            
            // Ensure data directory exists
            if let Err(e) = tokio::fs::create_dir_all(&config.data_dir).await {
                error!("Failed to create data directory {:?}: {}", config.data_dir, e);
                return;
            }

            loop {
                interval.tick().await;
                
                let profiles = fetch_profiles();
                if profiles.is_empty() {
                    continue;
                }
                
                let path = config.data_dir.join("profiles.json");
                let path_clone = path.clone();
                let count = profiles.len();
                
                // Offload CPU-intensive serialization and blocking I/O to a worker thread
                // This prevents hiccups in the async runtime (Pingora traffic)
                let res = tokio::task::spawn_blocking(move || {
                    Self::save_profiles(&profiles, &path_clone)
                }).await;
                
                match res {
                    Ok(Ok(_)) => info!("Saved {} profiles to {:?} (background)", count, path),
                    Ok(Err(e)) => error!("Failed to save profiles: {}", e),
                    Err(e) => error!("Save task panicked: {}", e),
                }
            }
        });
        
        info!("Background persistence started (interval: {}s)", config.save_interval_secs);
    }

    /// Save profiles to disk (Synchronous/Blocking).
    ///
    /// Use this within `spawn_blocking` to avoid stalling the async runtime.
    pub fn save_profiles(profiles: &[EndpointProfile], path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(profiles)?;
        
        // Write to temp file then rename for atomic write (prevents corruption on crash)
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load profiles from disk (Synchronous/Blocking).
    pub fn load_profiles(path: &Path) -> std::io::Result<Vec<EndpointProfile>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(path)?;
        let profiles: Vec<EndpointProfile> = serde_json::from_str(&json)?;
        Ok(profiles)
    }
}
