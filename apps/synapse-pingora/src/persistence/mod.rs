//! Persistence module for saving and loading WAF state.
//!
//! Handles periodic snapshots of all WAF state:
//! - Learned Endpoint Profiles (ProfileStore)
//! - IP Reputation Data (EntityStore)
//! - Campaign Correlations (CampaignManager)
//! - Actor States (ActorManager)

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use tokio::time;

use crate::actor::ActorState;
use crate::correlation::Campaign;
use crate::detection::StuffingState;
use crate::entity::EntityState;
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
    /// Whether persistence is enabled
    pub enabled: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            save_interval_secs: 60,
            load_on_startup: true,
            enabled: true,
        }
    }
}

/// Current snapshot format version.
/// Increment when making breaking changes to the snapshot structure.
const SNAPSHOT_VERSION: u32 = 1;

/// Unified WAF state snapshot for atomic persistence.
///
/// All state is saved together to ensure consistency across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafSnapshot {
    /// Snapshot format version for forward compatibility
    pub version: u32,
    /// Timestamp when snapshot was created (ms since epoch)
    pub saved_at: u64,
    /// Sensor instance ID
    pub instance_id: String,
    /// Entity states (IP reputation)
    pub entities: Vec<EntityState>,
    /// Campaign correlations
    pub campaigns: Vec<Campaign>,
    /// Actor states
    pub actors: Vec<ActorState>,
    /// Learned endpoint profiles
    pub profiles: Vec<EndpointProfile>,
    /// Credential stuffing detector state
    #[serde(default)]
    pub credential_stuffing: Option<StuffingState>,
}

impl WafSnapshot {
    /// Create a new snapshot with the given state.
    pub fn new(
        instance_id: String,
        entities: Vec<EntityState>,
        campaigns: Vec<Campaign>,
        actors: Vec<ActorState>,
        profiles: Vec<EndpointProfile>,
    ) -> Self {
        let saved_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: SNAPSHOT_VERSION,
            saved_at,
            instance_id,
            entities,
            campaigns,
            actors,
            profiles,
            credential_stuffing: None,
        }
    }

    /// Create a new snapshot with credential stuffing state.
    pub fn with_credential_stuffing(
        instance_id: String,
        entities: Vec<EntityState>,
        campaigns: Vec<Campaign>,
        actors: Vec<ActorState>,
        profiles: Vec<EndpointProfile>,
        credential_stuffing: StuffingState,
    ) -> Self {
        let saved_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            version: SNAPSHOT_VERSION,
            saved_at,
            instance_id,
            entities,
            campaigns,
            actors,
            profiles,
            credential_stuffing: Some(credential_stuffing),
        }
    }

    /// Check if this snapshot is empty (no state to persist).
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
            && self.campaigns.is_empty()
            && self.actors.is_empty()
            && self.profiles.is_empty()
            && self.credential_stuffing.as_ref().map_or(true, |s| {
                s.entity_metrics.is_empty()
                    && s.distributed_attacks.is_empty()
                    && s.takeover_alerts.is_empty()
            })
    }

    /// Get summary stats for logging.
    pub fn stats(&self) -> SnapshotStats {
        let (auth_entities, distributed_attacks, takeover_alerts) =
            self.credential_stuffing.as_ref().map_or((0, 0, 0), |s| {
                (
                    s.entity_metrics.len(),
                    s.distributed_attacks.len(),
                    s.takeover_alerts.len(),
                )
            });

        SnapshotStats {
            entities: self.entities.len(),
            campaigns: self.campaigns.len(),
            actors: self.actors.len(),
            profiles: self.profiles.len(),
            auth_entities,
            distributed_attacks,
            takeover_alerts,
        }
    }
}

/// Summary statistics for a snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotStats {
    pub entities: usize,
    pub campaigns: usize,
    pub actors: usize,
    pub profiles: usize,
    /// Credential stuffing: auth entity metrics
    pub auth_entities: usize,
    /// Credential stuffing: distributed attacks being tracked
    pub distributed_attacks: usize,
    /// Credential stuffing: takeover alerts
    pub takeover_alerts: usize,
}

impl std::fmt::Display for SnapshotStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} entities, {} campaigns, {} actors, {} profiles, {} auth entities, {} attacks, {} takeovers",
            self.entities, self.campaigns, self.actors, self.profiles,
            self.auth_entities, self.distributed_attacks, self.takeover_alerts
        )
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

    /// Get the path to the snapshot file.
    pub fn snapshot_path(&self) -> PathBuf {
        self.config.data_dir.join("waf_state.json")
    }

    /// Get the path to the legacy profiles file (for migration).
    pub fn legacy_profiles_path(&self) -> PathBuf {
        self.config.data_dir.join("profiles.json")
    }

    /// Check if persistence is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Start the background saver task with unified snapshot.
    ///
    /// # Arguments
    /// * `fetch_snapshot` - A closure that returns the current WAF state snapshot.
    ///
    /// # Returns
    /// `Ok(())` if the background saver started successfully, or an error if:
    /// - Persistence is disabled (returns Ok with early return)
    /// - Thread spawning failed
    ///
    /// # Errors
    /// Returns `io::Error` if the background thread cannot be spawned.
    pub fn start_background_saver<F>(self: Arc<Self>, fetch_snapshot: F) -> io::Result<()>
    where
        F: Fn() -> WafSnapshot + Send + Sync + 'static,
    {
        if !self.config.enabled {
            info!("Persistence disabled, skipping background saver");
            return Ok(());
        }

        let config = self.config.clone();
        let log_interval = config.save_interval_secs;
        let log_dir = config.data_dir.clone();

        // Spawn a dedicated thread with its own tokio runtime
        // This avoids requiring a pre-existing runtime context
        std::thread::Builder::new()
            .name("persistence-saver".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!("Failed to create persistence runtime: {}", e);
                        return;
                    }
                };

                rt.block_on(async move {
                    let mut interval =
                        time::interval(Duration::from_secs(config.save_interval_secs));

                    // Ensure data directory exists
                    if let Err(e) = tokio::fs::create_dir_all(&config.data_dir).await {
                        error!(
                            "Failed to create data directory {:?}: {}",
                            config.data_dir, e
                        );
                        return;
                    }

                    loop {
                        interval.tick().await;

                        let snapshot = fetch_snapshot();
                        if snapshot.is_empty() {
                            debug!("Snapshot empty, skipping save");
                            continue;
                        }

                        let path = config.data_dir.join("waf_state.json");
                        let path_clone = path.clone();
                        let stats = snapshot.stats();

                        // Offload CPU-intensive serialization and blocking I/O to a worker thread
                        let res = tokio::task::spawn_blocking(move || {
                            Self::save_snapshot(&snapshot, &path_clone)
                        })
                        .await;

                        match res {
                            Ok(Ok(_)) => info!("Saved WAF state to {:?} ({})", path, stats),
                            Ok(Err(e)) => error!("Failed to save WAF state: {}", e),
                            Err(e) => error!("Save task panicked: {}", e),
                        }
                    }
                });
            })?;

        info!(
            "Background persistence started (interval: {}s, dir: {:?})",
            log_interval, log_dir
        );

        Ok(())
    }

    /// Save a unified snapshot to disk (Synchronous/Blocking).
    ///
    /// Uses atomic write (temp file + rename) to prevent corruption.
    pub fn save_snapshot(snapshot: &WafSnapshot, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(snapshot)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write to temp file then rename for atomic write
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load a unified snapshot from disk (Synchronous/Blocking).
    pub fn load_snapshot(path: &Path) -> io::Result<Option<WafSnapshot>> {
        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(path)?;
        let snapshot: WafSnapshot = serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Version check for future compatibility
        if snapshot.version > SNAPSHOT_VERSION {
            warn!(
                "Snapshot version {} is newer than supported version {}",
                snapshot.version, SNAPSHOT_VERSION
            );
        }

        Ok(Some(snapshot))
    }

    /// Load snapshot on startup if configured.
    ///
    /// Returns the loaded snapshot or None if loading is disabled or file doesn't exist.
    pub fn load_on_startup(&self) -> io::Result<Option<WafSnapshot>> {
        if !self.config.enabled || !self.config.load_on_startup {
            return Ok(None);
        }

        let path = self.snapshot_path();
        match Self::load_snapshot(&path) {
            Ok(Some(snapshot)) => {
                let age_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64
                    - snapshot.saved_at;
                let age_mins = age_secs / 60_000;

                info!(
                    "Loaded WAF state from {:?} ({}, age: {}m)",
                    path,
                    snapshot.stats(),
                    age_mins
                );
                Ok(Some(snapshot))
            }
            Ok(None) => {
                info!("No existing WAF state found at {:?}", path);
                Ok(None)
            }
            Err(e) => {
                error!("Failed to load WAF state from {:?}: {}", path, e);
                Err(e)
            }
        }
    }

    // ========== Legacy Methods (for backwards compatibility) ==========

    /// Save profiles to disk (Synchronous/Blocking).
    /// @deprecated Use save_snapshot instead.
    pub fn save_profiles(profiles: &[EndpointProfile], path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(profiles)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load profiles from disk (Synchronous/Blocking).
    /// @deprecated Use load_snapshot instead.
    pub fn load_profiles(path: &Path) -> io::Result<Vec<EndpointProfile>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(path)?;
        let profiles: Vec<EndpointProfile> = serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(profiles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_snapshot_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_state.json");

        let snapshot = WafSnapshot::new("test-sensor".to_string(), vec![], vec![], vec![], vec![]);

        SnapshotManager::save_snapshot(&snapshot, &path).unwrap();
        let loaded = SnapshotManager::load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.version, SNAPSHOT_VERSION);
        assert_eq!(loaded.instance_id, "test-sensor");
    }

    #[test]
    fn test_empty_snapshot() {
        let snapshot = WafSnapshot::new("test".to_string(), vec![], vec![], vec![], vec![]);
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_snapshot_persists_profiles() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_profiles.json");

        let mut profile = EndpointProfile::new("/api/users".to_string(), 1000);
        profile.update(128, &[("name", "alice")], Some("application/json"), 2000);

        let snapshot = WafSnapshot::new(
            "test-sensor".to_string(),
            vec![],
            vec![],
            vec![],
            vec![profile.clone()],
        );

        SnapshotManager::save_snapshot(&snapshot, &path).unwrap();
        let loaded = SnapshotManager::load_snapshot(&path).unwrap().unwrap();

        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].template, profile.template);
        assert_eq!(loaded.profiles[0].sample_count, profile.sample_count);
    }
}
