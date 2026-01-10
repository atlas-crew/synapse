//! Persistence module for saving and loading WAF state.
//!
//! Handles periodic snapshots of:
//! - Learned Endpoint Profiles (ProfileStore)
//! - IP Reputation Data (EntityStore)
//! - Security Event History (ActorStore)

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::{error, info, warn};
use synapse::Synapse;
use tokio::time;

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
    synapse: Arc<std::cell::RefCell<Synapse>>, // Note: In main.rs this is thread-local, we need a strategy
}

// NOTE: Synapse is thread-local in main.rs.
// This poses a challenge for a global background task.
//
// Strategy:
// 1. Each worker thread maintains its own `ProfileStore`.
// 2. We can't easily "merge" them without a global lock or a message passing architecture.
// 3. For Phase 2 MVP, we will implement persistence for the *Load Testing* use case
//    where we might be running single-threaded or can accept per-thread files.
//
// Better Strategy for Production:
// - Move `ProfileStore` to an `Arc<RwLock<...>>` shared across threads?
// - OR have a dedicated "Learning Thread" that receives samples via channel.
//
// For now, let's implement the `save_profiles` logic that can be called.

impl SnapshotManager {
    /// Save profiles to disk.
    pub fn save_profiles(profiles: &[synapse::EndpointProfile], path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(profiles)?;
        // Write to temp file then rename for atomic write
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load profiles from disk.
    pub fn load_profiles(path: &Path) -> std::io::Result<Vec<synapse::EndpointProfile>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(path)?;
        let profiles: Vec<synapse::EndpointProfile> = serde_json::from_str(&json)?;
        Ok(profiles)
    }
}
