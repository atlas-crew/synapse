//! Graceful Shutdown Module
//!
//! Provides multi-phase shutdown orchestration with signal handling,
//! connection draining, and state machine transitions for synapse-pingora WAF proxy.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{broadcast, watch, Notify};
use tracing::{debug, info, warn};

/// Shutdown-related errors.
#[derive(Debug, Error)]
pub enum ShutdownError {
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition { from: ShutdownState, to: ShutdownState },

    #[error("drain timeout after {elapsed:?}")]
    DrainTimeout { elapsed: Duration },

    #[error("shutdown already in progress")]
    AlreadyShuttingDown,
}

pub type ShutdownResult<T> = Result<T, ShutdownError>;

/// Shutdown state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownState {
    #[default]
    Running,
    Draining,
    Shutdown,
}

impl ShutdownState {
    pub fn is_accepting_connections(&self) -> bool {
        matches!(self, Self::Running)
    }

    pub fn is_shutting_down(&self) -> bool {
        matches!(self, Self::Draining | Self::Shutdown)
    }
}

impl std::fmt::Display for ShutdownState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running => write!(f, "running"),
            Self::Draining => write!(f, "draining"),
            Self::Shutdown => write!(f, "shutdown"),
        }
    }
}

/// Configuration for shutdown behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShutdownConfig {
    /// Maximum time to wait for connections to drain.
    #[serde(with = "humantime_serde")]
    pub drain_timeout: Duration,

    /// Grace period after timeout before force shutdown.
    #[serde(with = "humantime_serde")]
    pub grace_period: Duration,

    /// Whether to fail health checks during drain phase.
    pub fail_health_on_drain: bool,

    /// Interval for logging drain progress.
    #[serde(with = "humantime_serde")]
    pub drain_log_interval: Duration,

    /// Whether to wait for pending requests to complete.
    pub wait_for_pending: bool,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        Self {
            drain_timeout: Duration::from_secs(30),
            grace_period: Duration::from_secs(5),
            fail_health_on_drain: true,
            drain_log_interval: Duration::from_secs(5),
            wait_for_pending: true,
        }
    }
}

impl ShutdownConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn with_grace_period(mut self, period: Duration) -> Self {
        self.grace_period = period;
        self
    }

    pub fn with_fail_health_on_drain(mut self, fail: bool) -> Self {
        self.fail_health_on_drain = fail;
        self
    }

    pub fn with_drain_log_interval(mut self, interval: Duration) -> Self {
        self.drain_log_interval = interval;
        self
    }

    pub fn with_wait_for_pending(mut self, wait: bool) -> Self {
        self.wait_for_pending = wait;
        self
    }
}

/// RAII guard for tracking active connections.
pub struct ConnectionGuard {
    drainer: Arc<ConnectionDrainer>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.drainer.decrement();
    }
}

/// Tracks active connections for graceful draining.
#[derive(Debug)]
pub struct ConnectionDrainer {
    active_count: AtomicU64,
    notify: Notify,
}

impl ConnectionDrainer {
    pub fn new() -> Self {
        Self {
            active_count: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    /// Tracks a new connection and returns an RAII guard.
    pub fn track_connection(self: &Arc<Self>) -> ConnectionGuard {
        self.increment();
        ConnectionGuard { drainer: self.clone() }
    }

    /// Increments the active connection count.
    pub fn increment(&self) {
        let count = self.active_count.fetch_add(1, Ordering::SeqCst) + 1;
        debug!(active_connections = count, "Connection opened");
    }

    /// Decrements the active connection count.
    pub fn decrement(&self) {
        let count = self.active_count.fetch_sub(1, Ordering::SeqCst) - 1;
        debug!(active_connections = count, "Connection closed");
        if count == 0 {
            self.notify.notify_waiters();
        }
    }

    /// Returns the current active connection count.
    pub fn active_count(&self) -> u64 {
        self.active_count.load(Ordering::SeqCst)
    }

    /// Waits for all connections to drain with timeout.
    pub async fn wait_for_drain(&self, timeout: Duration, log_interval: Duration) -> bool {
        let start = std::time::Instant::now();

        loop {
            let count = self.active_count();
            if count == 0 {
                info!("All connections drained");
                return true;
            }

            let elapsed = start.elapsed();
            if elapsed >= timeout {
                warn!(active_connections = count, "Drain timeout reached");
                return false;
            }

            let remaining = timeout - elapsed;
            let wait_time = remaining.min(log_interval);

            tokio::select! {
                _ = self.notify.notified() => {
                    // Connection closed, check count again
                }
                _ = tokio::time::sleep(wait_time) => {
                    info!(
                        active_connections = count,
                        elapsed_secs = elapsed.as_secs(),
                        "Waiting for connections to drain"
                    );
                }
            }
        }
    }

    /// Forces immediate close by resetting the count.
    pub fn force_close(&self) {
        let previous = self.active_count.swap(0, Ordering::SeqCst);
        if previous > 0 {
            warn!(forced_closed = previous, "Force closed active connections");
        }
        self.notify.notify_waiters();
    }
}

impl Default for ConnectionDrainer {
    fn default() -> Self {
        Self::new()
    }
}

/// Shutdown lifecycle hooks.
pub struct ShutdownHooks {
    /// Called when drain phase starts.
    pub on_drain_start: Option<Box<dyn Fn() + Send + Sync>>,

    /// Called when drain completes (all connections closed).
    pub on_drain_complete: Option<Box<dyn Fn() + Send + Sync>>,

    /// Called just before final shutdown.
    pub on_shutdown: Option<Box<dyn Fn() + Send + Sync>>,
}

impl Default for ShutdownHooks {
    fn default() -> Self {
        Self {
            on_drain_start: None,
            on_drain_complete: None,
            on_shutdown: None,
        }
    }
}

impl ShutdownHooks {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_drain_start<F: Fn() + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_drain_start = Some(Box::new(f));
        self
    }

    pub fn on_drain_complete<F: Fn() + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_drain_complete = Some(Box::new(f));
        self
    }

    pub fn on_shutdown<F: Fn() + Send + Sync + 'static>(mut self, f: F) -> Self {
        self.on_shutdown = Some(Box::new(f));
        self
    }
}

impl std::fmt::Debug for ShutdownHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShutdownHooks")
            .field("on_drain_start", &self.on_drain_start.is_some())
            .field("on_drain_complete", &self.on_drain_complete.is_some())
            .field("on_shutdown", &self.on_shutdown.is_some())
            .finish()
    }
}

/// Handle for observing and triggering shutdown from other tasks.
#[derive(Clone)]
pub struct ShutdownHandle {
    state_rx: watch::Receiver<ShutdownState>,
    trigger_tx: broadcast::Sender<()>,
}

impl ShutdownHandle {
    /// Returns true if shutdown has been initiated.
    pub fn is_shutting_down(&self) -> bool {
        self.state_rx.borrow().is_shutting_down()
    }

    /// Returns the current shutdown state.
    pub fn state(&self) -> ShutdownState {
        *self.state_rx.borrow()
    }

    /// Waits for shutdown to be initiated.
    pub async fn wait_for_shutdown(&mut self) {
        while !self.is_shutting_down() {
            if self.state_rx.changed().await.is_err() {
                break;
            }
        }
    }

    /// Returns a future that resolves when shutdown begins.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + '_ {
        let mut rx = self.state_rx.clone();
        async move {
            loop {
                if rx.borrow().is_shutting_down() {
                    break;
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    }

    /// Triggers shutdown programmatically.
    pub fn trigger_shutdown(&self) {
        let _ = self.trigger_tx.send(());
    }
}

/// Main shutdown controller.
pub struct ShutdownController {
    config: ShutdownConfig,
    drainer: Arc<ConnectionDrainer>,
    state_tx: watch::Sender<ShutdownState>,
    state_rx: watch::Receiver<ShutdownState>,
    trigger_tx: broadcast::Sender<()>,
    trigger_rx: broadcast::Receiver<()>,
    hooks: ShutdownHooks,
}

impl ShutdownController {
    pub fn new(config: ShutdownConfig) -> Self {
        let (state_tx, state_rx) = watch::channel(ShutdownState::Running);
        let (trigger_tx, trigger_rx) = broadcast::channel(1);

        Self {
            config,
            drainer: Arc::new(ConnectionDrainer::new()),
            state_tx,
            state_rx,
            trigger_tx,
            trigger_rx,
            hooks: ShutdownHooks::default(),
        }
    }

    pub fn with_hooks(mut self, hooks: ShutdownHooks) -> Self {
        self.hooks = hooks;
        self
    }

    /// Returns a handle for observing shutdown state from other tasks.
    pub fn handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            state_rx: self.state_rx.clone(),
            trigger_tx: self.trigger_tx.clone(),
        }
    }

    /// Returns a reference to the connection drainer.
    pub fn drainer(&self) -> Arc<ConnectionDrainer> {
        self.drainer.clone()
    }

    /// Returns the current state.
    pub fn state(&self) -> ShutdownState {
        *self.state_rx.borrow()
    }

    /// Returns true if accepting new connections.
    pub fn is_accepting(&self) -> bool {
        self.state().is_accepting_connections()
    }

    /// Transitions to draining state.
    pub fn transition_to_draining(&self) -> ShutdownResult<()> {
        let current = self.state();
        if current != ShutdownState::Running {
            return Err(ShutdownError::InvalidTransition {
                from: current,
                to: ShutdownState::Draining,
            });
        }

        info!("Transitioning to drain state");
        let _ = self.state_tx.send(ShutdownState::Draining);

        if let Some(ref hook) = self.hooks.on_drain_start {
            hook();
        }

        Ok(())
    }

    /// Transitions to shutdown state.
    pub fn transition_to_shutdown(&self) -> ShutdownResult<()> {
        let current = self.state();
        if current == ShutdownState::Shutdown {
            return Err(ShutdownError::InvalidTransition {
                from: current,
                to: ShutdownState::Shutdown,
            });
        }

        info!("Transitioning to shutdown state");
        let _ = self.state_tx.send(ShutdownState::Shutdown);

        if let Some(ref hook) = self.hooks.on_shutdown {
            hook();
        }

        Ok(())
    }

    /// Waits for connections to drain.
    pub async fn wait_for_drain(&self) -> bool {
        let drained = self.drainer.wait_for_drain(
            self.config.drain_timeout,
            self.config.drain_log_interval,
        ).await;

        if drained {
            if let Some(ref hook) = self.hooks.on_drain_complete {
                hook();
            }
        }

        drained
    }

    /// Forces immediate shutdown without waiting.
    pub fn force_close(&self) {
        warn!("Forcing immediate shutdown");
        self.drainer.force_close();
    }

    /// Runs the complete shutdown sequence.
    pub async fn run_shutdown_sequence(&self) -> ShutdownResult<()> {
        // Transition to draining
        self.transition_to_draining()?;

        // Wait for drain or timeout
        if self.config.wait_for_pending {
            let drained = self.wait_for_drain().await;

            if !drained {
                // Grace period before force close
                info!(
                    grace_period_secs = self.config.grace_period.as_secs(),
                    "Starting grace period"
                );
                tokio::time::sleep(self.config.grace_period).await;

                // Force close remaining
                self.force_close();
            }
        }

        // Final shutdown
        self.transition_to_shutdown()?;

        Ok(())
    }

    /// Starts listening for shutdown signals.
    pub async fn listen_for_signals(&mut self) {
        let mut trigger_rx = self.trigger_rx.resubscribe();

        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
            let mut sigquit = signal(SignalKind::quit()).expect("SIGQUIT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                }
                _ = sigquit.recv() => {
                    info!("Received SIGQUIT");
                }
                _ = trigger_rx.recv() => {
                    info!("Programmatic shutdown triggered");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received CTRL+C");
                }
                _ = trigger_rx.recv() => {
                    info!("Programmatic shutdown triggered");
                }
            }
        }
    }

    /// Convenience method to start and run shutdown on signal.
    pub async fn run(&mut self) -> ShutdownResult<()> {
        self.listen_for_signals().await;
        self.run_shutdown_sequence().await
    }
}

impl Default for ShutdownController {
    fn default() -> Self {
        Self::new(ShutdownConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn test_shutdown_state_properties() {
        assert!(ShutdownState::Running.is_accepting_connections());
        assert!(!ShutdownState::Draining.is_accepting_connections());
        assert!(!ShutdownState::Shutdown.is_accepting_connections());

        assert!(!ShutdownState::Running.is_shutting_down());
        assert!(ShutdownState::Draining.is_shutting_down());
        assert!(ShutdownState::Shutdown.is_shutting_down());
    }

    #[test]
    fn test_shutdown_state_display() {
        assert_eq!(format!("{}", ShutdownState::Running), "running");
        assert_eq!(format!("{}", ShutdownState::Draining), "draining");
        assert_eq!(format!("{}", ShutdownState::Shutdown), "shutdown");
    }

    #[test]
    fn test_config_defaults() {
        let config = ShutdownConfig::default();
        assert_eq!(config.drain_timeout, Duration::from_secs(30));
        assert_eq!(config.grace_period, Duration::from_secs(5));
        assert!(config.fail_health_on_drain);
        assert!(config.wait_for_pending);
    }

    #[test]
    fn test_config_builder() {
        let config = ShutdownConfig::new()
            .with_drain_timeout(Duration::from_secs(60))
            .with_grace_period(Duration::from_secs(10))
            .with_fail_health_on_drain(false)
            .with_wait_for_pending(false);

        assert_eq!(config.drain_timeout, Duration::from_secs(60));
        assert_eq!(config.grace_period, Duration::from_secs(10));
        assert!(!config.fail_health_on_drain);
        assert!(!config.wait_for_pending);
    }

    #[test]
    fn test_drainer_increment_decrement() {
        let drainer = ConnectionDrainer::new();

        drainer.increment();
        assert_eq!(drainer.active_count(), 1);

        drainer.increment();
        assert_eq!(drainer.active_count(), 2);

        drainer.decrement();
        assert_eq!(drainer.active_count(), 1);

        drainer.decrement();
        assert_eq!(drainer.active_count(), 0);
    }

    #[test]
    fn test_connection_guard_raii() {
        let drainer = Arc::new(ConnectionDrainer::new());
        assert_eq!(drainer.active_count(), 0);

        {
            let _guard = drainer.track_connection();
            assert_eq!(drainer.active_count(), 1);

            {
                let _guard2 = drainer.track_connection();
                assert_eq!(drainer.active_count(), 2);
            }

            assert_eq!(drainer.active_count(), 1);
        }

        assert_eq!(drainer.active_count(), 0);
    }

    #[tokio::test]
    async fn test_drainer_wait_for_drain_immediate() {
        let drainer = ConnectionDrainer::new();
        // No connections, should return immediately
        let result = drainer.wait_for_drain(Duration::from_secs(1), Duration::from_millis(100)).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_drainer_wait_for_drain_with_connections() {
        let drainer = Arc::new(ConnectionDrainer::new());
        let drainer_clone = drainer.clone();

        // Add a connection
        drainer.increment();

        // Spawn task to close connection after delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drainer_clone.decrement();
        });

        let result = drainer.wait_for_drain(Duration::from_secs(1), Duration::from_millis(100)).await;
        assert!(result);
        assert_eq!(drainer.active_count(), 0);
    }

    #[tokio::test]
    async fn test_drainer_timeout() {
        let drainer = ConnectionDrainer::new();
        drainer.increment();

        // Short timeout, connection won't close
        let result = drainer.wait_for_drain(Duration::from_millis(50), Duration::from_millis(10)).await;
        assert!(!result);
        assert_eq!(drainer.active_count(), 1);
    }

    #[test]
    fn test_drainer_force_close() {
        let drainer = ConnectionDrainer::new();
        drainer.increment();
        drainer.increment();
        drainer.increment();
        assert_eq!(drainer.active_count(), 3);

        drainer.force_close();
        assert_eq!(drainer.active_count(), 0);
    }

    #[test]
    fn test_controller_initial_state() {
        let controller = ShutdownController::default();
        assert_eq!(controller.state(), ShutdownState::Running);
        assert!(controller.is_accepting());
    }

    #[test]
    fn test_controller_transition_to_draining() {
        let controller = ShutdownController::default();
        let result = controller.transition_to_draining();
        assert!(result.is_ok());
        assert_eq!(controller.state(), ShutdownState::Draining);
        assert!(!controller.is_accepting());
    }

    #[test]
    fn test_controller_transition_to_shutdown() {
        let controller = ShutdownController::default();
        controller.transition_to_draining().unwrap();

        let result = controller.transition_to_shutdown();
        assert!(result.is_ok());
        assert_eq!(controller.state(), ShutdownState::Shutdown);
    }

    #[test]
    fn test_controller_invalid_transition() {
        let controller = ShutdownController::default();
        controller.transition_to_draining().unwrap();

        // Can't go back to draining from draining
        let result = controller.transition_to_draining();
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_creation() {
        let controller = ShutdownController::default();
        let handle = controller.handle();

        assert_eq!(handle.state(), ShutdownState::Running);
        assert!(!handle.is_shutting_down());
    }

    #[test]
    fn test_handle_clone() {
        let controller = ShutdownController::default();
        let handle1 = controller.handle();
        let handle2 = handle1.clone();

        controller.transition_to_draining().unwrap();

        assert!(handle1.is_shutting_down());
        assert!(handle2.is_shutting_down());
    }

    #[test]
    fn test_handle_trigger_shutdown() {
        let controller = ShutdownController::default();
        let handle = controller.handle();

        // Should not panic
        handle.trigger_shutdown();
    }

    #[tokio::test]
    async fn test_handle_wait_for_shutdown() {
        let controller = ShutdownController::default();
        let mut handle = controller.handle();

        // Spawn task to trigger shutdown
        let trigger_handle = controller.handle();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            trigger_handle.trigger_shutdown();
        });

        // Also transition state for wait_for_shutdown to detect
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = controller.transition_to_draining();
        });

        // This should return when shutdown is triggered
        tokio::time::timeout(Duration::from_secs(1), handle.wait_for_shutdown())
            .await
            .expect("wait_for_shutdown should complete");

        assert!(handle.is_shutting_down());
    }

    #[test]
    fn test_hooks_builder() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let hooks = ShutdownHooks::new()
            .on_drain_start(move || {
                called_clone.store(true, Ordering::SeqCst);
            });

        // Execute hook
        if let Some(ref hook) = hooks.on_drain_start {
            hook();
        }

        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_hooks_on_transition() {
        let drain_started = Arc::new(AtomicBool::new(false));
        let drain_started_clone = drain_started.clone();

        let hooks = ShutdownHooks::new()
            .on_drain_start(move || {
                drain_started_clone.store(true, Ordering::SeqCst);
            });

        let controller = ShutdownController::new(ShutdownConfig::default())
            .with_hooks(hooks);

        controller.transition_to_draining().unwrap();
        assert!(drain_started.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_run_shutdown_sequence() {
        let config = ShutdownConfig::new()
            .with_drain_timeout(Duration::from_millis(100))
            .with_grace_period(Duration::from_millis(50))
            .with_wait_for_pending(true);

        let controller = ShutdownController::new(config);

        let result = controller.run_shutdown_sequence().await;
        assert!(result.is_ok());
        assert_eq!(controller.state(), ShutdownState::Shutdown);
    }

    #[tokio::test]
    async fn test_run_shutdown_sequence_with_connections() {
        let config = ShutdownConfig::new()
            .with_drain_timeout(Duration::from_millis(200))
            .with_grace_period(Duration::from_millis(50));

        let controller = ShutdownController::new(config);
        let drainer = controller.drainer();

        // Add connection
        drainer.increment();

        // Spawn task to close connection
        let drainer_clone = drainer.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drainer_clone.decrement();
        });

        let result = controller.run_shutdown_sequence().await;
        assert!(result.is_ok());
        assert_eq!(controller.state(), ShutdownState::Shutdown);
    }

    #[test]
    fn test_config_serialization() {
        let config = ShutdownConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("drain_timeout"));

        let parsed: ShutdownConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.drain_timeout, config.drain_timeout);
    }

    #[test]
    fn test_state_serialization() {
        let state = ShutdownState::Draining;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"draining\"");

        let parsed: ShutdownState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ShutdownState::Draining);
    }

    #[test]
    fn test_hooks_debug() {
        let hooks = ShutdownHooks::new()
            .on_drain_start(|| {});

        let debug_str = format!("{:?}", hooks);
        assert!(debug_str.contains("on_drain_start: true"));
        assert!(debug_str.contains("on_drain_complete: false"));
    }
}
