use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, warn};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CircuitState {
    #[default]
    Closed,
    Open,
    HalfOpen,
}

/// Internal state protected by a single lock to prevent deadlocks.
#[derive(Debug)]
struct InnerState {
    state: CircuitState,
    last_failure: Option<Instant>,
}

/// Circuit breaker for resilient service communication.
///
/// Implements a simple state machine:
/// - Closed: Normal operation, requests pass through
/// - Open: Failures exceeded threshold, requests blocked
/// - HalfOpen: Testing if service recovered
#[derive(Debug)]
pub struct CircuitBreaker {
    inner: Mutex<InnerState>,
    failure_count: AtomicU64,
    failure_threshold: u64,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u64, reset_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(InnerState {
                state: CircuitState::Closed,
                last_failure: None,
            }),
            failure_count: AtomicU64::new(0),
            failure_threshold,
            reset_timeout,
        }
    }

    /// Get current circuit state, potentially transitioning from Open to HalfOpen.
    pub async fn state(&self) -> CircuitState {
        let mut inner = self.inner.lock().await;
        if inner.state == CircuitState::Open {
            if let Some(last) = inner.last_failure {
                if last.elapsed() >= self.reset_timeout {
                    inner.state = CircuitState::HalfOpen;
                    debug!("Circuit breaker transitioning to half-open");
                }
            }
        }
        inner.state
    }

    /// Record a successful operation.
    pub async fn record_success(&self) {
        let mut inner = self.inner.lock().await;
        self.failure_count.store(0, Ordering::SeqCst);
        if inner.state == CircuitState::HalfOpen {
            inner.state = CircuitState::Closed;
            debug!("Circuit breaker closed after successful operation");
        }
    }

    /// Record a failed operation.
    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
        let mut inner = self.inner.lock().await;
        inner.last_failure = Some(Instant::now());

        if count >= self.failure_threshold {
            if inner.state != CircuitState::Open {
                inner.state = CircuitState::Open;
                warn!("Circuit breaker opened after {} failures", count);
            }
        }
    }

    /// Check if requests should be allowed through.
    pub async fn allow_request(&self) -> bool {
        let state = self.state().await;
        matches!(state, CircuitState::Closed | CircuitState::HalfOpen)
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(60))
    }
}
