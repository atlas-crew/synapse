# Synapse WAF Testing & Thread Safety

Rules for ensuring deterministic and safe test execution in the Rust engine.

## The Global `SYNAPSE` Singleton

The engine relies on a global `Lazy<RwLock<Engine>>` instance named `SYNAPSE`. This instance holds WAF rules, state, and caches. Parallel tests that modify this state will cause race conditions and flaky failures.

### Mandatory `#[serial]`

Every test that interacts with the global engine must be tagged with `#[serial]`:

```rust
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_waf_blocking_logic() {
    // Test logic that touches global state
}
```

### Affected Symbols

Tests containing any of these patterns MUST be serial:
- `SYNAPSE`
- `DetectionEngine`
- `SynapseProxy::request_filter`
- `SynapseProxy::early_request_filter`
- `SynapseProxy::request_body_filter`
- `SynapseProxy::upstream_request_filter`
- `SynapseProxy::new`
- `SynapseProxy::with_health`

## Test Audit Tool

Use the built-in audit script to find missing `#[serial]` tags:
```bash
just audit-synapse-serial
```
This script (in `apps/synapse-pingora/scripts/check-synapse-test-serial.sh`) uses a Perl scanner to detect un-tagged tests that touch high-risk symbols.

## Test Features

Use specific features to toggle heavier suites:
- `cargo test --features heavy-tests`: Runs intensive integration and performance tests.
