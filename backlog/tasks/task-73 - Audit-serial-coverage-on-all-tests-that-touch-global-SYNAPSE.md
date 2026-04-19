---
id: TASK-73
title: 'Audit #[serial] coverage on all tests that touch global SYNAPSE'
status: In Progress
assignee: []
created_date: '2026-04-12 22:59'
updated_date: '2026-04-19 01:25'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - test-quality
  - flake-risk
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/tests/
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rust-pro (#7) and test-automator (#5) both flagged the need to verify that every test touching the global `SYNAPSE: Lazy<Arc<parking_lot::RwLock<Synapse>>>` has `#[serial]` applied. Tests without the annotation can race with tests that mutate the engine via `DetectionEngine::reload_rules`, causing flaky pass/fail depending on execution order.

## Scope

Grep all test files for any reference to:
- `SYNAPSE.read()` / `SYNAPSE.write()`
- `DetectionEngine::reload_rules`
- `DetectionEngine::analyze` / `analyze_with_signals` / `analyze_deferred` (these read SYNAPSE internally)
- `proxy.request_filter(...)` or any filter method that calls `DetectionEngine::analyze` via the proxy
- `SynapseProxy::with_health` / `new` / `with_entity_config` (any constructor that uses DetectionEngine)

For each hit, verify the containing test function has `#[serial]`. If not, add it.

## Test files to audit

- `apps/synapse-pingora/src/waf/engine.rs` (`#[cfg(test)] mod tests`)
- `apps/synapse-pingora/src/main.rs` (`#[cfg(test)] mod tests`)
- `apps/synapse-pingora/tests/filter_chain_integration.rs`
- `apps/synapse-pingora/tests/filter_chain_tests.rs`
- `apps/synapse-pingora/tests/waf_integration_tests.rs`
- Any other test file the grep reveals

## Alternative: introduce a test lock helper

Instead of relying on `#[serial]` annotations (which are easy to forget when adding new tests), introduce a shared test lock helper:

```rust
#[cfg(test)]
pub(crate) fn with_synapse_lock<T>(f: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    f()
}
```

Tests that touch SYNAPSE wrap their body in `with_synapse_lock(|| { ... })`. This moves the coordination from per-test annotations to per-access, which is harder to forget.

A test runner that forgets the wrapper would still race, but the wrapper is colocated with the mutation which makes the forgetting less likely. Pick one approach and apply consistently.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Grep audit completes: every test function that touches SYNAPSE (directly or indirectly via filter methods) is identified and its #[serial] status is verified
- [x] #2 Any test missing #[serial] that should have it gets the annotation added
- [x] #3 A grep command that finds missing annotations is documented in test docs or a CI check script (so future test additions don't silently race)
- [ ] #4 Optionally: with_synapse_lock helper introduced and used consistently instead of #[serial] annotations
- [ ] #5 Running the full test suite 5 times in a row (cargo test --lib + --bin + --test filter_chain_integration) produces zero flakes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-04-18: Audited singleton-touching tests with a repo-local script (`apps/synapse-pingora/scripts/check-synapse-test-serial.sh`) and wired it into `just audit-synapse-serial` / `check-synapse`. The audit now passes cleanly with 16 singleton-touching tests carrying #[serial].

Attempted the acceptance-criteria flake sweep (`cargo test --manifest-path apps/synapse-pingora/Cargo.toml --lib`, `--bin synapse-waf`, `--test filter_chain_integration`, repeated 5x), but the first `--lib` pass stalled for several minutes inside the existing lib test binary rather than failing on this serial guard. That broader suite hang remains the only open blocker for AC #5.
<!-- SECTION:NOTES:END -->
