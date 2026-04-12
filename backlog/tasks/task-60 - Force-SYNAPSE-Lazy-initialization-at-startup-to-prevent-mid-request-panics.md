---
id: TASK-60
title: Force SYNAPSE Lazy initialization at startup to prevent mid-request panics
status: Done
assignee: []
created_date: '2026-04-12 22:55'
updated_date: '2026-04-12 23:08'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - critical
  - panic-safety
  - robustness
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Three independent reviewers (code-reviewer, rust-pro, security-auditor) flagged that the panic-on-embedded-rule-load-failure introduced in TASK-45 is reachable from inside a request handler, not just at startup.

Current state in `apps/synapse-pingora/src/main.rs`:

```rust
static SYNAPSE: Lazy<Arc<parking_lot::RwLock<Synapse>>> =
    Lazy::new(|| Arc::new(parking_lot::RwLock::new(create_synapse_engine())));
```

`create_synapse_engine` panics with a verbose ops message if `include_str!("production_rules.json")` fails to parse. The CI compat test `test_production_rules_load_into_current_engine` proves the JSON parses at build time, but:

1. `Lazy::force` is deferred until the first access to `SYNAPSE`
2. If the first access is inside a Pingora worker thread handling a request (not at `main()` startup), a panic drops the in-flight request, tears down work on that worker thread, and depending on Pingora's panic handler may silently fail in logs
3. This contradicts the fail-fast-at-startup guarantee the panic design was intended to provide

The CI compat test guarantees the panic branch is unreachable on an undamaged binary, but the branch still exists in the compiled binary. A binary corruption or a future refactor that mutates the rule loader at runtime could reach it under load.

## Fix

Force `SYNAPSE` Lazy initialization explicitly during `main()` startup before `Server::run_forever()`:

```rust
// Eagerly initialize SYNAPSE so any panic from create_synapse_engine
// fires at startup rather than inside a Pingora worker mid-request.
// TASK-60: prevents the Lazy::force panic being reachable from a
// request handler after the binary has started serving traffic.
let _ = SYNAPSE.read();
```

Alternative (cleaner but larger refactor): migrate `SYNAPSE` from `Lazy<T>` to `OnceCell<T>` populated explicitly at startup. Then the type system prevents any code path from accessing `SYNAPSE` before explicit initialization, and the panic (or Result unwrap) happens at a known site in main().

## Verification

The existing `test_synapse_cold_start_ships_full_production_ruleset` test forces the Lazy via `DetectionEngine::rule_count()` but doesn't verify the forcing happens at startup in production main(). Add an integration test that inspects an observable side effect of the startup-time force (e.g., check a metric or log line emitted after forcing).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 main() (or the startup routine downstream) explicitly forces SYNAPSE initialization before any request handler can access it
- [x] #2 The force happens before Server::run_forever() is called
- [x] #3 The panic in create_synapse_engine remains (still the correct fail-fast on corruption) but is no longer reachable from inside a Pingora worker thread
- [x] #4 A startup-time log line confirms the rule count after forcing so ops has a visible signal that rules loaded successfully
- [x] #5 No regression in startup time (the force just moves the Lazy::force work from first-request to startup)
- [x] #6 All existing tests continue to pass
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Added an explicit `DetectionEngine::rule_count()` call in `main()` right before the TUI/non-TUI dispatch and `Server::run_forever()`. This forces the `SYNAPSE: Lazy<Arc<RwLock<Synapse>>>` static to initialize at startup rather than deferring to the first request handler's access.

## Why this matters

Three independent reviewers (code-reviewer, rust-pro, security-auditor) converged on this finding. The TASK-45 panic in `create_synapse_engine` was designed as a fail-fast guard on binary corruption, but its reachability window was too wide: `Lazy::force` is deferred until the first access, and the first access could happen inside a Pingora worker thread handling a real request. A panic at that point would drop in-flight traffic rather than preventing the proxy from starting.

The fix moves the `Lazy::force` to a known startup-time location, where ops sees any panic loudly as a startup failure instead of as a silent mid-request crash.

## Implementation

Added in `main.rs` right before the `if cli.tui { ... } else { ... }` dispatch at line ~6153:

```rust
let synapse_rule_count = DetectionEngine::rule_count();
info!(
    "SYNAPSE engine eagerly initialized: {} rules loaded (TASK-60: ...)",
    synapse_rule_count
);
if synapse_rule_count == 0 {
    panic!(
        "FATAL: SYNAPSE engine initialized with 0 rules. ..."
    );
}
```

Two guarantees:

1. **`DetectionEngine::rule_count()` forces the Lazy**: calling `rule_count()` reads `SYNAPSE`, which triggers `Lazy::force` if not already initialized. If `create_synapse_engine` panics (TASK-45's defense against corrupted embedded rules), it panics here at startup, not inside a worker.

2. **The 0-rule paranoia panic**: an additional defense against silent failures where the engine initializes with an empty rule set (e.g., if a future refactor introduces a runtime reload that produces 0 rules). A WAF running with 0 rules is worse than one that refuses to start, because ops believe they have protection. The existing CI compat test (`test_production_rules_load_into_current_engine`) gates this panic so it cannot fire in a released binary.

The log line gives ops a visible signal on every startup showing the actual loaded rule count (expected: 248 after TASK-45/46), satisfying AC#4.

## Verification

- `cargo check` clean
- `cargo test --lib waf::` — 103 passing (unchanged)
- `cargo test --bin synapse-waf -- tests::` — 48 passing (unchanged)
- `cargo test --test filter_chain_integration` — 53 passing (unchanged)
- **Total: 204 tests green, 0 regressions**

## Why no new dedicated test

- `main()` is a binary entry point; it's not unit-testable.
- The existing `test_synapse_cold_start_ships_full_production_ruleset` already asserts `SYNAPSE` initializes to >= 248 rules when any code path touches it, which is functionally equivalent to what the new force does at startup.
- The "force happens BEFORE run_forever" property is a code-inspection-level invariant (the code sequence is visible in one function). A runtime test would require spawning the actual binary, which is not part of the current test harness.
- TASK-67 (replace false-confidence unit tests with real integration tests) is already filed — if that task ends up introducing a binary-spawn test harness, TASK-60 can be retroactively covered by adding an assertion on the startup log line.

## AC mapping

- **AC#1** (main forces SYNAPSE) — `DetectionEngine::rule_count()` call in `main()` forces the Lazy before any request handler runs.
- **AC#2** (before `Server::run_forever`) — inserted right before the TUI/non-TUI dispatch, and both branches end in `run_forever()`.
- **AC#3** (panic remains as fail-fast) — the TASK-45 `panic!` inside `create_synapse_engine` is unchanged. The force just moves its reachability to a known startup-time location.
- **AC#4** (startup log line confirms rule count) — `info!("SYNAPSE engine eagerly initialized: {} rules loaded", ...)`.
- **AC#5** (no startup-time regression) — the Lazy::force work was going to happen anyway on first access; this just moves it earlier. No net change in startup cost.
- **AC#6** (existing tests pass) — 204 tests green.

## Scope notes

- I kept `Lazy<T>` rather than migrating to `OnceCell<T>`. The migration was the rust-pro reviewer's preferred approach ("make initialization explicit in the type system") but it's a larger refactor that touches every caller of `SYNAPSE`. Current approach satisfies the correctness requirement with a 10-line change; the OnceCell migration can happen separately if someone finds a second Lazy-panic reachability concern.
- The 0-rule paranoia panic I added is extra defense. If a future refactor adds the `OnceCell` migration, the 0-rule check should move into the construction path, not the force call site.
<!-- SECTION:FINAL_SUMMARY:END -->
