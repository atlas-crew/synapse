---
id: TASK-7
title: Migrate synapse-waf to Rust 2024 edition
status: To Do
assignee: []
created_date: '2026-03-26 16:55'
labels:
  - tech-debt
  - rust
  - synapse-waf
dependencies: []
references:
  - apps/synapse-pingora/Cargo.toml
  - tests/filter_chain_integration.rs
  - >-
    https://doc.rust-lang.org/edition-guide/rust-2024/temporary-tail-expr-scope.html
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Upgrade `apps/synapse-pingora/Cargo.toml` from `edition = "2021"` to `edition = "2024"`.

## Findings from dry run

`cargo fix --edition` identified:

1. **71 drop-order warnings** (`tail_expr_drop_order`) — Temporaries in tail expressions drop before locals in 2024. Most are in async/WebSocket code (`tokio-tungstenite`, `Bytes` trait objects). Each warning needs manual review to confirm the new drop order doesn't change behavior (releasing locks, closing sockets, etc.).

2. **Pre-existing broken test** — `tests/filter_chain_integration.rs:55` calls `SynapseProxy::with_health()` with the old 19-arg signature, but the function was refactored to take 2 args (`backends`, `ProxyDependencies`). This blocks `cargo fix` from fully applying. Fix this test first.

3. **`unsafe_op_in_unsafe_fn`** — Now deny-by-default in 2024. Any `unsafe fn` bodies need explicit `unsafe {}` blocks around unsafe operations. Check openssl/libc usage.

## Approach

1. Fix `filter_chain_integration.rs` broken test (pre-existing)
2. Run `cargo fix --edition` to auto-apply what it can
3. Manually review all 71 drop-order warnings
4. Add explicit `unsafe {}` blocks where needed
5. Update `edition = "2024"` in Cargo.toml
6. Full test pass (`cargo test`)
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Cargo.toml edition is 2024
- [ ] #2 cargo test passes with no failures
- [ ] #3 All 71 drop-order warnings resolved (not suppressed)
- [ ] #4 filter_chain_integration test compiles and passes
<!-- AC:END -->
