---
id: TASK-35
title: Fix deferred-pass gate so NOT(dlp_violation) rules can fire
status: Done
assignee: []
created_date: '2026-04-12 05:45'
updated_date: '2026-04-12 06:09'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - correctness
  - defect
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/waf/engine.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The deferred WAF pass in `upstream_request_filter` is gated on `!ctx.request_dlp_matches.is_empty()`. A rule that semantically means "block when the DLP scanner found nothing" — for example `not(dlp_violation)` combined with a path check — is tagged deferred by the engine (because it references `dlp_violation`), skipped in body-phase, and then never evaluated in the deferred phase because the gate short-circuits on empty matches. Such a rule silently becomes a no-op.

Fix: change the gate to reflect "DLP scan actually completed" rather than "matches were found". A small `ctx.dlp_scan_completed: bool` flag set after `rx.await` succeeds is the minimal correct signal. Positive dlp_violation rules must continue to fire exactly as before.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Deferred pass runs whenever the DLP scan completed successfully, not only when it produced matches
- [x] #2 RequestContext tracks DLP scan completion state in a way that survives the oneshot failure branch (no deferred pass if scan failed/was cancelled)
- [x] #3 Unit test loads a rule with a NOT-wrapped dlp_violation, sends a request with zero DLP matches, and confirms the rule is evaluated in the deferred pass
- [x] #4 Existing positive-case tests (test_dlp_violation_is_deferred_not_body_phase, test_dlp_violation_type_filter) still pass unchanged
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

The deferred WAF pass in `upstream_request_filter` was gated on `!ctx.request_dlp_matches.is_empty()`, which silently disabled any rule that wrapped `dlp_violation` in a NOT operator. The engine itself has always handled the NOT semantics correctly — `eval_dlp_violation` returns `false` on empty matches and the boolean `not` handler inverts that to `true` — but the engine never got called because the gate short-circuited.

## Fix

Added a `dlp_scan_completed: bool` field to `RequestContext`, defaulted `false` in `new_ctx`, set to `true` in the `Ok(...)` arm of the DLP oneshot `rx.await` (before the `match_count > 0` log branch so the flag is set regardless of whether matches were found). The `Err` arm for scan failures/cancellations leaves the flag `false` so failed scans correctly skip the deferred pass.

Changed the deferred-pass gate in `upstream_request_filter` from `!ctx.request_dlp_matches.is_empty()` to `ctx.dlp_scan_completed`. This means:

- **DLP scan ran, zero matches** → deferred pass runs. Rules with `not(dlp_violation)` are now evaluated and fire correctly.
- **DLP scan ran, some matches** → deferred pass runs (unchanged behavior). Positive `dlp_violation` rules still fire as before.
- **DLP scan never ran** (non-JSON body, scanner disabled) → deferred pass is skipped. Fast-path cost is preserved for requests that bypass DLP entirely.
- **DLP scan failed/cancelled** → flag stays false, deferred pass is skipped. A half-evaluated deferred verdict from a failed scan would be worse than no verdict at all.

## Tests

Added `test_deferred_not_dlp_violation_fires_on_zero_matches` in `apps/synapse-pingora/src/waf/engine.rs`. It pins the engine-side correctness contract that main.rs's gate fix depends on. The test is a triple-assertion over the same rule:

1. **Fires on empty matches** — `not(dlp_violation)` AND `method == POST` evaluates true when `dlp_matches: Some(&[])`, verdict blocks, `matched_rules` contains the rule id.
2. **Skipped in body-phase** — `engine.analyze(&req)` does NOT include the rule in matched_rules, proving the deferred tagging still excludes it from body-phase evaluation.
3. **Does NOT fire when matches present** — with a non-empty `dlp_matches`, the NOT path evaluates false and the rule correctly does not fire.

Also asserts the rule is tagged deferred (`deferred_rule_indices.len() == 1`, `deferred_rule_id_set.contains(&9010)`), confirming the `condition_is_deferred` walker correctly recurses through boolean operands.

## Verification

- `cargo check` clean
- 96 WAF lib tests passing (up from 95: 1 new test)
- 44 main.rs bin tests passing (unchanged — existing tests from TASK-32/33/34 + baseline)
- Existing positive-case tests (`test_dlp_violation_is_deferred_not_body_phase`, `test_dlp_violation_type_filter`) pass unchanged — AC#4.
- All 4 acceptance criteria pass via tests + code inspection of the gate.

## AC mapping

- **AC#1 (deferred pass runs when scan completed)** — gate is now `if ctx.dlp_scan_completed { ... }`.
- **AC#2 (scan failure branch leaves flag false)** — flag is only set inside `Ok(...)` arm; `Err(_)` arm doesn't touch it. Verified by reading the diff; defaults to `false` in `new_ctx` so any request that doesn't hit the `Ok` arm (no scan dispatched, scan dispatched but future dropped, etc.) correctly skips the deferred pass.
- **AC#3 (test asserts engine evaluates NOT rule)** — `test_deferred_not_dlp_violation_fires_on_zero_matches`.
- **AC#4 (existing positive-case tests still pass)** — the two named tests (`test_dlp_violation_is_deferred_not_body_phase`, `test_dlp_violation_type_filter`) run in every `cargo test --lib waf::` invocation, now 96 total, unchanged.

## Why the engine needed no changes

`eval_dlp_violation` at `waf/engine.rs` already has `if ctx.dlp_matches.is_empty() { return false; }` as its first branch. The generic boolean `not` handler at `eval_boolean` handles `"op": "not"` by inverting its operand. So a condition like `{"type": "boolean", "op": "not", "match": {"type": "dlp_violation"}}` resolves to `!false == true` when matches are empty, which is exactly what the rule author wants. The only missing piece was main.rs giving the engine a chance to run — that's what this task fixes.
<!-- SECTION:FINAL_SUMMARY:END -->
