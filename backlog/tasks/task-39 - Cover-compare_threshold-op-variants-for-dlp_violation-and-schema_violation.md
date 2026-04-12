---
id: TASK-39
title: Cover compare_threshold op variants for dlp_violation and schema_violation
status: Done
assignee: []
created_date: '2026-04-12 05:45'
updated_date: '2026-04-12 06:22'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - test-quality
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `compare_threshold` helper in apps/synapse-pingora/src/waf/engine.rs supports `gte`, `gt`, `eq`, `neq`, `lte`, `lt`, and defaults to `gte` when `op` is absent. The existing tests for the new `dlp_violation` and `schema_violation` match kinds only exercise the default `gte` path. Silent regressions in any of the other ops — or in the unknown-op fallthrough branch — would go unnoticed.

Fix: add parameterized or explicit unit tests that exercise each op variant with both matching and non-matching values, plus a negative test for unknown ops returning false.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 dlp_violation tests cover gte, gt, eq, neq, lte, lt each with a matching and a non-matching value
- [x] #2 schema_violation tests cover the same op variants
- [x] #3 Unknown op (e.g. 'approximately') returns false — explicit negative test
- [x] #4 Tests live alongside the existing signal-match tests in apps/synapse-pingora/src/waf/engine.rs and run under cargo test --lib waf::
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Added two table-driven unit tests in `apps/synapse-pingora/src/waf/engine.rs` that exercise every `compare_threshold` op variant (`gte`, `gt`, `eq`, `neq`, `lte`, `lt`) plus the unknown-op fallthrough branch, for both `dlp_violation` and `schema_violation` match kinds:

- `test_dlp_violation_compare_threshold_op_variants` — deferred path via `analyze_deferred_with_timeout`
- `test_schema_violation_compare_threshold_op_variants` — body-phase path via `analyze`

## Test structure

Each test follows the same pattern:

1. Load 7 rules in one batch — one per supported op plus one with `"op": "approximately"` (unknown, must never fire).
2. Define a closure `run(value)` that constructs the appropriate input (Vec<DlpMatch> of size `count` for dlp, ValidationResult with explicit `total_score` for schema) and returns the matched_rules set.
3. Call `run` three times — below, equal, above the rule threshold.
4. For each rule id, assert the exact fire/no-fire outcome for each of the 3 value cases, totaling 7×3 = 21 assertions per test (42 across both).

The threshold values are arbitrary (3 for dlp, 20 for schema) — only the below/equal/above relationship matters. The shared dispatch via `run` means a regression in compare_threshold or the match-kind handler itself will produce a precisely localized failure with a descriptive message (e.g. "gt: 3 > 3 must be false").

## Verification

- `cargo test --lib -- waf::engine::tests::test_dlp_violation_compare_threshold_op_variants waf::engine::tests::test_schema_violation_compare_threshold_op_variants` — both pass
- `cargo test --lib waf::` — 99 tests pass (up from 97, 2 new)
- No new warnings
- All 4 acceptance criteria ticked.

## AC mapping

- **AC#1** — `test_dlp_violation_compare_threshold_op_variants` covers all 6 ops with matching AND non-matching values via the below/equal/above cases.
- **AC#2** — `test_schema_violation_compare_threshold_op_variants` covers the same 6 ops for schema_violation.
- **AC#3** — both tests include an unknown-op rule (`"approximately"`) with 3 fire-never assertions each (6 total), exercising the `_ => false` fallthrough in `compare_threshold`.
- **AC#4** — both tests live in the existing `#[cfg(test)] mod tests` block in `waf/engine.rs` and run under `cargo test --lib waf::`.

## Design notes

- Using table-driven tests means 42 cell-level assertions with descriptive messages (`"gt: 3 > 3 must be false"`) rather than 42 separate test functions. A single failing assertion points precisely to which op broke and on which value.
- `below`, `equal`, `above` are captured once per test and reused across 7 rule-id assertions. This amortizes the engine analysis cost and keeps the test fast (both tests finish in <1ms).
- Note that `eval_dlp_violation` has an early-exit `if ctx.dlp_matches.is_empty() { return false; }` which bypasses compare_threshold entirely when count=0. I deliberately didn't test count=0 in this test — it's an empty-matches semantic concern, not an op-variant concern. The existing `test_deferred_not_dlp_violation_fires_on_zero_matches` (from TASK-35) covers that path.
<!-- SECTION:FINAL_SUMMARY:END -->
