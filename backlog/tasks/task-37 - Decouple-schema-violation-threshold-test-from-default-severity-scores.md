---
id: TASK-37
title: Decouple schema violation threshold test from default severity scores
status: To Do
assignee: []
created_date: '2026-04-12 05:45'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - test-quality
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
  - apps/synapse-pingora/src/profiler/schema_types.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`test_schema_violation_threshold` in apps/synapse-pingora/src/waf/engine.rs builds a `ValidationResult` by calling `SchemaViolation::unexpected_field` and `SchemaViolation::type_mismatch`, then asserts `result.total_score >= 10` based on the default severity scores defined in `schema_types.rs`. If those defaults are tuned (a reasonable change as the schema learner evolves), the test will fail for reasons unrelated to the `schema_violation` match kind it is meant to exercise.

Fix: make the test robust to severity-score retuning by either constructing a `ValidationResult` with an explicit known `total_score`, or choosing a rule threshold low enough that any plausible severity score produces a match, and document the intent in a short comment.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 test_schema_violation_threshold does not depend on specific default severity scores from schema_types.rs
- [ ] #2 Test retains both positive (above threshold fires) and negative (below threshold / no schema result does not fire) assertions
- [ ] #3 A comment on the test documents how the threshold was chosen so future maintainers understand the contract
- [ ] #4 cargo test --lib waf:: still passes
<!-- AC:END -->
