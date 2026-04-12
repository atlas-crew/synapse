---
id: TASK-39
title: Cover compare_threshold op variants for dlp_violation and schema_violation
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
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `compare_threshold` helper in apps/synapse-pingora/src/waf/engine.rs supports `gte`, `gt`, `eq`, `neq`, `lte`, `lt`, and defaults to `gte` when `op` is absent. The existing tests for the new `dlp_violation` and `schema_violation` match kinds only exercise the default `gte` path. Silent regressions in any of the other ops — or in the unknown-op fallthrough branch — would go unnoticed.

Fix: add parameterized or explicit unit tests that exercise each op variant with both matching and non-matching values, plus a negative test for unknown ops returning false.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dlp_violation tests cover gte, gt, eq, neq, lte, lt each with a matching and a non-matching value
- [ ] #2 schema_violation tests cover the same op variants
- [ ] #3 Unknown op (e.g. 'approximately') returns false — explicit negative test
- [ ] #4 Tests live alongside the existing signal-match tests in apps/synapse-pingora/src/waf/engine.rs and run under cargo test --lib waf::
<!-- AC:END -->
