---
id: TASK-38
title: Add unit tests for nested-condition deferred rule tagging
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
The `condition_is_deferred` walker in apps/synapse-pingora/src/waf/engine.rs recursively inspects nested `match_value` sub-conditions, boolean operand arrays (`and`/`or`/`not`), and selectors. The implementation looks correct, but the only test that exercises the tagging logic (`test_dlp_violation_is_deferred_not_body_phase`) uses a leaf-level `dlp_violation` at the top of the `matches` array. Non-trivial rule shapes that wrap `dlp_violation` inside boolean operators are not covered, so a future refactor of the walker could silently break them.

Fix: add targeted tests that load rules with `dlp_violation` nested under `and`, `or`, and `not` wrappers, and assert both that the rule is tagged deferred and that a non-dlp rule inside the same wrappers is NOT tagged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Test asserts a rule with dlp_violation inside an and wrapper is tagged deferred
- [ ] #2 Test asserts a rule with dlp_violation inside an or wrapper is tagged deferred
- [ ] #3 Test asserts a rule with dlp_violation inside a not wrapper is tagged deferred
- [ ] #4 Negative test: a rule with only non-deferred kinds (e.g. uri + ja4) nested under boolean wrappers is NOT tagged deferred
- [ ] #5 All tests run as part of cargo test --lib waf::
<!-- AC:END -->
