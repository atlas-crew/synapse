---
id: TASK-44
title: Apply a tighter deadline budget to the deferred WAF evaluation pass
status: To Do
assignee: []
created_date: '2026-04-12 05:46'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - performance
  - future-work
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/waf/engine.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`DetectionEngine::analyze_deferred` in apps/synapse-pingora/src/main.rs loads the timeout from `WAF_REGEX_TIMEOUT_US`, the same atomic that governs the body-phase pass. A pathological request could therefore spend up to roughly 2x `DEFAULT_EVAL_TIMEOUT` in total WAF work (body-phase pass + deferred pass), even though the deferred rule set is deliberately small. The deferred pass should have its own, tighter budget.

Fix: introduce a dedicated deferred-pass timeout (e.g. roughly 20ms vs the current 50ms default for body-phase), make it configurable alongside the existing `server.waf_regex_timeout_ms`, and thread it through `analyze_deferred_with_timeout`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A new constant and atomic (e.g. WAF_DEFERRED_REGEX_TIMEOUT_US) governs the deferred pass deadline independently from the body-phase deadline
- [ ] #2 Value is configurable via the same config loader that currently tunes server.waf_regex_timeout_ms (document the new knob)
- [ ] #3 Default is explicitly lower than the body-phase default and rationale is captured in a short comment
- [ ] #4 analyze_deferred_with_timeout uses the deferred budget; existing body-phase call sites are unchanged
- [ ] #5 Unit test asserts the deferred deadline is honored independently (e.g., a deferred rule set that would exceed the budget yields timed_out=true)
- [ ] #6 Existing timeout tests (test_timeout_cap and friends) still pass
<!-- AC:END -->
