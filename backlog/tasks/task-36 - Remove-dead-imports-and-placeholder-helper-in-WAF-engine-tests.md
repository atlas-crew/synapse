---
id: TASK-36
title: Remove dead imports and placeholder helper in WAF engine tests
status: To Do
assignee: []
created_date: '2026-04-12 05:45'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - test-quality
  - cleanup
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `#[cfg(test)] mod tests` in apps/synapse-pingora/src/waf/engine.rs imports `ViolationSeverity` and `ViolationType` via `use crate::profiler::{...}` and adds a `_keep_enums_used` helper function whose only purpose is to reference those symbols so `cargo test` does not emit unused-import warnings. Neither enum is actually used by any of the seven new signal-match tests — they were pulled in speculatively while sketching the tests and never cleaned up.

Fix: drop the unused imports and delete the placeholder helper. The remaining imports should map one-to-one with types the tests actually construct.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Unused imports (ViolationSeverity, ViolationType, any other speculative symbols) removed from the tests module in apps/synapse-pingora/src/waf/engine.rs
- [ ] #2 _keep_enums_used helper function deleted
- [ ] #3 cargo test --lib waf:: passes with no new warnings
- [ ] #4 Any import the tests genuinely need remains
<!-- AC:END -->
