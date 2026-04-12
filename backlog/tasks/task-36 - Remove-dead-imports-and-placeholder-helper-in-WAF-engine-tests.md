---
id: TASK-36
title: Remove dead imports and placeholder helper in WAF engine tests
status: Done
assignee: []
created_date: '2026-04-12 05:45'
updated_date: '2026-04-12 06:15'
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
- [x] #1 Unused imports (ViolationSeverity, ViolationType, any other speculative symbols) removed from the tests module in apps/synapse-pingora/src/waf/engine.rs
- [x] #2 _keep_enums_used helper function deleted
- [x] #3 cargo test --lib waf:: passes with no new warnings
- [x] #4 Any import the tests genuinely need remains
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Removed two unused imports (`ViolationSeverity`, `ViolationType`) from the `#[cfg(test)] mod tests` block in `apps/synapse-pingora/src/waf/engine.rs` and deleted the `_keep_enums_used` placeholder helper that existed only to silence the resulting unused-import warnings.

## Changes

**Line 2612:**
```rust
// Before
use crate::profiler::{FieldType, SchemaViolation, ValidationResult, ViolationSeverity, ViolationType};
// After
use crate::profiler::{FieldType, SchemaViolation, ValidationResult};
```

**Lines 2871-2876:** deleted the helper:
```rust
// Silence unused warnings for ViolationSeverity / ViolationType in tests.
#[allow(dead_code)]
fn _keep_enums_used() {
    let _ = ViolationSeverity::High;
    let _ = ViolationType::UnexpectedField;
}
```

## Verification

- `cargo test --lib waf::` — 96 tests pass (unchanged)
- No new warnings introduced. Pre-existing warnings in unrelated files (`headers.rs`, `signal_manager.rs`, `ratelimit.rs`, `tarpit/manager.rs`, `tunnel/shell.rs`, `tui.rs`) remain and are out of scope for this task.
- Remaining profiler imports (`FieldType`, `SchemaViolation`, `ValidationResult`) are all still in active use by the signal-match tests: `FieldType::String` and `FieldType::Number` in `test_schema_violation_threshold`'s `SchemaViolation::type_mismatch` call, `SchemaViolation` and `ValidationResult` throughout.

## AC mapping

- **AC#1** — `ViolationSeverity` and `ViolationType` removed from the use statement.
- **AC#2** — `_keep_enums_used` deleted.
- **AC#3** — `cargo test --lib waf::` passes with no new warnings.
- **AC#4** — `FieldType`, `SchemaViolation`, and `ValidationResult` remain because tests still construct them directly.
<!-- SECTION:FINAL_SUMMARY:END -->
