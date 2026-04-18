---
id: TASK-72
title: >-
  Replace String-typed trends apply_risk callback with a reason enum to avoid
  allocation
status: Done
assignee: []
created_date: '2026-04-12 22:59'
updated_date: '2026-04-18 20:50'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - idiom
  - api-shape
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/trends/manager.rs
  - apps/synapse-pingora/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rust-pro finding #3. The TASK-55 `TrendsManagerDependencies.apply_risk` callback is typed as `Box<dyn Fn(&str, u32, &str) + Send + Sync>`, and the production implementation in `main.rs:5611` does:

```rust
apply_risk: Some(Box::new(move |entity_id: &str, risk: u32, reason: &str| {
    entity_manager_for_trends.apply_external_risk(
        entity_id,
        risk as f64,
        &format!("trends_anomaly:{}", reason),
    );
})),
```

Every anomaly invocation allocates a `String` via the `format!`. Perf-monitor says it's not on the hot path (anomalies are rare), so the allocation cost is negligible. But rust-pro flags the trait design itself: the stringly-typed `reason: &str` forces the caller to either pass a `&'static str` tag (clean) or construct a dynamic string (allocates). There's no way to pass a compact reason identifier.

## Fix

**Option A — enum-typed reason**:

```rust
// In trends module:
#[derive(Debug, Clone, Copy)]
pub enum TrendsReason {
    Anomaly,
    VelocitySpike,
    RotationPattern,
    SessionSharing,
    // ...
}

impl TrendsReason {
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Anomaly => "trends_anomaly",
            Self::VelocitySpike => "trends_velocity_spike",
            // ...
        }
    }
}

pub type RiskCallback = Box<dyn Fn(&str, u32, TrendsReason) + Send + Sync>;
```

The callback now takes a strongly-typed enum. The TASK-55 closure becomes:

```rust
apply_risk: Some(Box::new(move |entity_id: &str, risk: u32, reason: TrendsReason| {
    entity_manager_for_trends.apply_external_risk(
        entity_id,
        risk as f64,
        reason.as_tag(), // &'static str, no allocation
    );
})),
```

Zero allocations per invocation. Type-safe. Exhaustive match prevents missing cases.

**Option B — accept the allocation**: it's negligible per perf-monitor. The only reason to fix is idiom correctness, not performance.

Recommended: **Option A** when the TrendsReason enum can be introduced without a large migration. Skip if the call sites in the trends subsystem span many files and would require a coordinated change.

## Compatibility

Existing internal callers (inside `trends/manager.rs`) that call `handle_anomaly` with a string reason need to migrate to the enum. That's the scope creep risk — depends how many call sites exist.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TrendsReason enum added with as_tag() method returning &'static str
- [ ] #2 RiskCallback type updated to take TrendsReason instead of &str
- [ ] #3 TASK-55 production closure updated to use .as_tag() and skip the format! allocation
- [ ] #4 All internal callers of handle_anomaly migrated to pass a TrendsReason variant
- [ ] #5 Backwards-compat: if any external code consumes the reason string, the &'static str values are preserved (same tags)
- [ ] #6 No new cargo warnings, all tests pass
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Replaced the stringly-typed trends risk callback with a `TrendsReason` enum. The production `apply_risk` closure now uses `reason.as_tag()` instead of allocating with `format!`, internal anomaly call sites pass typed reasons, and regression tests pin the emitted tag strings plus the end-to-end callback invocation path.
<!-- SECTION:FINAL_SUMMARY:END -->
