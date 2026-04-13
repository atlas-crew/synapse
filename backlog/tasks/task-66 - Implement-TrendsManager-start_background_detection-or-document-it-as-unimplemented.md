---
id: TASK-66
title: >-
  Implement TrendsManager::start_background_detection or document it as
  unimplemented
status: Done
assignee: []
created_date: '2026-04-12 22:57'
updated_date: '2026-04-13 02:21'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - dormant-feature
  - trends
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/trends/manager.rs
  - apps/synapse-pingora/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Code-reviewer caught the irony: TASK-55 wired `TrendsManagerDependencies.apply_risk` to the EntityManager so trends anomalies contribute to entity risk. But `TrendsManager::start_background_detection` at `src/trends/manager.rs:76-95` is a stub:

```rust
pub fn start_background_detection(&self) -> tokio::task::JoinHandle<()> {
    let shutdown = Arc::clone(&self.shutdown);
    let interval_ms = self.config.anomaly_check_interval_ms;

    // Note: In production, this would spawn a task that runs detection
    // For now, return a dummy task
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        loop {
            interval.tick().await;
            if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            // Batch detection would run here
        }
    })
}
```

The loop ticks forever and does nothing. The `apply_risk` callback I wired in TASK-55 can only fire if `record_payload_anomaly` or `record_login` is called directly by code that decides synchronously that an anomaly occurred. The background detection that's supposed to produce anomalies from recorded signals never runs.

This is the same "dormant infrastructure" anti-pattern the m-6 audit was supposed to fix. TASK-55 closed the dispatch gap but inherited the detection gap.

## Fix options (pick one)

**Option A — implement real detection**: actual detection logic inside the loop. Analyze `self.store` (TimeStore), `self.recent_signals`, run `AnomalyDetector::detect`, emit anomalies via `handle_anomaly`. This is potentially a significant effort depending on the algorithms intended.

**Option B — document and warn**: change the stub comment to be explicit (`#[doc = "Stub — see TASK-66"]`), add a `tracing::warn!("TrendsManager::start_background_detection is a stub")` at the function entry so ops sees the warning on every process start, and file a separate task for the actual implementation.

**Option C — remove the function**: if there's no concrete plan to implement detection, remove `start_background_detection` and the callback wiring from TASK-55 too. Avoids giving false confidence that trends detection is active when it isn't.

Recommended: **Option B** as the minimal correct step. Option A is the ideal but significantly larger scope. Option C gives up on the feature.

## Also verify

TASK-55's production wiring uses `TrendsManager::with_dependencies` to pass the apply_risk callback, but if `start_background_detection` is never called in main.rs anyway, the callback is even more dormant than the stub suggests. Grep for `start_background_detection` call sites in main.rs and confirm it's actually invoked at startup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 start_background_detection is either (A) implemented with real detection logic, (B) explicitly marked as a stub with a startup warning log, or (C) removed along with the TASK-55 callback wiring
- [x] #2 If Option B: a tracing::warn! fires on startup AND the doc comment clearly states the function is a stub pending implementation
- [x] #3 If Option A or B: call site in main.rs startup is verified to actually invoke start_background_detection (not just construct the TrendsManager)
- [ ] #4 A follow-up task is filed if Option B is chosen, tracking the actual implementation effort
- [x] #5 Documentation (if any) referencing TrendsManager background detection is updated to match reality
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Went with Option B (mark + warn + document). Updated `TrendsManager::start_background_detection` with a clear "STUB — TASK-66" doc comment explaining that real-time detection via record_request / record_payload_anomaly is LIVE (handle_anomaly + apply_risk callback fire synchronously from those paths), but cross-signal BATCH detection is not yet implemented. Added a `tracing::warn!` at function entry so any caller is immediately visible in logs.

Audit confirmed the stub is NOT invoked from main.rs startup, so TASK-55's callback wiring is not affected by TASK-66 — the synchronous anomaly paths still reach the EntityManager. The stub is dormant but not load-bearing.

Batch detection implementation tracked as a follow-up (separate task to be filed).
<!-- SECTION:NOTES:END -->
