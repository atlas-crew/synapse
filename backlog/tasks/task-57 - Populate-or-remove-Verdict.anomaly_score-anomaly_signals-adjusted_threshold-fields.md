---
id: TASK-57
title: >-
  Populate or remove Verdict.anomaly_score / anomaly_signals /
  adjusted_threshold fields
status: In Progress
assignee: []
created_date: '2026-04-12 19:38'
updated_date: '2026-04-18 20:50'
labels:
  - waf
  - synapse-pingora
  - audit-finding
  - dead-code-or-missing-feature
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/types.rs
  - apps/synapse-pingora/src/waf/engine.rs
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/profiler/endpoint_profile.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`Verdict` in `src/waf/types.rs:42` has four anomaly-related fields:

```rust
pub anomaly_score: Option<f64>,
pub adjusted_threshold: Option<f64>,
pub anomaly_signals: Vec<AnomalySignal>,
```

Plus the config layer has `AnomalyBlockingConfig` at `main.rs:546` with `enabled` and `threshold` knobs. Operators can turn this on in config — but nothing populates the anomaly fields in the Verdict. The engine's `evaluate_with_trace` hardcodes `anomaly_signals: Vec::new()`. The threshold from config is never compared against anything because the score that would feed the comparison doesn't exist.

This is either (a) dead code that should be removed so the type system reflects reality, or (b) a half-implemented feature where the plumbing was planned but the producer side never shipped. Decide which, then execute.

If the intended feature is "engine computes a per-request anomaly score from EndpointProfile observations and blocks at threshold", implementing it means:
1. Hook EndpointProfile.detect_anomaly or an equivalent into the engine's evaluation path
2. Populate Verdict.anomaly_signals from the returned signals
3. Sum into Verdict.anomaly_score
4. Compare against anomaly_blocking_threshold from config
5. Set Verdict.action to Block if score exceeds threshold

If the intended feature is "out of scope, never completed", the correct move is:
1. Delete the three Verdict fields
2. Delete AnomalyBlockingConfig from the config
3. Delete references in main.rs:5272 that configure the threshold
4. Update any test that references these fields

This task's deliverable is the DECISION plus the execution, not just the execution. Document the reasoning in the task's final summary so future auditors know which path was chosen and why.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A deliberate decision is made and documented: implement the anomaly path OR delete it as dead code
- [ ] #2 If implemented: EndpointProfile anomaly detection feeds Verdict.anomaly_signals + anomaly_score and the anomaly_blocking_threshold from config is actually compared against the score
- [ ] #3 If implemented: a new unit test asserts a request exceeding the threshold receives Verdict.action = Block with a populated anomaly_signals vector
- [ ] #4 If deleted: Verdict fields, AnomalyBlockingConfig, main.rs:5272 config application, and any test references are all removed in one commit
- [ ] #5 If deleted: a comment in Verdict documents that anomaly detection is not in scope and points at a follow-up task if reinstatement is planned
- [ ] #6 No new cargo warnings after the change
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Current implementation removed the dormant runtime anomaly-blocking path and deprecated config behavior, but kept `Verdict.anomaly_score` / `adjusted_threshold` / `anomaly_signals` as inert compatibility shims after independent review raised public-surface risk. Follow-up decision remains: remove those fields with an explicit compatibility break, or add a formal removal plan/changelog/admin-surface warning.
<!-- SECTION:NOTES:END -->
