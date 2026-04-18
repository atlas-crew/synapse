---
id: TASK-69
title: >-
  Prevent sub-threshold schema violations from training learner (baseline drift
  attack)
status: Done
assignee: []
created_date: '2026-04-12 22:58'
updated_date: '2026-04-18 20:50'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - security
  - schema-learner
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/profiler/schema_learner.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Security auditor finding M4. Rule 220011 (`schema_violation score>=25`, blocking) catches severe deviations. Rule 220010 (`score>=10`, non-blocking warning) logs moderate deviations. But bodies with score 1-24 still train the learner because TASK-41 only skips training when the body-phase WAF BLOCKS — and sub-threshold violations don't block.

## Attack scenario

An attacker can perform **adaptive baseline poisoning**:

1. Send 100 requests with slightly-deviant schemas, each scoring 20 (below block threshold 25).
2. Each request gets past all rules (scoring is between warning and block levels).
3. Each trains the learner, subtly shifting the baseline toward the attacker's shape.
4. After sufficient drift, the attacker's eventual attack payload scores below 10 (baseline has normalized it) and evades detection entirely.

Slow, patient, undetectable via per-request scoring.

## Fix options

**Option A — train only on score == 0**: only bodies that produce zero schema violations contribute to the learned baseline. Strict but safe.

**Option B — reservoir sampling with cap per source IP**: each IP can contribute at most N samples to the baseline within a time window. Prevents single-IP drift but allows gradual learning from diverse traffic.

**Option C — two-phase baseline**: separate "provisional" and "confirmed" baselines. New shapes enter provisional; only after confirmation from M diverse sources do they graduate to the confirmed baseline used for validation.

**Option D — explicitly drop sub-threshold training**: check the validation result before stashing `pending_learn`; if `score > 0`, set `pending_learn = None`.

Recommended: **Option A** as the simplest and safest default. It's strict — any deviation means "don't learn from this" — but baseline drift is a security concern that justifies strictness.

## Test

Fabricate a ValidationResult with total_score=5 and a valid violation, drive request_body_filter, assert SCHEMA_LEARNER did not train on that template even though the request was allowed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Schema learner trains only on bodies that produce score == 0 (no deviations) — or equivalently, pending_learn is cleared when the validation result is non-empty
- [ ] #2 The fix preserves legitimate learning on clean traffic: score-0 bodies continue to train the baseline
- [ ] #3 Unit or integration test asserts a body that produces a sub-threshold schema violation (score 5) does NOT train the learner
- [ ] #4 The fix composes cleanly with the TASK-59 deferred-pass poisoning fix (both guards coexist)
- [ ] #5 All 205 existing tests continue to pass
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Hardened schema learning so only fully valid bodies train the learner. `request_body_filter` now gates `pending_learn` on `validation_result.is_valid()`, preserving TASK-59's deferred-pass guard while preventing sub-threshold schema drift from poisoning the baseline. Added an integration test that seeds a mature schema, sends an allowed unexpected-field request, and proves the learner does not absorb the drift.
<!-- SECTION:FINAL_SUMMARY:END -->
