---
id: TASK-41
title: Prevent schema learner from training on WAF-blocked request bodies
status: To Do
assignee: []
created_date: '2026-04-12 05:46'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - correctness
  - security
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/profiler/schema_learner.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The signal-correlation change reordered schema validation to run before the body-phase WAF call so that rules using the `schema_violation` match kind can fire in the same pass. As a side effect, `SCHEMA_LEARNER.learn_from_request` in `request_body_filter` (apps/synapse-pingora/src/main.rs) now trains on every JSON body that survives earlier phases — including bodies that the body-phase WAF is about to block. An attacker who sends 10K SQLi/XSS attempts with novel JSON shapes will therefore pollute the learned schema baseline even though those requests are ultimately rejected.

Fix: validate (so schema_violation remains authoritative in the body-phase pass) but defer learning until after the WAF verdict. If the WAF blocks, do not call `learn_from_request` for that body. Legitimate (non-blocked) bodies must continue to train the learner as before.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Schema validation still runs before the body-phase WAF call so schema_violation rules fire correctly
- [ ] #2 learn_from_request is NOT invoked for JSON bodies that the body-phase WAF subsequently blocks
- [ ] #3 Legitimate non-blocked JSON bodies continue to train the learner exactly as they did before this follow-up
- [ ] #4 Unit or integration test sends a blocked SQLi JSON body and asserts it is absent from the learner's baseline afterwards
- [ ] #5 Test also asserts a benign JSON body IS present in the learner's baseline (regression guard)
<!-- AC:END -->
