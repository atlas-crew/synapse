---
id: TASK-35
title: Fix deferred-pass gate so NOT(dlp_violation) rules can fire
status: To Do
assignee: []
created_date: '2026-04-12 05:45'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - correctness
  - defect
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/waf/engine.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The deferred WAF pass in `upstream_request_filter` is gated on `!ctx.request_dlp_matches.is_empty()`. A rule that semantically means "block when the DLP scanner found nothing" — for example `not(dlp_violation)` combined with a path check — is tagged deferred by the engine (because it references `dlp_violation`), skipped in body-phase, and then never evaluated in the deferred phase because the gate short-circuits on empty matches. Such a rule silently becomes a no-op.

Fix: change the gate to reflect "DLP scan actually completed" rather than "matches were found". A small `ctx.dlp_scan_completed: bool` flag set after `rx.await` succeeds is the minimal correct signal. Positive dlp_violation rules must continue to fire exactly as before.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Deferred pass runs whenever the DLP scan completed successfully, not only when it produced matches
- [ ] #2 RequestContext tracks DLP scan completion state in a way that survives the oneshot failure branch (no deferred pass if scan failed/was cancelled)
- [ ] #3 Unit test loads a rule with a NOT-wrapped dlp_violation, sends a request with zero DLP matches, and confirms the rule is evaluated in the deferred pass
- [ ] #4 Existing positive-case tests (test_dlp_violation_is_deferred_not_body_phase, test_dlp_violation_type_filter) still pass unchanged
<!-- AC:END -->
