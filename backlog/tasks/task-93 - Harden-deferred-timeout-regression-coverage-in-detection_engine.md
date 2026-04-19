---
id: TASK-93
title: Harden deferred timeout regression coverage in detection_engine
status: To Do
assignee: []
created_date: '2026-04-19 01:55'
labels:
  - synapse-pingora
  - review-finding
  - test-debt
dependencies: []
references:
  - .agents/reviews/review-20260418-214912.md
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Review follow-up from .agents/reviews/review-20260418-214912.md.

The current deferred-timeout regression test proves the tighter deferred budget is honored, but it does so via a very large deferred rule set whose timeout behavior depends partly on general per-rule evaluation overhead. Harden the test so the timeout signal comes from a regex-driven or otherwise explicitly budget-sensitive path, or add a calibration guard that avoids machine-speed flakiness.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Deferred-timeout regression no longer relies primarily on generic per-rule iteration overhead
- [ ] #2 Test remains stable across typical local and CI hardware
<!-- AC:END -->
