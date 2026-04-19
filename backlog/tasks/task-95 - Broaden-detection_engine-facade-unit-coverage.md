---
id: TASK-95
title: Broaden detection_engine facade unit coverage
status: To Do
assignee: []
created_date: '2026-04-19 01:55'
labels:
  - synapse-pingora
  - test-debt
  - audit-followup
dependencies: []
references:
  - .agents/reviews/test-audit-20260418-215216.md
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Test-audit follow-up from .agents/reviews/test-audit-20260418-215216.md.

The file-level audit for apps/synapse-pingora/src/detection_engine.rs surfaced broader pre-existing unit-test debt around request building, verdict conversion, reload failure behavior, and facade helper invariants. This did not block TASK-44 because the new deferred-timeout path has focused coverage, but the remaining gaps should be closed in a dedicated cleanup slice.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 DetectionResult default and verdict-conversion invariants are covered
- [ ] #2 build_request header/filtering behavior is covered
- [ ] #3 reload_rules and shared_engine facade invariants are covered
<!-- AC:END -->
