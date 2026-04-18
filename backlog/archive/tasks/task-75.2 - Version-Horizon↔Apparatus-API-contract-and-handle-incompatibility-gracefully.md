---
id: TASK-75.2
title: Version Horizon↔Apparatus API contract and handle incompatibility gracefully
status: To Do
assignee: []
created_date: '2026-04-17 03:39'
labels:
  - horizon-api
  - apparatus
  - federation
  - contract
milestone: m-7
dependencies: []
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Introduce versioned API contract between Horizon and Apparatus so Apparatus can be upgraded independently without breaking Horizon's aggregator. Horizon pins to a semver range (e.g., `apparatus >=2.0.0 <3.0.0`) and fails gracefully when the running Apparatus is unreachable or reports an incompatible version.

Implementation notes:
- Horizon API reads Apparatus `/version` (or equivalent metadata endpoint) on startup and logs compatibility.
- Horizon UI shows a clear "Apparatus unavailable or incompatible (expected vX.Y, got vA.B)" empty state rather than broken panels.
- Version range lives in a single config point, not scattered across services.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Horizon API probes Apparatus version on startup and logs compatible/incompatible
- [ ] #2 Active Defense overview renders a distinct 'Apparatus unavailable or incompatible' state when probe fails
- [ ] #3 Version range documented in Horizon API README or config reference doc
- [ ] #4 Integration test covers: compatible version, incompatible version, unreachable Apparatus
<!-- AC:END -->
