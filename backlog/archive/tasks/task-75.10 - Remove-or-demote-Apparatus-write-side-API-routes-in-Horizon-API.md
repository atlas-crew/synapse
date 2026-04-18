---
id: TASK-75.10
title: Remove or demote Apparatus write-side API routes in Horizon API
status: To Do
assignee: []
created_date: '2026-04-17 03:41'
updated_date: '2026-04-18 05:45'
labels:
  - horizon-api
  - apparatus
  - federation
  - cleanup
milestone: m-7
dependencies: []
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Horizon API layer gained Apparatus write-side proxy/orchestration routes in completed tasks TASK-15 (drills), TASK-19 (scenarios), TASK-20 (chaos), TASK-21 (defense posture), TASK-25 (supply chain), TASK-27 (on-demand DLP). Once the UI no longer calls them (TASK-75.6 through TASK-75.9), remove or demote these routes so the Horizon API no longer mediates write-side Apparatus operations.

Keep read-side routes needed to populate the Active Defense overview summaries.

TASK-28 ("Split apparatus.ts route file into domain sub-modules") is adjacent — coordinate to avoid conflicting edits, but this cleanup takes precedence when the two conflict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Inventory of Horizon API routes that proxied Apparatus write-side operations documented in the PR
- [ ] #2 Each write-side route removed OR demoted to read-only
- [ ] #3 Horizon UI tests still pass (no 404s from remaining read paths)
- [ ] #4 OpenAPI / contract docs updated to reflect removed routes
- [ ] #5 Coordination with TASK-28 noted in PR description if both touch the same files
<!-- AC:END -->
