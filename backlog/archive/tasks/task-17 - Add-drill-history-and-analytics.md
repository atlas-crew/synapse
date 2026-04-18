---
id: TASK-17
title: Add drill history and analytics
status: In Progress
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-18 05:42'
labels:
  - apparatus
  - drills
  - analytics
milestone: m-2
dependencies:
  - TASK-15
  - TASK-16
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Track drill runs in PostgreSQL so Horizon retains a history of drills even if Apparatus is restarted:

- Create a `drill_runs` table: runId, drillId, drillName, tenantId, status, score, startedAt, finishedAt, debrief JSON
- Write drill completion events to this table when debrief is received
- Add `GET /api/v1/apparatus/drills/history` endpoint for past drill runs
- Add a "History" tab to the Breach Drills UI page showing past runs with scores, trends over time
- Optional: chart showing TTD/TTM improvement across repeated drill runs
<!-- SECTION:DESCRIPTION:END -->
