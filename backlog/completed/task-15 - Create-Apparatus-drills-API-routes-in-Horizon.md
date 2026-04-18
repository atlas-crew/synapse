---
id: TASK-15
title: Create Apparatus drills API routes in Horizon
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-05 06:38'
labels:
  - apparatus
  - api
  - drills
milestone: m-2
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add REST routes to the Horizon API that proxy drill operations to Apparatus via the client library:

- `GET /api/v1/apparatus/drills` — list available drill definitions (`client.drills.list()`)
- `POST /api/v1/apparatus/drills/:drillId/run` — launch a drill (`client.drills.run()`)
- `GET /api/v1/apparatus/drills/:drillId/status` — poll drill status (`client.drills.status()`)
- `POST /api/v1/apparatus/drills/:drillId/detect` — mark threat as detected (`client.drills.markDetected()`)
- `POST /api/v1/apparatus/drills/:drillId/cancel` — cancel active drill (`client.drills.cancel()`)
- `GET /api/v1/apparatus/drills/:drillId/debrief` — get final score and timeline (`client.drills.debrief()`)

All routes require authentication and should check that ApparatusService is connected before proxying. Return 503 if Apparatus is unavailable.

Drill timeline events should also be broadcast via WebSocket so the UI can show real-time progress.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All 6 drill endpoints return correct data when Apparatus is running
- [ ] #2 Endpoints return 503 with clear message when Apparatus is disconnected
- [ ] #3 Drill timeline events are broadcast via WebSocket
- [ ] #4 Routes require tenant authentication
<!-- AC:END -->
