---
id: TASK-9
title: Create ApparatusService in Horizon API
status: Done
assignee: []
created_date: '2026-04-03 18:29'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - api
  - service
milestone: m-0
dependencies:
  - TASK-8
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create `apps/signal-horizon/api/src/services/apparatusService.ts` — a singleton service that wraps `ApparatusClient` from apparatus-lib. Responsibilities:

- Initialize client from env vars (`APPARATUS_URL`, `APPARATUS_TIMEOUT`)
- Expose health check (`isConnected()`)
- Manage connection lifecycle (connect on startup, reconnect on failure)
- Expose typed accessors for the category APIs Horizon will use (drills, realtime, defense, chaos, scenarios, autopilot, data)
- Emit connection state changes via EventEmitter for the WebSocket pipeline to broadcast

The service should be lazy — don't fail startup if Apparatus is unreachable, just mark as disconnected.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ApparatusService initializes from APPARATUS_URL env var
- [ ] #2 Health check works when Apparatus is running and when it's not
- [ ] #3 Connection state is observable (connected/disconnected/error)
- [ ] #4 Service does not block Horizon startup if Apparatus is unavailable
<!-- AC:END -->
