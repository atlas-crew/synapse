---
id: TASK-20
title: Add Chaos engineering controls to Horizon
status: Done
assignee: []
created_date: '2026-04-03 18:31'
updated_date: '2026-04-05 07:05'
labels:
  - apparatus
  - chaos
  - api
  - ui
milestone: m-3
dependencies:
  - TASK-9
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus chaos engineering capabilities for resilience testing of the fleet:

**API routes:**
- `POST /api/v1/apparatus/chaos/cpu-spike` — trigger CPU stress (duration, intensity)
- `POST /api/v1/apparatus/chaos/memory-spike` — trigger memory pressure (size, duration)
- `POST /api/v1/apparatus/chaos/memory-clear` — release allocated memory
- `GET /api/v1/apparatus/chaos/ghost` — ghost traffic status
- `POST /api/v1/apparatus/chaos/ghost/start` — start background traffic generation
- `POST /api/v1/apparatus/chaos/ghost/stop` — stop ghost traffic

**UI:**
- Chaos controls panel under Fleet Operations
- Resource stress buttons with parameter sliders (duration, intensity)
- Ghost traffic configuration (RPS, target endpoints, duration)
- Live indicators showing active chaos operations
- Safety confirmation dialogs before triggering chaos
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
API routes done — chaos (cpu-spike/memory-spike/memory-clear/ghost-start/ghost-stop/ghost-status). UI deferred to future iteration.
<!-- SECTION:NOTES:END -->
