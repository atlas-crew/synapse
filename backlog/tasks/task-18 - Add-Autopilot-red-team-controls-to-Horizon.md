---
id: TASK-18
title: Add Autopilot red team controls to Horizon
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-05 07:13'
labels:
  - apparatus
  - autopilot
  - red-team
  - api
  - ui
milestone: m-3
dependencies:
  - TASK-9
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus Autopilot (AI red team agent) through Horizon. The autopilot autonomously discovers and exploits vulnerabilities, which is high-value for SOC training and posture assessment.

**API routes:**
- `GET /api/v1/apparatus/autopilot/config` — available tools and safety defaults
- `POST /api/v1/apparatus/autopilot/start` — launch with objective, scope, allowed tools
- `GET /api/v1/apparatus/autopilot/status` — current session state + latest report
- `POST /api/v1/apparatus/autopilot/stop` — graceful stop
- `POST /api/v1/apparatus/autopilot/kill` — force kill
- `GET /api/v1/apparatus/autopilot/reports` — historical reports

**UI:**
- Autopilot panel (could be a section on the War Room page or a new page)
- Objective input field with scope controls (allowed tools checkboxes, forbidCrash toggle)
- Live status indicator (idle/running/stopping/completed/failed)
- Report viewer showing findings from completed sessions
- Safety guardrails clearly visible (what the autopilot can and cannot do)
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
API routes done — autopilot (config/start/stop/kill/status/reports). UI page in progress via background agent.
<!-- SECTION:NOTES:END -->
