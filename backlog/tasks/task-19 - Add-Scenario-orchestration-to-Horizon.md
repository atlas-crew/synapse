---
id: TASK-19
title: Add Scenario orchestration to Horizon
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-05 07:13'
labels:
  - apparatus
  - scenarios
  - api
  - ui
milestone: m-3
dependencies:
  - TASK-9
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus multi-step scenario engine through Horizon. Scenarios are sequences of actions (chaos, attacks, defense changes) that simulate complex incidents.

**API routes:**
- `GET /api/v1/apparatus/scenarios` — list saved scenarios
- `POST /api/v1/apparatus/scenarios` — create/save a scenario
- `POST /api/v1/apparatus/scenarios/:id/run` — execute a scenario
- `GET /api/v1/apparatus/scenarios/:id/status` — execution progress

**UI:**
- Scenario library with descriptions and step previews
- Scenario builder (visual step editor with action picker, delay config, parameter forms)
- Execution monitor showing step-by-step progress
- Integration with drill history for tracking scenario outcomes

Scenarios are complementary to drills — drills are predefined challenges, scenarios are custom playbooks.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
API routes done — scenarios (list/save/run/status). UI page in progress via background agent.
<!-- SECTION:NOTES:END -->
