---
id: TASK-75.7
title: Demote AutopilotPage to read-only summary with deep-link to Apparatus
status: To Do
assignee: []
created_date: '2026-04-17 03:41'
updated_date: '2026-04-17 03:58'
labels:
  - horizon-ui
  - apparatus
  - federation
milestone: m-7
dependencies:
  - TASK-75.4
references:
  - apps/signal-horizon/ui/src/pages/AutopilotPage.tsx
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Same pattern as the BreachDrillsPage demotion, applied to `apps/signal-horizon/ui/src/pages/AutopilotPage.tsx`. Autopilot configuration and rule editing moves to Apparatus; Horizon shows only a status summary (enabled/disabled, recent actions) if the audit preserves a read-only view.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 apps/signal-horizon/ui/src/pages/AutopilotPage.tsx deleted OR reduced to read-only per audit decision
- [ ] #2 Nav entry updated (removed or redirected to overview)
- [ ] #3 'Manage autopilot' deep-link routes to Apparatus dashboard
- [ ] #4 No Horizon API call in the page path mutates autopilot state
- [ ] #5 Existing tests updated or removed; no dead imports
<!-- AC:END -->
