---
id: TASK-75.6
title: Demote BreachDrillsPage to read-only summary with deep-link to Apparatus
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
  - apps/signal-horizon/ui/src/pages/BreachDrillsPage.tsx
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Replace Horizon's `apps/signal-horizon/ui/src/pages/BreachDrillsPage.tsx` write-side UI with a read-only summary on the Active Defense overview per the design from TASK-75.4. Drill management (launch, configure, abort) moves entirely to the Apparatus dashboard.

If the audit (TASK-75.1) marks the page for full deletion, delete it and remove the route/nav entry. If it marks for demotion, keep a read-only summary of drill status and recent runs.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 apps/signal-horizon/ui/src/pages/BreachDrillsPage.tsx deleted OR reduced to read-only per audit decision
- [ ] #2 Nav entry in apps/signal-horizon/ui/src/App.tsx activeDefenseNavItems updated (removed or redirected to overview)
- [ ] #3 'Manage drills' deep-link routes to Apparatus dashboard using the TASK-75.4 URL scheme
- [ ] #4 No Horizon API call in the page path mutates drill state
- [ ] #5 Existing tests updated or removed; no dead imports left behind
- [ ] #6 lint:css-classes guard still passes
<!-- AC:END -->
