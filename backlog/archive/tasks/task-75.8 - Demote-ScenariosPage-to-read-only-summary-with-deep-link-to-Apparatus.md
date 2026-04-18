---
id: TASK-75.8
title: Demote ScenariosPage to read-only summary with deep-link to Apparatus
status: To Do
assignee: []
created_date: '2026-04-17 03:41'
updated_date: '2026-04-18 05:44'
labels:
  - horizon-ui
  - apparatus
  - federation
milestone: m-7
dependencies: []
references:
  - apps/signal-horizon/ui/src/pages/ScenariosPage.tsx
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Same pattern as BreachDrillsPage demotion, applied to `apps/signal-horizon/ui/src/pages/ScenariosPage.tsx`. Scenario authoring and orchestration (built in completed TASK-19) moves to Apparatus; Horizon shows read-only run history and status if preserved.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 apps/signal-horizon/ui/src/pages/ScenariosPage.tsx deleted OR reduced to read-only per audit decision
- [ ] #2 Nav entry updated (removed or redirected to overview)
- [ ] #3 'Manage scenarios' deep-link routes to Apparatus dashboard
- [ ] #4 No Horizon API call in the page path mutates scenario state
- [ ] #5 Existing tests updated or removed; no dead imports
<!-- AC:END -->
