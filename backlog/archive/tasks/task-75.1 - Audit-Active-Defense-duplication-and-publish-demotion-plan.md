---
id: TASK-75.1
title: Audit Active Defense duplication and publish demotion plan
status: To Do
assignee: []
created_date: '2026-04-17 03:39'
updated_date: '2026-04-17 03:59'
labels:
  - architecture
  - horizon-ui
  - apparatus
  - federation
  - analysis
milestone: m-7
dependencies: []
references:
  - apps/signal-horizon/ui/src/App.tsx
  - apps/signal-horizon/ui/src/pages/BreachDrillsPage.tsx
  - apps/signal-horizon/ui/src/pages/AutopilotPage.tsx
  - apps/signal-horizon/ui/src/pages/ScenariosPage.tsx
  - apps/signal-horizon/ui/src/pages/RedTeamScannerPage.tsx
  - /Users/nick/Developer/Apparatus/apps/apparatus/src/dashboard
parent_task_id: TASK-75
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Catalog every Active Defense surface in Signal Horizon (UI pages, API routes, state stores, WebSocket streams, demo fixtures) that duplicates functionality in the Apparatus dashboard at `/Users/nick/Developer/Apparatus/apps/apparatus/src/dashboard/`.

Apparatus parity is already confirmed: `DrillConsole.tsx`, `AutopilotConsole.tsx`, `ScenarioConsole.tsx` (plus the full scenario builder under `components/scenarios/`), and `RedTeamValidator.tsx` all exist in the Apparatus dashboard. The audit therefore decides per Horizon surface: (a) delete from Horizon outright, or (b) demote to read-only summary with deep-link. Option "keep as distinct SOC-analyst view" is reserved for cases with a written justification.

Covers: `BreachDrillsPage`, `AutopilotPage`, `ScenariosPage`, `RedTeamScannerPage` plus any supporting Horizon API routes, store slices, and WebSocket event handlers they rely on.

Output is a demotion plan committed at `docs/development/plans/active-defense-federation.md` that later subtasks execute against.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/development/plans/active-defense-federation.md committed with per-surface decision (delete / demote-to-read-only / keep+justify)
- [ ] #2 All four Active Defense pages covered plus their supporting API routes and store slices
- [ ] #3 Each Horizon surface mapped to the corresponding Apparatus dashboard component (DrillConsole / AutopilotConsole / ScenarioConsole / RedTeamValidator)
- [ ] #4 SOC-analyst vs red-team-operator user journey distinction called out for any page marked 'keep'
<!-- AC:END -->
