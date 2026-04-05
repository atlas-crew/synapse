---
id: TASK-29
title: Centralize Apparatus demo data fixtures
status: To Do
assignee: []
created_date: '2026-04-05 17:34'
labels:
  - cleanup
  - maintainability
  - demo
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Each Apparatus page (BreachDrillsPage, AutopilotPage, ScenariosPage, SupplyChainPage, JwtTestingPage, RedTeamScannerPage, DlpScannerPage) defines its own `DEMO_*` constants inline. Move all Apparatus demo fixtures to `ui/src/lib/demoData/generators/apparatus.ts` alongside the existing demo data system, so they are centralized and consistent.
<!-- SECTION:DESCRIPTION:END -->
