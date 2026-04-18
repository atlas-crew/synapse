---
id: TASK-28
title: Split apparatus.ts route file into domain sub-modules
status: To Do
assignee: []
created_date: '2026-04-05 17:34'
labels:
  - cleanup
  - maintainability
  - apparatus
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `apps/signal-horizon/api/src/api/routes/apparatus.ts` file is 590 lines with 37 handlers across 9 domains (drills, autopilot, scenarios, chaos, defense, forensics, simulator, identity, security/DLP). Split into sub-module files under `routes/apparatus/` (e.g., `drills.ts`, `autopilot.ts`, `simulator.ts`) with a barrel `index.ts` that composes them into one router.
<!-- SECTION:DESCRIPTION:END -->
