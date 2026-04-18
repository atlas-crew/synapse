---
id: TASK-75.11
title: Define Crucible federation boundary before first Horizon surface lands
status: To Do
assignee: []
created_date: '2026-04-17 03:42'
labels:
  - architecture
  - crucible
  - federation
  - planning
milestone: m-7
dependencies:
  - TASK-75.5
parent_task_id: TASK-75
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Apply the federation pattern to Crucible before any Crucible UI surface is introduced in Horizon. Avoid repeating the Active Defense drift problem by deciding the read/write boundary up front.

Deliverable is a short plan mirroring the Active Defense audit format: per-capability decision on what Horizon aggregates (read-only summary + deep-link) vs. what stays exclusively in Crucible's own UI. Also documents the Crucible deep-link URL scheme.

Blocks: no Horizon PR that adds a Crucible UI surface should merge without this plan referenced.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 docs/development/plans/crucible-federation.md committed
- [ ] #2 Read/write boundary defined per Crucible capability
- [ ] #3 Deep-link URL scheme for Crucible documented alongside the Apparatus scheme
- [ ] #4 Plan references the federation ADR (TASK-75.5) for canonical pattern
- [ ] #5 PR template or CODEOWNERS note added to prevent Crucible UI merges without this plan
<!-- AC:END -->
