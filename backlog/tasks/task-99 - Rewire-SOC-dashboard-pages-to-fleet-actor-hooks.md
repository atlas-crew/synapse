---
id: TASK-99
title: Rewire SOC dashboard pages to fleet actor hooks
status: To Do
assignee: []
created_date: '2026-04-29 10:17'
labels:
  - ui
  - signal-horizon
  - fleet-aggregation
  - soc
milestone: m-8
dependencies:
  - TASK-79
references:
  - apps/signal-horizon/ui/src/hooks/soc/api.ts
  - apps/signal-horizon/ui/src/pages/soc/ActorsPage.tsx
  - apps/signal-horizon/ui/src/pages/soc/ActorDetailPage.tsx
  - apps/signal-horizon/ui/src/pages/soc/SocSearchPage.tsx
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-79 added the fetchFleetActors / fetchFleetActorDetail / fetchFleetActorTimeline hooks but the SOC dashboard pages (ActorsPage, ActorDetailPage, SocSearchPage, CommandPalette quick search) still pass a sensorId to the per-sensor fetchers. Per ADR-0002 §Decision the SOC dashboard surface should be fleet-deduped — sensor pickers belong on the sensor-detail drawer only. Refactor the dashboard call sites to use the fleet hooks, surface stale-row badges from the envelope summary in the UI, and keep sensor-detail flows on the per-sensor fetchers. Includes Vitest component tests for the stale badge.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ActorsPage list view calls fetchFleetActors and renders deduped rows with seenOnSensors badges
- [ ] #2 ActorDetailPage uses fetchFleetActorDetail + fetchFleetActorTimeline by default; sensor-detail drawer keeps the sensor-prefixed routes
- [ ] #3 Stale per-sensor entries are surfaced in the UI as a 'last seen N min ago' badge on the corresponding row
- [ ] #4 Vitest component tests cover the stale badge and the deduped seenOnSensors render
<!-- AC:END -->
