---
id: TASK-80
title: 'Fleet SOC views: sessions via SensorIntelSession dedup'
status: To Do
assignee: []
created_date: '2026-04-17 21:48'
updated_date: '2026-04-18 05:43'
labels:
  - api
  - signal-horizon
  - fleet-aggregation
  - soc
milestone: m-8
dependencies:
  - TASK-78
references:
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
  - apps/signal-horizon/api/src/api/routes/synapse.ts
  - apps/signal-horizon/api/prisma/schema.prisma
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement fleet-wide session routes per ADR-0002. Reads from `SensorIntelSession`, deduplicates on `sessionId` per tenant. Sessions are typically bound to a single sensor in practice (sessions don't migrate between sensors), so dedup should be rare — mostly this is "union across sensors with stable ordering." Uses the shared aggregator helper from the actors task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 New fleet routes: `GET /synapse/sessions`, `GET /synapse/sessions/:sessionId`
- [ ] #2 Filter parameters work at the aggregated layer: `actorId`, `suspicious`, `limit`, `offset`
- [ ] #3 Partial-failure envelope with stale-row handling consistent with ADR-0002
- [ ] #4 UI rewired for fleet SOC dashboard session list; sensor-detail retains `/synapse/:sensorId/sessions`
<!-- AC:END -->
