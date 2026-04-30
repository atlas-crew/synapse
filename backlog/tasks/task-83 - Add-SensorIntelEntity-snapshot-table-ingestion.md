---
id: TASK-83
title: Add SensorIntelEntity snapshot table + ingestion
status: To Do
assignee: []
created_date: '2026-04-17 21:49'
updated_date: '2026-04-30 09:14'
labels:
  - api
  - signal-horizon
  - schema
  - fleet-aggregation
milestone: m-8
dependencies:
  - TASK-78
references:
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
  - apps/signal-horizon/api/src/services/fleet-intel/ingestion-service.ts
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Per ADR-0002 gap list: `/synapse/:sensorId/entities` has no snapshot table, so the fleet view runs on fan-out as a temporary fallback. Add `SensorIntelEntity`, extend ingestion to populate it.

Schema pattern matches existing snapshot tables: `@@unique([tenantId, sensorId, entityId])`, raw payload column, tenant/sensor relations.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Prisma migration adds `SensorIntelEntity` with the standard snapshot shape
- [ ] #2 Ingestion service polls `synapseProxy.listEntities` every 60 s
- [ ] #3 Fleet route `GET /synapse/entities` reads aggregated + deduped data from the new table
- [ ] #4 Per-sensor `/synapse/:sensorId/entities` retained as the diagnostic surface
<!-- AC:END -->
