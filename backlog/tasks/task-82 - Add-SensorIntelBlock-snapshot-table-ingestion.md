---
id: TASK-82
title: Add SensorIntelBlock snapshot table + ingestion
status: To Do
assignee: []
created_date: '2026-04-17 21:49'
labels:
  - api
  - signal-horizon
  - schema
  - fleet-aggregation
dependencies:
  - TASK-78
references:
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
  - apps/signal-horizon/api/src/services/fleet-intel/ingestion-service.ts
  - apps/signal-horizon/api/prisma/schema.prisma
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Per ADR-0002 gap list: the fleet view for `/synapse/:sensorId/blocks` currently has no snapshot table, so the aggregated path runs on fan-out as a temporary fallback. Add `SensorIntelBlock` to close the gap.

Schema should mirror the existing `SensorIntelActor`/`Session`/`Campaign` pattern: keyed `@@unique([tenantId, sensorId, blockId])`, `raw Json` column for full payload, `tenant` and `sensor` relations with cascade.

Ingestion wiring extends `FleetIntelIngestionService` to poll `synapseProxy.listBlocks(sensorId)` alongside the other four calls on the 60 s timer.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Prisma migration adds `SensorIntelBlock` table with the same shape pattern as the existing four snapshot tables
- [ ] #2 `FleetIntelIngestionService` calls `synapseProxy.listBlocks` and upserts rows every 60 s
- [ ] #3 Fleet route `GET /synapse/blocks` reads from the new table using the shared aggregator; per-sensor `/synapse/:sensorId/blocks` stays as-is
- [ ] #4 Duplicate ingestion paths NOT introduced — this task also consolidates with FleetIntelService if that work hasn't shipped yet, or uses the already-consolidated service if it has
<!-- AC:END -->
