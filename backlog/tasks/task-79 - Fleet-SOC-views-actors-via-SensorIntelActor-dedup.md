---
id: TASK-79
title: 'Fleet SOC views: actors via SensorIntelActor dedup'
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
Implement fleet-wide actor routes per ADR-0002. Reads from `SensorIntelActor`, deduplicates on `actorId` per tenant, returns merged rows with `seenOnSensors: string[]` attribution. Includes list, detail, and timeline surfaces. Uses the shared `FleetPartialResult<T>` envelope with tri-state `ok | stale | error` status.

Strategy: snapshot dedup. Score reconciliation = max, sets = union, times = min/max, counters = sum. See ADR-0002 "Dedup semantics" section.

Per-sensor `/synapse/:sensorId/actors*` routes remain as the sensor-detail drill-down surface.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 New fleet routes added: `GET /synapse/actors`, `GET /synapse/actors/:actorId`, `GET /synapse/actors/:actorId/timeline` — all non-sensor-prefixed, aggregating from `SensorIntelActor`
- [ ] #2 Shared helper `services/fleet-view/snapshot-aggregator.ts` implements dedup semantics from ADR-0002: max(risk), union(ips, fingerprints, sessionIds), min(firstSeenAt), max(lastSeenAt), sum(anomalyCount), attribution via `seenOnSensors` array
- [ ] #3 Stale-row handling: rows older than 5 min threshold (configurable via env) return `status: 'stale'` in the envelope rather than being dropped
- [ ] #4 UI hooks in `apps/signal-horizon/ui/src/hooks/soc/api.ts` updated to call the fleet routes for the SOC dashboard; sensor-detail drawer continues to call `/synapse/:sensorId/actors`
- [ ] #5 Integration tests verify dedup correctness across >=2 mock sensors, including same-actor-on-multiple-sensors merge and offline-sensor stale handling
<!-- AC:END -->
