---
id: TASK-79
title: 'Fleet SOC views: actors via SensorIntelActor dedup'
status: In Progress
assignee: []
created_date: '2026-04-17 21:48'
updated_date: '2026-04-29 10:17'
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
- [x] #1 New fleet routes added: `GET /synapse/actors`, `GET /synapse/actors/:actorId`, `GET /synapse/actors/:actorId/timeline` — all non-sensor-prefixed, aggregating from `SensorIntelActor`
- [x] #2 Shared helper `services/fleet-view/snapshot-aggregator.ts` implements dedup semantics from ADR-0002: max(risk), union(ips, fingerprints, sessionIds), min(firstSeenAt), max(lastSeenAt), sum(anomalyCount), attribution via `seenOnSensors` array
- [x] #3 Stale-row handling: rows older than 5 min threshold (configurable via env) return `status: 'stale'` in the envelope rather than being dropped
- [x] #4 UI hooks in `apps/signal-horizon/ui/src/hooks/soc/api.ts` updated to call the fleet routes for the SOC dashboard; sensor-detail drawer continues to call `/synapse/:sensorId/actors`
- [x] #5 Integration tests verify dedup correctness across >=2 mock sensors, including same-actor-on-multiple-sensors merge and offline-sensor stale handling
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Found existing infrastructure to build on:
- `FleetPartialResult<T>` and `FleetPartialAggregateResult<TItem, TAggregate>` already exist at `apps/signal-horizon/api/src/types/fleet-partial-result.ts` — need to extend status enum from 'ok'|'error' to 'ok'|'stale'|'error'.
- Per-sensor `/synapse/:sensorId/actors*` routes live at `apps/signal-horizon/api/src/api/routes/synapse.ts:1509-1593`. New fleet routes go in same router but registered BEFORE the `/:sensorId/...` routes (Express ordering).
- `FleetIntelService.getActors(tenantId, options)` returns `{ actors: SensorIntelActor[], total }` — non-deduped raw rows. Pagination cap is 200; filed TASK-98 to track.
- `Actor` interface (synapse-proxy.ts:99-112) is the canonical shape — `raw: Json` on each `SensorIntelActor` row stores this. Merged shape: `Actor & { seenOnSensors: string[] }`.
- Sister fleet-intel.ts route file (`/api/v1/fleet/intel/actors`) is pre-ADR, non-envelope; out of scope for TASK-79.
<!-- SECTION:NOTES:END -->
