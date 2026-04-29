---
id: TASK-79
title: 'Fleet SOC views: actors via SensorIntelActor dedup'
status: Done
assignee: []
created_date: '2026-04-17 21:48'
updated_date: '2026-04-29 10:19'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped fleet-deduped actor SOC views per ADR-0002 §Decision in 4 commits.

**Envelope** — `FleetPartialResult<T>` extended with `'stale'` status and matching `summary.stale` counter so snapshot-backed reads can flag age-of-data without dropping rows. Three pre-existing test fixtures (sensor-enrollment, synapse, payload-aggregator) updated to match the wider summary shape; full API suite remains green at 1795/1795.

**Aggregator** — `services/fleet-view/snapshot-aggregator.ts` encodes the dedup semantics (max risk, OR isBlocked, min/max times, union sets, sum counters) and the per-sensor freshness classifier (ok | stale | error). 13 unit tests cover each reconciliation rule and the freshness state machine. Stale threshold is configurable via `FLEET_VIEW_STALE_AFTER_MS` (default 5 min, 1 min – 1 h range).

**Routes** — `GET /synapse/actors`, `GET /synapse/actors/:actorId`, `GET /synapse/actors/:actorId/timeline` registered in synapse.ts BEFORE the `/:sensorId/...` block (Express literal routes must register first to win matching). List + detail use snapshot dedup; timeline uses tunnel fan-out across `seenOnSensors` and reports per-sensor proxy errors. 11 integration tests cover dedup correctness across mock sensors, stale-row handling, offline-sensor reporting, minRisk filter, pagination, route-order preservation for the per-sensor surface, and timeline error fan-out.

**UI** — `fetchFleetActors`, `fetchFleetActorDetail`, `fetchFleetActorTimeline` added to `hooks/soc/api.ts` with matching `SocFleet*` types in `types/soc.ts` (envelope mirror + `seenOnSensors`-augmented actor + sensor-tagged timeline events). Per-sensor fetchers preserved unchanged for the sensor-detail drawer. UI typecheck clean.

**Follow-ups filed:**
- TASK-98 — FleetIntelService 200-row pagination cap could silently truncate fleet-view dedup results at realistic cardinalities. Medium priority.
- TASK-99 — SOC dashboard pages (ActorsPage, ActorDetailPage, SocSearchPage, CommandPalette) still pass a sensorId; switch them to the new fleet hooks and surface the stale-badge UI. Medium priority, depends on TASK-79.

**Out of scope (intentionally):**
- Existing `/api/v1/fleet/intel/actors` route in `fleet-intel.ts` is pre-ADR (no envelope). Kept as-is — separate route module, not the canonical SOC surface.
<!-- SECTION:FINAL_SUMMARY:END -->
