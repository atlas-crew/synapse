# ADR 0002 — Fleet-view strategy for SOC surfaces

- **Status:** Accepted
- **Date:** 2026-04-17
- **Related:** TASK-77 (Fleet-wide payload snapshot reads), TASK-78 (this ADR), ADR-0001 (catalog overlay), memory `project_dashboard_federation.md`

## Context

The `synapse.ts` route module mounts every SOC-facing read under `/:sensorId/` — actors, sessions, campaigns, blocks, rules, entities, profiles. Each handler calls `synapseProxy.list*(sensorId, tenantId, ...)` which tunnels a WebSocket request to one sensor's local Synapse process and returns that sensor's slice of state.

A SOC analyst investigating a threat does not think in terms of one sensor. They want "every actor we are tracking across the fleet," "every active campaign," "every session flagged as suspicious." Forcing the UI to pick a sensor from a dropdown and paginate sensor-by-sensor is a usability failure and a modeling mistake — these are tenant-level observations that happen to be collected by a sensor, not sensor-level objects.

TASK-77 handled the narrow subset of this problem where the hub already stores the data: `SensorPayloadSnapshot` is indexed on `[tenantId, capturedAt]` and the DLP/payload routes could be migrated by dropping the `sensorId` filter and aggregating across sensors' latest snapshots. That fix did not generalise to the rest of the SOC surface, which is what this ADR addresses.

Three strategies were on the table:

- **A. Rollup tables.** `Threat` (schema.prisma:524) and `Campaign` (644) exist in the schema with `isFleetThreat`, `fleetRiskScore`, `tenantsAffected`, `isCrossTenant` fields. If maintained, they are the cheapest possible read — one indexed query per tenant.
- **B. Tunnel fan-out.** Iterate the tenant's sensors, call each via `synapseProxy`, merge in the API handler. Always live, uniform across surfaces, but O(N) round trips per user request and unbounded tail latency.
- **C. Snapshot dedup.** Read per-sensor snapshot mirrors (`SensorIntelActor`, `SensorIntelSession`, `SensorIntelCampaign`, `SensorIntelProfile` — schema.prisma:346–436), dedup on the application key (`actorId`, `sessionId`, `campaignId`). Cached fan-out — moderate freshness, good read performance.

Before deciding, we ran two audits (TASK-78 AC#2 and AC#3).

### Audit findings

**Snapshot ingestion — GREEN.** All four `SensorIntel*` tables are upserted on a 60-second timer by `FleetIntelIngestionService` (`services/fleet-intel/ingestion-service.ts:285-410`). Each cycle polls every connected sensor over the tunnel and writes the result. Max staleness is ~65 s including execution time. There is currently a duplicate service (`FleetIntelService`) doing identical upserts — tracked as a cleanup follow-up. Strategy (C) is backed by real production code, not aspirational schema.

**Rollup maintenance — MIXED.**
- `Threat` is **not maintained**. No code path writes Threat rows. The only Threat mutation in the codebase is `prisma.threat.update()` in `threats.ts:244` for operator feedback. `isFleetThreat`, `fleetRiskScore`, and `tenantsAffected` remain at schema defaults forever. The table is aspirational.
- `Campaign` is **actively maintained**. The correlator service (`services/correlator/index.ts:256,304`) creates and updates Campaign rows from signal ingestion, recomputing `isCrossTenant`, `tenantsAffected`, `confidence`, `severity`, and `lastActivityAt` on every batch. Cross-tenant correlation is live. Freshness is sub-second.

These findings collapse the decision space: strategy (A) is viable only for campaigns, strategy (C) is viable for actors/sessions/campaigns/profiles, strategy (B) remains the universal fallback but carries the costs we already knew about.

The decision axis is **freshness requirement**, not "which table exists." SOC browse-and-click flows can tolerate the ~65 s snapshot staleness. Write flows ("block this IP across the fleet now") cannot and must fan out through the existing `fleet-control.ts:721` broadcast path.

## Decision

Per SOC surface:

| Surface | Strategy | Source |
|---|---|---|
| **Actors** (list, detail, timeline) | Snapshot dedup | `SensorIntelActor` (dedup on `actorId`, merge `raw` payloads) |
| **Sessions** (list, detail) | Snapshot dedup | `SensorIntelSession` (dedup on `sessionId`) |
| **Campaigns** (list, detail, actors, graph) | Rollup | `Campaign` (filter `tenantId`, `isCrossTenant` or `status`) |
| **Profiles** (list, detail) | Snapshot dedup | `SensorIntelProfile` (dedup on `template, method`) |
| **Blocks** (list) | Fan-out (temporary) → new snapshot | No table today; fan-out via `synapseProxy.listBlocks` until `SensorIntelBlock` lands |
| **Rules** (list, detail) | Per-sensor only | Out of scope for fleet view — canonical rule catalog is served by the existing `fleet.ts` `/fleet/rules` routes backed by `SynapseRule`/`TenantRuleOverride` (see ADR-0001). The `/synapse/:sensorId/rules` endpoint represents "what is currently loaded on this one sensor" and stays sensor-scoped as a diagnostic view. |
| **Entities** (list, detail) | Fan-out (temporary) → new snapshot | No table today; fan-out until `SensorIntelEntity` lands |
| **Writes** (add/remove block, push rule, restart, etc.) | Fan-out | Existing `fleet-control.ts` broadcast pattern, `{ sensorIds: string[] }` body |

All aggregated SOC routes return the partial-failure envelope established in `fleet-control.ts:721` and extended in TASK-77:

```ts
{
  results: { sensorId: string, status: 'ok' | 'stale' | 'error', data?: T, error?: string }[],
  summary: { succeeded: number, stale: number, failed: number },
}
```

`stale` is new and specific to snapshot-backed reads: a sensor whose latest `SensorIntel*` row is older than a configurable threshold (default 5 minutes) contributes but flags the row so the UI can show a "last seen N min ago" badge without dropping the data.

### Dedup semantics

The snapshot strategy must reconcile the same `actorId` / `sessionId` / etc. appearing on multiple sensors:

- **Risk/severity/confidence scores**: take the **maximum** across sensors. Never average — averaging understates fleet-level risk. The whole point of fleet correlation is that a bad actor seen on three sensors is more concerning than on one.
- **Set-typed fields** (`ips`, `fingerprints`, `sessionIds`): union across sensors.
- **Time-typed fields**: `firstSeenAt` = min, `lastSeenAt` / `lastActivityAt` = max.
- **Counters** (`requestCount`, `anomalyCount`): sum.
- **Attribution**: every merged row carries a `seenOnSensors: string[]` array so the UI can drill down.

These semantics are encoded in a shared `services/fleet-view/snapshot-aggregator.ts` helper rather than repeated per route.

## Consequences

### Operational

- **Dashboard queries go from O(N sensors × tunnel hops) to O(1 indexed DB query)** for the snapshot and rollup paths. A 100-sensor tenant's SOC page stops multiplying WebSocket traffic by 100× on every refresh.
- **`FleetIntelIngestionService` becomes load-bearing.** If it stops running, every snapshot-backed dashboard freezes at whatever staleness the rows currently carry. Needs alerting on the service's liveness and on aggregated snapshot age (`max(updatedAt)` per tenant should stay under ~2 minutes).
- **The 60 s staleness bound is a product commitment now.** If a future change stretches it to 5 minutes, the "cached fan-out" framing breaks down for the SOC use case. Changes to the polling cadence need to be called out in PR descriptions.

### Separation of concerns

- **Per-sensor routes stay as the diagnostic surface.** `/synapse/:sensorId/*` routes remain for drill-down, sensor-detail pages, and live operator checks. Fleet routes live at non-sensor-prefixed paths. This maps cleanly onto the existing UI pattern where the fleet dashboard and the sensor-detail drawer are already separate.
- **Campaigns read from `Campaign`, not `SensorIntelCampaign`.** Both tables exist. The `Campaign` rollup is the better source because it already does cross-tenant correlation that the per-sensor snapshot cannot. `SensorIntelCampaign` is only kept because the ingestion service writes to it uniformly with the other snapshot tables; treating it as authoritative for fleet views would be wrong.
- **Writes never use snapshots or rollups.** A "block this IP" request that returns after the snapshot ingestion cycle is not actually blocked yet. All writes go through the existing fleet-control broadcast pattern with immediate tunnel commands.

### Known limitations

- **Blocks and entities ride on fan-out until follow-up work lands.** Fan-out for these works and is correct, it is just slow. For single-digit sensor counts it is fine; we accept the cost until `SensorIntelBlock` and `SensorIntelEntity` are added.
- **Sensors offline during the last poll cycle appear as `stale` in results.** The UI must handle the tri-state `ok | stale | error` — this is a real behavioural change from "one sensor, one response shape."
- **Pagination is simple** (DB-level offset/limit on the aggregated query) but is not identical to the sensor-side pagination users may have been used to. Cursor semantics change. No existing UI pages depend on sensor-side cursors, so this is a one-time migration cost.
- **The `Threat` table stays dead for now.** Implementing a threat-rollup job to mirror the campaign correlator is plausible future work — it would let actor dashboards read from `Threat` instead of from `SensorIntelActor` dedup, which would reduce aggregation cost. Not chosen now because the snapshot path already works for actors and duplicate writers of the same data is its own antipattern.

## Rejected alternatives

- **Universal fan-out for all SOC reads.** Simplest, uniform, always live — but P99 latency becomes the slowest sensor's P99 and sensor load amplifies per dashboard view. Only kept as a temporary fallback for blocks/entities until snapshot tables are added.
- **Universal snapshot dedup for all SOC reads (including campaigns).** Would ignore that `Campaign` is better-maintained and already does cross-tenant correlation. Reading from `SensorIntelCampaign` instead would duplicate correlator work and lose the cross-tenant dimension.
- **Implement a `Threat` rollup job now, read actors from `Threat`.** Would add a second write path for data we already have in `SensorIntelActor`. If one of the two paths diverges the dashboards silently drift. Choose one source; `SensorIntelActor` already works.
- **Push-based ingestion (sensors write `SensorIntel*` themselves).** Would eliminate the hub-side timer but requires sensors to hold hub DB credentials and pushes schema ownership into the Rust codebase. The current cached-pull architecture keeps the hub as the single writer to its own database.
- **New unified "fleet-view" response type (distinct from current per-sensor types).** Rejected — the snapshot rows carry the same shape as the sensor's proxy response because the ingestion service stored the raw payload. Preserve the existing types and extend only with the `seenOnSensors` attribution array and the partial-failure envelope.

## References

- Snapshot ingestion: `apps/signal-horizon/api/src/services/fleet-intel/ingestion-service.ts` (lines 285–410)
- Duplicate ingestion service: `apps/signal-horizon/api/src/services/fleet/fleet-intel.ts` (consolidation follow-up filed separately)
- Campaign correlator: `apps/signal-horizon/api/src/services/correlator/index.ts` (lines 256, 304)
- Fleet-control broadcast pattern: `apps/signal-horizon/api/src/api/routes/fleet-control.ts:721`
- Snapshot schema: `apps/signal-horizon/api/prisma/schema.prisma` (`SensorIntelActor`, `SensorIntelSession`, `SensorIntelCampaign`, `SensorIntelProfile` — lines 346–436; `SensorPayloadSnapshot` — line 438)
- Rollup schema: `apps/signal-horizon/api/prisma/schema.prisma` (`Threat` — line 524, unmaintained; `Campaign` — line 644, maintained)
- Per-sensor routes retained: `apps/signal-horizon/api/src/api/routes/synapse.ts` (diagnostic surface)
- Related ADR: `apps/signal-horizon/docs/architecture/adr-0001-synapse-catalog-overlay.md`
