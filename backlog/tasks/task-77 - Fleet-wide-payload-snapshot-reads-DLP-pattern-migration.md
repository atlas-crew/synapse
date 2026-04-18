---
id: TASK-77
title: Fleet-wide payload snapshot reads (DLP-pattern migration)
status: To Do
assignee: []
created_date: '2026-04-17 20:50'
updated_date: '2026-04-17 21:22'
labels:
  - api
  - signal-horizon
  - fleet-aggregation
  - payload-snapshot
dependencies: []
references:
  - apps/signal-horizon/api/src/api/routes/synapse.ts
  - apps/signal-horizon/api/src/api/routes/onboarding.ts
  - apps/signal-horizon/api/src/api/routes/fleet-control.ts
  - apps/signal-horizon/api/src/api/routes/fleet-diagnostics.ts
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Apply the DLP-stats/violations pattern to the remaining `synapse.ts` routes that read from the `SensorPayloadSnapshot` table. These are the routes where "drop the `sensorId` filter and aggregate across tenant snapshots" genuinely works without architectural work — the table is already tenant-indexed on `[tenantId, capturedAt]` (schema.prisma:453).

**Explicitly out of scope** (deferred to a separate architecture task): actors, sessions, campaigns, blocks, rules, entities. Those routes tunnel through `synapseProxy.list*` to per-sensor Synapse processes, and the `SensorIntel*` mirror tables are keyed `(tenantId, sensorId, resourceKey)` — a fleet-wide view for those requires a design decision between fan-out, snapshot dedup, and reading from the `Threat`/`Campaign` rollup tables. That decision is not part of this task.

Also in scope: onboarding batch approve/reject (real gap, independent of the snapshot work) and the partial-failure response envelope that the new routes should share.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Payload snapshot reads have fleet-wide counterparts (non-sensor-prefixed paths) that aggregate across the tenant's `SensorPayloadSnapshot` rows: `/payload/stats` (currently at synapse.ts:1533), `/payload/bandwidth` (1611), `/payload/anomalies` (1582), `/payload/endpoints` (1553). Existing per-sensor variants remain for the sensor-detail view.
- [ ] #2 DLP routes also migrated to fleet-wide paths for consistency (`/dlp/stats`, `/dlp/violations`), reading the same `SensorPayloadSnapshot.stats.dlp` JSON path as synapse.ts:176,207 but aggregated across sensors.
- [ ] #3 Onboarding supports batch approval and rejection — new `POST /onboarding/pending/approve` and `POST /onboarding/pending/reject` accepting `{ sensorIds: string[] }`, alongside the existing per-sensor routes at `onboarding.ts:237,318`.
- [ ] #4 Aggregated and batch responses use a consistent partial-failure envelope: `{ results: [{ sensorId, status: 'ok'|'error', data?, error? }], summary: { succeeded, failed } }` — matching the shape already established in `fleet-control.ts:721`.
- [ ] #5 UI call sites for the DLP/payload fleet dashboards are pointed at the new aggregated paths; per-sensor payload views continue to use the existing `/:sensorId/payload/*` routes.
<!-- AC:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Phase 1 — Payload snapshot aggregation helpers
Build one shared helper in a service (e.g. `services/payload-aggregator.ts`) that takes `tenantId` + a field selector (`stats` | `bandwidth` | `endpoints` | `anomalies`) and returns the merged result across the tenant's latest snapshot per sensor. Semantics:
- Use `findMany` with `distinct on sensorId` and `orderBy capturedAt desc` to pick each sensor's latest snapshot.
- Merge strategy per field:
  - `stats`: sum numeric counters, union sets where relevant (e.g. `dlp.patterns`).
  - `bandwidth`: sum throughput, time-align buckets.
  - `endpoints`: union by `(method, path)`, sum request counts.
  - `anomalies`: concatenate and sort by timestamp desc.

## Phase 2 — Route handlers
Add non-sensor-prefixed GET handlers in `synapse.ts` that call the helper. Keep the existing `/:sensorId/payload/*` and `/:sensorId/proxy/_sensor/dlp/*` routes intact for sensor-detail views.

## Phase 3 — Onboarding batch handlers
Add `POST /onboarding/pending/approve` and `POST /onboarding/pending/reject` in `onboarding.ts`. Loop over `sensorIds`, reuse the existing per-sensor approve/reject logic from onboarding.ts:237,318, and wrap in the partial-failure envelope.

## Phase 4 — Shared envelope type
Create a shared TS type `FleetPartialResult<T>` mirroring `fleet-control.ts:721`'s shape. Export from a common module so aggregated payload routes and onboarding batch handlers use the identical contract.

## Phase 5 — UI rewiring
Point the DLP/payload fleet dashboards at the new aggregated paths. Per-sensor detail drawers keep calling the old `/:sensorId/payload/*` routes unchanged.

## Phase 6 — Tests + docs
- Integration tests in `synapse.test.ts` with >=2 mock sensor snapshots to verify aggregation math (sums, unions, latest-per-sensor selection).
- New `onboarding.test.ts` cases for batch approve/reject including partial failure.
- API docs updated to list the new aggregated paths; per-sensor variants documented as "use for sensor-detail views only."
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Architecture-decision carve-out (2026-04-17): The actors/sessions/campaigns/blocks/rules/entities routes in synapse.ts tunnel to per-sensor Synapse processes via synapseProxy.list*, and the SensorIntel* mirror tables are keyed (tenantId, sensorId, resourceKey). A fleet-wide view for those requires a design choice between (a) tunnel fan-out, (b) SensorIntel snapshot dedup, or (c) reading Threat/Campaign rollup tables. That is being tracked as a separate follow-up task and is explicitly NOT in scope here. See the commit where the DLP routes were originally moved (synapse.ts:176,207) for the snapshot-aggregation precedent this task extends.
<!-- SECTION:NOTES:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Synapse API reference docs updated to list the new aggregated paths and mark the old `/:sensorId/` variants as deprecated (if kept for compat) or removed
- [ ] #2 Integration tests cover: (a) aggregation correctness across >=2 mock sensors for each moved route, (b) onboarding batch approve/reject happy path + partial failure, (c) partial-failure envelope shape is stable
<!-- DOD:END -->
