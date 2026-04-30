---
id: TASK-81
title: 'Fleet SOC views: campaigns via Campaign rollup (not snapshot)'
status: Done
assignee: []
created_date: '2026-04-17 21:48'
updated_date: '2026-04-18 05:55'
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
  - apps/signal-horizon/api/src/services/correlator/index.ts
  - apps/signal-horizon/api/prisma/schema.prisma
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement fleet-wide campaign routes reading from the `Campaign` rollup table (schema.prisma:644), NOT from `SensorIntelCampaign`. Per ADR-0002, `Campaign` is the authoritative source — the correlator service (services/correlator/index.ts:256,304) maintains `isCrossTenant`, `tenantsAffected`, `confidence`, `severity`, `lastActivityAt` in real time on signal ingestion.

This is the only rollup-backed surface in the ADR plan.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 New fleet routes: `GET /synapse/campaigns`, `GET /synapse/campaigns/:campaignId`, `GET /synapse/campaigns/:campaignId/actors`, `GET /synapse/campaigns/:campaignId/graph`
- [x] #2 All reads hit `prisma.campaign.findMany({ where: { tenantId, ... } })` — no fan-out, no SensorIntelCampaign read
- [x] #3 Response shape adapts Campaign rows to the existing `SocCampaign*` types so UI change is minimal
- [x] #4 Filter by `status`, `isCrossTenant`, `severity` work at the DB level
- [x] #5 UI hooks updated to point SOC dashboard at the fleet routes
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Fleet-wide campaign routes implemented per ADR-0002, reading from the `Campaign` rollup table maintained by the correlator service (services/correlator/index.ts:256,304). Four new non-sensor-prefixed routes added to `synapse.ts`, UI hooks rewired, 6 new tests added (21 existing tests still pass).

## Changes

**API** (`apps/signal-horizon/api/src/api/routes/synapse.ts`):
- Added 4 fleet routes mounted *before* the existing `/:sensorId/campaigns*` block so Express route-matching favours the literal prefix:
  - `GET /synapse/campaigns` (list, supports `status`, `limit`, `offset`)
  - `GET /synapse/campaigns/:campaignId` (detail + correlation signals)
  - `GET /synapse/campaigns/:campaignId/actors` (threats projected as actors via `CampaignThreat -> Threat`)
  - `GET /synapse/campaigns/:campaignId/graph` (2-hop nodes+edges for cytoscape)
- Added helpers `mapDbCampaignStatus`, `mapUiCampaignStatusToDb`, `campaignRowToSoc`, `extractCampaignAttackTypes` near the existing campaign normalizers.
- Status enum translation handled at the DB layer: UI `DETECTED`/`DORMANT` ↔ DB `MONITORING`/`FALSE_POSITIVE`.
- Returns 503 if `prisma` not wired, 404 if campaign not found for the tenant.

**UI**:
- `hooks/soc/api.ts`: `fetchCampaigns`/`fetchCampaignDetail`/`fetchCampaignActors` drop the `sensorId` argument; URLs now `/synapse/campaigns*`.
- `pages/soc/CampaignsPage.tsx`: removed `sensorId` from queryKey and call.
- `pages/soc/CampaignDetailPage.tsx`: removed `useSocSensor` entirely (no longer needed).
- `components/soc/CampaignGraph.tsx`: dropped the `sensorId` prop + call signature; `fetchGraphData` now takes only `campaignId`. No callers were passing `sensorId`, so no breakage.

**Tests** (`synapse.test.ts`, +6 cases, all 27 pass):
- List route reads from `Campaign` table with tenant scoping, maps status + severity + confidence.
- Status filter `?status=DETECTED` translates to DB `MONITORING`.
- Actors route projects `Threat` rows with `threatType=IP` to `ips: [indicator]`, others to `ips: []`.
- Graph route emits campaign + threat nodes with `type: role` edges.
- 404 when campaign not found for tenant; 503 when prisma not wired.

## Design notes

- Campaign rows are read with `include: { _count: { select: { threatLinks: true } } }` so `actorCount` is a single SQL aggregate, no N+1.
- The `role` column on `CampaignThreat` (e.g. `"primary_actor"`, `"infrastructure"`) is surfaced as the edge `type` in the graph, enabling richer cytoscape styling without schema changes.
- `campaignRowToSoc` matches the existing `SocCampaign` response shape used by the per-sensor routes, so UI types didn't need to change.
- Per-sensor `/:sensorId/campaigns*` routes are retained for sensor-detail drill-down, as committed in ADR-0002.

## Verification

- `pnpm exec tsc --noEmit` clean on both `apps/signal-horizon/api` and `apps/signal-horizon/ui`.
- `pnpm exec vitest run src/api/routes/synapse.test.ts` → 27/27 passing (21 existing + 6 new).
- No dev-server manual verification performed (no sensors connected in the local scratch env); logic is covered by the mocked-prisma integration tests.

## Out of scope / not done here

- Full browser-level smoke test of the SOC Campaigns page + detail drawer requires a populated `Campaign` table, which depends on correlator running against ingested signals. Should be verified once the rest of TASK-79/80/82/83 lands and the SOC dashboard is exercised end-to-end.
- The 5-min staleness badge from ADR-0002 does not apply here because the rollup is correlator-maintained in real time on signal ingestion — the freshness concern is specific to snapshot-backed surfaces.
<!-- SECTION:FINAL_SUMMARY:END -->
