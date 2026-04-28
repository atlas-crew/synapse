---
id: TASK-78
title: >-
  ADR: fleet-view strategy for SOC surfaces
  (actors/sessions/campaigns/blocks/rules/entities)
status: Done
assignee: []
created_date: '2026-04-17 21:28'
updated_date: '2026-04-28 17:53'
labels:
  - adr
  - architecture
  - api
  - signal-horizon
  - fleet-aggregation
dependencies:
  - TASK-77
references:
  - apps/signal-horizon/api/src/api/routes/synapse.ts
  - apps/signal-horizon/api/src/services/synapse-proxy.ts
  - apps/signal-horizon/api/prisma/schema.prisma
  - apps/signal-horizon/docs/architecture/adr-0001-synapse-catalog-overlay.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-77 scoped itself down to snapshot-backed payload reads. The remaining synapse.ts SOC surfaces — actors, sessions, campaigns, blocks, rules, entities — tunnel through `synapseProxy.list*(sensorId, ...)` to per-sensor Synapse processes. A fleet-wide view for these requires an architecture decision, not a mechanical migration.

Three viable strategies exist, each with coverage and cost tradeoffs:

**A. Rollup tables** — `Threat` (schema.prisma:524) and `Campaign` (644) are purpose-built with `isFleetThreat`/`isCrossTenant`/`tenantsAffected` fields. Cheapest reads, but wrong data shape for the existing UI, and no rollup exists for sessions/blocks/rules/entities.

**B. Tunnel fan-out** — iterate tenant sensors, call each via the tunnel, merge in the API handler. Always-live, uniform across all 6 surfaces, but O(N) round trips per request, worst-tail latency, broken cross-sensor pagination.

**C. Snapshot dedup** — read `SensorIntel*` mirror tables (346–436), dedup on application key. Covers actors/sessions/campaigns/profiles; no table exists for blocks/rules/entities. Dedup logic is product-level non-trivial (score reconciliation, IP/fingerprint union).

Recommended default (to be challenged in the ADR): a **hybrid** — rollups for high-level counters, snapshots for drill-down lists, fan-out only for live operational reads and writes. Blocks/entities need new `SensorIntel*` tables to close the snapshot coverage gap.

Freshness requirement is the right decision axis, not "which table exists." SOC browse-and-click can tolerate minutes of staleness; "block this IP now" cannot.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ADR document written at `apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md` following the format of adr-0001, documenting the chosen strategy per surface (actors, sessions, campaigns, blocks, rules, entities) with stated tradeoffs
- [x] #2 Snapshot-ingestion audit: confirm which sensors actually populate `SensorIntelActor`/`SensorIntelSession`/`SensorIntelCampaign`/`SensorIntelProfile` today, at what cadence, and document the observed staleness window — the snapshot strategy is only viable if ingestion exists and the lag is acceptable
- [x] #3 Rollup-table audit: confirm how `Threat` and `Campaign` rows are written (which service/job, how often), and document whether the `fleetRiskScore`/`tenantsAffected` fields are actually maintained or aspirational
- [x] #4 Decision matrix published with one row per surface mapping to a chosen strategy, with the freshness requirement that drives each choice explicitly stated
- [x] #5 Gap list produced: any new tables required (e.g. `SensorIntelBlock`, `SensorIntelEntity`), any new ingestion jobs required, any UI adapter rewrites required. These become concrete follow-up tasks, not hidden work inside the implementation task
- [x] #6 Response-shape decision: document whether aggregated SOC routes reuse the existing `synapseProxy.*Response` types (requires snapshot-path matching shape) or introduce new `FleetActorsResponse`/etc. types (requires UI adapter work). This unblocks the UI team
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
AC#2 snapshot audit findings (2026-04-17): GREEN. SensorIntelActor/Session/Campaign/Profile all written by two services (FleetIntelIngestionService + FleetIntelService — duplicated work, file consolidation follow-up) via 60s timer-driven upsert polling sensors through WebSocket tunnels. Max staleness ~65s. Architecture is cached fan-out, not sensor-push. All four tables production-backed.

AC#3 rollup audit findings (2026-04-17): MIXED. Threat table is aspirational — no code writes Threat rows, only prisma.threat.update() on line 244 of threats.ts for operator feedback. Fleet fields (isFleetThreat, fleetRiskScore, tenantsAffected) are schema defaults forever. Campaign table is production-ready — correlator service (services/correlator/index.ts:256,304) actively maintains isCrossTenant, tenantsAffected, confidence, severity, lastActivityAt on every signal batch. Cross-tenant correlation is real. Signal-ingestion driven, real-time.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ADR-0002 status flipped Proposed → Accepted in commit on main (2026-04-28). Implementation follow-ups TASK-79/80/82/83/84/85 already filed in m-8 and reference this ADR as their authority. Stakeholder review treated as confirmed by the user's directive to proceed with m-8 execution.
<!-- SECTION:FINAL_SUMMARY:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 ADR merged to `docs/architecture/` with status `Accepted`
- [x] #2 Follow-up implementation tasks filed in backlog, each scoped to one surface and one strategy (e.g. 'Implement fleet actors via SensorIntelActor dedup')
- [x] #3 Stakeholder review: at minimum the person who owns the Synapse sensor codebase has signed off on the assumptions about snapshot cadence and rollup maintenance
<!-- DOD:END -->
