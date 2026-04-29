---
id: TASK-84
title: Consolidate duplicate fleet-intel ingestion services
status: Done
assignee: []
created_date: '2026-04-17 21:49'
updated_date: '2026-04-28 18:00'
labels:
  - api
  - signal-horizon
  - tech-debt
dependencies: []
references:
  - apps/signal-horizon/api/src/services/fleet-intel/ingestion-service.ts
  - apps/signal-horizon/api/src/services/fleet/fleet-intel.ts
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Audit during TASK-78 (ADR-0002 prep) surfaced two services doing identical 60 s timer-driven upserts against `SensorIntelActor`/`Session`/`Campaign`/`Profile`:

- `services/fleet-intel/ingestion-service.ts` (`FleetIntelIngestionService`)
- `services/fleet/fleet-intel.ts` (`FleetIntelService`)

Both are instantiated and started at app boot. The result is double the sensor load and double the DB writes for identical data. Almost certainly the remnants of a half-done migration from one to the other.

Pick one as canonical, delete the other, verify the app still boots and snapshots still populate. Fleet SOC view implementation tasks (actors/sessions/blocks/entities) depend on exactly one ingestion path existing; this cleanup unblocks them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Identify which service is newer / intended and document the choice in the PR description
- [x] #2 Remove the other service and its app-boot wiring
- [x] #3 Verify on a local run that all four `SensorIntel*` tables continue to populate after the consolidation
- [x] #4 If the two services had any non-overlapping logic, port it to the canonical one before deletion
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Consolidated to FleetIntelService (services/fleet/fleet-intel.ts) and deleted FleetIntelIngestionService (services/fleet-intel/ingestion-service.ts) along with its test file and now-empty parent dir. Verified column-by-column that both services wrote identical shapes to all four SensorIntel* tables, so removal loses no data.

Decision: FleetIntelService is canonical because it owns both ingestion and the read API (getActors/getSessions/getCampaigns/getProfiles/getPayloadStats) consumed by 5 routes in fleet-intel.ts and 7 offline-fallback paths in synapse.ts. The deleted service was ingestion-only.

Known scaling gap to flag for follow-up: FleetIntelIngestionService used paginated polling (pageSize=100, maxPages=10, up to 1000 rows per sensor per cycle); FleetIntelService takes single-chunk caps at 200 per kind per cycle. With sensors holding >200 actors/sessions/campaigns the kept service silently truncates. Worth a follow-up task — likely emerges naturally during TASK-85 cadence observability work.

Verified locally: type-check clean, lint 0 errors, 109 test files / 1771 tests pass, build succeeds. CI green on push (Signal Horizon quality, deployment preflight, both CodeQL workflows).
<!-- SECTION:FINAL_SUMMARY:END -->
