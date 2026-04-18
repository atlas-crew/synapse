---
id: TASK-84
title: Consolidate duplicate fleet-intel ingestion services
status: To Do
assignee: []
created_date: '2026-04-17 21:49'
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
- [ ] #1 Identify which service is newer / intended and document the choice in the PR description
- [ ] #2 Remove the other service and its app-boot wiring
- [ ] #3 Verify on a local run that all four `SensorIntel*` tables continue to populate after the consolidation
- [ ] #4 If the two services had any non-overlapping logic, port it to the canonical one before deletion
<!-- AC:END -->
