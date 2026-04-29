---
id: TASK-98
title: FleetIntelService getActors single-chunk pagination scaling gap
status: To Do
assignee: []
created_date: '2026-04-29 10:04'
labels:
  - api
  - signal-horizon
  - fleet-aggregation
  - scaling
dependencies: []
references:
  - apps/signal-horizon/api/src/services/fleet/fleet-intel.ts
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FleetIntelService.getActors uses a single-chunk read with limit cap (~200 rows) where the legacy ingestion service paginated 100×10. With realistic fleet cardinalities this caps fleet-view actor results before dedup runs, which would silently truncate TASK-79 fleet routes and break tests at >200 distinct actors. Investigate moving to cursor-paged reads or raising the cap with batching, and add a guard that errors when the cap is hit (so we don't silently lose rows).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Read path for SensorIntelActor returns all rows above a single-page cap (cursor pagination or batched chunks), no silent truncation
- [ ] #2 If a cap is enforced, the API surface returns a structured warning rather than dropping rows
- [ ] #3 Test covers > cap distinct actors across the fleet
<!-- AC:END -->
