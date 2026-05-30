---
id: TASK-80
title: 'Fleet SOC views: sessions via SensorIntelSession dedup'
status: Done
assignee:
  - '@codex'
created_date: '2026-04-17 21:48'
updated_date: '2026-05-30 21:48'
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
Implement fleet-wide session routes per ADR-0002. Reads from `SensorIntelSession`, deduplicates on `sessionId` per tenant. Sessions are typically bound to a single sensor in practice (sessions don't migrate between sensors), so dedup should be rare — mostly this is "union across sensors with stable ordering." Uses the shared aggregator helper from the actors task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 New fleet routes: `GET /synapse/sessions`, `GET /synapse/sessions/:sessionId`
- [x] #2 Filter parameters work at the aggregated layer: `actorId`, `suspicious`, `limit`, `offset`
- [x] #3 Partial-failure envelope with stale-row handling consistent with ADR-0002
- [x] #4 UI rewired for fleet SOC dashboard session list; sensor-detail retains `/synapse/:sensorId/sessions`
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implementation pass started: scope is fleet-wide SOC session aggregation via SensorIntelSession, matching the completed fleet actor/campaign patterns where possible. First step is to map existing route/service/UI hooks and add focused tests before implementation.

Implemented fleet SOC sessions via SensorIntelSession snapshots: added literal GET /synapse/sessions and GET /synapse/sessions/:sessionId routes before per-sensor session routes; dedupes by sessionId, preserves seenOnSensors attribution, supports actorId/actor_id, suspicious, limit, and offset at the aggregated layer, emits ADR-0002 partial-result freshness envelopes, and keeps /synapse/:sensorId/sessions plus per-sensor helper/detail fetchers available for diagnostic surfaces. Rewired SessionsPage and SessionDetailPage to fleet aggregate responses and updated site-scan session ID resolution. Validation: API/UI typechecks passed; focused API/UI route, aggregator, page, and API helper tests passed; source review CLEAN; test audit CLEAN.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed TASK-80. Fleet SOC session list/detail now read SensorIntelSession snapshots, merge cross-sensor contributors, expose fleet freshness envelopes, and drive the SOC sessions list/detail UI from the new fleet API while preserving per-sensor diagnostic session routes/helpers.
<!-- SECTION:FINAL_SUMMARY:END -->
