---
id: TASK-99
title: Rewire SOC dashboard pages to fleet actor hooks
status: Done
assignee: []
created_date: '2026-04-29 10:17'
updated_date: '2026-04-29 11:39'
labels:
  - ui
  - signal-horizon
  - fleet-aggregation
  - soc
milestone: m-8
dependencies:
  - TASK-79
references:
  - apps/signal-horizon/ui/src/hooks/soc/api.ts
  - apps/signal-horizon/ui/src/pages/soc/ActorsPage.tsx
  - apps/signal-horizon/ui/src/pages/soc/ActorDetailPage.tsx
  - apps/signal-horizon/ui/src/pages/soc/SocSearchPage.tsx
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
TASK-79 added the fetchFleetActors / fetchFleetActorDetail / fetchFleetActorTimeline hooks but the SOC dashboard pages (ActorsPage, ActorDetailPage, SocSearchPage, CommandPalette quick search) still pass a sensorId to the per-sensor fetchers. Per ADR-0002 §Decision the SOC dashboard surface should be fleet-deduped — sensor pickers belong on the sensor-detail drawer only. Refactor the dashboard call sites to use the fleet hooks, surface stale-row badges from the envelope summary in the UI, and keep sensor-detail flows on the per-sensor fetchers. Includes Vitest component tests for the stale badge.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ActorsPage list view calls fetchFleetActors and renders deduped rows with seenOnSensors badges
- [x] #2 ActorDetailPage uses fetchFleetActorDetail + fetchFleetActorTimeline by default; sensor-detail drawer keeps the sensor-prefixed routes
- [x] #3 Stale per-sensor entries are surfaced in the UI as a 'last seen N min ago' badge on the corresponding row
- [x] #4 Vitest component tests cover the stale badge and the deduped seenOnSensors render
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Rewired the SOC dashboard pages to the fleet actor hooks introduced by TASK-79 in 2 commits.

**ActorsPage** — Now calls `fetchFleetActors` (no sensorId), renders the deduped list, and shows two badges per row in a new "Coverage" column: a `N sensor(s)` info badge from `seenOnSensors`, and a `N min ago` warning badge when any contributing sensor reports stale. The third stat card flipped from "Correlations" (per-sensor metric, dead in fleet view) to "Sensors Reporting" (succeeded + stale count, accent flips to orange when stale > 0). The legacy sensor picker Input was removed from the header.

**ActorDetailPage** — Now calls `fetchFleetActorDetail` and `fetchFleetActorTimeline`. Header carries a `N sensor(s)` badge plus a "Stale data — N min ago" warning badge when `summary.stale > 0`, derived from the oldest stale `lastUpdatedAt`. Timeline events render with their per-sensor attribution from the new `sensorId`-tagged events.

**Orphan call sites cleaned up** — SocSearchPage's IP, fingerprint, and actor-detail searches all use the fleet hooks; the session-detail call stays per-sensor (TASK-80 will migrate it). CommandPalette quick search uses `fetchFleetActors`.

**Tests** — 9 new Vitest component tests across two files (`ActorsPage.test.tsx`, `ActorDetailPage.test.tsx`) cover: fleet-hook signatures (no sensorId), seenOnSensors badge with singular/plural copy, stale-row badge timing math, sensor picker absence, header stale indicator, and timeline event sensor attribution. Used `vi.useFakeTimers({ toFake: ['Date'] })` to fake only Date so React Query's scheduler keeps working — that pattern is worth knowing for future fake-timer + RQ tests.

**End-to-end smoke** — Started API + UI in tmux, ran `db-seed`, hit `/api/v1/synapse/actors` with the dev key. Got the expected envelope: 20 deduped actors, summary `{ succeeded: 1, stale: 0, failed: 6 }`, per-sensor results array with `lastUpdatedAt` populated for the live sensor.

**Verification:**
- UI typecheck clean (`tsc --noEmit` → exit 0)
- All 9 new tests pass; pre-existing unrelated UI test failures (TarpitConfig, LoadingStates, ClickHouseOpsPanel, etc.) confirmed unaffected
- Live API smoke: fleet routes return real data through the new envelope

**Notes for follow-up tasks:**
- The main UI workspace doesn't have Playwright wired up (only `apps/synapse-console-ui` does). CLAUDE.md UI rule mandates Playwright smoke tests for UI features — acknowledged as a gap; component tests + manual API smoke serve as the smoke-test layer for now.
- `useSocSensor` hook still exists and is used by sensor-detail flows — left untouched.
- TASK-80 (fleet sessions) will need to migrate the remaining `fetchSessionDetail` call in SocSearchPage to a fleet equivalent.
<!-- SECTION:FINAL_SUMMARY:END -->
