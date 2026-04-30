---
id: TASK-100
title: Make UI tests a blocking CI gate (triage 16 pre-existing failures)
status: To Do
assignee: []
created_date: '2026-04-30 08:23'
labels:
  - ci
  - signal-horizon
  - ui
  - testing
dependencies: []
references:
  - .github/workflows/signal-horizon-quality.yml
  - >-
    apps/signal-horizon/ui/src/components/fleet/pingora/__tests__/TarpitConfig.test.tsx
  - apps/signal-horizon/ui/src/components/LoadingStates.test.tsx
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `ui-tests` job in `.github/workflows/signal-horizon-quality.yml` runs `pnpm --filter @atlascrew/signal-horizon-ui test` with `continue-on-error: true`, so UI test failures never block a merge. As of TASK-99 there are 16 pre-existing failing tests across 9 files (TarpitConfig, LoadingStates, ClickHouseOpsPanel, ThreatTrajectoryFeed, PlaybookRunner, CampaignTimelinePage, HuntingPage, DlpConfig, EntityConfig). New tests pass but old breakage accumulates. Triage each failure: fix it, or quarantine with `it.skip` + a per-failure tracking issue, then drop `continue-on-error: true` so the job becomes a real gate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the 16 pre-existing failing UI tests is either fixed or quarantined with it.skip + a tracking issue
- [ ] #2 ui-tests job in signal-horizon-quality.yml drops continue-on-error: true and becomes a required check
- [ ] #3 CI fails on any UI test regression
- [ ] #4 Quarantine list (if any) is documented in apps/signal-horizon/ui/CLAUDE.md or a docs/devel/testing/ note
<!-- AC:END -->
