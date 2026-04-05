---
id: TASK-5
title: Migrate SOC (Security Operations Center) Views to @/ui (Phase 3)
status: Done
assignee: []
created_date: '2026-03-18 04:43'
updated_date: '2026-03-18 04:49'
labels: []
dependencies: []
references:
  - apps/signal-horizon/ui/CODEX_MIGRATION_SPEC.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Modernize the Security Operations Center (SOC) views, bringing real-time monitoring and threat analysis pages into 100% compliance with the Apparatus Design System. This phase covers both high-level overview maps and granular detail views.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Replace all hardcoded colors, spacing, and typography in SOC pages: LiveMapPage, SessionsPage, ActorsPage, and CampaignsPage.
- [ ] #2 Migrate SOC detail views: ActorDetailPage, SessionDetailPage, and CampaignDetailPage to @/ui compliance.
- [ ] #3 Maintain WebGL/Canvas coordinate logic in LiveMap while migrating UI overlays to @/ui primitives.
- [ ] #4 TypeScript type-checking passes for all migrated SOC pages.
<!-- AC:END -->
