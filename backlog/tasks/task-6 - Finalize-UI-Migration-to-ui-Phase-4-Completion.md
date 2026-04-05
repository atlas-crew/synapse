---
id: TASK-6
title: Finalize UI Migration to @/ui (Phase 4 & Completion)
status: Done
assignee: []
created_date: '2026-03-18 04:54'
updated_date: '2026-03-18 04:59'
labels: []
dependencies: []
references:
  - apps/signal-horizon/ui/CODEX_MIGRATION_SPEC.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Complete the full migration of the Signal Horizon UI to the Apparatus Design System. This final phase covers the high-stakes War Room, search interfaces, and system-wide configuration/management views. Completion of this task marks 100% component library adoption across all user-facing pages.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Replace all hardcoded colors, spacing, and typography in final set of pages: WarRoomPage, SocSearchPage, ConfigManagerPage, SensorKeysPage, and FleetUpdatesPage.
- [ ] #2 Migrate remaining smaller utility pages like RuleDistributionPage and OnboardingPage to @/ui compliance.
- [ ] #3 Ensure all layouts use design system primitives (Box, Stack, Grid, Text).
- [ ] #4 Final TypeScript type-check for the entire UI workspace passes.
<!-- AC:END -->
