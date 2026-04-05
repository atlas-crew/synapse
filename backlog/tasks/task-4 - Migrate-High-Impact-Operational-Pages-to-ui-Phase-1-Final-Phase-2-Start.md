---
id: TASK-4
title: Migrate High-Impact Operational Pages to @/ui (Phase 1 Final & Phase 2 Start)
status: Done
assignee: []
created_date: '2026-03-18 04:24'
updated_date: '2026-03-18 04:34'
labels: []
dependencies: []
references:
  - apps/signal-horizon/ui/CODEX_MIGRATION_SPEC.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Continue the UI modernization by migrating the remaining high-impact pages from Phase 1 and establishing the pattern for Phase 2 (Fleet pages). This task focuses on operational depth and visual consistency across the core platform.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Replace all hardcoded colors, spacing, and typography in SensorDetailPage.tsx, ApiIntelligencePage.tsx, IntelPage.tsx, and HuntingPage.tsx.
- [ ] #2 Use Grid, Stack, Box, and Text primitives for all layout in these pages.
- [ ] #3 Ensure 100% theme-aware styling (dark mode support) using CSS variables.
- [ ] #4 TypeScript type-checking passes for the migrated pages.
<!-- AC:END -->
