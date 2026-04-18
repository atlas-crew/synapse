---
id: TASK-2
title: Migrate Beam Dashboard to @/ui Component Library (Phase 2)
status: Done
assignee: []
created_date: '2026-03-17 19:22'
updated_date: '2026-03-18 03:50'
labels: []
dependencies: []
references:
  - apps/signal-horizon/ui/src/pages/beam/BeamDashboardPage.tsx
  - apps/signal-horizon/ui/CODEX_MIGRATION_SPEC.md
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Bring the Beam Dashboard page and its sub-components into 100% compliance with the @/ui design system tokens and primitives, following the pattern established in Phase 1 (Fleet pages).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Replace all hardcoded colors, spacing, and typography in BeamDashboardPage.tsx.
- [ ] #2 Use Grid, Stack, Box, and Text primitives for all layout.
- [ ] #3 Ensure 100% theme-aware styling (dark mode support) using CSS variables.
- [ ] #4 TypeScript type-checking passes for the migrated page.
<!-- AC:END -->
