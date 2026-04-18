---
id: DRAFT-2
title: >-
  Internal code symbol rename: HorizonClient / horizonStore /
  SignalHorizonPageWrapper → Fleet*
status: Draft
assignee: []
created_date: '2026-04-18 11:08'
updated_date: '2026-04-18 11:30'
labels:
  - rename
  - brand-consolidation
  - refactor
milestone: m-9
dependencies:
  - TASK-87
  - TASK-88
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Rename non-user-visible code symbols and filenames per ADR-0003 decision D. No compat window needed — these aren't API contracts, they're internal identifiers.

**In scope** (confirmed via grep):
- `apps/synapse-fleet/ui/src/stores/horizonStore.ts` → `fleetStore.ts`
- `apps/synapse-fleet/ui/src/components/signal/SignalHorizonPageWrapper.tsx` → `SynapseFleetPageWrapper.tsx` (or just `PageWrapper.tsx`)
- `apps/synapse-fleet/ui/src/lib/demoData/generators/signalHorizon.ts` → `synapseFleet.ts`
- All callers of these symbols across the UI + API + shared packages

**Out of scope** (ADR-0003 decision E):
- `apps/synapse-pingora/src/horizon/*` module — deferred
- `config.horizon*.yaml` filenames — deferred
- `HorizonConfig` / `HorizonClient` types in pingora — deferred

**Also out of scope**:
- Historical references in `backlog/archive/`, `backlog/completed/`, shipped ADRs (0001, 0002) — ADR-0003 decision F preserves them.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Store files renamed with git mv; imports updated across the UI
- [ ] #2 Page-wrapper component renamed; all JSX call sites updated
- [ ] #3 Demo-data generator file renamed; generator registration updated
- [ ] #4 No reference to the renamed symbols remains in `apps/synapse-fleet/` (grep is clean except for the archived/completed backlog and shipped ADRs, which are explicitly preserved)
- [ ] #5 Typecheck and full test suite pass after the rename
- [ ] #6 Diff is pure rename — no behavioural changes, no API changes, no response-shape changes
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Deprioritized 2026-04-18 per user direction: internal code symbols stay as-is for now. Only user-facing surfaces (published packages + published docs) are being rebranded in this phase.
<!-- SECTION:NOTES:END -->
