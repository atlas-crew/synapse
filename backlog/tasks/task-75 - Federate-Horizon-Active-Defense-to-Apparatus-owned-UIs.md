---
id: TASK-75
title: Federate Horizon Active Defense to Apparatus-owned UIs
status: To Do
assignee: []
created_date: '2026-04-17 03:39'
updated_date: '2026-04-17 03:59'
labels:
  - architecture
  - horizon-ui
  - apparatus
  - federation
milestone: m-7
dependencies: []
references:
  - apps/signal-horizon/ui/src/App.tsx
  - /Users/nick/Developer/Apparatus/apps/apparatus/src/dashboard
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Apparatus is a standalone, independently deployable product that ships its own dashboard at `/Users/nick/Developer/Apparatus/apps/apparatus/src/dashboard/`. Signal Horizon's "Active Defense" navigation section currently duplicates Apparatus's write-side management UI — `BreachDrillsPage`, `AutopilotPage`, `ScenariosPage`, `RedTeamScannerPage`, labeled "Apparatus-backed views" in `apps/signal-horizon/ui/src/App.tsx:97`. Every Apparatus release risks drift between the two UIs.

This initiative repositions Horizon/Synapse as a federated read-side aggregator: it surfaces summaries and deep-links into the specialist sub-product UI (Apparatus) rather than re-implementing write-side management. Establishes the pattern for Crucible and future sub-products.

Context:
- Standalone deployment confirmed: Apparatus and Crucible can be installed without Horizon.
- Synapse brand consolidation (Signal Horizon → Synapse) is already in phased rollout.
- Completed groundwork: TASK-8/9/12/15/19/20/21/25/27 established Horizon-Apparatus integration; this work demotes the UI duplication that integration produced.

Out of scope:
- Crucible implementation (#11 defines the boundary, not the build).
- SOC-only narratives that don't touch Apparatus (Campaigns, War Room, Hunting stay as-is).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All four Active Defense pages demoted to read-only summaries or removed
- [ ] #2 Horizon API no longer exposes write-side routes that duplicate Apparatus management operations
- [ ] #3 Horizon↔Apparatus API contract uses versioned ranges and degrades gracefully on mismatch
- [ ] #4 ADR published documenting the federation pattern, linked from docs/NAVIGATOR.md
- [ ] #5 Crucible federation boundary documented before any Crucible UI surface merges into Horizon
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Apparatus dashboard already implements all four write-side surfaces (`DrillConsole.tsx`, `AutopilotConsole.tsx`, `ScenarioConsole.tsx` + `components/scenarios/*`, `RedTeamValidator.tsx`). No parity-closure work needed in the Apparatus repo — the original TASK-75.3 was archived. Demotions (TASK-75.6–75.9) depend only on the design task (TASK-75.4), not on parity.
<!-- SECTION:NOTES:END -->
