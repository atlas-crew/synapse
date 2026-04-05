---
id: TASK-16
title: Build Breach Drills UI page in Horizon dashboard
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-05 06:38'
labels:
  - apparatus
  - ui
  - drills
milestone: m-2
dependencies:
  - TASK-15
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create a new "Breach Drills" page in the Horizon dashboard under Threat Intelligence or as a top-level nav item. The page should have:

**Drill Library view:**
- List available drills with name, description, difficulty badge (junior/senior/principal), tags
- "Launch" button per drill (disabled if Apparatus is disconnected)

**Active Drill view** (when a drill is running):
- Real-time timeline showing events as they stream in via WebSocket
- Live snapshot metrics (CPU%, error rate, blocked SQLi ratio, etc.)
- "Mark Detected" button for the SOC operator to signal threat detection
- "Cancel" button for abort
- Elapsed time counter

**Debrief view** (after drill completes):
- Final score breakdown (total, TTD, TTM, TTR, penalties, bonuses)
- Full timeline with event types color-coded (system/metric/hint/user_action/status_change)
- Win/fail status with failure reason if applicable

Use the existing `@/ui` component library (DataTable, MetricCard, StatusBadge, etc.).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Drill library loads and displays available drills
- [ ] #2 Launching a drill transitions to the active drill view
- [ ] #3 Timeline updates in real-time via WebSocket
- [ ] #4 Mark Detected button sends detection signal and updates TTD
- [ ] #5 Debrief view shows score breakdown after drill ends
<!-- AC:END -->
