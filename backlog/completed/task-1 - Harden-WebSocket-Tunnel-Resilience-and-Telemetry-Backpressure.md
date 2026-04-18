---
id: TASK-1
title: Harden WebSocket Tunnel Resilience and Telemetry Backpressure
status: Done
assignee: []
created_date: '2026-03-17 19:22'
updated_date: '2026-03-17 23:25'
labels: []
dependencies: []
references:
  - apps/synapse-pingora/src/horizon/client.rs
  - apps/signal-horizon/BUG_HUNTING.md
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Ensure sensors can handle network failures, Signal Horizon restarts, and high-volume telemetry without data loss or memory leaks. The current implementation is flagged as "fragile" in BUG_HUNTING.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Implement exponential backoff with jitter for reconnections in HorizonClient.
- [ ] #2 Implement a bounded memory buffer for telemetry during disconnection.
- [ ] #3 Implement telemetry dropping with "dropped count" reporting when buffer is full.
- [ ] #4 Integration tests simulating Signal Horizon restarts mid-batch pass.
- [ ] #5 No memory growth during extended disconnection under high telemetry load.
<!-- AC:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
UI migration Phase 1 completed and verified. Backlogged final P2 findings from review 153137.md. Starting TASK-1 implementation loop.
<!-- SECTION:NOTES:END -->
