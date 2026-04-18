---
id: TASK-12
title: Connect Apparatus SSE stream to Horizon WebSocket pipeline
status: Done
assignee: []
created_date: '2026-04-03 18:29'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - streaming
  - websocket
milestone: m-1
dependencies:
  - TASK-9
  - TASK-11
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Use `ApparatusService.realtime` to subscribe to the Apparatus SSE event stream and bridge events into Horizon's existing WebSocket broadcast system.

When ApparatusService connects:
1. Call `client.realtime.connect()`
2. Subscribe to all event types: `onDeception`, `onTarpit`, `onThreatIntel`, `onRequest`
3. Run each event through the signal adapter (TASK-11) to map to internal types
4. Dispatch mapped signals into the existing SignalManager / WebSocket broadcast

When Apparatus disconnects, log and continue — Horizon should degrade gracefully.

This replaces the current model where Apparatus must POST to `/_sensor/report`. With SSE, Horizon pulls events in real-time instead of waiting for pushes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Apparatus deception events appear on the Horizon dashboard in real-time
- [ ] #2 Tarpit events are visible in the fleet/defense views
- [ ] #3 SSE reconnection happens automatically on disconnect
- [ ] #4 No data loss during brief Apparatus restarts
<!-- AC:END -->
