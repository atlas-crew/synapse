---
id: TASK-25
title: Add Apparatus supply chain simulator API routes
status: Done
assignee: []
created_date: '2026-04-05 07:22'
updated_date: '2026-04-05 07:24'
labels:
  - apparatus
  - supply-chain
  - simulator
  - api
milestone: m-5
dependencies:
  - TASK-9
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus SimulatorApi through the Horizon API. The supply chain simulator models dependency graphs and simulates compromised packages injecting malicious payloads.

API routes:
- `GET /api/v1/apparatus/simulator/status` → current simulation state
- `POST /api/v1/apparatus/simulator/start` → start a supply chain simulation
- `POST /api/v1/apparatus/simulator/stop` → stop active simulation
- `GET /api/v1/apparatus/simulator/graph` → dependency graph data
- `GET /api/v1/apparatus/simulator/events` → simulation event log

Check the SimulatorApi in apparatus-lib for the exact method signatures and add corresponding routes to the existing apparatus.ts route file.
<!-- SECTION:DESCRIPTION:END -->
