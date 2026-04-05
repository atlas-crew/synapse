---
id: TASK-26
title: Build Supply Chain Simulator UI page
status: Done
assignee: []
created_date: '2026-04-05 07:23'
updated_date: '2026-04-05 12:41'
labels:
  - apparatus
  - supply-chain
  - simulator
  - ui
  - visualization
milestone: m-5
dependencies:
  - TASK-25
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create a dedicated supply chain simulation page in the Horizon dashboard. This is a unique differentiator — no other WAF dashboard has it.

**Dependency Graph Visualization:**
- Interactive graph showing package dependency tree (use Cytoscape.js — already in the project)
- Compromised nodes highlighted in red
- Blast radius visualization showing which packages are affected by a compromised dependency

**Simulation Controls:**
- Start/stop simulation
- Select which dependency to "compromise"
- Configure payload type (data exfiltration, backdoor, cryptominer)

**Event Timeline:**
- Real-time log of simulation events (injection detected, payload executed, DLP triggered, etc.)
- Integration with the threat dashboard — simulation events should appear as signals

**Debrief Panel:**
- Summary of what was detected vs what slipped through
- DLP effectiveness score
- Recommendations for supply chain hardening

Demo mode: Synthetic dependency graph with 20-30 packages, pre-computed simulation showing a compromised package propagating through the tree.

Add to Threat Intelligence nav section as "Supply Chain".
<!-- SECTION:DESCRIPTION:END -->
