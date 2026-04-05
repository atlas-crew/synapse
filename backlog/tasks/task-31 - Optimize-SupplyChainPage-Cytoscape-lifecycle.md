---
id: TASK-31
title: Optimize SupplyChainPage Cytoscape lifecycle
status: To Do
assignee: []
created_date: '2026-04-05 17:34'
labels:
  - performance
  - ui
  - apparatus
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SupplyChainPage.tsx destroys and recreates the Cytoscape instance on every `[graph]` dependency change. This causes a visible repaint stall and runs the full layout algorithm each time. Instead, initialize Cytoscape once (store in useRef), and on subsequent graph changes use `cy.json({ elements })` or batch updates (`startBatch/endBatch`) to mutate the graph in place. Only re-run the layout when the element set actually changes (not on infection status updates).
<!-- SECTION:DESCRIPTION:END -->
