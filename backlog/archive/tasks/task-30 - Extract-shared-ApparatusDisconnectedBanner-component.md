---
id: TASK-30
title: Extract shared ApparatusDisconnectedBanner component
status: To Do
assignee: []
created_date: '2026-04-05 17:34'
labels:
  - cleanup
  - DRY
  - ui
dependencies: []
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
7 Apparatus pages render a similar disconnection warning banner (orange border, AlertTriangle icon, "Apparatus is not connected" text). Extract into a shared `ui/src/components/feedback/ApparatusDisconnectedBanner.tsx` accepting an optional `message` prop. Each page then renders `<ApparatusDisconnectedBanner show={!isConnected} />`.
<!-- SECTION:DESCRIPTION:END -->
