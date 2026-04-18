---
id: TASK-13
title: Add Apparatus event feed to Horizon UI
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - ui
  - dashboard
milestone: m-1
dependencies:
  - TASK-10
  - TASK-12
references:
  - apps/signal-horizon/ui/src/pages/AdminSettingsPage.tsx
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Create a dedicated Apparatus events panel in the UI that shows the live feed of Apparatus events. Could be:

- A new tab on the Threat Overview page showing Apparatus-sourced signals
- A badge/indicator in the header showing Apparatus connection state
- Filter controls on existing signal views to show/hide Apparatus events

The events already flow through the WebSocket pipeline (TASK-12), so this is purely UI work — render the events that have an Apparatus source tag.

Also wire up the existing Admin Settings "Apparatus" tab (currently a stub at `AdminSettingsPage.tsx:152`) to show connection status from the integrations API (TASK-10).
<!-- SECTION:DESCRIPTION:END -->
