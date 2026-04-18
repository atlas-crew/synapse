---
id: TASK-75.4
title: Design read-only Active Defense overview + Apparatus deep-link scheme
status: To Do
assignee: []
created_date: '2026-04-17 03:41'
labels:
  - architecture
  - horizon-ui
  - design
  - federation
milestone: m-7
dependencies:
  - TASK-75.1
parent_task_id: TASK-75
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Design the Horizon-side replacement for the four Active Defense write-side pages: a read-only overview that shows summary cards (drill status, autopilot activity, scenario runs, red-team findings) and deep-links into the Apparatus dashboard for management.

Deliverables:
- Wireframe or Figma-equivalent for the Active Defense overview, consistent with the Synapse brand rollout.
- URL scheme for deep-linking into Apparatus (e.g., `${APPARATUS_UI_URL}/drills/:id`) — document env var convention.
- Auth handoff approach: shared OIDC session vs. short-lived handoff token vs. rely on browser SSO. Choose one, document trade-offs.
- Contract for what Horizon reads from Apparatus (which endpoints, polling vs SSE) for the summary cards.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Wireframe or design artifact committed under docs/development/plans/ or linked from it
- [ ] #2 Deep-link URL scheme documented including how the Apparatus base URL is configured per environment
- [ ] #3 Auth handoff decision documented with rejected alternatives
- [ ] #4 Read API contract listed (endpoints, expected shapes, refresh cadence)
<!-- AC:END -->
