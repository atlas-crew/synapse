---
id: TASK-96
title: 'Console-Next operator surface: continue site + profiler editors'
status: To Do
assignee: []
created_date: '2026-04-19 03:15'
labels:
  - console-next
  - ui
  - operator
dependencies: []
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/main.tsx
  - apps/synapse-pingora/src/admin_server.rs
  - apps/synapse-pingora/assets/console-next/index.html
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parent task for extending the Console-Next SPA (`apps/synapse-console-ui`) past the current Overview + Server-config slice. The server tab already reads from `GET /config` and writes via `POST /config` with `If-Match` etag + warnings handling (see `apps/synapse-console-ui/src/App.tsx:507` `saveServerConfig`). This task tracks closing the remaining roadmap items surfaced in the SPA itself at `App.tsx:1038-1064`: site CRUD, per-site headers + WAF overrides, per-site TLS + shadow mirror, and profiler/module editors.

Work ships as subtasks so each lands as its own reviewable PR. All subtasks share:
- The existing `GET /config` + `POST /config` contract with etag / `If-Match` / warnings
- The `@atlascrew/signal-ui` component set already in use in `App.tsx`
- CSP `style-src 'self'` (no `'unsafe-inline'`) — any new UI must avoid runtime inline style injection
- Console routes live behind `admin:read` scope in `apps/synapse-pingora/src/admin_server.rs:1888-1914`; config writes require `config:write` + `admin:write`

Out of scope here: SOC dashboard surfaces (tracked separately under TASK-78 / TASK-79 / TASK-80) and fleet aggregation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 All four child subtasks are created and reported back
- [ ] #2 Child subtasks reference the same shared context: `apps/synapse-console-ui/src/App.tsx`, `apps/synapse-pingora/src/admin_server.rs`, and the `GET/POST /config` contract with etag semantics
- [ ] #3 Parent remains open until every subtask reaches Done
<!-- AC:END -->
