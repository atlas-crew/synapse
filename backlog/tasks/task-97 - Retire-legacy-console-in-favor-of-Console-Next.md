---
id: TASK-97
title: Retire legacy /console in favor of Console-Next
status: To Do
assignee: []
created_date: '2026-04-19 23:15'
labels:
  - console-next
  - retirement
  - legacy
dependencies: []
references:
  - apps/synapse-pingora/src/admin_server.rs
  - apps/synapse-pingora/assets/admin_console.html
  - apps/synapse-console-ui/src/App.tsx
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parent task tracking the retirement of the legacy embedded admin console at `/console` (served from `apps/synapse-pingora/assets/admin_console.html`, handler at `apps/synapse-pingora/src/admin_server.rs:2118-2144`, route at `admin_server.rs:1889`).

The retire gate is **feature parity**, not time. Before the deletion PR (TASK-97.4) can land, Console-Next must cover everything the operator currently uses legacy for — as scoped by the user, that is:

1. **Full configuration surface coverage** — every field of `ConfigFile` editable through Console-Next. Tracked under TASK-96 and its subtasks (TASK-96.1 through TASK-96.6). Not a subtask of TASK-97, but a gate on it.
2. **Horizon + Apparatus integrations UI** — TASK-97.1. Reads/writes the integrations config (`horizon_hub_url`, `tunnel_url`, `apparatus_url`) that the legacy console currently exposes.
3. **Config export / import** — TASK-97.2. Download the current `GET /config` body; upload → preview → `POST /config` with `If-Match` and warnings.
4. **WAF stats + system monitoring** — TASK-97.3. Expand the Overview tab to consume `/waf/stats`, `/_sensor/metrics`, `/stats` so the SPA is a credible replacement for the legacy monitoring panels.

**Explicitly out of scope:** a Console-Next log viewer. The user confirmed they may not keep a log viewer at all, so the `tracing_subscriber::Layer` bridge idea is shelved.

After 97.1-97.3 land and TASK-96 is fully closed, TASK-97.4 does the actual deletion PR: remove the route, handler, embedded HTML, `ADMIN_CONSOLE_CSP` (which is looser than `ADMIN_CONSOLE_NEXT_CSP` and its removal tightens the attack surface), the "Open legacy console" bridge link in `apps/synapse-console-ui/src/App.tsx`, and the `/console` entry in the endpoint listing returned by the root `/` admin handler.

**Context:** this is the same retirement pattern the Signal Horizon → Synapse Fleet rename used (ADR-0003 / TASK-87 / TASK-89). Keep the legacy surface alive through parity + bridge link, then one-commit cutover.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TASK-96 (configuration surface coverage) reports all subtasks Done before this parent can close
- [ ] #2 TASK-97.1 (integrations tab), TASK-97.2 (export/import), TASK-97.3 (WAF + system monitoring) all Done
- [ ] #3 TASK-97.4 (the deletion PR) removes `/console` route, `admin_console_handler`, `ADMIN_CONSOLE_TEMPLATE`, `ADMIN_CONSOLE_CSP`, legacy bridge link in SPA header, and `/console` from the root endpoint listing
- [ ] #4 A post-deletion smoke test on a fresh build confirms `GET /console` returns 404 and the Console-Next SPA is the only operator UI surface served by the admin port
- [ ] #5 No references to legacy `/console` remain in `apps/synapse-pingora/`, `apps/synapse-console-ui/`, or docs (grep-clean)
<!-- AC:END -->
