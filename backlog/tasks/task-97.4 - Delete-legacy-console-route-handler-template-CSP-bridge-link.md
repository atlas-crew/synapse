---
id: TASK-97.4
title: 'Delete legacy /console route, handler, template, CSP, bridge link'
status: To Do
assignee: []
created_date: '2026-04-19 23:17'
labels:
  - console-next
  - retirement
  - legacy
  - cleanup
dependencies:
  - TASK-96
  - TASK-97.1
  - TASK-97.2
  - TASK-97.3
references:
  - apps/synapse-pingora/src/admin_server.rs
  - apps/synapse-pingora/assets/admin_console.html
  - apps/synapse-console-ui/src/App.tsx
parent_task_id: TASK-97
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The actual deletion PR for legacy `/console`. This is the last subtask of TASK-97 and should not be worked on until TASK-96 (all configuration-surface subtasks), TASK-97.1 (integrations tab), TASK-97.2 (export/import), and TASK-97.3 (WAF + system monitoring) are all Done. Starting earlier risks shipping a sensor that regresses operator workflows currently served by the legacy UI.

**Files / symbols to remove in `apps/synapse-pingora/src/admin_server.rs`:**
- Route registration: `.route("/console", get(admin_console_handler))` at line ~1889, plus `"/console/assets/sidebar-lockup.svg"` at line ~1900.
- Handler function: `admin_console_handler` at ~line 2118-2144.
- Static asset: `ADMIN_CONSOLE_TEMPLATE: &str = include_str!("../assets/admin_console.html")` at ~line 397.
- CSP constant: `ADMIN_CONSOLE_CSP` at ~line 402 — note this CSP allows `'unsafe-inline'` for scripts **and** styles; its removal tightens the admin-port attack surface, so this is a security improvement not just a cleanup.
- `/console` entry in the root `/` endpoint listing handler (search for `"/console"` literal in the JSON response near the routes discovery; also remove the stale "WAF engine initialized with 237 detection rules" startup log at ~line 1688 while in that area — the current rule count is 248 per project memory).
- All test fixtures that reference `admin_console_handler` or `/console` (the `create_test_app_with_console` helper at ~line 9324 and its call sites).

**Files to remove outside `admin_server.rs`:**
- `apps/synapse-pingora/assets/admin_console.html` — the embedded legacy console HTML.
- `apps/synapse-pingora/assets/` — any legacy-only CSS / JS / images referenced by `admin_console.html` and not shared with Console-Next. Grep before deleting.

**Files to edit:**
- `apps/synapse-console-ui/src/App.tsx` at lines ~642-655 — delete the "Open legacy console" anchor (`<a href="/console">Open legacy console</a>`) from the SPA header.
- Docs under `apps/synapse-pingora/docs/` and `docs/` — grep for `/console` references (excluding `/console-next`) and either remove or update to point at `/console-next`.

**Post-deletion verification:**
- Fresh `cargo build --bin synapse-waf` + restart → `curl http://localhost:6191/console` returns 404, `/console-next` returns 200.
- `curl http://localhost:6191/` (endpoint listing) does not contain `/console` in its routes array.
- `rg '/console(?!-next)' apps/ docs/` returns no hits (use negative lookahead or post-filter `/console-next`).
- All Rust unit tests + `pnpm --filter @atlascrew/synapse-console-ui test` pass.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every file / symbol listed in the description is removed or updated; no compile errors; no test references to removed symbols remain
- [ ] #2 `GET /console` on a fresh build returns 404; `GET /console-next` still returns 200 (verify manually + via a new Rust unit test)
- [ ] #3 Root `/` endpoint listing no longer contains `/console` in its routes array (verify via a unit test that deserializes the response and asserts the path is absent)
- [ ] #4 SPA header no longer renders the 'Open legacy console' anchor; existing TASK-96 tests still pass
- [ ] #5 `rg '/console(?!-next)' apps/ docs/` returns no hits (excluding intentional historical mentions in changelog entries)
- [ ] #6 The `ADMIN_CONSOLE_CSP` constant is deleted; `ADMIN_CONSOLE_NEXT_CSP` is the only console CSP remaining (security improvement)
- [ ] #7 Stale 'WAF engine initialized with 237 detection rules' startup log is updated to 248 or sourced dynamically from the rules catalog while in the area
- [ ] #8 Full `cargo test --lib` passes; `pnpm --filter @atlascrew/synapse-console-ui test` and `type-check` pass
- [ ] #9 PR description cites TASK-96, TASK-97.1, TASK-97.2, TASK-97.3 as parity prerequisites and confirms each was completed before this one started
<!-- AC:END -->
