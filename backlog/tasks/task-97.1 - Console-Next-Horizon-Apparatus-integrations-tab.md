---
id: TASK-97.1
title: 'Console-Next: Horizon + Apparatus integrations tab'
status: To Do
assignee: []
created_date: '2026-04-19 23:16'
labels:
  - console-next
  - ui
  - operator
  - integrations
  - horizon
  - apparatus
dependencies: []
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/admin_server.rs
parent_task_id: TASK-97
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add an Integrations tab to the Console-Next SPA that lets operators view and update the external integrations configuration — Horizon hub URL, Tunnel URL, and Apparatus URL. This is a retirement gate for legacy `/console` (see TASK-97).

**Backend contract (already exists):**
- `GET /_sensor/config/integrations` — returns current integrations config (handler at `apps/synapse-pingora/src/admin_server.rs:6777`).
- `PUT /_sensor/config/integrations` — accepts an update body; handler at `admin_server.rs:6806`. The handler returns `400` on validation failure (see `integrations_error_response` at `admin_server.rs:211-228`) and `503` when the sensor instance doesn't support configuration updates (see `admin_server.rs:7082-7094`). Writes log the outcome via `record_log_with_source` — `integrations_update_applied` on success, `integrations_update_failed` on rejection.

**Fields to expose:** at minimum `horizon_hub_url`, `tunnel_url`, `apparatus_url` (inferred from the log message at `admin_server.rs:7067-7072`). The implementing agent should **grep the handler / request struct definition around admin_server.rs:6806** to enumerate every field before committing, and render each one as an Input with clear helper text describing what system it connects to.

**UX requirements:**
- Show the current config on load. On save, surface the handler's `message` field (success message from the 200 response, error from 400/503) through the existing Alert pattern used by `saveServerConfig`.
- Respect the handler's sticky note: "Restart synapse-waf to apply live Horizon and Tunnel connections" — surface this warning alongside success.
- Any URL field must pass a minimal format check client-side (non-empty, parseable as URL) before PUT.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 New `integrations` tab added to the `tabs` array in `apps/synapse-console-ui/src/App.tsx` with consistent tab/panel id pairing
- [ ] #2 Tab loads via `GET /_sensor/config/integrations` and renders every field the backend returns (enumerate exhaustively from the Rust request struct near `admin_server.rs:6806`, not the inferred three)
- [ ] #3 Save path uses `PUT /_sensor/config/integrations` with `Content-Type: application/json` and surfaces the handler's `message` string through the existing Alert pattern (success shows the restart warning; 400/503 show the error)
- [ ] #4 Client-side URL format validation blocks save when any URL field is empty or not a parseable URL; inline error shown
- [ ] #5 Vitest coverage covers: successful load, successful save, 400 validation error, 503 unsupported-instance error, and client-side URL validation block
- [ ] #6 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #7 Roadmap copy in `App.tsx` updated to reflect shipped state
<!-- AC:END -->
