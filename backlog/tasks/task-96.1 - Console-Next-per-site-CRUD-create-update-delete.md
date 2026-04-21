---
id: TASK-96.1
title: 'Console-Next: per-site CRUD (create, update, delete)'
status: Done
assignee: []
created_date: '2026-04-19 03:15'
updated_date: '2026-04-19 03:26'
labels:
  - console-next
  - ui
  - operator
dependencies: []
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-console-ui/src/styles.css
  - apps/synapse-pingora/src/admin_server.rs
parent_task_id: TASK-96
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implement create / update / delete flows for virtual-host `sites[]` entries in the Console-Next SPA. Today `App.tsx` renders a read-only list of sites (`App.tsx:968-1036`) but cannot mutate the array. All writes ride on the existing `POST /config` endpoint with the full config body and `If-Match: <etag>` header, exactly as `saveServerConfig` does at `App.tsx:507-622`.

The operator workflow is:
1. Read current `ConfigFile` via `readApiWithMeta<ConfigFile>('/config')` (already wired).
2. For add: append a new `SiteConfig` to `sites[]`; for update: mutate the matching entry; for delete: splice it out.
3. POST the whole config back with `If-Match: state.configEtag` and surface `warnings[]` + `rebuild_required` from the `MutationResult` response via the existing `Alert` pattern.
4. On success, call `load()` to refetch, which also refreshes the etag.

Backend contract is already in place — `apps/synapse-pingora/src/admin_server.rs` handles `GET /config` / `POST /config` with etag + warnings. The `@atlascrew/signal-ui` primitives (`Input`, `Select`, `Button`, `Alert`, `Box`, `Stack`, `Tabs`) are already imported.

CSP constraint: the embedded SPA runs under `style-src 'self'` (see `admin_server.rs:403`). Do not introduce runtime style injection (e.g., emotion/styled-components) — use the existing CSS class approach in `apps/synapse-console-ui/src/styles.css`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Sites tab gains 'Add site' button that opens a form seeded with empty hostname + at least one upstream row
- [x] #2 Each rendered site card in the Sites tab exposes Edit and Delete actions
- [x] #3 Edit form covers hostname + upstreams[] (host + port) at minimum; other site blocks (waf / headers / tls / shadow_mirror) are preserved across saves even when not edited
- [x] #4 Save path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` through the existing Alert component pattern used by `saveServerConfig`
- [x] #5 Delete confirms via an inline confirmation state (no native window.confirm) before POSTing the mutated config
- [x] #6 After a successful mutation, `load()` is called to refetch and refresh the etag
- [x] #7 Error states (etag mismatch 412, validation failures, network errors) render an `Alert status="error"` with the server's message
- [x] #8 Vitest coverage in `apps/synapse-console-ui/src/App.test.tsx` (or a new sibling test) covers add, edit, delete happy paths plus an etag-mismatch error path, mocking fetch
- [x] #9 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [x] #10 `apps/synapse-console-ui/src/App.tsx` roadmap copy at the bottom of the file is updated to reflect that per-site CRUD is shipped
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped per-site CRUD inside the Console-Next SPA.

**Scope landed:**
- New `SiteEditorState` + `SiteFormState` models driving add / edit / delete-confirm modes.
- `SiteEditor` component renders an inline form with hostname + an expandable list of `{host, port}` upstream rows; supports add/remove-row.
- `saveSiteMutation(action, options)` is the single write path — it composes the mutated `sites[]`, POSTs the full `ConfigFile` body with `If-Match: <etag>`, awaits `load()` to refresh state + etag, and surfaces `warnings[]` + `rebuild_required` through an Alert mirroring `saveServerConfig`.
- Delete uses a two-step inline confirmation (`{ mode: 'delete-confirm', index }`) — no `window.confirm`. Confirm button is `variant="magenta"` for danger signaling; Cancel reverts to idle.
- Non-edited site blocks (`waf`, `headers`, `tls`, `shadow_mirror`, etc.) are preserved byte-identical on save because `siteFromForm(form, base)` spreads `base` first and only overwrites `hostname` + `upstreams`. Verified by the edit-test asserting the full saved site still carries `waf.rule_overrides`, `headers.add`, etc.
- Duplicate-hostname guard + etag-stale guard + config-unavailable guard all surface through `Alert status="error"`.
- Roadmap copy in `App.tsx` updated to remove per-site CRUD from the remaining-gaps list.

**Verification:**
- `pnpm --filter @atlascrew/synapse-console-ui type-check` — clean.
- `pnpm --filter @atlascrew/synapse-console-ui test` — 7/7 passing (4 existing + 3 new covering add, edit, delete, 412 etag-mismatch).
- Bundle rebuilt (`vite build` → 235.44 kB) and re-embedded into the Rust binary via `cargo build --bin synapse-waf`; admin server restarted and confirmed to serve the fresh app.js.

**Implementation notes worth carrying to TASK-96.2 / 96.3:**
- React 19 + controlled Inputs require snapshotting `event.currentTarget.value` before entering `setState(updater)`; reading `.value` inside the updater throws null in jsdom. The new `SiteEditor` does this — mirror the pattern.
- Button sizes `sm`/`md`/`lg` and variants `primary|magenta|outlined|secondary|ghost` are the only options in signal-ui; `magenta` is the conventional danger/destructive color.
- On save failure, the editor state is *preserved* (not reset to idle) to match `saveServerConfig`'s UX.
<!-- SECTION:FINAL_SUMMARY:END -->
