---
id: TASK-97.2
title: 'Console-Next: config export + import'
status: To Do
assignee: []
created_date: '2026-04-19 23:16'
labels:
  - console-next
  - ui
  - operator
  - export-import
dependencies: []
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/admin_server.rs
parent_task_id: TASK-97
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add config export and import flows to the Console-Next SPA. This is a retirement gate for legacy `/console` (see TASK-97).

**Export (easy):** operator clicks "Export config" in the SPA header (next to the existing "Refresh" / "Open legacy console" actions at `apps/synapse-console-ui/src/App.tsx:642-655`). The SPA fetches `GET /config` (already wired via `readApiWithMeta<ConfigFile>`), serializes the body to pretty-printed JSON, and triggers a browser download (`application/json`, filename like `synapse-config-<hostname>-<ISO-timestamp>.json`).

**Import (risky):** operator clicks "Import config", picks a JSON file. The SPA:
1. Parses the file client-side. Shows a parse error inline if invalid JSON.
2. Renders a **preview diff** between current `state.fullConfig` and the uploaded body — at minimum a field-by-field changed-value list (even a simple "added / removed / changed" summary under each top-level block is fine).
3. Operator clicks "Apply import" to POST the full body with `If-Match: <etag>`. Backend returns the standard `MutationResult` with `warnings[]` and `rebuild_required`, which surface through the existing Alert pattern.
4. Import path must preserve unknown / unmodeled fields byte-identical — the operator is by definition submitting whatever shape the file has, not the SPA's model.

**Safety guardrails:**
- Reject imports whose top-level type isn't an object, or whose top-level is missing any of `server`, `sites`, `rate_limit`, `profiler` (soft warning, still allow with explicit confirmation).
- On etag mismatch (412), surface the error and prompt the operator to refresh before retry — do not auto-retry.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection. The download flow uses `Blob` + `URL.createObjectURL` which is allowed under `default-src 'self'` via `blob:` since the URL is same-origin.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Export button in the SPA header downloads a JSON file containing the full `GET /config` body, pretty-printed, filename format `synapse-config-<hostname>-<ISO-timestamp>.json`
- [ ] #2 Import button opens a file picker accepting `.json` and shows a parse error inline if the uploaded content is not valid JSON
- [ ] #3 After parse succeeds, a preview view renders the diff against current `state.fullConfig` — at minimum a list of added / removed / changed top-level keys, plus changed-value details for each top-level block
- [ ] #4 Apply-import path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` through the existing Alert pattern
- [ ] #5 Import preserves unknown / unmodeled fields byte-identical (round-trip unit test: export → modify unknown field → import → assert preserved)
- [ ] #6 Soft warning surfaced when the uploaded file is missing `server`, `sites`, `rate_limit`, or `profiler`, with explicit confirm-to-apply button; rejected entirely when not an object
- [ ] #7 Etag-mismatch (412) on apply shows error alert and prompts operator to refresh before retry — no auto-retry
- [ ] #8 Vitest coverage covers: export click, import with valid file, import with invalid JSON, import with missing top-level keys, 412 on apply, preserve-unknown-fields round-trip
- [ ] #9 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #10 Roadmap copy in `App.tsx` updated to reflect shipped state
<!-- AC:END -->
