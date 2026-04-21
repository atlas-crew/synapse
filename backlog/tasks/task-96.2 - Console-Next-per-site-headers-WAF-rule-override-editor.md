---
id: TASK-96.2
title: 'Console-Next: per-site headers + WAF rule override editor'
status: To Do
assignee: []
created_date: '2026-04-19 03:16'
updated_date: '2026-04-19 23:14'
labels:
  - console-next
  - ui
  - operator
  - waf
dependencies:
  - TASK-96.1
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/admin_server.rs
parent_task_id: TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add editors for `SiteConfig.waf` and `SiteConfig.headers` inside each site's detail view in the Console-Next SPA. Today these blocks are counted in the read-only summary (see `apps/synapse-console-ui/src/App.tsx` Sites tab) but cannot be edited.

**Shape (authoritative Rust source, `apps/synapse-pingora/src/config.rs`):**
- `SiteWafConfig` (`config.rs:237-246`): `enabled: bool` (default true), `threshold: Option<u8>` (0-100 per-site risk override), `rule_overrides: HashMap<String, String>` (rule_id → action string).
- `HeaderConfig` (`config.rs:211-219`) is **nested**, not flat: `request: HeaderOps`, `response: HeaderOps`.
- `HeaderOps` (`config.rs:222-233`) has three sub-maps: `add: HashMap<String, String>` (append semantics), `set: HashMap<String, String>` (replace semantics), `remove: Vec<String>`.

So the UI needs six distinct sub-editors for headers (request.add/set/remove + response.add/set/remove), rendered under a single "Headers" heading. The WAF editor covers `enabled` + `threshold` + `rule_overrides`.

All writes ride on the shared `POST /config` + `If-Match` path (same as `saveServerConfig`). Unknown / unmodeled fields inside `waf` and `headers` / `headers.*` / `headers.*.*` must be preserved byte-identical on save (round-trip unit test required).

Depends on TASK-96.1 landing first so the per-site edit UI exists to host these editors.

CSP constraint: the embedded SPA runs under `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). Do not introduce runtime style injection.

Layout guidance: follow the same three-subsection-card pattern TASK-96.4 used on the Profiler tab — one Box per sub-editor (WAF, Headers→request, Headers→response) so the Sites edit view structurally matches the rest of the Console-Next.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 WAF editor supports toggling `enabled`, setting/clearing `threshold` (0-100 integer with validation), and add/edit/remove on `rule_overrides` entries (rule_id + override action)
- [ ] #2 Headers editor exposes six distinct sub-sections — request.add / request.set / request.remove / response.add / response.set / response.remove — mirroring the authoritative `HeaderConfig` → `HeaderOps` shape in `apps/synapse-pingora/src/config.rs:211-233`
- [ ] #3 Both editors save via `POST /config` with `If-Match: <etag>` and surface `warnings[]` + `rebuild_required` through the existing Alert pattern
- [ ] #4 All non-edited `SiteConfig` blocks (`upstreams`, `tls`, `shadow_mirror`, `access_control`, `rate_limit`) are preserved byte-identical across a save (round-trip unit test)
- [ ] #5 Unknown / unmodeled fields inside `waf`, `headers`, or either `HeaderOps` are preserved byte-identical (round-trip unit test)
- [ ] #6 Threshold input accepts empty string to clear (Option<u8>::None) and rejects values outside 0-100 with inline error
- [ ] #7 Vitest coverage in `apps/synapse-console-ui/src/App.test.tsx` (or sibling) exercises: WAF enabled toggle, WAF threshold set + clear, rule_overrides add/edit/remove, each of the six header sub-operations, and a preserve-unknown-fields round-trip
- [ ] #8 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #9 Roadmap copy in `App.tsx` is updated to reflect shipped state
<!-- AC:END -->
