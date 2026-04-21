---
id: TASK-96.3
title: 'Console-Next: per-site TLS + shadow-mirror controls'
status: To Do
assignee: []
created_date: '2026-04-19 03:16'
labels:
  - console-next
  - ui
  - operator
  - tls
dependencies:
  - TASK-96.1
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/admin_server.rs
  - apps/synapse-pingora/src/config.rs
parent_task_id: TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add editors for `SiteConfig.tls` and `SiteConfig.shadow_mirror` inside each site's detail view in the Console-Next SPA. These blocks are `unknown`-typed in the current TypeScript model (`apps/synapse-console-ui/src/App.tsx:92-93`) because the SPA hasn't needed to touch them yet — the implementing agent must first tighten those types against the actual backend schema.

Scope:
- Discover the authoritative TLS and shadow-mirror schemas from the Rust side (`apps/synapse-pingora/src/config.rs`, or whatever the per-site config struct is called) and replicate them as TypeScript interfaces in `App.tsx` (or a new `types.ts` next to it).
- TLS editor should cover the minimum operator-facing fields (typically cert path, key path, enabled/disabled, ALPN/min-version if present). Mirror whatever the Rust struct exposes — do not invent fields.
- Shadow-mirror editor should cover target upstream + sampling/ratio + enabled toggle, again pulled from the Rust struct.
- Unknown / not-yet-modeled fields inside these blocks must be preserved byte-identical on save (round-trip).

Both editors write through the existing `POST /config` + `If-Match` path (mirroring `saveServerConfig` at `App.tsx:507-622`) and surface `warnings[]` + `rebuild_required` via the existing `Alert` pattern.

Depends on TASK-96.1 for the per-site edit host UI.

Security note: TLS key material paths may leak sensitive context if pulled into the UI and logged — do not render the key content itself, only the filesystem path string that the backend already exposes via `GET /config`.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TypeScript interfaces for `SiteConfig.tls` and `SiteConfig.shadow_mirror` match the Rust structs verified by grepping `apps/synapse-pingora/src/` (cite the Rust file + struct in the PR description)
- [ ] #2 TLS editor covers the minimum fields the Rust struct exposes; TLS key *content* is never rendered, only paths
- [ ] #3 Shadow-mirror editor covers target + sampling + enabled toggle (or whatever the struct actually exposes)
- [ ] #4 Unknown / unmodeled fields inside `tls` and `shadow_mirror` are preserved byte-identical across a save (round-trip unit test required)
- [ ] #5 Save path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` via the existing Alert pattern
- [ ] #6 Vitest coverage in `App.test.tsx` covers: TLS enable/disable, shadow-mirror enable/disable, a preserve-unknown-fields round-trip, and an etag-mismatch error
- [ ] #7 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #8 Roadmap copy in `App.tsx:1038-1064` is updated to reflect shipped state
<!-- AC:END -->
