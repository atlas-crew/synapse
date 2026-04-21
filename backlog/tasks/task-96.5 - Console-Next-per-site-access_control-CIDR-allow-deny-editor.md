---
id: TASK-96.5
title: 'Console-Next: per-site access_control (CIDR allow/deny) editor'
status: To Do
assignee: []
created_date: '2026-04-19 23:14'
labels:
  - console-next
  - ui
  - operator
  - access-control
dependencies:
  - TASK-96.1
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/config.rs
  - apps/synapse-pingora/src/validation.rs
parent_task_id: TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add an editor for `SiteConfig.access_control` inside each site's detail view in the Console-Next SPA. Shipping this closes part of the "fully cover the configuration surface" requirement before legacy `/console` can be retired (see TASK-97).

**Shape (authoritative Rust source):** `AccessControlConfig` at `apps/synapse-pingora/src/config.rs:197-208` has three fields:
- `allow: Vec<String>` — CIDR ranges to allow (IPv4 and IPv6 supported; e.g. `10.0.0.0/8`, `2001:db8::/32`)
- `deny: Vec<String>` — CIDR ranges to deny
- `default_action: String` — `"allow"` or `"deny"`; behavior when no rule matches

**Validation:** each CIDR entry must pass `validate_cidr` (see `apps/synapse-pingora/src/validation.rs:655` onward) before the SPA submits the config. Duplicate-in-list entries should be rejected inline with a clear message. `default_action` should be a select with exactly two options.

Editor writes through the shared `POST /config` + `If-Match` path (mirroring `saveServerConfig`). Unknown fields inside `access_control` and the existing entries inside `allow`/`deny` must round-trip byte-identical when not edited.

Depends on TASK-96.1 for the per-site edit host UI. Follows the three-subsection-card visual pattern established on the Profiler tab in TASK-96.4.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 TypeScript interface `AccessControlConfig` added matching `apps/synapse-pingora/src/config.rs:197-208` (allow: string[], deny: string[], default_action: string, plus catch-all index signature for unknown fields)
- [ ] #2 Editor supports add/edit/remove on both `allow` and `deny` CIDR lists with inline validation that rejects malformed CIDRs (use the same regex or parsing strategy as the Rust `validate_cidr` at `apps/synapse-pingora/src/validation.rs:655`)
- [ ] #3 `default_action` rendered as a Select with options `allow` and `deny`; empty / unknown value defaults to `allow` in the form but is preserved as-is on save if the stored value is something the backend accepts
- [ ] #4 Save path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` through the existing Alert pattern
- [ ] #5 Non-edited `SiteConfig` blocks (upstreams, waf, headers, tls, shadow_mirror, rate_limit) are preserved byte-identical across a save (round-trip unit test)
- [ ] #6 Unknown / unmodeled fields inside `access_control` are preserved byte-identical (round-trip unit test)
- [ ] #7 Vitest coverage covers: adding / editing / removing allow entries, adding / editing / removing deny entries, invalid-CIDR inline validation, default_action toggle, preserve-unknown-fields round-trip
- [ ] #8 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #9 Roadmap copy in `App.tsx` updated to reflect shipped state
<!-- AC:END -->
