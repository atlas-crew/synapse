---
id: TASK-96.6
title: 'Console-Next: per-site rate_limit override editor'
status: To Do
assignee: []
created_date: '2026-04-19 23:15'
labels:
  - console-next
  - ui
  - operator
  - rate-limit
dependencies:
  - TASK-96.1
  - TASK-96.4
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/config.rs
parent_task_id: TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add a per-site `rate_limit` override editor inside each site's detail view in the Console-Next SPA. Shipping this closes part of the "fully cover the configuration surface" requirement before legacy `/console` can be retired (see TASK-97).

**Shape (authoritative Rust source):** `SiteYamlConfig.rate_limit` at `apps/synapse-pingora/src/config.rs:270` is typed `Option<RateLimitConfig>`, reusing the same `RateLimitConfig` struct already tightened in TypeScript during TASK-96.4 (rps: u32, enabled: bool, burst: Option<u32>).

**Semantics (important):** the field is **optional per-site**. When absent, the site inherits the global `rate_limit` block edited in the Rate Limit tab. When present, it overrides the global for requests matching that site. The editor therefore needs three states:
1. Inherit (no override) — don't send a `rate_limit` key; if present in current config, remove it on save.
2. Enabled override — send a full `RateLimitConfig` object.
3. Disabled override (`enabled: false`) — send `{enabled: false, rps: 0, burst: null}` to actively disable rate limiting for this site even when global is on.

Editor writes through the shared `POST /config` + `If-Match` path. Unknown / unmodeled fields inside a stored per-site `rate_limit` must round-trip byte-identical when not edited.

Depends on TASK-96.1 for the per-site edit host UI. Reuses the `RateLimitConfig` TypeScript interface from TASK-96.4.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Editor exposes a three-state selector (Inherit global / Override enabled / Override disabled) rendering the rps + burst inputs only when an override is configured
- [ ] #2 Selecting Inherit on a site that previously had a rate_limit block removes the key from the POST body entirely so the backend falls back to the global rate_limit
- [ ] #3 Override-enabled state validates rps (non-negative integer) and burst (non-negative integer or blank for backend default), blocking save with inline error on invalid values
- [ ] #4 Save path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` through the existing Alert pattern
- [ ] #5 Non-edited `SiteConfig` blocks (upstreams, waf, headers, tls, shadow_mirror, access_control) are preserved byte-identical across a save (round-trip unit test)
- [ ] #6 Unknown / unmodeled fields inside a stored per-site `rate_limit` are preserved byte-identical when the operator keeps override mode unchanged
- [ ] #7 Global `rate_limit` block at the top level of the config is never modified by this editor (verified via unit test)
- [ ] #8 Vitest coverage covers: inherit → override transition, override → inherit transition (key deletion), override enabled → disabled toggle, validation errors, preserve-unknown-fields round-trip
- [ ] #9 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #10 Roadmap copy in `App.tsx` updated to reflect shipped state
<!-- AC:END -->
