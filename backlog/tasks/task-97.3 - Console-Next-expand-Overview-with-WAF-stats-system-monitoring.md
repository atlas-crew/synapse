---
id: TASK-97.3
title: 'Console-Next: expand Overview with WAF stats + system monitoring'
status: To Do
assignee: []
created_date: '2026-04-19 23:16'
labels:
  - console-next
  - ui
  - operator
  - monitoring
  - waf
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
Expand the Console-Next Overview tab so it's a credible replacement for the legacy `/console` monitoring panels. This is a retirement gate for legacy `/console` (see TASK-97).

**Current state:** Overview tab at `apps/synapse-console-ui/src/App.tsx:1043-1084` renders four MetricTiles from `/_sensor/status` (Mode, Sites, Workers, Blocked Requests) plus a PropertyList with health + HTTP/HTTPS bind + last-loaded timestamp. That's minimal compared to what's in the `/_sensor/status` payload and completely ignores the richer admin-only endpoints.

**Backend data available (no new endpoints needed):**
- `GET /_sensor/status` — currently used; contains `mode`, `running`, `active_connections`, `blocked_requests`, `requests_seen`, plus other runtime fields.
- `GET /waf/stats` — WAF-specific stats: analyzed / blocked counts, block rate, avg detection latency (in microseconds), per-rule / per-category breakdowns. Confirmed in use by `/health`'s `data.waf` shape already visible in smoke tests: `{enabled, analyzed, blocked, block_rate_percent, avg_detection_us}`.
- `GET /_sensor/metrics` — broader sensor metrics (runtime counters, reload state, ratelimit hit counts).
- `GET /stats` — top-level `{requests_seen, blocked_requests, active_connections}` summary.
- `GET /_sensor/system` (if present) — process + service state, covered at `admin_server.rs:4818-4852` with `processes`, `services`, `summary.{total, running, sleeping, stopped, zombie}`.

**Scope:** add these sections to the Overview tab, each as its own Box subsection in the same visual pattern the Profiler tab uses:
1. **WAF performance** — analyzed, blocked, block rate, avg detection latency, deferred-pass block counts if present.
2. **Runtime** — requests seen, active connections, workers, uptime, mode.
3. **System** — process summary counts (total/running/sleeping/stopped/zombie) from `/_sensor/system` if the endpoint is exposed; otherwise skip this section gracefully.
4. Keep the existing PropertyList (Health, HTTP Bind, HTTPS Bind, Last Loaded) as a fourth "Environment" subsection.

**UX requirements:**
- Load all required endpoints in parallel via the existing `Promise.allSettled([...])` pattern inside `load()` (currently at `App.tsx:475-487`). Render each subsection independently — one failing endpoint must not blank out the others; emit per-section warnings instead.
- Round latencies sensibly (µs → ms with 2 decimals; counts formatted with thousands separators). Use `Intl.NumberFormat` for locale-aware grouping.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection. No polling in this task — just a richer snapshot on each Refresh.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Overview tab gains a WAF Performance subsection rendering analyzed / blocked / block-rate / avg-detection-latency from `/waf/stats` (field names verified against the Rust handler, not guessed)
- [ ] #2 Overview tab gains a Runtime subsection rendering at minimum requests_seen, active_connections, workers, uptime, mode from the combined `/stats` + `/_sensor/status` responses
- [ ] #3 Overview tab gains a System subsection rendering process summary counts from `/_sensor/system` when available; the section renders a friendly 'unavailable' placeholder if that endpoint is missing or 404s, and does not blank out other sections
- [ ] #4 `load()` fetches the new endpoints in parallel via `Promise.allSettled(...)` alongside existing calls; per-endpoint failure emits a warning string in `state.warnings` rather than short-circuiting
- [ ] #5 Numeric counts use `Intl.NumberFormat` for thousands separators; microsecond latency values render as milliseconds with 2 decimals; missing / null fields render as `—` (em-dash) rather than `NaN` or `undefined`
- [ ] #6 Vitest coverage covers: happy-path load with all endpoints, one endpoint 500ing and others rendering correctly, `/_sensor/system` 404 rendering the unavailable placeholder, number formatting
- [ ] #7 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [ ] #8 Roadmap copy in `App.tsx` updated to reflect shipped state
<!-- AC:END -->
