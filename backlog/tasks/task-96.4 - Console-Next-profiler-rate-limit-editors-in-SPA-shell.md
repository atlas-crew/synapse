---
id: TASK-96.4
title: 'Console-Next: profiler + rate-limit editors in SPA shell'
status: Done
assignee: []
created_date: '2026-04-19 03:16'
updated_date: '2026-04-19 06:06'
labels:
  - console-next
  - ui
  - operator
  - profiler
dependencies: []
references:
  - apps/synapse-console-ui/src/App.tsx
  - apps/synapse-console-ui/src/App.test.tsx
  - apps/synapse-pingora/src/admin_server.rs
  - apps/synapse-pingora/src/config.rs
  - apps/synapse-pingora/src/ratelimit.rs
  - apps/synapse-pingora/src/profiler
parent_task_id: TASK-96
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add editors for the top-level `profiler` and `rate_limit` blocks of `ConfigFile` in the Console-Next SPA. Today both blocks are preserved across writes (see `App.tsx:590-596` — `saveServerConfig` spreads `state.fullConfig` but only touches `server.*`) but there is no UI to modify them, so the roadmap line in `App.tsx:1058` ("Profiler and module editors in the SPA shell") is still open.

Scope:
- Add a new tab to the `tabs` array at `App.tsx:152-157` (e.g. `profiler`, and optionally `rate-limit` as its own tab depending on how large the surface is).
- Discover the authoritative profiler + rate_limit schemas from the Rust side (`apps/synapse-pingora/src/config.rs` + `apps/synapse-pingora/src/ratelimit.rs` + `apps/synapse-pingora/src/profiler/`), tighten the currently-`Record<string, unknown>`-typed fields at `App.tsx:100-101`, and build field-level editors.
- Mutate via the shared `POST /config` + `If-Match` path; preserve all untouched blocks (`server`, `sites`, and whichever of `profiler` / `rate_limit` this tab isn't editing) byte-identical across saves.
- Handle the `warnings[]` and `rebuild_required` fields from `MutationResult` identically to the server tab.

Depends on nothing else in TASK-96 — can proceed in parallel with TASK-96.1 since it lives on a different top-level config block.

CSP constraint: `style-src 'self'` (see `apps/synapse-pingora/src/admin_server.rs:403`). No runtime style injection.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 TypeScript interfaces for `profiler` and `rate_limit` match the Rust structs — cite the Rust files + struct names in the PR description
- [x] #2 New tab(s) added to the `tabs` array at `App.tsx:152-157` with accessible tab/panel id pairing consistent with existing tabs
- [x] #3 Editor exposes the operator-facing fields the Rust struct defines; unknown / unmodeled fields are preserved byte-identical on save (round-trip unit test required)
- [x] #4 Save path uses `POST /config` with `If-Match: <etag>` and surfaces `warnings[]` + `rebuild_required` through the existing Alert pattern
- [x] #5 Vitest coverage in `App.test.tsx` covers: edit + save happy path for each new editor, preserve-unknown-fields round-trip, and an etag-mismatch error
- [x] #6 Other top-level config blocks (`server`, `sites`, and the sibling `profiler` or `rate_limit` block) are verified unchanged across a save via unit test
- [x] #7 `pnpm --filter @atlascrew/synapse-console-ui type-check` and `pnpm --filter @atlascrew/synapse-console-ui test` both pass
- [x] #8 Roadmap copy in `App.tsx:1038-1064` is updated to reflect shipped state
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Shipped profiler + rate-limit editors as two new tabs in the Console-Next SPA.

**Scope landed:**
- Tightened TypeScript interfaces for `RateLimitConfig` and `ProfilerConfig` against the Rust structs at `apps/synapse-pingora/src/config.rs:141-149` (RateLimitConfig: rps u32 / enabled bool / burst Option<u32>) and `apps/synapse-pingora/src/config.rs:282-335` (ProfilerConfig: 12 fields across core / anomaly thresholds / security controls). Both carry a `[key: string]: unknown` catch-all so unmodeled fields round-trip.
- New tabs: `rate-limit` (+ label "Rate Limit") and `profiler` (+ label "Profiler") in the `tabs` array, with accessible `tab-<key>` / `panel-<key>` id pairing consistent with the existing pattern.
- Rate-Limit tab: rps + burst number inputs + enabled toggle. Save uses shared `POST /config` + `If-Match` and surfaces `warnings[]` + `rebuild_required` via Alert.
- Profiler tab: three subsection cards (Core, Anomaly thresholds, Security controls) covering all 12 struct fields. `parseFloatField` helper added alongside the existing `parseIntegerField` for the z-threshold / stddev / type-ratio inputs (Finite check, optional min/max bounds).
- Both save paths spread the existing block first (`...state.fullConfig.rate_limit` / `...state.fullConfig.profiler`) before overlaying the form-edited fields, so any unmodeled keys returned by `GET /config` are preserved byte-identical.
- Sibling top-level blocks (`server`, `sites`, and the *other* of rate_limit/profiler) are preserved by the single-block-mutation pattern (`{...state.fullConfig, rate_limit: nextRateLimit}` or `{...state.fullConfig, profiler: nextProfiler}`).
- Roadmap copy at the bottom of `App.tsx` updated — removed "Profiler and module editors in the SPA shell" from the remaining-gaps list.

**Verification:**
- `pnpm --filter @atlascrew/synapse-console-ui type-check` — clean.
- `pnpm --filter @atlascrew/synapse-console-ui test` — 11/11 passing (7 pre-existing + 4 new: rate-limit happy path, profiler happy path with sibling-preservation, preserve-unknown-fields round-trip, profiler 412 etag-mismatch). The happy-path tests explicitly assert `body.server === baseConfig.server`, `body.sites === baseConfig.sites`, and the sibling block equals `baseConfig.{rate_limit|profiler}` — satisfying AC #6.
- Bundle rebuilt (`vite build` → 246.13 kB) and re-embedded via `cargo build --bin synapse-waf`; admin server restarted (PID 35205) and the fresh `app.js` serves at 246,133 B on :6191.

**Implementation notes for future editors:**
- `parseFloatField` uses `Number.isFinite` rather than regex; that's intentional since float inputs include decimals and scientific notation. Mirror it for any other float-heavy editor.
- The Rust `ProfilerConfig` uses `#[serde(default = "...")]` per field, so missing fields on the wire round-trip cleanly to defaults; the SPA doesn't need to send every field, but does anyway to keep the write authoritative and avoid surprise defaults.
- `type_ratio_threshold` is clamped `[0, 1]` in the SPA to match the "ratio" semantic — backend accepts f64 without bounds, so this is an SPA-side UX guardrail rather than a correctness check.
<!-- SECTION:FINAL_SUMMARY:END -->
