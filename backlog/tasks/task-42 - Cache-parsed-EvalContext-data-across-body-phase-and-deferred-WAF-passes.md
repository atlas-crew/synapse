---
id: TASK-42
title: Cache parsed EvalContext data across body-phase and deferred WAF passes
status: To Do
assignee: []
created_date: '2026-04-12 05:46'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - performance
  - future-work
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
  - apps/synapse-pingora/src/waf/types.rs
  - apps/synapse-pingora/src/main.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`Engine::analyze_deferred_with_timeout` in apps/synapse-pingora/src/waf/engine.rs calls `EvalContext::from_request_with_deadline`, which re-runs query-string parsing, JSON flattening (up to `MAX_JSON_ELEMENTS = 1000`), and optional multipart parsing — all of which already executed during the body-phase WAF pass on the same request. For requests that trip DLP and activate the deferred pass, this doubles the body-parse cost.

Fix: cache the parsed `args`, `arg_entries`, and `json_text` on `RequestContext` during the body-phase pass, and reuse them in the deferred pass via a new `Request::with_cached_args` (or equivalent) path. The tricky part is lifetime/ownership — the cached data must outlive both passes and be borrowable by a fresh `Request`/`EvalContext`.

Out of scope: rewriting the `Request<'a>` lifetime model end-to-end. Scope this to body-parse reuse only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Parsed args/arg_entries/json_text are computed once per request and reused by both the body-phase and deferred WAF passes
- [ ] #2 Storage lives on RequestContext (or an equivalent per-request struct) and is released when the request completes
- [ ] #3 A micro-benchmark or an instrumented counter demonstrates the deferred pass does not re-run JSON flattening on a request that has already been through body-phase
- [ ] #4 Existing WAF unit tests and the seven signal-match tests still pass
- [ ] #5 Lifetime/ownership approach is documented in a short comment on RequestContext or the reuse entry point
<!-- AC:END -->
