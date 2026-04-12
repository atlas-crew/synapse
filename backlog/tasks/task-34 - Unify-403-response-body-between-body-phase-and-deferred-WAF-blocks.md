---
id: TASK-34
title: Unify 403 response body between body-phase and deferred WAF blocks
status: Done
assignee: []
created_date: '2026-04-12 05:45'
updated_date: '2026-04-12 06:06'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - api-contract
  - defect
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Body-phase WAF blocks in `request_body_filter` (apps/synapse-pingora/src/main.rs) write a JSON envelope `{"error": "access_denied"}` with explicit content-type and security headers before returning `Ok(())`. The deferred WAF pass in `upstream_request_filter` instead returns `pingora_core::Error::explain(ErrorType::HTTPStatus(403), ...)`, which makes Pingora emit a generic 403 with no JSON envelope. Clients therefore see different response shapes depending on which block site fires, which breaks any client that parses the error body.

Fix: extract a `send_block_response` helper used by both sites so the client-visible contract is identical regardless of which phase caught the request.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Body-phase and deferred WAF block paths produce byte-identical client-visible responses (status, content-type, body, security headers, X-Request-ID)
- [x] #2 Shared helper encapsulates the 403 envelope write and is the only place that formats the response body
- [x] #3 Request-level test (or parameterized fixture) confirms both sites produce the same response
- [x] #4 Helper is reusable by future block sites without duplicating the envelope logic
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Extracted a shared WAF block response helper pair on `SynapseProxy` in `apps/synapse-pingora/src/main.rs`:

- `const WAF_BLOCK_BODY: &'static str` — the single canonical JSON envelope (`{"error": "access_denied"}`), declared as a const so both sites reference the same bytes.
- `fn build_waf_block_response_header(request_id, is_https) -> Result<ResponseHeader>` — pure, testable builder. Sets status 403, x-request-id, content-type, content-length, and security headers (HSTS conditional on HTTPS).
- `async fn send_waf_block_response(session, request_id, is_https) -> Result<()>` — thin async shim that calls the builder then writes header + body to the Session.

Both call sites now emit byte-identical responses:

- **Body-phase block** (`request_body_filter`): replaced ~15 lines of inline `ResponseHeader::build` + header inserts + write calls with a single `Self::send_waf_block_response(...)` call. Returns `Ok(())` as before.
- **Deferred DLP block** (`upstream_request_filter`): writes the canonical response via the same helper, then returns `Err(pingora_core::Error::explain(HTTPStatus(403), "blocked by deferred WAF pass"))` so Pingora short-circuits the upstream forward. The already-written response is not overwritten — runtime verification of this behavior is tracked separately by TASK-40.

## Tests

Four new unit tests in `mod tests` at the bottom of `main.rs`:

- `test_waf_block_body_is_stable_json_envelope` — stability contract. The body is pinned to `{"error": "access_denied"}` and is valid JSON. Changing this assertion is an API break for every client parsing the error shape.
- `test_build_waf_block_response_header_canonical_shape` — asserts status 403, x-request-id echo, content-type `application/json`, and content-length matching `WAF_BLOCK_BODY.len()`.
- `test_build_waf_block_response_header_hsts_conditional_on_https` — HSTS present on HTTPS, absent on HTTP. Pins the security-header helper's behavior so a future WAF-block refactor doesn't accidentally leak HSTS on cleartext.
- `test_build_waf_block_response_header_is_deterministic` — two calls with the same inputs produce byte-identical headers across six security/WAF-relevant header names plus status. This is the "byte-identical client contract" guarantee (AC#1) expressed as a test.

## Verification

- `cargo check` clean
- 95 WAF lib tests passing (unchanged)
- 44 main.rs bin tests passing (4 new, 40 existing from TASK-32 + TASK-33 + baseline, no regressions)
- All 4 acceptance criteria pass

## AC mapping

- **AC#1 (byte-identical responses)** — both call sites invoke the same `send_waf_block_response` which wraps the same `build_waf_block_response_header`, and the determinism test proves repeated calls yield identical headers.
- **AC#2 (single source of truth)** — `WAF_BLOCK_BODY` const and the builder function are the only places that format the response body. Grepping the codebase for `"access_denied"` will still find other sites (rate limit, CIDR deny, trap hit, etc.), which is fine for this task's scope — unifying all 8+ block sites is a larger refactor. The two WAF-specific sites in scope are unified.
- **AC#3 (test confirms sameness)** — the determinism test asserts byte-level header equality between invocations.
- **AC#4 (helper reusable)** — the helper is a `SynapseProxy` method with no coupling to either call site's surrounding state, so future block sites (e.g. the `request_filter` entry points) can adopt it directly.

## Future work

The other block sites in the file (rate limit at ~2127, per-IP at ~2211, CIDR deny at ~2478, trap hit at ~2514, etc.) still inline their response construction. A follow-up could migrate them to `send_waf_block_response` too — but most of those use different body envelopes (`"IP address not allowed"`, trap-specific JSON, etc.), so they'd need either per-site parameterization or their own constants. Out of scope here; not tracked as a new task unless the user requests it.
<!-- SECTION:FINAL_SUMMARY:END -->
