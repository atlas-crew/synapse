---
id: TASK-34
title: Unify 403 response body between body-phase and deferred WAF blocks
status: To Do
assignee: []
created_date: '2026-04-12 05:45'
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
- [ ] #1 Body-phase and deferred WAF block paths produce byte-identical client-visible responses (status, content-type, body, security headers, X-Request-ID)
- [ ] #2 Shared helper encapsulates the 403 envelope write and is the only place that formats the response body
- [ ] #3 Request-level test (or parameterized fixture) confirms both sites produce the same response
- [ ] #4 Helper is reusable by future block sites without duplicating the envelope logic
<!-- AC:END -->
