---
id: TASK-40
title: Runtime-verify Pingora 403 classification for deferred WAF block path
status: To Do
assignee: []
created_date: '2026-04-12 05:46'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - operations
  - integration-test
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The deferred WAF block path in `upstream_request_filter` returns `pingora_core::Error::explain(ErrorType::HTTPStatus(403), "blocked by deferred WAF pass")`. Static code review cannot confirm that Pingora's access log classifies this as a 403 (rather than as an upstream failure or 502) and that the request is not retried upstream. Ops teams need this verified end-to-end before deferred DLP enforcement is trusted in production.

Fix: run an integration test (or scripted curl against a locally running proxy) that triggers a deferred DLP block, captures Pingora's access log, and confirms the request is recorded as a 403 with no upstream retry. Record findings in a short note so future reviewers do not have to re-verify.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Integration test or documented manual procedure triggers a deferred DLP block against a locally running synapse-waf binary
- [ ] #2 Pingora access log line for the blocked request shows status 403 and not 502 / upstream error
- [ ] #3 No upstream retry is observed for the blocked request
- [ ] #4 Findings are documented in docs/development or linked from this task so the verification is replayable
- [ ] #5 If Pingora misclassifies the error, file a follow-up task and link it
<!-- AC:END -->
