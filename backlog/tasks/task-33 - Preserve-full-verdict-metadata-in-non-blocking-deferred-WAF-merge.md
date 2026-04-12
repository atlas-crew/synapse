---
id: TASK-33
title: Preserve full verdict metadata in non-blocking deferred WAF merge
status: To Do
assignee: []
created_date: '2026-04-12 05:45'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - observability
  - defect
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
When the deferred WAF pass produces a non-blocking match, the merge into `ctx.detection` in `SynapseProxy::upstream_request_filter` (apps/synapse-pingora/src/main.rs) copies only `risk_score` (via `max`) and `matched_rules` (via dedup-extend). It silently discards `entity_risk`, the deferred call's `detection_time_us`, and any `block_reason` note from the deferred verdict. Downstream phases that read `ctx.detection` get an under-reported picture of the WAF work performed on the request.

Fix: merge all verdict fields that are meaningful after a non-blocking match, or keep the deferred detection as a secondary field on `RequestContext` so observability surfaces see both passes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Non-blocking deferred merge accumulates entity_risk into the existing detection instead of dropping it
- [ ] #2 Deferred detection_time_us is either added to the existing timing or surfaced through a dedicated field
- [ ] #3 Non-empty deferred block_reason is preserved (appended, stored as secondary reason, or documented as intentionally dropped with rationale)
- [ ] #4 Unit test exercises a non-blocking deferred match merging with an already-populated ctx.detection and asserts all preserved fields
<!-- AC:END -->
