---
id: TASK-43
title: >-
  Expose richer structured predicates for dlp_violation and schema_violation
  match kinds
status: Done
assignee: []
created_date: '2026-04-12 05:46'
updated_date: '2026-04-18 20:50'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - rule-dsl
  - future-work
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/waf/engine.rs
  - apps/synapse-pingora/src/dlp/scanner.rs
  - apps/synapse-pingora/src/profiler/schema_types.rs
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `dlp_violation` match kind currently exposes only a count (optionally filtered by `data_type`) and `schema_violation` exposes only the aggregate `total_score`. Rule authors cannot express natural intents like "block if any DLP match has severity=critical", "block if any DLP match is from the aws_key pattern", or "block if a schema violation specifically is a type_mismatch on the email field". Everything collapses into a single numeric comparison, which forces fragile workarounds.

Fix: add structured predicates that let rules filter by additional fields before the count/score comparison. Maintain backwards compatibility with existing count/total_score rule shapes.

Scope notes:
- dlp_violation: add severity filter and pattern_name filter alongside the existing data_type filter
- schema_violation: add a violation-kind filter (e.g. unexpected_field, type_mismatch, missing_required)
- Keep JSON rule shape ergonomic — prefer adding fields to the existing match condition over introducing a new match kind
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 dlp_violation supports filtering by severity (e.g., 'critical') in addition to the existing data_type filter
- [ ] #2 dlp_violation supports filtering by pattern_name
- [ ] #3 schema_violation supports filtering by violation kind
- [ ] #4 Existing rules using only count/total_score thresholds continue to behave identically (backwards compatibility)
- [ ] #5 JSON rule examples are added as inline docstring snippets on the match-kind handlers
- [ ] #6 Unit tests cover at least one new predicate per match kind, including a negative case where the filter excludes an otherwise-matching signal
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added structured rule predicates for `dlp_violation` and `schema_violation` by extending `MatchCondition` with `severity`, `pattern_name`, and `violation_kind`. Updated engine evaluation to filter matching DLP/schema findings before threshold checks, preserved legacy count/total_score rule shapes, and added unit coverage for positive and negative filtered cases plus inline JSON examples on the handlers.
<!-- SECTION:FINAL_SUMMARY:END -->
