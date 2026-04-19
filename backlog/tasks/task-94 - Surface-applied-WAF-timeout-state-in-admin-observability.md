---
id: TASK-94
title: Surface applied WAF timeout state in admin observability
status: To Do
assignee: []
created_date: '2026-04-19 01:55'
labels:
  - synapse-pingora
  - review-finding
  - observability
dependencies: []
references:
  - .agents/reviews/review-20260418-214912.md
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Review follow-up from .agents/reviews/review-20260418-214912.md.

Expose the applied body and deferred WAF timeout values anywhere operators already inspect live WAF configuration or metrics, and revisit whether reload logging should only mention timeout values when they change. This keeps the new deferred timeout configurable and verifiable after hot reloads.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Admin or metrics surfaces expose both body and deferred applied timeout values
- [ ] #2 Reload-time observability for timeout changes is documented or implemented
<!-- AC:END -->
