---
id: TASK-24
title: Add red team scanner to Horizon dashboard
status: Done
assignee: []
created_date: '2026-04-05 07:22'
updated_date: '2026-04-05 12:55'
labels:
  - apparatus
  - security
  - red-team
  - api
  - ui
milestone: m-4
dependencies:
  - TASK-9
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Integrate Apparatus SecurityApi red team scanning. Lets SOC operators launch targeted OWASP scans against specific URLs from the Horizon dashboard with results flowing into the threat views.

API routes needed:
- `POST /api/v1/apparatus/security/redteam` → `client.security.redteam({ target, tests, timeout })`
- Results include: test name, pass/fail/warning, details per test, summary (total/passed/failed/warnings), duration

UI: New "Red Team Scanner" section (could be on the Threat Hunting page or a new page):
- Target URL input
- Test selection checkboxes (or run all)
- Results table with pass/fail badges, expandable details
- Summary card with total/passed/failed/warnings
- Option to save scan results as a threat intel report

Also expose Sentinel rule management:
- `GET /api/v1/apparatus/security/sentinel/rules` → list rules
- `POST /api/v1/apparatus/security/sentinel/rules` → create rule
- This could sync with Synapse's rule engine for unified rule management.
<!-- SECTION:DESCRIPTION:END -->
