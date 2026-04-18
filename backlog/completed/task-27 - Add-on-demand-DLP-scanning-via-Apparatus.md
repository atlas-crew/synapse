---
id: TASK-27
title: Add on-demand DLP scanning via Apparatus
status: Done
assignee: []
created_date: '2026-04-05 07:23'
updated_date: '2026-04-05 12:55'
labels:
  - apparatus
  - dlp
  - data
  - api
  - ui
milestone: m-4
dependencies:
  - TASK-9
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Integrate Apparatus DataApi DLP scanning for on-demand content inspection from the Horizon dashboard.

API route:
- `POST /api/v1/apparatus/data/dlp-scan` → `client.data.dlpScan({ content, rules })`
- Returns: matches (type, value, location, confidence), summary

UI: Add a "DLP Scanner" tool to the existing DLP Dashboard page under Fleet Operations:
- Text area for pasting content to scan
- Rule selection (credit cards, SSNs, API keys, custom patterns)
- Results showing detected PII with confidence scores and locations

This complements Synapse's edge DLP (which scans in-flight traffic) with an on-demand scanner for content review.
<!-- SECTION:DESCRIPTION:END -->
