---
id: TASK-14
title: Persist Apparatus events to ClickHouse
status: Done
assignee: []
created_date: '2026-04-03 18:30'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - clickhouse
  - telemetry
milestone: m-1
dependencies:
  - TASK-12
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Apparatus events flowing through the SSE bridge should be written to ClickHouse alongside native Synapse signals for historical analysis. 

- Ensure the existing telemetry dual-write path (PostgreSQL + ClickHouse) handles Apparatus-sourced signals
- Add a `source` column or tag to distinguish Apparatus signals from Synapse signals in queries
- Verify the analytics views (time-series queries, campaign correlation) include Apparatus events correctly

This enables historical threat hunting across both Synapse WAF detections and Apparatus deception/honeypot events.
<!-- SECTION:DESCRIPTION:END -->
