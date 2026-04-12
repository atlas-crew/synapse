---
id: TASK-32
title: Emit WafBlock telemetry from deferred DLP block path
status: To Do
assignee: []
created_date: '2026-04-12 05:44'
labels:
  - waf
  - synapse-pingora
  - review-finding
  - telemetry
  - defect
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The deferred WAF pass in `SynapseProxy::upstream_request_filter` (apps/synapse-pingora/src/main.rs) blocks requests that match `dlp_violation` rules but only records to the local `block_log`. Other block sites in the same file — the bad-bot branch in `request_filter` and the body-phase block in `request_body_filter` — additionally emit `TelemetryEvent::WafBlock` to `self.telemetry_client`, which feeds Hub's WAF block stream and request-id pivot. Deferred DLP blocks are therefore invisible to downstream observability and cannot be correlated with their originating requests.

Fix: mirror the existing telemetry emission pattern (gated on `telemetry_client.is_enabled()`) in the deferred block path so operational tooling sees every WAF block regardless of which site fired it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Deferred block path in upstream_request_filter emits TelemetryEvent::WafBlock with request_id, rule_id, severity, client_ip, site, and path populated from ctx
- [ ] #2 Emission is gated on telemetry_client.is_enabled() to match existing block sites
- [ ] #3 Unit or integration test asserts the telemetry call is made when a deferred DLP rule blocks a request
- [ ] #4 No telemetry emission occurs for non-blocking deferred matches
<!-- AC:END -->
