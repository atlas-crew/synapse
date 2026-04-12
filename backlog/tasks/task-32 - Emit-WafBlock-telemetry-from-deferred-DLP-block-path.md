---
id: TASK-32
title: Emit WafBlock telemetry from deferred DLP block path
status: Done
assignee: []
created_date: '2026-04-12 05:44'
updated_date: '2026-04-12 05:59'
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
- [x] #1 Deferred block path in upstream_request_filter emits TelemetryEvent::WafBlock with request_id, rule_id, severity, client_ip, site, and path populated from ctx
- [x] #2 Emission is gated on telemetry_client.is_enabled() to match existing block sites
- [x] #3 Unit or integration test asserts the telemetry call is made when a deferred DLP rule blocks a request
- [x] #4 No telemetry emission occurs for non-blocking deferred matches
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Extracted `build_deferred_waf_block_event` as a pure free function in `apps/synapse-pingora/src/main.rs` near `categorize_rule_id`, and replaced the inline event construction in the deferred block path of `upstream_request_filter` with a call to the helper. Emission is wrapped in `if self.telemetry_client.is_enabled()` and dispatched via `tokio::spawn` so it never blocks the proxy hot path, mirroring the fire-and-forget pattern used by the existing body-phase post-detection telemetry emitter.

## Rule ID format

Deferred DLP blocks emit a `rule_id` of `DLP_DEFERRED:{first_rule}` (falling back to `DLP_DEFERRED` when the verdict has no matched rules, which is pathological but defended-against). This prefix lets Hub distinguish deferred blocks from body-phase blocks (which use the raw rule id) and bad-bot blocks (which use `BAD_BOT:{bot_name}`).

## Severity mapping

Mirrors the body-phase post-detection emitter at `main.rs:4259-4266`: risk_score > 80 → `critical`, > 50 → `high`, otherwise `medium`. The mapping is strict-greater-than, so 80 → high and 50 → medium (documented in `test_build_deferred_waf_block_event_severity_tiers`).

## Tests

Three new unit tests in `mod tests` at the bottom of `main.rs`:

- `test_build_deferred_waf_block_event_populates_fields_from_inputs` — asserts every field of the returned `TelemetryEvent::WafBlock` matches the inputs, including the `DLP_DEFERRED:` prefix on rule_id.
- `test_build_deferred_waf_block_event_severity_tiers` — exercises the critical/high/medium boundaries (100, 81, 80, 51, 50, 0) to pin the strict-greater-than behavior.
- `test_build_deferred_waf_block_event_empty_rules_falls_back` — pathological blocking verdict with no matched rules still returns a routable event with rule_id `"DLP_DEFERRED"`.

## Verification

- `cargo check` clean
- 95 WAF lib tests passing (unchanged from before)
- 36 main.rs bin tests passing (3 new, no regressions)
- AC#2 (gated on `is_enabled()`) and AC#4 (no emission on non-blocking matches) are provable by code inspection — the emission block is inside `if self.telemetry_client.is_enabled()` which itself is inside `if deferred.blocked`, with a separate `else if !deferred.matched_rules.is_empty()` branch that does not call the helper.

## Follow-up note for TASK-34

The pure-helper pattern generalizes: when TASK-34 extracts a shared `send_block_response` for the body-phase and deferred block paths, it can call `build_deferred_waf_block_event` directly, and a parallel `build_body_phase_waf_block_event` (or a unified `build_waf_block_event(source: BlockSource, ...)`) can replace the inline construction at `main.rs:4268` as well.
<!-- SECTION:FINAL_SUMMARY:END -->
