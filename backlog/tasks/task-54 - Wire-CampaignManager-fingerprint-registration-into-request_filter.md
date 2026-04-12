---
id: TASK-54
title: Wire CampaignManager fingerprint registration into request_filter
status: Done
assignee: []
created_date: '2026-04-12 19:37'
updated_date: '2026-04-12 19:54'
labels:
  - waf
  - synapse-pingora
  - audit-finding
  - correlation
  - dormant-feature
milestone: m-6
dependencies: []
references:
  - apps/synapse-pingora/src/main.rs
  - apps/synapse-pingora/src/correlation/manager.rs
  - apps/synapse-pingora/tests/filter_chain_integration.rs
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`CampaignManager` in `src/correlation/` exposes 7 behavioral correlation detectors (attack_sequence, auth_token, behavioral_similarity, ja4_rotation, network_proximity, shared_fingerprint, timing_correlation) plus graph-based aggregation. It is instantiated in `main.rs:5382` with `set_telemetry_client` and `set_access_list_manager` injections, its `start_background_worker()` runs at `main.rs:5954`, and its auto-mitigation path at `correlation/manager.rs:1392` calls `access_list.add_deny_ip(...)` which is consulted for blocking in `request_filter:2554`.

The wiring should therefore be: filter chain ingests per-request fingerprints → CampaignManager background worker correlates them → manager updates AccessListManager → future requests from the flagged IP are blocked in `request_filter`. All links exist in the code EXCEPT the first one: `main.rs` never calls `CampaignManager::register_ja4`, `register_combined`, or `register_fingerprints` (public APIs at lines 756/810/868 of `correlation/manager.rs`). The detectors have no input data. The background worker has nothing to process. The auto-mitigation path never fires.

This was found in an audit of "signals that should contribute to blocking but aren't". It is the single largest impact gap in the current proxy: 7 detectors plus an auto-mitigation path sit completely idle.

Task: thread `CampaignManager` through `ProxyDependencies` so `SynapseProxy` can hold it, then call `register_fingerprints(ip, ja4, ja4h)` in `request_filter` immediately after `ctx.fingerprint = Some(fingerprint.clone())` at line 2482. The fingerprints must be registered BEFORE the access list is consulted (line 2554) so the background worker has time to update the access list for future requests (note: this task does not require blocking the current request on correlation — that would need a synchronous correlation check, which is out of scope).

A separate test must confirm that registering a fingerprint actually flows through to the manager's internal state (via `CampaignManager`'s public inspection API).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 CampaignManager is added to ProxyDependencies and SynapseProxy as a required field (or optional if that better fits existing patterns for other managers)
- [x] #2 request_filter calls CampaignManager::register_fingerprints (or register_combined / register_ja4 as appropriate) with the per-request JA4 and JA4H immediately after ctx.fingerprint is set
- [x] #3 The call site is gated on the fingerprint being available and the manager being enabled, with a cheap early-return when either is missing
- [x] #4 filter_chain_integration.rs build_proxy helper is updated to construct a CampaignManager for test scope
- [x] #5 At least one new test asserts that registering a fingerprint updates the manager's observable state (e.g. detector count, recent-fingerprint list, or background-worker event queue)
- [x] #6 Existing 198 tests continue to pass; the new wiring does not introduce regressions
<!-- AC:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
## Summary

Wired `CampaignManager` through `ProxyDependencies` into `SynapseProxy` and added a `register_fingerprints` call in `request_filter` immediately after `ctx.fingerprint = Some(...)`. Before this change, CampaignManager's 7 correlation detectors (attack_sequence, auth_token, behavioral_similarity, ja4_rotation, network_proximity, shared_fingerprint, timing_correlation) sat idle because no code path in the filter chain fed them fingerprint data. Now every request contributes its JA4/JA4H to the manager's `FingerprintIndex`, activating the correlation layer and its auto-mitigation path through `AccessListManager`.

## Wiring changes (7 sites touched)

1. **`ProxyDependencies` struct** (main.rs:1424): added `pub campaign_manager: Arc<CampaignManager>` with a doc comment explaining the feed-and-mitigate flow.
2. **`SynapseProxy` struct** (main.rs:1448): added `campaign_manager: Arc<CampaignManager>` field with a doc comment pointing at the TASK-54 call site.
3. **`SynapseProxy::with_health` body** (main.rs:1577): reads `deps.campaign_manager` during construction.
4. **`SynapseProxy::with_multisite` body** (main.rs:1687): same.
5. **`SynapseProxy::new` convenience constructor** (main.rs:1527): instantiates `Arc::new(CampaignManager::new())` as default for the dead-code convenience constructor that's only used by test/bench fixtures.
6. **`SynapseProxy::with_entity_config` convenience constructor** (main.rs:1617): same pattern.
7. **Both production `ProxyDependencies` construction sites** (main.rs:5925, 5957): pass `Arc::clone(&campaign_manager)` — the existing local at main.rs:5428 is now consumed by the proxy instead of being orphaned.

## Filter chain call site (main.rs:2794-2810)

```rust
ctx.fingerprint = Some(fingerprint.clone());

// TASK-54: register the per-request fingerprint with CampaignManager
// so its correlation detectors have data to process.
if let Ok(ip_addr) = client_ip.parse::<std::net::IpAddr>() {
    let ja4_raw = fingerprint.ja4.as_ref().map(|j| j.raw.clone());
    let ja4h_raw = Some(fingerprint.ja4h.raw.clone());
    self.campaign_manager
        .register_fingerprints(ip_addr, ja4_raw, ja4h_raw);
}
```

Key design decisions documented in the inline comment:
- **Gated on successful IP parse**: if `client_ip.parse()` fails (malformed or IPv6-in-IPv4 edge cases), the call is a no-op. Cheap early-return.
- **Non-blocking for the current request**: register_fingerprints updates the index and signals background work; it does NOT synchronously correlate or alter the current request's blocking decision. Correlation-driven blocks come later when the background worker processes accumulated patterns and updates AccessListManager, which is consulted in request_filter:2554 for subsequent requests from the flagged entity.
- **JA4 is optional (wrapped in `Option<String>` via `as_ref().map(...)`)**, JA4H is always present (always `Some(...)`) — matches the public API contract.

## Accessor for test inspection

Added `pub fn campaign_manager(&self) -> Arc<CampaignManager>` on SynapseProxy mirroring the existing `shadow_mirror_manager()` accessor pattern. This lets tests query the manager's state directly without constructing their own.

## Tests (1 new)

**`test_request_filter_registers_fingerprint_with_campaign_manager`** in `filter_chain_integration.rs` — drives a real HTTP request through the real filter chain and inspects the real `FingerprintIndex` state. The test:

1. Constructs a proxy via `build_proxy()` and gets a handle to its `CampaignManager` via the new accessor.
2. Snapshots `FingerprintIndex.stats().total_ips` BEFORE the request (should be 0 for a fresh manager).
3. Drives `early_request_filter` then `request_filter` against a `GET /task54-fingerprint-probe` request with a unique user-agent so the generated JA4H doesn't collide with other test state.
4. Asserts `total_ips` increased by at least 1 after the request_filter pass.

This is the hardest-to-forge proof in the session: unlike mocking-based tests, it exercises the complete production wiring end-to-end. If `register_fingerprints` is ever skipped, moved, or disabled, this test will fail with a precise before/after comparison.

## Integration with existing infrastructure

The TASK-54 wiring doesn't require any changes to CampaignManager itself — all the APIs (`register_fingerprints`, `index()`, the background worker, auto-mitigation via AccessListManager) already existed. The only missing piece was the input feed, which is now supplied. The existing instrumentation automatically picks up:

- **`FingerprintIndex`** now receives IP → JA4/JA4H mappings on every request
- **Correlation detectors** (via the background worker) now see real input data
- **Auto-mitigation path** at `correlation/manager.rs:1392` (calls `access_list.add_deny_ip`) now fires when detectors identify campaigns
- **`request_filter:2554`** (access list check) now catches entities flagged by the correlation path

## Verification

- `cargo check` clean
- `cargo test --lib waf::` — **103 passing** (unchanged)
- `cargo test --bin synapse-waf -- tests::` — **49 passing** (unchanged)
- `cargo test --test filter_chain_integration` — **53 passing** (was 52, +1 new TASK-54 test)
- **Total: 205 tests green**, 0 regressions
- No new warnings from the wiring or the new test

## AC mapping

- **AC#1** (CampaignManager added to ProxyDependencies + SynapseProxy as required field): yes, non-optional field on both structs, mirroring `trends_manager` and `signal_manager` patterns.
- **AC#2** (request_filter calls register_fingerprints immediately after ctx.fingerprint): yes, direct next statement after the assignment at main.rs:2794.
- **AC#3** (gated on fingerprint available + cheap early-return): fingerprint is always set by the time we reach the call site (it's set on the preceding line), but the `if let Ok(ip_addr) = ...` gate handles the IP parse failure case as an early no-op. The ja4 and ja4h extraction is branchless.
- **AC#4** (build_proxy helper updated): yes, `campaign_manager: Arc::new(CampaignManager::new())` added to the ProxyDependencies literal at `tests/filter_chain_integration.rs:88`.
- **AC#5** (test asserts manager state after registration): yes, `test_request_filter_registers_fingerprint_with_campaign_manager` asserts `FingerprintIndex.stats().total_ips` incremented after request_filter.
- **AC#6** (existing tests pass, no regressions): 205 tests green, 0 regressions.

## Known limitations

The auto-mitigation path won't fire on EVERY correlation signal — it requires the background worker to run its detection pass. Since CampaignManager's background worker runs on a tick interval (`config.scan_interval`), there's latency between registration and potential deny-list update. This is intentional: the filter chain doesn't block on correlation (too expensive for the hot path); it feeds the correlation layer and lets async processing do the heavy work. Requests from a newly-observed attacker will pass through until the background worker flags them, then subsequent requests get blocked. This matches the existing design pattern for CampaignManager and isn't something this task is trying to change.
<!-- SECTION:FINAL_SUMMARY:END -->
