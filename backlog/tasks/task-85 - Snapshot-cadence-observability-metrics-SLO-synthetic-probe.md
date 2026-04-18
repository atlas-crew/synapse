---
id: TASK-85
title: 'Snapshot cadence observability (metrics, SLO, synthetic probe)'
status: To Do
assignee: []
created_date: '2026-04-17 22:49'
labels:
  - observability
  - signal-horizon
  - fleet-aggregation
  - slo
dependencies:
  - TASK-78
  - TASK-84
references:
  - apps/signal-horizon/docs/architecture/adr-0002-fleet-view-strategy.md
  - apps/signal-horizon/api/src/services/fleet-intel/ingestion-service.ts
priority: high
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ADR-0002 commits to ~65 s max staleness for `SensorIntel*` snapshot tables as a product contract for fleet SOC dashboards. The commitment only holds if it is *measurable in prod* — the failure mode we care about is silent staleness (timer fires but upserts fail, a sensor silently drops out of the poll loop, service hangs without crashing), not process death.

This task instruments the ingestion path with metrics, wires an SLO, adds a synthetic probe, and makes the stale-row threshold a single config value used everywhere.

Depends on TASK-84 (consolidate duplicate services) because with two writers running, `poll_completions_total` double-counts and the SLO becomes meaningless. Either TASK-84 ships first, or the metric labels include `service_name` so we can disambiguate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Prometheus histogram `fleet_intel_poll_duration_seconds{sensor_id, table}` emitted per sensor per poll cycle — proves polling is happening and captures per-sensor tail latency
- [ ] #2 Prometheus counter `fleet_intel_poll_completions_total{sensor_id, table, outcome}` with outcome ∈ {ok, tunnel_error, upsert_error} — liveness + failure breakdown per sensor
- [ ] #3 Prometheus gauge `fleet_intel_snapshot_age_seconds{table, tenant}` computed as `now() - max(updated_at)` for each `SensorIntel*` table per tenant, refreshed on a short interval — this is the load-bearing SLO signal
- [ ] #4 SLO defined: `p99(fleet_intel_snapshot_age_seconds) < 90s over 5min window`. Burn-rate alerts wired at 2× and 14× budget per SRE standard (fast + slow burn)
- [ ] #5 Synthetic probe cron hits `GET /synapse/actors` every 5 min with a test tenant, reads `lastSeenAt` on every returned row, alerts if any row is older than threshold — validates full stack (ingestion → DB → route → envelope)
- [ ] #6 Single source of truth for the threshold: `STALE_THRESHOLD_SECONDS` config constant consumed by (a) snapshot-aggregator stale filter from TASK-79, (b) SLO threshold in Prometheus config, (c) integration-test assertions, (d) synthetic probe. No magic numbers repeated across those four places.
- [ ] #7 Integration test with 2+ mock sensors asserts: after 65 s, every snapshot row's `updatedAt` is within the threshold. Test reads the threshold from the same config constant as the production code.
- [ ] #8 Runbook entry at `docs/operations/fleet-intel-ingestion.md` documents: what the alerts mean, expected steady-state values, debugging steps for each outcome type, what to do if staleness breaches SLO.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Alerts tested by artificially stopping the ingestion service in staging and confirming the staleness SLO burn-rate alert fires within its budget window
- [ ] #2 Dashboard panel added to the fleet observability Grafana board showing per-tenant snapshot age distribution
- [ ] #3 ADR-0002 updated to cross-reference this observability task in its 'Operational' consequences section so future readers see the enforcement mechanism, not just the promise
<!-- DOD:END -->
