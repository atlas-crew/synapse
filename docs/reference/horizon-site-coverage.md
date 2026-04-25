# Signal Horizon Technical Reference — Site Coverage

Tracks parity between the long-form **Signal Horizon (Fleet & Intel) —
Technical Reference** PDF and the VitePress GitHub Pages site under
[`site/`](../../site/). The PDF is the authoritative engineering reference;
`site/` is the published user-facing documentation.

> **Rename in progress (ADR-0003, milestone m-9).** Signal Horizon is being
> renamed to **Synapse Fleet** as part of the Synapse brand consolidation.
> Authoritative site content now lives under the `synapse-fleet*` filenames
> below. The old `horizon-*.md` paths are `<meta http-equiv="refresh">`
> redirect stubs (9–11 lines each) and are scheduled for removal once the
> redirect period ends. This doc links to the **new** paths; if you are
> landing here after the stubs are deleted, nothing breaks.
>
> Related backlog: tasks 87 (ADR published-docs rename), 89 (package
> rename), 92 (rewrite docs site). This coverage doc feeds task 92.

Source PDF: `Signal Horizon (Fleet & Intel) - Technical Reference.pdf`
(A10/ThreatX Portfolio → Architecture archive). 8 numbered sections +
Appendix A (API) + Appendix B (Error Codes). Version 2.1, Feb 2026. Last
reviewed 2026-04-18.

## Coverage map

Legend: **Full** / **Partial** / **None** (same semantics as the Synapse
coverage doc).

| PDF section | Site page(s) | Coverage |
|---|---|---|
| 1. Overview (3-pillar framing, fleet scale figures) | [`getting-started/index`](../../site/getting-started/index.md), [`architecture/index`](../../site/architecture/index.md), [`architecture/synapse-fleet`](../../site/architecture/synapse-fleet.md), [`index`](../../site/index.md) | Full |
| 2. Architecture (FleetAggregator, FleetCommander, ConfigManager, RuleDistributor, ThreatHunter, WarRoom; PostgreSQL / ClickHouse / Redis data layer) | [`architecture/synapse-fleet`](../../site/architecture/synapse-fleet.md), [`index`](../../site/index.md) | Full |
| 3. Signal Horizon — Global Intel (campaign correlation, threat hunting, war rooms, collective defense) | [`architecture/data-flow`](../../site/architecture/data-flow.md), [`reference/synapse-fleet-features`](../../site/reference/synapse-fleet-features.md) | Full |
| 4. SOC Analyst Tooling | [`reference/synapse-fleet-features`](../../site/reference/synapse-fleet-features.md), [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md) | Full |
| 5. Fleet Management (registration, health, config push, rule distribution, onboarding) | [`reference/synapse-fleet-features`](../../site/reference/synapse-fleet-features.md), [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md) | Full |
| 6. Fleet Security (aggregated analytics, protection dashboard, API catalog, rules, threats) | [`reference/synapse-fleet-features`](../../site/reference/synapse-fleet-features.md) | Full |
| 7. Sensor Protocol (bidirectional WebSocket between Horizon and sensors) | [`architecture/data-flow`](../../site/architecture/data-flow.md), [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md) | Full |
| 8. Aggregation & Metrics (batching, dedup, enrichment, dual-write) | [`architecture/data-flow`](../../site/architecture/data-flow.md), [`architecture/synapse-fleet`](../../site/architecture/synapse-fleet.md) | Full |
| Appendix A: API Reference | [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md) | Full |
| Appendix B: Error Codes | [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md) | Partial — no dedicated error-code catalog with error-id ↔ meaning ↔ remediation mapping |

**Coverage summary:** 9 full · 1 partial · 0 none (10 rows).

## Cross-reference: Horizon §7 vs Synapse §14

The sensor protocol has two sides:
- **Horizon PDF §7 Sensor Protocol** — command plane view (`FleetCommander` →
  sensor command queue, `FleetAggregator` ← sensor telemetry).
- **Synapse PDF §14 Signal Horizon Integration** — sensor view (telemetry
  batching, registration-token handoff).

Both audits mark the relevant section *Full*, but the same site pages
([`architecture/data-flow`](../../site/architecture/data-flow.md),
[`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md))
carry the weight. If either page is materially changed, re-check **both**
coverage docs in the same pass.

## Gap plan

One gap. Small.

### P1

1. **Appendix B — Error Code Catalog**
   Add a dedicated section to
   [`reference/synapse-fleet-api`](../../site/reference/synapse-fleet-api.md)
   listing every error code returned by the fleet API with: id, HTTP
   status, meaning, operator remediation. The PDF appendix is already
   structured this way; port it over. Low-effort, high-value for
   integrators writing client code against the fleet API.

### Not planned

All 9 Full-coverage sections. No action.

## Rename-cleanup checklist

Tied to milestone m-9. Items the site-side rename needs to close out
*after* the redirect period ends:

- [ ] Delete `site/architecture/horizon.md` (11-line redirect stub).
- [ ] Delete `site/configuration/horizon.md` (11-line redirect stub).
- [ ] Delete `site/deployment/horizon.md` (11-line redirect stub).
- [ ] Delete `site/reference/horizon-api.md` (9-line redirect stub).
- [ ] Delete `site/reference/horizon-features.md` (9-line redirect stub).
- [ ] Verify VitePress sidebar in `site/.vitepress/config.mts` only links
  `synapse-fleet*` paths.
- [ ] Grep the repo for residual `horizon-*.md` internal links and rewrite.
- [ ] Update this doc's title and move it to `synapse-fleet-site-coverage.md`
  once the PDF itself is renamed (end of m-9).

## Maintenance notes

- PDF section numbers (1–8, Appendix A, Appendix B) are the stable key.
- When `site/` pages add or lose content, update the coverage row in the
  same commit.
- Horizon §7 / Synapse §14 overlap — always re-check both docs when the
  protocol pages change. See the cross-reference section above.
- When the PDF is eventually renamed to match Synapse Fleet, update the
  top-of-file source reference and rename this doc; keep the section-number
  keys intact.
- This doc is developer-only. It is **not** part of the VitePress site.
