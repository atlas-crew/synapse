# Synapse Technical Reference — Site Coverage

Tracks parity between the long-form **Synapse (Embedded Sensor) — Technical
Reference** PDF and the VitePress GitHub Pages site under
[`site/`](../../site/). The PDF is the authoritative engineering reference;
`site/` is the published user-facing documentation.

Sister doc: [`synapse-infographic-coverage.md`](./synapse-infographic-coverage.md)
covers the same PDF against `brand/infographics/`.

Source PDF: `Synapse (Embedded Sensor) - Technical Reference.pdf` (A10/ThreatX
Portfolio → Architecture archive). 70 pages, 25 numbered sections + executive
summary + appendix. Last reviewed 2026-04-18.

## Coverage map

Legend:
- **Full** — the site covers the concept end-to-end at reasonable depth.
- **Partial** — the site touches the topic but is missing meaningful
  subtopics. Missing pieces called out under the row.
- **None** — no site page addresses it.

| PDF section | Site page(s) | Coverage |
|---|---|---|
| Executive Summary | [`architecture/synapse`](../../site/architecture/synapse.md), [`reference/synapse-features`](../../site/reference/synapse-features.md), [`index`](../../site/index.md) | Full |
| 1. Core Architecture | [`architecture/synapse`](../../site/architecture/synapse.md), [`development/benchmarks`](../../site/development/benchmarks.md), [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 2. Site Management | [`reference/synapse-api`](../../site/reference/synapse-api.md), [`configuration/synapse`](../../site/configuration/synapse.md) | Partial — missing vhost/SNI detail, per-site TLS certificate chains, hostname routing specifics |
| 3. WAF Engine | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 4. Detection Capabilities | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`development/benchmarks`](../../site/development/benchmarks.md) | Full |
| 5. Campaign Correlation | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`architecture/data-flow`](../../site/architecture/data-flow.md) | Full |
| 6. Graph Correlation | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Partial — graph-walk detector not called out as its own algorithm; traversal semantics absent |
| 7. Rate Limiting | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`configuration/synapse`](../../site/configuration/synapse.md) | Full |
| 8. Endpoint Profiling | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`reference/synapse-api`](../../site/reference/synapse-api.md) | Full |
| 9. Response Profiling | [`reference/synapse-api`](../../site/reference/synapse-api.md), [`reference/synapse-features`](../../site/reference/synapse-features.md) | Partial — response-side profile learning and Welford streaming stats not documented |
| 10. Interrogator System | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 11. Auto-Mitigation | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 12. Bot & Crawler Detection | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 13. Credential Stuffing Detection | [`reference/synapse-api`](../../site/reference/synapse-api.md), [`reference/synapse-features`](../../site/reference/synapse-features.md) | Partial — distributed pattern detection across fleet sensors not documented; only single-sensor view |
| 14. Signal Horizon Integration | [`configuration/synapse`](../../site/configuration/synapse.md), [`architecture/data-flow`](../../site/architecture/data-flow.md) | Full |
| 15. Admin API | [`reference/synapse-api`](../../site/reference/synapse-api.md) | Full |
| 16. Configuration | [`configuration/synapse`](../../site/configuration/synapse.md), [`reference/synapse-api`](../../site/reference/synapse-api.md) | Full |
| 17. Metrics & Telemetry | [`reference/synapse-api`](../../site/reference/synapse-api.md), [`architecture/data-flow`](../../site/architecture/data-flow.md) | Full |
| 18. Performance Profile | [`development/benchmarks`](../../site/development/benchmarks.md) | Full |
| 19. Additional Capabilities (DLP, tarpit, trap) | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`configuration/features`](../../site/configuration/features.md) | Full |
| 20. Session Intelligence | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 21. Actor Correlation | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| 22. Schema Learning | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`reference/synapse-api`](../../site/reference/synapse-api.md) | Full |
| 23. Header Profiling | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`reference/synapse-api`](../../site/reference/synapse-api.md) | Partial — per-endpoint header baselining specifics and anomaly-scoring algorithm absent |
| 24. Shadow Mirroring | [`reference/synapse-features`](../../site/reference/synapse-features.md), [`configuration/features`](../../site/configuration/features.md) | Partial — async honeypot mirror flow and no-impact-on-live-traffic guarantees not depicted |
| 25. Headless Detection | [`reference/synapse-features`](../../site/reference/synapse-features.md) | Full |
| Appendix: API Reference | [`reference/synapse-api`](../../site/reference/synapse-api.md) | Full |

**Coverage summary:** 19 full · 6 partial · 0 none (26 rows).

## Gap plan

All gaps are *Partial* — no topic is entirely absent from the site. The
remediation work is to **deepen existing pages**, not to create new ones.
Ranked by user-impact × editorial effort.

### P1 — deepen in place

1. **§13 Credential Stuffing — distributed detection** (in
   [`reference/synapse-features`](../../site/reference/synapse-features.md))
   Add a subsection showing how credential-stuffing signals correlate across
   fleet sensors via Horizon, not just per-sensor. This is a differentiator
   prospects ask about; today the page reads as single-sensor only.

2. **§6 Graph Correlation** (in
   [`reference/synapse-features`](../../site/reference/synapse-features.md))
   Break the graph-walk detector out from the general "eight detectors" list
   with a short walk-through (seed actor → edge rules → connected component
   verdict). Can borrow the visual from a future
   `campaign-graph-walk` infographic (see
   [`synapse-infographic-coverage.md`](./synapse-infographic-coverage.md)
   §Gap P1 #2).

3. **§2 Site Management — vhost/SNI/TLS chains** (in
   [`configuration/synapse`](../../site/configuration/synapse.md))
   Add the per-site TLS certificate chain story (SNI resolution, cert
   reload, hostname routing). Operators hit this during first install and
   today have to read the admin-console code.

### P2 — deepen opportunistically

4. **§9 Response Profiling** — add a short section next to §8 Endpoint
   Profiling. Response-side Welford stats are a real feature and currently
   invisible on the site.

5. **§23 Header Profiling** — same treatment as §9. One subsection under
   the existing profiler coverage explaining the per-endpoint baseline
   and anomaly scoring.

6. **§24 Shadow Mirroring** — add the async honeypot mirror flow diagram
   (matches the proposed infographic in the brand coverage doc). Useful
   for the "zero risk to live traffic" claim in sales decks.

### Not planned (already adequate)

All 19 Full-coverage sections. No action.

## Maintenance notes

- When `site/` pages add or lose content, update the coverage row in the
  same commit. The PDF section number is the stable key.
- If the Synapse Technical Reference PDF gains or reorders sections,
  re-audit against the new TOC.
- Upgrade a row from *Partial* to *Full* when the "missing" bullet no
  longer applies, and strike the matching P1/P2 item.
- This doc is developer-only. It is **not** part of the VitePress site.
