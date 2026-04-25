# Synapse Technical Reference — Infographic Coverage

Tracks parity between the long-form **Synapse (Embedded Sensor) — Technical
Reference** PDF and the one-page infographics in
[`brand/infographics/`](../../brand/infographics/). The PDF is the
authoritative engineering reference; the infographics are the
visual/marketing counterparts derived from it.

Source PDF: `Synapse (Embedded Sensor) - Technical Reference.pdf` (A10/ThreatX
Portfolio → Architecture archive). 70 pages, 25 numbered sections + executive
summary + appendix. Last reviewed 2026-04-18.

## Coverage map

Legend:
- **Full** — the infographic covers the core concept, flow, and vocabulary of
  that PDF section end-to-end.
- **Partial** — the infographic touches the section but only covers a subset
  (e.g. risk scoring flows through auto-mitigation but auto-mitigation itself
  has no dedicated visual).
- **None** — no infographic addresses this section yet. See
  [Gaps](#gaps-and-proposed-infographics) for prioritised next steps.

| PDF section | Infographic(s) | Coverage |
|---|---|---|
| Executive Summary | [`request-processing-lifecycle`](../../brand/infographics/html/request-processing-lifecycle.html), [`full-architecture`](../../brand/infographics/html/full-architecture.html) | Full |
| 1. Core Architecture | [`full-architecture`](../../brand/infographics/html/full-architecture.html), [`deployment-topology`](../../brand/infographics/html/deployment-topology.html) | Full |
| 2. Site Management | — | None |
| 3. WAF Engine | [`waf-rule-pipeline`](../../brand/infographics/html/waf-rule-pipeline.html) | Full |
| 4. Detection Capabilities | [`risk-scoring-lifecycle`](../../brand/infographics/html/risk-scoring-lifecycle.html) | Full |
| 5. Campaign Correlation | [`campaign-correlation-engine`](../../brand/infographics/html/campaign-correlation-engine.html) | Full |
| 6. Graph Correlation | [`campaign-correlation-engine`](../../brand/infographics/html/campaign-correlation-engine.html) | Partial (graph detector shown as one of eight; no dedicated graph-walk visual) |
| 7. Rate Limiting | — | None |
| 8. Endpoint Profiling | — | None |
| 9. Response Profiling | — | None |
| 10. Interrogator System | [`interrogator-system`](../../brand/infographics/html/interrogator-system.html) | Full |
| 11. Auto-Mitigation | [`risk-scoring-lifecycle`](../../brand/infographics/html/risk-scoring-lifecycle.html) | Partial (threshold crossing shown; escalation/de-escalation ladder not broken out) |
| 12. Bot & Crawler Detection | — | None |
| 13. Credential Stuffing Detection | — | None |
| 14. Signal Horizon Integration | [`signal-horizon-telemetry-pipeline`](../../brand/infographics/html/signal-horizon-telemetry-pipeline.html), [`threat-intel-feedback-loop`](../../brand/infographics/html/threat-intel-feedback-loop.html), [`synapse-client-integration-flow`](../../brand/infographics/html/synapse-client-integration-flow.html) | Full |
| 15. Admin API | — | None (reference-heavy; unlikely to warrant a visual) |
| 16. Configuration | — | None (reference-heavy; unlikely to warrant a visual) |
| 17. Metrics & Telemetry | [`signal-horizon-telemetry-pipeline`](../../brand/infographics/html/signal-horizon-telemetry-pipeline.html) | Partial (pipeline shown; local Prometheus surface not depicted) |
| 18. Performance Profile | — | None (table-heavy; unlikely to warrant a visual) |
| 19. Additional Capabilities (DLP) | [`dlp-edge-protection`](../../brand/infographics/html/dlp-edge-protection.html) | Full (for DLP subset only) |
| 20. Session Intelligence | — | None |
| 21. Actor Correlation | — | None |
| 22. Schema Learning | [`schema-learning-lifecycle`](../../brand/infographics/html/schema-learning-lifecycle.html) | Full |
| 23. Header Profiling | — | None |
| 24. Shadow Mirroring | — | None |
| 25. Headless Detection | — | Partial (mentioned inside `interrogator-system`; no dedicated injection-tracker visual) |
| Appendix: API Reference | — | None (reference-heavy; unlikely to warrant a visual) |

**Coverage summary:** 10 sections full · 4 partial · 13 none.
Of the 13 uncovered, 4 are intentionally skipped as reference-heavy
(Admin API, Configuration, Performance Profile, Appendix).

## Gaps and proposed infographics

Ranked by a rough *visual narratability × detection-story value* heuristic.
P1 items tell a story the marketing deck cannot tell with bullets; P3 items
are nice-to-have parity fillers.

### P1 — high narrative value

1. **Session Intelligence & Hijack Detection** (§20)
   Session lifecycle from cookie bind → fingerprint drift → hijack verdict.
   Natural companion to `interrogator-system` and plugs a visible gap in the
   "what does Synapse do after the first request?" story. Module:
   `session/manager.rs` (1,562 LOC).

2. **Actor Correlation — Composite Identity** (§21)
   Multi-IP actor merging (JA4 + UA hash + behavioural link) into a single
   entity. Visually pairs well with `campaign-correlation-engine` but zooms
   to the per-actor level. Module: `actor/manager.rs` (1,450 LOC).

3. **Credential Stuffing Detection** (§13)
   Distributed-pattern detection across auth endpoints. Strong standalone
   story; maps to a real attack category prospects care about.

4. **Auto-Mitigation Escalation Ladder** (§11)
   Five-level challenge progression with de-escalation arrows. Extract from
   `risk-scoring-lifecycle` and give it its own page; today it's compressed
   into one node there.

### P2 — medium narrative value

5. **Bot & Crawler Classification** (§12)
   JA4 rotation + behavioural fingerprints → class verdict (good bot / bad
   bot / human). Complements the interrogator and headless pages.

6. **Rate Limiting — Token Bucket Per Site** (§7)
   Simple, clean visual. Good for operator-focused materials where the
   interrogator/correlation visuals feel too abstract.

7. **Endpoint & Response Profiling** (§§8–9, combined)
   Streaming statistics (Welford) → per-endpoint baseline → anomaly signal.
   One diagram covers both; pairs naturally with `schema-learning-lifecycle`.

8. **Shadow Mirroring Flow** (§24)
   Async honeypot mirror path with rate limiting. Reinforces the "no impact
   on live traffic" claim visually.

9. **Headless Browser Detection** (§25)
   Injection-tracker deep-dive. Currently a single node inside
   `interrogator-system`; the detection signals (navigator fingerprints, JS
   execution quirks) deserve their own visual.

### P3 — low priority / filler

10. **Header Profiling** (§23) — overlaps heavily with endpoint profiling;
    could be rolled into the §§8–9 visual instead of a standalone.
11. **Site Management** (§2) — operator-onboarding flow; may be better as
    tutorial content in `site/` than as an infographic.

### Not planned

- §15 Admin API, §16 Configuration, §18 Performance Profile, Appendix —
  reference-heavy sections. Infographic format offers no lift over the
  tables/lists already in the PDF and the `site/reference/` markdown.

## Maintenance notes

- When a new infographic lands in `brand/infographics/`, update the
  coverage map row and the summary count in the same commit.
- When the Synapse Technical Reference PDF gains or reorders sections,
  re-run the PDF TOC against this map and adjust. The PDF's section
  numbers are the stable key.
- If an infographic's scope drifts (e.g. `risk-scoring-lifecycle` grows to
  cover auto-mitigation escalation end-to-end), upgrade its row from
  *Partial* to *Full* and strike the matching P1/P2 proposal.
- This doc is developer-only. It is **not** part of the VitePress site.
  User-facing visuals ship via `site/architecture/` and `site/reference/`
  where the infographic PNGs/PDFs are embedded.
