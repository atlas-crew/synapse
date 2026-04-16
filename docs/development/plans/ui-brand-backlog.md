# UI & Brand Backlog

Open threads from the design system overhaul and analytics page review.
Each item is self-contained and can be picked up independently.

## Brand Consolidation Decision (2026-04-16)

Consolidating from two product brands (Synapse WAF sensor + Signal
Horizon dashboard) to **one unified brand: Synapse**.

- Phase 1: Admin console palette resync (**done** — see below)
- Phase 2: Horizon UI sidebar rebrand → "Synapse" / "Synapse Dashboard"
- Phase 3: Mechanical rename (npm packages, Docker images, directory
  names, docs)

The blue/cyan palette (`#1E90FF` / `#06B6D4` / `#0B4F8A`) is the
canonical Synapse palette. Orange is legacy — drop it from accent
tokens as the rebrand progresses.

## Synapse Admin Console Overhaul

The sensor admin console at `apps/synapse-pingora/assets/admin_console.html`
is a single-file embedded HTML page served at `/console` from the admin
port. It's functional but visually drifted from the dashboard. The file
is `include_str!`-ed into the binary, so the single-file constraint is
load-bearing — no npm, no framework, no external bundles.

### Tier 1 — Brand resync ✅ DONE

All CSS variables resynced to canonical `tokens.ts` values. Stat cards
restyled to left-aligned label-above-value. Tone accent classes added
and applied to 6 cards (operations=warning, config/detection/ratelimit/
tls=info, active-config=system). Mono font fallback fixed (dropped
IBM Plex Mono, uses system mono stack). Button/tag/toast/output colors
all updated. Status dot enlarged with glow. Toast moved to top-right.
Nav section labels and active state contrast improved.

### Tier 2 — Functional polish

- **Sidebar active state:** bump section label contrast, add subtle
  `bg-ac-blue/10`-equivalent tint to active item.
- **Status dot visibility:** 6px → 8px, add `box-shadow: 0 0 8px
  var(--green)` glow when healthy.
- **Toast position:** bottom-right → top-right (matches Horizon).
- **Overview output two-scroll-container:** `pre.output` with
  `max-height: 300px` nests inside scrollable `.content`. Either drop the
  inner cap or make the outer non-scrollable for that panel.
- **`<select>` styling:** form controls inherit Rubik but dropdown
  options inherit OS default.
- **Mobile sidebar:** currently hides all labels and shows nothing.
  Add icons-only mode.

### Tier 3 — Stat cards with trends

- Pull rolling deltas from auto-refresh data (the overview already
  refreshes every 30s). Show `+12% vs last minute` on each stat card.
  Requires a small in-page rolling buffer of previous values.

### What NOT to change

- Don't try to share React components or `@/ui` — the single-file
  embed constraint is load-bearing.
- Don't add a router or SPA framework — panel-switching via
  `display: none/block` is fine for ~10 panels.
- Don't replace the `buildField`/`collectFields` form builder — it works
  because the config schema is flat enough.
- Don't remove the Raw API panel — it's invaluable for debugging.

---

## Horizon UI — Remaining Design System Items

These are threads left open after the `.card` deprecation, MetricCard
unification, and CI guard landed.

### `colors.navy` direct imports on hero-migrated pages

OverviewPage still imports `colors.navy` for inline styles on child
elements inside the hero panel. The navy background is now owned by
`variant="hero"` in Panel — page-level `colors.navy` references are
a token leak. Sweep to replace with Tailwind `text-white/70` etc. or
drop entirely where Panel already handles the bg.

### Hero variant — second caller audit

Only one page (OverviewPage Strategic Insight) uses `variant="hero"`.
The variant might be overfit to that single card. If a second hero
call-site appears, verify the API is still right. If a hero starts
needing its own tone variants (e.g. `tone="destructive"` on a dark-bg
incident card), evaluate whether hero should split into tone-aware
sub-variants.

### Typography harmonisation pass

Many migrated panels still have inline `<h3 className="text-lg
font-semibold ...">` instead of routing through `<SectionHeader
size="h4" titleStyle={CARD_HEADER_TITLE_STYLE}>`. The wrapper is
consistent now (Panel), but the *headers inside* drift across pages.
Mechanical sweep, would touch ~50 files. Non-urgent — the visual
inconsistency is subtle.

### Form control consistency audit

Some older fleet pages still use hand-rolled `<input>` / `<select>` /
`<button>` elements instead of `@/ui` `Input` / `Select` / `Button`.
No inventory yet. Worth a grep sweep to size the gap.

### GeoTrafficMap — deck.gl → d3-geo (optional)

The analytics page GeoTrafficMap uses deck.gl (WebGL) for a static
10-country choropleth. The visual problems are fixed (dark substrate,
monotonic scale, legend, header placement, luma.gl hack removal), but
deck.gl is still a heavy dependency (~500 KB chunk) for what could be
a lightweight d3-geo SVG choropleth. The page already depends on
`topojson-client` and `d3-scale`; adding `d3-geo` is ~30 KB.
Benefits: no WebGL, no shader log hack, smaller bundle, real SVG you
can CSS-style and make accessible via ARIA. Only worth doing if bundle
size becomes a priority.

### Visual regression tests

The `.card` deletion shipped a broken MetricCard for several commits
because no test caught it. The CI grep guard catches *that specific*
regression class, but structural CSS breakage in general is still
undetected. Playwright + visual snapshots of the `/design-system`
showcase page would catch any component regression in one place.
Highest-leverage future investment in the testing stack.

### Bundle splitting

The index chunk is 5.18 MB (gzipped 1.41 MB) with a Vite warning on
every build. Unrelated to the design system but visible. Candidates
for code-splitting: Mermaid/Katex (heavy, lazy-loaded on first render),
deck.gl (only used on one page), Wardley map.

---

## Prioritised order

| Priority | Item | Effort | Impact | Status |
|----------|------|--------|--------|--------|
| ~~1~~ | ~~Synapse admin console brand resync (Tier 1)~~ | ~~2h~~ | ~~High~~ | **Done** |
| 2 | Horizon UI sidebar rebrand → "Synapse" (Phase 2) | ~2h | High — unifies the product identity |
| 3 | Synapse admin console functional polish (Tier 2) | ~2h | Medium — makes console feel maintained |
| 4 | Typography harmonisation pass | ~3h | Medium — subtle consistency win across ~50 files |
| 5 | Form control consistency audit + sweep | ~2h | Medium — reduces hand-rolled form elements |
| 6 | `colors.navy` token leak sweep | ~30min | Low — one file, small visual impact |
| 7 | Visual regression tests | ~4h | High long-term — prevents all future CSS regressions |
| 8 | Bundle splitting | ~3h | Medium — build warning + load time improvement |
| 9 | GeoTrafficMap d3-geo swap | ~3h | Low — only matters for bundle size |
| 10 | Synapse admin console stat trends (Tier 3) | ~2h | Low — informational polish |
| 11 | Mechanical rename (npm/Docker/dirs) (Phase 3) | ~4h | Medium — finalises the brand consolidation |
