# `<Panel>` — Page-Zone Wrapper Component

New in the `@/ui` component library. Resolves the long-running
"four coexisting card conventions" drift documented in the session
notes from the UI audit.

## Why it exists

Before this component, the `@/ui` library provided atoms (`Text`,
`Stack`, `Box`), layout primitives (`Grid`, `Divider`), and widgets
(`MetricCard`, `ChartPanel`, `StatCard`), but had **no canonical
answer for "how do I wrap a multi-element zone on a page?"** Every
page contributor invented their own wrapper — and three or four
distinct conventions grew in parallel:

| Convention | Mechanism | Example page |
|---|---|---|
| A | Inline React `style={{ ... }}` using tokens | `ChartPanel` (widget layer) |
| B | Hand-rolled Tailwind className | `AdminSettingsPage` |
| C | Custom `.card` CSS class in `index.css` | `OverviewPage` |
| D | Plain `<div className="border ...">` | most fleet pages |

The visual difference between them is real and visible — users
commented that "some pages look polished, others look flat" without
being able to articulate why. The root cause was that Convention B
and C (the polished ones) weren't reusable, and Convention D (used
by most pages) had no accent structure to fall back on.

`<Panel>` codifies Convention B (the AdminSettings pattern) as a
first-class, discoverable, type-checked component so every new page
has one canonical answer.

## API

```tsx
import { Panel } from '@/ui';

<Panel tone="info">
  <SectionHeader title="Tenant Privacy" />
  <Stack gap="md">...</Stack>
</Panel>
```

### Props

- `tone` — semantic color of the top accent bar. One of:
  `default` (neutral), `info` (blue), `warning` (orange),
  `destructive` (red), `advanced` (magenta), `system` (muted). Default
  is `default`.
- `padding` — `sm` (p-4, 16px), `md` (p-6, 24px), or `lg` (p-8, 32px).
  Default is `lg` to match the AdminSettings feel.
- `spacing` — internal vertical rhythm between direct children.
  `none`, `sm` (space-y-3), `md` (space-y-6, default), or `lg`
  (space-y-8).
- `as` — polymorphic element tag. `section` (default), `div`,
  `article`, or `aside`.
- `noAccent` — hide the top accent bar. Use sparingly (only for
  nested panels where an outer Panel already provides the accent).
- Plus any standard HTML attributes (`className`, `aria-labelledby`,
  `role`, etc.).

### Tone vocabulary

The six tones are a **semantic vocabulary, not just colors**. Apply
them consistently:

- **`default`** — informational zones, summaries, neutral data displays
- **`info`** — primary or core control zones, main settings
- **`warning`** — cautionary zones, important but recoverable actions
- **`destructive`** — danger zones (deletions, revocations, resets)
- **`advanced`** — advanced/expert-mode controls, experimental features
- **`system`** — system information, read-only metadata

The goal: teach users "red top bar = destructive, magenta = advanced"
across every page so they can transfer the intuition without reading
labels. AdminSettings already uses this vocabulary internally; `<Panel>`
makes it reusable app-wide.

## When to use Panel vs a widget component

- **Widgets** (`MetricCard`, `ChartPanel`, `StatCard`, `DataTable`) own
  their own card-like visual. Use them directly; **do not wrap them in
  a Panel** (you'd get nested card chrome).
- **Panel** is for **grouping multiple atoms or widgets** into a named
  zone. A settings section with a header and some form controls, a
  page section with a mix of `KpiStrip` + `DataTable`, a danger zone
  with a button — those are Panel territory.
- **Plain `<div>`** is fine for **trivial wrappers** that don't warrant
  a zone (e.g., a flex container around two buttons). Don't reach for
  Panel just because you need a `<div>`.

## Migration guide

When converting an existing page:

1. **Find ad-hoc card wrappers**: grep for `bg-surface-card`,
   `border-t-4 border-ac-`, `shadow-card`, `className="card"`, or
   raw `<section className="border...">`.
2. **Pick the tone** by asking "what does this zone semantically mean?"
   — not "what color looks right." If you catch yourself picking a
   color for aesthetic reasons, you probably want `default`.
3. **Pick the padding** — `lg` for top-level page sections (default),
   `md` for standard control zones, `sm` for compact inline panels.
4. **Pick the spacing** — `md` is the default and matches
   AdminSettings. Use `none` if the Panel's children manage their own
   layout (e.g., a single child like `ActiveCampaignList`).
5. **Keep accessibility attributes** — `aria-labelledby`, `role`, etc.
   pass through via the `...rest` spread.
6. **Delete the old wrapper's className** and let Panel own the
   background, border, shadow, and padding.

## Examples in the codebase (POC migrations)

- `apps/signal-horizon/ui/src/pages/OverviewPage.tsx` — Active
  Campaigns section. Converted from `<section className="card border-t-4
  border-ac-blue">` to `<Panel tone="info" padding="md" spacing="none">`.
- `apps/signal-horizon/ui/src/pages/fleet/SensorConfigPage.tsx` —
  Apparatus Echo Target preset row. Converted from
  `<Stack className="border border-border-subtle bg-surface-card p-4">`
  to `<Panel tone="default" padding="sm" spacing="none" as="div">`.

Both pages type-check and build clean (`pnpm type-check`,
`pnpm build` in `apps/signal-horizon/ui`) with no visual regression
in the retained conventions.

## Compound slots: `Panel.Header` and `Panel.Body`

**Added in the second Panel commit.** For panels with an internal
header/body split (previously the ad-hoc `.card` + `card-header` +
`card-body` pattern), use the compound API:

```tsx
<Panel tone="default" className="min-h-[450px]">
  <Panel.Header>
    <SectionHeader title="Top Attackers" size="h4" />
    <Button variant="ghost" size="sm">View all</Button>
  </Panel.Header>
  <Panel.Body className="space-y-5 overflow-auto flex-1">
    {rows.map(...)}
  </Panel.Body>
</Panel>
```

### What the slots do

- **`Panel.Header`** — dense header bar with `px-6 py-4` padding, a
  subtle `bg-surface-subtle/50` tint, a `border-b border-border-subtle`
  separator, and a default `flex justify-between items-center gap-4`
  layout so a title and actions naturally sit on opposite sides.
  Also includes `shrink-0` so it stays pinned when the Panel flexes.
- **`Panel.Body`** — content slot beneath the header. Takes an
  optional `padding` prop (`sm` | `md` | `lg` | `none`, default `md`
  which is `p-6`). Use `padding="none"` for full-bleed children like
  lists, tables, or iframes that manage their own padding.

### Auto-detection behavior

When Panel detects that one of its direct children is `Panel.Header`
or `Panel.Body`, it **automatically**:

1. Drops its own `padding` — slots control internal spacing
2. Drops its own `spacing` (the `space-y-*` between children)
3. Switches to `flex flex-col` so `Panel.Body className="flex-1"`
   grows to fill available height and pins the header to the top

Panels without slots still use their own padding/spacing normally.
This means the compound API is **opt-in**: existing Panel usage
doesn't change behavior when you add Header/Body to a new panel.

### Detection caveat

The auto-detect logic does a `React.Children.toArray(children).some()`
check by element type. It only fires for **direct children** — if you
wrap `Panel.Header` in a fragment or another div, the detection
misses it and Panel keeps its own padding. This is intentional: if
you're wrapping slots in something else, you probably want manual
control of layout anyway.

## Migrated (current)

- `OverviewPage.tsx` — **Active Campaigns** (info tone, slotted),
  **Top Attackers** (default tone, slotted), **Top Fingerprints**
  (default tone, slotted)
- `fleet/SensorConfigPage.tsx` — Apparatus Echo Target preset row
  (default tone, non-slotted, `as="div"`)
- `AdminSettingsPage.tsx` — **14 accented sections** across all seven
  tabs (Tenant / Policies / Automation / Fleet / Synapse / Apparatus
  / System). Tone mix: 7× `info`, 2× `destructive`, 2× `advanced`,
  2× `success`, 1× `default`, 1× `system`. **The `success` tone was
  added to Panel as part of this migration** (two AdminSettings
  sections used `border-status-success` for active/healthy states
  that the original vocabulary didn't cover).
- `components/AdminSettingsSkeleton.tsx` — 2 loading-state panels
  (`info` + `destructive`) that duplicated the inline pattern.
- **Hunting section sweep (10 components)** — migrated every
  hunting panel that had an ad-hoc card wrapper:
  - Pattern A (`<div className="border border-border-subtle
    bg-surface-card">`): **BehavioralAnomaliesPanel**,
    **ClickHouseOpsPanel**, **FleetIntelligencePanel**,
    **LowAndSlowPanel**, **RecentRequestsPanel**,
    **SigmaLeadsPanel**, **SigmaRulesPanel**. All converted to
    `<Panel tone="default" padding="none" spacing="none" as="div">`,
    preserving the existing inner layouts unchanged. Each gains the
    Panel shadow and the 4px neutral accent bar while keeping its
    internal `p-4 border-b` header row — a deliberate "minimal
    migration" that keeps the diff scriptable (a Python sweep
    replaced all 7 wrappers atomically).
  - Pattern B (`.card` / `card-header` / `card-body` split):
    **SavedQueries** (full slot migration with empty-state +
    populated-state panels), **HuntResultsTable** (three card
    states: empty, loading, results with slotted header), and
    **HuntQueryBuilder** (simple `.card` → Panel conversion).
    These exercise the compound-slot API and prove that
    Panel.Header / Panel.Body can absorb the `.card-header` /
    `.card-body` patterns without functional regression.

  **PanelPadding gained a `'none'` variant as part of this
  sweep** — Pattern A components needed `<Panel padding="none">`
  because they manage their own internal padding via a nested
  `p-4 border-b` row, and the original `'sm' | 'md' | 'lg'` type
  forced a non-zero padding class. The `'none'` variant is now
  available on both `Panel` itself and `Panel.Body`, unifying the
  type across the two slots.

- **Fleet page sweep (6 files, 14 wrappers)** — migrated every
  fleet page that had an ad-hoc card wrapper:
  - **BandwidthDashboardPage** — 3 wrappers (script-migrated:
    1 inline class swap + 2 div→Panel conversions)
  - **RuleDistributionPage** — 1 inline class swap
  - **ConnectivityPage** — 4 wrappers (1 inline + 3 div→Panel)
  - **OnboardingPage** — 2 full-bleed Panel conversions
  - **DlpDashboardPage** — 2 hand-migrated cards using `info`
    and `advanced` tones for Compliance Coverage + Violation
    Distribution (the first fleet page to use non-`default`
    tones, semantically matching the page's two-zone layout)
  - **ReleasesPage** — 3 `.card` wrappers (Active Rollout, Releases
    Table, Recent Rollouts), all using compound slots with
    `info`/`default`/`default` tones respectively

  Note on the inline class swaps: three wrappers (BandwidthDashboard
  line 115, RuleDistribution line 71, Connectivity line 468) used
  `className` on a non-`<div>` element (Stack/section) and
  couldn't be cleanly converted to `<Panel>` without rewriting the
  element type. For those, the classes were swapped inline to
  `bg-surface-card border-t-4 border-border-subtle shadow-card p-6`
  — producing the same visual result as a Panel but through raw
  Tailwind. These are candidates for proper Panel conversion when
  the surrounding element gets refactored.

  **p-5 → p-6 subtle padding change**: several Bandwidth and
  RuleDistribution wrappers used `p-5` (20px) which doesn't map
  to any Panel padding token. They were migrated to `padding="md"`
  (p-6, 24px) — a 2px per-side increase that's imperceptible
  visually but keeps the token set clean.

  Fleet pages NOT touched in this sweep (no card wrappers to
  migrate): FleetOverviewPage, FleetHealthPage, CapacityForecastPage,
  ConfigManagerPage, FleetUpdatesPage, GlobalSessionSearchPage,
  SensorKeysPage, SensorDetailPage. These rely entirely on @/ui
  widget components (MetricCard, ChartPanel, KpiStrip, DataTable)
  for their card chrome and are already design-system-compliant
  at the widget level. They're the reference for "how a fleet
  page should look" going forward.

The AdminSettings migration was the regression test for Panel's
defaults: since AdminSettings was the canonical source the pattern
was modeled on, the visual result had to be pixel-identical to the
hand-rolled version it replaced. Any discrepancy would have been
a Panel defaults bug. None surfaced — all 14 sections render the
same accent/padding/shadow/spacing as before.

One section on AdminSettingsPage is deliberately NOT migrated: the
dark hero card at line 1962 (`<section className="bg-ac-card-dark
p-8 text-white space-y-6">`), which uses a dark navy background and
white text instead of the standard `bg-surface-card` accent pattern.
This is a themed exception parallel to OverviewPage's Strategic
Insight hero — candidate for a `Panel variant="hero"` if we decide
heros should live inside Panel's vocabulary.

## Tactical variant

**Added in the 7th Panel commit** (after AdminSettings, Hunting, and
Fleet sweeps proved the base Panel API works at scale).

The Live Attack Map on the Threat Overview page used a hand-rolled
`<section className="card scanlines tactical-bg ...">` to layer the
"tactical HUD" aesthetic (subtle dot-grid background + CRT scanline
overlay) on top of standard card chrome. Migrating it required
extending Panel with a new orthogonal axis: **variant**.

```tsx
<Panel tone="info" variant="tactical">
  <Panel.Header className="relative z-10">...</Panel.Header>
  <Panel.Body className="relative z-10">
    <AttackMap />
  </Panel.Body>
</Panel>
```

`variant` is independent of `tone`/`padding`/`spacing` — they all
compose. `tone="info"` still produces the blue accent bar at the top
of the panel, but the bar now sits above a navy gradient + dot grid
+ scanlines layered by the tactical CSS classes. The chrome and the
theme work together rather than fighting each other.

### Variant vocabulary

- `default` — plain card background, no overlays. The shape every
  AdminSettings / Fleet / Hunting Panel uses today.
- `tactical` — adds `scanlines tactical-bg relative overflow-hidden`
  classes on top of the base card. The `relative` is load-bearing
  because the `.scanlines` class places its overlay via a
  `::before` pseudo-element with `position: absolute`, and any
  child overlays (e.g. the diagonal-split decoration on the Live
  Attack Map) need a containing block. `overflow-hidden` clips
  the scanlines to the panel's bounds.
- `hero` — swaps the whole substrate: `bg-ac-navy` with on-dark
  text, no accent bar, `relative overflow-hidden` for child
  decorations. Used for marquee featured content like the
  Strategic Insight card on the Threat Overview page. `tone` is
  ignored when `variant="hero"` — the dark navy background is
  the identity, and there is no second axis of semantic color
  to layer on top. `shadow-card` is preserved so hero panels
  still sit visually in line with the rest of the page.

### Child requirements when using tactical variant

When `variant="tactical"`, child elements that should sit above the
grid/scanline backgrounds need `relative z-10` themselves. The
`Panel.Header` and `Panel.Body` slots accept a `className` override
for this. The Live Attack Map migration applies it explicitly:

```tsx
<Panel.Header className="relative z-10">
<Panel.Body className="relative z-10">
```

A future enhancement could auto-inject `relative z-10` on slots
when the parent variant is `tactical`, but that needs context
plumbing. For now the explicit className is the contract.

### Page-specific decorations

The diagonal-split overlay on the Live Attack Map is NOT part of
the tactical variant — it's a page-specific decoration that lives
as a child element inside the Panel:

```tsx
<Panel variant="tactical">
  <div className="absolute top-0 right-0 w-1/2 h-full bg-white/5 diagonal-split pointer-events-none" />
  <Panel.Header>...
```

The reasoning: not every tactical panel will want a diagonal split,
and not every diagonal split lives on a tactical panel. Keeping the
two concepts separable is the right scope decision for the variant
prop. If a second tactical panel wants the same overlay, it can
duplicate the div; if it shows up three times, then it deserves its
own component.

## Hero variant

**Added in the 8th Panel commit** to finish the OverviewPage migration.

The Strategic Insight card on the Threat Overview page is a marquee
panel — dark navy background, on-dark typography, diagonal-split
decoration that scales on hover. It was the last non-Panel wrapper
on OverviewPage and needed a dedicated variant because it breaks
from the light-on-light card substrate the rest of the design system
uses.

```tsx
<Panel
  variant="hero"
  padding="md"
  spacing="none"
  className="group flex flex-col justify-center min-h-[450px]"
>
  <div className="absolute top-0 right-0 w-32 h-full bg-white/5 diagonal-split transition-transform group-hover:scale-110 duration-500" />
  <div className="relative z-10">
    {/* hero content — label, title, description, threat bar, CTA */}
  </div>
</Panel>
```

### What belongs to Panel vs. the caller

**Panel owns:** the dark navy substrate (`bg-ac-navy`), on-dark text
color (`text-white/90`), the card shadow, and `relative overflow-hidden`
for absolutely-positioned children. No accent bar, no tone.

**Caller owns:** layout-specific classes like `group`, `flex flex-col
justify-center`, and `min-h-[450px]`. Also the hover animation target
(`group-hover:scale-110`) and the diagonal-split decoration itself —
those are per-page flourishes, not Panel vocabulary. Same reasoning
as the tactical variant: keep decorations separable so Panel stays
small.

### Why `tone` is ignored in hero variant

Tone paints an accent bar on top of a light card. A dark navy hero
has no room for a second semantic color axis — the navy *is* the
identity. Trying to layer `tone="info"` on top would put a blue bar
on a nearly-blue surface, and `tone="destructive"` would be visually
louder than the content it's framing. The API accepts the prop (for
type uniformity) but the variant branch skips the accent class list
entirely.

## Migration status

Shipped in order:
1. Base Panel API (tone / padding / spacing / `as` / `noAccent`)
2. Compound slot API (`Panel.Header` + `Panel.Body`) with
   auto-detect and automatic flex-column layout
3. AdminSettings sweep — 14 sections across `AdminSettingsPage.tsx`,
   plus 2 loading panels in `AdminSettingsSkeleton.tsx`
4. Hunting sweep — 10 components in `src/components/hunting/`
5. Fleet sweep — 6 files, 14 wrappers under `src/pages/fleet/`
6. OverviewPage compound slots — Active Campaigns, Top Attackers,
   Top Fingerprints
7. Tactical variant + Live Attack Map migration
8. Hero variant + Strategic Insight migration — **OverviewPage is
   now fully on Panel with zero inline `.card` wrappers remaining**

## Not yet migrated
- 8 fleet pages intentionally skipped because they already use
  `@/ui` widgets (`MetricCard`, `ChartPanel`, `KpiStrip`) directly
  and don't have a card-shaped wrapper to replace. Those pages are
  the reference for "how a fleet page should look" — they do not
  need Panel.

## Next steps

The `.card` CSS family has been fully removed (commit 3ef5a81) and a
CI guard (`lint:css-classes`) prevents reintroduction. MetricCard has
been unified into a single canonical component in `@/ui` (commit
97cf1de). The remaining open threads are tracked in
[docs/development/plans/ui-brand-backlog.md](plans/ui-brand-backlog.md).
