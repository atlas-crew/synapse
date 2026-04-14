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

## Not yet migrated

- `OverviewPage.tsx`'s **Live Attack Map** section uses `.card scanlines
  tactical-bg` — a themed "tactical HUD" aesthetic with custom visual
  effects (grid overlay, scanlines) that aren't part of Panel's
  vocabulary. Leave as-is until we decide whether to add a
  `variant="tactical"` prop to Panel or keep it as a themed exception.
- `OverviewPage.tsx`'s **Strategic Insight hero card** uses navy
  background with diagonal-split overlays — also a themed exception,
  not a Panel candidate without a hero variant.
- `AdminSettingsSkeleton.tsx` duplicates the AdminSettings pattern
  inline for its loading state. Convert in the same sweep that
  migrates `AdminSettingsPage.tsx` itself.
- `AdminSettingsPage.tsx` — the canonical pattern the Panel was
  modeled on. Migration is mechanical but touches ~8 sections, so
  it needs its own commit.
- Most Hunting pages (`HuntResultsTable`, `SavedQueries`,
  `SigmaLeadsPanel`, `SigmaRulesPanel`, `BehavioralAnomaliesPanel`,
  `ClickHouseOpsPanel`, `RecentRequestsPanel`) — mostly
  header-body splits that can now use the compound slot API. Queue
  up as a focused "Hunting section migration" commit.

## Next steps

With compound slots landed, the remaining Panel feature work is:

1. **Tactical variant**: should Panel gain a `variant="tactical"`
   prop that layers on `scanlines`/`tactical-bg` effects for themed
   pages like the attack map? Or should those stay outside Panel's
   responsibility entirely? Decision needed before the attack map
   migration.
2. **Deprecate `.card`**: once enough pages have migrated to Panel,
   mark `.card` in `src/index.css` as deprecated with a comment and
   a grep-count target. When usage drops below ~5 files, delete the
   CSS class.
3. **Sweep migrations**: run a focused migration commit per page
   cluster (AdminSettings + skeleton, Hunting section, remaining
   fleet pages) rather than a single megadiff. Each commit should
   touch one section of the codebase and be independently reversible.
