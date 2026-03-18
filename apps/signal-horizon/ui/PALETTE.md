# Signal Horizon — Design System Palette

> **Vivid + Slate Command + Arc Violet**
> Six-role semantic color system with outlined method badges.
> Updated March 2026.

---

## Surfaces — Slate Command

Blue-gray tinted surfaces in both modes. Never pure gray, never pure white.

### Dark mode (primary)

| Token              | Hex       | Usage                              |
|--------------------|-----------|-------------------------------------|
| `surface-inset`    | `#080E1A` | Sidebar, recessed areas             |
| `surface-base`     | `#0C1220` | Page background                     |
| `surface-card`     | `#101828` | Cards, table bodies                 |
| `surface-subtle`   | `#131C2E` | Hover states, subtle backgrounds    |
| `surface-overlay`  | `#182440` | Modals, dropdowns                   |
| `border-subtle`    | `#1E2D44` | Card borders, dividers              |
| `border-strong`    | `#2A3F5C` | Emphasized borders, active states   |
| `text-muted`       | `#5A6F8A` | Captions, labels, timestamps        |
| `text-secondary`   | `#8899B0` | Body text, descriptions             |
| `text-primary`     | `#E8ECF4` | Headings, primary content           |

### Light mode

| Token              | Hex       | Usage                              |
|--------------------|-----------|-------------------------------------|
| `surface-card`     | `#FFFFFF` | Cards (elevation via shadow)        |
| `surface-base`     | `#F7F9FC` | Page background                     |
| `surface-subtle`   | `#EEF2F7` | Hover, hero areas                   |
| `surface-inset`    | `#E4EAF2` | Recessed inputs, recessed areas     |
| `border-subtle`    | `#D4DCE8` | Card borders, dividers              |
| `border-strong`    | `#B0BDD0` | Emphasized borders                  |
| `text-muted`       | `#6B7D96` | Captions, labels, timestamps        |
| `text-secondary`   | `#475A72` | Body text, descriptions             |
| `text-primary`     | `#1A2B42` | Headings, primary content           |
| `surface-header`   | `#0B4F8A` | Sidebar (stays dark in light mode)  |

### Shadow tint

All shadows use `rgba(26, 43, 66, ...)` — the slate base color at varying opacity.
Never use `rgba(0,0,0)` for shadows (too harsh) or the old `rgba(0,30,98)` (wrong hue).

---

## Six Semantic Roles

Each role has four stops: **dark**, **shade**, **base**, **tint**.

- **Dark mode** uses `base` for solid fills and `tint` for text/stat values.
- **Light mode** uses `shade` for solid fills and text, `base` for data viz.
- Both modes share the same `base` stop for chart bars and data visualization.

### 1. Primary — Vivid Blue

Interactive elements, links, table headers, POST method.

| Stop  | Hex       | CSS var              |
|-------|-----------|----------------------|
| Dark  | `#0B4F8A` | `--ac-blue-darker`   |
| Shade | `#0A6ED8` | `--ac-blue-dark`     |
| Base  | `#1E90FF` | `--ac-blue`          |
| Tint  | `#7EC8FF` | `--ac-blue-light`    |

Glow: `rgba(30, 144, 255, 0.35)`

### 2. Accent — Arc Violet

CTAs, deploy buttons, focus rings, key metrics, anomaly data.
Replaces the old magenta (`#D62598`) in all CTA/accent contexts.

| Stop  | Hex       | CSS var              |
|-------|-----------|----------------------|
| Dark  | `#4C1D95` | `--ac-magenta-darker`|
| Shade | `#6D28D9` | `--ac-magenta-dark`  |
| Base  | `#8B5CF6` | `--ac-magenta`       |
| Tint  | `#C4B5FD` | `--ac-magenta-light` |

Glow: `rgba(139, 92, 246, 0.3)`

### 3. Danger — Red

Critical severity, blocked status, DELETE method.

| Stop  | Hex       | CSS var          |
|-------|-----------|------------------|
| Dark  | `#991B1B` |                  |
| Shade | `#DC2626` |                  |
| Base  | `#EF4444` | `--ac-red`       |
| Tint  | `#FCA5A5` |                  |

### 4. Warning — Amber

Warning severity, degraded status, PUT method.

| Stop  | Hex       | CSS var          |
|-------|-----------|------------------|
| Dark  | `#92400E` |                  |
| Shade | `#D97706` |                  |
| Base  | `#F59E0B` | `--ac-orange`    |
| Tint  | `#FCD34D` |                  |

### 5. Success — Emerald

Healthy status, connected, GET method.

| Stop  | Hex       | CSS var          |
|-------|-----------|------------------|
| Dark  | `#065F46` |                  |
| Shade | `#059669` |                  |
| Base  | `#10B981` | `--ac-green`     |
| Tint  | `#6EE7B7` |                  |

### 6. Info — Cyan

Informational status, sky indicators, PATCH method.
Shifted from old sky blue (`#529EEC`) to cyan for separation from primary.

| Stop  | Hex       | CSS var          |
|-------|-----------|------------------|
| Dark  | `#155E75` |                  |
| Shade | `#0891B2` |                  |
| Base  | `#06B6D4` | `--ac-sky-blue`  |
| Tint  | `#67E8F9` |                  |

---

## Badge Hierarchy

Two visual tiers. Severity badges are solid (demand attention). Method/info badges are outlined (provide context).

### Severity badges — solid fills

| Badge     | Fill (dark mode) | Fill (light mode) |
|-----------|------------------|-------------------|
| Critical  | `#EF4444`        | `#DC2626`         |
| Warning   | `#F59E0B`        | `#D97706`         |
| OK        | `#10B981`        | `#059669`         |
| Info      | outlined cyan    | outlined cyan     |

### Method badges — outlined

```
background: rgba({color}, 0.10)    /* dark mode */
background: rgba({color}, 0.06)    /* light mode */
border:     1px solid rgba({color}, 0.30)  /* dark */
border:     1px solid rgba({color}, 0.25)  /* light */
color:      {base stop}
```

| Method | Color     | Hex       |
|--------|-----------|-----------|
| GET    | Success   | `#10B981` |
| POST   | Primary   | `#1E90FF` |
| PUT    | Warning   | `#F59E0B` |
| PATCH  | Info      | `#06B6D4` |
| DELETE | Danger    | `#EF4444` |

---

## Risk Mapping

| Level    | Color   | Hex       | Notes                          |
|----------|---------|-----------|--------------------------------|
| Low      | Success | `#10B981` |                                |
| Medium   | Warning | `#F59E0B` |                                |
| High     | Warning | `#F59E0B` | Same as medium (severity tier) |
| Critical | Danger  | `#EF4444` | Red, not violet                |

> **Note:** Critical risk uses danger red, not the accent violet.
> Violet is for CTAs and emphasis — not for "something is on fire."

---

## Atmosphere

The tactical grid and radial gradients use primary blue and accent violet.

### Dark mode atmosphere

```css
background:
  linear-gradient(rgba(30, 144, 255, 0.02) 1px, transparent 1px),      /* grid */
  linear-gradient(90deg, rgba(30, 144, 255, 0.02) 1px, transparent 1px),
  radial-gradient(ellipse at 30% 20%, rgba(30, 144, 255, 0.10) ...),   /* blue focal */
  radial-gradient(ellipse at 70% 80%, rgba(139, 92, 246, 0.07) ...),   /* violet focal */
  linear-gradient(180deg, #131c2e 0%, #0c1220 100%);                    /* base */
```

### Light mode atmosphere

```css
background:
  linear-gradient(rgba(26, 43, 66, 0.02) 1px, transparent 1px),        /* grid */
  linear-gradient(90deg, rgba(26, 43, 66, 0.02) 1px, transparent 1px),
  radial-gradient(ellipse at 0% 0%, rgba(30, 144, 255, 0.05) ...),     /* blue corner */
  radial-gradient(ellipse at 100% 100%, rgba(139, 92, 246, 0.02) ...), /* violet corner */
  linear-gradient(180deg, #F7F9FC 0%, #F7F9FC 100%);                    /* base */
```

### Table headers

Both modes: `linear-gradient(180deg, #0B4F8A 0%, #083D6C 100%)` with white text.

---

## Migration Reference

Colors that were removed or remapped from the old Atlas Crew palette.

| Old                        | New                       | Notes                         |
|----------------------------|---------------------------|-------------------------------|
| `#0057B7` ac-blue          | `#1E90FF` primary         | More vivid, electric          |
| `#001E62` ac-navy          | `#0B4F8A` navy/header     | Lighter, used for headers     |
| `#D62598` ac-magenta       | `#8B5CF6` accent          | Arc Violet for CTAs           |
| `#EF3340` / `#BF3A30` red  | `#EF4444` danger          | Standardized                  |
| `#C24900` ac-orange        | `#F59E0B` warning         | Brighter amber                |
| `#008731` ac-green         | `#10B981` success         | Emerald                       |
| `#529EEC` ac-sky-blue      | `#06B6D4` info            | Shifted to cyan               |
| `#440099` ac-purple        | **Removed**               | Folded into accent violet     |
| `#5E8AB4` ac-cloud-blue    | **Removed**               | Redundant with primary tint   |
| `#3298BC` sky              | `#06B6D4` info            | Remapped                      |
| `rgba(0,30,98)` shadows    | `rgba(26,43,66)` shadows  | Slate tint                    |
| `rgba(0,87,183)` glows     | `rgba(30,144,255)` glows  | Vivid blue                    |
| `rgba(214,37,152)` glows   | `rgba(139,92,246)` glows  | Arc Violet                    |
| Zinc surfaces (`#09090b`)  | Slate surfaces (`#0c1220`)| Blue-tinted dark mode         |

---

## Tailwind Quick Reference

```js
// tailwind.config.js semantic tokens
ctrlx.primary   → '#0B4F8A'  // Navy (headers, hero)
ctrlx.success   → '#10B981'  // Success
ctrlx.warning   → '#F59E0B'  // Warning
ctrlx.danger    → '#EF4444'  // Danger
ctrlx.info      → '#06B6D4'  // Info
```

### Inline TSX cleanup

The CSS variables and Tailwind config are fully migrated. Remaining old-palette
references will be in TSX component files as inline styles or string literals.

**Search patterns for remaining cleanup:**

```bash
# Find inline hex references to old palette
grep -rn '#0057B7\|#D62598\|#001E62\|#BF3A30\|#C24900\|#008731\|#440099\|#529EEC\|#3298BC' \
  src/ --include="*.tsx" --include="*.ts"

# Find inline rgba references to old palette
grep -rn 'rgba(0, 87, 183\|rgba(214, 37, 152\|rgba(0, 30, 98' \
  src/ --include="*.tsx" --include="*.ts"

# Find Tailwind class references to old colors (magenta as CTA is now accent)
grep -rn 'text-ac-magenta\|bg-ac-magenta\|border-ac-magenta' \
  src/ --include="*.tsx" --include="*.ts"
```

**Replacement rules for TSX cleanup:**

- `#D62598` / `ac-magenta` in **CTA/button/focus contexts** → `#8B5CF6` / `ac-magenta` (already remapped)
- `#D62598` / `ac-magenta` in **severity/alert contexts** → `#EF4444` / `ac-red`
- `#0057B7` / `ac-blue` → already remapped via CSS vars
- Any `magenta` string literals in text → check context, likely accent or danger


---

## Logo accent

Logos use **coral (#F97316)** for accent elements, not the UI's arc violet.
Violet disappears into blue backgrounds at small sizes — coral provides the
warm/cool tension needed for the mark to read at 20–80px.

| Element             | Color     | Notes                            |
|---------------------|-----------|----------------------------------|
| Outer rect (dark)   | `#1E90FF` | Vivid blue                       |
| Inner rect (dark)   | `#0A6ED8` | Primary shade                    |
| Outer rect (light)  | `#0A6ED8` | Primary shade                    |
| Inner rect (light)  | `#0B4F8A` | Navy                             |
| Accent arcs/nodes   | `#F97316` | Coral — warm on cool             |
| Sun (signal logo)   | `#F97316` | Matches accent arcs              |
| Structural elements | `#FFFFFF` | White lines, nodes               |

This is intentional brand divergence — the logo accent and the UI accent
serve different roles. The logo needs to pop at favicon size on any background.
The UI accent needs to work in context with six semantic colors on controlled
surfaces. Different constraints, different answers.


---

## Wordmark system

Font: Recursive (variable). All wordmarks use the same font with different
axis settings. Single-word names in heavy proportional, accent-colored.

### Horizon (parent brand)

```
HORIZON   wght 700 · MONO 0 · CASL 0 · slnt 0 · tracking 1px · color #F97316
```

Tagline: "See Further. Act Faster."
```
── SEE FURTHER. ACT FASTER.
   wght 500 · MONO 1 · CASL 0 · slnt 0 · tracking 2.5px · color #5a6f8a
```
Preceded by a 24px horizontal rule (`#2a3f5c`) with 10px gap.
Data mono role — clinical, tracked, uppercase.

### Synapse (standalone peer / Horizon module)

Synapse ships both as a standalone product and as Horizon's threat
intelligence module. Same name, same icon, same wordmark in both contexts.

```
SYNAPSE   wght 700 · MONO 0 · CASL 0 · slnt 0 · tracking 1px · color #8B5CF6
```

Tagline: "On-board intelligence"
```
── ON-BOARD INTELLIGENCE
   wght 500 · MONO 1 · CASL 0 · slnt 0 · tracking 2.5px · color #5a6f8a
```
Preceded by a 24px horizontal rule in dark violet (`#4C1D95` at 0.6 opacity).

### Module labels (inside Horizon nav)

```
wght 600 · MONO 1 · CASL 0.3 · slnt -4 · tracking 2px · uppercase · 11px
```

Label role from the type system. Accent color per module:
- SYNAPSE: `#8B5CF6` (violet) — defense interface
- BRIDGE: `#F97316` (coral) — deployment interface
- BEAM: `#F97316` (coral) — observability interface

Subtitle below each module name:
```
wght 400 · MONO 1 · CASL 0 · slnt 0 · tracking 1px · color #5a6f8a · 9px
```

### Hierarchy

Horizon is the parent brand. It gets heavy proportional coral at full size.
Synapse is a peer when standalone, a module when inside Horizon.
Fleet Command and Beam are always modules — they never appear outside Horizon.

### Navigation structure

| Section | Interface to | What lives here |
|---------|-------------|----------------|
| SYNAPSE | Defense | Actors, campaigns, war rooms, threat hunting, global intel, global search, API intelligence, session/actor/signal tracking |
| BRIDGE | Deployment | Sensor deploy, topology, canary, health, push rules |
| BEAM | Observability | Real-time metrics, traffic, latency, block rates, API catalog, Beam API |

Three domains: defense, deployment, observability. No overlap.
Three icons: circles (Synapse), squares (Bridge), rings (Beam).
Three visual primitives that are distinguishable at 20px by shape alone.
