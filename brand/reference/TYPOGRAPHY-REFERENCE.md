# Edge Protection Design System — Typography Reference

> **For AI agents**: This document contains exact `font-variation-settings` values for all 15 type roles. Use these values directly in inline styles or CSS. The font is **Recursive** (Google Fonts variable font). One font, 15 roles — no other fonts should be used.

## Font Import

```
https://fonts.googleapis.com/css2?family=Recursive:slnt,wght,CASL,CRSV,MONO@-15..0,300..900,0..1,0..1,0..1&display=swap
```

## Font Stack

```css
font-family: 'Recursive', ui-monospace, -apple-system, BlinkMacSystemFont, sans-serif;
```

CSS variable: `var(--font-stack)`

---

## Variable Axes

| Axis | Range | Purpose |
|------|-------|---------|
| `wght` | 300–900 | Weight (light to black) |
| `MONO` | 0–1 | Proportional (0) → Monospace (1) |
| `CASL` | 0–1 | Linear/clinical (0) → Casual/warm (1) |
| `slnt` | -15–0 | Upright (0) → Full italic (-15) |
| `CRSV` | 0.5 | **Locked** — not a design variable |

## The CASL Rule

CASL encodes the brand voice into the font itself:
- **CASL 0.6** = human-facing text (body, descriptions, tooltips) — warm, approachable
- **CASL 0.2–0.3** = headings, labels — slightly warm
- **CASL 0** = machine output (data, code, timestamps, tables) — cold, clinical

If text is for humans to read → increase CASL. If it's machine output → CASL 0.

---

## 15 Type Roles

### Display
- **Class**: `.t-display`
- **Use**: Page titles, hero text
- **Settings**: `font-variation-settings: 'wght' 300, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 36px
- **Note**: Lightest weight for biggest text — confidence, not volume

### Heading
- **Class**: `.t-heading`
- **Use**: Section headers, card titles
- **Settings**: `font-variation-settings: 'wght' 500, 'MONO' 0, 'CASL' 0.2, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 24px

### Subhead
- **Class**: `.t-subhead`
- **Use**: Card subtitles, secondary headers, eyebrows
- **Settings**: `font-variation-settings: 'wght' 600, 'MONO' 0, 'CASL' 0.3, 'CRSV' 0.5, 'slnt' -3;`
- **Size**: 14px · `letter-spacing: 1.5px`

### Body
- **Class**: `.t-body`
- **Use**: Descriptions, tooltips, longer prose
- **Settings**: `font-variation-settings: 'wght' 400, 'MONO' 0, 'CASL' 0.6, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 13px
- **Note**: Highest CASL value — warmest role

### Label
- **Class**: `.t-label`
- **Use**: Sidebar group titles, section labels
- **Settings**: `font-variation-settings: 'wght' 600, 'MONO' 1, 'CASL' 0.3, 'CRSV' 0.5, 'slnt' -4;`
- **Size**: 12px · `letter-spacing: 1px`

### Tag
- **Class**: `.t-tag`
- **Use**: Status badges, severity chips
- **Settings**: `font-variation-settings: 'wght' 800, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' -3;`
- **Size**: 11px · `letter-spacing: 1.5px`

### Metric
- **Class**: `.t-metric`
- **Use**: Big KPI numbers, dashboard values
- **Settings**: `font-variation-settings: 'wght' 400, 'MONO' 1, 'CASL' 0.6, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 32px · `letter-spacing: -0.5px`
- **Note**: MONO 1 for alignment + CASL 0.6 for warmth

### Metric Unit
- **Class**: `.t-metric-unit`
- **Use**: Units next to metrics (req/s, ms, etc.)
- **Settings**: `font-variation-settings: 'wght' 500, 'MONO' 1, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 13px · `letter-spacing: 0.5px`

### Data
- **Class**: `.t-data`
- **Use**: Table cells, log entries, IP addresses
- **Settings**: `font-variation-settings: 'wght' 500, 'MONO' 1, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 13px

### Code
- **Class**: `.t-code`
- **Use**: Inline code, config values, identifiers
- **Settings**: `font-variation-settings: 'wght' 400, 'MONO' 1, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 13px · `letter-spacing: 0.5px`

### Timestamp
- **Class**: `.t-timestamp`
- **Use**: Log times, event dates
- **Settings**: `font-variation-settings: 'wght' 500, 'MONO' 1, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;`
- **Size**: 11px · `letter-spacing: 0.5px`

### Nav
- **Class**: `.t-nav`
- **Use**: Sidebar navigation items (inactive)
- **Settings**: `font-variation-settings: 'wght' 500, 'MONO' 0.5, 'CASL' 0.2, 'CRSV' 0.5, 'slnt' -2;`
- **Size**: 14px · `letter-spacing: 1px`
- **Note**: MONO 0.5 creates a hybrid prose/data texture

### Nav Active
- **Class**: `.t-nav-active`
- **Use**: Active sidebar item
- **Settings**: `font-variation-settings: 'wght' 700, 'MONO' 0.5, 'CASL' 0.1, 'CRSV' 0.5, 'slnt' -2;`
- **Size**: 14px · `letter-spacing: 1px`

### Link
- **Class**: `.t-link`
- **Use**: Clickable text actions, "View All →" CTAs
- **Settings**: `font-variation-settings: 'wght' 700, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' -15;`
- **Size**: 10px · `letter-spacing: 1px`
- **Note**: Full italic slant (-15) — most kinetic role

### Breadcrumb
- **Class**: `.t-breadcrumb`
- **Use**: Path navigation
- **Settings**: `font-variation-settings: 'wght' 700, 'MONO' 1, 'CASL' 0.2, 'CRSV' 0.5, 'slnt' -7;`
- **Size**: 10px · `letter-spacing: 2.5px`

---

## Wordmark Styles

### Colored Uppercase (lockups, banners)
```css
font-variation-settings: 'wght' 400, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;
letter-spacing: 0.2em;
text-transform: uppercase;
/* Horizon: color #F97316; Synapse: color #A78BFA; */
```

### Light Mixed Case (alternative, UI headers)
```css
font-variation-settings: 'wght' 300, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;
/* color: #e8ecf4 (dark) or #0c1220 (light) */
```

## Rules

1. **One font only.** Recursive does everything — no Inter, Rubik, system fonts.
2. **Don't use Tailwind `font-bold`/`font-light`.** These don't set CASL/MONO/slnt axes.
3. **CASL 0 for machine data.** Tables, logs, IPs, timestamps — always clinical.
4. **CASL 0.6 for human text.** Body copy, descriptions, help text — always warm.
5. **wght 300 for display.** Lightest weight at biggest size. Don't bold headlines.
6. **Border radius: 0 everywhere.** No exceptions. Sharp corners on everything.
