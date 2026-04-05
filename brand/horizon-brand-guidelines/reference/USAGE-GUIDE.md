# Edge Protection Design System — Usage Guide

> **For AI agents**: Practical rules for applying the Edge Protection design system. When generating UI code, follow these rules exactly. When in doubt, reference COLOR-REFERENCE.md and TYPOGRAPHY-REFERENCE.md for exact values.

---

## Quick Decisions

| Question | Answer |
|----------|--------|
| What font? | Recursive (only Recursive, nothing else) |
| Border radius? | 0 everywhere, no exceptions |
| Primary color? | `#1E90FF` (blue) |
| Accent color? | `#8B5CF6` (violet) |
| Can I use orange? | Only in logo/icon marks, never in UI |
| Body text CASL? | 0.6 (warm) |
| Data text CASL? | 0 (clinical) |
| Wordmark weight? | 700 (Sans Linear Bold) |
| Wordmark CASL? | 0 (always clinical) |
| Muted text min size? | 14px (fails WCAG AA below that) |

---

## Typography — When to Use What

### Human-Facing Text (CASL 0.4–0.6)
- Body copy, descriptions, tooltips → `.t-body` (CASL 0.6)
- Headings → `.t-heading` (CASL 0.2)
- Subheadings → `.t-subhead` (CASL 0.3)
- Metric numbers → `.t-metric` (CASL 0.6 + MONO 1)

### Machine Output (CASL 0)
- Table cells, log entries → `.t-data` (CASL 0, MONO 1)
- Code, config values → `.t-code` (CASL 0, MONO 1)
- Timestamps → `.t-timestamp` (CASL 0, MONO 1)
- Tags/badges → `.t-tag` (CASL 0)

### Navigation (Hybrid)
- Nav items → `.t-nav` (MONO 0.5, CASL 0.2, slnt -2)
- Active nav → `.t-nav-active` (MONO 0.5, wght 700)
- Links → `.t-link` (slnt -15 — full italic for kinetic energy)
- Breadcrumbs → `.t-breadcrumb` (MONO 1, slnt -7, ls 2.5px)

### Wordmarks (CASL 0, always clinical)
- **Lockups, banners, badges** → Sans Linear Bold (wght 700, MONO 0), uppercase, ls 0.2em, product-colored
- **In-app headers, sidebar** → Sans Linear Bold (wght 700, MONO 0), mixed case, white or dark
- **CLI/terminal contexts** → Mono Linear Medium (wght 500, MONO 1), uppercase

---

## Color — When to Use What

### Blue (#1E90FF)
✓ Links, buttons, active indicators, primary CTAs, chart series 1, borders on focus
✗ Never as a background fill for large areas

### Violet (#8B5CF6)
✓ Focus rings, anomaly accents, Synapse-specific elements, chart series 2, small badges
✗ Never as a background. Never for small body text (fails AA). Never dominant.

### Coral (#F97316)
✓ Horizon icon arcs, logo warm accents, Horizon wordmark color
✗ Never as UI buttons, links, backgrounds, text, or any interactive element

### Status Colors
✓ `#EF4444` = error/critical, `#F59E0B` = warning, `#10B981` = success, `#06B6D4` = info
✗ Never decorative. Red always means error. Green always means success.

### Surfaces (Dark Mode)
Use the slate scale for layered depth:
- `#080e1a` — deepest inset
- `#0c1220` — default page background
- `#101828` — cards
- `#131c2e` — hover/active rows
- `#182440` — dropdowns, modals
- `#1e2d44` — borders

---

## Do / Don't

| ✓ DO | ✗ DON'T |
|------|---------|
| Use Recursive for everything | Mix Inter, Rubik, or system fonts |
| Sharp corners on all UI elements | Use rounded corners or pill shapes |
| CASL 0.6 for body text | Use CASL 0 for human-facing copy |
| CASL 0 for data/machine output | Use CASL 0.6 for table cells or IPs |
| CASL 0 for wordmarks | Use casual (CASL > 0) in brand marks |
| wght 700 Sans Linear Bold for wordmarks | Use thin (300) or regular (400) for brand marks |
| wght 300 for display/hero text | Bold the display role |
| Coral for logos only | Use coral as a UI accent |
| Status colors for alerts/data only | Use red/green decoratively |
| `font-variation-settings` for all type | Tailwind `font-bold` / `font-light` |
| Muted text (`#5a6f8a`) at 14px+ | Muted text at small sizes |
| `#e8ecf4` for text on dark | Pure white `#ffffff` for text |

---

## Component Patterns

### Stat Card
```html
<div class="stat-card">
  <span class="t-metric">4,412</span>
  <span class="t-metric-unit">req/s</span>
  <span class="t-label">THROUGHPUT</span>
</div>
```

### Table
```html
<th class="t-label">SOURCE</th>      <!-- wght 600, MONO 1, CASL 0.3 -->
<td class="t-data">192.168.1.42</td>  <!-- wght 500, MONO 1, CASL 0 -->
```

### Navigation
```html
<a class="t-nav-active" style="color: var(--ac-blue);">Overview</a>  <!-- Active -->
<a class="t-nav" style="color: var(--text-secondary);">Traffic</a>   <!-- Inactive -->
```

### Alert
```html
<div style="border-left: 3px solid var(--ac-red); padding: 8px; background: rgba(239,68,68,0.08);">
  <span class="t-tag" style="color: var(--ac-red);">CRITICAL</span>
  <span class="t-body">SQLi attempt blocked on /api/v2/users</span>
</div>
```

### Wordmark (Primary Lockup)
```html
<span style="font-variation-settings: 'wght' 700, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;
             letter-spacing: 0.2em; text-transform: uppercase; color: #F97316;">
  HORIZON
</span>
```

### Wordmark (In-App Header)
```html
<span style="font-variation-settings: 'wght' 700, 'MONO' 0, 'CASL' 0, 'CRSV' 0.5, 'slnt' 0;
             color: var(--text-primary);">
  Horizon
</span>
```

---

## Icon System

- Corner brackets at sizes ≥28px (`#5a6f8a`, 30% opacity, 1.5px stroke)
- Below 28px: brackets dropped, mark stands alone
- Stroke-based geometry — no fills except accent nodes
- Blue for structure, coral for Horizon accents, violet for Synapse accents
- Dark variant: `#0c1220` background rect
- Light variant: transparent background

## CSS Variables Quick Reference

```css
/* Surfaces */
var(--surface-base)     /* #0c1220 (dark) / #F7F9FC (light) */
var(--surface-card)     /* #101828 (dark) / #FFFFFF (light) */
var(--border-subtle)    /* #1e2d44 (dark) / #D4DCE8 (light) */

/* Text */
var(--text-primary)     /* #e8ecf4 (dark) / #1A2B42 (light) */
var(--text-secondary)   /* #8899b0 (dark) / #475A72 (light) */
var(--text-muted)       /* #5a6f8a (dark) / #6B7D96 (light) */

/* Colors */
var(--ac-blue)          /* #1E90FF */
var(--ac-purple)        /* #8B5CF6 */
var(--ac-red)           /* #EF4444 */
var(--ac-green)         /* #10B981 */
var(--ac-orange)        /* #F59E0B */

/* Interactive */
var(--link)             /* #1E90FF (dark) / #0A6ED8 (light) */
var(--focus-ring)       /* #8B5CF6 */
var(--accent)           /* #8B5CF6 */
```
