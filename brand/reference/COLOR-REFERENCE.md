# Edge Protection Design System — Color Reference

> **For AI agents**: This document contains exact hex values, CSS variable names, Tailwind classes, and usage rules for the Edge Protection color system. Use these values directly — do not infer or approximate colors.

## Source of Truth
- CSS: `apps/signal-horizon/ui/src/index.css`
- Tailwind: `apps/signal-horizon/ui/tailwind.config.js`
- Border radius: **0 everywhere** (Tailwind override)

---

## Primary — Vivid Blue

| Token | Hex | CSS Variable | Tailwind | Role |
|-------|-----|-------------|----------|------|
| Blue | `#1E90FF` | `--ac-blue` | `text-ac-blue` | Primary UI, links, CTAs, chart series 1 |
| Blue Shade | `#0A6ED8` | `--ac-blue-shade` | `text-ac-blue-shade` | Hover, pressed states |
| Blue Tint | `#7EC8FF` | `--ac-blue-tint` | `text-ac-blue-tint` | Dark mode hover, link hover |
| Navy | `#0B4F8A` | `--ac-navy` | `text-ac-navy` | Headers, hero backgrounds |
| Navy Shade | `#083D6C` | `--ac-navy-shade` | — | Deep hero backgrounds |

## Accent — Arc Violet

| Token | Hex | CSS Variable | Tailwind | Role |
|-------|-----|-------------|----------|------|
| Violet | `#8B5CF6` | `--ac-purple` | `text-ac-purple` | Focus rings, anomaly accents, Synapse identity, chart series 2 |
| Violet Tint | `#C4B5FD` | `--ac-magenta-tint` | `text-ac-magenta-tint` | Dark mode hover |
| Violet Shade | `#6D28D9` | `--ac-magenta-shade` | `text-ac-magenta-shade` | Hover, pressed |
| Violet Dark | `#4C1D95` | `--ac-magenta-darker` | — | Deep backgrounds |

## Brand — Logo Only (NOT for UI)

| Token | Hex | Role |
|-------|-----|------|
| Coral | `#F97316` | Horizon icon arcs, logo warm accent. **Never use as UI color.** |
| Coral Light | `#FB923C` | Logo hover states |
| Violet Light | `#A78BFA` | Synapse colored wordmark |

## Status — Functional Only

| Token | Hex | CSS Variable | Tailwind | Role |
|-------|-----|-------------|----------|------|
| Red | `#EF4444` | `--ac-red` | `text-ac-red` | Error, critical, danger |
| Amber | `#F59E0B` | `--ac-orange` | `text-ac-orange` | Warning, high risk |
| Green | `#10B981` | `--ac-green` | `text-ac-green` | Success, healthy, low risk |
| Cyan | `#06B6D4` | `--ac-sky-blue` | `text-ac-sky-blue` | Info, secondary data viz |

## Surface Scale — Dark Mode

| Step | Hex | CSS Variable | Role |
|------|-----|-------------|------|
| Darkest | `#080e1a` | `--ac-navy-darkest` | Page background (inset) |
| Base | `#0c1220` | `--surface-base` | Default page background |
| Card | `#101828` | `--surface-card` | Elevated cards |
| Subtle | `#131c2e` | `--surface-subtle` | Hover rows, active states |
| Overlay | `#182440` | `--surface-overlay` | Dropdowns, modals |
| Border | `#1e2d44` | `--border-subtle` | Dividers, card edges |
| Border Strong | `#2a3f5c` | `--border-strong` | Emphasized borders |

## Surface Scale — Light Mode

| Token | Hex | CSS Variable | Role |
|-------|-----|-------------|------|
| Base | `#F7F9FC` | `--surface-base` | Page background |
| Elevated | `#FFFFFF` | `--surface-elevated` | Cards |
| Subtle | `#EEF2F7` | `--surface-subtle` | Hover, secondary areas |
| Muted | `#E4EAF2` | `--surface-muted` | Inset panels |

## Text — Dark Mode

| Token | Hex | CSS Variable | Tailwind | Constraint |
|-------|-----|-------------|----------|------------|
| Primary | `#e8ecf4` | `--text-primary` | `text-ink-primary` | All sizes |
| Secondary | `#8899b0` | `--text-secondary` | `text-ink-secondary` | All sizes |
| Muted | `#5a6f8a` | `--text-muted` | `text-ink-muted` | **14px+ only** (fails AA Normal) |

## Text — Light Mode

| Token | Hex | CSS Variable | Role |
|-------|-----|-------------|------|
| Primary | `#1A2B42` | `--text-primary` | Headlines, body |
| Secondary | `#475A72` | `--text-secondary` | Descriptions |
| Muted | `#6B7D96` | `--text-muted` | Captions |

## Usage Proportions

- Surface: 35% — Let the dark slate breathe
- Blue: 25% — Primary interactive color
- Text: 20% — Content layer
- Violet: 10% — Accent, not dominant
- Coral: 5% — Logo marks only
- Status: 5% — Functional indicators only

## WCAG 2.1 AA Contrast

| Pair | Ratio | AA Normal | AA Large |
|------|-------|-----------|----------|
| `#e8ecf4` on `#0c1220` | 14.2:1 | ✓ | ✓ |
| `#8899b0` on `#0c1220` | 5.6:1 | ✓ | ✓ |
| `#5a6f8a` on `#0c1220` | 3.2:1 | ✗ | ✓ |
| `#1E90FF` on `#0c1220` | 4.8:1 | ✓ | ✓ |
| `#8B5CF6` on `#0c1220` | 3.8:1 | ✗ | ✓ |

## Rules

1. **Coral is for logos, not UI.** Never use `#F97316` as a button, link, or background color.
2. **Status colors are functional.** Red means error. Green means success. Always.
3. **Muted text at 14px+ only.** `#5a6f8a` fails WCAG AA at normal text sizes.
4. **Violet fails AA Normal.** Use at large sizes or as non-text accents only.
5. **No pure white (#fff) for text.** Use `#e8ecf4` instead.
