# Edge Protection Design System — Quick Reference

> Single-page cheatsheet. For details see COLOR-REFERENCE.md, TYPOGRAPHY-REFERENCE.md, USAGE-GUIDE.md.

## Colors

### Primary
`#1E90FF` Blue (primary) · `#0A6ED8` Shade · `#7EC8FF` Tint · `#0B4F8A` Navy

### Accent
`#8B5CF6` Violet (accent) · `#C4B5FD` Tint · `#6D28D9` Shade

### Logo Only
`#F97316` Coral (Horizon) · `#A78BFA` Violet Light (Synapse) — **NOT for UI**

### Status
`#EF4444` Red · `#F59E0B` Amber · `#10B981` Green · `#06B6D4` Cyan

### Surfaces (Dark)
`#080e1a` → `#0c1220` → `#101828` → `#131c2e` → `#182440` → `#1e2d44`

### Text (Dark)
`#e8ecf4` Primary · `#8899b0` Secondary · `#5a6f8a` Muted (14px+ only)

## Typography — Recursive Variable Font

### Axes
wght 300–900 · MONO 0–1 · CASL 0–1 · slnt -15–0 · CRSV 0.5 (locked)

### 15 Roles

| Role | Class | wght | MONO | CASL | slnt | Size | Spacing |
|------|-------|------|------|------|------|------|---------|
| Display | `.t-display` | 300 | 0 | 0 | 0 | 36px | — |
| Heading | `.t-heading` | 500 | 0 | 0.2 | 0 | 24px | — |
| Subhead | `.t-subhead` | 600 | 0 | 0.3 | -3 | 14px | 1.5px |
| Body | `.t-body` | 400 | 0 | 0.6 | 0 | 13px | — |
| Label | `.t-label` | 600 | 1 | 0.3 | -4 | 12px | 1px |
| Tag | `.t-tag` | 800 | 0 | 0 | -3 | 11px | 1.5px |
| Metric | `.t-metric` | 400 | 1 | 0.6 | 0 | 32px | -0.5px |
| Metric Unit | `.t-metric-unit` | 500 | 1 | 0 | 0 | 13px | 0.5px |
| Data | `.t-data` | 500 | 1 | 0 | 0 | 13px | — |
| Code | `.t-code` | 400 | 1 | 0 | 0 | 13px | 0.5px |
| Timestamp | `.t-timestamp` | 500 | 1 | 0 | 0 | 11px | 0.5px |
| Nav | `.t-nav` | 500 | 0.5 | 0.2 | -2 | 14px | 1px |
| Nav Active | `.t-nav-active` | 700 | 0.5 | 0.1 | -2 | 14px | 1px |
| Link | `.t-link` | 700 | 0 | 0 | -15 | 10px | 1px |
| Breadcrumb | `.t-breadcrumb` | 700 | 1 | 0.2 | -7 | 10px | 2.5px |

### CASL Rule
- Human text → CASL 0.6 (warm)
- Machine data → CASL 0 (clinical)
- Navigation → CASL 0.2 (hybrid)

### Wordmarks
- **Colored uppercase**: wght 400, letter-spacing 0.2em. Horizon=#F97316, Synapse=#A78BFA
- **Light mixed case**: wght 300, color #e8ecf4 (dark) / #0c1220 (light)

## Rules

1. Font: Recursive only, nothing else
2. Border radius: 0 everywhere, no exceptions
3. Coral (#F97316): logos only, never UI
4. Status colors: functional only, never decorative
5. Muted text (#5a6f8a): 14px+ only
6. Display role: wght 300 (light), never bold
7. Use `font-variation-settings`, not Tailwind font-weight utilities
8. No pure white (#fff) for text — use #e8ecf4

## Product Names
- **Horizon** = edge protection hub (top-level name for both products)
- **Synapse** = API/WAF sensor (runs standalone, "Defense" module within Horizon)
- Taglines: Horizon = "See Further. Act Faster." / Synapse = "On-Board Intelligence"
