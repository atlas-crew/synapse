# Design Tokens

Standard design tokens for the Apparatus Design System. Import from `@/ui`.

## Typography

- **Font Family**: "Rubik", sans-serif.
- **Headings**: weight 300 (Light).
- **Body**: weight 400 (Regular).
- **Numbers**: weight 500 (Medium).

## Colors

| Token | Hex | Role |
|-------|-----|------|
| `colors.blue` | #0057B7 | Primary Brand Color |
| `colors.navy` | #001E62 | Deep Background / Text |
| `colors.magenta` | #D62598 | Accent / Secondary |
| `colors.red` | #C53030 | Error / Critical |
| `colors.green` | #38A169 | Success / Active |
| `colors.orange` | #DD6B20 | Warning / Warning |

## Spacing

Scale for padding and margins.

| Token | Pixels |
|-------|--------|
| `spacing.xs` | 4px |
| `spacing.sm` | 8px |
| `spacing.md` | 16px |
| `spacing.lg` | 24px |
| `spacing.xl` | 32px |
| `spacing.xxl` | 48px |

## Borders & Shadows

- **Radius**: ALWAYS 0. No exceptions.
- **Shadow**: `shadows.subtle`, `shadows.card`, `shadows.modal`.

## Charts

Use `chartColors` array (e.g., `chartColors[0]`, `chartColors[1]`).

Standard Chart Gradients:
- `barGradientId(color)`
- `barGradientStops(color)`
- `<defs>{barGradientDefs()}</defs>`
