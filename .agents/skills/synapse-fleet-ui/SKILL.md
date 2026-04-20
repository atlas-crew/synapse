---
name: synapse-fleet-ui
description: Enforce strict Synapse Fleet UI brand rules, component library usage, and accessibility standards for the fleet intelligence dashboard (formerly Signal Horizon). Use when creating or modifying any React components, pages, or layouts in the apps/signal-horizon/ui directory.
---

# Synapse Fleet UI Strategy

This skill ensures all UI work in the `apps/signal-horizon/ui` project (the Synapse Fleet dashboard, directory name retained per phased rename) adheres to the mandatory Apparatus Design System.

## Mandatory Rules (Non-Negotiable)

- **Import from `@/ui`**: Always import design tokens, primitives, and components from the `@/ui` barrel export. Never use relative imports to `tokens/` or `components/`.
- **Border Radius**: ALWAYS 0. `borderRadius: 0` is global. Never use rounded corners.
- **Typography**: Use "Rubik" font only. Headings use weight 300 (light). Body uses weight 400 (regular).
- **Colors**: Use the `colors` token. Primary: blue (#0057B7), navy (#001E62), magenta (#D62598).
- **Spacing**: Use `spacing` tokens (xs/sm/md/lg/xl/xxl). Never hardcode pixel values.
- **Accessibility**: Follow WCAG 2.2 AA. Use semantic HTML and ensure keyboard/screen reader operability.

## Bundled Utilities

- **`scripts/audit_components.cjs`**: Scans React source code for UI standard violations (relative token imports, hardcoded hex colors, non-zero border radius).
  - Usage: `node scripts/audit_components.cjs <dir_or_file>`

## Component Library

Before creating a new UI element, check the [Component Catalog](references/components.md). If it exists in `@/ui`, you MUST use it.

### Correct Import Pattern

```tsx
// ✅ CORRECT
import { MetricCard, KpiStrip, Button, Stack, Box, Text, colors, spacing } from '@/ui';

// ❌ WRONG
import { colors } from '../tokens';
const blue = '#0057B7';
<div style={{ padding: '16px', borderRadius: '8px' }}>
```

## Workflow

1. **Research**: Check `apps/signal-horizon/ui/src/ui/index.ts` for the latest exported components.
2. **Strategy**: Plan the layout using `Stack`, `Box`, and `Grid` primitives.
3. **Implementation**: Build the feature using library components.
4. **Audit**: Run `node scripts/audit_components.cjs src/` to check for violations.
5. **Validation**: Run `pnpm exec nx run signal-horizon-ui:lint` and `type-check`.

## Resources

- [Component Catalog](references/components.md): List of available components and usage.
- [Design Tokens](references/tokens.md): Detailed color, spacing, and typography reference.
- [Accessibility Guide](references/accessibility.md): Project-specific accessibility requirements.
