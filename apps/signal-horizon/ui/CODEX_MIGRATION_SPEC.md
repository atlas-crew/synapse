# Signal Horizon → @/ui Component Library Migration

## Objective

Migrate all pages and shared components in `/src/pages/` and `/src/components/` to import design tokens, primitives, and components from the `@/ui` component library at `/src/ui/`. The goal is to eliminate hardcoded colors, local `COLORS` constants, and inconsistent inline styles in favor of the centralized token system.

---

## What Already Works

- `@/ui` alias → resolves to `./src/ui/` (configured in both `tsconfig.json` and `vite.config.ts`)
- `@/ui/styles/global.css` → already imported in `main.tsx`
- `OverviewPage.tsx` → already migrated (reference implementation)
- All 26 library components are built and exported from `@/ui`
- Legacy `src/lib/chartTheme.ts` is removed; use `@/ui` chart defaults + helpers instead (`axisDefaults`, `gridDefaults*`, `tooltipDefaults`, `legendDefaults`, `formatValue`, `alpha`, `lighten`, `darken`)

---

## Architecture: What's in @/ui

```
src/ui/
├── tokens/tokens.ts     # colors, spacing, typography, shadows, transitions, borders
├── utils/helpers.ts      # lighten(), darken(), alpha(), formatValue(), formatPercent()
├── primitives/           # Box, Text, Stack, Grid, Divider
├── components/           # MetricCard, KpiStrip, ChartPanel, StatusBadge, SectionHeader,
│                         # DataTable, Button, Alert, Tabs, Modal, Drawer, Sidebar,
│                         # AppShell, TimeRangeSelector, Input, Select, Tooltip,
│                         # ProgressBar, EmptyState, Spinner, LoadingOverlay, Breadcrumb
├── charts/defaults.tsx   # Recharts axis, grid, tooltip, legend, bar, line defaults
├── styles/global.css     # Font import, brand reset, keyframes, utility classes
└── index.ts              # Barrel export — everything available via `import { X } from '@/ui'`
```

---

## Migration Rules

### 1. Replace Hardcoded Colors with Tokens

Every file that contains hardcoded hex colors should import from `@/ui` instead.

**Color mapping:**

```typescript
// BEFORE (hardcoded)                    → AFTER (token)
'#0057B7'                                → colors.blue
'#001E62'                                → colors.navy
'#D62598'                                → colors.magenta
'#529EEC'                                → colors.skyBlue
'#00B140'                                → colors.green
'#EF3340'                                → colors.red
'#E35205'                                → colors.orange
'#440099'                                → colors.purple
'#5E8AB4'                                → colors.cloudBlue
'#F0F4F8'                                → colors.gray.light
'#DFE8F0'                                → colors.gray.medium
'#404040'                                → colors.gray.dark
'#7F7F7F'                                → colors.gray.mid
'#0A1A3A'                                → colors.card.dark
'#000A1A'                                → colors.bg.dark
'#7CBAFF'                                → colors.tint.blueLight
'#004189'                                → colors.tint.blueDark
'#00174A'                                → colors.tint.blueDarker
'#BEDDFF'                                → colors.tint.skyLight
'#3D77B1'                                → colors.tint.skyDark
'#E979C2'                                → colors.tint.magentaLight
'#A01B72'                                → colors.tint.magentaDark
'#003EC8'                                → colors.tint.navyMedium
```

**Pattern — local COLORS objects:**

Many pages define local constants like:

```typescript
// BEFORE
const COLORS = {
  ingress: '#0057B7',
  egress: '#00B140',
  primary: '#0057B7',
  secondary: '#529EEC',
  accent: '#EF3340',
};
```

Replace with:

```typescript
// AFTER
import { colors } from '@/ui';

const COLORS = {
  ingress: colors.blue,
  egress: colors.green,
  primary: colors.blue,
  secondary: colors.skyBlue,
  accent: colors.red,
};
```

If the local COLORS object maps 1:1 to tokens, eliminate it entirely. If it adds semantic meaning (like `ingress`/`egress`), keep the object but replace the hex values with token references.

### 2. Replace Hardcoded Font References

```typescript
// BEFORE
fontFamily: "'Rubik', sans-serif"
fontWeight: 300
fontSize: '12px'

// AFTER
import { fontFamily, fontWeight, typography } from '@/ui';
fontFamily            // → "'Rubik', 'Calibri', -apple-system, BlinkMacSystemFont, sans-serif"
fontWeight.light      // → 300
typography.caption    // → { fontSize: '0.75rem', lineHeight: '16px', fontWeight: 400 }
```

### 3. Replace Hardcoded Spacing

```typescript
// BEFORE
padding: '16px'
gap: '8px'
margin: '24px'

// AFTER
import { spacing } from '@/ui';
padding: spacing.md   // → '16px'
gap: spacing.sm        // → '8px'
margin: spacing.lg     // → '24px'
```

Mapping: `4px` → `xs`, `8px` → `sm`, `16px` → `md`, `24px` → `lg`, `32px` → `xl`, `48px` → `2xl`, `64px` → `3xl`.

### 4. Replace Chart Hardcoded Styles with Chart Defaults

Files using Recharts should import chart defaults:

```typescript
// BEFORE
<XAxis tick={{ fontSize: 12, fill: '#7F7F7F' }} />
<CartesianGrid strokeDasharray="3 3" stroke="rgba(0,30,98,0.3)" />

// AFTER
import { axisDefaults, gridDefaults } from '@/ui';
<XAxis {...axisDefaults} />
<CartesianGrid {...gridDefaults} />
```

Available chart defaults: `axisDefaults`, `gridDefaults`, `tooltipDefaults`, `legendDefaults`, `barDefaults`, `lineDefaults`, `barGradientDefs`, `ChartValueLabel`, `areaFillOpacity`.

### 5. Replace Shadow Strings

```typescript
// BEFORE
boxShadow: '0 2px 8px rgba(0,0,0,0.3)'

// AFTER
import { shadows } from '@/ui';
boxShadow: shadows.card.dark
```

### 6. Replace Transition Strings

```typescript
// BEFORE
transition: 'all 0.15s ease'

// AFTER
import { transitions } from '@/ui';
transition: `all ${transitions.fast}`
```

---

## DO NOT Replace (Critical Exceptions)

### Domain-Specific Components

The following components in `/src/components/` have **different APIs** than their `@/ui` counterparts and must **NOT** be replaced:

| Component | Location | Reason |
|-----------|----------|--------|
| `MetricCard` | `components/fleet/MetricCard.tsx` | Has `variant` prop (fleet/ctrlx), `accent` system, trend with direction — different interface than `@/ui` MetricCard |
| `SensorStatusBadge` | `components/fleet/SensorStatusBadge.tsx` | Domain-specific sensor status logic |
| All `components/fleet/*` | barrel export via `index.ts` | Fleet domain components — keep as-is |
| All `components/soc/*` | SOC domain | Domain-specific threat/campaign components |
| All `components/beam/*` | Beam domain | API analytics domain components |
| All `components/hunting/*` | Hunting domain | Threat hunting domain components |

**Rule:** If a page imports `MetricCard` from `../../components/fleet`, leave that import alone. Only replace when a page is defining its own ad-hoc metric card with inline styles.

### Tailwind Classes

Some pages use Tailwind utility classes (`className="text-3xl font-light"`). These are fine — do NOT convert Tailwind to inline style tokens unless the Tailwind classes reference colors that should come from tokens. Specifically:

- **Leave alone:** `className="space-y-6 p-6 grid grid-cols-4"` (layout utilities)
- **Replace colors:** `className="text-ac-green border-l-ac-blue"` — check if these map to Tailwind config or are custom; if custom, they should reference the same hex values as the tokens

### Recharts Color Arrays as RGB Tuples

Some chart components (e.g., `GeoTrafficMap.tsx`) use RGB arrays for WebGL/canvas rendering:

```typescript
.range([
  [82, 158, 236],   // Sky Blue
  [0, 87, 183],     // Atlas Crew Blue
])
```

Leave these as-is. The token system uses hex strings, not RGB tuples.

---

## Migration Phases

### Phase 1: High-Impact Pages (start here)

These pages are most likely to be shown to leadership and should be migrated first:

1. `pages/fleet/FleetOverviewPage.tsx`
2. `pages/fleet/FleetHealthPage.tsx`
3. `pages/fleet/SensorDetailPage.tsx`
4. `pages/beam/BeamDashboardPage.tsx`
5. `pages/ApiIntelligencePage.tsx`
6. `pages/IntelPage.tsx`
7. `pages/HuntingPage.tsx`

### Phase 2: Fleet Pages

All remaining `pages/fleet/*.tsx` files.

### Phase 3: SOC & Beam Pages

All `pages/soc/*.tsx` and `pages/beam/**/*.tsx` files.

### Phase 4: Shared Components

Components in `/src/components/` that define their own colors/styles but are NOT domain-specific (things like chart wrappers, layout shells, utility components).

---

## Import Pattern

Always import from the barrel export:

```typescript
// ✅ CORRECT — single import from barrel
import { colors, spacing, fontFamily, MetricCard, KpiStrip, SectionHeader, Button } from '@/ui';

// ❌ WRONG — deep imports
import { colors } from '@/ui/tokens/tokens';
import { MetricCard } from '@/ui/components/MetricCard';
```

---

## Reference Implementation

See `pages/OverviewPage.tsx` for how a migrated page should look. Key patterns:

```typescript
// Imports at top of file
import {
  SectionHeader,
  KpiStrip,
  Button,
  colors,
} from '@/ui';

// Usage in JSX
<SectionHeader title="Active Campaigns" subtitle="Last 24 hours" />
<KpiStrip metrics={[
  { label: 'RPS', value: formatValue(stats.totalRps) },
  { label: 'Blocked', value: stats.blockedCount, borderColor: colors.red },
]} />
```

---

## Validation Checklist (per file)

- [ ] No hardcoded hex colors that exist in the token map
- [ ] No local `COLORS = { ... }` with hex values (either eliminated or replaced with token refs)
- [ ] No hardcoded `fontFamily` strings
- [ ] No hardcoded spacing values where tokens exist
- [ ] Chart components use `axisDefaults`, `gridDefaults`, `tooltipDefaults` where applicable
- [ ] Imports use barrel `@/ui`, not deep paths
- [ ] Existing functionality is preserved — this is a visual consistency migration, not a refactor
- [ ] TypeScript compiles cleanly (`npx tsc --noEmit`)
- [ ] No domain component imports were accidentally replaced

---

## Files Summary

| Category | Count | Action |
|----------|-------|--------|
| Pages | 50 | Migrate hardcoded values to tokens |
| Shared Components | ~94 | Migrate where appropriate, skip domain components |
| Domain Components (fleet, soc, beam, hunting) | ~60 | Internal hex values → tokens, but keep component APIs |
| @/ui library | 26 | Do NOT modify |

---

## Running Validation

```bash
# Type check
cd /path/to/signal-horizon/ui && npx tsc --noEmit

# Search for remaining hardcoded colors (should return 0 for pages/)
grep -rn '#0057B7\|#001E62\|#D62598\|#529EEC\|#00B140\|#EF3340\|#0A1A3A\|#000A1A' src/pages/

# Verify no deep @/ui imports
grep -rn "from '@/ui/" src/pages/ src/components/
```
