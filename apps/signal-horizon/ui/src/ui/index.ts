/**
 * Apparatus Design System Component Library
 * ========================================
 * brand-compliant React component library for Signal Horizon dashboards.
 *
 * Quick Start:
 *   import { MetricCard, KpiStrip, ChartPanel, DataTable, Button } from '@/ui';
 *   import { colors, spacing, chartColors } from '@/ui';
 *
 * Architecture:
 *   tokens/    → Design tokens (colors, typography, spacing)
 *   utils/     → Color manipulation, value formatting
 *   primitives/ → Box, Text, Stack, Grid, Divider (layout atoms)
 *   components/ → MetricCard, KpiStrip, ChartPanel, StatusBadge, etc.
 *   charts/    → Recharts brand defaults (axis, grid, tooltip, gradients)
 *   styles/    → Global CSS (import once at app root)
 */

// ─── Tokens ──────────────────────────────────────────────────────────────────
export {
  colors,
  chartColors,
  semanticChartColors,
  fontFamily,
  typography,
  spacing,
  spacingN,
  shadows,
  transitions,
  borders,
  gradients,
  fv,
} from '@atlascrew/signal-ui';

// ─── Utilities ───────────────────────────────────────────────────────────────
export {
  lighten,
  darken,
  alpha,
  barGradientId,
  barGradientStops,
  formatValue,
  formatPercent,
  formatDuration,
  formatBytes,
  sx,
  clamp,
  applyType,
} from '@atlascrew/signal-ui';

// ─── Primitives ──────────────────────────────────────────────────────────────
export { Box, Text, Stack, Divider, Grid } from '@atlascrew/signal-ui';

// ─── Components ──────────────────────────────────────────────────────────────
export { MetricCard } from './components/MetricCard';
export { KpiStrip } from './components/KpiStrip';
export { ChartPanel } from './components/ChartPanel';
export { StatusBadge } from './components/StatusBadge';
export {
  SectionHeader,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
  TRUNCATED_CARD_HEADER_TITLE_STYLE,
} from './components/SectionHeader';
export { StatCard } from './components/StatCard';
export { Panel } from '@atlascrew/signal-ui';
export type { PanelTone, PanelPadding, PanelSpacing, PanelVariant } from '@atlascrew/signal-ui';
export { DataTable, ValuePill } from './components/DataTable';
export { Button, Alert, Tabs } from '@atlascrew/signal-ui';
export { Modal, Drawer } from './components/Modal';
export { Sidebar, AppShell } from './components/Sidebar';
export { TimeRangeSelector } from './components/TimeRangeSelector';
export { Input, Select, Tooltip, ProgressBar, EmptyState, Spinner, LoadingOverlay } from '@atlascrew/signal-ui';
export { Breadcrumb } from './components/Utilities';

// ─── Chart Defaults ──────────────────────────────────────────────────────────
export {
  axisDefaults,
  xAxisNoLine,
  gridDefaults,
  gridDefaultsSoft,
  tooltipDefaults,
  legendDefaults,
  barDefaults,
  lineDefaults,
  barGradientDefs,
  ChartValueLabel,
  areaFillOpacity,
} from './charts/defaults';
