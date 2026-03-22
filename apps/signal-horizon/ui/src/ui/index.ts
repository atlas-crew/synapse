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
} from './tokens/tokens';

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
} from './utils/helpers';

// ─── Primitives ──────────────────────────────────────────────────────────────
export { Box } from './primitives/Box';
export { Text } from './primitives/Text';
export { Stack } from './primitives/Stack';
export { Divider, Grid } from './primitives/Layout';

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
export { DataTable, ValuePill } from './components/DataTable';
export { Button } from './components/Button';
export { Alert } from './components/Alert';
export { Tabs } from './components/Tabs';
export { Modal, Drawer } from './components/Modal';
export { Sidebar, AppShell } from './components/Sidebar';
export { TimeRangeSelector } from './components/TimeRangeSelector';
export { Input, Select } from './components/FormControls';
export { Tooltip, ProgressBar, EmptyState, Spinner, LoadingOverlay, Breadcrumb } from './components/Utilities';

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
