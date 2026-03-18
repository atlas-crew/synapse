/**
 * Signal Horizon Design Tokens
 * ====================================
 * Single source of truth for all visual decisions.
 * Updated March 2026.
 */

// ─── Colors ──────────────────────────────────────────────────────────────────

export const colors = {
  // Primary - Vivid Blue
  blue: '#1E90FF',
  navy: '#0B4F8A',
  white: '#FFFFFF',

  // Accent - Arc Violet
  magenta: '#8B5CF6',
  cyan: '#06B6D4',
  black: '#000000',

  // Status & Data
  orange: '#F59E0B',
  green: '#10B981',
  red: '#EF4444',
  skyBlue: '#06B6D4', // Remapped to Cyan per PALETTE.md

  // Neutrals - Slate Command
  gray: {
    light: '#F7F9FC',
    medium: '#D4DCE8',
    dark: '#1A2B42',
    mid: '#6B7D96',
  },

  // Semantic
  status: {
    success: '#10B981',
    warning: '#F59E0B',
    error: '#EF4444',
    info: '#06B6D4',
  },

  // Surfaces (Dark Mode Primary)
  surface: {
    base: '#0C1220',
    card: '#101828',
    subtle: '#131C2E',
    inset: '#080E1A',
    overlay: '#182440',
  },

  // Borders
  border: {
    subtle: '#1E2D44',
    strong: '#2A3F5C',
  },

  // Legacy mappings for compatibility
  purple: '#8B5CF6', // Folded into Arc Violet
  cloudBlue: '#7EC8FF', // Folded into primary tint

  // Structural aliases used by UI primitives
  card: { dark: '#101828', light: '#FFFFFF' },
  bg: { dark: '#0C1220', light: '#F7F9FC' },

  // Interactive state colors used by Button, Utilities, etc.
  hover: {
    blueLight: '#1579D6',
    magenta: '#7C3AED',
    navy: '#0A4070',
    linkDark: '#7EC8FF',
  },
  tint: {
    navyMedium: '#1A3A5C',
  },

  // Chart palette used by chart defaults
  chart: {
    grid: '#1E2D44',
    gridOpacity: 0.4,
    gridOpacitySoft: 0.2,
    baselineOpacity: 0.3,
    barOpacity: 0.85,
  },
} as const;

// ─── Shadows ─────────────────────────────────────────────────────────────────

export const shadows = {
  card: {
    light: '0 2px 8px rgba(26, 43, 66, 0.1)',
    dark: '0 2px 8px rgba(0, 0, 0, 0.3)',
  },
  elevated: {
    light: '0 4px 16px rgba(26, 43, 66, 0.15)',
    dark: '0 4px 16px rgba(0, 0, 0, 0.5)',
  },
  subtle: {
    light: '0 1px 3px rgba(26, 43, 66, 0.06)',
    dark: '0 1px 3px rgba(0, 0, 0, 0.2)',
  },
} as const;

// ─── Gradients ───────────────────────────────────────────────────────────────

export const gradients = {
  navyToBlue: 'linear-gradient(135deg, #0B4F8A 0%, #1E90FF 100%)',
  magentaToDark: 'linear-gradient(135deg, #8B5CF6 0%, #4C1D95 100%)',
  blueScale: 'linear-gradient(90deg, #1E90FF 0%, #06B6D4 50%, #7EC8FF 100%)',
  purpleToMagenta: 'linear-gradient(135deg, #6D28D9 0%, #8B5CF6 100%)',
} as const;

// ─── Typography ─────────────────────────────────────────────────────────────

export const typography = {
  fontFamily: "'Recursive', ui-monospace, monospace",
  fontWeight: {
    light: 300,
    regular: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
    black: 900,
  },
  // Recursive-specific axes
  axes: {
    mono: { prose: 0, data: 1 },
    casl: { clinical: 0, warm: 0.6 },
  }
} as const;

// ─── Spacing ────────────────────────────────────────────────────────────────

export const spacing = {
  none: 0,
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  '2xl': 48,
  '3xl': 64,
} as const;

// ─── Transitions ─────────────────────────────────────────────────────────────

export const transitions = {
  fast: '0.15s ease',
  normal: '0.25s ease',
  slow: '0.4s ease',
} as const;

// ─── Borders ─────────────────────────────────────────────────────────────────

export const borders = {
  subtle: {
    light: `1px solid ${colors.gray.medium}`,
    dark: '1px solid #1E2D44',
  },
  strong: {
    light: `1px solid ${colors.gray.mid}`,
    dark: '1px solid #2A3F5C',
  },
  accent: (color: string) => `4px solid ${color}`,
} as const;

// ─── Convenience Re-exports ─────────────────────────────────────────────────

/** Shorthand for typography.fontFamily */
export const fontFamily = typography.fontFamily;

/** Shorthand for typography.fontWeight */
export const fontWeight = typography.fontWeight;

/** Numeric spacing values for use in calculations */
export const spacingN = spacing;

/** Chart data series palette (ordered for visual distinction) */
export const chartColors = [
  colors.blue,
  colors.magenta,
  colors.cyan,
  colors.green,
  colors.orange,
  colors.red,
  colors.navy,
] as const;

/** Semantic chart colors for status-mapped visualizations */
export const semanticChartColors = {
  success: colors.status.success,
  warning: colors.status.warning,
  error: colors.status.error,
  info: colors.status.info,
  primary: colors.blue,
  secondary: colors.magenta,
} as const;

/** Font variation shorthand for Recursive axes */
export const fv = (opts: { wght?: number; MONO?: number; CASL?: number; CRSV?: number; slnt?: number }) => {
  const parts: string[] = [];
  if (opts.wght !== undefined) parts.push(`'wght' ${opts.wght}`);
  if (opts.MONO !== undefined) parts.push(`'MONO' ${opts.MONO}`);
  if (opts.CASL !== undefined) parts.push(`'CASL' ${opts.CASL}`);
  if (opts.CRSV !== undefined) parts.push(`'CRSV' ${opts.CRSV}`);
  if (opts.slnt !== undefined) parts.push(`'slnt' ${opts.slnt}`);
  return parts.join(', ');
};

// ─── KPI Border Color Cycle ─────────────────────────────────────────────────

export const kpiBorderColors = [
  colors.blue,
  colors.navy,
  colors.green,
  colors.magenta,
  colors.cyan,
  colors.orange,
  colors.red,
] as const;
