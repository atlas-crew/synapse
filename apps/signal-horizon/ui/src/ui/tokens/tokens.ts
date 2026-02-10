/**
 * Atlas Crew / Signal Horizon Design Tokens
 * ====================================
 * Single source of truth for all visual decisions.
 * Every component imports from here. Never hardcode values.
 *
 * Usage:
 *   import { colors, typography, spacing } from '@/tokens';
 *   <div style={{ background: colors.card.dark, padding: spacing.lg }}>
 */

// ─── Colors ──────────────────────────────────────────────────────────────────

export const colors = {
  // Primary
  blue: '#0057B7',
  navy: '#001E62',
  white: '#FFFFFF',

  // Secondary
  skyBlue: '#529EEC',
  magenta: '#D62598',
  black: '#000000',

  // Accent (data & status)
  purple: '#440099',
  orange: '#E35205',
  cloudBlue: '#5E8AB4',
  green: '#00B140',
  red: '#EF3340',

  // Neutrals
  gray: {
    light: '#F0F4F8',
    medium: '#DFE8F0',
    dark: '#404040',
    mid: '#7F7F7F',
  },

  // Surfaces
  card: {
    dark: '#0A1A3A',
    light: '#FFFFFF',
  },
  bg: {
    dark: '#000A1A',
    light: '#F0F4F8',
  },

  // Tints & Shades
  tint: {
    blueLight: '#7CBAFF',
    blueDark: '#004189',
    blueDarker: '#00174A',
    skyLight: '#BEDDFF',
    skyDark: '#3D77B1',
    magentaLight: '#E979C2',
    magentaDark: '#A01B72',
    navyMedium: '#003EC8',
  },

  // Hover states
  hover: {
    blueLight: '#004189',
    blueDark: '#7CBAFF',
    magenta: '#A01B72',
    navy: '#00174A',
    linkLight: '#003EC8',
    linkDark: '#7CBAFF',
  },

  // Semantic
  status: {
    success: '#00B140',
    warning: '#E35205',
    error: '#EF3340',
    info: '#0057B7',
  },

  // Chart-specific
  chart: {
    grid: '#001E62',        // at 0.3 opacity
    gridOpacity: 0.3,
    gridOpacitySoft: 0.15,
    baselineOpacity: 0.8,
    barOpacity: 0.9,
    barHoverOpacity: 1.0,
    highlightEdge: 'rgba(255,255,255,0.12)',
  },
} as const;

// Ordered chart series palette
export const chartColors = [
  colors.blue,       // Primary series
  colors.skyBlue,    // Secondary series
  colors.green,      // Success / positive
  colors.orange,     // Warning / caution
  colors.red,        // Danger / error
  colors.magenta,    // Accent
  colors.cloudBlue,  // Additional
  colors.purple,     // Additional
] as const;

// Semantic chart mapping for allow/block/error type data
export const semanticChartColors = {
  success: colors.green,
  allowed: colors.blue,
  warning: colors.orange,
  error: colors.red,
  blocked: colors.red,
  info: colors.skyBlue,
  accent: colors.magenta,
} as const;

// ─── Typography ──────────────────────────────────────────────────────────────

export const fontFamily =
  "'Rubik', 'Calibri', -apple-system, BlinkMacSystemFont, sans-serif";

export const fontWeight = {
  light: 300,
  regular: 400,
  medium: 500,
  semibold: 600,
  bold: 700,
} as const;

export const typography = {
  eyebrow: {
    fontSize: '1rem',
    fontWeight: fontWeight.bold,
    lineHeight: 1.2,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.1em',
  },
  h1: { fontSize: '3rem', lineHeight: '56px', fontWeight: fontWeight.light },
  h2: { fontSize: '2rem', lineHeight: '40px', fontWeight: fontWeight.light },
  h3: { fontSize: '1.75rem', lineHeight: '36px', fontWeight: fontWeight.light },
  h4: { fontSize: '1.5rem', lineHeight: '32px', fontWeight: fontWeight.light },
  h5: { fontSize: '1.25rem', lineHeight: '28px', fontWeight: fontWeight.medium },
  h6: { fontSize: '1rem', lineHeight: '24px', fontWeight: fontWeight.medium },
  subhead: { fontSize: '1.25rem', lineHeight: '28px', fontWeight: fontWeight.regular },
  body: { fontSize: '1rem', lineHeight: '24px', fontWeight: fontWeight.regular },
  small: { fontSize: '0.875rem', lineHeight: '20px', fontWeight: fontWeight.regular },
  caption: { fontSize: '0.75rem', lineHeight: '16px', fontWeight: fontWeight.regular },

  // Chart-specific
  chartTitle: { fontSize: '20px', fontWeight: fontWeight.light },
  chartSubtitle: { fontSize: '14px', fontWeight: fontWeight.regular },
  chartLabel: { fontSize: '12px', fontWeight: fontWeight.regular },
  chartValue: { fontSize: '13px', fontWeight: fontWeight.medium },
  chartLegend: { fontSize: '12px', fontWeight: fontWeight.regular },

  // KPI-specific
  kpiValue: { fontSize: '28px', fontWeight: fontWeight.medium },
  kpiValueLarge: { fontSize: '36px', fontWeight: fontWeight.medium },
  kpiLabel: { fontSize: '12px', fontWeight: fontWeight.regular },
} as const;

// ─── Spacing ─────────────────────────────────────────────────────────────────

export const spacing = {
  xs: '4px',
  sm: '8px',
  md: '16px',
  lg: '24px',
  xl: '32px',
  '2xl': '48px',
  '3xl': '64px',
} as const;

// Numeric versions for calculations
export const spacingN = {
  xs: 4,
  sm: 8,
  md: 16,
  lg: 24,
  xl: 32,
  '2xl': 48,
  '3xl': 64,
} as const;

// ─── Shadows ─────────────────────────────────────────────────────────────────

export const shadows = {
  card: {
    light: '0 2px 8px rgba(0, 30, 98, 0.1)',
    dark: '0 2px 8px rgba(0, 0, 0, 0.3)',
  },
  elevated: {
    light: '0 4px 16px rgba(0, 30, 98, 0.15)',
    dark: '0 4px 16px rgba(0, 0, 0, 0.5)',
  },
  subtle: {
    light: '0 1px 3px rgba(0, 30, 98, 0.06)',
    dark: '0 1px 3px rgba(0, 0, 0, 0.2)',
  },
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
    dark: '1px solid rgba(255, 255, 255, 0.08)',
  },
  accent: (color: string) => `4px solid ${color}`,
  input: {
    light: `2px solid ${colors.gray.medium}`,
    dark: `2px solid ${colors.tint.navyMedium}`,
  },
} as const;

// ─── KPI Border Color Cycle ─────────────────────────────────────────────────

export const kpiBorderColors = [
  colors.blue,
  colors.navy,
  colors.green,
  colors.magenta,
  colors.skyBlue,
  colors.purple,
  colors.orange,
  colors.cloudBlue,
] as const;

// ─── Gradients ───────────────────────────────────────────────────────────────

export const gradients = {
  navyToBlue: 'linear-gradient(135deg, #001E62 0%, #0057B7 100%)',
  magentaToDark: 'linear-gradient(135deg, #D62598 0%, #A01B72 100%)',
  blueScale: 'linear-gradient(90deg, #0057B7 0%, #529EEC 50%, #7CBAFF 100%)',
  purpleToMagenta: 'linear-gradient(135deg, #440099 0%, #D62598 100%)',
} as const;
