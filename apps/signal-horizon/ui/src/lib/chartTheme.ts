/**
 * Signal Horizon Chart Theme
 * Consistent styling for all Recharts components using Atlas Crew brand colors
 * Supports both light and dark modes
 */

// Atlas Crew Brand color palette for charts (ordered by brand hierarchy)
export const CHART_COLORS = {
  primary: '#001E62',    // Navy - dominant
  secondary: '#0057B7',  // Atlas Crew Blue - interactive
  tertiary: '#529EEC',   // Sky Blue
  quaternary: '#D62598', // Magenta - accent
  quinary: '#008731',    // Green (contrast-safe)
  senary: '#C24900',     // Orange (contrast-safe)
};

// Categorical palette for multi-series charts (brand hierarchy order)
export const CATEGORICAL_COLORS = [
  '#001E62', // Navy
  '#0057B7', // Atlas Crew Blue
  '#529EEC', // Sky Blue
  '#D62598', // Magenta
  '#008731', // Green
  '#C24900', // Orange
];

// Gradient definitions for area/bar charts
export const GRADIENTS = {
  primary: {
    id: 'gradientPrimary',
    stops: [
      { offset: '0%', color: '#529EEC', opacity: 0.5 },
      { offset: '50%', color: '#0057B7', opacity: 0.25 },
      { offset: '100%', color: '#0057B7', opacity: 0.05 },
    ],
  },
  magenta: {
    id: 'gradientMagenta',
    stops: [
      { offset: '0%', color: '#D62598', opacity: 0.5 },
      { offset: '100%', color: '#D62598', opacity: 0.1 },
    ],
  },
  success: {
    id: 'gradientSuccess',
    stops: [
      { offset: '0%', color: '#008731', opacity: 0.5 },
      { offset: '100%', color: '#008731', opacity: 0.1 },
    ],
  },
  warning: {
    id: 'gradientWarning',
    stops: [
      { offset: '0%', color: '#C24900', opacity: 0.5 },
      { offset: '100%', color: '#C24900', opacity: 0.1 },
    ],
  },
};

// Axis styling - theme aware
export const AXIS_STYLE = {
  stroke: '#7B8FA8',
  fontSize: 11,
  tickLine: false,
  axisLine: false,
};

// Dynamic axis tick color based on theme
export function getAxisTickColor(): string {
  return isDarkMode() ? '#7B8FA8' : '#627D98';
}

// Dynamic grid stroke based on theme
export function getGridStroke(): string {
  return isDarkMode() ? 'rgba(0, 87, 183, 0.15)' : 'rgba(0, 30, 98, 0.12)';
}

// Dynamic cursor fill for tooltips
export function getCursorFill(): string {
  return isDarkMode() ? 'rgba(0, 87, 183, 0.1)' : 'rgba(0, 30, 98, 0.08)';
}

// Grid styling - theme aware
export const GRID_STYLE = {
  strokeDasharray: '3 3',
  stroke: 'rgba(0, 87, 183, 0.15)',
  vertical: false,
};

// Helper to detect dark mode
export function isDarkMode(): boolean {
  if (typeof window === 'undefined') return true;
  return document.documentElement.classList.contains('dark');
}

// Tooltip styling - theme aware via CSS variables
export const TOOLTIP_STYLE_DARK = {
  contentStyle: {
    backgroundColor: '#001544',
    border: '1px solid rgba(0, 87, 183, 0.4)',
    borderRadius: 0,
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
  },
  labelStyle: {
    color: '#FFFFFF',
    fontWeight: 500,
  },
  itemStyle: {
    color: '#B0C4DE',
  },
};

export const TOOLTIP_STYLE_LIGHT = {
  contentStyle: {
    backgroundColor: '#FFFFFF',
    border: '1px solid rgba(0, 30, 98, 0.15)',
    borderRadius: 0,
    boxShadow: '0 4px 12px rgba(0, 30, 98, 0.15)',
  },
  labelStyle: {
    color: '#001E62',
    fontWeight: 500,
  },
  itemStyle: {
    color: '#334E68',
  },
};

// Dynamic tooltip style based on current theme
export function getTooltipStyle() {
  return isDarkMode() ? TOOLTIP_STYLE_DARK : TOOLTIP_STYLE_LIGHT;
}

// Legacy export for backwards compatibility
export const TOOLTIP_STYLE = TOOLTIP_STYLE_DARK;

/**
 * CSS-variable-based tooltip styles that adapt to light/dark mode automatically.
 * Use these for inline Recharts Tooltip props without needing isDarkMode() checks.
 */
export const TOOLTIP_CONTENT_STYLE: React.CSSProperties = {
  backgroundColor: 'var(--chart-tooltip-bg)',
  border: '1px solid var(--chart-tooltip-border)',
  borderRadius: 0,
  boxShadow: 'var(--chart-tooltip-shadow)',
};

export const TOOLTIP_LABEL_STYLE: React.CSSProperties = {
  color: 'var(--chart-tooltip-label)',
  fontWeight: 500,
};

export const TOOLTIP_ITEM_STYLE: React.CSSProperties = {
  color: 'var(--chart-tooltip-item)',
};

// Line chart defaults
export const LINE_DEFAULTS = {
  strokeWidth: 2.5,
  dot: false,
  activeDot: { r: 4, fill: '#529EEC', stroke: '#001E62', strokeWidth: 2 },
};

// Bar chart defaults
export const BAR_DEFAULTS = {
  radius: [0, 0, 0, 0] as [number, number, number, number],
  barSize: 16,
};

// Area chart defaults
export const AREA_DEFAULTS = {
  strokeWidth: 2,
  fillOpacity: 1,
};

/**
 * Helper to render gradient definitions in SVG
 */
export function renderGradientDefs() {
  return Object.values(GRADIENTS).map((gradient) => (
    `<linearGradient key="${gradient.id}" id="${gradient.id}" x1="0" y1="0" x2="0" y2="1">
      ${gradient.stops.map((stop) =>
        `<stop offset="${stop.offset}" stopColor="${stop.color}" stopOpacity="${stop.opacity}" />`
      ).join('')}
    </linearGradient>`
  )).join('');
}
