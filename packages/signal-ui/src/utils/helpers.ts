import React from 'react';
import { fontFamily, typography } from '../tokens/tokens';

/**
 * Utility functions for the component library.
 * Color manipulation, value formatting, gradient generation.
 */

// ─── Color Manipulation ─────────────────────────────────────────────────────

export const lighten = (hex: string, amount: number): string => {
  const num = parseInt(hex.replace('#', ''), 16);
  const r = Math.min(255, ((num >> 16) & 0xff) + amount);
  const g = Math.min(255, ((num >> 8) & 0xff) + amount);
  const b = Math.min(255, (num & 0xff) + amount);
  return `rgb(${r},${g},${b})`;
};

export const darken = (hex: string, amount: number): string =>
  lighten(hex, -amount);

export const alpha = (color: string, opacity: number): string => {
  if (!color) return 'transparent';
  if (color.startsWith('var(')) {
    return `color-mix(in srgb, ${color}, transparent ${Math.round((1 - opacity) * 100)}%)`;
  }
  const hex = color.replace('#', '');
  const num = parseInt(hex, 16);
  const r = (num >> 16) & 0xff;
  const g = (num >> 8) & 0xff;
  const b = num & 0xff;
  return `rgba(${r},${g},${b},${opacity})`;
};

// ─── Chart Gradient Helpers ──────────────────────────────────────────────────

/** SVG gradient ID for a bar fill. Call once per color in <defs>. */
export const barGradientId = (color: string, direction: 'vertical' | 'horizontal' = 'vertical') =>
  `bar-grad-${color.replace('#', '')}-${direction[0]}`;

/** Returns SVG linearGradient props for brand-compliant bar fills */
export const barGradientStops = (baseColor: string, direction: 'vertical' | 'horizontal' = 'vertical') => {
  if (direction === 'vertical') {
    return {
      x1: '0', y1: '0', x2: '0', y2: '1',
      startColor: lighten(baseColor, 30),
      endColor: darken(baseColor, 20),
    };
  }
  return {
    x1: '0', y1: '0', x2: '1', y2: '0',
    startColor: darken(baseColor, 20),
    endColor: lighten(baseColor, 30),
  };
};

// ─── Value Formatting ────────────────────────────────────────────────────────

export const formatValue = (value: number, decimals = 1): string => {
  if (value >= 1_000_000) {
    const v = value / 1_000_000;
    return v >= 10 ? `${Math.round(v)}M` : `${v.toFixed(decimals)}M`;
  }
  if (value >= 10_000) return `${Math.round(value / 1000)}k`;
  if (value >= 1_000) {
    const v = value / 1000;
    return `${v.toFixed(decimals)}k`;
  }
  return value.toLocaleString();
};

export const formatPercent = (value: number, decimals = 1): string =>
  `${value.toFixed(decimals)}%`;

export const formatDuration = (ms: number): string => {
  if (ms < 1) return `${(ms * 1000).toFixed(0)}μs`;
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
};

export const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)}GB`;
};

// ─── CSS Helpers ─────────────────────────────────────────────────────────────

/** Merges style objects, later values override earlier */
export const sx = (...styles: (React.CSSProperties | undefined | false | null)[]): React.CSSProperties =>
  Object.assign({}, ...styles.filter(Boolean));

/** Responsive clamp: fluid sizing between min and max */
export const clamp = (min: string, preferred: string, max: string) =>
  `clamp(${min}, ${preferred}, ${max})`;

/** Apply a type role as a style object */
export const applyType = (role: keyof typeof typography): React.CSSProperties => ({
  fontFamily,
  ...(typography[role] as React.CSSProperties),
});

