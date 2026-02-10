/**
 * Recharts brand defaults for Signal Horizon charts.
 *
 * Usage:
 *   import { axisDefaults, gridDefaults, tooltipDefaults, chartColors } from '@/ui';
 *
 *   <BarChart>
 *     <CartesianGrid {...gridDefaults} />
 *     <XAxis {...axisDefaults.x} />
 *     <YAxis {...axisDefaults.y} />
 *     <Tooltip {...tooltipDefaults} />
 *     <Bar dataKey="value" fill={chartColors[0]} radius={0} />
 *   </BarChart>
 */

import React from 'react';
import { colors, fontFamily, fontWeight } from '../tokens/tokens';
import { lighten, darken } from '../utils/helpers';

export { chartColors } from '../tokens/tokens';
export { semanticChartColors } from '../tokens/tokens';

const axisTick = {
  fill: colors.gray.mid,
  fontFamily,
  fontSize: 12,
  fontWeight: fontWeight.regular,
};

export const axisDefaults = {
  x: {
    tick: axisTick,
    tickLine: false,
    axisLine: { stroke: colors.chart.grid, strokeOpacity: colors.chart.baselineOpacity },
  },
  y: {
    tick: axisTick,
    tickLine: false,
    axisLine: false,
    width: 50,
  },
} as const;

export const gridDefaults = {
  strokeDasharray: '4 4',
  stroke: colors.chart.grid,
  strokeOpacity: colors.chart.gridOpacity,
  vertical: false,
} as const;

// Softer grid variant for dense charts where the default grid competes with data.
export const gridDefaultsSoft = {
  ...gridDefaults,
  strokeDasharray: '3 3',
  stroke: colors.blue,
  strokeOpacity: 0.15,
} as const;

export const tooltipDefaults = {
  contentStyle: {
    background: '#0A1A3A',
    border: `1px solid rgba(255,255,255,0.12)`,
    borderRadius: 0,
    fontFamily,
    fontSize: '13px',
    color: '#F0F4F8',
    boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
  },
  labelStyle: {
    fontFamily,
    fontWeight: fontWeight.medium,
    color: '#F0F4F8',
    marginBottom: '4px',
  },
  itemStyle: {
    fontFamily,
    fontWeight: fontWeight.regular,
    fontSize: '12px',
    color: '#F0F4F8',
    padding: '2px 0',
  },
  cursor: { fill: 'rgba(255,255,255,0.06)' },
} as const;

export const legendDefaults = {
  wrapperStyle: {
    fontFamily,
    fontSize: '12px',
    color: colors.gray.mid,
  },
  iconType: 'square' as const,
  iconSize: 12,
} as const;

export const barGradientDefs = (
  baseColor: string,
  id: string,
  direction: 'vertical' | 'horizontal' = 'vertical',
) => {
  const isVertical = direction === 'vertical';
  return (
    <linearGradient
      id={`grad-${id}`}
      x1="0" y1="0"
      x2={isVertical ? '0' : '1'}
      y2={isVertical ? '1' : '0'}
    >
      <stop offset="0%" stopColor={isVertical ? lighten(baseColor, 30) : darken(baseColor, 20)} />
      <stop offset="100%" stopColor={isVertical ? darken(baseColor, 20) : lighten(baseColor, 30)} />
    </linearGradient>
  );
};

export const ChartValueLabel: React.FC<any> = ({
  x, y, width, height, value,
  position = 'top', offset = 8, formatter,
}) => {
  const displayValue = formatter ? formatter(value) : value;
  const xPos = x + (width || 0) / 2;
  const yPos = position === 'top' ? y - offset : y + (height || 0) / 2;

  return (
    <text
      x={xPos} y={yPos}
      fill="#F0F4F8" fontFamily={fontFamily}
      fontWeight={fontWeight.medium} fontSize={13}
      textAnchor="middle"
      dominantBaseline={position === 'top' ? 'auto' : 'central'}
    >
      {displayValue}
    </text>
  );
};

export const barDefaults = {
  radius: [0, 0, 0, 0] as [number, number, number, number],
  opacity: colors.chart.barOpacity,
} as const;

export const lineDefaults = {
  strokeWidth: 2,
  dot: false,
  activeDot: { r: 4, fill: '#F0F4F8', strokeWidth: 2 },
  type: 'monotone' as const,
} as const;

export const areaFillOpacity = 0.15;
