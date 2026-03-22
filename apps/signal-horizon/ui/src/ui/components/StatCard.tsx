import React from 'react';
import { colors, fontFamily, fontWeight, spacing } from '../tokens/tokens';

/**
 * StatCard — Compact metric card for data pages.
 *
 * Use for beam, catalog, intel, and fleet data pages.
 * For status dashboards (Overview, Fleet Overview), use KpiStrip instead.
 *
 * Usage:
 *   <StatCard label="Total Requests" value="88.7k" icon={<Activity />} />
 *   <StatCard label="Block Rate" value="1.65%" trend={{ value: 8, label: "vs previous" }} icon={<Shield />} />
 */

interface StatCardProps {
  label: string;
  value: string;
  /** Optional trend indicator */
  trend?: { value: number; label: string };
  /** Icon displayed to the right of the value */
  icon?: React.ReactNode;
  /** Optional description below the value */
  description?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  trend,
  icon,
  description,
}) => {
  const isPositive = trend && trend.value >= 0;

  return (
    <div
      style={{
        background: colors.surface.card,
        border: `1px solid ${colors.border.subtle}`,
        padding: spacing.lg,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      <div>
        <div
          style={{
            fontFamily,
            fontWeight: fontWeight.regular,
            fontSize: '13px',
            color: colors.gray.mid,
          }}
        >
          {label}
        </div>
        <div
          style={{
            fontFamily,
            fontWeight: fontWeight.bold,
            fontSize: '24px',
            lineHeight: '32px',
            color: '#F0F4F8',
            marginTop: spacing.xs,
          }}
        >
          {value}
        </div>
        {trend && (
          <div
            style={{
              fontFamily,
              fontSize: '12px',
              marginTop: spacing.xs,
              color: isPositive ? colors.green : colors.red,
            }}
          >
            {isPositive ? '↗' : '↘'} {Math.abs(trend.value)}% {trend.label}
          </div>
        )}
        {description && (
          <div
            style={{
              fontFamily,
              fontSize: '12px',
              color: colors.gray.mid,
              marginTop: spacing.xs,
            }}
          >
            {description}
          </div>
        )}
      </div>
      {icon && (
        <div style={{ color: colors.blue, opacity: 0.6, flexShrink: 0 }}>
          {icon}
        </div>
      )}
    </div>
  );
};

StatCard.displayName = 'StatCard';
