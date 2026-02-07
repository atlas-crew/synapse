import { memo, type ReactNode } from 'react';
import { TrendIndicator, type TrendDirection } from '../ctrlx/TrendIndicator';

export type MetricCardVariant = 'fleet' | 'ctrlx';
export type MetricAccent = 'primary' | 'success' | 'warning' | 'danger' | 'info';

/**
 * Trend shape for the fleet variant: value + label, direction inferred from sign.
 */
interface FleetTrend {
  value: number;
  label: string;
}

/**
 * Trend shape for the ctrlx variant: value + explicit direction.
 */
interface CtrlxTrend {
  value: number;
  direction: TrendDirection;
}

export interface MetricCardProps {
  label: string;
  value: string | number;
  /** Tooltip text explaining what this metric means */
  description?: string;
  /** Fleet-style trend (value + label) OR ctrlx-style trend (value + direction). */
  trend?: FleetTrend | CtrlxTrend;
  icon?: ReactNode;
  className?: string;

  /**
   * Visual variant.
   * - 'fleet' (default): Standard card with label-above-value, text trend arrows.
   * - 'ctrlx': Colored top-border accent, value-above-label eyebrow, TrendIndicator icons.
   */
  variant?: MetricCardVariant;

  // --- Fleet-specific optional class overrides ---
  labelClassName?: string;
  valueClassName?: string;

  // --- CtrlX-specific optional props ---
  /** Accent color for top border and value text (ctrlx variant only). */
  accent?: MetricAccent;
  /** Small subtitle shown below trend (ctrlx variant only). */
  subtitle?: string;
}

// ── CtrlX accent maps ──────────────────────────────────────────────

const accentBorderColors: Record<MetricAccent, string> = {
  primary: 'bg-ac-magenta',
  success: 'bg-ac-green',
  warning: 'bg-ac-orange',
  danger: 'bg-ac-magenta',
  info: 'bg-ac-blue',
};

const accentValueColors: Record<MetricAccent, string> = {
  primary: 'text-ac-magenta',
  success: 'text-ac-green',
  warning: 'text-ac-orange',
  danger: 'text-ac-magenta',
  info: 'text-ac-blue',
};

// ── Helpers ────────────────────────────────────────────────────────

function isCtrlxTrend(trend: FleetTrend | CtrlxTrend): trend is CtrlxTrend {
  return 'direction' in trend;
}

// ── Component ──────────────────────────────────────────────────────

export const MetricCard = memo(function MetricCard({
  label,
  value,
  description,
  trend,
  icon,
  className = '',
  variant = 'fleet',
  labelClassName = '',
  valueClassName = '',
  accent = 'primary',
  subtitle,
}: MetricCardProps) {
  // ── CtrlX variant ──────────────────────────────────────────────
  if (variant === 'ctrlx') {
    return (
      <div
        className={`bg-surface-card border border-border-subtle shadow-sm p-4 relative overflow-hidden ${className}`}
      >
        {/* Colored top border accent */}
        <div className={`absolute top-0 left-0 right-0 h-1 ${accentBorderColors[accent]}`} />

        <div className="flex items-start justify-between pt-1">
          <div className="flex-1">
            {/* Large value - Rubik Light (300) per design system */}
            <p className={`text-3xl font-light ${accentValueColors[accent]}`} aria-live="polite">
              {value}
            </p>

            {/* Eyebrow label - caps, small, tracked per design system */}
            <p className="mt-1 text-xs font-bold text-ink-muted uppercase tracking-[0.1em]" title={description}>
              {label}
            </p>

            {/* Trend indicator (ctrlx-style with icons) */}
            {trend && isCtrlxTrend(trend) && (
              <div className="mt-2">
                <TrendIndicator
                  value={trend.value}
                  direction={trend.direction}
                />
              </div>
            )}

            {/* Optional subtitle */}
            {subtitle && (
              <p className="mt-1 text-xs text-ink-muted">{subtitle}</p>
            )}
          </div>

          {/* Icon in top-right */}
          {icon && (
            <div className="text-ink-muted ml-2">{icon}</div>
          )}
        </div>
      </div>
    );
  }

  // ── Fleet variant (default) ────────────────────────────────────
  const trendColor = trend
    ? trend.value > 0 ? 'text-ac-green' : trend.value < 0 ? 'text-ac-red' : 'text-ink-muted'
    : '';

  const trendLabel = trend && !isCtrlxTrend(trend) ? trend.label : '';

  return (
    <div className={`card p-6 ${className}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className={`text-sm font-medium text-ink-secondary ${labelClassName}`} title={description}>{label}</p>
          <p className={`mt-2 text-3xl font-light text-ink-primary ${valueClassName}`} aria-live="polite">{value}</p>
          {trend && (
            <p className={`mt-2 text-sm font-medium ${trendColor}`}>
              {trend.value > 0 ? '\u2191' : trend.value < 0 ? '\u2193' : '\u2192'} {Math.abs(trend.value)}%{trendLabel ? ` ${trendLabel}` : ''}
            </p>
          )}
        </div>
        {icon && <div className="text-ac-blue">{icon}</div>}
      </div>
    </div>
  );
});

export default MetricCard;
