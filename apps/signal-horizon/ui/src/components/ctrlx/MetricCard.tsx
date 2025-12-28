import { memo, type ReactNode } from 'react';
import { TrendIndicator, type TrendDirection } from './TrendIndicator';

export type MetricAccent = 'primary' | 'success' | 'warning' | 'danger' | 'info';

interface MetricCardProps {
  label: string;
  value: string | number;
  trend?: {
    value: number;
    direction: TrendDirection;
  };
  icon?: ReactNode;
  accent?: MetricAccent;
  subtitle?: string;
  className?: string;
}

/**
 * CtrlX MetricCard - Large number display with colored top border accent.
 * Matches the CtrlX design system mockups with light theme styling.
 */
export const MetricCard = memo(function MetricCard({
  label,
  value,
  trend,
  icon,
  accent = 'primary',
  subtitle,
  className = '',
}: MetricCardProps) {
  const accentColors: Record<MetricAccent, string> = {
    primary: 'bg-ctrlx-primary',
    success: 'bg-ctrlx-success',
    warning: 'bg-ctrlx-warning',
    danger: 'bg-ctrlx-danger',
    info: 'bg-ctrlx-info',
  };

  const valueColors: Record<MetricAccent, string> = {
    primary: 'text-ctrlx-primary',
    success: 'text-ctrlx-success',
    warning: 'text-ctrlx-warning',
    danger: 'text-ctrlx-danger',
    info: 'text-ctrlx-info',
  };

  return (
    <div
      className={`bg-white border border-gray-200 shadow-sm p-4 relative overflow-hidden ${className}`}
    >
      {/* Colored top border accent */}
      <div className={`absolute top-0 left-0 right-0 h-1 ${accentColors[accent]}`} />

      <div className="flex items-start justify-between pt-1">
        <div className="flex-1">
          {/* Large value */}
          <p className={`text-3xl font-semibold ${valueColors[accent]}`}>
            {value}
          </p>

          {/* Small caps label */}
          <p className="mt-1 text-xs font-semibold text-gray-500 uppercase tracking-wider">
            {label}
          </p>

          {/* Trend indicator */}
          {trend && (
            <div className="mt-2">
              <TrendIndicator
                value={trend.value}
                direction={trend.direction}
              />
            </div>
          )}

          {/* Optional subtitle */}
          {subtitle && (
            <p className="mt-1 text-xs text-gray-500">{subtitle}</p>
          )}
        </div>

        {/* Icon in top-right */}
        {icon && (
          <div className="text-gray-400 ml-2">{icon}</div>
        )}
      </div>
    </div>
  );
});

export default MetricCard;
