import { memo, type ReactNode } from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  trend?: { value: number; label: string };
  icon?: ReactNode;
  className?: string;
  labelClassName?: string;
  valueClassName?: string;
}

export const MetricCard = memo(function MetricCard({
  label,
  value,
  trend,
  icon,
  className = '',
  labelClassName = '',
  valueClassName = '',
}: MetricCardProps) {
  const trendColor = trend
    ? trend.value > 0 ? 'text-ac-green' : trend.value < 0 ? 'text-ac-red' : 'text-ink-muted'
    : '';

  return (
    <div className={`card p-6 ${className}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className={`text-sm font-medium text-ink-secondary ${labelClassName}`}>{label}</p>
          <p className={`mt-2 text-3xl font-light text-ink-primary ${valueClassName}`}>{value}</p>
          {trend && (
            <p className={`mt-2 text-sm font-medium ${trendColor}`}>
              {trend.value > 0 ? '↑' : trend.value < 0 ? '↓' : '→'} {Math.abs(trend.value)}% {trend.label}
            </p>
          )}
        </div>
        {icon && <div className="text-ac-blue">{icon}</div>}
      </div>
    </div>
  );
});
