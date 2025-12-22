import { memo, type ReactNode } from 'react';

interface MetricCardProps {
  label: string;
  value: string | number;
  trend?: { value: number; label: string };
  icon?: ReactNode;
  className?: string;
}

export const MetricCard = memo(function MetricCard({
  label,
  value,
  trend,
  icon,
  className = '',
}: MetricCardProps) {
  const trendColor = trend
    ? trend.value > 0 ? 'text-green-600' : trend.value < 0 ? 'text-red-600' : 'text-gray-600'
    : '';

  return (
    <div className={`bg-white border border-gray-200 p-6 ${className}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-600">{label}</p>
          <p className="mt-2 text-3xl font-bold text-gray-900">{value}</p>
          {trend && (
            <p className={`mt-2 text-sm font-medium ${trendColor}`}>
              {trend.value > 0 ? '↑' : trend.value < 0 ? '↓' : '→'} {Math.abs(trend.value)}% {trend.label}
            </p>
          )}
        </div>
        {icon && <div className="text-[#0057B7]">{icon}</div>}
      </div>
    </div>
  );
});
