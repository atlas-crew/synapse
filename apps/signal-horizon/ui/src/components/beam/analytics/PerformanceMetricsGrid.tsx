import { memo } from 'react';
import { Stack } from '@/ui';

interface PerformanceMetric {
  label: string;
  value: string | number;
  unit?: string;
  highlight?: boolean;
}

interface PerformanceMetricsGridProps {
  metrics: PerformanceMetric[];
  className?: string;
}

/**
 * PerformanceMetricsGrid - Compact grid of performance metrics.
 * Shows P50/P90/P99 latencies, throughput, etc.
 */
export const PerformanceMetricsGrid = memo(function PerformanceMetricsGrid({
  metrics,
  className = '',
}: PerformanceMetricsGridProps) {
  return (
    <Stack
      direction="row"
      align="center"
      gap="sm"
      className={`flex-wrap gap-x-8 gap-y-2 py-4 px-6 bg-gray-50 border border-gray-200 ${className}`}
    >
      {metrics.map((metric, index) => (
        <div
          key={metric.label}
          className={`flex items-baseline gap-2 ${
            index !== metrics.length - 1 ? 'border-r border-gray-200 pr-8' : ''
          }`}
        >
          <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">
            {metric.label}:
          </span>
          <span
            className={`text-sm font-semibold ${
              metric.highlight ? 'text-ctrlx-danger' : 'text-navy-900'
            }`}
          >
            {metric.value}
            {metric.unit && (
              <span className="text-gray-500 font-normal ml-0.5">{metric.unit}</span>
            )}
          </span>
        </div>
      ))}
    </Stack>
  );
});

// Demo data generator
export function generatePerformanceMetrics(): PerformanceMetric[] {
  return [
    { label: 'P50', value: 23, unit: 'ms' },
    { label: 'P90', value: 67, unit: 'ms' },
    { label: 'P99', value: 245, unit: 'ms', highlight: true },
    { label: 'Req/sec', value: '1,847' },
    { label: 'Avg Size', value: '4.2', unit: 'KB' },
    { label: 'Cache Hit', value: '94.2', unit: '%' },
  ];
}

export default PerformanceMetricsGrid;
