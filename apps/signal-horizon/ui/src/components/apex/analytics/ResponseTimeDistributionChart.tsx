import { memo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';

interface ResponseTimeBucket {
  range: string;
  count: number;
  percentage: number;
}

interface ResponseTimeDistributionChartProps {
  data: ResponseTimeBucket[];
  className?: string;
}

// Gradient colors from fast (green) to slow (red)
const bucketColors = [
  '#22c55e', // <25ms - green
  '#84cc16', // 25-50ms - lime
  '#eab308', // 50-100ms - yellow
  '#f97316', // 100-250ms - orange
  '#ef4444', // 250-500ms - red
  '#dc2626', // >500ms - dark red
];

/**
 * ResponseTimeDistributionChart - Vertical bar chart showing response time distribution.
 * Colors gradient from green (fast) to red (slow).
 */
export const ResponseTimeDistributionChart = memo(function ResponseTimeDistributionChart({
  data,
  className = '',
}: ResponseTimeDistributionChartProps) {
  return (
    <div className={`h-64 ${className}`}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -10, bottom: 20 }}
        >
          <XAxis
            dataKey="range"
            tick={{ fontSize: 11, fill: '#627d98' }}
            tickLine={false}
            axisLine={{ stroke: '#e5e7eb' }}
          />
          <YAxis
            tick={{ fontSize: 11, fill: '#627d98' }}
            tickLine={false}
            axisLine={false}
            tickFormatter={(value) => `${value}%`}
          />
          <Tooltip
            formatter={(value: number, _name: string) => [
              `${value.toFixed(1)}%`,
              'Requests',
            ]}
            contentStyle={{
              backgroundColor: '#ffffff',
              border: '1px solid #e5e7eb',
              borderRadius: '0',
              fontSize: '12px',
            }}
            labelStyle={{ color: '#1e3a5f', fontWeight: 600 }}
          />
          <Bar dataKey="percentage" radius={[2, 2, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={bucketColors[Math.min(index, bucketColors.length - 1)]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
});

// Demo data generator
export function generateResponseTimeData(): ResponseTimeBucket[] {
  return [
    { range: '<25ms', count: 45230, percentage: 38.2 },
    { range: '25-50ms', count: 32100, percentage: 27.1 },
    { range: '50-100ms', count: 21500, percentage: 18.2 },
    { range: '100-250ms', count: 12300, percentage: 10.4 },
    { range: '250-500ms', count: 5200, percentage: 4.4 },
    { range: '>500ms', count: 2100, percentage: 1.8 },
  ];
}

export default ResponseTimeDistributionChart;
