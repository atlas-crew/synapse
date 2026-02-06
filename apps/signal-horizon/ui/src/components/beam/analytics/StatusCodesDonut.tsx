import { memo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { TOOLTIP_CONTENT_STYLE, TOOLTIP_LABEL_STYLE, TOOLTIP_ITEM_STYLE } from '../../../lib/chartTheme';

interface StatusCodeData {
  name: string;
  value: number;
  color: string;
}

interface StatusCodesDonutProps {
  data: StatusCodeData[];
  className?: string;
}

// Atlas Crew brand colors for status codes
const statusCodeColors: Record<string, string> = {
  '2xx': '#00B140', // success - Atlas Crew Green
  '3xx': '#0057B7', // redirect - Atlas Crew Blue
  '4xx': '#E35205', // client error - Atlas Crew Orange
  '5xx': '#D62598', // server error - Atlas Crew Magenta
};

/**
 * StatusCodesDonut - Donut chart showing HTTP status code distribution.
 * 2xx=green, 3xx=blue, 4xx=sky blue (Atlas Crew brand), 5xx=red.
 */
export const StatusCodesDonut = memo(function StatusCodesDonut({
  data,
  className = '',
}: StatusCodesDonutProps) {
  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className={`h-64 ${className}`} role="img" aria-label="Donut chart showing HTTP status code distribution">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={50}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number, name: string) => [
              `${value.toLocaleString()} (${((value / total) * 100).toFixed(1)}%)`,
              name,
            ]}
            contentStyle={{ ...TOOLTIP_CONTENT_STYLE, fontSize: '12px' }}
            labelStyle={TOOLTIP_LABEL_STYLE}
            itemStyle={TOOLTIP_ITEM_STYLE}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            formatter={(value, _entry) => {
              const item = data.find((d) => d.name === value);
              const percentage = item ? ((item.value / total) * 100).toFixed(1) : '0';
              return (
                <span className="text-xs text-ink-secondary">
                  {value} ({percentage}%)
                </span>
              );
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
});

// Demo data generator
export function generateStatusCodeData(): StatusCodeData[] {
  return [
    { name: '2xx', value: 2145000, color: statusCodeColors['2xx'] },
    { name: '3xx', value: 156000, color: statusCodeColors['3xx'] },
    { name: '4xx', value: 89000, color: statusCodeColors['4xx'] },
    { name: '5xx', value: 12000, color: statusCodeColors['5xx'] },
  ];
}

export default StatusCodesDonut;
