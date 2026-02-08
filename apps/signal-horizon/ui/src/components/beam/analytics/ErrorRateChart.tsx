import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer
} from 'recharts';
import { getTooltipStyle, getAxisTickColor, getGridStroke, getCursorFill, isDarkMode } from '../../../lib/chartTheme';

// Demo Data: Status codes per service
const DEMO_ERROR_DATA = [
  { service: 'Auth', success: 4500, clientError: 850, serverError: 20 },
  { service: 'Users', success: 12000, clientError: 120, serverError: 5 },
  { service: 'Products', success: 8500, clientError: 45, serverError: 0 },
  { service: 'Orders', success: 6200, clientError: 300, serverError: 15 },
  { service: 'Search', success: 3800, clientError: 900, serverError: 50 }, // High client errors (bots?)
  { service: 'Payments', success: 2100, clientError: 50, serverError: 120 }, // High server errors (gateway issues?)
];

export function ErrorRateChart() {
  const tooltipStyle = useMemo(() => getTooltipStyle(), []);
  const tickColor = useMemo(() => getAxisTickColor(), []);
  const gridStroke = useMemo(() => getGridStroke(), []);
  const cursorFill = useMemo(() => getCursorFill(), []);
  const legendColor = useMemo(() => isDarkMode() ? '#B0C4DE' : '#334E68', []);

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-ink-primary">Service Health</h3>
          <p className="text-sm text-ink-secondary">Response codes breakdown by service</p>
        </div>
      </div>

      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={DEMO_ERROR_DATA}
            layout="vertical"
            margin={{ top: 0, right: 30, left: 20, bottom: 0 }}
            barSize={16}
          >
            <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} horizontal={true} vertical={false} />
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="service"
              tick={{ fill: tickColor, fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={70}
            />
            <Tooltip
              contentStyle={tooltipStyle.contentStyle}
              labelStyle={tooltipStyle.labelStyle}
              itemStyle={tooltipStyle.itemStyle}
              cursor={{ fill: cursorFill }}
            />
            <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '10px', color: legendColor }} />

            <Bar dataKey="serverError" name="5xx Error" stackId="a" fill="#BF3A30" radius={[0, 0, 0, 0]} />
            <Bar dataKey="clientError" name="4xx Error" stackId="a" fill="#C24900" />
            <Bar dataKey="success" name="2xx Success" stackId="a" fill="#0057B7" radius={[0, 0, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
