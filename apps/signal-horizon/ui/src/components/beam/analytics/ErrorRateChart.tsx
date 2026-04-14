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
import {
  axisDefaults,
  barDefaults,
  CARD_HEADER_TITLE_STYLE,
  colors,
  darken,
  gridDefaults,
  legendDefaults,
  lighten,
  Panel,
  SectionHeader,
  tooltipDefaults,
} from '@/ui';

// Demo Data: Status codes per service
const DEMO_ERROR_DATA = [
  { service: 'Auth', success: 4500, clientError: 850, serverError: 20 },
  { service: 'Users', success: 12000, clientError: 120, serverError: 5 },
  { service: 'Products', success: 8500, clientError: 45, serverError: 0 },
  { service: 'Orders', success: 6200, clientError: 300, serverError: 15 },
  { service: 'Search', success: 3800, clientError: 900, serverError: 50 }, // High client errors (bots?)
  { service: 'Payments', success: 2100, clientError: 50, serverError: 120 }, // High server errors (gateway issues?)
];

// Chart series colors per brand chart standards
const SERIES = {
  serverError: { color: colors.red, label: '5xx Error' },
  clientError: { color: colors.orange, label: '4xx Error' },
  success: { color: colors.blue, label: '2xx Success' },
};

export function ErrorRateChart() {
  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Service Health"
          description="Response codes breakdown by service"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Panel.Header>

      <Panel.Body className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={DEMO_ERROR_DATA}
            layout="vertical"
            margin={{ top: 0, right: 30, left: 20, bottom: 0 }}
            barSize={16}
          >
            <defs>
              {Object.entries(SERIES).map(([key, { color }]) => (
                <linearGradient key={key} id={`bar-h-${key}`} x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%" stopColor={darken(color, 20)} />
                  <stop offset="100%" stopColor={lighten(color, 30)} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid {...gridDefaults} horizontal={true} vertical={false} />
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="service"
              tick={axisDefaults.y.tick}
              axisLine={false}
              tickLine={false}
              width={70}
            />
            <Tooltip
              {...tooltipDefaults}
            />
            <Legend
              {...legendDefaults}
              wrapperStyle={{ ...legendDefaults.wrapperStyle, paddingTop: '10px' }}
            />

            <Bar
              dataKey="serverError"
              name={SERIES.serverError.label}
              stackId="a"
              fill="url(#bar-h-serverError)"
              fillOpacity={barDefaults.opacity}
              radius={barDefaults.radius}
            />
            <Bar
              dataKey="clientError"
              name={SERIES.clientError.label}
              stackId="a"
              fill="url(#bar-h-clientError)"
              fillOpacity={barDefaults.opacity}
            />
            <Bar
              dataKey="success"
              name={SERIES.success.label}
              stackId="a"
              fill="url(#bar-h-success)"
              fillOpacity={barDefaults.opacity}
              radius={barDefaults.radius}
            />
          </BarChart>
        </ResponsiveContainer>
      </Panel.Body>
    </Panel>
  );
}
