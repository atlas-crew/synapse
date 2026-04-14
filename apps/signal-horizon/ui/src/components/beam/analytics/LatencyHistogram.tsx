import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LabelList,
} from 'recharts';
import {
  axisDefaults,
  ChartValueLabel,
  CARD_HEADER_TITLE_STYLE,
  colors,
  darken,
  formatValue,
  gridDefaults,
  lighten,
  Panel,
  SectionHeader,
  tooltipDefaults,
  xAxisNoLine,
} from '@/ui';

// Demo Data: Distribution of request latencies (Atlas Crew brand chart colors)
const DEMO_LATENCY_DATA = [
  { bucket: '0-50ms', count: 45000, color: colors.blue },
  { bucket: '50-100ms', count: 28000, color: colors.blue },
  { bucket: '100-200ms', count: 12000, color: colors.blue },
  { bucket: '200-500ms', count: 5000, color: colors.blue },
  { bucket: '500ms-1s', count: 1200, color: colors.orange },
  { bucket: '1s+', count: 450, color: colors.red },
];

// Pre-compute unique colors for gradient defs
const uniqueColors = [...new Set(DEMO_LATENCY_DATA.map((d) => d.color))];

export function LatencyHistogram() {
  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Latency Distribution"
          description="Request processing time buckets"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
        <div className="text-right">
          <p className="text-xs text-ink-secondary uppercase tracking-wider">P95 Latency</p>
          <p className="text-xl font-mono text-ink-primary">184ms</p>
        </div>
      </Panel.Header>

      <Panel.Body className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={DEMO_LATENCY_DATA} margin={{ top: 24, right: 0, left: 0, bottom: 0 }}>
            <defs>
              {uniqueColors.map((color) => (
                <linearGradient key={color} id={`bar-v-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={lighten(color, 30)} />
                  <stop offset="100%" stopColor={darken(color, 20)} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid {...gridDefaults} />
            <XAxis
              dataKey="bucket"
              {...xAxisNoLine}
            />
            <YAxis
              {...axisDefaults.y}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <Tooltip
              {...tooltipDefaults}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Bar dataKey="count" radius={[0, 0, 0, 0]} fillOpacity={0.9}>
              <LabelList
                dataKey="count"
                content={<ChartValueLabel formatter={(value: number) => formatValue(value)} />}
              />
              {DEMO_LATENCY_DATA.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={`url(#bar-v-${entry.color.replace('#', '')})`} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Panel.Body>
    </Panel>
  );
}
