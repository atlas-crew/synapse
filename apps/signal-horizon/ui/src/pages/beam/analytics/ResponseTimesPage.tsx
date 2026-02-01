/**
 * Response Times Analytics Page
 * P50/P95/P99 latency tracking and performance analysis
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Clock,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Zap,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';
import { getTooltipStyle, getAxisTickColor, getGridStroke } from '../../../lib/chartTheme';

type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d';

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h', label: '1 Hour' },
  { value: '6h', label: '6 Hours' },
  { value: '24h', label: '24 Hours' },
  { value: '7d', label: '7 Days' },
  { value: '30d', label: '30 Days' },
];

// Demo data - latency over time with percentiles
const DEMO_LATENCY_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, '0')}:00`,
  p50: Math.floor(Math.random() * 50) + 30,
  p95: Math.floor(Math.random() * 100) + 80,
  p99: Math.floor(Math.random() * 200) + 150,
}));

// Demo data - slowest endpoints
const DEMO_SLOWEST_ENDPOINTS = [
  { endpoint: '/api/v1/reports/generate', p50: 850, p95: 1200, p99: 2100, calls: 1250 },
  { endpoint: '/api/v1/search', p50: 320, p95: 580, p99: 1100, calls: 8500 },
  { endpoint: '/api/v1/export/csv', p50: 280, p95: 520, p99: 950, calls: 890 },
  { endpoint: '/api/v1/auth/oauth/callback', p50: 245, p95: 420, p99: 780, calls: 3200 },
  { endpoint: '/api/v1/analytics/dashboard', p50: 180, p95: 350, p99: 620, calls: 12000 },
];

// Demo data - latency distribution
const DEMO_LATENCY_DISTRIBUTION = [
  { range: '0-50ms', count: 45000, percentage: 45 },
  { range: '50-100ms', count: 32000, percentage: 32 },
  { range: '100-200ms', count: 15000, percentage: 15 },
  { range: '200-500ms', count: 6000, percentage: 6 },
  { range: '500ms+', count: 2000, percentage: 2 },
];

// Atlas Crew brand colors for latency
const CHART_COLORS = {
  p50: '#00B140',   // Atlas Crew Green (fast)
  p95: '#529EEC',   // Sky Blue
  p99: '#D62598',   // Atlas Crew Magenta (slow)
  distribution: '#0057B7', // Atlas Crew Blue
};

// Time Range Selector
function TimeRangeSelector({
  value,
  onChange,
}: {
  value: TimeRange;
  onChange: (v: TimeRange) => void;
}) {
  return (
    <div className="flex gap-1 bg-surface-card p-1">
      {TIME_RANGES.map((range) => (
        <button
          key={range.value}
          onClick={() => onChange(range.value)}
          className={clsx(
            'px-3 py-1.5 text-sm font-medium transition-colors',
            value === range.value
              ? 'bg-horizon-600 text-ink-primary'
              : 'text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle'
          )}
        >
          {range.label}
        </button>
      ))}
    </div>
  );
}

// Stat Card with trend
function StatCard({
  label,
  value,
  unit,
  trend,
  icon: Icon,
  color,
}: {
  label: string;
  value: string;
  unit?: string;
  trend?: { value: number; isGood: boolean };
  icon: React.ElementType;
  color: 'green' | 'sky' | 'red' | 'blue';
}) {
  const colorClasses = {
    green: 'text-green-400 bg-green-500/20',
    sky: 'text-sky-400 bg-sky-500/20',
    red: 'text-red-400 bg-red-500/20',
    blue: 'text-blue-400 bg-blue-500/20',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-ink-secondary">{label}</p>
          <div className="mt-1 flex items-baseline gap-1">
            <span className="text-2xl font-bold text-ink-primary">{value}</span>
            {unit && <span className="text-sm text-ink-secondary">{unit}</span>}
          </div>
          {trend && (
            <div
              className={clsx(
                'mt-2 flex items-center gap-1 text-sm',
                trend.isGood ? 'text-green-400' : 'text-red-400'
              )}
            >
              {trend.isGood ? (
                <TrendingDown className="w-4 h-4" />
              ) : (
                <TrendingUp className="w-4 h-4" />
              )}
              <span>{Math.abs(trend.value)}% vs previous</span>
            </div>
          )}
        </div>
        <div className={clsx('p-3', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </motion.div>
  );
}

// Latency Percentile Chart
function LatencyPercentileChart({ data }: { data: typeof DEMO_LATENCY_TIMELINE }) {
  const tooltipStyle = useMemo(() => getTooltipStyle(), []);
  const tickColor = useMemo(() => getAxisTickColor(), []);
  const gridStroke = useMemo(() => getGridStroke(), []);

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-ink-primary">Response Time Percentiles</h3>
          <p className="text-sm text-ink-secondary mt-1">P50, P95, P99 latency over time</p>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span className="text-ink-secondary">P50</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-sky-500" />
            <span className="text-ink-secondary">P95</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <span className="text-ink-secondary">P99</span>
          </div>
        </div>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => `${v}ms`}
            />
            <Tooltip
              contentStyle={tooltipStyle.contentStyle}
              labelStyle={tooltipStyle.labelStyle}
              itemStyle={tooltipStyle.itemStyle}
              formatter={(value: number, name: string) => [
                `${value}ms`,
                name.toUpperCase(),
              ]}
            />
            <Line
              type="monotone"
              dataKey="p50"
              stroke={CHART_COLORS.p50}
              strokeWidth={2}
              dot={false}
              name="p50"
            />
            <Line
              type="monotone"
              dataKey="p95"
              stroke={CHART_COLORS.p95}
              strokeWidth={2}
              dot={false}
              name="p95"
            />
            <Line
              type="monotone"
              dataKey="p99"
              stroke={CHART_COLORS.p99}
              strokeWidth={2}
              dot={false}
              name="p99"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Latency Distribution Chart
function LatencyDistributionChart({ data }: { data: typeof DEMO_LATENCY_DISTRIBUTION }) {
  const tooltipStyle = useMemo(() => getTooltipStyle(), []);
  const tickColor = useMemo(() => getAxisTickColor(), []);
  const gridStroke = useMemo(() => getGridStroke(), []);

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <h3 className="text-lg font-semibold text-ink-primary mb-4">Latency Distribution</h3>
      <div className="h-60">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ left: 10, right: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} vertical={false} />
            <XAxis
              dataKey="range"
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <Tooltip
              contentStyle={tooltipStyle.contentStyle}
              labelStyle={tooltipStyle.labelStyle}
              itemStyle={tooltipStyle.itemStyle}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Bar
              dataKey="count"
              fill={CHART_COLORS.distribution}
              radius={[0, 0, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 grid grid-cols-5 gap-2">
        {data.map((item) => (
          <div key={item.range} className="text-center">
            <p className="text-xs text-ink-secondary">{item.range}</p>
            <p className="text-sm font-medium text-ink-primary">{item.percentage}%</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// Slowest Endpoints Table
function SlowestEndpointsTable({ data }: { data: typeof DEMO_SLOWEST_ENDPOINTS }) {
  return (
    <div className="bg-surface-card border border-border-subtle">
      <div className="px-5 py-4 border-b border-border-subtle">
        <h3 className="text-lg font-semibold text-ink-primary">Slowest Endpoints</h3>
        <p className="text-sm text-ink-secondary mt-1">Endpoints with highest latency</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-ink-secondary border-b border-border-subtle">
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium text-right">P50</th>
              <th className="px-5 py-3 font-medium text-right">P95</th>
              <th className="px-5 py-3 font-medium text-right">P99</th>
              <th className="px-5 py-3 font-medium text-right">Calls</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item, idx) => (
              <tr
                key={item.endpoint}
                className="border-b border-border-subtle/50 hover:bg-surface-subtle transition-colors"
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <span className="text-ink-muted text-sm w-6">{idx + 1}</span>
                    <code className="text-blue-400 bg-blue-500/10 px-2 py-0.5 text-sm">
                      {item.endpoint}
                    </code>
                  </div>
                </td>
                <td className="px-5 py-3 text-right">
                  <span className="text-green-400 font-medium">{item.p50}ms</span>
                </td>
                <td className="px-5 py-3 text-right">
                  <span className="text-sky-400 font-medium">{item.p95}ms</span>
                </td>
                <td className="px-5 py-3 text-right">
                  <span className={clsx(
                    'font-medium',
                    item.p99 > 1000 ? 'text-red-400' : 'text-orange-400'
                  )}>
                    {item.p99}ms
                  </span>
                </td>
                <td className="px-5 py-3 text-right text-ink-secondary">
                  {item.calls.toLocaleString()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function ResponseTimesPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const isLoading = false;

  // Calculate summary stats from demo data
  const stats = useMemo(() => {
    const latestData = DEMO_LATENCY_TIMELINE;
    const avgP50 = Math.round(
      latestData.reduce((sum, d) => sum + d.p50, 0) / latestData.length
    );
    const avgP95 = Math.round(
      latestData.reduce((sum, d) => sum + d.p95, 0) / latestData.length
    );
    const avgP99 = Math.round(
      latestData.reduce((sum, d) => sum + d.p99, 0) / latestData.length
    );
    const slowRequests = DEMO_LATENCY_DISTRIBUTION
      .filter((d) => d.range === '500ms+')
      .reduce((sum, d) => sum + d.count, 0);

    return { avgP50, avgP95, avgP99, slowRequests };
  }, []);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Response Times</h1>
          <p className="text-ink-secondary mt-1">Loading performance data...</p>
        </div>
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Response Times</h1>
          <p className="text-ink-secondary mt-1">Performance metrics and latency analysis</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="P50 (Median)"
          value={stats.avgP50.toString()}
          unit="ms"
          trend={{ value: 5, isGood: true }}
          icon={Clock}
          color="green"
        />
        <StatCard
          label="P95"
          value={stats.avgP95.toString()}
          unit="ms"
          trend={{ value: 8, isGood: true }}
          icon={Zap}
          color="sky"
        />
        <StatCard
          label="P99"
          value={stats.avgP99.toString()}
          unit="ms"
          trend={{ value: 12, isGood: false }}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          label="Slow Requests"
          value={(stats.slowRequests / 1000).toFixed(1) + 'k'}
          trend={{ value: 3, isGood: true }}
          icon={TrendingDown}
          color="blue"
        />
      </div>

      {/* Latency Timeline */}
      <LatencyPercentileChart data={DEMO_LATENCY_TIMELINE} />

      {/* Distribution + Slowest Endpoints */}
      <div className="grid grid-cols-3 gap-6">
        <LatencyDistributionChart data={DEMO_LATENCY_DISTRIBUTION} />
        <div className="col-span-2">
          <SlowestEndpointsTable data={DEMO_SLOWEST_ENDPOINTS} />
        </div>
      </div>
    </div>
  );
}
