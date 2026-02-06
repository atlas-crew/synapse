/**
 * Traffic Analytics Page
 * Detailed API traffic patterns, trends, and breakdowns
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  TrendingUp,
  ArrowUpRight,
  ArrowDownRight,
  Clock,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useDocumentTitle } from '../../../hooks/useDocumentTitle';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import { useTrafficTimeline } from '../../../stores/beamStore';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';
import { GeoTrafficMap } from '../../../components/beam/analytics/GeoTrafficMap';
import { LatencyHistogram } from '../../../components/beam/analytics/LatencyHistogram';
import { ErrorRateChart } from '../../../components/beam/analytics/ErrorRateChart';
import { getTooltipStyle, getAxisTickColor, getGridStroke } from '../../../lib/chartTheme';

type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d';

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h', label: '1 Hour' },
  { value: '6h', label: '6 Hours' },
  { value: '24h', label: '24 Hours' },
  { value: '7d', label: '7 Days' },
  { value: '30d', label: '30 Days' },
];

// Demo data
const DEMO_TRAFFIC_HOURLY = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, '0')}:00`,
  requests: Math.floor(Math.random() * 5000) + 1000,
  blocked: Math.floor(Math.random() * 100) + 10,
  allowed: Math.floor(Math.random() * 4900) + 900,
}));

const DEMO_METHOD_BREAKDOWN = [
  { method: 'GET', count: 45200, percentage: 65 },
  { method: 'POST', count: 18500, percentage: 27 },
  { method: 'PUT', count: 3500, percentage: 5 },
  { method: 'DELETE', count: 2100, percentage: 3 },
];

const DEMO_TOP_ENDPOINTS = [
  { endpoint: '/api/v1/users', requests: 12500, blocked: 45 },
  { endpoint: '/api/v1/products', requests: 9800, blocked: 23 },
  { endpoint: '/api/v1/orders', requests: 7600, blocked: 89 },
  { endpoint: '/api/v1/auth/login', requests: 5400, blocked: 156 },
  { endpoint: '/api/v1/search', requests: 4200, blocked: 12 },
];

// Atlas Crew brand colors
const CHART_COLORS = {
  requests: '#0057B7',  // Atlas Crew Blue
  blocked: '#D62598',   // Atlas Crew Magenta
  allowed: '#00B140',   // Atlas Crew Green
  get: '#0057B7',       // Atlas Crew Blue
  post: '#00B140',      // Atlas Crew Green
  put: '#E35205',       // Atlas Crew Orange
  delete: '#D62598',    // Atlas Crew Magenta
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

// Stat Card
function StatCard({
  label,
  value,
  trend,
  icon: Icon,
}: {
  label: string;
  value: string;
  trend?: { value: number; label: string };
  icon: React.ElementType;
}) {
  const isPositive = trend && trend.value >= 0;
  const TrendIcon = isPositive ? ArrowUpRight : ArrowDownRight;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-ink-secondary">{label}</p>
          <p className="mt-1 text-2xl font-bold text-ink-primary">{value}</p>
          {trend && (
            <div
              className={clsx(
                'mt-2 flex items-center gap-1 text-sm',
                isPositive ? 'text-green-400' : 'text-red-400'
              )}
            >
              <TrendIcon className="w-4 h-4" />
              <span>
                {Math.abs(trend.value)}% {trend.label}
              </span>
            </div>
          )}
        </div>
        <div className="p-3 bg-surface-subtle/50">
          <Icon className="w-6 h-6 text-horizon-400" />
        </div>
      </div>
    </motion.div>
  );
}

// Traffic Timeline Chart
function TrafficTimelineChart({ data }: { data: typeof DEMO_TRAFFIC_HOURLY }) {
  const tooltipStyle = useMemo(() => getTooltipStyle(), []);
  const tickColor = useMemo(() => getAxisTickColor(), []);
  const gridStroke = useMemo(() => getGridStroke(), []);

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-ink-primary">Traffic Over Time</h3>
          <p className="text-sm text-ink-secondary mt-1">Requests per hour</p>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-500" />
            <span className="text-ink-secondary">Total</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-green-500" />
            <span className="text-ink-secondary">Allowed</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500" />
            <span className="text-ink-secondary">Blocked</span>
          </div>
        </div>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="requestsGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.requests} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.requests} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="allowedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.allowed} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.allowed} stopOpacity={0} />
              </linearGradient>
            </defs>
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
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <Tooltip
              contentStyle={tooltipStyle.contentStyle}
              labelStyle={tooltipStyle.labelStyle}
              itemStyle={tooltipStyle.itemStyle}
            />
            <Area
              type="monotone"
              dataKey="requests"
              stroke={CHART_COLORS.requests}
              fill="url(#requestsGrad)"
              strokeWidth={2}
              name="Total"
            />
            <Area
              type="monotone"
              dataKey="allowed"
              stroke={CHART_COLORS.allowed}
              fill="url(#allowedGrad)"
              strokeWidth={2}
              name="Allowed"
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke={CHART_COLORS.blocked}
              fill="transparent"
              strokeWidth={2}
              name="Blocked"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Method Breakdown Chart
function MethodBreakdownChart({ data }: { data: typeof DEMO_METHOD_BREAKDOWN }) {
  const tooltipStyle = useMemo(() => getTooltipStyle(), []);
  const tickColor = useMemo(() => getAxisTickColor(), []);
  const gridStroke = useMemo(() => getGridStroke(), []);

  const colors: Record<string, string> = {
    GET: CHART_COLORS.get,
    POST: CHART_COLORS.post,
    PUT: CHART_COLORS.put,
    DELETE: CHART_COLORS.delete,
  };

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <h3 className="text-lg font-semibold text-ink-primary mb-4">Request Methods</h3>
      <div className="h-60">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <YAxis
              type="category"
              dataKey="method"
              tick={{ fill: tickColor, fontSize: 12 }}
              axisLine={false}
              tickLine={false}
              width={60}
            />
            <Tooltip
              contentStyle={tooltipStyle.contentStyle}
              labelStyle={tooltipStyle.labelStyle}
              itemStyle={tooltipStyle.itemStyle}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Bar
              dataKey="count"
              fill={CHART_COLORS.requests}
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              shape={(props: any) => {
                const { x, y, width, height, payload } = props;
                return (
                  <rect
                    x={x}
                    y={y}
                    width={width}
                    height={height}
                    fill={colors[payload.method] || CHART_COLORS.requests}
                    rx={0}
                    ry={0}
                  />
                );
              }}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 grid grid-cols-4 gap-2">
        {data.map((item) => (
          <div key={item.method} className="text-center">
            <div
              className="w-4 h-4 mx-auto mb-1"
              style={{ backgroundColor: colors[item.method] }}
            />
            <p className="text-xs text-ink-secondary">{item.method}</p>
            <p className="text-sm font-medium text-ink-primary">{item.percentage}%</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// Top Endpoints Table
function TopEndpointsTable({ data }: { data: typeof DEMO_TOP_ENDPOINTS }) {
  return (
    <div className="bg-surface-card border border-border-subtle">
      <div className="px-5 py-4 border-b border-border-subtle">
        <h3 className="text-lg font-semibold text-ink-primary">Top Endpoints</h3>
        <p className="text-sm text-ink-secondary mt-1">Highest traffic endpoints</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-ink-secondary border-b border-border-subtle">
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium text-right">Requests</th>
              <th className="px-5 py-3 font-medium text-right">Blocked</th>
              <th className="px-5 py-3 font-medium text-right">Block Rate</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item, idx) => {
              const blockRate = ((item.blocked / item.requests) * 100).toFixed(2);
              return (
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
                  <td className="px-5 py-3 text-right text-ink-primary font-medium">
                    {item.requests.toLocaleString()}
                  </td>
                  <td className="px-5 py-3 text-right text-red-400">
                    {item.blocked.toLocaleString()}
                  </td>
                  <td className="px-5 py-3 text-right">
                    <span
                      className={clsx(
                        'px-2 py-0.5 text-xs font-medium',
                        parseFloat(blockRate) < 1
                          ? 'text-green-400 bg-green-500/20'
                          : parseFloat(blockRate) < 3
                          ? 'text-sky-400 bg-sky-500/20'
                          : 'text-red-400 bg-red-500/20'
                      )}
                    >
                      {blockRate}%
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function TrafficAnalyticsPage() {
  useDocumentTitle('Beam - Traffic Analytics');
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const trafficData = useTrafficTimeline();
  // Will be used when real-time stats are integrated
  // const stats = useBeamStats();

  // Transform traffic data to chart format or use demo data
  const displayData = useMemo(() => {
    if (trafficData.length > 0) {
      return trafficData.map((d) => ({
        time: new Date(d.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }),
        requests: d.requests,
        blocked: d.blocked,
        allowed: d.requests - d.blocked,
      }));
    }
    return DEMO_TRAFFIC_HOURLY;
  }, [trafficData]);
  const isLoading = false;

  // Calculate summary stats
  const totalRequests = useMemo(
    () => displayData.reduce((sum, d) => sum + d.requests, 0),
    [displayData]
  );
  const totalBlocked = useMemo(
    () => displayData.reduce((sum, d) => sum + d.blocked, 0),
    [displayData]
  );
  const avgRequestsPerHour = Math.round(totalRequests / displayData.length);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Traffic Analytics</h1>
          <p className="text-ink-secondary mt-1">Loading traffic data...</p>
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
          <h1 className="text-2xl font-bold text-ink-primary">Traffic Analytics</h1>
          <p className="text-ink-secondary mt-1">API traffic patterns and trends</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Total Requests"
          value={`${(totalRequests / 1000).toFixed(1)}k`}
          trend={{ value: 12, label: 'vs previous' }}
          icon={Activity}
        />
        <StatCard
          label="Blocked Requests"
          value={totalBlocked.toLocaleString()}
          trend={{ value: -8, label: 'vs previous' }}
          icon={TrendingUp}
        />
        <StatCard
          label="Avg Requests/Hour"
          value={avgRequestsPerHour.toLocaleString()}
          trend={{ value: 5, label: 'vs previous' }}
          icon={Clock}
        />
        <StatCard
          label="Block Rate"
          value={`${((totalBlocked / totalRequests) * 100).toFixed(2)}%`}
          icon={TrendingUp}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Traffic Timeline */}
        <TrafficTimelineChart data={displayData} />
        
        {/* Geo Distribution */}
        <GeoTrafficMap />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <LatencyHistogram />
        <ErrorRateChart />
      </div>

      {/* Method Breakdown + Top Endpoints */}
      <div className="grid grid-cols-3 gap-6">
        <MethodBreakdownChart data={DEMO_METHOD_BREAKDOWN} />
        <div className="col-span-2">
          <TopEndpointsTable data={DEMO_TOP_ENDPOINTS} />
        </div>
      </div>
    </div>
  );
}
