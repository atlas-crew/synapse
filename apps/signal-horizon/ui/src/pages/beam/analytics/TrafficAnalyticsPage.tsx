/**
 * Traffic Analytics Page
 * Detailed API traffic patterns, trends, and breakdowns
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { Activity, TrendingUp, Clock } from 'lucide-react';
import { useDocumentTitle } from '../../../hooks/useDocumentTitle';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
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
import {
  SectionHeader,
  Stack,
  Panel,
  StatCard,
  DataTable,
  ValuePill,
  TimeRangeSelector,
  alpha,
  axisDefaults,
  colors,
  gridDefaultsSoft,
  tooltipDefaults,
  xAxisNoLine,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
} from '@/ui';

// Matches the @/ui TimeRangeSelector PresetRange type — only the subset
// this page exposes. The selector is intentionally unwired until the
// traffic query accepts a range parameter; state is preserved so the
// component works as a visual affordance without silently disabling.
type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d';
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const TIME_RANGE_PRESETS: TimeRange[] = ['1h', '6h', '24h', '7d', '30d'];

// Demo data. Deterministic per-hour curve rather than Math.random() so
// values don't shuffle on hot-reload or re-mount — shuffling values in a
// dev environment made it impossible to eyeball chart tweaks.
const DEMO_TRAFFIC_HOURLY = Array.from({ length: 24 }, (_, i) => {
  // Gentle diurnal-ish curve: low overnight, peak mid-afternoon.
  const wave = Math.sin(((i - 3) / 24) * Math.PI * 2) * 0.45 + 0.55;
  const requests = Math.round(1500 + wave * 4500);
  const blocked = Math.round(15 + wave * 80);
  return {
    time: `${String(i).padStart(2, '0')}:00`,
    requests,
    blocked,
    allowed: Math.max(0, requests - blocked),
  };
});

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
  allowed: colors.blue,
  blocked: colors.red,
  get: colors.blue,
  post: colors.green,
  put: colors.orange,
  delete: colors.magenta,
};

// Traffic Timeline Chart
function TrafficTimelineChart({ data }: { data: typeof DEMO_TRAFFIC_HOURLY }) {
  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Traffic Over Time"
          description="Allowed + Blocked requests per hour (total implied)"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
        <Stack direction="row" align="center" gap="md" className="text-sm">
          <Stack direction="row" align="center" gap="sm">
            <div className="w-3 h-3" style={{ backgroundColor: CHART_COLORS.allowed }} />
            <span className="text-ink-secondary">Allowed</span>
          </Stack>
          <Stack direction="row" align="center" gap="sm">
            <div className="w-3 h-3" style={{ backgroundColor: CHART_COLORS.blocked }} />
            <span className="text-ink-secondary">Blocked</span>
          </Stack>
        </Stack>
      </Panel.Header>
      <Panel.Body className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="allowedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={CHART_COLORS.allowed} stopOpacity={0.22} />
                <stop offset="100%" stopColor={CHART_COLORS.allowed} stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={CHART_COLORS.blocked} stopOpacity={0.28} />
                <stop offset="100%" stopColor={CHART_COLORS.blocked} stopOpacity={0.03} />
              </linearGradient>
            </defs>
            <CartesianGrid {...gridDefaultsSoft} />
            <XAxis dataKey="time" {...xAxisNoLine} />
            <YAxis
              {...axisDefaults.y}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <Tooltip
              {...tooltipDefaults}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Area
              type="monotone"
              dataKey="allowed"
              stackId="traffic"
              stroke={CHART_COLORS.allowed}
              fill="url(#allowedGrad)"
              strokeWidth={2.5}
              dot={false}
              activeDot={{
                r: 3.5,
                fill: colors.gray.light,
                stroke: CHART_COLORS.allowed,
                strokeWidth: 2,
              }}
              name="Allowed"
              style={{ filter: `drop-shadow(0 0 6px ${alpha(CHART_COLORS.allowed, 0.35)})` }}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stackId="traffic"
              stroke={CHART_COLORS.blocked}
              fill="url(#blockedGrad)"
              strokeWidth={2.5}
              dot={false}
              activeDot={{
                r: 3.5,
                fill: colors.gray.light,
                stroke: CHART_COLORS.blocked,
                strokeWidth: 2,
              }}
              name="Blocked"
              style={{ filter: `drop-shadow(0 0 6px ${alpha(CHART_COLORS.blocked, 0.28)})` }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </Panel.Body>
    </Panel>
  );
}

// Method Breakdown Chart
function MethodBreakdownChart({ data }: { data: typeof DEMO_METHOD_BREAKDOWN }) {
  const methodColors: Record<string, string> = {
    GET: CHART_COLORS.get,
    POST: CHART_COLORS.post,
    PUT: CHART_COLORS.put,
    DELETE: CHART_COLORS.delete,
  };

  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Request Methods"
          description="HTTP verb distribution"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Panel.Header>
      <Panel.Body className="h-60">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
            <CartesianGrid {...gridDefaultsSoft} horizontal={false} />
            <XAxis
              type="number"
              tick={axisDefaults.x.tick}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v)}
            />
            <YAxis
              type="category"
              dataKey="method"
              tick={axisDefaults.y.tick}
              axisLine={false}
              tickLine={false}
              width={60}
            />
            <Tooltip
              {...tooltipDefaults}
              formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            />
            <Bar dataKey="count">
              {data.map((entry) => (
                <Cell
                  key={entry.method}
                  fill={methodColors[entry.method] || CHART_COLORS.allowed}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Panel.Body>
      <div className="px-6 pb-6 grid grid-cols-4 gap-2">
        {data.map((item) => (
          <div key={item.method} className="text-center">
            <div
              className="w-4 h-4 mx-auto mb-1"
              style={{ backgroundColor: methodColors[item.method] }}
            />
            <p className="text-xs text-ink-secondary">{item.method}</p>
            <p className="text-sm font-medium text-ink-primary">{item.percentage}%</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// Top Endpoints Table
//
// Wrapped in <Panel> with Panel.Body padding="none" so Panel owns the
// card chrome and <DataTable card={false}> renders without its own
// second border. Block-rate pill color is chosen by a small helper
// mapping that reuses the design-system ValuePill component rather
// than hand-rolled colored spans.
function blockRatePillColor(rate: number): 'green' | 'orange' | 'red' {
  if (rate < 1) return 'green';
  if (rate < 3) return 'orange';
  return 'red';
}

function TopEndpointsTable({ data }: { data: typeof DEMO_TOP_ENDPOINTS }) {
  // Pre-compute block rate once per row so it's available for both the
  // sort-safe value display and the pill color. Building the row shape
  // DataTable expects (flat Record<string, any>) lets the column render
  // functions stay focused on presentation.
  const rows = data.map((item, idx) => ({
    idx: idx + 1,
    endpoint: item.endpoint,
    requests: item.requests,
    blocked: item.blocked,
    blockRate: (item.blocked / item.requests) * 100,
  }));

  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Top Endpoints"
          description="Highest traffic endpoints"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Panel.Header>
      <Panel.Body padding="none">
        <DataTable
          card={false}
          columns={[
            {
              key: 'endpoint',
              label: 'Endpoint',
              render: (_v, row) => (
                <Stack direction="row" align="center" gap="smPlus">
                  <span className="text-ink-muted text-sm w-6">{row.idx}</span>
                  <code className="text-ac-blue bg-ac-blue/10 px-2 py-0.5 text-sm">
                    {row.endpoint}
                  </code>
                </Stack>
              ),
            },
            {
              key: 'requests',
              label: 'Requests',
              align: 'right',
              render: (v) => (
                <span className="text-ink-primary font-medium">
                  {Number(v).toLocaleString()}
                </span>
              ),
            },
            {
              key: 'blocked',
              label: 'Blocked',
              align: 'right',
              render: (v) => (
                <span className="text-status-error">
                  {Number(v).toLocaleString()}
                </span>
              ),
            },
            {
              key: 'blockRate',
              label: 'Block Rate',
              align: 'right',
              render: (v) => (
                <ValuePill
                  value={`${Number(v).toFixed(2)}%`}
                  color={blockRatePillColor(Number(v))}
                />
              ),
            },
          ]}
          data={rows}
        />
      </Panel.Body>
    </Panel>
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
        time: new Date(d.timestamp).toLocaleTimeString('en-US', {
          hour: '2-digit',
          minute: '2-digit',
        }),
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
    [displayData],
  );
  const totalBlocked = useMemo(
    () => displayData.reduce((sum, d) => sum + d.blocked, 0),
    [displayData],
  );
  const avgRequestsPerHour = Math.round(totalRequests / displayData.length);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <SectionHeader
          title="Traffic Analytics"
          description="Loading traffic data..."
          size="h1"
          style={PAGE_HEADER_STYLE}
          titleStyle={PAGE_TITLE_STYLE}
        />
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <SectionHeader
        title="Traffic Analytics"
        description="API traffic patterns and trends"
        size="h1"
        style={PAGE_HEADER_STYLE}
        titleStyle={PAGE_TITLE_STYLE}
        actions={
          <TimeRangeSelector
            value={timeRange}
            onChange={(v) => setTimeRange(v as TimeRange)}
            presets={TIME_RANGE_PRESETS}
          />
        }
      />

      {/* Stats Grid. Each card wraps the @/ui <StatCard> in a motion.div
          so the entrance animation stays (framer-motion was the one
          thing worth preserving from the old local component). */}
      <div className="grid grid-cols-4 gap-4">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <StatCard
            label="Total Requests"
            value={`${(totalRequests / 1000).toFixed(1)}k`}
            trend={{ value: 12, label: 'vs previous' }}
            icon={<Activity className="w-6 h-6" />}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <StatCard
            label="Blocked Requests"
            value={totalBlocked.toLocaleString()}
            trend={{ value: -8, label: 'vs previous' }}
            icon={<TrendingUp className="w-6 h-6" />}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <StatCard
            label="Avg Requests/Hour"
            value={avgRequestsPerHour.toLocaleString()}
            trend={{ value: 5, label: 'vs previous' }}
            icon={<Clock className="w-6 h-6" />}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <StatCard
            label="Block Rate"
            value={`${((totalBlocked / totalRequests) * 100).toFixed(2)}%`}
            icon={<TrendingUp className="w-6 h-6" />}
          />
        </motion.div>
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
