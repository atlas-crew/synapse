/**
 * Bandwidth Dashboard Page
 * Fleet-wide bandwidth metrics, timeline visualization, and billing breakdown
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowUpRight,
  ArrowDownLeft,
  Activity,
  DollarSign,
  Server,
  TrendingUp,
  Download,
  type LucideIcon,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import { PAGE_TITLE_STYLE, Panel, SectionHeader, Stack, Text, alpha, axisDefaults, barDefaults, chartColors, colors, tooltipDefaults } from '@/ui';
import {
  useBandwidthDashboard,
  type BandwidthDataPoint,
  type EndpointBandwidthStats,
} from '../../hooks/fleet/useBandwidth';
import { CardSkeleton, TableSkeleton } from '../../components/LoadingStates';

// ============================================================================
// Constants
// ============================================================================

const COLORS = {
  ingress: colors.blue,
  egress: colors.green,
  primary: colors.blue,
  secondary: colors.skyBlue,
  accent: colors.red,
};
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const STATE_HEADER_TITLE_STYLE = {
  fontSize: '18px',
  lineHeight: '28px',
  fontWeight: 600,
};

// ============================================================================
// Utility Functions
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toLocaleString();
}

function formatCurrency(amount: number): string {
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
  }).format(amount);
}

// ============================================================================
// Stat Card Component
// ============================================================================

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: string;
  subValue?: string;
  trend?: { value: number; label: string };
  color: string;
  bgColor: string;
}

function StatCard({ icon: Icon, label, value, subValue, trend, color, bgColor }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border-t-4 border-border-subtle shadow-card p-6"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-ink-secondary">{label}</p>
          <p className="mt-2 text-3xl font-bold text-ink-primary">{value}</p>
          {subValue && <p className="text-sm text-ink-muted mt-1">{subValue}</p>}
          {trend && (
            <Stack
              direction="row"
              align="center"
              gap="xs"
              className={clsx('mt-2 text-sm')}
              style={{ color: trend.value >= 0 ? colors.green : colors.red }}
            >
              <TrendingUp className={clsx('w-4 h-4', trend.value < 0 && 'rotate-180')} />
              <span>
                {Math.abs(trend.value)}% {trend.label}
              </span>
            </Stack>
          )}
        </div>
        <div className="p-3" style={{ backgroundColor: bgColor }}>
          <Icon className="w-6 h-6" style={{ color }} />
        </div>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Timeline Chart Component
// ============================================================================

interface TimelineChartProps {
  data: BandwidthDataPoint[];
  granularity: '1m' | '5m' | '1h';
}

function TimelineChart({ data, granularity }: TimelineChartProps) {
  const formattedData = useMemo(
    () =>
      data.map((d) => ({
        ...d,
        time: new Date(d.timestamp).toLocaleTimeString([], {
          hour: '2-digit',
          minute: '2-digit',
        }),
        ingressMB: d.bytesIn / (1024 * 1024),
        egressMB: d.bytesOut / (1024 * 1024),
      })),
    [data],
  );

  return (
    <Panel tone="default" padding="md" spacing="none" as="div">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-ink-primary">Bandwidth Timeline</h3>
        <Stack direction="row" align="center" gap="md" className="text-sm">
          <Stack direction="row" align="center" gap="sm">
            <div className="w-3 h-3" style={{ backgroundColor: COLORS.ingress }} />
            <span className="text-ink-secondary">Ingress</span>
          </Stack>
          <Stack direction="row" align="center" gap="sm">
            <div className="w-3 h-3" style={{ backgroundColor: COLORS.egress }} />
            <span className="text-ink-secondary">Egress</span>
          </Stack>
          <span className="text-ink-muted text-xs">({granularity} intervals)</span>
        </Stack>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={formattedData} margin={{ top: 5, right: 5, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="ingressGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.ingress} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.ingress} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="egressGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.egress} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.egress} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" {...axisDefaults.x} axisLine={false} />
            <YAxis {...axisDefaults.y} tickFormatter={(v) => `${v.toFixed(0)} MB`} />
            <Tooltip
              {...tooltipDefaults}
              formatter={(value: number, name: string) => [
                `${value.toFixed(2)} MB`,
                name === 'ingressMB' ? 'Ingress' : 'Egress',
              ]}
            />
            <Area
              type="monotone"
              dataKey="ingressMB"
              stroke={COLORS.ingress}
              fill="url(#ingressGradient)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="egressMB"
              stroke={COLORS.egress}
              fill="url(#egressGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}

// ============================================================================
// Top Endpoints Table
// ============================================================================

interface TopEndpointsTableProps {
  endpoints: EndpointBandwidthStats[];
}

function TopEndpointsTable({ endpoints }: TopEndpointsTableProps) {
  return (
    <Panel tone="default" padding="none" spacing="none" as="div">
      <div className="px-5 py-4 border-b border-border-subtle flex items-center justify-between">
        <h3 className="text-lg font-semibold text-ink-primary">Top Endpoints by Bandwidth</h3>
        <span className="text-sm text-ink-secondary">{endpoints.length} endpoints</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <caption className="sr-only">Top endpoints ranked by bandwidth consumption</caption>
          <thead>
            <tr className="text-left text-sm text-ink-secondary border-b border-border-subtle">
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium text-right">Ingress</th>
              <th className="px-5 py-3 font-medium text-right">Egress</th>
              <th className="px-5 py-3 font-medium text-right">Requests</th>
              <th className="px-5 py-3 font-medium text-right">Avg Size</th>
            </tr>
          </thead>
          <tbody>
            {endpoints.slice(0, 10).map((ep) => (
              <tr
                key={ep.endpoint}
                className="border-b border-border-subtle/50 hover:bg-surface-subtle transition-colors"
              >
                <td className="px-5 py-3 text-sm">
                  <code
                    className="px-2 py-0.5"
                    style={{ color: colors.blue, backgroundColor: alpha(colors.blue, 0.1) }}
                  >
                    {ep.endpoint}
                  </code>
                  <div className="mt-1 flex gap-1">
                    {ep.methods.map((m) => (
                      <span
                        key={m}
                        className="text-xs text-ink-muted bg-surface-subtle px-1.5 py-0.5"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-5 py-3 text-sm text-ink-secondary text-right">
                  <Stack direction="row" align="center" justify="flex-end" gap="xs">
                    <ArrowDownLeft className="w-3 h-3" style={{ color: colors.blue }} />
                    {formatBytes(ep.bytesIn)}
                  </Stack>
                </td>
                <td className="px-5 py-3 text-sm text-ink-secondary text-right">
                  <Stack direction="row" align="center" justify="flex-end" gap="xs">
                    <ArrowUpRight className="w-3 h-3" style={{ color: colors.green }} />
                    {formatBytes(ep.bytesOut)}
                  </Stack>
                </td>
                <td className="px-5 py-3 text-sm text-ink-primary text-right font-medium">
                  {formatNumber(ep.requestCount)}
                </td>
                <td className="px-5 py-3 text-sm text-ink-secondary text-right">
                  {formatBytes(ep.avgResponseSize)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

// ============================================================================
// Billing Panel
// ============================================================================

interface BillingPanelProps {
  totalTransfer: number;
  ingressBytes: number;
  egressBytes: number;
  estimatedCost: number;
  costPerGb: number;
  periodStart: string;
  periodEnd: string;
}

function BillingPanel({
  totalTransfer,
  ingressBytes,
  egressBytes,
  estimatedCost,
  costPerGb,
  periodStart,
  periodEnd,
}: BillingPanelProps) {
  const pieData = [
    { name: 'Ingress', value: ingressBytes },
    { name: 'Egress', value: egressBytes },
  ];

  const startDate = new Date(periodStart).toLocaleDateString();
  const endDate = new Date(periodEnd).toLocaleDateString();

  return (
    <Panel tone="default" padding="md" spacing="none" as="div">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-ink-primary">Billing Summary</h3>
        <span className="text-xs text-ink-muted">
          {startDate} - {endDate}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div className="bg-surface-subtle p-3">
          <Stack direction="row" align="center" gap="sm" className="text-ink-secondary text-sm">
            <Download className="w-4 h-4" />
            Total Transfer
          </Stack>
          <div className="text-2xl font-bold text-ink-primary mt-1">
            {formatBytes(totalTransfer)}
          </div>
        </div>
        <div className="bg-surface-subtle p-3">
          <Stack direction="row" align="center" gap="sm" className="text-ink-secondary text-sm">
            <DollarSign className="w-4 h-4" />
            Estimated Cost
          </Stack>
          <div className="text-2xl font-bold mt-1" style={{ color: colors.green }}>
            {formatCurrency(estimatedCost)}
          </div>
          <div className="text-xs text-ink-muted mt-1">@ {formatCurrency(costPerGb)}/GB</div>
        </div>
      </div>

      <div className="h-40">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={pieData}
              cx="50%"
              cy="50%"
              innerRadius={40}
              outerRadius={60}
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
            >
              {pieData.map((_, index) => (
                <Cell key={`cell-${index}`} fill={index === 0 ? COLORS.ingress : COLORS.egress} />
              ))}
            </Pie>
            <Legend
              formatter={(value, entry) => (
                <span className="text-ink-secondary text-sm">
                  {value}: {formatBytes(entry.payload?.value || 0)}
                </span>
              )}
            />
            <Tooltip {...tooltipDefaults} formatter={(value: number) => formatBytes(value)} />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}

// ============================================================================
// Sensor Breakdown Chart
// ============================================================================

interface SensorBreakdownProps {
  sensors: Array<{
    sensorId: string;
    sensorName: string;
    bytes: number;
    percentage: number;
    requestCount: number;
  }>;
}

function SensorBreakdown({ sensors }: SensorBreakdownProps) {
  const chartData = useMemo(
    () =>
      sensors.map((s) => ({
        id: s.sensorId,
        name: s.sensorName,
        bytes: s.bytes / (1024 * 1024 * 1024), // Convert to GB
        requests: s.requestCount,
      })),
    [sensors],
  );

  return (
    <Panel tone="default" padding="md" spacing="none" as="div">
      <h3 className="text-lg font-semibold text-ink-primary mb-4">Bandwidth by Sensor</h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 100 }}>
            <XAxis type="number" {...axisDefaults.x} tickFormatter={(v) => `${v.toFixed(0)} GB`} />
            <YAxis type="category" dataKey="name" {...axisDefaults.y} width={100} />
            <Tooltip
              {...tooltipDefaults}
              formatter={(value: number) => [`${value.toFixed(2)} GB`, 'Bandwidth']}
            />
            <Bar dataKey="bytes" radius={barDefaults.radius} opacity={barDefaults.opacity}>
              {chartData.map((d, index) => (
                <Cell key={d.id} fill={chartColors[index % chartColors.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 space-y-2">
        {sensors.map((sensor, index) => (
          <div key={sensor.sensorId} className="flex items-center justify-between text-sm">
            <Stack direction="row" align="center" gap="sm">
              <div
                className="w-3 h-3"
                style={{ backgroundColor: chartColors[index % chartColors.length] }}
              />
              <span className="text-ink-secondary">{sensor.sensorName}</span>
            </Stack>
            <Stack direction="row" align="center" gap="md">
              <span className="text-ink-muted">{formatNumber(sensor.requestCount)} req</span>
              <span className="text-ink-primary font-medium">{sensor.percentage}%</span>
            </Stack>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ============================================================================
// Main Page Component
// ============================================================================

export default function BandwidthDashboardPage() {
  const [timelineGranularity, setTimelineGranularity] = useState<'1m' | '5m' | '1h'>('5m');
  const [timelineDuration, setTimelineDuration] = useState(60);

  const { fleetStats, timeline, endpoints, billing, isLoading, isError, error } =
    useBandwidthDashboard({
      timelineGranularity,
      timelineDuration,
    });

  if (isLoading) {
    return (
      <div
        className="p-6 space-y-6"
        role="main"
        aria-busy="true"
        aria-label="Loading bandwidth dashboard"
      >
        <div className="flex items-center justify-between">
          <SectionHeader
            title="Bandwidth Dashboard"
            description="Loading bandwidth metrics..."
            size="h1"
            style={PAGE_HEADER_STYLE}
            titleStyle={PAGE_TITLE_STYLE}
          />
        </div>
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
        <CardSkeleton />
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <TableSkeleton rows={5} />
          </div>
          <CardSkeleton />
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="p-6">
        <div
          className="border p-4"
          style={{
            backgroundColor: alpha(colors.red, 0.1),
            borderColor: alpha(colors.red, 0.5),
          }}
        >
          <SectionHeader
            title="Error Loading Dashboard"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={{ ...STATE_HEADER_TITLE_STYLE, color: colors.red }}
          />
          <p className="text-ink-secondary mt-1">
            {error instanceof Error ? error.message : 'Unknown error'}
          </p>
        </div>
      </div>
    );
  }

  // Safely extract data with null guards
  const stats = fleetStats.data;
  const timelineData = timeline.data;
  const endpointData = endpoints.data;
  const billingData = billing.data;

  // Handle case where queries succeeded but returned no data
  if (!stats && !timelineData && !endpointData && !billingData) {
    return (
      <div className="p-6">
        <div
          className="border p-4"
          style={{
            backgroundColor: alpha(colors.orange, 0.1),
            borderColor: alpha(colors.orange, 0.5),
          }}
        >
          <SectionHeader
            title="No Data Available"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={{ ...STATE_HEADER_TITLE_STYLE, color: colors.orange }}
          />
          <p className="text-ink-secondary mt-1">
            Bandwidth data is not currently available. This may be because no sensors are connected
            or reporting metrics.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Bandwidth dashboard">
      {/* Header */}
      <header className="flex items-center justify-between">
        <SectionHeader
          title="Bandwidth Dashboard"
          description="Fleet-wide bandwidth metrics and billing analysis"
          size="h1"
          style={PAGE_HEADER_STYLE}
          titleStyle={PAGE_TITLE_STYLE}
        />
        <Stack direction="row" align="center" gap="md">
          <select
            value={timelineGranularity}
            onChange={(e) => setTimelineGranularity(e.target.value as '1m' | '5m' | '1h')}
            className="bg-surface-card border border-border-subtle px-3 py-2 text-sm text-ink-primary"
          >
            <option value="1m">1 minute intervals</option>
            <option value="5m">5 minute intervals</option>
            <option value="1h">1 hour intervals</option>
          </select>
          <select
            value={timelineDuration}
            onChange={(e) => setTimelineDuration(Number(e.target.value))}
            className="bg-surface-card border border-border-subtle px-3 py-2 text-sm text-ink-primary"
          >
            <option value={30}>Last 30 minutes</option>
            <option value={60}>Last 1 hour</option>
            <option value={180}>Last 3 hours</option>
            <option value={360}>Last 6 hours</option>
            <option value={1440}>Last 24 hours</option>
          </select>
          <Stack
            direction="row"
            align="center"
            gap="sm"
            className="text-sm"
            role="status"
            aria-live="polite"
          >
            <span
              className="w-2 h-2 animate-pulse"
              aria-hidden="true"
              style={{ backgroundColor: colors.green }}
            />
            <Text as="span" color={colors.green} noMargin>
              Live
            </Text>
          </Stack>
        </Stack>
      </header>

      {/* Stats Grid */}
      {stats && (
        <section aria-label="Key metrics" className="grid grid-cols-4 gap-4">
          <StatCard
            icon={ArrowDownLeft}
            label="Total Ingress"
            value={formatBytes(stats.totalBytesIn)}
            color={colors.blue}
            bgColor={alpha(colors.blue, 0.1)}
          />
          <StatCard
            icon={ArrowUpRight}
            label="Total Egress"
            value={formatBytes(stats.totalBytesOut)}
            color={colors.green}
            bgColor={alpha(colors.green, 0.1)}
          />
          <StatCard
            icon={Activity}
            label="Total Requests"
            value={formatNumber(stats.totalRequests)}
            subValue={`Avg ${formatBytes(stats.avgBytesPerRequest)}/req`}
            color={colors.purple}
            bgColor={alpha(colors.purple, 0.1)}
          />
          <StatCard
            icon={Server}
            label="Fleet Coverage"
            value={`${stats.respondedSensors}/${stats.sensorCount}`}
            subValue="Sensors responding"
            color={colors.orange}
            bgColor={alpha(colors.orange, 0.1)}
          />
        </section>
      )}

      {/* Timeline Chart */}
      {timelineData && (
        <section>
          <TimelineChart data={timelineData.points} granularity={timelineData.granularity} />
        </section>
      )}

      {/* Endpoints Table + Billing Panel */}
      <section className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          {endpointData && <TopEndpointsTable endpoints={endpointData} />}
        </div>
        {billingData && (
          <BillingPanel
            totalTransfer={billingData.totalDataTransfer}
            ingressBytes={billingData.ingressBytes}
            egressBytes={billingData.egressBytes}
            estimatedCost={billingData.estimatedCost}
            costPerGb={billingData.costPerGb}
            periodStart={billingData.period.start}
            periodEnd={billingData.period.end}
          />
        )}
      </section>

      {/* Sensor Breakdown */}
      {billingData && billingData.sensorBreakdown.length > 0 && (
        <section>
          <SensorBreakdown sensors={billingData.sensorBreakdown} />
        </section>
      )}
    </div>
  );
}
