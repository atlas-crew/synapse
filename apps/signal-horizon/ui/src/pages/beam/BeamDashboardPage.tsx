/**
 * Beam Protection Dashboard
 * Real-time API security overview with traffic, threats, and protection status
 */

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { PersistentTooltip } from '../../components/ui/PersistentTooltip';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import {
  Shield,
  AlertTriangle,
  Activity,
  Target,
  TrendingUp,
  TrendingDown,
  Clock,
  Globe,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { clsx } from 'clsx';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { Box, SectionHeader, alpha, axisDefaults, colors, spacing } from '@/ui';
import {
  useBeamStats,
  useBlockedRequests,
  useBeamAlerts,
  useBeamLoading,
  useTrafficTimeline,
} from '../../stores/beamStore';
import { useBeamDashboard } from '../../hooks/useBeamDashboard';
import { useBeamThreats } from '../../hooks/useBeamThreats';
import { StatsGridSkeleton, TableSkeleton, CardSkeleton } from '../../components/LoadingStates';
import type { BlockedRequest, ProtectionAlert, TrafficDataPoint } from '../../types/beam';

// Color palette for dark theme - Atlas Crew Brand compliant
const COLORS = {
  requests: colors.blue,
  blocked: colors.red,
  protected: colors.green,
  warning: colors.skyBlue,
  chart: {
    area: alpha(colors.blue, 0.2),
    line: colors.blue,
    blocked: alpha(colors.red, 0.4),
    blockedLine: colors.red,
  },
};

const ATTACK_COLORS = [colors.blue, colors.magenta, colors.orange, colors.red, colors.green];

// Demo data for initial development
const DEMO_TRAFFIC: TrafficDataPoint[] = Array.from({ length: 24 }, (_, i) => ({
  timestamp: new Date(Date.now() - (23 - i) * 60 * 60 * 1000).toISOString(),
  requests: Math.floor(Math.random() * 5000) + 1000,
  blocked: Math.floor(Math.random() * 100) + 10,
}));

const DEMO_ATTACK_TYPES = [
  { type: 'SQL Injection', count: 156, percentage: 42 },
  { type: 'XSS', count: 89, percentage: 24 },
  { type: 'Bot Traffic', count: 67, percentage: 18 },
  { type: 'Rate Limit', count: 45, percentage: 12 },
  { type: 'Other', count: 15, percentage: 4 },
];

// Stat Card Component
interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: string | number;
  trend?: { value: number; period: string };
  accentColor: string;
  iconBg: string;
  description?: string;
}

function StatCard({
  icon: Icon,
  label,
  value,
  trend,
  accentColor,
  iconBg,
  description,
}: StatCardProps) {
  const trendColor = trend && trend.value >= 0 ? colors.green : colors.red;
  const TrendIcon = trend && trend.value >= 0 ? TrendingUp : TrendingDown;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-ink-secondary" title={description}>
            {label}
          </p>
          <p className="mt-2 text-3xl font-light text-ink-primary">{value.toLocaleString()}</p>
          {trend && (
            <div className="mt-2 flex items-center gap-1 text-sm" style={{ color: trendColor }}>
              <TrendIcon className="w-4 h-4" />
              <span>{Math.abs(trend.value)}%</span>
              <span className="text-ink-muted">{trend.period}</span>
            </div>
          )}
        </div>
        <div className="p-3" style={{ background: iconBg }}>
          <Icon className="w-6 h-6" style={{ color: accentColor }} />
        </div>
      </div>
    </motion.div>
  );
}

// Traffic Chart Component
interface TrafficChartProps {
  data: TrafficDataPoint[];
}

function TrafficChart({ data }: TrafficChartProps) {
  const formattedData = useMemo(
    () =>
      data.map((d) => ({
        ...d,
        time: new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      })),
    [data],
  );

  return (
    <div className="bg-surface-card border border-border-subtle p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-ink-primary">Traffic Overview</h3>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3" style={{ background: COLORS.requests }} />
            <span className="text-ink-secondary">Requests</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3" style={{ background: COLORS.blocked }} />
            <span className="text-ink-secondary">Blocked</span>
          </div>
        </div>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={formattedData} margin={{ top: 5, right: 5, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.requests} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.requests} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={COLORS.blocked} stopOpacity={0.3} />
                <stop offset="95%" stopColor={COLORS.blocked} stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" {...axisDefaults.x} axisLine={false} />
            <YAxis
              {...axisDefaults.y}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v)}
            />
            <Tooltip content={<PersistentTooltip />} />
            <Area
              type="monotone"
              dataKey="requests"
              stroke={COLORS.requests}
              fill="url(#requestsGradient)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke={COLORS.blocked}
              fill="url(#blockedGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Attack Types Stacked Bar Chart with depth/gradients
function AttackTypesChart({ data }: { data: typeof DEMO_ATTACK_TYPES }) {
  // Calculate total for stacked bar
  const total = data.reduce((sum, item) => sum + item.count, 0);

  // Generate gradient style for each color
  const getBarGradient = (color: string, isHovered = false) => {
    const opacity = isHovered ? 1 : 0.9;
    return `linear-gradient(180deg,
      ${color}${Math.round(opacity * 255)
        .toString(16)
        .padStart(2, '0')} 0%,
      ${color}cc 50%,
      ${color}99 100%)`;
  };

  return (
    <div className="bg-surface-card border border-border-subtle p-5 relative overflow-hidden">
      {/* Subtle background glow */}
      <div
        className="absolute inset-0 opacity-30 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse at 50% 0%, ${alpha(colors.blue, 0.15)} 0%, transparent 60%)`,
        }}
      />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-ink-primary tracking-wide">
            ATTACK DISTRIBUTION
          </h3>
          <span className="text-xs text-ink-muted font-mono">{total} TOTAL</span>
        </div>

        {/* Stacked horizontal bar with depth */}
        <div
          className="h-10 flex overflow-hidden border border-border-subtle relative"
          style={{
            boxShadow:
              'inset 0 2px 4px rgba(0, 0, 0, 0.3), inset 0 -1px 2px rgba(255, 255, 255, 0.05)',
          }}
        >
          {data.map((item, index) => {
            const color = ATTACK_COLORS[index % ATTACK_COLORS.length];
            return (
              <div
                key={item.type}
                className="h-full relative group transition-all duration-200 hover:brightness-110"
                style={{
                  width: `${item.percentage}%`,
                  background: getBarGradient(color),
                  boxShadow: `inset 0 1px 0 rgba(255, 255, 255, 0.2), inset 0 -1px 0 rgba(0, 0, 0, 0.2)`,
                }}
              >
                {/* Highlight edge */}
                <div
                  className="absolute inset-y-0 right-0 w-px"
                  style={{ background: 'rgba(0, 0, 0, 0.3)' }}
                />
                {/* Tooltip on hover */}
                <div
                  className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-1.5 text-xs text-ink-primary whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10"
                  style={{
                    background: `linear-gradient(180deg, ${alpha(colors.navy, 0.95)} 0%, ${alpha(colors.tint.blueDarker, 0.98)} 100%)`,
                    border: `1px solid ${alpha(colors.blue, 0.4)}`,
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.5)',
                  }}
                >
                  <span className="font-medium">{item.type}</span>
                  <span className="text-ink-muted ml-2">{item.count}</span>
                </div>
              </div>
            );
          })}
        </div>

        {/* Legend with individual bars */}
        <div className="mt-5 space-y-3">
          {data.map((item, index) => {
            const color = ATTACK_COLORS[index % ATTACK_COLORS.length];
            return (
              <div key={item.type} className="group">
                <div className="flex items-center justify-between text-sm mb-1.5">
                  <div className="flex items-center gap-2">
                    <div
                      className="w-2.5 h-2.5"
                      style={{
                        background: `linear-gradient(135deg, ${color} 0%, ${color}99 100%)`,
                        boxShadow: `0 0 6px ${color}66`,
                      }}
                    />
                    <span className="text-ink-secondary">{item.type}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-ink-muted font-mono text-xs">{item.count}</span>
                    <span className="text-ink-primary font-medium font-mono w-10 text-right">
                      {item.percentage}%
                    </span>
                  </div>
                </div>
                {/* Individual progress bar with gradient */}
                <div
                  className="h-2 overflow-hidden relative"
                  style={{
                    background: 'rgba(0, 0, 0, 0.3)',
                    boxShadow: 'inset 0 1px 2px rgba(0, 0, 0, 0.4)',
                  }}
                >
                  <div
                    className="h-full transition-all duration-500 ease-out group-hover:brightness-110"
                    style={{
                      width: `${item.percentage}%`,
                      background: `linear-gradient(90deg, ${color}cc 0%, ${color} 50%, ${color}cc 100%)`,
                      boxShadow: `0 0 8px ${color}44, inset 0 1px 0 rgba(255, 255, 255, 0.15)`,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// Recent Blocked Requests Table
function RecentBlockedTable({ requests }: { requests: BlockedRequest[] }) {
  const actionColors: Record<string, string> = {
    blocked: 'text-ac-red bg-ac-red/20',
    challenged: 'text-ac-sky bg-ac-sky/20',
    throttled: 'text-ac-orange bg-ac-orange/20',
    logged: 'text-ac-blue bg-ac-blue/20',
  };

  return (
    <div className="bg-surface-card border border-border-subtle">
      <div className="px-5 py-4 border-b border-border-subtle flex items-center justify-between">
        <h3 className="text-lg font-semibold text-ink-primary">Recent Blocked Requests</h3>
        <span className="text-sm text-ink-secondary">{requests.length} blocked</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <caption className="sr-only">
            Recently blocked requests with threat classification
          </caption>
          <thead>
            <tr className="text-left text-sm text-ink-secondary border-b border-border-subtle">
              <th className="px-5 py-3 font-medium">Time</th>
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium">Source IP</th>
              <th className="px-5 py-3 font-medium">Threat</th>
              <th className="px-5 py-3 font-medium">Action</th>
            </tr>
          </thead>
          <tbody>
            {requests.slice(0, 5).map((req) => (
              <tr
                key={req.id}
                className="border-b border-border-subtle/50 hover:bg-surface-subtle transition-colors"
              >
                <td className="px-5 py-3 text-sm text-ink-secondary">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    {new Date(req.timestamp).toLocaleTimeString()}
                  </div>
                </td>
                <td className="px-5 py-3 text-sm">
                  <code className="text-ac-blue bg-ac-blue/10 px-2 py-0.5">
                    {req.method} {req.endpoint}
                  </code>
                </td>
                <td className="px-5 py-3 text-sm text-ink-secondary">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-ink-muted" />
                    {req.sourceIp}
                  </div>
                </td>
                <td className="px-5 py-3 text-sm text-ink-secondary">{req.threatType}</td>
                <td className="px-5 py-3">
                  <span
                    className={clsx(
                      'px-2 py-1 text-xs font-medium',
                      actionColors[req.action] || actionColors.blocked,
                    )}
                  >
                    {req.action}
                  </span>
                </td>
              </tr>
            ))}
            {requests.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-ink-muted">
                  No blocked requests in the last 24 hours
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Protection Alerts
function AlertsFeed({ alerts }: { alerts: ProtectionAlert[] }) {
  const severityColors: Record<string, string> = {
    low: 'border-l-ac-green bg-ac-green/5',
    medium: 'border-l-ac-sky bg-ac-sky/5',
    high: 'border-l-ac-orange bg-ac-orange/5',
    critical: 'border-l-ac-red bg-ac-red/5',
  };

  const typeIcons: Record<string, LucideIcon> = {
    endpoint_discovered: Globe,
    schema_change: Activity,
    rule_triggered: Zap,
    deployment_complete: Shield,
  };

  return (
    <div className="bg-surface-card border border-border-subtle">
      <div className="px-5 py-4 border-b border-border-subtle">
        <h3 className="text-lg font-semibold text-ink-primary">Recent Alerts</h3>
      </div>
      <div className="divide-y divide-border-subtle/50 max-h-80 overflow-y-auto">
        {alerts.slice(0, 5).map((alert) => {
          const Icon = typeIcons[alert.type] || AlertTriangle;
          return (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={clsx(
                'px-5 py-4 border-l-4',
                severityColors[alert.severity] || severityColors.low,
              )}
            >
              <div className="flex items-start gap-3">
                <Icon className="w-5 h-5 text-ink-secondary mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-ink-primary truncate">{alert.title}</p>
                  <p className="text-xs text-ink-secondary mt-1 truncate">{alert.description}</p>
                  <p className="text-xs text-ink-muted mt-2">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </motion.div>
          );
        })}
        {alerts.length === 0 && (
          <div className="px-5 py-8 text-center text-ink-muted">No recent alerts</div>
        )}
      </div>
    </div>
  );
}

// Demo blocked requests for initial development
const DEMO_BLOCKED: BlockedRequest[] = [
  {
    id: '1',
    timestamp: new Date().toISOString(),
    action: 'blocked',
    threatType: 'SQL Injection',
    sourceIp: '192.168.1.45',
    endpoint: '/api/users',
    method: 'POST',
    ruleId: 'rule-1',
    ruleName: 'SQL Injection Detection',
    riskScore: 85,
  },
  {
    id: '2',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    action: 'challenged',
    threatType: 'Bot Traffic',
    sourceIp: '10.0.0.123',
    endpoint: '/api/products',
    method: 'GET',
    riskScore: 65,
  },
  {
    id: '3',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    action: 'blocked',
    threatType: 'XSS Attack',
    sourceIp: '172.16.0.89',
    endpoint: '/api/comments',
    method: 'POST',
    riskScore: 92,
  },
];

const DEMO_ALERTS: ProtectionAlert[] = [
  {
    id: '1',
    type: 'endpoint_discovered',
    title: 'New Endpoint Discovered',
    description: 'GET /api/v2/users detected on sensor-prod-01',
    timestamp: new Date().toISOString(),
    severity: 'low',
  },
  {
    id: '2',
    type: 'schema_change',
    title: 'Schema Change Detected',
    description: 'New field "email" added to POST /api/users response',
    timestamp: new Date(Date.now() - 1800000).toISOString(),
    severity: 'medium',
  },
  {
    id: '3',
    type: 'rule_triggered',
    title: 'High-Volume Rule Trigger',
    description: 'SQL Injection rule triggered 50+ times in 5 minutes',
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    severity: 'high',
  },
];

// Main Dashboard Component
export default function BeamDashboardPage() {
  useDocumentTitle('Beam - Dashboard');
  const storeLoading = useBeamLoading();
  const stats = useBeamStats();
  const storeBlockedRequests = useBlockedRequests();
  const alerts = useBeamAlerts();
  const trafficTimeline = useTrafficTimeline();

  // API hooks for real data
  const { data: dashboardData, isLoading: dashboardLoading } = useBeamDashboard();
  const { blocks: apiBlocks } = useBeamThreats({ pollingInterval: 30000 });

  // Combined loading state
  const isLoading = storeLoading || (dashboardLoading && !dashboardData);

  // Merge API data with store data (store takes priority for WebSocket updates)
  const blockedRequests = storeBlockedRequests.length > 0 ? storeBlockedRequests : apiBlocks;

  // Use demo data as fallback when no real data available
  const displayTraffic =
    trafficTimeline.length > 0
      ? trafficTimeline
      : dashboardData?.trafficTimeline?.length
        ? dashboardData.trafficTimeline
        : DEMO_TRAFFIC;
  const displayBlocked = blockedRequests.length > 0 ? blockedRequests : DEMO_BLOCKED;
  const displayAlerts = alerts.length > 0 ? alerts : DEMO_ALERTS;

  // Show loading skeletons while initial data loads
  if (isLoading) {
    return (
      <div
        className="p-6 space-y-6"
        role="main"
        aria-busy="true"
        aria-label="Loading Beam dashboard"
      >
        <SectionHeader
          title="Beam Protection Dashboard"
          description="Loading protection status..."
        />
        <StatsGridSkeleton />
        <div className="grid grid-cols-3 gap-6">
          <div className="col-span-2">
            <CardSkeleton />
          </div>
          <CardSkeleton />
        </div>
        <TableSkeleton rows={5} />
      </div>
    );
  }

  // Calculate display values - prefer API data over store data over defaults
  const totalRequests = dashboardData?.summary?.requests?.value || stats.blockedRequests24h || 1247;
  const blockedCount = dashboardData?.summary?.blocked?.value || stats.blockedRequests24h || 89;
  const endpointCount = dashboardData?.endpointCount || stats.totalEndpoints || 45;
  const coveragePercent =
    dashboardData?.summary?.coverage?.value ||
    (stats.protectedEndpoints
      ? Math.round((stats.protectedEndpoints / Math.max(stats.totalEndpoints, 1)) * 100)
      : 94);

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Beam protection dashboard">
      {/* Header */}
      <SectionHeader
        title="Beam Protection Dashboard"
        description="Real-time API security overview"
        actions={
          <Box
            bg="card"
            border="subtle"
            flex
            direction="row"
            align="center"
            gap="sm"
            style={{ padding: `${spacing.xs} ${spacing.md}` }}
          >
            <span
              className="animate-pulse"
              aria-hidden="true"
              style={{ width: 8, height: 8, background: colors.green, display: 'inline-block' }}
            />
            <span style={{ color: colors.green, fontSize: '14px' }}>Protected</span>
          </Box>
        }
      />

      {/* Stats Grid */}
      <section aria-label="Key metrics" className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Activity}
          label="Requests (24h)"
          value={`${(totalRequests / 1000).toFixed(1)}k`}
          trend={{ value: 12, period: 'vs yesterday' }}
          accentColor={colors.blue}
          iconBg={alpha(colors.blue, 0.1)}
          description="Total API requests processed across all monitored endpoints in the last 24 hours"
        />
        <StatCard
          icon={Shield}
          label="Blocked"
          value={blockedCount}
          trend={{ value: -8, period: 'vs yesterday' }}
          accentColor={colors.red}
          iconBg={alpha(colors.red, 0.1)}
          description="Requests blocked by WAF rules including SQL injection, XSS, and bot traffic"
        />
        <StatCard
          icon={Target}
          label="Endpoints"
          value={endpointCount}
          trend={{ value: 3, period: 'new this week' }}
          accentColor={colors.purple}
          iconBg={alpha(colors.purple, 0.1)}
          description="Distinct API endpoints discovered and monitored by the profiler"
        />
        <StatCard
          icon={Shield}
          label="Coverage"
          value={`${coveragePercent}%`}
          accentColor={colors.green}
          iconBg={alpha(colors.green, 0.1)}
          description="Percentage of discovered endpoints protected by at least one WAF rule"
        />
      </section>

      {/* Traffic Chart + Attack Distribution */}
      <section className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <TrafficChart data={displayTraffic} />
        </div>
        <AttackTypesChart data={DEMO_ATTACK_TYPES} />
      </section>

      {/* Recent Blocked + Alerts */}
      <section className="grid grid-cols-3 gap-6">
        <div className="col-span-2">
          <RecentBlockedTable requests={displayBlocked} />
        </div>
        <AlertsFeed alerts={displayAlerts} />
      </section>
    </div>
  );
}
