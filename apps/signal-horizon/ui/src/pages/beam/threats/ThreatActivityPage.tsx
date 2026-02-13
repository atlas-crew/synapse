/**
 * Threat Activity Page
 * Real-time threat monitoring with heatmap and incident timeline
 */

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  Shield,
  ShieldAlert,
  Activity,
  Clock,
  MapPin,
  Target,
  RefreshCw,
  Wifi,
  WifiOff,
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
  CartesianGrid,
} from 'recharts';
import { useBeamThreats, type ThreatTimeRange } from '../../../hooks/useBeamThreats';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';
import { useHorizonStore, useTimeRange } from '../../../stores/horizonStore';
import {
  Button,
  SectionHeader,
  Stack,
  Spinner,
  axisDefaults,
  colors,
  gridDefaultsSoft,
  tooltipDefaults,
  xAxisNoLine,
} from '@/ui';

type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';
type TimeRange = ThreatTimeRange;

const tickSmallX = { ...axisDefaults.x.tick, fontSize: 11 };
const tickSmallY = { ...axisDefaults.y.tick, fontSize: 11 };
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const PAGE_HEADER_TITLE_STYLE = {
  fontSize: '20px',
  lineHeight: '28px',
  color: 'var(--text-primary)',
};

// Demo data - threat activity timeline
const DEMO_THREAT_TIMELINE = [
  { time: '00:00', threats: 12, blocked: 12, critical: 1, high: 3, medium: 5, low: 3 },
  { time: '01:00', threats: 8, blocked: 8, critical: 0, high: 2, medium: 4, low: 2 },
  { time: '02:00', threats: 5, blocked: 5, critical: 0, high: 1, medium: 2, low: 2 },
  { time: '03:00', threats: 3, blocked: 3, critical: 0, high: 0, medium: 2, low: 1 },
  { time: '04:00', threats: 6, blocked: 6, critical: 0, high: 1, medium: 3, low: 2 },
  { time: '05:00', threats: 9, blocked: 9, critical: 0, high: 2, medium: 4, low: 3 },
  { time: '06:00', threats: 15, blocked: 15, critical: 1, high: 4, medium: 6, low: 4 },
  { time: '07:00', threats: 28, blocked: 28, critical: 2, high: 7, medium: 12, low: 7 },
  { time: '08:00', threats: 45, blocked: 44, critical: 3, high: 12, medium: 18, low: 12 },
  { time: '09:00', threats: 52, blocked: 51, critical: 4, high: 14, medium: 21, low: 13 },
  { time: '10:00', threats: 48, blocked: 47, critical: 3, high: 13, medium: 19, low: 13 },
  { time: '11:00', threats: 55, blocked: 55, critical: 4, high: 15, medium: 22, low: 14 },
  { time: '12:00', threats: 62, blocked: 61, critical: 5, high: 17, medium: 25, low: 15 },
  { time: '13:00', threats: 58, blocked: 58, critical: 4, high: 16, medium: 23, low: 15 },
  { time: '14:00', threats: 51, blocked: 50, critical: 3, high: 14, medium: 20, low: 14 },
  { time: '15:00', threats: 49, blocked: 49, critical: 3, high: 13, medium: 20, low: 13 },
  { time: '16:00', threats: 45, blocked: 45, critical: 3, high: 12, medium: 18, low: 12 },
  { time: '17:00', threats: 38, blocked: 38, critical: 2, high: 10, medium: 15, low: 11 },
  { time: '18:00', threats: 32, blocked: 32, critical: 2, high: 8, medium: 13, low: 9 },
  { time: '19:00', threats: 28, blocked: 28, critical: 1, high: 7, medium: 12, low: 8 },
  { time: '20:00', threats: 22, blocked: 22, critical: 1, high: 5, medium: 10, low: 6 },
  { time: '21:00', threats: 18, blocked: 18, critical: 1, high: 4, medium: 8, low: 5 },
  { time: '22:00', threats: 15, blocked: 15, critical: 0, high: 4, medium: 7, low: 4 },
  { time: '23:00', threats: 11, blocked: 11, critical: 0, high: 3, medium: 5, low: 3 },
];

// Demo data - recent incidents
const DEMO_INCIDENTS = [
  {
    id: '1',
    type: 'SQL Injection Attempt',
    severity: 'critical' as ThreatSeverity,
    sourceIp: '192.168.45.102',
    targetEndpoint: '/api/v1/users/search',
    timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    blocked: true,
    details: 'UNION SELECT pattern detected in query parameter',
  },
  {
    id: '2',
    type: 'Credential Stuffing',
    severity: 'high' as ThreatSeverity,
    sourceIp: '10.0.1.55',
    targetEndpoint: '/api/v1/auth/login',
    timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    blocked: true,
    details: '47 rapid login attempts from single IP',
  },
  {
    id: '3',
    type: 'Path Traversal',
    severity: 'high' as ThreatSeverity,
    sourceIp: '203.45.112.89',
    targetEndpoint: '/api/v1/files/download',
    timestamp: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    blocked: true,
    details: 'Directory traversal pattern ../../../ detected',
  },
  {
    id: '4',
    type: 'XSS Attempt',
    severity: 'medium' as ThreatSeverity,
    sourceIp: '172.16.0.45',
    targetEndpoint: '/api/v1/comments',
    timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    blocked: true,
    details: 'Script tag injection in request body',
  },
  {
    id: '5',
    type: 'Rate Limit Exceeded',
    severity: 'low' as ThreatSeverity,
    sourceIp: '192.168.1.100',
    targetEndpoint: '/api/v1/products',
    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
    blocked: true,
    details: 'Exceeded 100 requests per minute threshold',
  },
  {
    id: '6',
    type: 'Bot Activity Detected',
    severity: 'medium' as ThreatSeverity,
    sourceIp: '45.67.89.123',
    targetEndpoint: '/api/v1/search',
    timestamp: new Date(Date.now() - 42 * 60 * 1000).toISOString(),
    blocked: true,
    details: 'Automated scraping behavior detected',
  },
];

// Demo data - top source IPs
const DEMO_TOP_SOURCES = [
  { ip: '192.168.45.102', threats: 156, country: 'US', blocked: 156 },
  { ip: '10.0.1.55', threats: 89, country: 'CN', blocked: 87 },
  { ip: '203.45.112.89', threats: 72, country: 'RU', blocked: 72 },
  { ip: '172.16.0.45', threats: 45, country: 'BR', blocked: 44 },
  { ip: '45.67.89.123', threats: 38, country: 'IN', blocked: 38 },
];

// Demo data - severity distribution (brand colors: Magenta, Orange, Atlas Crew Blue, Navy)
const DEMO_SEVERITY_DIST = [
  { name: 'Critical', value: 42, color: colors.magenta },
  { name: 'High', value: 168, color: colors.orange },
  { name: 'Medium', value: 289, color: colors.blue },
  { name: 'Low', value: 198, color: colors.navy },
];

// Calculate total for percentage display
const SEVERITY_TOTAL = DEMO_SEVERITY_DIST.reduce((sum, d) => sum + d.value, 0);

// Brand colors for severity (Magenta, Orange, Atlas Crew Blue, Navy)
const SEVERITY_CONFIG: Record<ThreatSeverity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-ac-magenta', bg: 'bg-ac-magenta/20', label: 'Critical' },
  high: { color: 'text-ac-orange', bg: 'bg-ac-orange/20', label: 'High' },
  medium: { color: 'text-ac-blue', bg: 'bg-ac-blue/20', label: 'Medium' },
  low: { color: 'text-ac-navy', bg: 'bg-ac-navy/20', label: 'Low' },
};

// Stat Card Component
function StatCard({
  label,
  value,
  change,
  icon: Icon,
  color = 'text-horizon-400',
}: {
  label: string;
  value: string;
  change?: { value: number; trend: 'up' | 'down' };
  icon: React.ElementType;
  color?: string;
}) {
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
          {change && (
            <p
              className={clsx(
                'text-xs mt-1',
                change.trend === 'up' ? 'text-red-400' : 'text-green-400',
              )}
            >
              {change.trend === 'up' ? '↑' : '↓'} {Math.abs(change.value)}% vs last period
            </p>
          )}
        </div>
        <div className="p-3 bg-surface-subtle/50">
          <Icon className={clsx('w-6 h-6', color)} />
        </div>
      </div>
    </motion.div>
  );
}

// Format relative time
function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();

  const minutes = Math.floor(diff / (1000 * 60));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// Time Range Selector
function TimeRangeSelector({
  value,
  onChange,
}: {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
}) {
  const options: { value: TimeRange; label: string }[] = [
    { value: '1h', label: '1H' },
    { value: '6h', label: '6H' },
    { value: '24h', label: '24H' },
    { value: '7d', label: '7D' },
  ];

  return (
    <Stack direction="row" align="center" gap="xs" className="bg-surface-card p-1">
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={clsx(
            'px-3 py-1.5 text-sm font-medium transition-colors',
            value === option.value
              ? 'bg-horizon-600 text-ink-primary'
              : 'text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle',
          )}
        >
          {option.label}
        </button>
      ))}
    </Stack>
  );
}

// Threat Timeline Chart
function ThreatTimelineChart() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="col-span-2 bg-surface-card border border-border-subtle p-5"
    >
      <h3 className="text-ink-primary font-medium mb-4">Threat Timeline</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={DEMO_THREAT_TIMELINE}>
            <defs>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={colors.magenta} stopOpacity={0.5} />
                <stop offset="50%" stopColor={colors.magenta} stopOpacity={0.2} />
                <stop offset="100%" stopColor={colors.magenta} stopOpacity={0.05} />
              </linearGradient>
            </defs>
            <CartesianGrid {...gridDefaultsSoft} />
            <XAxis dataKey="time" {...xAxisNoLine} tick={tickSmallX} />
            <YAxis {...axisDefaults.y} tick={tickSmallY} />
            <Tooltip {...tooltipDefaults} />
            <Area
              type="monotone"
              dataKey="threats"
              stroke={colors.magenta}
              fill="url(#threatGradient)"
              strokeWidth={2.5}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

// Top Threat Sources Chart
function TopThreatSourcesChart() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5"
    >
      <h3 className="text-ink-primary font-medium mb-4">Top Threat Sources</h3>
      <div className="h-48 mb-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={DEMO_TOP_SOURCES} layout="vertical">
            <XAxis type="number" axisLine={false} tickLine={false} tick={tickSmallX} />
            <YAxis
              type="category"
              dataKey="ip"
              axisLine={false}
              tickLine={false}
              tick={tickSmallY}
              width={110}
            />
            <Tooltip {...tooltipDefaults} />
            <Bar dataKey="threats" fill={colors.magenta} radius={[0, 0, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="space-y-2">
        {DEMO_TOP_SOURCES.slice(0, 3).map((source) => (
          <div key={source.ip} className="flex items-center justify-between text-sm">
            <Stack direction="row" align="center" gap="sm">
              <span className="text-ink-secondary font-mono">{source.ip}</span>
              <span className="text-xs text-ink-muted">({source.country})</span>
            </Stack>
            <span className="text-red-400">{source.threats} threats</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}

// Incident Card
function IncidentCard({ incident }: { incident: (typeof DEMO_INCIDENTS)[0] }) {
  const config = SEVERITY_CONFIG[incident.severity];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="bg-surface-subtle border border-border-subtle p-4 hover:bg-surface-subtle transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <div className={clsx('p-2', config.bg)}>
            <ShieldAlert className={clsx('w-4 h-4', config.color)} />
          </div>
          <div>
            <Stack direction="row" align="center" gap="sm">
              <h4 className="text-ink-primary font-medium">{incident.type}</h4>
              <span className={clsx('px-2 py-0.5 text-xs font-medium', config.bg, config.color)}>
                {config.label}
              </span>
            </Stack>
            <p className="text-sm text-ink-secondary mt-1">{incident.details}</p>
            <Stack direction="row" align="center" gap="md" className="mt-2 text-xs text-ink-muted">
              <Stack as="span" direction="row" inline align="center" gap="xs">
                <MapPin className="w-3 h-3" />
                {incident.sourceIp}
              </Stack>
              <Stack as="span" direction="row" inline align="center" gap="xs">
                <Target className="w-3 h-3" />
                {incident.targetEndpoint}
              </Stack>
            </Stack>
          </div>
        </div>
        <div className="text-right">
          <Stack as="span" direction="row" inline align="center" gap="xs" className="text-xs text-ink-muted">
            <Clock className="w-3 h-3" />
            {formatRelativeTime(incident.timestamp)}
          </Stack>
          {incident.blocked && (
            <span className="mt-1 inline-block px-2 py-0.5 bg-green-500/20 text-green-400 text-xs">
              Blocked
            </span>
          )}
        </div>
      </div>
    </motion.div>
  );
}

export default function ThreatActivityPage() {
  const timeRange = useTimeRange() as TimeRange;
  const setTimeRange = useHorizonStore((s) => s.setTimeRange);

  // Fetch threats from API
  const {
    blocks,
    stats: apiStats,
    isLoading: hookLoading,
    isConnected,
    refetch,
  } = useBeamThreats({
    pollingInterval: 15000,
    queryParams: { timeRange },
  });

  const isLoading = hookLoading && blocks.length === 0;

  // Transform blocks to incidents format
  const incidents = useMemo(() => {
    if (blocks.length > 0) {
      return blocks.slice(0, 6).map((block) => ({
        id: block.id,
        type: block.threatType.replace(/_/g, ' '),
        severity: (block.riskScore >= 80
          ? 'critical'
          : block.riskScore >= 60
            ? 'high'
            : block.riskScore >= 40
              ? 'medium'
              : 'low') as ThreatSeverity,
        sourceIp: block.sourceIp,
        targetEndpoint: block.endpoint,
        timestamp: block.timestamp,
        blocked: block.action === 'blocked',
        details: `Risk score: ${block.riskScore}`,
      }));
    }
    return DEMO_INCIDENTS;
  }, [blocks]);

  // Calculate stats from API data or demo data
  const stats = useMemo(() => {
    if (apiStats.total > 0) {
      return {
        totalThreats: apiStats.total,
        totalBlocked: apiStats.blocked,
        criticalCount: apiStats.criticalCount,
        blockRate:
          apiStats.total > 0 ? ((apiStats.blocked / apiStats.total) * 100).toFixed(1) : '0.0',
      };
    }
    const totalThreats = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.threats, 0);
    const totalBlocked = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.blocked, 0);
    const criticalCount = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.critical, 0);
    const blockRate = ((totalBlocked / totalThreats) * 100).toFixed(1);

    return { totalThreats, totalBlocked, criticalCount, blockRate };
  }, [apiStats]);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <SectionHeader
          title="Threat Activity"
          description="Loading threat data..."
          size="h1"
          style={PAGE_HEADER_STYLE}
          titleStyle={PAGE_HEADER_TITLE_STYLE}
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
        title="Threat Activity"
        description="Real-time threat monitoring and incident response"
        size="h1"
        style={PAGE_HEADER_STYLE}
        titleStyle={PAGE_HEADER_TITLE_STYLE}
        actions={
          <Stack direction="row" align="center" gap="md">
            <Stack direction="row" align="center" gap="sm" className="text-sm">
              {isConnected ? (
                <Wifi className="w-4 h-4 text-green-400" />
              ) : (
                <WifiOff className="w-4 h-4 text-ink-secondary" />
              )}
              <span className={isConnected ? 'text-green-400' : 'text-ink-secondary'}>
                {isConnected ? 'Live' : 'Demo Data'}
              </span>
            </Stack>
            <button
              onClick={() => refetch()}
              className="px-3 py-1.5 bg-surface-subtle hover:bg-surface-card text-sm text-ink-secondary transition-colors"
              disabled={hookLoading}
            >
              <Stack as="span" direction="row" inline align="center" gap="sm">
                {hookLoading ? (
                  <Spinner size={16} color={colors.gray.mid} />
                ) : (
                  <RefreshCw className="w-4 h-4" />
                )}
                Refresh
              </Stack>
            </button>
            <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
          </Stack>
        }
      />

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Total Threats"
          value={stats.totalThreats.toLocaleString()}
          change={{ value: 12, trend: 'up' }}
          icon={AlertTriangle}
          color="text-red-400"
        />
        <StatCard
          label="Blocked"
          value={stats.totalBlocked.toLocaleString()}
          change={{ value: 12, trend: 'up' }}
          icon={Shield}
          color="text-green-400"
        />
        <StatCard
          label="Critical Threats"
          value={stats.criticalCount.toString()}
          change={{ value: 5, trend: 'down' }}
          icon={ShieldAlert}
          color="text-orange-400"
        />
        <StatCard
          label="Block Rate"
          value={`${stats.blockRate}%`}
          icon={Activity}
          color="text-horizon-400"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Threat Timeline */}
        <ThreatTimelineChart />

        {/* Severity Distribution - Horizontal Stacked Bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-surface-card border border-border-subtle p-5"
        >
          <h3 className="text-ink-primary font-medium mb-4">Severity Distribution</h3>

          {/* Stacked Bar */}
          <div className="h-10 flex w-full overflow-hidden">
            {DEMO_SEVERITY_DIST.map((item) => (
              <div
                key={item.name}
                className="h-full transition-all hover:opacity-80"
                style={{
                  backgroundColor: item.color,
                  width: `${(item.value / SEVERITY_TOTAL) * 100}%`,
                }}
                title={`${item.name}: ${item.value} (${((item.value / SEVERITY_TOTAL) * 100).toFixed(1)}%)`}
              />
            ))}
          </div>

          {/* Legend */}
          <div className="grid grid-cols-2 gap-3 mt-4">
            {DEMO_SEVERITY_DIST.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <Stack direction="row" align="center" gap="sm">
                  <div className="w-3 h-3" style={{ backgroundColor: item.color }} />
                  <span className="text-sm text-ink-secondary">{item.name}</span>
                </Stack>
                <div className="text-right">
                  <span className="text-sm text-ink-primary font-medium">{item.value}</span>
                  <span className="text-xs text-ink-muted ml-1">
                    ({((item.value / SEVERITY_TOTAL) * 100).toFixed(0)}%)
                  </span>
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Recent Incidents */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="col-span-2 bg-surface-card border border-border-subtle p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-ink-primary font-medium">Recent Incidents</h3>
            <Button
              variant="ghost"
              size="sm"
              style={{ height: '28px', padding: 0, fontSize: '14px', color: colors.skyBlue }}
            >
              View all →
            </Button>
          </div>
          <div className="space-y-3">
            {incidents.map((incident) => (
              <IncidentCard key={incident.id} incident={incident} />
            ))}
          </div>
        </motion.div>

        {/* Top Threat Sources */}
        <TopThreatSourcesChart />
      </div>
    </div>
  );
}
