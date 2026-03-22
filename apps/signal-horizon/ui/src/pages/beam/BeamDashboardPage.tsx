/**
 * Beam Protection Dashboard
 * Real-time API security overview with traffic, threats, and protection status
 */

import { useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
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
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import {
  Box,
  SectionHeader,
  Stack,
  Text,
  alpha,
  axisDefaults,
  colors,
  Grid,
  Button,
  StatusBadge,
  DataTable,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
} from '@/ui';
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

// Recharts SVG can't resolve CSS variables; use resolved hex tokens for chart colors.
const CHART_COLORS = {
  requests: colors.blue,
  blocked: colors.red,
};

const ATTACK_COLORS = [
  'var(--ac-blue)',
  'var(--ac-magenta)',
  'var(--ac-orange)',
  'var(--ac-red)',
  'var(--ac-green)',
];

// Animation Variants
const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1
    }
  }
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0 }
};

// Demo data for initial development
const DEMO_TRAFFIC: TrafficDataPoint[] = Array.from({ length: 24 }, (_, i) => ({
  timestamp: new Date(Date.now() - (23 - i) * 60 * 60 * 1000).toISOString(),
  requests: Math.floor(Math.random() * 5000) + 1000,
  blocked: Math.floor(Math.random() * 100) + 10,
}));

// Restore demo blocked requests for consistent fallback
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

// Restore demo alerts to demonstrate all severity levels
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
  accentColorVar: string;
  description?: string;
}

function StatCard({ icon: Icon, label, value, trend, accentColorVar, description }: StatCardProps) {
  const isPositive = trend && trend.value >= 0;
  const trendColor = isPositive ? 'var(--ac-green)' : 'var(--ac-red)';
  const TrendIcon = isPositive ? TrendingUp : TrendingDown;

  return (
    <Box
      bg="card"
      border="subtle"
      p="lg"
      style={{ position: 'relative', overflow: 'hidden' }}
    >
      <Stack direction="row" justify="space-between" align="start">
        <Stack gap="sm" style={{ flex: 1 }}>
            <Text variant="small" weight="medium" color="secondary" style={{ cursor: 'help' }} title={description}>
              {label}
            </Text>
            <Text variant="h2" weight="light">
              {value.toLocaleString()}
            </Text>
            {trend && (
              <Stack direction="row" align="center" gap="xs">
                <TrendIcon size={14} style={{ color: trendColor }} />
                <Text variant="small" weight="medium" style={{ color: trendColor }}>
                  {Math.abs(trend.value)}%
                </Text>
                <Text variant="small" color="secondary">
                  {trend.period}
                </Text>
              </Stack>
            )}
        </Stack>
        <Box
          p="smPlus"
          bg="surface-subtle"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: `1px solid ${alpha(colors.border.subtle, 0.3)}`,
          }}
        >
          <Icon size={24} style={{ color: `var(${accentColorVar})` }} />
        </Box>
      </Stack>
    </Box>
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
    <Box bg="card" border="subtle" p="lg">
      <SectionHeader
        title="Traffic Overview"
        size="h4"
        titleStyle={CARD_HEADER_TITLE_STYLE}
        actions={
          <Stack direction="row" gap="md">
            <Stack direction="row" align="center" gap="xs">
              <Box style={{ width: 10, height: 10, background: CHART_COLORS.requests }} />
              <Text variant="caption" color="secondary">Requests</Text>
            </Stack>
            <Stack direction="row" align="center" gap="xs">
              <Box style={{ width: 10, height: 10, background: CHART_COLORS.blocked }} />
              <Text variant="caption" color="secondary">Blocked</Text>
            </Stack>
          </Stack>
        }
      />
      <Box style={{ height: 256, marginTop: '24px' }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={formattedData} margin={{ top: 5, right: 5, left: 0, bottom: 5 }}>
            <defs>
              <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.requests} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.requests} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.blocked} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.blocked} stopOpacity={0} />
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
              stroke={CHART_COLORS.requests}
              fill="url(#requestsGradient)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke={CHART_COLORS.blocked}
              fill="url(#blockedGradient)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </Box>
    </Box>
  );
}

// Attack Distribution Component
function AttackTypesChart({ data }: { data: typeof DEMO_ATTACK_TYPES }) {
  const total = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <Box bg="card" border="subtle" p="lg" style={{ position: 'relative', overflow: 'hidden' }}>
      <Box
        style={{
          position: 'absolute',
          inset: 0,
          opacity: 0.1,
          pointerEvents: 'none',
          background: `radial-gradient(ellipse at 50% 0%, var(--ac-blue) 0%, transparent 70%)`,
        }}
      />

      <Stack gap="lg" style={{ position: 'relative', zIndex: 1 }}>
        <SectionHeader
          title="ATTACK DISTRIBUTION"
          size="h4"
          titleStyle={{ ...CARD_HEADER_TITLE_STYLE, letterSpacing: '0.05em' }}
          actions={
            <Text variant="caption" weight="medium" color="secondary" style={{ fontFamily: 'var(--font-mono)' }}>
              {total} TOTAL
            </Text>
          }
        />

        <Stack
          direction="row"
          style={{
            height: '40px',
            background: 'rgba(0,0,0,0.2)',
            border: '1px solid var(--border-subtle)',
            overflow: 'hidden',
          }}
        >
          {data.map((item, index) => {
            const colorVar = ATTACK_COLORS[index % ATTACK_COLORS.length];
            return (
              <Box
                key={item.type}
                style={{
                  width: `${item.percentage}%`,
                  height: '100%',
                  // P2-004 Fix: Consistent gradient using RGBA for interpolation safety
                  background: `linear-gradient(180deg, ${colorVar} 0%, rgba(0,0,0,0.3) 100%)`,
                  borderRight: '1px solid rgba(0,0,0,0.2)',
                  transition: 'filter 0.2s ease',
                  cursor: 'help',
                }}
                className="hover:brightness-110"
                title={`${item.type}: ${item.count} (${item.percentage}%)`}
              />
            );
          })}
        </Stack>

        {/* Legend */}
        <Stack gap="md">
          {data.map((item, index) => {
            const colorVar = ATTACK_COLORS[index % ATTACK_COLORS.length];
            return (
              <Box key={item.type}>
                <Stack direction="row" align="center" justify="space-between" style={{ marginBottom: '6px' }}>
                  <Stack direction="row" align="center" gap="sm">
                    <Box style={{ width: 10, height: 10, background: colorVar }} />
                    <Text variant="small" color="secondary">{item.type}</Text>
                  </Stack>
                  <Stack direction="row" align="center" gap="md">
                    <Text variant="caption" color="secondary" style={{ fontFamily: 'var(--font-mono)' }}>{item.count}</Text>
                    <Text variant="small" weight="semibold" style={{ width: 40, textAlign: 'right' }}>{item.percentage}%</Text>
                  </Stack>
                </Stack>
                <Box
                  style={{
                    height: '6px',
                    background: 'rgba(0,0,0,0.2)',
                    overflow: 'hidden',
                  }}
                >
                  <Box
                    style={{
                      height: '100%',
                      width: `${item.percentage}%`,
                      background: colorVar,
                      transition: 'width 1s ease-out',
                    }}
                  />
                </Box>
              </Box>
            );
          })}
        </Stack>
      </Stack>
    </Box>
  );
}

// Blocked Requests Table
function RecentBlockedTable({ requests }: { requests: BlockedRequest[] }) {
  const columns = [
    {
      key: 'time',
      label: 'Time',
      render: (_: any, req: BlockedRequest) => (
        <Stack direction="row" align="center" gap="sm">
          <Clock size={14} className="text-ink-muted" />
          <Text variant="small" color="secondary">{new Date(req.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</Text>
        </Stack>
      ),
    },
    {
      key: 'endpoint',
      label: 'Endpoint',
      render: (_: any, req: BlockedRequest) => (
        <Text variant="small" weight="medium" style={{ fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--ac-blue)', opacity: 0.8, marginRight: '8px' }}>{req.method}</span>
          {req.endpoint}
        </Text>
      ),
    },
    {
      key: 'source',
      label: 'Source IP',
      render: (_: any, req: BlockedRequest) => (
        <Stack direction="row" align="center" gap="sm">
          <Globe size={14} className="text-ink-muted" />
          <Text variant="small" color="secondary">{req.sourceIp}</Text>
        </Stack>
      ),
    },
    {
      key: 'threat',
      label: 'Threat',
      render: (_: any, req: BlockedRequest) => (
        <Text variant="small" color="secondary">{req.threatType}</Text>
      ),
    },
    {
      key: 'action',
      label: 'Action',
      render: (_: any, req: BlockedRequest) => {
        const variant = req.action === 'blocked' ? 'error' : req.action === 'challenged' ? 'warning' : 'info';
        return <StatusBadge status={variant} size="sm">{req.action}</StatusBadge>;
      },
    },
  ];

  return (
    <Box bg="card" border="subtle" role="region" aria-label="Recently blocked requests">
      <Box p="md" bg="surface-inset" border="bottom">
        <SectionHeader
          title="Recent Blocked Requests"
          size="h4"
          titleStyle={CARD_HEADER_TITLE_STYLE}
          actions={
            <Text variant="caption" color="secondary">{requests.length} blocked</Text>
          }
        />
      </Box>
      {/* TODO: DataTable needs caption/aria-label support for inner table element */}
      <DataTable
        columns={columns}
        data={requests.slice(0, 5)}
        emptyMessage="No blocked requests in the last 24 hours"
      />
    </Box>
  );
}

// Alerts Feed Component
function AlertsFeed({ alerts }: { alerts: ProtectionAlert[] }) {
  const navigate = useNavigate();
  const typeIcons: Record<string, LucideIcon> = {
    endpoint_discovered: Globe,
    schema_change: Activity,
    rule_triggered: Zap,
    deployment_complete: Shield,
  };

  return (
    <Box bg="card" border="subtle">
      <Box p="md" bg="surface-inset" border="bottom">
        <SectionHeader
          title="Recent Alerts"
          size="h4"
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Box>
      <Stack gap="none" style={{ maxHeight: '380px', overflowY: 'auto' }}>
        {alerts.length === 0 ? (
          <Box p="xl" style={{ textAlign: 'center' }}>
            <Text variant="small" color="secondary">No recent alerts</Text>
          </Box>
        ) : (
          alerts.slice(0, 8).map((alert, index) => {
            const Icon = typeIcons[alert.type] || AlertTriangle;
            const severityColor = alert.severity === 'critical' ? 'var(--ac-red)' : alert.severity === 'high' ? 'var(--ac-orange)' : alert.severity === 'medium' ? 'var(--ac-sky)' : 'var(--ac-green)';
            
            return (
              <Box
                key={alert.id}
                p="md"
                border={index > 0 ? 'top' : 'none'}
                borderColor="subtle"
                className="hover:bg-surface-subtle transition-colors"
                style={{ borderLeft: `4px solid ${severityColor}` }}
              >
                <Stack direction="row" gap="md" align="start">
                  <Box p="xs" style={{ background: alpha(colors.white, 0.05) }}>
                    <Icon size={18} className="text-ink-secondary" />
                  </Box>
                  <Stack gap="xs" style={{ flex: 1, minWidth: 0 }}>
                    <Text variant="small" weight="medium" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {alert.title}
                    </Text>
                    <Text variant="caption" color="secondary" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {alert.description}
                    </Text>
                    <Text variant="caption" color="muted">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </Text>
                  </Stack>
                </Stack>
              </Box>
            );
          })
        )}
      </Stack>
      <Box p="sm" border="top" style={{ textAlign: 'center' }}>
        <Button variant="ghost" size="sm" fullWidth onClick={() => navigate('/beam/threats')}>
          View All Alerts
        </Button>
      </Box>
    </Box>
  );
}

// Main Dashboard Component
export default function BeamDashboardPage() {
  useDocumentTitle('Beam - Dashboard');
  const storeLoading = useBeamLoading();
  const stats = useBeamStats();
  const storeBlockedRequests = useBlockedRequests();
  const alerts = useBeamAlerts();
  const trafficTimeline = useTrafficTimeline();

  const { data: dashboardData, isLoading: dashboardLoading } = useBeamDashboard();
  const { blocks: apiBlocks } = useBeamThreats({ pollingInterval: 30000 });

  const isLoading = storeLoading || (dashboardLoading && !dashboardData);
  const blockedRequests = storeBlockedRequests.length > 0 ? storeBlockedRequests : apiBlocks;

  const displayTraffic = trafficTimeline.length > 0 ? trafficTimeline : (dashboardData?.trafficTimeline || DEMO_TRAFFIC);
  const displayBlocked = blockedRequests.length > 0 ? blockedRequests : DEMO_BLOCKED;
  const displayAlerts = alerts.length > 0 ? alerts : DEMO_ALERTS;

  if (isLoading) {
    return (
      <Box p="xl" role="main" aria-busy="true" aria-label="Loading Beam dashboard">
        <Stack gap="xl">
          <SectionHeader title="Beam Protection Dashboard" description="Loading..." titleStyle={PAGE_TITLE_STYLE} />
          <StatsGridSkeleton />
          <Grid cols={3} gap="xl">
            <Box style={{ gridColumn: 'span 2' }}><CardSkeleton /></Box>
            <CardSkeleton />
          </Grid>
          <TableSkeleton rows={5} />
        </Stack>
      </Box>
    );
  }

  // TODO: Add stats.totalRequests24h to beamStore and wire fallback here
  const totalRequests = dashboardData?.summary?.requests?.value || 1247;
  const blockedCount = dashboardData?.summary?.blocked?.value || stats.blockedRequests24h || 89;


  const endpointCount = dashboardData?.endpointCount || stats.totalEndpoints || 45;
  const coveragePercent = dashboardData?.summary?.coverage?.value || 
    (stats.protectedEndpoints ? Math.round((stats.protectedEndpoints / Math.max(stats.totalEndpoints, 1)) * 100) : 94);

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={containerVariants}
    >
      <Box 
        p="xl" 
        role="main" 
        aria-label="Beam protection dashboard"
      >
        <Stack gap="xl">
        {/* Header */}
        <SectionHeader
          title="Beam Protection Dashboard"
          description="Real-time API security overview"
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            // Use inline style for indicator border to ensure theme-aware green renders correctly
            <Box bg="card" border="all" px="md" py="xs" style={{ borderColor: 'var(--ac-green)' }}>
              <Stack direction="row" align="center" gap="sm">
                <Box style={{ width: 8, height: 8, background: 'var(--ac-green)' }} className="animate-pulse" />
                <Text variant="small" weight="semibold" style={{ color: 'var(--ac-green)' }} noMargin>PROTECTED</Text>
              </Stack>
            </Box>
          }
        />

        {/* Stats Grid */}
        <motion.section aria-label="Key metrics" variants={itemVariants}>
          <Grid cols={4} gap="md">
            <StatCard
              icon={Activity}
              label="Requests (24h)"
              value={`${(totalRequests / 1000).toFixed(1)}k`}
              trend={{ value: 12, period: 'vs yesterday' }}
              accentColorVar="--ac-blue"
              description="Total API requests processed"
            />
            <StatCard
              icon={Shield}
              label="Blocked"
              value={blockedCount}
              trend={{ value: -8, period: 'vs yesterday' }}
              accentColorVar="--ac-red"
              description="Requests blocked by WAF rules"
            />
            <StatCard
              icon={Target}
              label="Endpoints"
              value={endpointCount}
              trend={{ value: 3, period: 'new this week' }}
              accentColorVar="--ac-purple"
              description="Distinct API endpoints monitored"
            />
            <StatCard
              icon={Shield}
              label="Coverage"
              value={`${coveragePercent}%`}
              accentColorVar="--ac-green"
              description="Discovery coverage"
            />
          </Grid>
        </motion.section>

        {/* Maintain animation stagger chain */}
        <motion.div variants={itemVariants}>
          <Grid cols={3} gap="xl">
            <Box style={{ gridColumn: 'span 2' }}>
              <TrafficChart data={displayTraffic} />
            </Box>
            <AttackTypesChart data={DEMO_ATTACK_TYPES} />
          </Grid>
        </motion.div>

        {/* Maintain animation stagger chain */}
        <motion.div variants={itemVariants}>
          <Grid cols={3} gap="xl">
            <Box style={{ gridColumn: 'span 2' }}>
              <RecentBlockedTable requests={displayBlocked} />
            </Box>
            <AlertsFeed alerts={displayAlerts} />
          </Grid>
        </motion.div>
      </Stack>
    </Box>
    </motion.div>
  );
}
