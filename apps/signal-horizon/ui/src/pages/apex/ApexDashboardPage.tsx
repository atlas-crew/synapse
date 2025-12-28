/**
 * Apex Protection Dashboard
 * Real-time API security overview with traffic, threats, and protection status
 */

import { useMemo } from 'react';
import { motion } from 'framer-motion';
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
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  // useApexDashboard,
  useApexStats,
  useBlockedRequests,
  useApexAlerts,
  useApexLoading,
  useTrafficTimeline,
} from '../../stores/apexStore';
import { StatsGridSkeleton, TableSkeleton, CardSkeleton } from '../../components/LoadingStates';
import type { BlockedRequest, ProtectionAlert, TrafficDataPoint } from '../../types/apex';

// Color palette for dark theme
const COLORS = {
  requests: '#3b82f6', // blue
  blocked: '#ef4444', // red
  protected: '#22c55e', // green
  warning: '#f59e0b', // amber
  chart: {
    area: 'rgba(59, 130, 246, 0.2)',
    line: '#3b82f6',
    blocked: 'rgba(239, 68, 68, 0.4)',
    blockedLine: '#ef4444',
  },
};

const PIE_COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6'];

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
  color: string;
  bgColor: string;
}

function StatCard({ icon: Icon, label, value, trend, color, bgColor }: StatCardProps) {
  const trendColor = trend && trend.value >= 0 ? 'text-green-400' : 'text-red-400';
  const TrendIcon = trend && trend.value >= 0 ? TrendingUp : TrendingDown;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm font-medium text-gray-400">{label}</p>
          <p className="mt-2 text-3xl font-bold text-white">{value.toLocaleString()}</p>
          {trend && (
            <div className={clsx('mt-2 flex items-center gap-1 text-sm', trendColor)}>
              <TrendIcon className="w-4 h-4" />
              <span>{Math.abs(trend.value)}%</span>
              <span className="text-gray-500">{trend.period}</span>
            </div>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg', bgColor)}>
          <Icon className={clsx('w-6 h-6', color)} />
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
  const formattedData = useMemo(() =>
    data.map(d => ({
      ...d,
      time: new Date(d.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    })), [data]
  );

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-white">Traffic Overview</h3>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-500" />
            <span className="text-gray-400">Requests</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <span className="text-gray-400">Blocked</span>
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
            <XAxis
              dataKey="time"
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              axisLine={{ stroke: '#374151' }}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: '#9ca3af', fontSize: 12 }}
              axisLine={{ stroke: '#374151' }}
              tickLine={false}
              tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#9ca3af' }}
            />
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

// Attack Types Pie Chart
function AttackTypesChart({ data }: { data: typeof DEMO_ATTACK_TYPES }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <h3 className="text-lg font-semibold text-white mb-4">Attack Distribution</h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={70}
              paddingAngle={2}
              dataKey="count"
              nameKey="type"
            >
              {data.map((_, index) => (
                <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '8px',
                color: '#fff',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-4 space-y-2">
        {data.map((item, index) => (
          <div key={item.type} className="flex items-center justify-between text-sm">
            <div className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: PIE_COLORS[index % PIE_COLORS.length] }}
              />
              <span className="text-gray-400">{item.type}</span>
            </div>
            <span className="text-white font-medium">{item.percentage}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Recent Blocked Requests Table
function RecentBlockedTable({ requests }: { requests: BlockedRequest[] }) {
  const actionColors: Record<string, string> = {
    blocked: 'text-red-400 bg-red-500/20',
    challenged: 'text-yellow-400 bg-yellow-500/20',
    throttled: 'text-orange-400 bg-orange-500/20',
    logged: 'text-blue-400 bg-blue-500/20',
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl">
      <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Recent Blocked Requests</h3>
        <span className="text-sm text-gray-400">{requests.length} blocked</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-gray-400 border-b border-gray-700">
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
                className="border-b border-gray-700/50 hover:bg-gray-750 transition-colors"
              >
                <td className="px-5 py-3 text-sm text-gray-400">
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    {new Date(req.timestamp).toLocaleTimeString()}
                  </div>
                </td>
                <td className="px-5 py-3 text-sm">
                  <code className="text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded">
                    {req.method} {req.endpoint}
                  </code>
                </td>
                <td className="px-5 py-3 text-sm text-gray-300">
                  <div className="flex items-center gap-2">
                    <Globe className="w-4 h-4 text-gray-500" />
                    {req.sourceIp}
                  </div>
                </td>
                <td className="px-5 py-3 text-sm text-gray-300">{req.threatType}</td>
                <td className="px-5 py-3">
                  <span
                    className={clsx(
                      'px-2 py-1 rounded text-xs font-medium',
                      actionColors[req.action] || actionColors.blocked
                    )}
                  >
                    {req.action}
                  </span>
                </td>
              </tr>
            ))}
            {requests.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8 text-center text-gray-500">
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
    low: 'border-l-green-500 bg-green-500/5',
    medium: 'border-l-yellow-500 bg-yellow-500/5',
    high: 'border-l-orange-500 bg-orange-500/5',
    critical: 'border-l-red-500 bg-red-500/5',
  };

  const typeIcons: Record<string, LucideIcon> = {
    endpoint_discovered: Globe,
    schema_change: Activity,
    rule_triggered: Zap,
    deployment_complete: Shield,
  };

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl">
      <div className="px-5 py-4 border-b border-gray-700">
        <h3 className="text-lg font-semibold text-white">Recent Alerts</h3>
      </div>
      <div className="divide-y divide-gray-700/50 max-h-80 overflow-y-auto">
        {alerts.slice(0, 5).map((alert) => {
          const Icon = typeIcons[alert.type] || AlertTriangle;
          return (
            <motion.div
              key={alert.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={clsx(
                'px-5 py-4 border-l-4',
                severityColors[alert.severity] || severityColors.low
              )}
            >
              <div className="flex items-start gap-3">
                <Icon className="w-5 h-5 text-gray-400 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-white truncate">{alert.title}</p>
                  <p className="text-xs text-gray-400 mt-1 truncate">{alert.description}</p>
                  <p className="text-xs text-gray-500 mt-2">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                </div>
              </div>
            </motion.div>
          );
        })}
        {alerts.length === 0 && (
          <div className="px-5 py-8 text-center text-gray-500">No recent alerts</div>
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
export default function ApexDashboardPage() {
  const isLoading = useApexLoading();
  // const dashboard = useApexDashboard(); // Will be used when real data comes in
  const stats = useApexStats();
  const blockedRequests = useBlockedRequests();
  const alerts = useApexAlerts();
  const trafficTimeline = useTrafficTimeline();

  // Use demo data for now (will be replaced by real data from WebSocket/API)
  const displayTraffic = trafficTimeline.length > 0 ? trafficTimeline : DEMO_TRAFFIC;
  const displayBlocked = blockedRequests.length > 0 ? blockedRequests : DEMO_BLOCKED;
  const displayAlerts = alerts.length > 0 ? alerts : DEMO_ALERTS;

  // Show loading skeletons while initial data loads
  if (isLoading) {
    return (
      <div className="p-6 space-y-6" role="main" aria-busy="true" aria-label="Loading Apex dashboard">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">Apex Protection Dashboard</h1>
            <p className="text-gray-400 mt-1">Loading protection status...</p>
          </div>
        </div>
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

  // Calculate display values
  const totalRequests = stats.blockedRequests24h || 1247;
  const blockedCount = stats.blockedRequests24h || 89;
  const endpointCount = stats.totalEndpoints || 45;
  const coveragePercent = stats.protectedEndpoints
    ? Math.round((stats.protectedEndpoints / Math.max(stats.totalEndpoints, 1)) * 100)
    : 94;

  return (
    <div className="p-6 space-y-6" role="main" aria-label="Apex protection dashboard">
      {/* Header */}
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Apex Protection Dashboard</h1>
          <p className="text-gray-400 mt-1">Real-time API security overview</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-sm" role="status" aria-live="polite">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" aria-hidden="true" />
            <span className="text-green-400">Protected</span>
          </div>
        </div>
      </header>

      {/* Stats Grid */}
      <section aria-label="Key metrics" className="grid grid-cols-4 gap-4">
        <StatCard
          icon={Activity}
          label="Requests (24h)"
          value={`${(totalRequests / 1000).toFixed(1)}k`}
          trend={{ value: 12, period: 'vs yesterday' }}
          color="text-blue-400"
          bgColor="bg-blue-500/10"
        />
        <StatCard
          icon={Shield}
          label="Blocked"
          value={blockedCount}
          trend={{ value: -8, period: 'vs yesterday' }}
          color="text-red-400"
          bgColor="bg-red-500/10"
        />
        <StatCard
          icon={Target}
          label="Endpoints"
          value={endpointCount}
          trend={{ value: 3, period: 'new this week' }}
          color="text-purple-400"
          bgColor="bg-purple-500/10"
        />
        <StatCard
          icon={Shield}
          label="Coverage"
          value={`${coveragePercent}%`}
          color="text-green-400"
          bgColor="bg-green-500/10"
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
