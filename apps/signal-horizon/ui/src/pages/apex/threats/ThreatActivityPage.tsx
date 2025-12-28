/**
 * Threat Activity Page
 * Real-time threat monitoring with heatmap and incident timeline
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  Shield,
  ShieldAlert,
  Activity,
  Clock,
  MapPin,
  Target,
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
  Cell,
  PieChart,
  Pie,
} from 'recharts';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low';
type TimeRange = '1h' | '6h' | '24h' | '7d';

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

// Demo data - severity distribution
const DEMO_SEVERITY_DIST = [
  { name: 'Critical', value: 42, color: '#ef4444' },
  { name: 'High', value: 168, color: '#f97316' },
  { name: 'Medium', value: 289, color: '#eab308' },
  { name: 'Low', value: 198, color: '#3b82f6' },
];

const SEVERITY_CONFIG: Record<ThreatSeverity, { color: string; bg: string; label: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20', label: 'Critical' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20', label: 'High' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20', label: 'Medium' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'Low' },
};

const CHART_COLORS = {
  threats: '#ef4444',
  blocked: '#22c55e',
  gradient: {
    start: '#ef4444',
    end: '#f97316',
  },
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
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
          {change && (
            <p
              className={clsx(
                'text-xs mt-1',
                change.trend === 'up' ? 'text-red-400' : 'text-green-400'
              )}
            >
              {change.trend === 'up' ? '↑' : '↓'} {Math.abs(change.value)}% vs last period
            </p>
          )}
        </div>
        <div className="p-3 bg-gray-700/50 rounded-lg">
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
    <div className="flex items-center gap-1 bg-gray-800 rounded-lg p-1">
      {options.map((option) => (
        <button
          key={option.value}
          onClick={() => onChange(option.value)}
          className={clsx(
            'px-3 py-1.5 rounded-md text-sm font-medium transition-colors',
            value === option.value
              ? 'bg-horizon-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-700'
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

// Incident Card
function IncidentCard({ incident }: { incident: (typeof DEMO_INCIDENTS)[0] }) {
  const config = SEVERITY_CONFIG[incident.severity];

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="bg-gray-800/50 border border-gray-700 rounded-lg p-4 hover:bg-gray-750 transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3">
          <div className={clsx('p-2 rounded-lg', config.bg)}>
            <ShieldAlert className={clsx('w-4 h-4', config.color)} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-white font-medium">{incident.type}</h4>
              <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', config.bg, config.color)}>
                {config.label}
              </span>
            </div>
            <p className="text-sm text-gray-400 mt-1">{incident.details}</p>
            <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
              <span className="flex items-center gap-1">
                <MapPin className="w-3 h-3" />
                {incident.sourceIp}
              </span>
              <span className="flex items-center gap-1">
                <Target className="w-3 h-3" />
                {incident.targetEndpoint}
              </span>
            </div>
          </div>
        </div>
        <div className="text-right">
          <span className="text-xs text-gray-500 flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {formatRelativeTime(incident.timestamp)}
          </span>
          {incident.blocked && (
            <span className="mt-1 inline-block px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs">
              Blocked
            </span>
          )}
        </div>
      </div>
    </motion.div>
  );
}

export default function ThreatActivityPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const isLoading = false;

  // Calculate stats
  const stats = useMemo(() => {
    const totalThreats = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.threats, 0);
    const totalBlocked = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.blocked, 0);
    const criticalCount = DEMO_THREAT_TIMELINE.reduce((sum, d) => sum + d.critical, 0);
    const blockRate = ((totalBlocked / totalThreats) * 100).toFixed(1);

    return { totalThreats, totalBlocked, criticalCount, blockRate };
  }, []);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Activity</h1>
          <p className="text-gray-400 mt-1">Loading threat data...</p>
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
          <h1 className="text-2xl font-bold text-white">Threat Activity</h1>
          <p className="text-gray-400 mt-1">Real-time threat monitoring and incident response</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

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
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="col-span-2 bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <h3 className="text-white font-medium mb-4">Threat Timeline</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={DEMO_THREAT_TIMELINE}>
                <defs>
                  <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={CHART_COLORS.gradient.start} stopOpacity={0.4} />
                    <stop offset="95%" stopColor={CHART_COLORS.gradient.end} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="time"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#9ca3af', fontSize: 12 }}
                />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '0.5rem',
                  }}
                  labelStyle={{ color: '#9ca3af' }}
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  stroke={CHART_COLORS.threats}
                  fill="url(#threatGradient)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </motion.div>

        {/* Severity Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <h3 className="text-white font-medium mb-4">Severity Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={DEMO_SEVERITY_DIST}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {DEMO_SEVERITY_DIST.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '0.5rem',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2">
            {DEMO_SEVERITY_DIST.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-sm text-gray-400">{item.name}</span>
                <span className="text-sm text-white ml-auto">{item.value}</span>
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
          className="col-span-2 bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-white font-medium">Recent Incidents</h3>
            <button className="text-sm text-horizon-400 hover:text-horizon-300 transition-colors">
              View all →
            </button>
          </div>
          <div className="space-y-3">
            {DEMO_INCIDENTS.map((incident) => (
              <IncidentCard key={incident.id} incident={incident} />
            ))}
          </div>
        </motion.div>

        {/* Top Threat Sources */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <h3 className="text-white font-medium mb-4">Top Threat Sources</h3>
          <div className="h-48 mb-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={DEMO_TOP_SOURCES} layout="vertical">
                <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis
                  type="category"
                  dataKey="ip"
                  axisLine={false}
                  tickLine={false}
                  tick={{ fill: '#9ca3af', fontSize: 11 }}
                  width={110}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1f2937',
                    border: '1px solid #374151',
                    borderRadius: '0.5rem',
                  }}
                />
                <Bar dataKey="threats" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2">
            {DEMO_TOP_SOURCES.slice(0, 3).map((source) => (
              <div key={source.ip} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <span className="text-gray-400 font-mono">{source.ip}</span>
                  <span className="text-xs text-gray-500">({source.country})</span>
                </div>
                <span className="text-red-400">{source.threats} threats</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </div>
  );
}
