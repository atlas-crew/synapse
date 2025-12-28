/**
 * Attack Patterns Page
 * Pattern detection, threat intelligence, and trend analysis
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Target,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  BarChart3,
  Activity,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type PatternCategory = 'injection' | 'authentication' | 'bot' | 'rate_abuse' | 'data_exposure' | 'protocol';
type TrendDirection = 'up' | 'down' | 'stable';

// Demo data - attack patterns
const DEMO_ATTACK_PATTERNS = [
  {
    id: 'pat-001',
    name: 'SQL Injection',
    category: 'injection' as PatternCategory,
    count: 1247,
    blocked: 1245,
    trend: 'up' as TrendDirection,
    trendPercent: 23,
    severity: 'critical',
    lastSeen: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/users/search', '/api/v1/products', '/api/v1/orders'],
    signatures: ['UNION SELECT', "' OR '1'='1", 'DROP TABLE', 'INSERT INTO'],
  },
  {
    id: 'pat-002',
    name: 'Cross-Site Scripting (XSS)',
    category: 'injection' as PatternCategory,
    count: 892,
    blocked: 890,
    trend: 'down' as TrendDirection,
    trendPercent: 8,
    severity: 'high',
    lastSeen: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/comments', '/api/v1/profile', '/api/v1/messages'],
    signatures: ['<script>', 'javascript:', 'onerror=', 'onclick='],
  },
  {
    id: 'pat-003',
    name: 'Credential Stuffing',
    category: 'authentication' as PatternCategory,
    count: 756,
    blocked: 754,
    trend: 'up' as TrendDirection,
    trendPercent: 45,
    severity: 'high',
    lastSeen: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/auth/login', '/api/v1/auth/register'],
    signatures: ['rapid attempts', 'credential rotation', 'known leaked credentials'],
  },
  {
    id: 'pat-004',
    name: 'Bot Scraping',
    category: 'bot' as PatternCategory,
    count: 534,
    blocked: 532,
    trend: 'stable' as TrendDirection,
    trendPercent: 2,
    severity: 'medium',
    lastSeen: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/products', '/api/v1/search', '/api/v1/catalog'],
    signatures: ['no JS execution', 'headless browser', 'rapid sequential requests'],
  },
  {
    id: 'pat-005',
    name: 'Path Traversal',
    category: 'injection' as PatternCategory,
    count: 423,
    blocked: 423,
    trend: 'down' as TrendDirection,
    trendPercent: 15,
    severity: 'high',
    lastSeen: new Date(Date.now() - 18 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/files/download', '/api/v1/assets'],
    signatures: ['../', '%2e%2e', 'etc/passwd'],
  },
  {
    id: 'pat-006',
    name: 'Rate Limit Abuse',
    category: 'rate_abuse' as PatternCategory,
    count: 389,
    blocked: 385,
    trend: 'up' as TrendDirection,
    trendPercent: 12,
    severity: 'low',
    lastSeen: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/products', '/api/v1/search'],
    signatures: ['exceeds threshold', 'burst traffic', 'distributed sources'],
  },
  {
    id: 'pat-007',
    name: 'API Key Exposure Attempt',
    category: 'data_exposure' as PatternCategory,
    count: 234,
    blocked: 234,
    trend: 'stable' as TrendDirection,
    trendPercent: 3,
    severity: 'medium',
    lastSeen: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/config', '/api/v1/settings'],
    signatures: ['api_key=', 'secret=', 'authorization probe'],
  },
  {
    id: 'pat-008',
    name: 'Protocol Violation',
    category: 'protocol' as PatternCategory,
    count: 178,
    blocked: 178,
    trend: 'down' as TrendDirection,
    trendPercent: 20,
    severity: 'medium',
    lastSeen: new Date(Date.now() - 60 * 60 * 1000).toISOString(),
    topTargets: ['/api/v1/upload', '/api/v1/webhook'],
    signatures: ['malformed headers', 'content-length mismatch', 'invalid encoding'],
  },
];

// Demo data - pattern timeline
const DEMO_PATTERN_TIMELINE = [
  { day: 'Mon', injection: 45, auth: 28, bot: 22, other: 15 },
  { day: 'Tue', injection: 52, auth: 32, bot: 25, other: 18 },
  { day: 'Wed', injection: 48, auth: 38, bot: 28, other: 20 },
  { day: 'Thu', injection: 65, auth: 42, bot: 32, other: 22 },
  { day: 'Fri', injection: 58, auth: 48, bot: 35, other: 25 },
  { day: 'Sat', injection: 35, auth: 25, bot: 18, other: 12 },
  { day: 'Sun', injection: 28, auth: 20, bot: 15, other: 10 },
];

// Demo data - category distribution
const DEMO_CATEGORY_DIST = [
  { name: 'Injection', value: 2562, color: '#ef4444' },
  { name: 'Authentication', value: 756, color: '#f97316' },
  { name: 'Bot Activity', value: 534, color: '#8b5cf6' },
  { name: 'Rate Abuse', value: 389, color: '#3b82f6' },
  { name: 'Data Exposure', value: 234, color: '#22c55e' },
  { name: 'Protocol', value: 178, color: '#eab308' },
];

const CATEGORY_CONFIG: Record<PatternCategory, { label: string; color: string; bg: string }> = {
  injection: { label: 'Injection', color: 'text-red-400', bg: 'bg-red-500/20' },
  authentication: { label: 'Authentication', color: 'text-orange-400', bg: 'bg-orange-500/20' },
  bot: { label: 'Bot Activity', color: 'text-purple-400', bg: 'bg-purple-500/20' },
  rate_abuse: { label: 'Rate Abuse', color: 'text-blue-400', bg: 'bg-blue-500/20' },
  data_exposure: { label: 'Data Exposure', color: 'text-green-400', bg: 'bg-green-500/20' },
  protocol: { label: 'Protocol', color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
};

const SEVERITY_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20' },
};

const CHART_COLORS = {
  injection: '#ef4444',
  auth: '#f97316',
  bot: '#8b5cf6',
  other: '#6b7280',
};

// Stat Card
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
                'text-xs mt-1 flex items-center gap-1',
                change.trend === 'up' ? 'text-red-400' : 'text-green-400'
              )}
            >
              {change.trend === 'up' ? (
                <TrendingUp className="w-3 h-3" />
              ) : (
                <TrendingDown className="w-3 h-3" />
              )}
              {Math.abs(change.value)}% vs last week
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

// Pattern Card
function PatternCard({
  pattern,
  isExpanded,
  onToggle,
}: {
  pattern: (typeof DEMO_ATTACK_PATTERNS)[0];
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const categoryConfig = CATEGORY_CONFIG[pattern.category];
  const severityConfig = SEVERITY_CONFIG[pattern.severity];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden"
    >
      <button
        onClick={onToggle}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-4">
          <div className={clsx('p-2 rounded-lg', categoryConfig.bg)}>
            <Target className={clsx('w-5 h-5', categoryConfig.color)} />
          </div>
          <div className="text-left">
            <h3 className="text-white font-medium">{pattern.name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <span className={clsx('px-2 py-0.5 rounded text-xs', categoryConfig.bg, categoryConfig.color)}>
                {categoryConfig.label}
              </span>
              <span className={clsx('px-2 py-0.5 rounded text-xs', severityConfig.bg, severityConfig.color)}>
                {pattern.severity}
              </span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-sm text-gray-400">Detections</p>
            <p className="text-white font-medium">{pattern.count.toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Block Rate</p>
            <p className="text-green-400 font-medium">
              {((pattern.blocked / pattern.count) * 100).toFixed(1)}%
            </p>
          </div>
          <div className="text-right min-w-[80px]">
            <p className="text-sm text-gray-400">Trend</p>
            <p
              className={clsx(
                'font-medium flex items-center gap-1 justify-end',
                pattern.trend === 'up'
                  ? 'text-red-400'
                  : pattern.trend === 'down'
                  ? 'text-green-400'
                  : 'text-gray-400'
              )}
            >
              {pattern.trend === 'up' ? (
                <TrendingUp className="w-4 h-4" />
              ) : pattern.trend === 'down' ? (
                <TrendingDown className="w-4 h-4" />
              ) : (
                <Activity className="w-4 h-4" />
              )}
              {pattern.trendPercent}%
            </p>
          </div>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
      </button>

      {isExpanded && (
        <div className="px-5 py-4 border-t border-gray-700 bg-gray-800/50">
          <div className="grid grid-cols-2 gap-6">
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Top Targeted Endpoints</h4>
              <div className="space-y-2">
                {pattern.topTargets.map((target, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="text-gray-500">{idx + 1}.</span>
                    <code className="text-blue-400 text-sm">{target}</code>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Detection Signatures</h4>
              <div className="flex flex-wrap gap-2">
                {pattern.signatures.map((sig, idx) => (
                  <code
                    key={idx}
                    className={clsx(
                      'px-2 py-1 rounded text-xs',
                      categoryConfig.bg,
                      categoryConfig.color
                    )}
                  >
                    {sig}
                  </code>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function AttackPatternsPage() {
  const [expandedPatterns, setExpandedPatterns] = useState<Set<string>>(new Set());
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const isLoading = false;

  // Filter patterns
  const filteredPatterns = useMemo(() => {
    if (!categoryFilter) return DEMO_ATTACK_PATTERNS;
    return DEMO_ATTACK_PATTERNS.filter((p) => p.category === categoryFilter);
  }, [categoryFilter]);

  // Calculate stats
  const stats = useMemo(() => {
    const totalPatterns = DEMO_ATTACK_PATTERNS.length;
    const totalDetections = DEMO_ATTACK_PATTERNS.reduce((sum, p) => sum + p.count, 0);
    const totalBlocked = DEMO_ATTACK_PATTERNS.reduce((sum, p) => sum + p.blocked, 0);
    const criticalPatterns = DEMO_ATTACK_PATTERNS.filter((p) => p.severity === 'critical').length;
    const avgBlockRate = ((totalBlocked / totalDetections) * 100).toFixed(1);
    const risingPatterns = DEMO_ATTACK_PATTERNS.filter((p) => p.trend === 'up').length;

    return { totalPatterns, totalDetections, criticalPatterns, avgBlockRate, risingPatterns };
  }, []);

  const togglePattern = (patternId: string) => {
    const newExpanded = new Set(expandedPatterns);
    if (newExpanded.has(patternId)) {
      newExpanded.delete(patternId);
    } else {
      newExpanded.add(patternId);
    }
    setExpandedPatterns(newExpanded);
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Attack Patterns</h1>
          <p className="text-gray-400 mt-1">Loading pattern data...</p>
        </div>
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Attack Patterns</h1>
        <p className="text-gray-400 mt-1">Pattern detection and threat intelligence</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-5 gap-4">
        <StatCard
          label="Unique Patterns"
          value={stats.totalPatterns.toString()}
          icon={Target}
          color="text-horizon-400"
        />
        <StatCard
          label="Total Detections"
          value={stats.totalDetections.toLocaleString()}
          change={{ value: 18, trend: 'up' }}
          icon={Activity}
          color="text-blue-400"
        />
        <StatCard
          label="Critical Patterns"
          value={stats.criticalPatterns.toString()}
          icon={AlertTriangle}
          color="text-red-400"
        />
        <StatCard
          label="Block Rate"
          value={`${stats.avgBlockRate}%`}
          icon={Shield}
          color="text-green-400"
        />
        <StatCard
          label="Rising Patterns"
          value={stats.risingPatterns.toString()}
          icon={TrendingUp}
          color="text-orange-400"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-3 gap-4">
        {/* Pattern Trend */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="col-span-2 bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <h3 className="text-white font-medium mb-4">Weekly Pattern Trend</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={DEMO_PATTERN_TIMELINE}>
                <XAxis
                  dataKey="day"
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
                <Line
                  type="monotone"
                  dataKey="injection"
                  stroke={CHART_COLORS.injection}
                  strokeWidth={2}
                  dot={false}
                  name="Injection"
                />
                <Line
                  type="monotone"
                  dataKey="auth"
                  stroke={CHART_COLORS.auth}
                  strokeWidth={2}
                  dot={false}
                  name="Auth"
                />
                <Line
                  type="monotone"
                  dataKey="bot"
                  stroke={CHART_COLORS.bot}
                  strokeWidth={2}
                  dot={false}
                  name="Bot"
                />
                <Line
                  type="monotone"
                  dataKey="other"
                  stroke={CHART_COLORS.other}
                  strokeWidth={2}
                  dot={false}
                  name="Other"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <div className="flex items-center justify-center gap-6 mt-4">
            {Object.entries(CHART_COLORS).map(([key, color]) => (
              <div key={key} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                <span className="text-sm text-gray-400 capitalize">{key}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* Category Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-gray-800 border border-gray-700 rounded-xl p-5"
        >
          <h3 className="text-white font-medium mb-4">Category Distribution</h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={DEMO_CATEGORY_DIST}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {DEMO_CATEGORY_DIST.map((entry, index) => (
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
          <div className="space-y-2 mt-4">
            {DEMO_CATEGORY_DIST.slice(0, 4).map((item) => (
              <div key={item.name} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-gray-400">{item.name}</span>
                </div>
                <span className="text-white">{item.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </motion.div>
      </div>

      {/* Top Patterns by Volume */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gray-800 border border-gray-700 rounded-xl p-5"
      >
        <h3 className="text-white font-medium mb-4">Top Patterns by Volume</h3>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={DEMO_ATTACK_PATTERNS.slice(0, 6)} layout="vertical">
              <XAxis
                type="number"
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#9ca3af', fontSize: 12 }}
              />
              <YAxis
                type="category"
                dataKey="name"
                axisLine={false}
                tickLine={false}
                tick={{ fill: '#9ca3af', fontSize: 11 }}
                width={140}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1f2937',
                  border: '1px solid #374151',
                  borderRadius: '0.5rem',
                }}
              />
              <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} name="Detections" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </motion.div>

      {/* Filter */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-gray-400" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-horizon-500"
          >
            <option value="">All Categories</option>
            {Object.entries(CATEGORY_CONFIG).map(([key, config]) => (
              <option key={key} value={key}>
                {config.label}
              </option>
            ))}
          </select>
        </div>
        <span className="text-sm text-gray-400">
          Showing {filteredPatterns.length} of {DEMO_ATTACK_PATTERNS.length} patterns
        </span>
      </div>

      {/* Patterns List */}
      <div className="space-y-3">
        {filteredPatterns.map((pattern) => (
          <PatternCard
            key={pattern.id}
            pattern={pattern}
            isExpanded={expandedPatterns.has(pattern.id)}
            onToggle={() => togglePattern(pattern.id)}
          />
        ))}
        {filteredPatterns.length === 0 && (
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-8 text-center">
            <p className="text-gray-400">No patterns match your filter</p>
          </div>
        )}
      </div>
    </div>
  );
}
