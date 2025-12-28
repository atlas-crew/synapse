/**
 * Error Analysis Page
 * Error rates, breakdown by type, and root cause analysis
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  AlertCircle,
  TrendingUp,
  TrendingDown,
  Server,
  ShieldAlert,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d';

const TIME_RANGES: { value: TimeRange; label: string }[] = [
  { value: '1h', label: '1 Hour' },
  { value: '6h', label: '6 Hours' },
  { value: '24h', label: '24 Hours' },
  { value: '7d', label: '7 Days' },
  { value: '30d', label: '30 Days' },
];

// Demo data - error rates over time
const DEMO_ERROR_TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, '0')}:00`,
  total: Math.floor(Math.random() * 5000) + 2000,
  errors4xx: Math.floor(Math.random() * 100) + 20,
  errors5xx: Math.floor(Math.random() * 30) + 5,
  blocked: Math.floor(Math.random() * 50) + 10,
}));

// Demo data - error type breakdown
const DEMO_ERROR_TYPES = [
  { type: '400 Bad Request', count: 1250, percentage: 35 },
  { type: '401 Unauthorized', count: 890, percentage: 25 },
  { type: '403 Forbidden', count: 535, percentage: 15 },
  { type: '404 Not Found', count: 425, percentage: 12 },
  { type: '500 Internal Server Error', count: 320, percentage: 9 },
  { type: '503 Service Unavailable', count: 140, percentage: 4 },
];

// Demo data - error breakdown by category
const DEMO_ERROR_CATEGORIES = [
  { name: 'Client Errors (4xx)', value: 3100, color: '#f59e0b' },
  { name: 'Server Errors (5xx)', value: 460, color: '#ef4444' },
  { name: 'Blocked by WAF', value: 890, color: '#8b5cf6' },
];

// Demo data - endpoints with highest errors
const DEMO_ERROR_ENDPOINTS = [
  { endpoint: '/api/v1/auth/login', total: 12500, errors: 450, rate: 3.6 },
  { endpoint: '/api/v1/users/profile', total: 8900, errors: 210, rate: 2.4 },
  { endpoint: '/api/v1/orders/create', total: 5600, errors: 180, rate: 3.2 },
  { endpoint: '/api/v1/search', total: 15200, errors: 150, rate: 1.0 },
  { endpoint: '/api/v1/payments/process', total: 3400, errors: 85, rate: 2.5 },
];

const CHART_COLORS = {
  total: '#3b82f6',
  errors4xx: '#f59e0b',
  errors5xx: '#ef4444',
  blocked: '#8b5cf6',
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
    <div className="flex gap-1 bg-gray-800 rounded-lg p-1">
      {TIME_RANGES.map((range) => (
        <button
          key={range.value}
          onClick={() => onChange(range.value)}
          className={clsx(
            'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
            value === range.value
              ? 'bg-horizon-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-700'
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
  subvalue,
  trend,
  icon: Icon,
  color,
}: {
  label: string;
  value: string;
  subvalue?: string;
  trend?: { value: number; isGood: boolean };
  icon: React.ElementType;
  color: 'yellow' | 'red' | 'purple' | 'blue';
}) {
  const colorClasses = {
    yellow: 'text-yellow-400 bg-yellow-500/20',
    red: 'text-red-400 bg-red-500/20',
    purple: 'text-purple-400 bg-purple-500/20',
    blue: 'text-blue-400 bg-blue-500/20',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <div className="mt-1 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{value}</span>
            {subvalue && <span className="text-sm text-gray-400">{subvalue}</span>}
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
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </motion.div>
  );
}

// Error Timeline Chart
function ErrorTimelineChart({ data }: { data: typeof DEMO_ERROR_TIMELINE }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-white">Error Rate Over Time</h3>
          <p className="text-sm text-gray-400 mt-1">4xx, 5xx, and blocked requests</p>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <span className="text-gray-400">4xx</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <span className="text-gray-400">5xx</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-purple-500" />
            <span className="text-gray-400">Blocked</span>
          </div>
        </div>
      </div>
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="errors4xxGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.errors4xx} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.errors4xx} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="errors5xxGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.errors5xx} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.errors5xx} stopOpacity={0} />
              </linearGradient>
              <linearGradient id="blockedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={CHART_COLORS.blocked} stopOpacity={0.3} />
                <stop offset="95%" stopColor={CHART_COLORS.blocked} stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
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
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '8px',
              }}
              labelStyle={{ color: '#9ca3af' }}
              itemStyle={{ color: '#fff' }}
            />
            <Area
              type="monotone"
              dataKey="errors4xx"
              stroke={CHART_COLORS.errors4xx}
              fill="url(#errors4xxGrad)"
              strokeWidth={2}
              name="4xx Errors"
            />
            <Area
              type="monotone"
              dataKey="errors5xx"
              stroke={CHART_COLORS.errors5xx}
              fill="url(#errors5xxGrad)"
              strokeWidth={2}
              name="5xx Errors"
            />
            <Area
              type="monotone"
              dataKey="blocked"
              stroke={CHART_COLORS.blocked}
              fill="url(#blockedGrad)"
              strokeWidth={2}
              name="Blocked"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// Error Category Pie Chart
function ErrorCategoryChart({ data }: { data: typeof DEMO_ERROR_CATEGORIES }) {
  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <h3 className="text-lg font-semibold text-white mb-4">Error Distribution</h3>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={70}
              paddingAngle={4}
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: '#1f2937',
                border: '1px solid #374151',
                borderRadius: '8px',
              }}
              formatter={(value: number) => [
                `${value.toLocaleString()} (${((value / total) * 100).toFixed(1)}%)`,
                'Errors',
              ]}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="space-y-2 mt-4">
        {data.map((item) => (
          <div key={item.name} className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: item.color }}
              />
              <span className="text-sm text-gray-400">{item.name}</span>
            </div>
            <span className="text-sm font-medium text-white">
              {item.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Error Types Breakdown
function ErrorTypesTable({ data }: { data: typeof DEMO_ERROR_TYPES }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl p-5">
      <h3 className="text-lg font-semibold text-white mb-4">Error Types</h3>
      <div className="space-y-3">
        {data.map((item) => (
          <div key={item.type}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm text-gray-300">{item.type}</span>
              <span className="text-sm font-medium text-white">
                {item.count.toLocaleString()}
              </span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div
                className={clsx(
                  'h-2 rounded-full transition-all',
                  item.type.startsWith('5')
                    ? 'bg-red-500'
                    : item.type.startsWith('4')
                    ? 'bg-yellow-500'
                    : 'bg-blue-500'
                )}
                style={{ width: `${item.percentage}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Endpoints with Highest Errors
function HighErrorEndpointsTable({ data }: { data: typeof DEMO_ERROR_ENDPOINTS }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-xl">
      <div className="px-5 py-4 border-b border-gray-700">
        <h3 className="text-lg font-semibold text-white">Highest Error Endpoints</h3>
        <p className="text-sm text-gray-400 mt-1">Endpoints with the most errors</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left text-sm text-gray-400 border-b border-gray-700">
              <th className="px-5 py-3 font-medium">Endpoint</th>
              <th className="px-5 py-3 font-medium text-right">Total Requests</th>
              <th className="px-5 py-3 font-medium text-right">Errors</th>
              <th className="px-5 py-3 font-medium text-right">Error Rate</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item, idx) => (
              <tr
                key={item.endpoint}
                className="border-b border-gray-700/50 hover:bg-gray-750 transition-colors"
              >
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <span className="text-gray-500 text-sm w-6">{idx + 1}</span>
                    <code className="text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded text-sm">
                      {item.endpoint}
                    </code>
                  </div>
                </td>
                <td className="px-5 py-3 text-right text-gray-300">
                  {item.total.toLocaleString()}
                </td>
                <td className="px-5 py-3 text-right text-red-400 font-medium">
                  {item.errors.toLocaleString()}
                </td>
                <td className="px-5 py-3 text-right">
                  <span
                    className={clsx(
                      'px-2 py-0.5 rounded text-xs font-medium',
                      item.rate < 2
                        ? 'text-green-400 bg-green-500/20'
                        : item.rate < 3
                        ? 'text-yellow-400 bg-yellow-500/20'
                        : 'text-red-400 bg-red-500/20'
                    )}
                  >
                    {item.rate.toFixed(1)}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function ErrorAnalysisPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const isLoading = false;

  // Calculate summary stats from demo data
  const stats = useMemo(() => {
    const data = DEMO_ERROR_TIMELINE;
    const total4xx = data.reduce((sum, d) => sum + d.errors4xx, 0);
    const total5xx = data.reduce((sum, d) => sum + d.errors5xx, 0);
    const totalBlocked = data.reduce((sum, d) => sum + d.blocked, 0);
    const totalRequests = data.reduce((sum, d) => sum + d.total, 0);
    const errorRate = ((total4xx + total5xx) / totalRequests) * 100;

    return { total4xx, total5xx, totalBlocked, errorRate };
  }, []);

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Error Analysis</h1>
          <p className="text-gray-400 mt-1">Loading error data...</p>
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
          <h1 className="text-2xl font-bold text-white">Error Analysis</h1>
          <p className="text-gray-400 mt-1">Error rates and patterns</p>
        </div>
        <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="4xx Client Errors"
          value={stats.total4xx.toLocaleString()}
          trend={{ value: 8, isGood: true }}
          icon={AlertCircle}
          color="yellow"
        />
        <StatCard
          label="5xx Server Errors"
          value={stats.total5xx.toLocaleString()}
          trend={{ value: 12, isGood: true }}
          icon={Server}
          color="red"
        />
        <StatCard
          label="Blocked Requests"
          value={stats.totalBlocked.toLocaleString()}
          trend={{ value: 5, isGood: false }}
          icon={ShieldAlert}
          color="purple"
        />
        <StatCard
          label="Error Rate"
          value={stats.errorRate.toFixed(2)}
          subvalue="%"
          trend={{ value: 10, isGood: true }}
          icon={TrendingDown}
          color="blue"
        />
      </div>

      {/* Error Timeline */}
      <ErrorTimelineChart data={DEMO_ERROR_TIMELINE} />

      {/* Error Breakdown Section */}
      <div className="grid grid-cols-3 gap-6">
        <ErrorCategoryChart data={DEMO_ERROR_CATEGORIES} />
        <ErrorTypesTable data={DEMO_ERROR_TYPES} />
        <div className="col-span-1" />
      </div>

      {/* High Error Endpoints */}
      <HighErrorEndpointsTable data={DEMO_ERROR_ENDPOINTS} />
    </div>
  );
}
