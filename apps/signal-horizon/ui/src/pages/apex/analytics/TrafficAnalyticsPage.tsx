/**
 * Traffic Analytics Page - CtrlX Design System
 * Displays traffic metrics, response time distribution, regional traffic, and status codes
 * Fetches real data from risk-server via signal-horizon API with demo fallbacks
 */

import { useState, useMemo } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import {
  Download,
  Calendar,
  Activity,
  Zap,
  AlertCircle,
  TrendingUp,
  Globe,
  Filter,
  RefreshCw,
  Wifi,
  WifiOff,
} from 'lucide-react';

import { MetricCard, TimeRangeSelector, type TimeRange } from '../../../components/ctrlx';
import {
  ResponseTimeDistributionChart,
  TrafficByRegionList,
  StatusCodesDonut,
  PerformanceMetricsGrid,
  TopEndpointsTable,
} from '../../../components/apex/analytics';
import { useApexAnalytics } from '../../../hooks/useApexAnalytics';

// Format bytes to human readable (GB, MB, etc.)
function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(0)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(0)} KB`;
  return `${bytes} B`;
}

// Format large numbers (M, K)
function formatNumber(num: number): string {
  if (num >= 1e6) return `${(num / 1e6).toFixed(1)}M`;
  if (num >= 1e3) return `${(num / 1e3).toFixed(0)}K`;
  return num.toString();
}

export default function TrafficAnalyticsPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>('24H');
  const [siteFilter, setSiteFilter] = useState<string>('all');

  // Fetch real data from API
  const { data, isLoading, isConnected, refetch, lastUpdated } = useApexAnalytics({
    pollingInterval: 30000, // Refresh every 30 seconds
  });

  // Transform traffic timeline for chart
  const trafficData = useMemo(() => {
    if (!data?.traffic.timeline?.length) {
      // Generate demo data if no real timeline available
      return Array.from({ length: 24 }, (_, i) => {
        const baseRequests = 80000 + Math.random() * 40000;
        const blockedRate = 0.02 + Math.random() * 0.03;
        return {
          hour: `${String(i).padStart(2, '0')}:00`,
          requests: Math.round(baseRequests),
          blocked: Math.round(baseRequests * blockedRate),
        };
      });
    }

    return data.traffic.timeline.map((point) => {
      const date = new Date(point.timestamp);
      return {
        hour: `${String(date.getHours()).padStart(2, '0')}:00`,
        requests: point.requests,
        blocked: point.blocked,
      };
    });
  }, [data?.traffic.timeline]);

  // Transform response time data for chart
  const responseTimeData = useMemo(() => {
    if (!data?.responseTimeDistribution?.length) return [];
    return data.responseTimeDistribution;
  }, [data?.responseTimeDistribution]);

  // Transform region data for list (map to component's expected interface)
  const regionData = useMemo(() => {
    if (!data?.regionTraffic?.length) return [];
    return data.regionTraffic.map((r) => ({
      code: r.countryCode,
      name: r.countryName,
      requests: r.requests,
      percentage: r.percentage,
    }));
  }, [data?.regionTraffic]);

  // Transform status codes for donut chart
  const statusCodeData = useMemo(() => {
    if (!data?.statusCodes) return [];
    const { code2xx, code3xx, code4xx, code5xx } = data.statusCodes;
    return [
      { name: '2xx', value: code2xx, color: '#22c55e' },
      { name: '3xx', value: code3xx, color: '#3b82f6' },
      { name: '4xx', value: code4xx, color: '#f59e0b' },
      { name: '5xx', value: code5xx, color: '#ef4444' },
    ];
  }, [data?.statusCodes]);

  // Transform performance metrics
  const performanceMetrics = useMemo(() => {
    if (!data?.sensor) return [];
    const { latencyP50, latencyP95, latencyP99, rps } = data.sensor;
    return [
      { label: 'P50 Latency', value: `${latencyP50}ms`, color: '#22c55e' as const },
      { label: 'P90 Latency', value: `${latencyP95}ms`, color: '#3b82f6' as const },
      { label: 'P99 Latency', value: `${latencyP99}ms`, color: '#f97316' as const },
      { label: 'Requests/sec', value: formatNumber(rps), color: '#8b5cf6' as const },
      { label: 'Block Rate', value: `${data.traffic.blockRate.toFixed(2)}%`, color: '#ef4444' as const },
      { label: 'Entities', value: formatNumber(data.sensor.entitiesTracked), color: '#06b6d4' as const },
    ];
  }, [data?.sensor, data?.traffic.blockRate]);

  // Transform top endpoints
  const topEndpoints = useMemo(() => {
    if (!data?.topEndpoints?.length) return [];
    return data.topEndpoints.map((ep) => ({
      method: ep.method,
      path: ep.path,
      requests: ep.requests,
      avgLatency: Math.round(ep.avgLatency),
      errorRate: ep.errorRate,
    }));
  }, [data?.topEndpoints]);

  // Summary metrics
  const totalRequests = data?.traffic.totalRequests ?? 0;
  const totalBandwidth = (data?.traffic.totalBandwidthIn ?? 0) + (data?.traffic.totalBandwidthOut ?? 0);
  const avgLatency = data?.sensor?.latencyP50 ?? 45;
  const blockRate = data?.traffic.blockRate ?? 0;

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      {/* Page Header */}
      <header className="ctrlx-page-header">
        <div>
          <h1 className="ctrlx-page-title">Analytics</h1>
          <p className="text-sm text-gray-500 mt-1 flex items-center gap-2">
            Traffic insights and performance metrics
            {data?.dataSource && (
              <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs rounded ${
                data.dataSource === 'live'
                  ? 'bg-green-100 text-green-700'
                  : data.dataSource === 'mixed'
                    ? 'bg-blue-100 text-blue-700'
                    : 'bg-gray-100 text-gray-600'
              }`}>
                {isConnected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                {data.dataSource === 'live' ? 'Live' : data.dataSource === 'mixed' ? 'Mixed' : 'Demo'}
              </span>
            )}
          </p>
        </div>
        <div className="ctrlx-page-actions">
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="ctrlx-btn-ghost"
            title={lastUpdated ? `Last updated: ${lastUpdated.toLocaleTimeString()}` : 'Refresh'}
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
          <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
          <button className="ctrlx-btn-secondary">
            <Download className="w-4 h-4" />
            Export
          </button>
          <button className="ctrlx-btn-secondary">
            <Calendar className="w-4 h-4" />
            Schedule Report
          </button>
        </div>
      </header>

      {/* Metric Cards */}
      <section className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <MetricCard
          label="Requests"
          value={formatNumber(totalRequests)}
          accent="primary"
          icon={<Activity className="w-5 h-5" />}
          trend={{ value: 18, direction: 'up' }}
        />
        <MetricCard
          label="Bandwidth"
          value={formatBytes(totalBandwidth)}
          accent="info"
          icon={<Globe className="w-5 h-5" />}
          trend={{ value: 12, direction: 'up' }}
        />
        <MetricCard
          label="Latency"
          value={`${avgLatency}ms`}
          accent="success"
          icon={<Zap className="w-5 h-5" />}
          trend={{ value: 8, direction: 'down' }}
        />
        <MetricCard
          label="Block Rate"
          value={`${blockRate.toFixed(2)}%`}
          accent="warning"
          icon={<AlertCircle className="w-5 h-5" />}
          trend={{ value: 0, direction: 'neutral' }}
          subtitle={data?.threats ? `${data.threats.total} threats` : 'No change'}
        />
      </section>

      {/* Traffic Overview Chart */}
      <section className="ctrlx-card p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-navy-900">Traffic Overview</h2>
          <div className="flex items-center gap-2">
            <select
              value={siteFilter}
              onChange={(e) => setSiteFilter(e.target.value)}
              className="px-3 py-1.5 text-sm border border-gray-300 bg-white text-navy-800 focus:outline-none focus:ring-2 focus:ring-ctrlx-primary"
            >
              <option value="all">All Sites</option>
              <option value="api">API Gateway</option>
              <option value="web">Web Application</option>
              <option value="mobile">Mobile API</option>
            </select>
            <button className="ctrlx-btn-ghost">
              <Filter className="w-4 h-4" />
            </button>
          </div>
        </div>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={trafficData}
              margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="requestsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="blockedGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis
                dataKey="hour"
                tick={{ fontSize: 11, fill: '#627d98' }}
                tickLine={false}
                axisLine={{ stroke: '#e5e7eb' }}
              />
              <YAxis
                tick={{ fontSize: 11, fill: '#627d98' }}
                tickLine={false}
                axisLine={false}
                tickFormatter={(value) => `${(value / 1000).toFixed(0)}K`}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0',
                  fontSize: '12px',
                }}
                labelStyle={{ color: '#1e3a5f', fontWeight: 600 }}
                formatter={(value: number, name: string) => [
                  value.toLocaleString(),
                  name === 'requests' ? 'Requests' : 'Blocked',
                ]}
              />
              <Area
                type="monotone"
                dataKey="requests"
                stroke="#3b82f6"
                strokeWidth={2}
                fill="url(#requestsGradient)"
              />
              <Area
                type="monotone"
                dataKey="blocked"
                stroke="#ef4444"
                strokeWidth={2}
                fill="url(#blockedGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="flex items-center gap-6 mt-4 text-xs text-gray-500">
          <div className="flex items-center gap-2">
            <span className="w-3 h-0.5 bg-ctrlx-info" />
            <span>Total Requests</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-0.5 bg-ctrlx-danger" />
            <span>Blocked</span>
          </div>
        </div>
      </section>

      {/* Two Column Grid: Response Time + Traffic by Region */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <section className="ctrlx-card p-6">
          <h2 className="text-lg font-semibold text-navy-900 mb-4">
            Response Time Distribution
          </h2>
          <ResponseTimeDistributionChart data={responseTimeData} />
        </section>

        <section className="ctrlx-card p-6">
          <h2 className="text-lg font-semibold text-navy-900 mb-4">
            Traffic by Region
          </h2>
          <TrafficByRegionList data={regionData} />
        </section>
      </div>

      {/* Two Column Grid: Status Codes + Top Endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <section className="ctrlx-card p-6">
          <h2 className="text-lg font-semibold text-navy-900 mb-4">
            Response Status Codes
          </h2>
          <StatusCodesDonut data={statusCodeData} />
        </section>

        <section className="ctrlx-card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-navy-900">
              Top Endpoints by Traffic
            </h2>
            <TrendingUp className="w-4 h-4 text-gray-400" />
          </div>
          <TopEndpointsTable data={topEndpoints} />
        </section>
      </div>

      {/* Performance Metrics Bar */}
      <section className="mb-6">
        <h2 className="text-lg font-semibold text-navy-900 mb-4">
          Performance Metrics
        </h2>
        <PerformanceMetricsGrid metrics={performanceMetrics} />
      </section>
    </div>
  );
}
