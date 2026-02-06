/**
 * Global Intel Page
 * Attack volume trends, trending threats, IOC table, export
 */

import { useState } from 'react';
import { TOOLTIP_CONTENT_STYLE, TOOLTIP_LABEL_STYLE, TOOLTIP_ITEM_STYLE } from '../lib/chartTheme';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  BarChart3,
  TrendingUp,
  Download,
  Calendar,
  FileJson,
  FileText,
  Fingerprint,
  MapPinned,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  BarChart,
  Bar,
} from 'recharts';

const timeRanges = ['24h', '7d', '30d', '90d'];

const volumeData = [
  { day: 'Mon', attacks: 32000, blocked: 24000, campaigns: 8 },
  { day: 'Tue', attacks: 36000, blocked: 27000, campaigns: 9 },
  { day: 'Wed', attacks: 38000, blocked: 29000, campaigns: 11 },
  { day: 'Thu', attacks: 34000, blocked: 28000, campaigns: 10 },
  { day: 'Fri', attacks: 42000, blocked: 32000, campaigns: 14 },
  { day: 'Sat', attacks: 47000, blocked: 35000, campaigns: 16 },
  { day: 'Sun', attacks: 41000, blocked: 31000, campaigns: 12 },
];

const trendingThreats = [
  { type: 'Credential Stuffing', change: +34, volume: 12450 },
  { type: 'API Scraping', change: +12, volume: 8920 },
  { type: 'Scanner Activity', change: +8, volume: 45230 },
  { type: 'SQL Attempts', change: -12, volume: 2340 },
  { type: 'XSS Attempts', change: +6, volume: 890 },
];

const newFingerprints = [
  { label: 'custom-bot-cb123', hits: 1247 },
  { label: 'unknown-jsd-4f56', hits: 892 },
  { label: 'headless-chrome-mod', hits: 654 },
  { label: 'python-custom-ua', hits: 421 },
];

const topOrigins = [
  { label: 'Russia', value: 28 },
  { label: 'China', value: 21 },
  { label: 'United States', value: 15 },
  { label: 'Ukraine', value: 9 },
  { label: 'Romania', value: 7 },
];

const targetedEndpoints = [
  { label: '/api/auth/login', value: 34 },
  { label: '/api/v1/users', value: 18 },
  { label: '/admin/*', value: 12 },
  { label: '/graphql', value: 8 },
  { label: '/api/payment', value: 6 },
];

const mockIOCs = [
  { type: 'IP', value: '185.228.101.0/24', firstSeen: '2h ago', hits: 12421, status: 'BLOCKED' },
  { type: 'Fingerprint', value: 'python-requests', firstSeen: '4h ago', hits: 8234, status: 'BLOCKED' },
  { type: 'ASN', value: 'AS12345', firstSeen: '6h ago', hits: 5102, status: 'MONITORING' },
  { type: 'UA', value: 'abC123d45f6...', firstSeen: '8h ago', hits: 3891, status: 'BLOCKED' },
  { type: 'IP', value: '45.134.26.0/24', firstSeen: '12h ago', hits: 2567, status: 'BLOCKED' },
];

export default function IntelPage() {
  useDocumentTitle('Intel');
  const [timeRange, setTimeRange] = useState('7d');

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Global Intelligence</h1>
          <p className="text-ink-secondary mt-1">
            Fleet-wide attack trends and IOC export
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1 border border-border-subtle p-1">
            {timeRanges.map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={clsx(
                  'px-3 py-1.5 text-xs font-medium tracking-[0.08em] uppercase',
                  timeRange === range
                    ? 'bg-link text-ac-white'
                    : 'text-ink-muted hover:text-ink-primary'
                )}
              >
                {range}
              </button>
            ))}
          </div>
          <button className="btn-outline h-10 px-4 text-xs">
            <Download className="w-4 h-4 mr-2" />
            Export Report
          </button>
        </div>
      </div>

      {/* Attack Volume Trend */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-ink-muted" />
            <h2 className="font-medium text-ink-primary">Attack Volume Trend</h2>
          </div>
          <span className="text-xs text-ink-muted">Last {timeRange}</span>
        </div>
        <div className="card-body h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={volumeData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 87, 183, 0.15)" vertical={false} />
              <XAxis dataKey="day" stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} />
              <YAxis stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} />
              <Tooltip
                contentStyle={TOOLTIP_CONTENT_STYLE}
                labelStyle={TOOLTIP_LABEL_STYLE}
                itemStyle={TOOLTIP_ITEM_STYLE}
              />
              <Line type="monotone" dataKey="attacks" stroke="#D62598" strokeWidth={2.5} dot={false} name="Attacks" />
              <Line type="monotone" dataKey="blocked" stroke="#00B140" strokeWidth={2.5} dot={false} name="Blocked" />
              <Line type="monotone" dataKey="campaigns" stroke="#529EEC" strokeWidth={2.5} dot={false} name="Campaigns" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trending Threats */}
        <div className="card">
          <div className="card-header">
            <h2 className="font-medium text-ink-primary">Trending Threats</h2>
          </div>
          <div className="card-body space-y-3">
            {trendingThreats.map((threat) => (
              <div key={threat.type} className="flex items-center justify-between">
                <div>
                  <div className="text-sm text-ink-primary">{threat.type}</div>
                  <div className="text-xs text-ink-muted">
                    {threat.volume.toLocaleString()} events
                  </div>
                </div>
                <span
                  className={clsx(
                    'text-sm font-medium',
                    threat.change > 0 ? 'text-ac-red' : 'text-ac-green'
                  )}
                >
                  {threat.change > 0 ? '+' : ''}
                  {threat.change}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* New Fingerprints */}
        <div className="card">
          <div className="card-header flex items-center gap-2">
            <Fingerprint className="w-4 h-4 text-ink-muted" />
            <h2 className="font-medium text-ink-primary">New Fingerprints (24h)</h2>
          </div>
          <div className="card-body space-y-3">
            {newFingerprints.map((fp) => (
              <div key={fp.label} className="flex items-center justify-between text-sm">
                <span className="text-ink-secondary">{fp.label}</span>
                <span className="text-ac-red">{fp.hits.toLocaleString()} hits</span>
              </div>
            ))}
            <button className="text-link text-xs font-semibold tracking-[0.14em] uppercase">
              Investigate All →
            </button>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="card">
          <div className="card-header flex items-center gap-2">
            <Calendar className="w-4 h-4 text-ink-muted" />
            <h2 className="font-medium text-ink-primary">Intel Summary</h2>
          </div>
          <div className="card-body space-y-4">
            <SummaryRow label="Total Threats" value="156,234" delta="+12%" positive={false} />
            <SummaryRow label="Blocked Attacks" value="89,456" delta="+28%" positive />
            <SummaryRow label="Active Campaigns" value="23" delta="-5%" positive={false} />
            <SummaryRow label="Fleet IOCs" value="4,567" delta="+8%" positive />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Attack Origins */}
        <div className="card">
          <div className="card-header flex items-center gap-2">
            <MapPinned className="w-4 h-4 text-ink-muted" />
            <h2 className="font-medium text-ink-primary">Top Attack Origins</h2>
          </div>
          <div className="card-body h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topOrigins} layout="vertical">
                <defs>
                  <linearGradient id="barGradientMagenta" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#D62598" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#D62598" stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 87, 183, 0.15)" horizontal={true} vertical={false} />
                <XAxis type="number" stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} hide />
                <YAxis dataKey="label" type="category" width={90} stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={TOOLTIP_CONTENT_STYLE}
                  labelStyle={TOOLTIP_LABEL_STYLE}
                  cursor={{ fill: 'rgba(0, 87, 183, 0.1)' }}
                />
                <Bar dataKey="value" fill="url(#barGradientMagenta)" radius={[0, 0, 0, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Most Targeted Endpoints */}
        <div className="card">
          <div className="card-header flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-ink-muted" />
            <h2 className="font-medium text-ink-primary">Most Targeted Endpoints</h2>
          </div>
          <div className="card-body h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={targetedEndpoints} layout="vertical">
                <defs>
                  <linearGradient id="barGradientBlue" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#0057B7" stopOpacity={0.8} />
                    <stop offset="100%" stopColor="#529EEC" stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0, 87, 183, 0.15)" horizontal={true} vertical={false} />
                <XAxis type="number" stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} hide />
                <YAxis dataKey="label" type="category" width={120} stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={TOOLTIP_CONTENT_STYLE}
                  labelStyle={TOOLTIP_LABEL_STYLE}
                  cursor={{ fill: 'rgba(0, 87, 183, 0.1)' }}
                />
                <Bar dataKey="value" fill="url(#barGradientBlue)" radius={[0, 0, 0, 0]} barSize={14} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <h2 className="font-medium text-ink-primary">Recent IOCs (Indicators of Compromise)</h2>
          <div className="flex gap-2">
            <button className="btn-ghost text-xs py-1 px-2">
              <FileJson className="w-4 h-4 mr-1" />
              JSON
            </button>
            <button className="btn-ghost text-xs py-1 px-2">
              <FileText className="w-4 h-4 mr-1" />
              CSV
            </button>
            <button className="btn-primary h-10 px-4 text-xs">
              <Download className="w-4 h-4 mr-1" />
              Export
            </button>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
                <th>First Seen</th>
                <th>Hits</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {mockIOCs.map((ioc) => (
                <tr key={ioc.value}>
                  <td className="text-ink-secondary">{ioc.type}</td>
                  <td className="font-mono text-sm text-ink-primary">{ioc.value}</td>
                  <td className="text-ink-muted">{ioc.firstSeen}</td>
                  <td className="text-ink-secondary">{ioc.hits.toLocaleString()}</td>
                  <td>
                    <span
                      className={clsx(
                        'px-2 py-0.5 text-xs border',
                        ioc.status === 'BLOCKED'
                          ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                          : 'bg-ac-orange/10 text-ac-orange border-ac-orange/30'
                      )}
                    >
                      {ioc.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function SummaryRow({
  label,
  value,
  delta,
  positive,
}: {
  label: string;
  value: string;
  delta: string;
  positive: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <div className="text-sm text-ink-secondary">{label}</div>
        <div className="text-2xl font-light text-ink-primary">{value}</div>
      </div>
      <span className={clsx('text-sm font-medium', positive ? 'text-ac-green' : 'text-ac-red')}>
        {delta}
      </span>
    </div>
  );
}
