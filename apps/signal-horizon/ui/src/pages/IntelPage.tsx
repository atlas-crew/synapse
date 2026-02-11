/**
 * Global Intel Page
 * Attack volume trends, trending threats, IOC table, export
 */

import { useHorizonStore, useTimeRange } from '../stores/horizonStore';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Button,
  CARD_HEADER_TITLE_STYLE,
  SectionHeader,
  Tabs,
  Text,
  alpha,
  axisDefaults,
  colors,
  gridDefaults,
  lineDefaults,
  tooltipDefaults,
} from '@/ui';
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
import type { CSSProperties, ReactNode } from 'react';

const timeRanges = ['1h', '6h', '24h', '7d', '30d'];

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
  {
    type: 'Fingerprint',
    value: 'python-requests',
    firstSeen: '4h ago',
    hits: 8234,
    status: 'BLOCKED',
  },
  { type: 'ASN', value: 'AS12345', firstSeen: '6h ago', hits: 5102, status: 'MONITORING' },
  { type: 'UA', value: 'abC123d45f6...', firstSeen: '8h ago', hits: 3891, status: 'BLOCKED' },
  { type: 'IP', value: '45.134.26.0/24', firstSeen: '12h ago', hits: 2567, status: 'BLOCKED' },
];

const CARD_HEADER_STYLE: CSSProperties = { marginBottom: 0 };
const PAGE_HEADER_TITLE_STYLE: CSSProperties = { fontSize: '24px', lineHeight: '32px' };

function CardHeader({
  title,
  icon,
  actions,
}: {
  title: string;
  icon?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <SectionHeader
      title={title}
      icon={icon}
      actions={actions}
      size="h4"
      style={CARD_HEADER_STYLE}
      titleStyle={CARD_HEADER_TITLE_STYLE}
    />
  );
}

export default function IntelPage() {
  useDocumentTitle('Intel');
  const timeRange = useTimeRange();
  const setTimeRange = useHorizonStore((s) => s.setTimeRange);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <SectionHeader
        title="Global Intelligence"
        description="Fleet-wide attack trends and IOC export"
        size="h1"
        titleStyle={PAGE_HEADER_TITLE_STYLE}
        actions={
          <div className="flex items-center gap-3">
            <Tabs
              variant="pills"
              size="sm"
              active={timeRange}
              onChange={(key) => setTimeRange(key)}
              tabs={timeRanges.map((range) => ({ key: range, label: range }))}
            />
            <Button
              variant="outlined"
              size="md"
              icon={<Download className="w-4 h-4" aria-hidden="true" />}
            >
              Export Report
            </Button>
          </div>
        }
      />

      {/* Attack Volume Trend */}
      <div className="card">
        <div className="card-header">
          <CardHeader
            title="Attack Volume Trend"
            icon={<BarChart3 className="w-4 h-4 text-ink-muted" />}
            actions={<span className="text-xs text-ink-muted">Last {timeRange}</span>}
          />
        </div>
        <div className="card-body h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={volumeData}>
              <CartesianGrid {...gridDefaults} strokeDasharray="3 3" />
              <XAxis dataKey="day" {...axisDefaults.x} axisLine={false} />
              <YAxis {...axisDefaults.y} />
              <Tooltip {...tooltipDefaults} />
              <Line
                {...lineDefaults}
                dataKey="attacks"
                stroke={colors.magenta}
                strokeWidth={2.5}
                name="Attacks"
              />
              <Line
                {...lineDefaults}
                dataKey="blocked"
                stroke={colors.green}
                strokeWidth={2.5}
                name="Blocked"
              />
              <Line
                {...lineDefaults}
                dataKey="campaigns"
                stroke={colors.skyBlue}
                strokeWidth={2.5}
                name="Campaigns"
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trending Threats */}
        <div className="card">
          <div className="card-header">
            <CardHeader
              title="Trending Threats"
            />
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
                  className="text-sm font-medium"
                  style={{ color: threat.change > 0 ? colors.red : colors.green }}
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
          <div className="card-header">
            <CardHeader
              title="New Fingerprints (24h)"
              icon={<Fingerprint className="w-4 h-4 text-ink-muted" />}
            />
          </div>
          <div className="card-body space-y-3">
            {newFingerprints.map((fp) => (
              <div key={fp.label} className="flex items-center justify-between text-sm">
                <span className="text-ink-secondary">{fp.label}</span>
                <Text as="span" color={colors.red} noMargin>
                  {fp.hits.toLocaleString()} hits
                </Text>
              </div>
            ))}
            <div>
              <Button variant="ghost" size="sm">
                Investigate All →
              </Button>
            </div>
          </div>
        </div>

        {/* Quick Stats */}
        <div className="card">
          <div className="card-header">
            <CardHeader
              title="Intel Summary"
              icon={<Calendar className="w-4 h-4 text-ink-muted" />}
            />
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
          <div className="card-header">
            <CardHeader
              title="Top Attack Origins"
              icon={<MapPinned className="w-4 h-4 text-ink-muted" />}
            />
          </div>
          <div className="card-body h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topOrigins} layout="vertical">
                <defs>
                  <linearGradient id="barGradientMagenta" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor={colors.magenta} stopOpacity={0.8} />
                    <stop offset="100%" stopColor={colors.magenta} stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid {...gridDefaults} strokeDasharray="3 3" horizontal={true} />
                <XAxis type="number" {...axisDefaults.x} hide />
                <YAxis dataKey="label" type="category" {...axisDefaults.y} width={90} />
                <Tooltip {...tooltipDefaults} cursor={{ fill: alpha(colors.blue, 0.1) }} />
                <Bar
                  dataKey="value"
                  fill="url(#barGradientMagenta)"
                  radius={[0, 0, 0, 0]}
                  barSize={14}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Most Targeted Endpoints */}
        <div className="card">
          <div className="card-header">
            <CardHeader
              title="Most Targeted Endpoints"
              icon={<TrendingUp className="w-4 h-4 text-ink-muted" />}
            />
          </div>
          <div className="card-body h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={targetedEndpoints} layout="vertical">
                <defs>
                  <linearGradient id="barGradientBlue" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor={colors.blue} stopOpacity={0.8} />
                    <stop offset="100%" stopColor={colors.skyBlue} stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid {...gridDefaults} strokeDasharray="3 3" horizontal={true} />
                <XAxis type="number" {...axisDefaults.x} hide />
                <YAxis dataKey="label" type="category" {...axisDefaults.y} width={120} />
                <Tooltip {...tooltipDefaults} cursor={{ fill: alpha(colors.blue, 0.1) }} />
                <Bar
                  dataKey="value"
                  fill="url(#barGradientBlue)"
                  radius={[0, 0, 0, 0]}
                  barSize={14}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* IOC Table */}
      <div className="card">
        <div className="card-header">
          <CardHeader
            title="Recent IOCs (Indicators of Compromise)"
            actions={
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<FileJson className="w-4 h-4" aria-hidden="true" />}
                >
                  JSON
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={<FileText className="w-4 h-4" aria-hidden="true" />}
                >
                  CSV
                </Button>
                <Button
                  variant="primary"
                  size="md"
                  icon={<Download className="w-4 h-4" aria-hidden="true" />}
                >
                  Export
                </Button>
              </div>
            }
          />
        </div>
        <div className="overflow-x-auto">
          <table className="data-table">
            <caption className="sr-only">
              Indicators of compromise with hit counts and status
            </caption>
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
                      className="px-2 py-0.5 text-xs border"
                      style={
                        ioc.status === 'BLOCKED'
                          ? {
                              background: alpha(colors.red, 0.15),
                              color: colors.red,
                              borderColor: alpha(colors.red, 0.4),
                            }
                          : {
                              background: alpha(colors.orange, 0.1),
                              color: colors.orange,
                              borderColor: alpha(colors.orange, 0.3),
                            }
                      }
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
      <span className="text-sm font-medium" style={{ color: positive ? colors.green : colors.red }}>
        {delta}
      </span>
    </div>
  );
}
