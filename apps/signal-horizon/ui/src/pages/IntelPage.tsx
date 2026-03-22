/**
 * Global Intel Page
 * Attack volume trends, trending threats, IOC table, export
 */

import { useHorizonStore, useTimeRange } from '../stores/horizonStore';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Button,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
  SectionHeader,
  Tabs,
  Text,
  alpha,
  axisDefaults,
  colors,
  spacing,
  gridDefaults,
  lineDefaults,
  tooltipDefaults,
  Box,
  Stack,
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

const TH_STYLE: React.CSSProperties = { 
  textAlign: 'left', 
  padding: '12px 16px', 
  background: 'var(--surface-inset)', 
  borderBottom: '1px solid var(--border-accent)' 
};

export default function IntelPage() {
  useDocumentTitle('Intel');
  const timeRange = useTimeRange();
  const setTimeRange = useHorizonStore((s) => s.setTimeRange);

  return (
    <Box p="xl">
      <Stack gap="xl">
        {/* Header */}
        <SectionHeader
          title="Global Intelligence"
          description="Fleet-wide attack trends and IOC export"
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            <Stack direction="row" align="center" gap="md">
              <Tabs
                variant="pills"
                size="sm"
                active={timeRange}
                onChange={(key) => setTimeRange(key as any)}
                tabs={timeRanges.map((range) => ({ key: range, label: range }))}
              />
              <Button
                variant="outlined"
                size="md"
                icon={<Download className="w-4 h-4" aria-hidden="true" />}
              >
                Export Report
              </Button>
            </Stack>
          }
        />

        {/* Attack Volume Trend */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)">
          <Box p="lg" border="bottom" borderColor="subtle" bg="surface-inset">
            <SectionHeader
              title="Attack Volume Trend"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
              icon={<BarChart3 className="w-4 h-4 text-ink-muted" />}
              actions={<Text variant="caption" color="secondary">Last {timeRange}</Text>}
            />
          </Box>
          <Box p="lg" style={{ height: 256 }}>
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
          </Box>
        </Box>

        {/* Restore responsive grid behavior */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Trending Threats */}
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="Trending Threats"
                size="h4"
                titleStyle={CARD_HEADER_TITLE_STYLE}
              />
            </Box>
            <Box p="lg">
              <Stack gap="md">
                {trendingThreats.map((threat) => (
                  <Stack key={threat.type} direction="row" align="center" justify="space-between">
                    <Box>
                      <Text variant="body" weight="medium">{threat.type}</Text>
                      <Text variant="caption" color="secondary">
                        {threat.volume.toLocaleString()} events
                      </Text>
                    </Box>
                    <Text
                      variant="small"
                      weight="medium"
                      style={{ color: threat.change > 0 ? colors.red : colors.green }}
                    >
                      {threat.change > 0 ? '+' : ''}
                      {threat.change}%
                    </Text>
                  </Stack>
                ))}
              </Stack>
            </Box>
          </Box>

          {/* New Fingerprints */}
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="New Fingerprints (24h)"
                size="h4"
                titleStyle={CARD_HEADER_TITLE_STYLE}
                icon={<Fingerprint className="w-4 h-4 text-ink-muted" />}
              />
            </Box>
            <Box p="lg">
              <Stack gap="md">
                {newFingerprints.map((fp) => (
                  <Stack key={fp.label} direction="row" align="center" justify="space-between">
                    <Text variant="body" color="secondary">{fp.label}</Text>
                    <Text variant="body" weight="medium" style={{ color: 'var(--ac-red)' }}>
                      {fp.hits.toLocaleString()} hits
                    </Text>
                  </Stack>
                ))}
                <Box style={{ marginTop: spacing.md }}>
                  <Button variant="ghost" size="sm" fullWidth>
                    Investigate All →
                  </Button>
                </Box>
              </Stack>
            </Box>
          </Box>

          {/* Quick Stats */}
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="Intel Summary"
                size="h4"
                titleStyle={CARD_HEADER_TITLE_STYLE}
                icon={<Calendar className="w-4 h-4 text-ink-muted" />}
              />
            </Box>
            <Box p="lg">
              <Stack gap="lg">
                <SummaryRow label="Total Threats" value="156,234" delta="+12%" positive={false} />
                <SummaryRow label="Blocked Attacks" value="89,456" delta="+28%" positive />
                <SummaryRow label="Active Campaigns" value="23" delta="-5%" positive={false} />
                <SummaryRow label="Fleet IOCs" value="4,567" delta="+8%" positive />
              </Stack>
            </Box>
          </Box>
        </div>

        {/* Restore responsive grid behavior */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Attack Origins */}
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="Top Attack Origins"
                size="h4"
                titleStyle={CARD_HEADER_TITLE_STYLE}
                icon={<MapPinned className="w-4 h-4 text-ink-muted" />}
              />
            </Box>
            <Box p="lg" style={{ height: 192 }}>
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
            </Box>
          </Box>

          {/* Most Targeted Endpoints */}
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="Most Targeted Endpoints"
                size="h4"
                titleStyle={CARD_HEADER_TITLE_STYLE}
                icon={<TrendingUp className="w-4 h-4 text-ink-muted" />}
              />
            </Box>
            <Box p="lg" style={{ height: 192 }}>
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
            </Box>
          </Box>
        </div>

        {/* IOC Table */}
        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <SectionHeader
              title="Recent IOCs"
              description="Indicators of Compromise"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Stack direction="row" gap="sm">
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
                    size="sm"
                    icon={<Download className="w-4 h-4" aria-hidden="true" />}
                  >
                    Export
                  </Button>
                </Stack>
              }
            />
          </Box>
          <Box style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <caption className="sr-only">
                Indicators of compromise with hit counts and status
              </caption>
              <thead>
                <tr>
                  <th style={TH_STYLE}><Text variant="label" color="secondary" noMargin>Type</Text></th>
                  <th style={TH_STYLE}><Text variant="label" color="secondary" noMargin>Value</Text></th>
                  <th style={TH_STYLE}><Text variant="label" color="secondary" noMargin>First Seen</Text></th>
                  <th style={TH_STYLE}><Text variant="label" color="secondary" noMargin>Hits</Text></th>
                  <th style={TH_STYLE}><Text variant="label" color="secondary" noMargin>Status</Text></th>
                </tr>
              </thead>
              <tbody>
                {mockIOCs.map((ioc) => (
                  <tr key={ioc.value} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>{ioc.type}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="code" noMargin>{ioc.value}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="small" color="secondary" noMargin>{ioc.firstSeen}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" weight="medium" noMargin>{ioc.hits.toLocaleString()}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Box
                        px="sm"
                        py="xs"
                        style={{
                          width: 'fit-content',
                          border: '1px solid',
                          background: ioc.status === 'BLOCKED' ? 'var(--ac-red-dim)' : 'var(--ac-orange-dim)',
                          color: ioc.status === 'BLOCKED' ? 'var(--ac-red)' : 'var(--ac-orange)',
                          /* Use alpha helper for consistent borders */
                          borderColor: ioc.status === 'BLOCKED' ? alpha(colors.red, 0.3) : alpha(colors.orange, 0.3),
                        }}
                      >
                        <Text variant="tag" noMargin>{ioc.status}</Text>
                      </Box>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Box>
        </Box>
      </Stack>
    </Box>
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
    <Stack direction="row" align="center" justify="space-between">
      <Box>
        <Text variant="small" color="secondary" noMargin>{label}</Text>
        <Text variant="h2" weight="light" noMargin>{value}</Text>
      </Box>
      <Text
        variant="small"
        weight="medium"
        style={{ color: positive ? colors.green : colors.red }}
      >
        {delta}
      </Text>
    </Stack>
  );
}
