/**
 * Campaign Detail Page
 * Timeline, participating actors, correlation signals, actions
 */

import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  Breadcrumb,
  Button,
  CARD_HEADER_TITLE_STYLE,
  EmptyState,
  SectionHeader,
  PAGE_TITLE_STYLE,
  Stack,
  StatusBadge,
  alpha,
  axisDefaults,
  colors,
  gridDefaultsSoft,
  tooltipDefaults,
  xAxisNoLine,
} from '@/ui';
import {
  Target,
  Clock,
  Users,
  Shield,
  Activity,
  ExternalLink,
  Flame,
  Swords,
  ChevronRight,
} from 'lucide-react';
import { CampaignGraph } from '../components/soc/CampaignGraph';
import { ErrorBoundary } from '../components/ErrorBoundary';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { useHorizonStore } from '../stores/horizonStore';

const mockCorrelationSignals = [
  { name: 'HTTP Fingerprint Match', confidence: 0.98, color: colors.green },
  { name: 'TLS Fingerprint Match', confidence: 0.95, color: colors.blue },
  { name: 'Timing Correlation', confidence: 0.89, color: colors.orange },
  { name: 'Target Endpoint Match', confidence: 0.82, color: colors.magenta },
  { name: 'Network Proximity', confidence: 0.72, color: colors.red },
];

const attackTimeline = [
  { time: '10:15', volume: 120 },
  { time: '10:30', volume: 240 },
  { time: '10:45', volume: 420 },
  { time: '11:00', volume: 820 },
  { time: '11:15', volume: 1340 },
  { time: '11:30', volume: 2100 },
  { time: '11:45', volume: 1500 },
  { time: '12:00', volume: 900 },
];

const participatingIps = [
  { ip: '185.228.101.34', hits: 8421, status: 'BLOCKED' },
  { ip: '185.228.101.35', hits: 7892, status: 'BLOCKED' },
  { ip: '45.134.26.108', hits: 6234, status: 'BLOCKED' },
  { ip: '45.134.26.109', hits: 5102, status: 'BLOCKED' },
  { ip: '91.240.118.42', hits: 4891, status: 'MONITORING' },
];

const affectedCustomers = [
  { name: 'Healthcare-A', attempts: 12421, status: 'ACTIVE' },
  { name: 'Finance-B', attempts: 9832, status: 'ACTIVE' },
  { name: 'Retail-C', attempts: 8421, status: 'PROTECTED' },
  { name: 'Healthcare-D', attempts: 6234, status: 'PROTECTED' },
  { name: 'E-commerce-E', attempts: 4102, status: 'PROTECTED' },
];

function severityToStatus(severity: string): 'error' | 'warning' | 'info' {
  if (severity === 'CRITICAL') return 'error';
  if (severity === 'HIGH' || severity === 'MEDIUM') return 'warning';
  return 'info';
}

export default function CampaignDetailPage() {
  useDocumentTitle('SOC - Campaign Detail');
  const { id } = useParams();
  const campaigns = useHorizonStore((s) => s.campaigns);

  const campaign = useMemo(() => {
    return id ? campaigns.find((c) => c.id === id) : campaigns[0];
  }, [campaigns, id]);

  if (!campaign) {
    return (
      <EmptyState
        icon={<Target aria-hidden="true" />}
        title="No Campaign Selected"
        description="Select a campaign from the overview to view details."
      />
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Breadcrumb items={[{ label: 'Campaigns', to: '/campaigns' }, { label: campaign.name }]} />
      <header className="space-y-2">
        <Link
          to="/campaigns"
          className="text-sm text-link hover:text-link-hover flex items-center gap-1"
        >
          <ChevronRight aria-hidden="true" className="w-4 h-4 rotate-180" />
          Back to Campaigns
        </Link>
        <SectionHeader
          title={campaign.name}
          description={
            campaign.description || 'Coordinated attack campaign detected by Signal Horizon'
          }
          size="h1"
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            <Stack direction="row" align="center" gap="sm">
              <Button
                variant="outlined"
                size="sm"
                icon={<ExternalLink aria-hidden="true" className="w-4 h-4" />}
              >
                Export IOCs
              </Button>
              <Button size="sm" icon={<Shield aria-hidden="true" className="w-4 h-4" />}>
                Open War Room
              </Button>
            </Stack>
          }
        />
        <div className="flex items-center gap-2">
          <StatusBadge status={severityToStatus(campaign.severity)} variant="subtle" size="sm">
            {campaign.severity}
          </StatusBadge>
          {campaign.isCrossTenant && (
            <StatusBadge status="accent" variant="subtle" size="sm">
              Cross-Tenant
            </StatusBadge>
          )}
        </div>
      </header>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatMini icon={Users} label="Customers" value={campaign.tenantsAffected.toString()} />
        <StatMini
          icon={Activity}
          label="Confidence"
          value={`${Math.round(campaign.confidence * 100)}%`}
        />
        <StatMini
          icon={Clock}
          label="First Seen"
          value={new Date(campaign.firstSeenAt).toLocaleDateString()}
        />
        <StatMini icon={Flame} label="Total Attempts" value="47,832" />
      </div>

      {/* Campaign Graph */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ErrorBoundary>
            <CampaignGraph campaignId={id} />
          </ErrorBoundary>
        </div>

        <div className="space-y-6">
          <div className="card p-6">
            <h3 className="text-sm font-medium text-ink-secondary mb-4">Campaign Intelligence</h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                <span className="text-sm text-ink-muted">Confidence</span>
                <span className="text-sm font-medium" style={{ color: colors.green }}>
                  98%
                </span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                <span className="text-sm text-ink-muted">Attribution</span>
                <span className="text-sm font-medium text-ink-primary">APT-29</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-border-subtle">
                <span className="text-sm text-ink-muted">Targeting</span>
                <span className="text-sm font-medium text-ink-primary">Finance, Govt</span>
              </div>
              <div className="pt-2 text-xs text-ink-muted">
                Automated graph correlation identified 3 distinct IP clusters associated with this
                campaign.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Attack Timeline */}
      <section className="card">
        <div className="card-header">
          <SectionHeader
            title="Attack Timeline"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
        </div>
        <div className="card-body h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={attackTimeline}>
              <CartesianGrid {...gridDefaultsSoft} />
              <XAxis dataKey="time" {...xAxisNoLine} />
              <YAxis {...axisDefaults.y} />
              <Tooltip {...tooltipDefaults} />
              <Area
                type="monotone"
                dataKey="volume"
                stroke={colors.red}
                fill={colors.red}
                fillOpacity={0.25}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Participating IPs */}
        <section className="card">
          <div className="card-header flex items-center justify-between">
            <SectionHeader
              title="Participating IPs"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Button variant="outlined" size="sm">
                  Block All
                </Button>
              }
            />
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <caption className="sr-only">IP addresses participating in this campaign</caption>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hits</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {participatingIps.map((ip) => (
                  <tr key={ip.ip}>
                    <td className="font-mono text-sm text-ink-primary">{ip.ip}</td>
                    <td className="text-ink-secondary">{ip.hits.toLocaleString()}</td>
                    <td>
                      <StatusBadge
                        status={ip.status === 'BLOCKED' ? 'error' : 'warning'}
                        variant="subtle"
                        size="sm"
                      >
                        {ip.status}
                      </StatusBadge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Affected Customers */}
        <section className="card">
          <div className="card-header flex items-center justify-between">
            <SectionHeader
              title="Affected Customers"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Button variant="outlined" size="sm">
                  View All
                </Button>
              }
            />
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <caption className="sr-only">Customers affected by this campaign</caption>
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Attempts</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {affectedCustomers.map((customer) => (
                  <tr key={customer.name}>
                    <td className="text-ink-primary">{customer.name}</td>
                    <td className="text-ink-secondary">{customer.attempts.toLocaleString()}</td>
                    <td>
                      <StatusBadge
                        status={customer.status === 'ACTIVE' ? 'error' : 'success'}
                        variant="subtle"
                        size="sm"
                      >
                        {customer.status}
                      </StatusBadge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      {/* Correlation Signals */}
      <section className="card">
        <div className="card-header">
          <SectionHeader
            title="Correlation Signals"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
        </div>
        <div className="card-body space-y-4">
          {mockCorrelationSignals.map((signal) => (
            <div key={signal.name} className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-ink-secondary">{signal.name}</span>
                <span className="text-ink-primary font-medium">
                  {Math.round(signal.confidence * 100)}%
                </span>
              </div>
              <div className="h-2 bg-surface-subtle border border-border-subtle">
                <div
                  className="h-2"
                  style={{ background: signal.color, width: `${signal.confidence * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Response Actions */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <ActionButton icon={Swords} label="Block All IPs" tone={colors.red} />
        <ActionButton icon={Shield} label="Block Fingerprint" tone={colors.red} />
        <ActionButton icon={Activity} label="Block ASN" tone={colors.red} />
        <ActionButton icon={Flame} label="Challenge Mode" tone={colors.orange} />
        <ActionButton icon={ExternalLink} label="Export IOCs" tone={colors.blue} />
        <ActionButton icon={Users} label="Notify Customers" tone={colors.blue} />
      </section>
    </div>
  );
}

function StatMini({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType;
  label: string;
  value: string;
}) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <div className="w-10 h-10 border border-border-subtle flex items-center justify-center">
        <Icon aria-hidden="true" className="w-5 h-5" style={{ color: colors.blue }} />
      </div>
      <div>
        <div className="text-xs tracking-[0.18em] uppercase text-ink-muted">{label}</div>
        <div className="text-xl font-light text-ink-primary">{value}</div>
      </div>
    </div>
  );
}

function ActionButton({
  icon: Icon,
  label,
  tone,
}: {
  icon: React.ElementType;
  label: string;
  tone: string;
}) {
  return (
    <Button
      size="sm"
      fill
      icon={<Icon aria-hidden="true" className="w-4 h-4" />}
      style={{
        background: tone,
        border: `1px solid ${alpha(tone, 0.6)}`,
        color: colors.white,
      }}
    >
      {label}
    </Button>
  );
}
