import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import {
  Breadcrumb,
  Button,
  EmptyState,
  SectionHeader,
  Stack,
  StatusBadge,
  alpha,
  axisDefaults,
  colors,
  gridDefaultsSoft,
  tooltipDefaults,
  xAxisNoLine,
  Box,
  Text,
  CARD_HEADER_TITLE_STYLE
} from '@/ui';
import {
  Target,
  Clock,
  Users,
  Shield,
  Activity,
  ExternalLink,
  AlertTriangle,
  Flame,
  Swords,
  ChevronRight,
  Network,
  Building,
} from 'lucide-react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { useDemoMode } from '../../stores/demoModeStore';
import { fetchCampaignActors, fetchCampaignDetail } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { CampaignGraph } from '../../components/soc/CampaignGraph';
import { ErrorBoundary } from '../../components/ErrorBoundary';
import type {
  SocCampaign,
  SocCampaignActor,
  SocCampaignDetailResponse,
  SocCampaignActorsResponse,
  SocCampaignSignal,
} from '../../types/soc';

function campaignStatusToBadge(
  status: SocCampaign['status'],
): 'error' | 'warning' | 'info' | 'success' {
  if (status === 'ACTIVE') return 'error';
  if (status === 'DETECTED') return 'warning';
  if (status === 'DORMANT') return 'info';
  return 'success';
}

function severityToBadge(severity: SocCampaign['severity']): 'error' | 'warning' | 'info' {
  if (severity === 'CRITICAL') return 'error';
  if (severity === 'HIGH' || severity === 'MEDIUM') return 'warning';
  return 'info';
}

const demoSignals: SocCampaignSignal[] = [
  {
    type: 'HTTP Fingerprint Match',
    confidence: 0.96,
    reason: 'Shared fingerprint across 4 sensors.',
  },
  {
    type: 'Timing Correlation',
    confidence: 0.89,
    reason: 'Burst pattern repeats every 15 minutes.',
  },
  { type: 'Target Overlap', confidence: 0.81, reason: 'Same endpoint matrix across tenants.' },
];

const demoCampaign: SocCampaign = {
  campaignId: 'cmp-demo-1',
  name: 'Credential Stuffing Wave',
  status: 'ACTIVE',
  severity: 'HIGH',
  confidence: 0.88,
  actorCount: 18,
  firstSeen: Date.now() - 36 * 3600 * 1000,
  lastSeen: Date.now() - 22 * 60 * 1000,
  summary: 'Automated credential stuffing across API auth and checkout paths.',
  correlationTypes: ['fingerprint', 'timing', 'endpoint'],
};

const demoActors: SocCampaignActor[] = Array.from({ length: 6 }).map((_, index) => ({
  actorId: `actor-demo-${index + 1}`,
  riskScore: 70 + index * 4,
  lastSeen: Date.now() - index * 35 * 60 * 1000,
  ips: [`203.0.113.${80 + index}`],
}));

const demoParticipatingIps = [
  { ip: '185.228.101.34', hits: 8421, status: 'BLOCKED' as const },
  { ip: '185.228.101.35', hits: 7892, status: 'BLOCKED' as const },
  { ip: '45.134.26.108', hits: 6234, status: 'BLOCKED' as const },
  { ip: '45.134.26.109', hits: 5102, status: 'BLOCKED' as const },
  { ip: '91.240.118.42', hits: 4891, status: 'MONITORING' as const },
];

const demoAffectedCustomers = [
  { name: 'Healthcare-A', attempts: 12421, status: 'ACTIVE' as const },
  { name: 'Finance-B', attempts: 9832, status: 'ACTIVE' as const },
  { name: 'Retail-C', attempts: 8421, status: 'PROTECTED' as const },
  { name: 'Healthcare-D', attempts: 6234, status: 'PROTECTED' as const },
  { name: 'E-commerce-E', attempts: 4102, status: 'PROTECTED' as const },
];

function buildVelocitySeries(baseTime: number) {
  return Array.from({ length: 8 }).map((_, index) => {
    const timestamp = baseTime - (7 - index) * 30 * 60 * 1000;
    const value = 120 + index * 140 + Math.round(Math.sin(index) * 40);
    return {
      time: new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      volume: Math.max(60, value),
    };
  });
}

function buildDemoCampaignDetail(id?: string): SocCampaignDetailResponse {
  return {
    campaign: {
      ...demoCampaign,
      campaignId: id ?? demoCampaign.campaignId,
    },
    signals: demoSignals,
  };
}

function buildDemoCampaignActors(id?: string): SocCampaignActorsResponse {
  return {
    campaignId: id ?? demoCampaign.campaignId,
    actors: demoActors,
  };
}

export default function CampaignDetailPage() {
  useDocumentTitle('SOC - Campaign Detail');
  const { id } = useParams();
  const { sensorId } = useSocSensor();
  const { isEnabled: isDemoMode } = useDemoMode();

  const { data: campaignResponse, isLoading } = useQuery({
    queryKey: ['soc', 'campaign', sensorId, id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return buildDemoCampaignDetail(id);
      if (!id) throw new Error('Missing campaign ID');
      return fetchCampaignDetail(sensorId, id);
    },
    enabled: !!id,
  });

  const { data: actorsResponse } = useQuery({
    queryKey: ['soc', 'campaign-actors', sensorId, id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return buildDemoCampaignActors(id);
      if (!id) throw new Error('Missing campaign ID');
      return fetchCampaignActors(sensorId, id);
    },
    enabled: !!id,
  });

  const campaign = campaignResponse?.campaign;
  const actors = actorsResponse?.actors ?? [];
  const signals = campaignResponse?.signals ?? [];

  const velocityData = useMemo(() => {
    const base = campaign?.lastSeen ?? Date.now();
    return buildVelocitySeries(base);
  }, [campaign?.lastSeen]);

  if (isLoading && !campaign) {
    return (
      <Box p="xl" style={{ textAlign: 'center' }}>
        <Text variant="body" color="secondary">Loading campaign...</Text>
      </Box>
    );
  }

  if (!campaign) {
    return (
      <EmptyState
        icon={<AlertTriangle aria-hidden="true" />}
        title="Campaign Not Found"
        description="The requested campaign could not be found."
      />
    );
  }

  return (
    <Box p="xl">
      <Stack gap="xl">
        <Breadcrumb items={[{ label: 'Campaigns', to: '/campaigns' }, { label: campaign.name }]} />
        
        {/* Header */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
          <Stack gap="md">
            <Link
              to="/campaigns"
              className="text-link hover:opacity-80 transition-opacity"
              style={{ fontSize: '13px', width: 'fit-content' }}
            >
              <Stack direction="row" align="center" gap="sm">
                <ChevronRight aria-hidden="true" size={14} className="rotate-180" />
                <span>Back to Campaigns</span>
              </Stack>
            </Link>
            <SectionHeader
              title={campaign.name}
              description={campaign.summary ?? 'Coordinated campaign detected across multiple signals.'}
              size="h2"
              actions={
                <Stack direction="row" align="center" gap="md">
                  <Button
                    variant="outlined"
                    size="sm"
                    icon={<ExternalLink aria-hidden="true" size={14} />}
                  >
                    Export IOCs
                  </Button>
                  <Button size="sm" icon={<Shield aria-hidden="true" size={14} />}>
                    Open War Room
                  </Button>
                </Stack>
              }
            />
            <Stack direction="row" align="center" gap="md">
              <StatusBadge status={campaignStatusToBadge(campaign.status)} variant="subtle" size="sm">
                {campaign.status}
              </StatusBadge>
              <StatusBadge status={severityToBadge(campaign.severity)} variant="subtle" size="sm">
                {campaign.severity}
              </StatusBadge>
              {campaign.actorCount > 5 && (
                <StatusBadge status="accent" variant="subtle" size="sm">
                  Cross-Tenant
                </StatusBadge>
              )}
            </Stack>
          </Stack>
        </Box>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatMini icon={Users} label="Actors" value={campaign.actorCount.toString()} />
          <StatMini
            icon={Activity}
            label="Confidence"
            value={`${Math.round(campaign.confidence * 100)}%`}
          />
          <StatMini
            icon={Clock}
            label="First Seen"
            value={new Date(campaign.firstSeen).toLocaleDateString()}
          />
          <StatMini
            icon={Target}
            label="Last Seen"
            value={new Date(campaign.lastSeen).toLocaleTimeString()}
          />
        </div>

        {/* Campaign Correlation Graph */}
        <Box bg="card" border="subtle" p="none" style={{ height: 400, position: 'relative' }}>
          <ErrorBoundary>
            <CampaignGraph campaignId={id} />
          </ErrorBoundary>
        </Box>

        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <SectionHeader
              title="Campaign Velocity"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
            />
          </Box>
          <Box p="lg" style={{ height: 256 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={velocityData}>
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
          </Box>
        </Box>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <SectionHeader
                title="Correlation Signals"
                size="h4"
                style={{ marginBottom: 0 }}
                titleStyle={CARD_HEADER_TITLE_STYLE}
              />
            </Box>
            <Box p="lg">
              <Stack gap="lg">
                {signals.length === 0 && (
                  <Text variant="body" color="secondary" align="center">No correlation signals yet.</Text>
                )}
                {signals.map((signal) => (
                  <Stack key={signal.type} gap="sm">
                    <Stack direction="row" align="center" justify="space-between">
                      <Text variant="body" color="secondary" noMargin>{signal.type}</Text>
                      <Text variant="body" weight="medium" noMargin>
                        {Math.round(signal.confidence * 100)}%
                      </Text>
                    </Stack>
                    <Box style={{ height: 4, background: 'var(--bg-surface-subtle)', border: '1px solid var(--border-subtle)' }}>
                      <Box
                        style={{
                          height: '100%',
                          background: 'var(--ac-green)',
                          width: `${Math.round(signal.confidence * 100)}%`,
                        }}
                      />
                    </Box>
                    {signal.reason && (
                      <Text variant="caption" color="secondary" noMargin>{signal.reason}</Text>
                    )}
                  </Stack>
                ))}
              </Stack>
            </Box>
          </Box>

          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <Stack direction="row" align="center" justify="space-between">
                <SectionHeader
                  title="Associated Actors"
                  size="h4"
                  style={{ marginBottom: 0 }}
                  titleStyle={CARD_HEADER_TITLE_STYLE}
                />
                <Button variant="outlined" size="sm">
                  Add to Watchlist
                </Button>
              </Stack>
            </Box>
            <Box style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <caption className="sr-only">Actors associated with this campaign</caption>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Actor</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Risk</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>IPs</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Last Seen</Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {actors.length === 0 && (
                    <tr>
                      <td colSpan={4} style={{ padding: '24px', textAlign: 'center' }}>
                        <Text variant="body" color="secondary" noMargin>No actors linked yet.</Text>
                      </td>
                    </tr>
                  )}
                  {actors.map((actor) => (
                    <tr key={actor.actorId} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <Link
                          to={`/actors/${actor.actorId}`}
                          className="text-link hover:opacity-80 transition-opacity"
                          style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                        >
                          {actor.actorId}
                        </Link>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" weight="medium" noMargin>{Math.round(actor.riskScore)}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" color="secondary" noMargin>{actor.ips.length}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" color="secondary" noMargin>
                          {new Date(actor.lastSeen).toLocaleString()}
                        </Text>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
          </Box>
        </div>

        {/* Participating IPs & Affected Customers */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <Stack direction="row" align="center" justify="space-between">
                <SectionHeader
                  title="Participating IPs"
                  size="h4"
                  style={{ marginBottom: 0 }}
                  titleStyle={CARD_HEADER_TITLE_STYLE}
                />
                <Button variant="outlined" size="sm">
                  Block All
                </Button>
              </Stack>
            </Box>
            <Box style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <caption className="sr-only">IP addresses participating in this campaign</caption>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>IP</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Hits</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Status</Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {demoParticipatingIps.map((ip) => (
                    <tr key={ip.ip} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="code" noMargin>{ip.ip}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" color="secondary" noMargin>{ip.hits.toLocaleString()}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
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
            </Box>
          </Box>

          <Box bg="card" border="subtle">
            <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
              <Stack direction="row" align="center" justify="space-between">
                <SectionHeader
                  title="Affected Customers"
                  size="h4"
                  style={{ marginBottom: 0 }}
                  titleStyle={CARD_HEADER_TITLE_STYLE}
                />
                <Button variant="outlined" size="sm">
                  View All
                </Button>
              </Stack>
            </Box>
            <Box style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <caption className="sr-only">Customers affected by this campaign</caption>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Customer</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Attempts</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Status</Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {demoAffectedCustomers.map((customer) => (
                    <tr key={customer.name} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" noMargin>{customer.name}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" color="secondary" noMargin>{customer.attempts.toLocaleString()}</Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
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
            </Box>
          </Box>
        </div>

        {/* Response Actions */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <ActionButton icon={Swords} label="Block All IPs" tone="red" />
          <ActionButton icon={Shield} label="Block Fingerprint" tone="red" />
          <ActionButton icon={Network} label="Block ASN" tone="red" />
          <ActionButton icon={Flame} label="Challenge Mode" tone="orange" />
          <ActionButton icon={ExternalLink} label="Export IOCs" tone="blue" />
          <ActionButton icon={Building} label="Notify Customers" tone="blue" />
        </div>
      </Stack>
    </Box>
  );
}

function StatMini({
  icon: Icon,
  label,
  value,
}: {
  icon: any;
  label: string;
  value: string;
}) {
  return (
    <Box bg="card" border="subtle" p="lg">
      <Stack direction="row" align="center" gap="lg">
        <Box
          style={{
            width: 40,
            height: 40,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'var(--bg-surface-subtle)',
          }}
        >
          <Icon aria-hidden="true" size={20} className="text-ink-muted" />
        </Box>
        <Box>
          <Text variant="label" color="secondary" noMargin>{label}</Text>
          <Text variant="body" weight="medium" noMargin style={{ marginTop: '4px', fontSize: '18px' }}>
            {value}
          </Text>
        </Box>
      </Stack>
    </Box>
  );
}

function ActionButton({
  icon: Icon,
  label,
  tone,
}: {
  icon: any;
  label: string;
  tone: 'red' | 'orange' | 'blue';
}) {
  const toneColor = tone === 'red' ? 'var(--ac-red)' : tone === 'orange' ? 'var(--ac-orange)' : 'var(--ac-blue)';

  return (
    <Button
      size="sm"
      fullWidth
      icon={<Icon aria-hidden="true" size={14} />}
      style={{
        background: toneColor,
        border: `1px solid ${alpha(toneColor, 0.6)}`,
        color: '#FFFFFF',
      }}
    >
      {label}
    </Button>
  );
}
