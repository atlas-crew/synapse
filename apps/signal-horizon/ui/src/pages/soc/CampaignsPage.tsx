import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Target, Activity, Shield, Users } from 'lucide-react';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchCampaigns } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocCampaign, SocCampaignListResponse } from '../../types/soc';
import { 
  Box, 
  Button, 
  Input, 
  SectionHeader, 
  Stack, 
  Tabs, 
  Text, 
  alpha, 
  colors,
  spacing,
} from '@/ui';

const statusTabs = [
  { label: 'Active', value: 'ACTIVE' },
  { label: 'Detected', value: 'DETECTED' },
  { label: 'Dormant', value: 'DORMANT' },
  { label: 'Resolved', value: 'RESOLVED' },
  { label: 'All', value: 'ALL' },
];

function buildDemoCampaigns(scenario: string): SocCampaignListResponse {
  const now = Date.now();
  const intensity = scenario === 'high-threat' ? 1.2 : scenario === 'normal' ? 1 : 0.6;
  const campaigns: SocCampaign[] = Array.from({ length: 7 }).map((_, index) => {
    const status = statusTabs[index % 4].value as SocCampaign['status'];
    const severity = (
      index % 4 === 0 ? 'CRITICAL' : index % 4 === 1 ? 'HIGH' : index % 4 === 2 ? 'MEDIUM' : 'LOW'
    ) as SocCampaign['severity'];
    const actorCount = Math.round((12 + index * 3) * intensity);
    const confidence = Math.min(0.98, 0.6 + index * 0.05);
    return {
      campaignId: `cmp-${scenario}-${index + 1}`,
      name: `Campaign ${index + 1}`,
      status,
      severity,
      confidence,
      actorCount,
      firstSeen: now - (index + 2) * 12 * 3600 * 1000,
      lastSeen: now - index * 2 * 3600 * 1000,
      summary:
        status === 'RESOLVED'
          ? 'Contained and resolved by automated controls.'
          : 'Coordinated probing across multiple endpoints.',
      correlationTypes: ['fingerprint', 'timing', 'targeting'].slice(0, (index % 3) + 1),
    };
  });

  return { campaigns };
}

export default function CampaignsPage() {
  useDocumentTitle('SOC - Campaigns');
  const { sensorId, setSensorId } = useSocSensor();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [statusFilter, setStatusFilter] = useState('ACTIVE');
  const [searchTerm, setSearchTerm] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['soc', 'campaigns', sensorId, statusFilter, isDemoMode, scenario],
    queryFn: async () => {
      if (isDemoMode) {
        return buildDemoCampaigns(scenario);
      }
      return fetchCampaigns(sensorId, {
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        limit: 50,
      });
    },
    staleTime: isDemoMode ? Infinity : 15000,
  });

  const campaigns = data?.campaigns ?? [];
  const canExport = campaigns.length > 0;

  const filteredCampaigns = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    return campaigns.filter((campaign) => {
      if (statusFilter !== 'ALL' && campaign.status !== statusFilter) return false;
      if (!term) return true;
      return (
        campaign.name.toLowerCase().includes(term) ||
        campaign.campaignId.toLowerCase().includes(term)
      );
    });
  }, [campaigns, searchTerm, statusFilter]);

  const stats = useMemo(() => {
    const byStatus = campaigns.reduce(
      (acc, campaign) => {
        acc[campaign.status] = (acc[campaign.status] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    return {
      active: byStatus.ACTIVE ?? 0,
      detected: byStatus.DETECTED ?? 0,
      dormant: byStatus.DORMANT ?? 0,
      resolved: byStatus.RESOLVED ?? 0,
      totalActors: campaigns.reduce((acc, campaign) => acc + campaign.actorCount, 0),
    };
  }, [campaigns]);

  const handleExport = () => {
    if (!canExport) return;
    downloadCsv(
      `soc-campaigns-${sensorId}-${new Date().toISOString().split('T')[0]}.csv`,
      ['Campaign ID', 'Name', 'Status', 'Severity', 'Actors', 'Confidence', 'Last Seen'],
      campaigns.map((campaign) => [
        campaign.campaignId,
        campaign.name,
        campaign.status,
        campaign.severity,
        campaign.actorCount,
        Math.round(campaign.confidence * 100),
        new Date(campaign.lastSeen).toISOString(),
      ]),
    );
  };

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          eyebrow="Signal Horizon"
          title="Campaigns"
          description="Coordinate response to active multi-actor campaigns across the fleet."
          actions={
            <Stack direction="row" align="center" gap="sm">
              <Text variant="label" color="secondary" noMargin>Sensor</Text>
              <Box style={{ width: 180 }}>
                <Input
                  value={sensorId}
                  onChange={(event) => setSensorId(event.target.value)}
                  placeholder="synapse-pingora-1"
                  size="sm"
                />
              </Box>
              <Button variant="outlined" size="sm" onClick={handleExport} disabled={!canExport}>
                Export CSV
              </Button>
            </Stack>
          }
        />

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard
            icon={Target}
            label="Active Campaigns"
            value={stats.active}
            accentColorVar="--ac-red"
          />
          <StatCard
            icon={Shield}
            label="Detected"
            value={stats.detected}
            accentColorVar="--ac-orange"
          />
          <StatCard
            icon={Users}
            label="Actors Linked"
            value={stats.totalActors}
            accentColorVar="--ac-blue"
          />
        </div>

        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" gap="lg" wrap>
              <Text variant="label" color="secondary" noMargin>Status</Text>
              <Tabs
                tabs={statusTabs.map((tab) => ({ key: tab.value, label: tab.label }))}
                active={statusFilter}
                onChange={setStatusFilter}
                variant="pills"
                size="sm"
              />
              <Box style={{ width: 180, marginLeft: 'auto' }}>
                <Input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  placeholder="Search campaign"
                  aria-label="Search campaigns"
                  size="sm"
                />
              </Box>
            </Stack>
          </Box>
          <Box p="none">
            {isLoading && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">Loading campaigns...</Text>
              </Box>
            )}
            {error && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" style={{ color: 'var(--ac-red)' }}>
                  Failed to load campaigns.
                </Text>
              </Box>
            )}
            {!isLoading && filteredCampaigns.length === 0 && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">No campaigns match the current filters.</Text>
              </Box>
            )}
            {filteredCampaigns.length > 0 && (
              <Box style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <caption className="sr-only">
                    Threat campaigns with severity and confidence levels
                  </caption>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Campaign</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Status</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Severity</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Actors</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Confidence</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Last Seen</Text>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredCampaigns.map((campaign) => (
                      <tr key={campaign.campaignId} style={{ borderBottom: '1px solid var(--border)' }}>
                        <td style={{ padding: '12px 16px' }}>
                          <Link
                            to={`/campaigns/${campaign.campaignId}`}
                            className="text-link hover:opacity-80 transition-opacity"
                            style={{ fontWeight: 500 }}
                          >
                            {campaign.name}
                          </Link>
                          <Text variant="caption" color="secondary" noMargin style={{ fontFamily: 'var(--font-mono)' }}>
                            {campaign.campaignId}
                          </Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Box
                            px="sm"
                            py="xs"
                            style={{
                              width: 'fit-content',
                              border: '1px solid',
                              background: 
                                campaign.status === 'ACTIVE' ? 'var(--ac-red-dim)' : 
                                campaign.status === 'DETECTED' ? 'var(--ac-orange-dim)' : 
                                campaign.status === 'RESOLVED' ? 'var(--ac-green-dim)' : 
                                'var(--ac-blue-dim)',
                              color: 
                                campaign.status === 'ACTIVE' ? 'var(--ac-red)' : 
                                campaign.status === 'DETECTED' ? 'var(--ac-orange)' : 
                                campaign.status === 'RESOLVED' ? 'var(--ac-green)' : 
                                'var(--ac-blue)',
                              borderColor: 
                                campaign.status === 'ACTIVE' ? alpha(colors.red, 0.3) : 
                                campaign.status === 'DETECTED' ? alpha(colors.orange, 0.3) : 
                                campaign.status === 'RESOLVED' ? alpha(colors.green, 0.3) : 
                                alpha(colors.blue, 0.3),
                            }}
                          >
                            <Text variant="tag" noMargin>{campaign.status}</Text>
                          </Box>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>{campaign.severity}</Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>{campaign.actorCount}</Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>
                            {Math.round(campaign.confidence * 100)}%
                          </Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>
                            {new Date(campaign.lastSeen).toLocaleString()}
                          </Text>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Box>
            )}
          </Box>
        </Box>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Activity className="w-4 h-4 text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Correlation Notes</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                Campaigns are prioritized by cross-sensor correlation density and risk velocity.
              </Text>
            </Box>
          </Box>
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Shield className="w-4 h-4 text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Response Guidance</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                Escalate ACTIVE campaigns to the War Room with mitigation playbooks enabled.
              </Text>
            </Box>
          </Box>
        </div>
      </Stack>
    </Box>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  accentColorVar,
}: {
  icon: any;
  label: string;
  value: number;
  accentColorVar: string;
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
          <Icon aria-hidden="true" size={20} style={{ color: `var(${accentColorVar})` }} />
        </Box>
        <Box>
          <Text variant="label" color="secondary" noMargin>{label}</Text>
          <Text variant="h2" weight="light" noMargin>{value}</Text>
        </Box>
      </Stack>
    </Box>
  );
}
