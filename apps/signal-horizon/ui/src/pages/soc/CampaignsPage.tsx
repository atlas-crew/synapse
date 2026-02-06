import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Target, Activity, Shield, Users } from 'lucide-react';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchCampaigns } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocCampaign, SocCampaignListResponse } from '../../types/soc';

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
    const severity = (index % 4 === 0 ? 'CRITICAL' : index % 4 === 1 ? 'HIGH' : index % 4 === 2 ? 'MEDIUM' : 'LOW') as SocCampaign['severity'];
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
      summary: status === 'RESOLVED' ? 'Contained and resolved by automated controls.' : 'Coordinated probing across multiple endpoints.',
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
    const byStatus = campaigns.reduce((acc, campaign) => {
      acc[campaign.status] = (acc[campaign.status] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

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
      ])
    );
  };

  return (
    <div className="p-6 space-y-6">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-xs tracking-[0.3em] uppercase text-ink-muted">Signal Horizon</p>
          <h1 className="text-3xl font-light text-ink-primary">Campaigns</h1>
          <p className="text-ink-secondary mt-2">Coordinate response to active multi-actor campaigns across the fleet.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs text-ink-muted uppercase tracking-[0.18em]">Sensor</label>
          <input
            value={sensorId}
            onChange={(event) => setSensorId(event.target.value)}
            className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            placeholder="synapse-pingora-1"
          />
          <button
            className="btn-outline h-10 px-4 text-xs"
            onClick={handleExport}
            disabled={!canExport}
          >
            Export CSV
          </button>
        </div>
      </header>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard icon={Target} label="Active Campaigns" value={stats.active} tone="text-ac-red" />
        <StatCard icon={Shield} label="Detected" value={stats.detected} tone="text-ac-orange" />
        <StatCard icon={Users} label="Actors Linked" value={stats.totalActors} tone="text-ac-blue" />
      </section>

      <section className="card">
        <div className="card-header flex flex-wrap items-center gap-3">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Status</div>
          <div className="flex flex-wrap gap-2">
            {statusTabs.map((tab) => (
              <button
                key={tab.value}
                type="button"
                className={clsx(
                  'px-3 py-1 text-xs border transition-colors',
                  statusFilter === tab.value
                    ? 'bg-surface-card text-ink-primary border-link'
                    : 'text-ink-secondary border-border-subtle hover:text-ink-primary'
                )}
                onClick={() => setStatusFilter(tab.value)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <div className="ml-auto">
            <input
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search campaign"
              aria-label="Search campaigns"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            />
          </div>
        </div>
        <div className="card-body">
          {isLoading && <div className="text-ink-muted">Loading campaigns...</div>}
          {error && <div className="text-ac-red">Failed to load campaigns.</div>}
          {!isLoading && filteredCampaigns.length === 0 && (
            <div className="text-ink-muted">No campaigns match the current filters.</div>
          )}
          {filteredCampaigns.length > 0 && (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Campaign</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Actors</th>
                    <th>Confidence</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCampaigns.map((campaign) => (
                    <tr key={campaign.campaignId}>
                      <td className="text-ink-primary">
                        <Link to={`/campaigns/${campaign.campaignId}`} className="text-link hover:text-link-hover">
                          {campaign.name}
                        </Link>
                        <div className="text-xs text-ink-muted font-mono">{campaign.campaignId}</div>
                      </td>
                      <td>
                        <span
                          className={clsx(
                            'px-2 py-0.5 text-xs border',
                            campaign.status === 'ACTIVE'
                              ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                              : campaign.status === 'DETECTED'
                                ? 'bg-ac-orange/15 text-ac-orange border-ac-orange/40'
                                : campaign.status === 'DORMANT'
                                  ? 'bg-ac-blue/10 text-ac-blue border-ac-blue/40'
                                  : 'bg-ac-green/10 text-ac-green border-ac-green/40'
                          )}
                        >
                          {campaign.status}
                        </span>
                      </td>
                      <td className="text-ink-secondary">{campaign.severity}</td>
                      <td className="text-ink-secondary">{campaign.actorCount}</td>
                      <td className="text-ink-secondary">{Math.round(campaign.confidence * 100)}%</td>
                      <td className="text-ink-secondary">{new Date(campaign.lastSeen).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Activity className="w-4 h-4" /> Correlation Notes
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            Campaigns are prioritized by cross-sensor correlation density and risk velocity.
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Shield className="w-4 h-4" /> Response Guidance
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            Escalate ACTIVE campaigns to the War Room with mitigation playbooks enabled.
          </div>
        </div>
      </section>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Target;
  label: string;
  value: number;
  tone: string;
}) {
  return (
    <div className="card p-4 flex items-center gap-4">
      <div className={clsx('w-10 h-10 flex items-center justify-center', tone, 'bg-surface-subtle')}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">{label}</p>
        <p className="text-2xl font-light text-ink-primary">{value}</p>
      </div>
    </div>
  );
}
