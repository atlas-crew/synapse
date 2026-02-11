import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Shield, Users } from 'lucide-react';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchActors } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocActor, SocActorListResponse } from '../../types/soc';
import { Button, Input, SectionHeader, alpha, colors, spacing } from '@/ui';

function buildDemoActors(scenario: string): SocActorListResponse {
  const baseRisk = scenario === 'high-threat' ? 82 : scenario === 'normal' ? 55 : 28;
  const actors: SocActor[] = Array.from({ length: 10 }).map((_, index) => {
    const risk = Math.min(100, baseRisk + index * 3);
    const now = Date.now();
    return {
      actorId: `actor-${scenario}-${index + 1}`,
      riskScore: risk,
      ruleMatches: [],
      anomalyCount: Math.max(0, index - 3),
      sessionIds: Array.from({ length: Math.max(1, 3 - (index % 3)) }).map(
        (_, idx) => `sess-${index + 1}-${idx + 1}`,
      ),
      firstSeen: now - (index + 2) * 3600 * 1000,
      lastSeen: now - index * 900 * 1000,
      ips: [`203.0.113.${10 + index}`],
      fingerprints: [`fp-${index + 1}`],
      isBlocked: risk > 75,
      blockReason: risk > 75 ? 'Auto-block threshold' : null,
      blockedSince: risk > 75 ? now - 3600 * 1000 : null,
    };
  });

  return {
    actors,
    stats: {
      totalActors: actors.length,
      blockedActors: actors.filter((a) => a.isBlocked).length,
      correlationsMade: 12,
      evictions: 3,
      totalCreated: 128,
      totalRuleMatches: 256,
    },
  };
}

export default function ActorsPage() {
  useDocumentTitle('SOC - Actors');
  const { sensorId, setSensorId } = useSocSensor();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [ipFilter, setIpFilter] = useState('');
  const [fingerprintFilter, setFingerprintFilter] = useState('');
  const [minRisk, setMinRisk] = useState('50');

  const queryParams = useMemo(
    () => ({
      ip: ipFilter.trim() || undefined,
      fingerprint: fingerprintFilter.trim() || undefined,
      minRisk: minRisk ? Number(minRisk) : undefined,
      limit: 50,
    }),
    [ipFilter, fingerprintFilter, minRisk],
  );

  const { data, isLoading, error } = useQuery({
    queryKey: ['soc', 'actors', sensorId, queryParams, isDemoMode, scenario],
    queryFn: async () => {
      if (isDemoMode) {
        return buildDemoActors(scenario);
      }
      return fetchActors(sensorId, queryParams);
    },
    staleTime: isDemoMode ? Infinity : 15000,
  });

  const actors = data?.actors ?? [];
  const stats = data?.stats;
  const canExport = actors.length > 0;

  const handleExport = () => {
    if (!canExport) return;
    downloadCsv(
      `soc-actors-${sensorId}-${new Date().toISOString().split('T')[0]}.csv`,
      ['Actor ID', 'Risk Score', 'Last Seen', 'IPs', 'Fingerprints', 'Status'],
      actors.map((actor) => [
        actor.actorId,
        Math.round(actor.riskScore),
        new Date(actor.lastSeen).toISOString(),
        actor.ips.join('; '),
        actor.fingerprints.join('; '),
        actor.isBlocked ? 'BLOCKED' : 'ACTIVE',
      ]),
    );
  };

  return (
    <div className="p-6 space-y-6">
      <SectionHeader
        eyebrow="Signal Horizon"
        title="Actors"
        description="Track correlated actors and behavioral risk across the fleet."
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>
            <span className="text-xs text-ink-muted uppercase tracking-[0.18em]">Sensor</span>
            <div style={{ width: 180 }}>
              <Input
                value={sensorId}
                onChange={(event) => setSensorId(event.target.value)}
                placeholder="synapse-pingora-1"
                size="sm"
              />
            </div>
            <Button variant="outlined" size="sm" onClick={handleExport} disabled={!canExport}>
              Export CSV
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          icon={Users}
          label="Tracked Actors"
          value={stats?.totalActors ?? actors.length}
          accentColor={colors.blue}
        />
        <StatCard
          icon={AlertTriangle}
          label="Blocked"
          value={stats?.blockedActors ?? actors.filter((a) => a.isBlocked).length}
          accentColor={colors.red}
        />
        <StatCard
          icon={Shield}
          label="Correlations"
          value={stats?.correlationsMade ?? 0}
          accentColor={colors.green}
        />
      </section>

      <section className="card">
        <div className="card-header flex flex-wrap items-center gap-3">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Filters</div>
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <div style={{ width: 160 }}>
              <Input
                value={ipFilter}
                onChange={(event) => setIpFilter(event.target.value)}
                placeholder="IP address"
                size="sm"
              />
            </div>
            <div style={{ width: 180 }}>
              <Input
                value={fingerprintFilter}
                onChange={(event) => setFingerprintFilter(event.target.value)}
                placeholder="Fingerprint"
                size="sm"
              />
            </div>
            <div style={{ width: 96 }}>
              <Input
                value={minRisk}
                onChange={(event) => setMinRisk(event.target.value)}
                type="number"
                min={0}
                max={100}
                size="sm"
              />
            </div>
          </div>
        </div>
        <div className="card-body">
          {isLoading && <div className="text-ink-muted">Loading actors...</div>}
          {error && <div style={{ color: colors.red }}>Failed to load actors.</div>}
          {!isLoading && actors.length === 0 && (
            <div className="text-ink-muted">No actors match the current filters.</div>
          )}
          {actors.length > 0 && (
            <div className="overflow-x-auto">
              <table className="data-table">
                <caption className="sr-only">
                  Tracked actors with risk scores and activity status
                </caption>
                <thead>
                  <tr>
                    <th>Actor</th>
                    <th>Risk</th>
                    <th>Last Seen</th>
                    <th>IPs</th>
                    <th>Fingerprints</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {actors.map((actor) => (
                    <tr key={actor.actorId}>
                      <td className="font-mono text-sm text-ink-primary">
                        <Link
                          to={`/actors/${actor.actorId}`}
                          className="text-link hover:text-link-hover"
                        >
                          {actor.actorId}
                        </Link>
                      </td>
                      <td className="text-ink-primary">{Math.round(actor.riskScore)}</td>
                      <td className="text-ink-secondary">
                        {new Date(actor.lastSeen).toLocaleString()}
                      </td>
                      <td className="text-ink-secondary">{actor.ips.length}</td>
                      <td className="text-ink-secondary">{actor.fingerprints.length}</td>
                      <td>
                        {(() => {
                          const isBlocked = actor.isBlocked;
                          const badgeStyle = isBlocked
                            ? {
                                background: alpha(colors.red, 0.15),
                                color: colors.red,
                                borderColor: alpha(colors.red, 0.4),
                              }
                            : {
                                background: alpha(colors.green, 0.1),
                                color: colors.green,
                                borderColor: alpha(colors.green, 0.4),
                              };
                          return (
                            <span className="px-2 py-0.5 text-xs border" style={badgeStyle}>
                              {isBlocked ? 'Blocked' : 'Active'}
                            </span>
                          );
                        })()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  accentColor,
}: {
  icon: typeof Users;
  label: string;
  value: number;
  accentColor: string;
}) {
  return (
    <div className="card p-4 flex items-center gap-4">
      <div className="w-10 h-10 flex items-center justify-center bg-surface-subtle">
        <Icon aria-hidden="true" className="w-5 h-5" style={{ color: accentColor }} />
      </div>
      <div>
        <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">{label}</p>
        <p className="text-2xl font-light text-ink-primary">{value}</p>
      </div>
    </div>
  );
}
