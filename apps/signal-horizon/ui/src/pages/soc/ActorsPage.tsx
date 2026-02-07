import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Shield, Users } from 'lucide-react';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchActors } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocActor, SocActorListResponse } from '../../types/soc';

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
      sessionIds: Array.from({ length: Math.max(1, 3 - index % 3) }).map(
        (_, idx) => `sess-${index + 1}-${idx + 1}`
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

  const queryParams = useMemo(() => ({
    ip: ipFilter.trim() || undefined,
    fingerprint: fingerprintFilter.trim() || undefined,
    minRisk: minRisk ? Number(minRisk) : undefined,
    limit: 50,
  }), [ipFilter, fingerprintFilter, minRisk]);

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
      ])
    );
  };

  return (
    <div className="p-6 space-y-6">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-xs tracking-[0.3em] uppercase text-ink-muted">Signal Horizon</p>
          <h1 className="text-3xl font-light text-ink-primary">Actors</h1>
          <p className="text-ink-secondary mt-2">Track correlated actors and behavioral risk across the fleet.</p>
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
        <StatCard
          icon={Users}
          label="Tracked Actors"
          value={stats?.totalActors ?? actors.length}
          tone="text-ac-blue"
        />
        <StatCard
          icon={AlertTriangle}
          label="Blocked"
          value={stats?.blockedActors ?? actors.filter((a) => a.isBlocked).length}
          tone="text-ac-red"
        />
        <StatCard
          icon={Shield}
          label="Correlations"
          value={stats?.correlationsMade ?? 0}
          tone="text-ac-green"
        />
      </section>

      <section className="card">
        <div className="card-header flex flex-wrap items-center gap-3">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Filters</div>
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <input
              value={ipFilter}
              onChange={(event) => setIpFilter(event.target.value)}
              placeholder="IP address"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            />
            <input
              value={fingerprintFilter}
              onChange={(event) => setFingerprintFilter(event.target.value)}
              placeholder="Fingerprint"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            />
            <input
              value={minRisk}
              onChange={(event) => setMinRisk(event.target.value)}
              type="number"
              min={0}
              max={100}
              className="w-24 px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            />
          </div>
        </div>
        <div className="card-body">
          {isLoading && <div className="text-ink-muted">Loading actors...</div>}
          {error && <div className="text-ac-red">Failed to load actors.</div>}
          {!isLoading && actors.length === 0 && (
            <div className="text-ink-muted">No actors match the current filters.</div>
          )}
          {actors.length > 0 && (
            <div className="overflow-x-auto">
              <table className="data-table">
                <caption className="sr-only">Tracked actors with risk scores and activity status</caption>
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
                        <Link to={`/actors/${actor.actorId}`} className="text-link hover:text-link-hover">
                          {actor.actorId}
                        </Link>
                      </td>
                      <td className="text-ink-primary">{Math.round(actor.riskScore)}</td>
                      <td className="text-ink-secondary">{new Date(actor.lastSeen).toLocaleString()}</td>
                      <td className="text-ink-secondary">{actor.ips.length}</td>
                      <td className="text-ink-secondary">{actor.fingerprints.length}</td>
                      <td>
                        <span
                          className={clsx(
                            'px-2 py-0.5 text-xs border',
                            actor.isBlocked
                              ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                              : 'bg-ac-green/10 text-ac-green border-ac-green/40'
                          )}
                        >
                          {actor.isBlocked ? 'Blocked' : 'Active'}
                        </span>
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
  tone,
}: {
  icon: typeof Users;
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
