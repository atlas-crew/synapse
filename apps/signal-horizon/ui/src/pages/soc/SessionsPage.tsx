import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Activity, Shield, Clock } from 'lucide-react';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchSessions } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocSession, SocSessionListResponse } from '../../types/soc';

function buildDemoSessions(scenario: string): SocSessionListResponse {
  const now = Date.now();
  const baseSuspicious = scenario === 'high-threat' ? 0.45 : scenario === 'normal' ? 0.25 : 0.1;
  const sessions: SocSession[] = Array.from({ length: 14 }).map((_, index) => {
    const suspicious = index % Math.max(2, Math.floor(1 / baseSuspicious)) === 0;
    const created = now - (index + 2) * 45 * 60 * 1000;
    const last = now - index * 12 * 60 * 1000;
    const alertCount = suspicious ? Math.min(2, (index % 3) + 1) : 0;
    return {
      sessionId: `sess-${scenario}-${index + 1}`,
      tokenHash: `tok_${scenario}_${index + 12}`,
      actorId: index % 2 === 0 ? `actor-${scenario}-${index + 1}` : null,
      creationTime: created,
      lastActivity: last,
      requestCount: 120 + index * 14,
      boundJa4: index % 3 === 0 ? `ja4-${index}-${scenario}` : null,
      boundIp: `203.0.113.${20 + index}`,
      isSuspicious: suspicious,
      hijackAlerts: Array.from({ length: alertCount }).map((_, alertIndex) => ({
        sessionId: `sess-${scenario}-${index + 1}`,
        alertType: alertIndex % 2 === 0 ? 'fingerprint_change' : 'ip_drift',
        originalValue: alertIndex % 2 === 0 ? 'ja4-base' : `203.0.113.${18 + index}`,
        newValue: alertIndex % 2 === 0 ? `ja4-${index}-${scenario}` : `203.0.113.${40 + index}`,
        timestamp: last - alertIndex * 18 * 60 * 1000,
        confidence: 0.72 + alertIndex * 0.08,
      })),
    };
  });

  const suspiciousSessions = sessions.filter((session) => session.isSuspicious).length;
  const activeSessions = sessions.filter((session) => session.lastActivity > now - 30 * 60 * 1000).length;
  const hijackAlerts = sessions.reduce((count, session) => count + session.hijackAlerts.length, 0);

  return {
    sessions,
    stats: {
      totalSessions: sessions.length,
      activeSessions,
      suspiciousSessions,
      expiredSessions: Math.max(0, sessions.length - activeSessions),
      hijackAlerts,
      evictions: scenario === 'high-threat' ? 6 : 2,
      totalCreated: 240 + sessions.length,
      totalInvalidated: scenario === 'high-threat' ? 36 : 14,
    },
  };
}

export default function SessionsPage() {
  useDocumentTitle('SOC - Sessions');
  const { sensorId, setSensorId } = useSocSensor();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [actorFilter, setActorFilter] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);

  const queryParams = useMemo(() => ({
    actorId: actorFilter.trim() || undefined,
    suspicious: suspiciousOnly || undefined,
    limit: 50,
  }), [actorFilter, suspiciousOnly]);

  const { data, isLoading, error } = useQuery({
    queryKey: ['soc', 'sessions', sensorId, queryParams, isDemoMode, scenario],
    queryFn: async () => {
      if (isDemoMode) {
        return buildDemoSessions(scenario);
      }
      return fetchSessions(sensorId, queryParams);
    },
    staleTime: isDemoMode ? Infinity : 15000,
  });

  const sessions = data?.sessions ?? [];
  const stats = data?.stats;
  const canExport = sessions.length > 0;

  const handleExport = () => {
    if (!canExport) return;
    downloadCsv(
      `soc-sessions-${sensorId}-${new Date().toISOString().split('T')[0]}.csv`,
      ['Session ID', 'Actor ID', 'Last Activity', 'Requests', 'Suspicious', 'Hijack Alerts', 'Bound IP', 'JA4'],
      sessions.map((session) => [
        session.sessionId,
        session.actorId ?? '',
        new Date(session.lastActivity).toISOString(),
        session.requestCount,
        session.isSuspicious ? 'YES' : 'NO',
        session.hijackAlerts.length,
        session.boundIp ?? '',
        session.boundJa4 ?? '',
      ])
    );
  };

  return (
    <div className="p-6 space-y-6">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-xs tracking-[0.3em] uppercase text-ink-muted">Signal Horizon</p>
          <h1 className="text-3xl font-light text-ink-primary">Sessions</h1>
          <p className="text-ink-secondary mt-2">Inspect session behavior, hijack alerts, and enforcement actions.</p>
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
          icon={Activity}
          label="Active Sessions"
          value={stats?.activeSessions ?? sessions.filter((session) => session.lastActivity > Date.now() - 30 * 60 * 1000).length}
          tone="text-ac-blue"
        />
        <StatCard
          icon={AlertTriangle}
          label="Suspicious"
          value={stats?.suspiciousSessions ?? sessions.filter((session) => session.isSuspicious).length}
          tone="text-ac-orange"
        />
        <StatCard
          icon={Shield}
          label="Hijack Alerts"
          value={stats?.hijackAlerts ?? sessions.reduce((count, session) => count + session.hijackAlerts.length, 0)}
          tone="text-ac-red"
        />
      </section>

      <section className="card">
        <div className="card-header flex flex-wrap items-center gap-3">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Filters</div>
          <div className="ml-auto flex flex-wrap items-center gap-3">
            <input
              value={actorFilter}
              onChange={(event) => setActorFilter(event.target.value)}
              placeholder="Actor ID"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            />
            <label className="flex items-center gap-2 text-sm text-ink-secondary">
              <input
                type="checkbox"
                checked={suspiciousOnly}
                onChange={(event) => setSuspiciousOnly(event.target.checked)}
                className="h-4 w-4"
              />
              Suspicious only
            </label>
          </div>
        </div>
        <div className="card-body">
          {isLoading && <div className="text-ink-muted">Loading sessions...</div>}
          {error && <div className="text-ac-red">Failed to load sessions.</div>}
          {!isLoading && sessions.length === 0 && (
            <div className="text-ink-muted">No sessions match the current filters.</div>
          )}
          {sessions.length > 0 && (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Session</th>
                    <th>Actor</th>
                    <th>Last Activity</th>
                    <th>Requests</th>
                    <th>Alerts</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.sessionId}>
                      <td className="font-mono text-sm text-ink-primary">
                        <Link to={`/sessions/${session.sessionId}`} className="text-link hover:text-link-hover">
                          {session.sessionId}
                        </Link>
                      </td>
                      <td className="text-ink-secondary">
                        {session.actorId ? (
                          <Link to={`/actors/${session.actorId}`} className="text-link hover:text-link-hover">
                            {session.actorId}
                          </Link>
                        ) : (
                          <span className="text-ink-muted">Unbound</span>
                        )}
                      </td>
                      <td className="text-ink-secondary">
                        {new Date(session.lastActivity).toLocaleString()}
                      </td>
                      <td className="text-ink-secondary">{session.requestCount}</td>
                      <td className="text-ink-secondary">{session.hijackAlerts.length}</td>
                      <td>
                        <span
                          className={clsx(
                            'px-2 py-0.5 text-xs border',
                            session.isSuspicious
                              ? 'bg-ac-orange/15 text-ac-orange border-ac-orange/40'
                              : 'bg-ac-green/10 text-ac-green border-ac-green/40'
                          )}
                        >
                          {session.isSuspicious ? 'Suspicious' : 'Active'}
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

      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Clock className="w-4 h-4" /> Session Aging
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            {stats?.expiredSessions ?? 0} expired sessions tracked. Focus on suspicious sessions first.
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Shield className="w-4 h-4" /> Enforcement
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            {stats?.totalInvalidated ? `${stats.totalInvalidated} sessions invalidated recently.` : 'No automatic revocations recorded.'}
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
  icon: typeof Activity;
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
