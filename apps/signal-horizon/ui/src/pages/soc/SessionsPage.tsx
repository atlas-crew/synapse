import { useDeferredValue, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Activity, Shield, Clock } from 'lucide-react';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchFleetSessions } from '../../hooks/soc/api';
import { downloadCsv } from '../../lib/csv';
import type { SocFleetSession, SocFleetSessionListResponse } from '../../types/soc';
import { 
  Box, 
  Button, 
  Input, 
  SectionHeader, 
  Stack, 
  StatusBadge,
  Text, 
  alpha, 
  colors, 
  spacing,
  PAGE_TITLE_STYLE,
} from '@/ui';

function buildDemoSessions(scenario: string): SocFleetSessionListResponse {
  const now = Date.now();
  const baseSuspicious = scenario === 'high-threat' ? 0.45 : scenario === 'normal' ? 0.25 : 0.1;
  const sessions: SocFleetSession[] = Array.from({ length: 14 }).map((_, index) => {
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
      seenOnSensors: Array.from({ length: (index % 3) + 1 }, (_, sensorIndex) => `sensor-${sensorIndex + 1}`),
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
  const activeSessions = sessions.filter(
    (session) => session.lastActivity > now - 30 * 60 * 1000,
  ).length;
  const hijackAlerts = sessions.reduce(
    (count, session) => count + (session.hijackAlerts?.length ?? 0),
    0,
  );

  return {
    aggregate: sessions,
    results: [
      { sensorId: 'sensor-1', status: 'ok' },
      { sensorId: 'sensor-2', status: 'ok' },
      { sensorId: 'sensor-3', status: 'ok' },
    ],
    summary: { succeeded: 3, stale: 0, failed: 0 },
    total: sessions.length,
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

function formatRelativeMinutes(iso: string, nowMs: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return 'unknown';
  const ageMin = Math.max(1, Math.round((nowMs - then) / 60_000));
  return `${ageMin} min ago`;
}

export default function SessionsPage() {
  useDocumentTitle('SOC - Sessions');
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [actorFilter, setActorFilter] = useState('');
  const deferredActorFilter = useDeferredValue(actorFilter);
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);

  const queryParams = useMemo(
    () => ({
      actorId: deferredActorFilter.trim() || undefined,
      suspicious: suspiciousOnly || undefined,
      limit: 50,
    }),
    [deferredActorFilter, suspiciousOnly],
  );

  const { data, isLoading, error } = useQuery({
    queryKey: ['soc', 'fleet-sessions', queryParams, isDemoMode, scenario],
    queryFn: async () => {
      if (isDemoMode) {
        return buildDemoSessions(scenario);
      }
      return fetchFleetSessions(queryParams);
    },
    staleTime: isDemoMode ? Infinity : 15000,
  });

  const sessions = data?.aggregate ?? [];
  const stats = data?.stats;
  const results = data?.results ?? [];
  const summary = data?.summary ?? { succeeded: 0, stale: 0, failed: 0 };
  const canExport = sessions.length > 0;
  const nowMs = Date.now();

  const staleSensors = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of results) {
      if (r.status === 'stale' && r.lastUpdatedAt) {
        m.set(r.sensorId, r.lastUpdatedAt);
      }
    }
    return m;
  }, [results]);

  const handleExport = () => {
    if (!canExport) return;
    downloadCsv(
      `soc-sessions-fleet-${new Date().toISOString().split('T')[0]}.csv`,
      [
        'Session ID',
        'Actor ID',
        'Last Activity',
        'Requests',
        'Suspicious',
        'Hijack Alerts',
        'Sensors',
        'Bound IP',
        'JA4',
      ],
      sessions.map((session) => [
        session.sessionId,
        session.actorId ?? '',
        new Date(session.lastActivity).toISOString(),
        session.requestCount,
        session.isSuspicious ? 'YES' : 'NO',
        session.hijackAlerts?.length ?? 0,
        session.seenOnSensors?.join('; ') ?? '',
        session.boundIp ?? '',
        session.boundJa4 ?? '',
      ]),
    );
  };

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          title="Sessions"
          description="Inspect session behavior, hijack alerts, and enforcement actions."
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            <Button variant="outlined" size="sm" onClick={handleExport} disabled={!canExport}>
              Export CSV
            </Button>
          }
        />

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard
            icon={Activity}
            label="Active Sessions"
            value={
              stats?.activeSessions ??
              sessions.filter((session) => session.lastActivity > nowMs - 30 * 60 * 1000).length
            }
            accentColorVar="--ac-blue"
          />
          <StatCard
            icon={AlertTriangle}
            label="Suspicious"
            value={
              stats?.suspiciousSessions ?? sessions.filter((session) => session.isSuspicious).length
            }
            accentColorVar="--ac-orange"
          />
          <StatCard
            icon={Shield}
            label="Sensors Reporting"
            value={summary.succeeded + summary.stale}
            accentColorVar={summary.stale > 0 ? '--ac-orange' : '--ac-green'}
          />
        </div>

        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" justify="space-between" wrap>
              <Text variant="label" color="secondary" noMargin>Filters</Text>
              <Stack direction="row" align="center" gap="md" wrap>
                <Box style={{ width: 180 }}>
                  <Input
                    value={actorFilter}
                    onChange={(event) => setActorFilter(event.target.value)}
                    placeholder="Actor ID"
                    size="sm"
                  />
                </Box>
                <Stack as="label" direction="row" align="center" gap="sm">
                  <input
                    type="checkbox"
                    checked={suspiciousOnly}
                    onChange={(event) => setSuspiciousOnly(event.target.checked)}
                    className="h-4 w-4"
                    style={{ accentColor: 'var(--ac-blue)' }}
                  />
                  <Text variant="small" color="secondary" noMargin>Suspicious only</Text>
                </Stack>
              </Stack>
            </Stack>
          </Box>
          <Box p="none">
            {isLoading && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">Loading sessions...</Text>
              </Box>
            )}
            {error && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" style={{ color: 'var(--ac-red)' }}>
                  Failed to load sessions.
                </Text>
              </Box>
            )}
            {!isLoading && sessions.length === 0 && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">No sessions match the current filters.</Text>
              </Box>
            )}
            {sessions.length > 0 && (
              <Box style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <caption className="sr-only">
                    Active sessions with actor and alert information
                  </caption>
                  <thead>
                    <tr>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Session</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Actor</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Last Activity</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Requests</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Alerts</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Coverage</Text>
                      </th>
                      <th scope="col" style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Status</Text>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((session) => {
                      const seenOnSensors = session.seenOnSensors ?? [];
                      const sensorCount = seenOnSensors.length;
                      const sensorLabel = `${sensorCount} ${sensorCount === 1 ? 'sensor' : 'sensors'}`;
                      const staleContributor = seenOnSensors
                        .map((id) => ({ id, lastUpdatedAt: staleSensors.get(id) }))
                        .find((entry) => entry.lastUpdatedAt !== undefined);
                      return (
                        <tr key={session.sessionId} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '12px 16px' }}>
                            <Link
                              to={`/sessions/${session.sessionId}`}
                              className="text-link hover:opacity-80 transition-opacity"
                              style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                            >
                              {session.sessionId}
                            </Link>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            {session.actorId ? (
                              <Link
                                to={`/actors/${session.actorId}`}
                                className="text-link hover:opacity-80 transition-opacity"
                                style={{ fontSize: '13px' }}
                              >
                                {session.actorId}
                              </Link>
                            ) : (
                              <Text variant="body" color="secondary" noMargin>Unbound</Text>
                            )}
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Text variant="body" color="secondary" noMargin>
                              {new Date(session.lastActivity).toLocaleString()}
                            </Text>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Text variant="body" color="secondary" noMargin>{session.requestCount}</Text>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Text variant="body" color="secondary" noMargin>{session.hijackAlerts?.length ?? 0}</Text>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Stack direction="row" align="center" gap="sm" wrap>
                              <StatusBadge status="info" variant="subtle" size="sm">
                                {sensorLabel}
                              </StatusBadge>
                              {staleContributor?.lastUpdatedAt && (
                                <StatusBadge status="warning" variant="subtle" size="sm">
                                  <Stack direction="row" align="center" gap="xs">
                                    <Clock size={10} aria-hidden="true" />
                                    <span>{formatRelativeMinutes(staleContributor.lastUpdatedAt, nowMs)}</span>
                                  </Stack>
                                </StatusBadge>
                              )}
                            </Stack>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Box
                              px="sm"
                              py="xs"
                              style={{
                                width: 'fit-content',
                                border: '1px solid',
                                background: session.isSuspicious ? 'var(--ac-orange-dim)' : 'var(--ac-green-dim)',
                                color: session.isSuspicious ? 'var(--ac-orange)' : 'var(--ac-green)',
                                borderColor: session.isSuspicious ? alpha(colors.orange, 0.3) : alpha(colors.green, 0.3),
                              }}
                            >
                              <Text variant="tag" noMargin>{session.isSuspicious ? 'Suspicious' : 'Active'}</Text>
                            </Box>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </Box>
            )}
          </Box>
        </Box>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Clock className="w-4 h-4 text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Session Aging</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                {stats?.expiredSessions ?? 0} expired sessions tracked. Focus on suspicious sessions
                first.
              </Text>
            </Box>
          </Box>
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Shield className="w-4 h-4 text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Enforcement</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                {stats?.totalInvalidated
                  ? `${stats.totalInvalidated} sessions invalidated recently.`
                  : 'No automatic revocations recorded.'}
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
