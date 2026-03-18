import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { AlertTriangle, Activity, Shield, Clock } from 'lucide-react';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchSessions } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { downloadCsv } from '../../lib/csv';
import type { SocSession, SocSessionListResponse } from '../../types/soc';
import { 
  Box, 
  Button, 
  Input, 
  SectionHeader, 
  Stack, 
  Text, 
  alpha, 
  colors, 
  spacing,
} from '@/ui';

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
  const activeSessions = sessions.filter(
    (session) => session.lastActivity > now - 30 * 60 * 1000,
  ).length;
  const hijackAlerts = sessions.reduce(
    (count, session) => count + (session.hijackAlerts?.length ?? 0),
    0,
  );

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

  const queryParams = useMemo(
    () => ({
      actorId: actorFilter.trim() || undefined,
      suspicious: suspiciousOnly || undefined,
      limit: 50,
    }),
    [actorFilter, suspiciousOnly],
  );

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
      [
        'Session ID',
        'Actor ID',
        'Last Activity',
        'Requests',
        'Suspicious',
        'Hijack Alerts',
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
        session.boundIp ?? '',
        session.boundJa4 ?? '',
      ]),
    );
  };

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          eyebrow="Signal Horizon"
          title="Sessions"
          description="Inspect session behavior, hijack alerts, and enforcement actions."
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
            icon={Activity}
            label="Active Sessions"
            value={
              stats?.activeSessions ??
              sessions.filter((session) => session.lastActivity > Date.now() - 30 * 60 * 1000).length
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
            label="Hijack Alerts"
            value={
              stats?.hijackAlerts ??
              sessions.reduce((count, session) => count + (session.hijackAlerts?.length ?? 0), 0)
            }
            accentColorVar="--ac-red"
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
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Session</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Actor</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Last Activity</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Requests</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Alerts</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Status</Text>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((session) => (
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
