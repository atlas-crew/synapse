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
import { 
  Box,
  Button,
  Input,
  SectionHeader,
  Stack,
  Text,
  alpha,
  colors,
  } from '@/ui';
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
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          eyebrow="Signal Horizon"
          title="Actors"
          description="Track correlated actors and behavioral risk across the fleet."
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
            icon={Users}
            label="Tracked Actors"
            value={stats?.totalActors ?? actors.length}
            accentColorVar="--ac-blue"
          />
          <StatCard
            icon={AlertTriangle}
            label="Blocked"
            value={stats?.blockedActors ?? actors.filter((a) => a.isBlocked).length}
            accentColorVar="--ac-red"
          />
          <StatCard
            icon={Shield}
            label="Correlations"
            value={stats?.correlationsMade ?? 0}
            accentColorVar="--ac-green"
          />
        </div>

        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" justify="space-between" wrap>
              <Text variant="label" color="secondary" noMargin>Filters</Text>
              <Stack direction="row" align="center" gap="md" wrap>
                <Box style={{ width: 160 }}>
                  <Input
                    value={ipFilter}
                    onChange={(event) => setIpFilter(event.target.value)}
                    placeholder="IP address"
                    size="sm"
                  />
                </Box>
                <Box style={{ width: 180 }}>
                  <Input
                    value={fingerprintFilter}
                    onChange={(event) => setFingerprintFilter(event.target.value)}
                    placeholder="Fingerprint"
                    size="sm"
                  />
                </Box>
                <Box style={{ width: 96 }}>
                  <Input
                    value={minRisk}
                    onChange={(event) => setMinRisk(event.target.value)}
                    type="number"
                    min={0}
                    max={100}
                    size="sm"
                  />
                </Box>
              </Stack>
            </Stack>
          </Box>
          <Box p="none">
            {isLoading && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">Loading actors...</Text>
              </Box>
            )}
            {error && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" style={{ color: 'var(--ac-red)' }}>
                  Failed to load actors.
                </Text>
              </Box>
            )}
            {!isLoading && actors.length === 0 && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">No actors match the current filters.</Text>
              </Box>
            )}
            {actors.length > 0 && (
              <Box style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <caption className="sr-only">
                    Tracked actors with risk scores and activity status
                  </caption>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Actor</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Risk</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Last Seen</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>IPs</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Fingerprints</Text>
                      </th>
                      <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                        <Text variant="label" color="secondary" noMargin>Status</Text>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
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
                          <Text variant="body" weight="medium" noMargin>
                            {Math.round(actor.riskScore)}
                          </Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>
                            {new Date(actor.lastSeen).toLocaleString()}
                          </Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>{actor.ips.length}</Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Text variant="body" color="secondary" noMargin>{actor.fingerprints.length}</Text>
                        </td>
                        <td style={{ padding: '12px 16px' }}>
                          <Box
                            px="sm"
                            py="xs"
                            style={{
                              width: 'fit-content',
                              border: '1px solid',
                              background: actor.isBlocked ? 'var(--ac-red-dim)' : 'var(--ac-green-dim)',
                              color: actor.isBlocked ? 'var(--ac-red)' : 'var(--ac-green)',
                              borderColor: actor.isBlocked ? alpha(colors.red, 0.3) : alpha(colors.green, 0.3),
                            }}
                          >
                            <Text variant="tag" noMargin>{actor.isBlocked ? 'Blocked' : 'Active'}</Text>
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
