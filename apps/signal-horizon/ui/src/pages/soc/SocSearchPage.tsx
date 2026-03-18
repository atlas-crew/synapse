import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Search } from 'lucide-react';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchActorDetail, fetchActors, fetchSessionDetail } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import type { SocActor, SocSession } from '../../types/soc';
import { 
  Alert, 
  Box, 
  Button, 
  Input, 
  SectionHeader, 
  Select, 
  Stack, 
  StatusBadge,
  Text,
  alpha,
  colors
} from '@/ui';

type SearchType = 'auto' | 'ip' | 'fingerprint' | 'actor' | 'session';

type SearchResult =
  | { kind: 'actors'; actors: SocActor[] }
  | { kind: 'actor'; actor: SocActor }
  | { kind: 'session'; session: SocSession };

const searchTypeOptions = [
  { value: 'auto', label: 'Auto detect' },
  { value: 'ip', label: 'IP' },
  { value: 'fingerprint', label: 'Fingerprint' },
  { value: 'actor', label: 'Actor' },
  { value: 'session', label: 'Session' },
];

const demoActor: SocActor = {
  actorId: 'actor-demo-9',
  riskScore: 78,
  ruleMatches: [],
  anomalyCount: 2,
  sessionIds: ['sess-demo-101', 'sess-demo-102'],
  firstSeen: Date.now() - 6 * 3600 * 1000,
  lastSeen: Date.now() - 24 * 60 * 1000,
  ips: ['203.0.113.55'],
  fingerprints: ['fp-demo-9'],
  isBlocked: false,
  blockReason: null,
  blockedSince: null,
};

const demoSession: SocSession = {
  sessionId: 'sess-demo-101',
  tokenHash: 'tok-demo-101',
  actorId: 'actor-demo-9',
  creationTime: Date.now() - 2 * 3600 * 1000,
  lastActivity: Date.now() - 10 * 60 * 1000,
  requestCount: 312,
  boundJa4: 'ja4-demo-9',
  boundIp: '203.0.113.55',
  isSuspicious: true,
  hijackAlerts: [],
};

function detectSearchType(input: string): Exclude<SearchType, 'auto'> {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(input)) return 'ip';
  const lower = input.toLowerCase();
  if (lower.startsWith('sess-') || lower.startsWith('session-')) return 'session';
  if (lower.startsWith('actor-') || lower.startsWith('act-')) return 'actor';
  if (lower.startsWith('fp-') || lower.startsWith('ja4-')) return 'fingerprint';
  return 'actor';
}

export default function SocSearchPage() {
  useDocumentTitle('SOC - Search');
  const { sensorId, setSensorId } = useSocSensor();
  const { isEnabled: isDemoMode } = useDemoMode();
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<SearchType>('auto');
  const [submitted, setSubmitted] = useState<{ term: string; type: SearchType } | null>(null);

  const resolvedType = useMemo<Exclude<SearchType, 'auto'>>(() => {
    if (!submitted) return 'actor';
    if (submitted.type === 'auto') return detectSearchType(submitted.term);
    return submitted.type;
  }, [submitted]);

  const { data, isLoading, error } = useQuery<SearchResult | null>({
    queryKey: ['soc', 'search', sensorId, submitted?.term, resolvedType, isDemoMode],
    queryFn: async () => {
      if (!submitted) return null;
      const term = submitted.term.trim();
      if (!term) return null;

      if (isDemoMode) {
        if (resolvedType === 'session') return { kind: 'session', session: demoSession };
        if (resolvedType === 'actor') return { kind: 'actor', actor: demoActor };
        return { kind: 'actors', actors: [demoActor] };
      }

      if (resolvedType === 'ip') {
        const result = await fetchActors(sensorId, { ip: term, limit: 25 });
        return { kind: 'actors', actors: result.actors };
      }

      if (resolvedType === 'fingerprint') {
        const result = await fetchActors(sensorId, { fingerprint: term, limit: 25 });
        return { kind: 'actors', actors: result.actors };
      }

      if (resolvedType === 'session') {
        const result = await fetchSessionDetail(sensorId, term);
        return { kind: 'session', session: result.session };
      }

      const result = await fetchActorDetail(sensorId, term);
      return { kind: 'actor', actor: result.actor };
    },
    enabled: !!submitted?.term,
  });

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    const term = query.trim();
    if (!term) return;
    setSubmitted({ term, type: searchType });
  };

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          eyebrow="Signal Horizon"
          title="Global Search"
          description="Search actors, sessions, IPs, and fingerprints across the fleet."
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
            </Stack>
          }
        />

        <Box bg="card" border="subtle" p="lg">
          <form onSubmit={handleSubmit}>
            <Stack direction="row" align="end" gap="md" wrap>
              <Box style={{ flex: 1, minWidth: 220 }}>
                <Input
                  label="Query"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="IP, actor ID, session ID, fingerprint"
                  size="sm"
                  fill
                />
              </Box>
              <Box style={{ width: 160 }}>
                <Select
                  label="Type"
                  value={searchType}
                  onChange={(event) => setSearchType(event.target.value as SearchType)}
                  options={searchTypeOptions}
                  size="sm"
                />
              </Box>
              <Button type="submit" size="md" icon={<Search size={16} aria-hidden="true" />}>
                Search
              </Button>
            </Stack>
          </form>
        </Box>

        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" justify="space-between">
              <Text variant="label" color="secondary" noMargin>Results</Text>
              {submitted?.term && (
                <Text variant="caption" color="secondary" noMargin>
                  Showing {resolvedType} match for “{submitted.term}”
                </Text>
              )}
            </Stack>
          </Box>
          <Box p="none">
            {!submitted && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">Run a search to see results.</Text>
              </Box>
            )}
            {isLoading && (
              <Box p="xl" style={{ textAlign: 'center' }}>
                <Text variant="body" color="secondary">Searching...</Text>
              </Box>
            )}
            {error && (
              <Box p="xl">
                <Alert status="error" title="Search Failed">
                  Verify the ID and try again.
                </Alert>
              </Box>
            )}
            {!isLoading && submitted && data && data.kind === 'actors' && (
              data.actors.length === 0 ? (
                <Box p="xl" style={{ textAlign: 'center' }}>
                  <Text variant="body" color="secondary">No actors matched the query.</Text>
                </Box>
              ) : (
                <Box style={{ overflowX: 'auto' }}>
                  <table className="data-table">
                    <caption className="sr-only">
                      Actor search results with risk and activity details
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
                      {data.actors.map((actor) => (
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
                            <StatusBadge
                              status={actor.isBlocked ? 'error' : 'success'}
                              variant="subtle"
                              size="sm"
                            >
                              {actor.isBlocked ? 'Blocked' : 'Active'}
                            </StatusBadge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Box>
              )
            )}
            {!isLoading && submitted && data && data.kind === 'actor' && (
              <Box p="lg">
                <Stack gap="lg">
                  <Box>
                    <Text variant="label" color="secondary" style={{ marginBottom: '8px' }}>Actor</Text>
                    <Link
                      to={`/actors/${data.actor.actorId}`}
                      className="text-link hover:opacity-80 transition-opacity"
                      style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 500 }}
                    >
                      {data.actor.actorId}
                    </Link>
                  </Box>
                  <Stack direction="row" gap="xl" wrap>
                    <Box>
                      <Text variant="caption" color="secondary">Risk</Text>
                      <Text variant="body" weight="bold" color={data.actor.riskScore > 75 ? 'error' : 'inherit'}>
                        {Math.round(data.actor.riskScore)}
                      </Text>
                    </Box>
                    <Box>
                      <Text variant="caption" color="secondary">Sessions</Text>
                      <Text variant="body" weight="bold">{data.actor.sessionIds.length}</Text>
                    </Box>
                    <Box>
                      <Text variant="caption" color="secondary">IPs</Text>
                      <Text variant="body" weight="bold">{data.actor.ips.length}</Text>
                    </Box>
                    <Box>
                      <Text variant="caption" color="secondary">Status</Text>
                      <StatusBadge
                        status={data.actor.isBlocked ? 'error' : 'success'}
                        variant="subtle"
                        size="sm"
                      >
                        {data.actor.isBlocked ? 'Blocked' : 'Active'}
                      </StatusBadge>
                    </Box>
                  </Stack>
                </Stack>
              </Box>
            )}
            {!isLoading && submitted && data && data.kind === 'session' && (
              <Box p="lg">
                <Stack gap="lg">
                  <Box>
                    <Text variant="label" color="secondary" style={{ marginBottom: '8px' }}>Session</Text>
                    <Link
                      to={`/sessions/${data.session.sessionId}`}
                      className="text-link hover:opacity-80 transition-opacity"
                      style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 500 }}
                    >
                      {data.session.sessionId}
                    </Link>
                  </Box>
                  <Stack direction="row" gap="xl" wrap>
                    <Box>
                      <Text variant="caption" color="secondary">Requests</Text>
                      <Text variant="body" weight="bold">{data.session.requestCount}</Text>
                    </Box>
                    <Box>
                      <Text variant="caption" color="secondary">Status</Text>
                      <Box
                        px="sm"
                        py="xs"
                        style={{
                          width: 'fit-content',
                          border: '1px solid',
                          background: data.session.isSuspicious ? 'var(--ac-orange-dim)' : 'var(--ac-green-dim)',
                          color: data.session.isSuspicious ? 'var(--ac-orange)' : 'var(--ac-green)',
                          borderColor: data.session.isSuspicious ? alpha(colors.orange, 0.3) : alpha(colors.green, 0.3),
                        }}
                      >
                        <Text variant="tag" noMargin>{data.session.isSuspicious ? 'Suspicious' : 'Active'}</Text>
                      </Box>
                    </Box>
                    <Box>
                      <Text variant="caption" color="secondary">Last Activity</Text>
                      <Text variant="body" weight="bold">{new Date(data.session.lastActivity).toLocaleString()}</Text>
                    </Box>
                  </Stack>
                </Stack>
              </Box>
            )}
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}
