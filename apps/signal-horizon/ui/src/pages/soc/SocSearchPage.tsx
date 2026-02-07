import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Search, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { fetchActorDetail, fetchActors, fetchSessionDetail } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import type { SocActor, SocSession } from '../../types/soc';

type SearchType = 'auto' | 'ip' | 'fingerprint' | 'actor' | 'session';

type SearchResult =
  | { kind: 'actors'; actors: SocActor[] }
  | { kind: 'actor'; actor: SocActor }
  | { kind: 'session'; session: SocSession };

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
    <div className="p-6 space-y-6">
      <header className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="text-xs tracking-[0.3em] uppercase text-ink-muted">Signal Horizon</p>
          <h1 className="text-3xl font-light text-ink-primary">Global Search</h1>
          <p className="text-ink-secondary mt-2">Search actors, sessions, IPs, and fingerprints across the fleet.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs text-ink-muted uppercase tracking-[0.18em]">Sensor</label>
          <input
            value={sensorId}
            onChange={(event) => setSensorId(event.target.value)}
            className="px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
            placeholder="synapse-pingora-1"
          />
        </div>
      </header>

      <form onSubmit={handleSubmit} className="card p-4 flex flex-wrap gap-3 items-center">
        <div className="flex-1 min-w-[220px]">
          <label className="text-xs uppercase tracking-[0.2em] text-ink-muted">Query</label>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="IP, actor ID, session ID, fingerprint"
            className="mt-2 w-full px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
          />
        </div>
        <div className="min-w-[160px]">
          <label className="text-xs uppercase tracking-[0.2em] text-ink-muted">Type</label>
          <select
            value={searchType}
            onChange={(event) => setSearchType(event.target.value as SearchType)}
            className="mt-2 w-full px-3 py-2 text-sm border border-border-subtle bg-surface-base text-ink-primary"
          >
            <option value="auto">Auto detect</option>
            <option value="ip">IP</option>
            <option value="fingerprint">Fingerprint</option>
            <option value="actor">Actor</option>
            <option value="session">Session</option>
          </select>
        </div>
        <button type="submit" className="btn-primary h-10 px-4 text-xs flex items-center gap-2">
          <Search className="w-4 h-4" /> Search
        </button>
      </form>

      <section className="card">
        <div className="card-header flex items-center justify-between">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Results</div>
          {submitted?.term && (
            <div className="text-xs text-ink-muted">
              Showing {resolvedType} match for “{submitted.term}”
            </div>
          )}
        </div>
        <div className="card-body">
          {!submitted && <div className="text-ink-muted">Run a search to see results.</div>}
          {isLoading && <div className="text-ink-muted">Searching...</div>}
          {error && (
            <div className="flex items-center gap-2 text-ac-red">
              <AlertTriangle className="w-4 h-4" /> Search failed. Verify the ID and try again.
            </div>
          )}
          {!isLoading && submitted && data && data.kind === 'actors' && (
            data.actors.length === 0 ? (
              <div className="text-ink-muted">No actors matched the query.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="data-table">
                  <caption className="sr-only">Actor search results with risk and activity details</caption>
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
                    {data.actors.map((actor) => (
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
            )
          )}
          {!isLoading && submitted && data && data.kind === 'actor' && (
            <div className="space-y-3">
              <div className="text-sm text-ink-muted uppercase tracking-[0.2em]">Actor</div>
              <Link to={`/actors/${data.actor.actorId}`} className="text-link hover:text-link-hover text-lg font-mono">
                {data.actor.actorId}
              </Link>
              <div className="flex flex-wrap gap-4 text-sm text-ink-secondary">
                <span>Risk {Math.round(data.actor.riskScore)}</span>
                <span>{data.actor.sessionIds.length} sessions</span>
                <span>{data.actor.ips.length} IPs</span>
                <span>{data.actor.isBlocked ? 'Blocked' : 'Active'}</span>
              </div>
            </div>
          )}
          {!isLoading && submitted && data && data.kind === 'session' && (
            <div className="space-y-3">
              <div className="text-sm text-ink-muted uppercase tracking-[0.2em]">Session</div>
              <Link to={`/sessions/${data.session.sessionId}`} className="text-link hover:text-link-hover text-lg font-mono">
                {data.session.sessionId}
              </Link>
              <div className="flex flex-wrap gap-4 text-sm text-ink-secondary">
                <span>{data.session.requestCount} requests</span>
                <span>{data.session.isSuspicious ? 'Suspicious' : 'Active'}</span>
                <span>Last activity {new Date(data.session.lastActivity).toLocaleString()}</span>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
