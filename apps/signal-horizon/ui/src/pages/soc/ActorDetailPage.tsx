import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Activity, Shield, Star } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb } from '../../components/ui/Breadcrumb';
import { clsx } from 'clsx';
import { useDemoMode } from '../../stores/demoModeStore';
import { fetchActorDetail, fetchActorTimeline } from '../../hooks/soc/api';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { useSocWatchlist } from '../../hooks/soc/useSocWatchlist';
import type { SocActor, SocActorTimelineEvent } from '../../types/soc';

const demoActor: SocActor = {
  actorId: 'actor-demo-1',
  riskScore: 86,
  ruleMatches: [],
  anomalyCount: 2,
  sessionIds: ['sess-100', 'sess-101'],
  firstSeen: Date.now() - 12 * 3600 * 1000,
  lastSeen: Date.now() - 45 * 60 * 1000,
  ips: ['203.0.113.10', '203.0.113.11'],
  fingerprints: ['fp-demo-1'],
  isBlocked: true,
  blockReason: 'Auto-block threshold',
  blockedSince: Date.now() - 2 * 3600 * 1000,
};

const demoTimeline: SocActorTimelineEvent[] = [
  {
    timestamp: Date.now() - 4 * 3600 * 1000,
    eventType: 'rule_match',
    ruleId: 'sqli-001',
    category: 'sqli',
    riskDelta: 25,
  },
  {
    timestamp: Date.now() - 3 * 3600 * 1000,
    eventType: 'block',
    clientIp: '203.0.113.10',
    method: 'POST',
    path: '/api/login',
    riskScore: 92,
    blockReason: 'High risk',
  },
  {
    timestamp: Date.now() - 2 * 3600 * 1000,
    eventType: 'actor_blocked',
    reason: 'Auto-block',
    riskScore: 86,
  },
];

const eventTone: Record<string, string> = {
  rule_match: 'bg-ac-orange/10 text-ac-orange border-ac-orange/40',
  block: 'bg-ac-red/15 text-ac-red border-ac-red/40',
  actor_blocked: 'bg-ac-red/15 text-ac-red border-ac-red/40',
  session_bind: 'bg-ac-blue/10 text-ac-blue border-ac-blue/40',
  session_alert: 'bg-ac-purple/10 text-ac-purple border-ac-purple/40',
};

export default function ActorDetailPage() {
  useDocumentTitle('SOC - Actor Detail');
  const { id } = useParams();
  const { sensorId } = useSocSensor();
  const { isEnabled: isDemoMode } = useDemoMode();
  const { isWatched, toggleWatch } = useSocWatchlist();

  const { data: actorResponse, isLoading: actorLoading } = useQuery({
    queryKey: ['soc', 'actor', sensorId, id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return { actor: demoActor };
      if (!id) throw new Error('Missing actor ID');
      return fetchActorDetail(sensorId, id);
    },
    enabled: !!id,
  });

  const { data: timelineResponse } = useQuery({
    queryKey: ['soc', 'actor-timeline', sensorId, id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return { actorId: demoActor.actorId, events: demoTimeline };
      if (!id) throw new Error('Missing actor ID');
      return fetchActorTimeline(sensorId, id, 120);
    },
    enabled: !!id,
  });

  const actor = actorResponse?.actor;
  const timeline = timelineResponse?.events ?? [];
  const watched = actor ? isWatched(actor.actorId) : false;

  const summaryStats = useMemo(() => {
    if (!actor) return [];
    return [
      { label: 'Risk Score', value: Math.round(actor.riskScore) },
      { label: 'Sessions', value: actor.sessionIds.length },
      { label: 'IPs', value: actor.ips.length },
      { label: 'Fingerprints', value: actor.fingerprints.length },
    ];
  }, [actor]);

  if (actorLoading && !actor) {
    return <div className="p-6 text-ink-muted">Loading actor...</div>;
  }

  if (!actor) {
    return (
      <div className="p-6">
        <div className="card p-6 text-center">
          <AlertTriangle className="w-8 h-8 text-ink-muted mx-auto mb-3" />
          <p className="text-ink-secondary">Actor not found.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Breadcrumb items={[
        { label: 'Actors', to: '/actors' },
        { label: actor.actorId },
      ]} />
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <Link to="/actors" className="text-sm text-link hover:text-link-hover">Back to Actors</Link>
          <h1 className="text-3xl font-light text-ink-primary mt-2">{actor.actorId}</h1>
          <p className="text-ink-secondary mt-1">First seen {new Date(actor.firstSeen).toLocaleString()}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            className="btn-outline h-10 px-4 text-xs"
            onClick={() => toggleWatch(actor.actorId)}
          >
            <Star className={clsx('w-4 h-4 mr-2', watched && 'text-ac-orange')} />
            {watched ? 'Remove Watch' : 'Add to Watchlist'}
          </button>
          <span
            className={clsx(
              'px-2 py-1 text-xs border',
              actor.isBlocked
                ? 'bg-ac-red/15 text-ac-red border-ac-red/40'
                : 'bg-ac-green/10 text-ac-green border-ac-green/40'
            )}
          >
            {actor.isBlocked ? 'Blocked' : 'Active'}
          </span>
        </div>
      </header>

      <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryStats.map((stat) => (
          <div key={stat.label} className="card p-4">
            <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">{stat.label}</p>
            <p className="text-2xl font-light text-ink-primary mt-2">{stat.value}</p>
          </div>
        ))}
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="card p-4">
          <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">Associated IPs</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {actor.ips.map((ip) => (
              <span key={ip} className="px-2 py-1 text-xs border border-border-subtle bg-surface-subtle text-ink-secondary font-mono">
                {ip}
              </span>
            ))}
          </div>
        </div>
        <div className="card p-4">
          <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">Fingerprints</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {actor.fingerprints.map((fp) => (
              <span key={fp} className="px-2 py-1 text-xs border border-border-subtle bg-surface-subtle text-ink-secondary font-mono">
                {fp}
              </span>
            ))}
          </div>
        </div>
        <div className="card p-4">
          <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">Sessions</p>
          <div className="mt-3 space-y-2">
            {actor.sessionIds.map((sessionId) => (
              <Link key={sessionId} to={`/sessions/${sessionId}`} className="block text-sm text-link hover:text-link-hover font-mono">
                {sessionId}
              </Link>
            ))}
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-header flex items-center justify-between">
          <div className="text-sm uppercase tracking-[0.2em] text-ink-muted">Timeline</div>
          <div className="text-xs text-ink-muted">{timeline.length} events</div>
        </div>
        <div className="card-body space-y-3">
          {timeline.length === 0 && (
            <div className="text-ink-muted">No timeline events yet.</div>
          )}
          {timeline.map((event, index) => (
            <div key={`${event.eventType}-${index}`} className="flex gap-3">
              <div className={clsx('px-2 py-1 text-xs border h-fit', eventTone[event.eventType] || 'border-border-subtle text-ink-muted')}>
                {event.eventType.replace('_', ' ')}
              </div>
              <div className="flex-1">
                <div className="text-sm text-ink-primary">
                  {event.ruleId && `Rule ${event.ruleId}`} {event.path && `${event.method} ${event.path}`}
                  {event.sessionId && `Session ${event.sessionId}`}
                </div>
                <div className="text-xs text-ink-muted">
                  {new Date(event.timestamp).toLocaleString()}
                  {event.riskDelta ? ` · +${event.riskDelta}` : ''}
                  {event.riskScore ? ` · Risk ${event.riskScore}` : ''}
                </div>
                {event.blockReason && (
                  <div className="text-xs text-ink-secondary mt-1">{event.blockReason}</div>
                )}
              </div>
              {event.confidence && (
                <div className="text-xs text-ink-muted">{Math.round(event.confidence * 100)}%</div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Activity className="w-4 h-4" /> Activity Summary
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            Last seen {new Date(actor.lastSeen).toLocaleString()}. {actor.isBlocked ? 'Actor is currently blocked.' : 'Actor is being monitored.'}
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-sm text-ink-muted uppercase tracking-[0.2em]">
            <Shield className="w-4 h-4" /> Response Notes
          </div>
          <div className="mt-3 text-ink-secondary text-sm">
            {actor.blockReason ? `Block reason: ${actor.blockReason}` : 'No automated block action recorded.'}
          </div>
        </div>
      </section>
    </div>
  );
}
