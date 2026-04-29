import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Activity, Clock, Shield, Star } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import {
  Breadcrumb,
  Button,
  EmptyState,
  SectionHeader,
  Stack,
  StatusBadge,
  Box,
  Text,
  Grid,
  spacing,
  PAGE_TITLE_STYLE,
} from '@/ui';
import { CopyButton } from '../../components/ui/CopyButton';
import { useDemoMode } from '../../stores/demoModeStore';
import {
  fetchFleetActorDetail,
  fetchFleetActorTimeline,
} from '../../hooks/soc/api';
import { useSocWatchlist } from '../../hooks/soc/useSocWatchlist';
import type {
  SocFleetActor,
  SocFleetActorDetailResponse,
  SocFleetActorTimelineResponse,
  SocFleetTimelineEvent,
} from '../../types/soc';

const demoActor: SocFleetActor = {
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
  seenOnSensors: ['sensor-1', 'sensor-2'],
};

const demoTimeline: SocFleetTimelineEvent[] = [
  {
    sensorId: 'sensor-1',
    timestamp: Date.now() - 4 * 3600 * 1000,
    eventType: 'rule_match',
    ruleId: 'sqli-001',
    category: 'sqli',
    riskDelta: 25,
  },
  {
    sensorId: 'sensor-2',
    timestamp: Date.now() - 3 * 3600 * 1000,
    eventType: 'block',
    clientIp: '203.0.113.10',
    method: 'POST',
    path: '/api/login',
    riskScore: 92,
    blockReason: 'High risk',
  },
  {
    sensorId: 'sensor-1',
    timestamp: Date.now() - 2 * 3600 * 1000,
    eventType: 'actor_blocked',
    reason: 'Auto-block',
    riskScore: 86,
  },
];

const eventStyles: Record<string, { bg: string; color: string; border: string }> = {
  rule_match: {
    bg: 'var(--ac-orange-dim)',
    color: 'var(--ac-orange)',
    border: 'rgba(229, 168, 32, 0.3)',
  },
  block: {
    bg: 'var(--ac-red-dim)',
    color: 'var(--ac-red)',
    border: 'rgba(239, 68, 68, 0.3)',
  },
  actor_blocked: {
    bg: 'var(--ac-red-dim)',
    color: 'var(--ac-red)',
    border: 'rgba(239, 68, 68, 0.3)',
  },
  session_bind: {
    bg: 'var(--ac-blue-dim)',
    color: 'var(--ac-blue)',
    border: 'rgba(56, 160, 255, 0.3)',
  },
  session_alert: {
    bg: 'var(--ac-magenta-dim)',
    color: 'var(--ac-magenta)',
    border: 'rgba(217, 70, 168, 0.3)',
  },
};

function formatRelativeMinutes(iso: string, nowMs: number): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return 'unknown';
  const ageMin = Math.max(1, Math.round((nowMs - then) / 60_000));
  return `${ageMin} min ago`;
}

function buildDemoDetail(): SocFleetActorDetailResponse {
  return {
    aggregate: demoActor,
    results: [
      { sensorId: 'sensor-1', status: 'ok' },
      { sensorId: 'sensor-2', status: 'ok' },
    ],
    summary: { succeeded: 2, stale: 0, failed: 0 },
  };
}

function buildDemoTimeline(): SocFleetActorTimelineResponse {
  return {
    aggregate: { actorId: demoActor.actorId, events: demoTimeline },
    results: [
      { sensorId: 'sensor-1', status: 'ok' },
      { sensorId: 'sensor-2', status: 'ok' },
    ],
    summary: { succeeded: 2, stale: 0, failed: 0 },
  };
}

export default function ActorDetailPage() {
  useDocumentTitle('SOC - Actor Detail');
  const { id } = useParams();
  const { isEnabled: isDemoMode } = useDemoMode();
  const { isWatched, toggleWatch } = useSocWatchlist();

  const { data: actorResponse, isLoading: actorLoading } = useQuery({
    queryKey: ['soc', 'fleet-actor', id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return buildDemoDetail();
      if (!id) throw new Error('Missing actor ID');
      return fetchFleetActorDetail(id);
    },
    enabled: !!id,
  });

  const { data: timelineResponse } = useQuery({
    queryKey: ['soc', 'fleet-actor-timeline', id, isDemoMode],
    queryFn: async () => {
      if (isDemoMode) return buildDemoTimeline();
      if (!id) throw new Error('Missing actor ID');
      return fetchFleetActorTimeline(id, 120);
    },
    enabled: !!id,
  });

  const actor = actorResponse?.aggregate;
  const detailSummary = actorResponse?.summary;
  const detailResults = actorResponse?.results ?? [];
  const timeline = timelineResponse?.aggregate.events ?? [];
  const watched = actor ? isWatched(actor.actorId) : false;
  const nowMs = Date.now();

  const oldestStaleEntry = useMemo(() => {
    return detailResults
      .filter((r) => r.status === 'stale' && r.lastUpdatedAt)
      .sort((a, b) => Date.parse(a.lastUpdatedAt!) - Date.parse(b.lastUpdatedAt!))[0];
  }, [detailResults]);

  const summaryStats = useMemo(() => {
    if (!actor) return [];
    return [
      { label: 'Risk Score', value: Math.round(actor.riskScore), color: actor.riskScore > 75 ? 'var(--ac-red)' : 'var(--text)' },
      { label: 'Sessions', value: actor.sessionIds.length },
      { label: 'IPs', value: actor.ips.length },
      { label: 'Fingerprints', value: actor.fingerprints.length },
    ];
  }, [actor]);

  if (actorLoading && !actor) {
    return (
      <Box p="xl" style={{ textAlign: 'center' }}>
        <Text variant="body" color="secondary">Loading actor...</Text>
      </Box>
    );
  }

  if (!actor) {
    return (
      <EmptyState
        icon={<AlertTriangle aria-hidden="true" />}
        title="Actor Not Found"
        description="The requested actor could not be found."
      />
    );
  }

  const sensorCount = actor.seenOnSensors.length;
  const sensorLabel = `${sensorCount} ${sensorCount === 1 ? 'sensor' : 'sensors'}`;

  return (
    <Box p="xl">
      <Stack gap="xl">
        <Breadcrumb items={[{ label: 'Actors', to: '/actors' }, { label: actor.actorId }]} />

        {/* Header */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
          <Stack gap="md">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => window.history.back()}
              icon={<span aria-hidden="true">←</span>}
              style={{ width: 'fit-content' }}
            >
              Back to Actors
            </Button>
            <SectionHeader
              title={actor.actorId}
              description={`First seen ${new Date(actor.firstSeen).toLocaleString()}`}
              size="h2"
              titleStyle={PAGE_TITLE_STYLE}
              actions={
                <Stack direction="row" align="center" gap="md" wrap>
                  <Button
                    variant="outlined"
                    size="sm"
                    onClick={() => toggleWatch(actor.actorId)}
                    icon={
                      <Star
                        aria-hidden="true"
                        size={16}
                        style={{ color: watched ? 'var(--ac-orange)' : 'inherit' }}
                      />
                    }
                  >
                    {watched ? 'Remove Watch' : 'Add to Watchlist'}
                  </Button>
                  <StatusBadge status="info" variant="subtle" size="sm">
                    {sensorLabel}
                  </StatusBadge>
                  {detailSummary && detailSummary.stale > 0 && oldestStaleEntry?.lastUpdatedAt && (
                    <StatusBadge status="warning" variant="subtle" size="sm">
                      <Stack direction="row" align="center" gap="xs">
                        <Clock size={10} aria-hidden="true" />
                        <span>Stale data — {formatRelativeMinutes(oldestStaleEntry.lastUpdatedAt, nowMs)}</span>
                      </Stack>
                    </StatusBadge>
                  )}
                  <StatusBadge
                    status={actor.isBlocked ? 'error' : 'success'}
                    variant="subtle"
                    size="sm"
                  >
                    {actor.isBlocked ? 'Blocked' : 'Active'}
                  </StatusBadge>
                </Stack>
              }
            />
            <Stack direction="row" align="center" gap="md">
              <Text variant="small" color="secondary" noMargin>Actor ID</Text>
              <Text variant="code" noMargin>{actor.actorId}</Text>
              <CopyButton value={actor.actorId} />
            </Stack>
          </Stack>
        </Box>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {summaryStats.map((stat) => (
            <Box key={stat.label} bg="card" border="subtle" p="lg">
              <Text variant="label" color="secondary" noMargin>{stat.label}</Text>
              <Text variant="h2" weight="light" noMargin style={{ marginTop: '8px', color: stat.color }}>
                {stat.value}
              </Text>
            </Box>
          ))}
        </div>

        {/* Details Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Box bg="card" border="subtle" p="lg">
            <Text variant="label" color="secondary" noMargin style={{ marginBottom: '16px' }}>Associated IPs</Text>
            <Stack direction="row" gap="sm" wrap>
              {actor.ips.map((ip) => (
                <Box
                  key={ip}
                  px="sm"
                  py="xs"
                  bg="surface-inset"
                  border="subtle"
                >
                  <Text variant="code" noMargin>{ip}</Text>
                </Box>
              ))}
            </Stack>
          </Box>
          <Box bg="card" border="subtle" p="lg">
            <Text variant="label" color="secondary" noMargin style={{ marginBottom: '16px' }}>Fingerprints</Text>
            <Stack direction="row" gap="sm" wrap>
              {actor.fingerprints.map((fp) => (
                <Box
                  key={fp}
                  px="sm"
                  py="xs"
                  bg="surface-inset"
                  border="subtle"
                >
                  <Text variant="code" noMargin>{fp}</Text>
                </Box>
              ))}
            </Stack>
          </Box>
          <Box bg="card" border="subtle" p="lg">
            <Text variant="label" color="secondary" noMargin style={{ marginBottom: '16px' }}>Sessions</Text>
            <Stack gap="sm">
              {actor.sessionIds.map((sessionId) => (
                <Link
                  key={sessionId}
                  to={`/sessions/${sessionId}`}
                  className="text-link hover:opacity-80 transition-opacity"
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '13px' }}
                >
                  {sessionId}
                </Link>
              ))}
            </Stack>
          </Box>
        </div>

        {/* Timeline */}
        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <Stack direction="row" align="center" justify="space-between">
              <Text variant="label" color="secondary" noMargin>Timeline</Text>
              <Text variant="caption" color="secondary" noMargin>{timeline.length} events</Text>
            </Stack>
          </Box>
          <Box p="lg">
            <Stack gap="lg">
              {timeline.length === 0 && (
                <Text variant="body" color="secondary" align="center">No timeline events yet.</Text>
              )}
              {timeline.map((event, index) => {
                const style = eventStyles[event.eventType] || {
                  bg: 'var(--bg-surface-inset)',
                  color: 'var(--text-muted)',
                  border: 'var(--border-subtle)'
                };
                return (
                  <Stack key={`${event.eventType}-${index}`} direction="row" gap="lg" align="start">
                    <Box
                      px="sm"
                      py="xs"
                      style={{
                        width: 'fit-content',
                        border: '1px solid',
                        background: style.bg,
                        color: style.color,
                        borderColor: style.border,
                        flexShrink: 0,
                      }}
                    >
                      <Text variant="tag" noMargin>{event.eventType.replace('_', ' ')}</Text>
                    </Box>
                    <Box style={{ flex: 1 }}>
                      <Text variant="body" weight="medium" noMargin>
                        {event.ruleId && `Rule ${event.ruleId}`}
                        {event.path && `${event.method} ${event.path}`}
                        {event.sessionId && `Session ${event.sessionId}`}
                      </Text>
                      <Text variant="caption" color="secondary" noMargin>
                        {new Date(event.timestamp).toLocaleString()}
                        {event.riskDelta ? ` · +${event.riskDelta}` : ''}
                        {event.riskScore ? ` · Risk ${event.riskScore}` : ''}
                        {' · '}
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{event.sensorId}</span>
                      </Text>
                      {event.blockReason && (
                        <Text variant="small" color="secondary" style={{ marginTop: '4px' }}>
                          {event.blockReason}
                        </Text>
                      )}
                    </Box>
                    {event.confidence && (
                      <Text variant="caption" color="secondary" noMargin>
                        {Math.round(event.confidence * 100)}%
                      </Text>
                    )}
                  </Stack>
                );
              })}
            </Stack>
          </Box>
        </Box>

        {/* Guidance Panels */}
        <Grid cols={2} gap="xl">
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Activity size={18} className="text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Activity Summary</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                Last seen {new Date(actor.lastSeen).toLocaleString()}.{' '}
                {actor.isBlocked ? 'Actor is currently blocked.' : 'Actor is being monitored.'}
              </Text>
            </Box>
          </Box>
          <Box bg="card" border="subtle" p="lg">
            <Stack direction="row" align="center" gap="md">
              <Shield size={18} className="text-ink-muted" />
              <Text variant="label" color="secondary" noMargin>Response Notes</Text>
            </Stack>
            <Box style={{ marginTop: spacing.md }}>
              <Text variant="body" color="secondary">
                {actor.blockReason
                  ? `Block reason: ${actor.blockReason}`
                  : 'No automated block action recorded.'}
              </Text>
            </Box>
          </Box>
        </Grid>
      </Stack>
    </Box>
  );
}
