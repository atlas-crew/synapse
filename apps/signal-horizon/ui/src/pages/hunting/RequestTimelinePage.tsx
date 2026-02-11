/**
 * Request Timeline Pivot Page
 * Correlates ClickHouse rows by request_id across http_transactions/signal_events/sensor_logs/actor_events/session_events.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Clipboard, RefreshCw } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useHunt, type RecentRequest, type RequestTimelineEvent } from '../../hooks/useHunt';
import RequestTimelineGraph from '../../components/hunting/RequestTimelineGraph';
import {
  Alert,
  Button,
  CARD_HEADER_TITLE_STYLE,
  Input,
  SectionHeader,
  Spinner,
  Stack,
  Tabs,
  TRUNCATED_CARD_HEADER_TITLE_STYLE,
} from '@/ui';

function summarizeEvent(e: RequestTimelineEvent): string {
  switch (e.kind) {
    case 'http_transaction':
      return `${e.method} ${e.path} status=${e.statusCode} latency=${Math.round(e.latencyMs)}ms waf=${e.wafAction ?? '-'}`;
    case 'signal_event':
      return `${e.signalType} severity=${e.severity} ip=${e.sourceIp} count=${e.eventCount}`;
    case 'sensor_log':
      return `[${e.level}] ${e.source}: ${e.message}`;
    case 'actor_event':
      return `${e.eventType} actor=${e.actorId} risk=${e.riskScore} (${e.riskDelta >= 0 ? '+' : ''}${e.riskDelta}) ip=${e.ip}`;
    case 'session_event':
      return `${e.eventType} session=${e.sessionId} actor=${e.actorId} requests=${e.requestCount}`;
    default:
      return 'unknown';
  }
}

function jsonDetails(label: string, value: unknown) {
  if (value === null || value === undefined) return null;
  const str = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  if (!str || str.trim().length === 0) return null;

  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-link hover:text-link-hover">{label}</summary>
      <pre className="mt-2 whitespace-pre-wrap bg-surface-inset border border-border-subtle p-3 overflow-auto text-ink-secondary">
        {str}
      </pre>
    </details>
  );
}

export default function RequestTimelinePage() {
  useDocumentTitle('Request Timeline');

  const { requestId: routeRequestId } = useParams();
  const navigate = useNavigate();

  const { isLoading, error, clearError, getRequestTimeline, getRecentRequests } = useHunt();
  const [requestId, setRequestId] = useState(routeRequestId ?? '');
  const [events, setEvents] = useState<RequestTimelineEvent[] | null>(null);
  const [recent, setRecent] = useState<RecentRequest[] | null>(null);
  const [recentError, setRecentError] = useState<string | null>(null);

  // Optional time window (ISO strings expected by API).
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [limit, setLimit] = useState<number>(500);
  const [localError, setLocalError] = useState<string | null>(null);
  const [view, setView] = useState<'graph' | 'table'>('graph');
  const [timelineNote, setTimelineNote] = useState<string | null>(null);

  const canRun = requestId.trim().length > 0 && !isLoading;

  const loadRecent = useCallback(async () => {
    setRecentError(null);
    try {
      const data = await getRecentRequests(25);
      setRecent(data);
    } catch (err) {
      setRecent([]);
      setRecentError(err instanceof Error ? err.message : 'Failed to load recent request ids');
    }
  }, [getRecentRequests]);

  useEffect(() => {
    if (routeRequestId && routeRequestId !== requestId) {
      setRequestId(routeRequestId);
    }
  }, [routeRequestId]);

  const run = useCallback(
    async (id: string) => {
      clearError();
      setLocalError(null);
      setTimelineNote(null);
      try {
        const res = await getRequestTimeline(id, {
          startTime: startTime.trim() || undefined,
          endTime: endTime.trim() || undefined,
          limit,
        });
        setEvents(res.events);
        if (res.events.length >= Math.max(1, limit)) {
          setTimelineNote(
            'Results may be truncated. Reduce limit or narrow the time window for full fidelity.',
          );
        }
      } catch (err) {
        setEvents(null);
        setLocalError(err instanceof Error ? err.message : 'Request timeline query failed');
      }
    },
    [clearError, endTime, getRequestTimeline, limit, startTime],
  );

  // Auto-run when deep-linked.
  useEffect(() => {
    if (routeRequestId) {
      void run(routeRequestId);
    }
  }, [routeRequestId, run]);

  useEffect(() => {
    void loadRecent();
  }, [loadRecent]);

  const header = useMemo(() => {
    const id = requestId.trim();
    return id.length > 0 ? id : '(enter request id)';
  }, [requestId]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const id = requestId.trim();
    if (!id) return;
    navigate(`/hunting/request/${encodeURIComponent(id)}`);
    await run(id);
  };

  const handleCopy = async () => {
    const id = requestId.trim();
    if (!id) return;
    try {
      await navigator.clipboard.writeText(id);
    } catch {
      // ignore
    }
  };

  return (
    <div className="p-6 space-y-6">
      <SectionHeader
        title="Request Timeline"
        description="Pivot ClickHouse telemetry by request_id."
        size="h3"
        actions={
          <Stack direction="row" align="center" gap="sm">
            <Button
              type="button"
              variant="outlined"
              size="sm"
              onClick={handleCopy}
              disabled={!requestId.trim()}
              aria-label="Copy request id"
              title="Copy request id"
              icon={<Clipboard aria-hidden="true" className="w-4 h-4" />}
            >
              Copy
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={() => requestId.trim() && void run(requestId.trim())}
              disabled={!requestId.trim() || isLoading}
              aria-label="Refresh"
              title="Refresh"
              icon={
                isLoading ? (
                  <Spinner size={16} color="#0057B7" />
                ) : (
                  <RefreshCw aria-hidden="true" className="w-4 h-4" />
                )
              }
            >
              Refresh
            </Button>
          </Stack>
        }
      />
      <div className="text-ink-secondary -mt-3">
        <Link className="text-link hover:text-link-hover" to="/hunting">
          Back to hunting
        </Link>
      </div>

      {(error || localError) && (
        <Alert
          status="error"
          dismissible
          onDismiss={() => {
            clearError();
            setLocalError(null);
          }}
        >
          {localError ?? error}
        </Alert>
      )}

      <div className="card">
        <div className="card-header flex items-center justify-between gap-4">
          <div className="min-w-0">
            <SectionHeader
              title="Recent"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={TRUNCATED_CARD_HEADER_TITLE_STYLE}
            />
            <p className="text-xs text-ink-muted mt-1">
              Latest <span className="font-mono">request_id</span> values (ClickHouse).
            </p>
          </div>
          <Button
            type="button"
            variant="outlined"
            size="sm"
            onClick={() => void loadRecent()}
            aria-label="Refresh recent request ids"
            title="Refresh recent"
            icon={<RefreshCw aria-hidden="true" className="w-4 h-4" />}
          >
            Refresh
          </Button>
        </div>
        <div className="card-body">
          {recentError && <Alert status="error">{recentError}</Alert>}

          {!recent && <div className="text-sm text-ink-secondary">Loading…</div>}

          {recent && recent.length === 0 && !recentError && (
            <div className="text-sm text-ink-secondary">No recent request ids yet.</div>
          )}

          {recent && recent.length > 0 && (
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Recent request ids</caption>
                <thead className="text-xs text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left py-2 pr-3">Time</th>
                    <th className="text-left py-2 pr-3">request_id</th>
                    <th className="text-left py-2 pr-3">Path</th>
                    <th className="text-left py-2 pr-3">Status</th>
                    <th className="text-left py-2 pr-3">WAF</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {recent.map((r) => (
                    <tr key={r.requestId} className="align-top">
                      <td className="py-2 pr-3 whitespace-nowrap font-mono text-xs text-ink-secondary">
                        {new Date(r.lastSeenAt).toLocaleString()}
                      </td>
                      <td className="py-2 pr-3 whitespace-nowrap">
                        <button
                          type="button"
                          onClick={() =>
                            navigate(`/hunting/request/${encodeURIComponent(r.requestId)}`)
                          }
                          className="text-link hover:text-link-hover font-mono text-xs"
                          title="Open timeline"
                        >
                          {r.requestId}
                        </button>
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs text-ink-primary">{r.path}</td>
                      <td className="py-2 pr-3 whitespace-nowrap font-mono text-xs text-ink-primary">
                        {r.statusCode}
                      </td>
                      <td className="py-2 pr-3 whitespace-nowrap font-mono text-xs text-ink-primary">
                        {r.wafAction ?? '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <SectionHeader
            title="Lookup"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
        </div>
        <div className="card-body">
          <form
            onSubmit={handleSubmit}
            className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-end"
          >
            <div className="lg:col-span-6">
              <Input
                id="request-id"
                label="request_id"
                value={requestId}
                onChange={(e) => setRequestId(e.target.value)}
                placeholder="req_abc123"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="lg:col-span-2">
              <Input
                id="start-time"
                label="startTime (ISO)"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                placeholder="2026-02-06T12:00:00Z"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="lg:col-span-2">
              <Input
                id="end-time"
                label="endTime (ISO)"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                placeholder="2026-02-06T13:00:00Z"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="lg:col-span-1">
              <Input
                id="limit"
                label="limit"
                type="number"
                min={1}
                max={5000}
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="lg:col-span-1 flex gap-2">
              <Button type="submit" size="sm" fill disabled={!canRun}>
                Run
              </Button>
            </div>
          </form>
        </div>
      </div>

      <div className="card">
        <div className="card-header flex items-center justify-between gap-4">
          <div className="min-w-0">
            <SectionHeader
              title="Timeline"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={TRUNCATED_CARD_HEADER_TITLE_STYLE}
            />
            <p className="text-xs text-ink-muted mt-1 font-mono truncate">{header}</p>
          </div>
          <div className="flex items-center gap-3">
            <Tabs
              tabs={[
                { key: 'graph', label: 'Graph' },
                { key: 'table', label: 'Table' },
              ]}
              active={view}
              onChange={(key) => setView(key as 'graph' | 'table')}
              variant="pills"
              size="sm"
            />
            <div className="text-xs text-ink-muted font-mono whitespace-nowrap">
              {events ? `${events.length} events` : 'no data'}
            </div>
          </div>
        </div>
        <div className="card-body">
          {timelineNote && <Alert status="warning">{timelineNote}</Alert>}

          {!events && (
            <div className="text-sm text-ink-secondary">
              Enter a <span className="font-mono">request_id</span> and run.
            </div>
          )}

          {events && events.length === 0 && (
            <div className="text-sm text-ink-secondary">
              No matching rows in ClickHouse for this request_id and time window.
            </div>
          )}

          {events && events.length > 0 && (
            <>
              {view === 'graph' && <RequestTimelineGraph events={events} />}

              {view === 'table' && (
                <div className="overflow-auto">
                  <table className="w-full text-sm">
                    <caption className="sr-only">
                      Request timeline events correlated by request id
                    </caption>
                    <thead className="text-xs text-ink-muted border-b border-border-subtle">
                      <tr>
                        <th className="text-left py-2 pr-3">Time</th>
                        <th className="text-left py-2 pr-3">Kind</th>
                        <th className="text-left py-2 pr-3">Summary</th>
                        <th className="text-left py-2 pr-3">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-subtle">
                      {events.map((e, idx) => (
                        <tr key={`${e.kind}-${e.timestamp}-${idx}`} className="align-top">
                          <td className="py-2 pr-3 whitespace-nowrap font-mono text-xs text-ink-secondary">
                            {new Date(e.timestamp).toLocaleString()}
                          </td>
                          <td className="py-2 pr-3 whitespace-nowrap">
                            <span className="px-2 py-1 border border-border-subtle bg-surface-inset text-xs font-mono">
                              {e.kind}
                            </span>
                          </td>
                          <td className="py-2 pr-3 text-ink-primary">
                            <span className="font-mono text-xs">{summarizeEvent(e)}</span>
                          </td>
                          <td className="py-2 pr-3">
                            {e.kind === 'signal_event' && jsonDetails('metadata', e.metadata)}
                            {e.kind === 'sensor_log' && jsonDetails('fields', e.fields)}
                            {e.kind === 'actor_event' &&
                              jsonDetails('actor', {
                                actorId: e.actorId,
                                ruleId: e.ruleId,
                                ruleCategory: e.ruleCategory,
                              })}
                            {e.kind === 'session_event' &&
                              jsonDetails('session', {
                                sessionId: e.sessionId,
                                actorId: e.actorId,
                              })}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
