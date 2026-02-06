/**
 * Request Timeline Pivot Page
 * Correlates ClickHouse rows by request_id across http_transactions/signal_events/sensor_logs.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Clipboard, RefreshCw } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useHunt, type RequestTimelineEvent } from '../../hooks/useHunt';

function summarizeEvent(e: RequestTimelineEvent): string {
  switch (e.kind) {
    case 'http_transaction':
      return `${e.method} ${e.path} status=${e.statusCode} latency=${Math.round(e.latencyMs)}ms waf=${e.wafAction ?? '-'}`;
    case 'signal_event':
      return `${e.signalType} severity=${e.severity} ip=${e.sourceIp} count=${e.eventCount}`;
    case 'sensor_log':
      return `[${e.level}] ${e.source}: ${e.message}`;
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

  const { isLoading, error, clearError, getRequestTimeline } = useHunt();
  const [requestId, setRequestId] = useState(routeRequestId ?? '');
  const [events, setEvents] = useState<RequestTimelineEvent[] | null>(null);

  // Optional time window (ISO strings expected by API).
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [limit, setLimit] = useState<number>(500);
  const [localError, setLocalError] = useState<string | null>(null);

  const canRun = requestId.trim().length > 0 && !isLoading;

  useEffect(() => {
    if (routeRequestId && routeRequestId !== requestId) {
      setRequestId(routeRequestId);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [routeRequestId]);

  const run = useCallback(async (id: string) => {
    clearError();
    setLocalError(null);
    try {
      const res = await getRequestTimeline(id, {
        startTime: startTime.trim() || undefined,
        endTime: endTime.trim() || undefined,
        limit,
      });
      setEvents(res.events);
    } catch (err) {
      setEvents(null);
      setLocalError(err instanceof Error ? err.message : 'Request timeline query failed');
    }
  }, [clearError, endTime, getRequestTimeline, limit, startTime]);

  // Auto-run when deep-linked.
  useEffect(() => {
    if (routeRequestId) {
      void run(routeRequestId);
    }
  }, [routeRequestId, run]);

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
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Request Timeline</h1>
          <p className="text-ink-secondary mt-1">
            Pivot ClickHouse telemetry by <span className="font-mono">request_id</span>.
            <span className="ml-2 text-ink-muted">
              <Link className="text-link hover:text-link-hover" to="/hunting">Back to hunting</Link>
            </span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopy}
            className="btn-outline h-10 px-3 text-sm inline-flex items-center gap-2"
            disabled={!requestId.trim()}
            aria-label="Copy request id"
            title="Copy request id"
          >
            <Clipboard className="w-4 h-4" />
            Copy
          </button>
          <button
            type="button"
            onClick={() => requestId.trim() && void run(requestId.trim())}
            className="btn-primary h-10 px-3 text-sm inline-flex items-center gap-2"
            disabled={!requestId.trim() || isLoading}
            aria-label="Refresh"
            title="Refresh"
          >
            <RefreshCw className={isLoading ? 'w-4 h-4 animate-spin' : 'w-4 h-4'} />
            Refresh
          </button>
        </div>
      </div>

      {(error || localError) && (
        <div className="p-4 bg-ac-red/10 border border-ac-red/30 text-ac-red flex items-center justify-between gap-4">
          <span className="text-sm">{localError ?? error}</span>
          <button onClick={() => { clearError(); setLocalError(null); }} className="text-sm hover:text-ac-red/80">
            Dismiss
          </button>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2 className="font-medium text-ink-primary">Lookup</h2>
        </div>
        <div className="card-body">
          <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-end">
            <div className="lg:col-span-6">
              <label htmlFor="request-id" className="block text-sm font-medium text-ink-secondary mb-1">
                request_id
              </label>
              <input
                id="request-id"
                value={requestId}
                onChange={(e) => setRequestId(e.target.value)}
                placeholder="req_abc123"
                className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue font-mono"
              />
            </div>

            <div className="lg:col-span-2">
              <label htmlFor="start-time" className="block text-sm font-medium text-ink-secondary mb-1">
                startTime (ISO)
              </label>
              <input
                id="start-time"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                placeholder="2026-02-06T12:00:00Z"
                className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue font-mono text-xs"
              />
            </div>

            <div className="lg:col-span-2">
              <label htmlFor="end-time" className="block text-sm font-medium text-ink-secondary mb-1">
                endTime (ISO)
              </label>
              <input
                id="end-time"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                placeholder="2026-02-06T13:00:00Z"
                className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary placeholder-ink-muted focus:outline-none focus:border-ac-blue font-mono text-xs"
              />
            </div>

            <div className="lg:col-span-1">
              <label htmlFor="limit" className="block text-sm font-medium text-ink-secondary mb-1">
                limit
              </label>
              <input
                id="limit"
                type="number"
                min={1}
                max={5000}
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
                className="w-full bg-surface-inset border border-border-subtle px-3 py-2 text-ink-primary focus:outline-none focus:border-ac-blue font-mono"
              />
            </div>

            <div className="lg:col-span-1 flex gap-2">
              <button
                type="submit"
                className="btn-primary h-10 px-4 text-sm w-full"
                disabled={!canRun}
              >
                Run
              </button>
            </div>
          </form>
        </div>
      </div>

      <div className="card">
        <div className="card-header flex items-center justify-between gap-4">
          <div className="min-w-0">
            <h2 className="font-medium text-ink-primary truncate">Timeline</h2>
            <p className="text-xs text-ink-muted mt-1 font-mono truncate">{header}</p>
          </div>
          <div className="text-xs text-ink-muted font-mono">
            {events ? `${events.length} events` : 'no data'}
          </div>
        </div>
        <div className="card-body">
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
            <div className="overflow-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Request timeline events correlated by request id</caption>
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
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
