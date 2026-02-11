/**
 * Campaign Timeline Pivot Page
 * Correlates ClickHouse rows by campaign_id across campaign_history.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Clipboard, RefreshCw } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useHunt, type CampaignTimelineEvent } from '../../hooks/useHunt';
import { formatIsoOrInvalid } from '../../utils';
import { Alert, Button, CARD_HEADER_TITLE_STYLE, Input, SectionHeader, spacing } from '@/ui';

function formatConfidenceOrNa(confidence: unknown): string {
  if (typeof confidence !== 'number') return 'n/a';
  if (!Number.isFinite(confidence)) return 'n/a';
  if (confidence < 0 || confidence > 1) return 'n/a';
  return confidence.toFixed(2);
}

export default function CampaignTimelinePage() {
  useDocumentTitle('Campaign Timeline');

  const { campaignId: routeCampaignId } = useParams();
  const navigate = useNavigate();
  const { isLoading, error, clearError, getCampaignTimeline } = useHunt();

  const [campaignId, setCampaignId] = useState(routeCampaignId ?? '');
  const [events, setEvents] = useState<CampaignTimelineEvent[] | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const runSeqRef = useRef(0);
  const skipAutoRunIdRef = useRef<string | null>(null);
  const submitInFlightRef = useRef(false);
  const lastAutoRunIdRef = useRef<string | null>(null);

  // Optional time window (ISO strings expected by API).
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');

  const canRun = campaignId.trim().length > 0 && !isLoading;

  // One-way sync from route param into the input field.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (routeCampaignId && routeCampaignId !== campaignId) {
      setCampaignId(routeCampaignId);
    }
  }, [routeCampaignId]);

  const run = useCallback(
    async (id: string) => {
      const seq = ++runSeqRef.current;
      clearError();
      setLocalError(null);
      try {
        const res = await getCampaignTimeline(id, {
          startTime: startTime.trim() || undefined,
          endTime: endTime.trim() || undefined,
        });
        if (seq !== runSeqRef.current) return;
        setEvents(res.events);
      } catch (err) {
        if (seq !== runSeqRef.current) return;
        setEvents(null);
        setLocalError(err instanceof Error ? err.message : 'Campaign timeline query failed');
      }
    },
    [clearError, endTime, getCampaignTimeline, startTime],
  );

  // Auto-run when deep-linked.
  useEffect(() => {
    if (routeCampaignId) {
      if (skipAutoRunIdRef.current === routeCampaignId) {
        skipAutoRunIdRef.current = null;
        lastAutoRunIdRef.current = routeCampaignId;
        return;
      }
      if (lastAutoRunIdRef.current === routeCampaignId) return;
      lastAutoRunIdRef.current = routeCampaignId;
      void run(routeCampaignId);
    }
  }, [routeCampaignId, run]);

  const header = useMemo(() => {
    const id = campaignId.trim();
    return id.length > 0 ? id : '(enter campaign id)';
  }, [campaignId]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const id = campaignId.trim();
    if (!id) return;
    if (isLoading) return;
    if (submitInFlightRef.current) return;
    submitInFlightRef.current = true;
    skipAutoRunIdRef.current = id;
    navigate(`/hunting/campaign/${encodeURIComponent(id)}`);
    try {
      await run(id);
    } finally {
      submitInFlightRef.current = false;
    }
  };

  const handleCopy = async () => {
    const id = campaignId.trim();
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
        title="Campaign Timeline"
        description="Pivot ClickHouse telemetry by campaign_id."
        size="h3"
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>
            <Button
              type="button"
              variant="outlined"
              size="sm"
              onClick={handleCopy}
              disabled={!campaignId.trim()}
              aria-label="Copy campaign id"
              title="Copy campaign id"
              icon={<Clipboard aria-hidden="true" className="w-4 h-4" />}
            >
              Copy
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={() => campaignId.trim() && void run(campaignId.trim())}
              disabled={!campaignId.trim() || isLoading}
              aria-label="Refresh"
              title="Refresh"
              icon={
                <RefreshCw
                  aria-hidden="true"
                  className={isLoading ? 'w-4 h-4 animate-spin' : 'w-4 h-4'}
                />
              }
            >
              Refresh
            </Button>
          </div>
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
        <div className="card-header">
          <SectionHeader
            title="Query"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
          <p className="text-xs text-ink-muted mt-1">
            Campaign: <span className="font-mono">{header}</span>
          </p>
        </div>

        <div className="card-body">
          <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <div className="md:col-span-4">
              <Input
                id="campaign-id"
                label="campaign_id"
                value={campaignId}
                onChange={(e) => setCampaignId(e.target.value)}
                placeholder="campaign-123"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="md:col-span-3">
              <Input
                id="start-time"
                label="startTime (optional)"
                value={startTime}
                onChange={(e) => setStartTime(e.target.value)}
                placeholder="2026-02-09T00:00:00.000Z"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="md:col-span-3">
              <Input
                id="end-time"
                label="endTime (optional)"
                value={endTime}
                onChange={(e) => setEndTime(e.target.value)}
                placeholder="2026-02-09T12:00:00.000Z"
                size="sm"
                style={{ fontFamily: 'monospace' }}
              />
            </div>

            <div className="md:col-span-2 flex items-end">
              <Button type="submit" disabled={!canRun} size="sm" fill>
                Run
              </Button>
            </div>
          </form>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <SectionHeader
            title="Timeline"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
          <p className="text-xs text-ink-muted mt-1">
            {events ? (
              <span className="font-mono">count={events.length}</span>
            ) : (
              <span className="font-mono">count=?</span>
            )}
          </p>
        </div>

        <div className="card-body">
          {!events && (
            <div className="text-sm text-ink-secondary">
              {isLoading ? 'Loading…' : 'Run a query to load campaign history.'}
            </div>
          )}

          {events && events.length === 0 && (
            <div className="text-sm text-ink-secondary">No events found.</div>
          )}

          {events && events.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left font-medium py-2 pr-3">Timestamp</th>
                    <th className="text-left font-medium py-2 pr-3">Type</th>
                    <th className="text-left font-medium py-2 pr-3">Name</th>
                    <th className="text-left font-medium py-2 pr-3">Status</th>
                    <th className="text-left font-medium py-2 pr-3">Severity</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Tenants</th>
                    <th className="text-right font-medium py-2 font-mono">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e, idx) => (
                    <tr key={`${e.timestamp}-${idx}`} className="border-b border-border-subtle">
                      <td className="py-2 pr-3 font-mono text-ink-secondary whitespace-nowrap">
                        {formatIsoOrInvalid(e.timestamp)}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">{e.eventType}</td>
                      <td className="py-2 pr-3">{e.name}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{e.status}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{e.severity}</td>
                      <td className="py-2 pr-3 text-right font-mono">{e.tenantsAffected}</td>
                      <td className="py-2 text-right font-mono">
                        {formatConfidenceOrNa(e.confidence)}
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
