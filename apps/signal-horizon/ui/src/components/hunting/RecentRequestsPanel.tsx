import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Clipboard, Clock, RefreshCw } from 'lucide-react';
import type { RecentRequest } from '../../hooks/useHunt';
import { formatIsoOrInvalid } from '../../utils';
import { LoadingSpinner } from '../LoadingStates';
import { Alert, SectionHeader, Stack } from '@/ui';

interface RecentRequestsPanelProps {
  historicalEnabled: boolean;
  getRecentRequests: (limit?: number) => Promise<RecentRequest[]>;
}

export function RecentRequestsPanel({ historicalEnabled, getRecentRequests }: RecentRequestsPanelProps) {
  const [limit, setLimit] = useState(50);
  const [rows, setRows] = useState<RecentRequest[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedOnceRef = useRef(false);
  const requestSeqRef = useRef(0);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
  }, [rows]);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    const seq = ++requestSeqRef.current;
    setLoading(true);
    setError(null);
    try {
      const data = await getRecentRequests(limit);
      if (seq !== requestSeqRef.current) return;
      setRows(data);
    } catch (err) {
      if (seq !== requestSeqRef.current) return;
      setRows([]);
      setError(err instanceof Error ? err.message : 'Failed to load recent requests');
    } finally {
      if (seq === requestSeqRef.current) {
        setLoading(false);
      }
    }
  }, [getRecentRequests, historicalEnabled, limit]);

  useEffect(() => {
    if (!historicalEnabled) {
      setRows([]);
      setError(null);
      loadedOnceRef.current = false;
      return;
    }
    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    void refresh();
  }, [historicalEnabled, refresh]);

  const handleCopy = async (requestId: string) => {
    try {
      await navigator.clipboard.writeText(requestId);
    } catch {
      // ignore
    }
  };

  return (
    <div className="border border-border-subtle bg-surface-card">
      <Stack
        direction="row"
        align="flex-start"
        justify="space-between"
        gap="md"
        className="p-4 border-b border-border-subtle"
      >
        <div className="min-w-0">
          <SectionHeader
            title="Recent Requests"
            description="Latest request_id values (HTTP transactions) for quick pivot into the timeline view."
            icon={<Clock className="w-4 h-4 text-ac-blue" />}
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{ fontSize: '18px', lineHeight: '24px' }}
          />
        </div>

        <button
          type="button"
          onClick={() => void refresh()}
          disabled={!historicalEnabled || loading}
          className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-2"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </Stack>

      {!historicalEnabled && (
        <div className="p-4 text-sm text-ink-secondary">
          Historical analytics unavailable (ClickHouse disabled).
        </div>
      )}

      {historicalEnabled && (
        <div className="p-4 space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-ink-secondary">
              Limit
              <input
                className="ml-2 w-24 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={1}
                max={200}
                value={limit}
                onChange={(e) => {
                  const raw = e.target.value;
                  const next = raw.trim() === '' ? Number.NaN : Number(raw);
                  // HTML min/max is advisory; clamp so API never sees NaN/0/out-of-range.
                  const bounded = Number.isFinite(next) ? Math.max(1, Math.min(200, next)) : 50;
                  setLimit(bounded);
                }}
              />
            </label>

            <button
              type="button"
              onClick={() => void refresh()}
              disabled={loading}
              className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Apply
            </button>

            <div className="ml-auto flex items-center gap-2">
              {loading && <LoadingSpinner />}
              <div className="text-xs text-ink-muted font-mono">count={sorted.length}</div>
            </div>
          </div>

          {error && (
            <Alert status="error" title="Load Error" style={{ padding: '12px 16px' }}>
              {error}
            </Alert>
          )}

          {!loading && !error && sorted.length === 0 && (
            <div role="status" className="text-sm text-ink-secondary">
              No recent requests.
            </div>
          )}

          {sorted.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm" aria-label="Recent HTTP requests">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th scope="col" className="text-left font-medium py-2 pr-3">Last Seen</th>
                    <th scope="col" className="text-left font-medium py-2 pr-3">Sensor</th>
                    <th scope="col" className="text-left font-medium py-2 pr-3">Path</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">Status</th>
                    <th scope="col" className="text-left font-medium py-2 pr-3">WAF</th>
                    <th scope="col" className="text-left font-medium py-2 pr-3">Request</th>
                    <th scope="col" className="text-right font-medium py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => (
                    <tr key={r.requestId} className="border-b border-border-subtle">
                      <td className="py-2 pr-3 font-mono text-ink-secondary whitespace-nowrap">
                        {formatIsoOrInvalid(r.lastSeenAt)}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">{r.sensorId}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-ink-secondary">{r.path}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.statusCode}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{r.wafAction ?? ''}</td>
                      <td className="py-2 pr-3 font-mono text-xs">{r.requestId}</td>
                      <td className="py-2 text-right whitespace-nowrap">
                        <Link
                          to={`/hunting/request/${encodeURIComponent(r.requestId)}`}
                          aria-label={`Open request timeline for ${r.requestId}`}
                          className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary font-mono mr-2 inline-block"
                          title="Open request timeline"
                        >
                          Open
                        </Link>
                        <button
                          type="button"
                          onClick={() => void handleCopy(r.requestId)}
                          className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary font-mono inline-flex items-center gap-2"
                          title="Copy request id"
                          aria-label={`Copy request id ${r.requestId}`}
                        >
                          <Clipboard className="w-3 h-3" />
                          Copy
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
