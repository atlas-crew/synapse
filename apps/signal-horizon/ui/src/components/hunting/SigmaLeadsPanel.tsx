import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileSearch, RefreshCw } from 'lucide-react';
import type { SigmaLead } from '../../hooks/useHunt';
import { LoadingSpinner } from '../LoadingStates';
import { Panel, SectionHeader, Stack } from '@/ui';

interface SigmaLeadsPanelProps {
  historicalEnabled: boolean;
  getSigmaLeads: (limit?: number) => Promise<SigmaLead[]>;
  ackSigmaLead: (id: string) => Promise<SigmaLead>;
  onPivotExample?: (q: string) => void;
}

export function SigmaLeadsPanel({
  historicalEnabled,
  getSigmaLeads,
  ackSigmaLead,
  onPivotExample,
}: SigmaLeadsPanelProps) {
  const [limit, setLimit] = useState(200);
  const [rows, setRows] = useState<SigmaLead[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedOnceRef = useRef(false);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
  }, [rows]);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getSigmaLeads(limit);
      setRows(data);
    } catch (err) {
      setRows([]);
      setError(err instanceof Error ? err.message : 'Failed to load sigma leads');
    } finally {
      setLoading(false);
    }
  }, [getSigmaLeads, historicalEnabled, limit]);

  useEffect(() => {
    if (!historicalEnabled) {
      setRows([]);
      setError(null);
      loadedOnceRef.current = false;
      return;
    }
    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    refresh();
  }, [historicalEnabled, refresh]);

  const handleAck = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const updated = await ackSigmaLead(id);
      setRows((prev) => prev.map((r) => (r.id === id ? updated : r)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to ack lead');
    } finally {
      setLoading(false);
    }
  };

  const pivot = (lead: SigmaLead) => {
    if (!onPivotExample) return;
    if (lead.pivot.anonFingerprint) {
      onPivotExample(`fingerprint:\"${lead.pivot.anonFingerprint}\"`);
      return;
    }
    if (lead.pivot.sourceIp) {
      onPivotExample(`ip:${lead.pivot.sourceIp}`);
    }
  };

  return (
    <Panel tone="default" padding="none" spacing="none" as="div">
      <Stack
        direction="row"
        align="flex-start"
        justify="space-between"
        gap="md"
        className="p-4 border-b border-border-subtle"
      >
        <div className="min-w-0">
          <SectionHeader
            title="Sigma Leads"
            description="Background hunting results from saved Sigma rules (ClickHouse)."
            icon={<FileSearch className="w-4 h-4 text-ac-blue" />}
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{ fontSize: '18px', lineHeight: '24px' }}
          />
        </div>

        <button
          type="button"
          onClick={() => refresh()}
          disabled={!historicalEnabled || loading}
          className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
          title="Refresh"
        >
          <Stack direction="row" align="center" gap="sm">
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </Stack>
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
                max={1000}
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
              />
            </label>
            <button
              type="button"
              onClick={() => refresh()}
              disabled={loading}
              className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Apply
            </button>

            <Stack direction="row" align="center" gap="sm" className="ml-auto">
              {loading && <LoadingSpinner />}
              <div className="text-xs text-ink-muted font-mono">
                count={sorted.length}
              </div>
            </Stack>
          </div>

          {error && (
            <div className="p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
              {error}
            </div>
          )}

          {!loading && !error && sorted.length === 0 && (
            <div className="text-sm text-ink-secondary">
              No leads. Save a rule via "Import Sigma Rule" then "Save Background Hunt".
            </div>
          )}

          {sorted.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left font-medium py-2 pr-3">Rule</th>
                    <th className="text-left font-medium py-2 pr-3">Last Seen</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Matches</th>
                    <th className="text-left font-medium py-2 pr-3">Pivot</th>
                    <th className="text-left font-medium py-2 pr-3">Status</th>
                    <th className="text-right font-medium py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => (
                    <tr key={r.id} className="border-b border-border-subtle">
                      <td className="py-2 pr-3">{r.ruleName}</td>
                      <td className="py-2 pr-3 font-mono text-ink-secondary">{new Date(r.lastSeenAt).toISOString()}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.matchCount}</td>
                      <td className="py-2 pr-3 font-mono text-xs text-ink-secondary">
                        {r.pivot.requestId
                          ? `req:${r.pivot.requestId.slice(0, 12)}...`
                          : (r.pivot.anonFingerprint
                            ? `fp:${r.pivot.anonFingerprint.slice(0, 10)}...`
                            : (r.pivot.sourceIp ?? ''))}
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {r.status}
                      </td>
                      <td className="py-2 text-right whitespace-nowrap">
                        {r.pivot.requestId && (
                          <Link
                            to={`/hunting/request/${encodeURIComponent(r.pivot.requestId)}`}
                            className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary font-mono mr-2 inline-block"
                            title="Open request timeline"
                          >
                            Request
                          </Link>
                        )}
                        <button
                          type="button"
                          onClick={() => pivot(r)}
                          disabled={!onPivotExample}
                          className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed font-mono mr-2"
                        >
                          Pivot
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAck(r.id)}
                          disabled={loading || r.status === 'ACKED'}
                          className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed font-mono"
                        >
                          Ack
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
    </Panel>
  );
}
