import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import type { LowAndSlowIpCandidate } from '../../hooks/useHunt';
import { LoadingSpinner } from '../LoadingStates';
import { Panel, SectionHeader, Stack } from '@/ui';

type LowAndSlowMeta = {
  days: number;
  minDistinctDays: number;
  maxSignalsPerDay: number;
  limit: number;
  count: number;
  historical: boolean;
};

interface LowAndSlowPanelProps {
  historicalEnabled: boolean;
  getLowAndSlowIps: (params?: {
    days?: number;
    minDistinctDays?: number;
    maxSignalsPerDay?: number;
    limit?: number;
  }) => Promise<{ candidates: LowAndSlowIpCandidate[]; meta: LowAndSlowMeta }>;
}

export function LowAndSlowPanel({ historicalEnabled, getLowAndSlowIps }: LowAndSlowPanelProps) {
  const [days, setDays] = useState(90);
  const [minDistinctDays, setMinDistinctDays] = useState(5);
  const [maxSignalsPerDay, setMaxSignalsPerDay] = useState(10);
  const [limit, setLimit] = useState(100);

  const [rows, setRows] = useState<LowAndSlowIpCandidate[]>([]);
  const [meta, setMeta] = useState<LowAndSlowMeta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadedOnceRef = useRef(false);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) => (b.daysSeen - a.daysSeen) || (b.totalSignals - a.totalSignals));
  }, [rows]);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    setLoading(true);
    setError(null);
    try {
      const r = await getLowAndSlowIps({ days, minDistinctDays, maxSignalsPerDay, limit });
      setRows(r.candidates);
      setMeta(r.meta);
    } catch (err) {
      setRows([]);
      setMeta(null);
      setError(err instanceof Error ? err.message : 'Failed to load low-and-slow');
    } finally {
      setLoading(false);
    }
  }, [days, getLowAndSlowIps, historicalEnabled, limit, maxSignalsPerDay, minDistinctDays]);

  useEffect(() => {
    if (!historicalEnabled) {
      setRows([]);
      setMeta(null);
      setError(null);
      loadedOnceRef.current = false;
      return;
    }

    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    refresh();
  }, [historicalEnabled, refresh]);

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
            title="Low And Slow"
            description="Cross-tenant IPs with long dwell time but low daily volume (admin-only intelligence)."
            icon={<Activity className="w-4 h-4 text-ac-blue" />}
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
              Window (days)
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={1}
                max={365}
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
              />
            </label>
            <label className="text-sm text-ink-secondary">
              Min Days
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={2}
                max={365}
                value={minDistinctDays}
                onChange={(e) => setMinDistinctDays(Number(e.target.value))}
              />
            </label>
            <label className="text-sm text-ink-secondary">
              Max/Day
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={1}
                max={100000}
                value={maxSignalsPerDay}
                onChange={(e) => setMaxSignalsPerDay(Number(e.target.value))}
              />
            </label>
            <label className="text-sm text-ink-secondary">
              Limit
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
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
              {meta && (
                <div className="text-xs text-ink-muted font-mono">
                  historical={String(meta.historical)} count={meta.count}
                </div>
              )}
            </Stack>
          </div>

          {error && (
            <div className="p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
              {error}
            </div>
          )}

          {!loading && !error && sorted.length === 0 && (
            <div className="text-sm text-ink-secondary">
              No candidates.
            </div>
          )}

          {sorted.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left font-medium py-2 pr-3">IP</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Days</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Max/Day</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Total</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Tenants</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => (
                    <tr key={r.sourceIp} className="border-b border-border-subtle">
                      <td className="py-2 pr-3 font-mono">{r.sourceIp}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.daysSeen}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.maxDailySignals}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.totalSignals}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.tenantsHit}</td>
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
