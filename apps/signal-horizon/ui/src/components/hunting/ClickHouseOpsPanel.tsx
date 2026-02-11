import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Gauge, RefreshCw, Settings2 } from 'lucide-react';
import type { ClickHouseOpsSnapshot } from '../../hooks/useHunt';
import { LoadingSpinner } from '../LoadingStates';
import { byOpGauge, formatMs, histogramSumCountByOp, queueDepthByOp } from './clickhouseOpsMetrics';
import { SectionHeader } from '@/ui';

interface ClickHouseOpsPanelProps {
  historicalEnabled: boolean;
  getClickHouseOpsSnapshot: () => Promise<ClickHouseOpsSnapshot>;
}

export function ClickHouseOpsPanel({ historicalEnabled, getClickHouseOpsSnapshot }: ClickHouseOpsPanelProps) {
  const [data, setData] = useState<ClickHouseOpsSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedOnceRef = useRef(false);
  const requestSeqRef = useRef(0);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    const seq = ++requestSeqRef.current;
    setLoading(true);
    setError(null);
    try {
      const snapshot = await getClickHouseOpsSnapshot();
      if (seq !== requestSeqRef.current) return;
      setData(snapshot);
    } catch (err) {
      if (seq !== requestSeqRef.current) return;
      setData(null);
      setError(err instanceof Error ? err.message : 'Failed to load ClickHouse ops snapshot');
    } finally {
      if (seq === requestSeqRef.current) setLoading(false);
    }
  }, [getClickHouseOpsSnapshot, historicalEnabled]);

  useEffect(() => {
    if (!historicalEnabled) {
      setData(null);
      setError(null);
      loadedOnceRef.current = false;
      return;
    }
    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    void refresh();
  }, [historicalEnabled, refresh]);

  // Poll lightly so the panel is actually useful without manual refresh spam.
  useEffect(() => {
    const id = setInterval(() => {
      if (typeof document !== 'undefined' && document.hidden) return;
      void refresh();
    }, 30000);
    return () => clearInterval(id);
  }, [refresh]);

  const derived = useMemo(() => {
    const queueDepth = queueDepthByOp(data?.metrics?.clickhouseQueryQueueDepth);
    const inflight = byOpGauge(data?.metrics?.clickhouseQueriesInFlight);
    const errors = byOpGauge(data?.metrics?.clickhouseQueryErrors);
    const wait = histogramSumCountByOp(data?.metrics?.clickhouseQueryWaitDuration);
    const duration = histogramSumCountByOp(data?.metrics?.clickhouseQueryDuration);

    const ops = Array.from(
      new Set([
        ...Object.keys(queueDepth),
        ...Object.keys(inflight),
        ...Object.keys(errors),
        ...Object.keys(wait),
        ...Object.keys(duration),
      ])
    ).sort();

    const rows = ops.map((op) => {
      const q = queueDepth[op] ?? { query: 0, stream: 0 };
      const infl = inflight[op] ?? 0;
      const err = errors[op] ?? 0;
      const waitAvgMs =
        wait[op] && wait[op].count > 0 ? (wait[op].sum / wait[op].count) * 1000 : null;
      const durAvgMs =
        duration[op] && duration[op].count > 0 ? (duration[op].sum / duration[op].count) * 1000 : null;
      return {
        op,
        inflight: infl,
        queueQuery: q.query,
        queueStream: q.stream,
        errors: err,
        waitAvgMs,
        durAvgMs,
      };
    });

    return { rows };
  }, [data]);

  return (
    <div className="border border-border-subtle bg-surface-card">
      <div className="flex items-start justify-between gap-4 p-4 border-b border-border-subtle">
        <div className="min-w-0">
          <SectionHeader
            title="ClickHouse Ops"
            description="Backpressure, in-flight, error, and latency telemetry for historical analytics queries."
            icon={<Gauge className="w-4 h-4 text-ac-magenta" />}
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
      </div>

      {!historicalEnabled && (
        <div className="p-4 text-sm text-ink-secondary">
          Historical analytics unavailable (ClickHouse disabled).
        </div>
      )}

      {historicalEnabled && (
        <div className="p-4 space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            {loading && <LoadingSpinner />}
            {data && (
              <div className="text-xs text-ink-muted font-mono">
                sampledAt={data.sampledAt} enabled={String(data.clickhouse.enabled)} connected={String(data.clickhouse.connected)}
              </div>
            )}
          </div>

          {error && (
            <div role="alert" className="p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
              {error}
            </div>
          )}

          {data?.clickhouse.config && (
            <div className="border border-border-subtle bg-surface-base">
              <div className="flex items-center gap-2 px-3 py-2 border-b border-border-subtle">
                <Settings2 className="w-4 h-4 text-ink-muted" />
                <div className="text-sm text-ink-secondary">Runtime limits</div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 text-xs font-mono text-ink-secondary">
                <div>maxOpenConnections={data.clickhouse.config.maxOpenConnections}</div>
                <div>maxInFlightQueries={data.clickhouse.config.maxInFlightQueries}</div>
                <div>maxInFlightStreamQueries={data.clickhouse.config.maxInFlightStreamQueries}</div>
                <div>queryTimeoutSec={data.clickhouse.config.queryTimeoutSec}</div>
                <div>queueTimeoutSec={data.clickhouse.config.queueTimeoutSec}</div>
                <div>maxRowsLimit={data.clickhouse.config.maxRowsLimit}</div>
              </div>
            </div>
          )}

          {!loading && !error && derived.rows.length === 0 && (
            <div role="status" className="text-sm text-ink-secondary">
              No ClickHouse ops metrics yet.
            </div>
          )}

          {derived.rows.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm" aria-label="ClickHouse ops metrics">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th scope="col" className="text-left font-medium py-2 pr-3">op</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">inFlight</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">queue(query)</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">queue(stream)</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">errors</th>
                    <th scope="col" className="text-right font-medium py-2 pr-3 font-mono">wait(avg)</th>
                    <th scope="col" className="text-right font-medium py-2 font-mono">dur(avg)</th>
                  </tr>
                </thead>
                <tbody>
                  {derived.rows.map((r) => (
                    <tr key={r.op} className="border-b border-border-subtle">
                      <td className="py-2 pr-3 font-mono text-xs text-ink-secondary">{r.op}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.inflight}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.queueQuery}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.queueStream}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.errors}</td>
                      <td className="py-2 pr-3 text-right font-mono">{formatMs(r.waitAvgMs)}</td>
                      <td className="py-2 text-right font-mono">{formatMs(r.durAvgMs)}</td>
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
