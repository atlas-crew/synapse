import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Fingerprint, RefreshCw } from 'lucide-react';
import type { FleetFingerprintCandidate } from '../../hooks/useHunt';
import { LoadingSpinner } from '../LoadingStates';
import { SectionHeader } from '@/ui';

type FleetFingerprintMeta = {
  days: number;
  minTenants: number;
  minSensors: number;
  limit: number;
  count: number;
  historical: boolean;
};

interface FleetIntelligencePanelProps {
  historicalEnabled: boolean;
  getFleetFingerprintIntelligence: (params?: {
    days?: number;
    minTenants?: number;
    minSensors?: number;
    limit?: number;
  }) => Promise<{ candidates: FleetFingerprintCandidate[]; meta: FleetFingerprintMeta }>;
  onPivotFingerprint?: (anonFingerprint: string) => void;
}

function shortFp(fp: string): string {
  if (fp.length <= 14) return fp;
  return `${fp.slice(0, 10)}...${fp.slice(-4)}`;
}

export function FleetIntelligencePanel({
  historicalEnabled,
  getFleetFingerprintIntelligence,
  onPivotFingerprint,
}: FleetIntelligencePanelProps) {
  const [days, setDays] = useState(30);
  const [minTenants, setMinTenants] = useState(3);
  const [minSensors, setMinSensors] = useState(5);
  const [limit, setLimit] = useState(100);

  const [rows, setRows] = useState<FleetFingerprintCandidate[]>([]);
  const [meta, setMeta] = useState<FleetFingerprintMeta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadedOnceRef = useRef(false);

  const sorted = useMemo(() => {
    return [...rows].sort((a, b) =>
      (b.tenantsHit - a.tenantsHit) || (b.sensorsHit - a.sensorsHit) || (b.totalSignals - a.totalSignals)
    );
  }, [rows]);

  const refresh = useCallback(async () => {
    if (!historicalEnabled) return;
    setLoading(true);
    setError(null);
    try {
      const r = await getFleetFingerprintIntelligence({ days, minTenants, minSensors, limit });
      setRows(r.candidates);
      setMeta(r.meta);
    } catch (err) {
      setRows([]);
      setMeta(null);
      setError(err instanceof Error ? err.message : 'Failed to load fleet fingerprint intel');
    } finally {
      setLoading(false);
    }
  }, [days, getFleetFingerprintIntelligence, historicalEnabled, limit, minSensors, minTenants]);

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
    <div className="border border-border-subtle bg-surface-card">
      <div className="flex items-start justify-between gap-4 p-4 border-b border-border-subtle">
        <div className="min-w-0">
          <SectionHeader
            title="Fleet Intel: Fingerprints"
            description="Cross-tenant anonymized fingerprints spreading across multiple tenants/sensors (admin-only intelligence)."
            icon={<Fingerprint className="w-4 h-4 text-ac-magenta" />}
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
              Min Tenants
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={2}
                max={10000}
                value={minTenants}
                onChange={(e) => setMinTenants(Number(e.target.value))}
              />
            </label>
            <label className="text-sm text-ink-secondary">
              Min Sensors
              <input
                className="ml-2 w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={2}
                max={10000}
                value={minSensors}
                onChange={(e) => setMinSensors(Number(e.target.value))}
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

            <div className="ml-auto flex items-center gap-2">
              {loading && <LoadingSpinner />}
              {meta && (
                <div className="text-xs text-ink-muted font-mono">
                  historical={String(meta.historical)} count={meta.count}
                </div>
              )}
            </div>
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
                    <th className="text-left font-medium py-2 pr-3">Fingerprint</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Tenants</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Sensors</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Signals</th>
                    <th className="text-left font-medium py-2 pr-3">Last Seen</th>
                    <th className="text-right font-medium py-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((r) => (
                    <tr key={r.anonFingerprint} className="border-b border-border-subtle">
                      <td className="py-2 pr-3 font-mono" title={r.anonFingerprint}>{shortFp(r.anonFingerprint)}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.tenantsHit}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.sensorsHit}</td>
                      <td className="py-2 pr-3 text-right font-mono">{r.totalSignals}</td>
                      <td className="py-2 pr-3 font-mono text-ink-secondary">{new Date(r.lastSeen).toISOString()}</td>
                      <td className="py-2 text-right">
                        <button
                          type="button"
                          onClick={() => onPivotFingerprint?.(r.anonFingerprint)}
                          disabled={!onPivotFingerprint}
                          className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed font-mono"
                          title="Pivot in Hunt query builder"
                        >
                          Pivot
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
