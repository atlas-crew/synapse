import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, RefreshCw, SlidersHorizontal } from 'lucide-react';
import type { TenantAnomaly, TenantBaseline } from '../../hooks/useHunt';
import { LoadingSpinner } from '../LoadingStates';
import { SectionHeader, Stack } from '@/ui';

type BaselinesMeta = {
  tenantId: string;
  lookbackDays: number;
  count: number;
  historical: boolean;
};

type AnomaliesMeta = {
  tenantId: string;
  zScoreThreshold: number;
  count: number;
  historical: boolean;
};

interface BehavioralAnomaliesPanelProps {
  historicalEnabled: boolean;
  getTenantBaselines: (days?: number) => Promise<{ baselines: TenantBaseline[]; meta: BaselinesMeta }>;
  getAnomalies: (zScore?: number) => Promise<{ anomalies: TenantAnomaly[]; meta: AnomaliesMeta }>;
}

function severityDot(sev: TenantAnomaly['severity']): string {
  switch (sev) {
    case 'HIGH':
      return 'bg-ac-red';
    case 'MEDIUM':
      return 'bg-ac-orange';
    case 'LOW':
      return 'bg-ac-blue';
  }
}

export function BehavioralAnomaliesPanel({
  historicalEnabled,
  getTenantBaselines,
  getAnomalies,
}: BehavioralAnomaliesPanelProps) {
  const [zScore, setZScore] = useState(2.0);
  const [days, setDays] = useState(30);

  const [anomalies, setAnomalies] = useState<TenantAnomaly[]>([]);
  const [anomaliesMeta, setAnomaliesMeta] = useState<AnomaliesMeta | null>(null);
  const [anomaliesLoading, setAnomaliesLoading] = useState(false);
  const [anomaliesError, setAnomaliesError] = useState<string | null>(null);

  const [baselines, setBaselines] = useState<TenantBaseline[]>([]);
  const [baselinesMeta, setBaselinesMeta] = useState<BaselinesMeta | null>(null);
  const [baselinesLoading, setBaselinesLoading] = useState(false);
  const [baselinesError, setBaselinesError] = useState<string | null>(null);
  const [showBaselines, setShowBaselines] = useState(false);

  const loadedOnceRef = useRef(false);

  const sortedAnomalies = useMemo(() => {
    return [...anomalies].sort((a, b) => b.deviation - a.deviation);
  }, [anomalies]);

  const refreshAnomalies = useCallback(async () => {
    if (!historicalEnabled) return;
    setAnomaliesLoading(true);
    setAnomaliesError(null);
    try {
      const r = await getAnomalies(zScore);
      setAnomalies(r.anomalies);
      setAnomaliesMeta(r.meta);
    } catch (err) {
      setAnomalies([]);
      setAnomaliesMeta(null);
      setAnomaliesError(err instanceof Error ? err.message : 'Failed to load anomalies');
    } finally {
      setAnomaliesLoading(false);
    }
  }, [getAnomalies, historicalEnabled, zScore]);

  const refreshBaselines = useCallback(async () => {
    if (!historicalEnabled) return;
    setBaselinesLoading(true);
    setBaselinesError(null);
    try {
      const r = await getTenantBaselines(days);
      setBaselines(r.baselines);
      setBaselinesMeta(r.meta);
    } catch (err) {
      setBaselines([]);
      setBaselinesMeta(null);
      setBaselinesError(err instanceof Error ? err.message : 'Failed to load baselines');
    } finally {
      setBaselinesLoading(false);
    }
  }, [days, getTenantBaselines, historicalEnabled]);

  useEffect(() => {
    if (!historicalEnabled) {
      setAnomalies([]);
      setAnomaliesMeta(null);
      setAnomaliesError(null);
      setBaselines([]);
      setBaselinesMeta(null);
      setBaselinesError(null);
      loadedOnceRef.current = false;
      return;
    }

    if (loadedOnceRef.current) return;
    loadedOnceRef.current = true;
    refreshAnomalies();
  }, [historicalEnabled, refreshAnomalies]);

  useEffect(() => {
    if (!showBaselines) return;
    if (baselinesMeta) return;
    refreshBaselines();
  }, [baselinesMeta, refreshBaselines, showBaselines]);

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
            title="Behavioral Anomalies"
            description="Compare the last complete hour to a 30d baseline (per signal type)."
            icon={<AlertTriangle className="w-4 h-4 text-ac-orange" />}
            size="h4"
            mb="xs"
            style={{ marginBottom: 0 }}
            titleStyle={{ fontSize: '18px', lineHeight: '24px' }}
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => refreshAnomalies()}
            disabled={!historicalEnabled || anomaliesLoading}
            className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center gap-2"
            title="Refresh"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
        </div>
      </Stack>

      {!historicalEnabled && (
        <div className="p-4 text-sm text-ink-secondary">
          Historical analytics unavailable (ClickHouse disabled).
        </div>
      )}

      {historicalEnabled && (
        <div className="p-4 space-y-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-ink-muted" />
              <span className="text-xs uppercase tracking-wider text-ink-muted">Threshold</span>
            </div>
            <label className="text-sm text-ink-secondary">
              Z-Score
              <input
                className="ml-2 w-24 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono"
                type="number"
                min={0.1}
                max={10}
                step={0.1}
                value={zScore}
                onChange={(e) => setZScore(Number(e.target.value))}
              />
            </label>
            <button
              type="button"
              onClick={() => refreshAnomalies()}
              disabled={anomaliesLoading}
              className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Apply
            </button>

            <div className="ml-auto flex items-center gap-2">
              {anomaliesLoading && <LoadingSpinner />}
              {anomaliesMeta && (
                <div className="text-xs text-ink-muted font-mono">
                  historical={String(anomaliesMeta.historical)} count={anomaliesMeta.count}
                </div>
              )}
            </div>
          </div>

          {anomaliesError && (
            <div className="p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
              {anomaliesError}
            </div>
          )}

          {!anomaliesLoading && !anomaliesError && sortedAnomalies.length === 0 && (
            <div className="text-sm text-ink-secondary">
              No anomalies above threshold.
            </div>
          )}

          {sortedAnomalies.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-ink-muted border-b border-border-subtle">
                  <tr>
                    <th className="text-left font-medium py-2 pr-3">Severity</th>
                    <th className="text-left font-medium py-2 pr-3">Signal Type</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Current</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Avg</th>
                    <th className="text-right font-medium py-2 pr-3 font-mono">Z</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedAnomalies.map((a) => (
                    <tr key={a.signalType} className="border-b border-border-subtle">
                      <td className="py-2 pr-3">
                        <span className="inline-flex items-center gap-2">
                          <span className={`w-2 h-2 ${severityDot(a.severity)}`} />
                          <span className="font-mono text-xs">{a.severity}</span>
                        </span>
                      </td>
                      <td className="py-2 pr-3 font-mono">{a.signalType}</td>
                      <td className="py-2 pr-3 text-right font-mono">{a.currentCount}</td>
                      <td className="py-2 pr-3 text-right font-mono">{a.expectedAvg.toFixed(2)}</td>
                      <td className="py-2 pr-3 text-right font-mono">{a.deviation.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <div className="pt-2 border-t border-border-subtle">
            <Stack direction="row" align="center" justify="space-between" style={{ gap: '12px' }}>
              <button
                type="button"
                onClick={() => setShowBaselines((v) => !v)}
                className="text-sm text-link hover:text-link-hover"
              >
                {showBaselines ? 'Hide baselines' : 'Show baselines'}
              </button>

              <div className="flex items-center gap-2">
                <span className="text-xs text-ink-muted">Lookback (days)</span>
                <input
                  className="w-20 px-2 py-1 border border-border-subtle bg-surface-base text-ink-primary font-mono text-sm"
                  type="number"
                  min={1}
                  max={90}
                  step={1}
                  value={days}
                  onChange={(e) => setDays(Number(e.target.value))}
                  disabled={!showBaselines}
                />
                <button
                  type="button"
                  onClick={() => refreshBaselines()}
                  disabled={!showBaselines || baselinesLoading}
                  className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-ink-secondary hover:text-ink-primary disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Load
                </button>
                {baselinesLoading && <LoadingSpinner />}
                {baselinesMeta && showBaselines && (
                  <div className="text-xs text-ink-muted font-mono">
                    count={baselinesMeta.count}
                  </div>
                )}
              </div>
            </Stack>

            {showBaselines && baselinesError && (
              <div className="mt-3 p-3 bg-ac-red/10 border border-ac-red/30 text-ac-red text-sm">
                {baselinesError}
              </div>
            )}

            {showBaselines && !baselinesLoading && !baselinesError && baselines.length === 0 && (
              <div className="mt-3 text-sm text-ink-secondary">
                No baselines returned.
              </div>
            )}

            {showBaselines && baselines.length > 0 && (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-ink-muted border-b border-border-subtle">
                    <tr>
                      <th className="text-left font-medium py-2 pr-3">Signal Type</th>
                      <th className="text-right font-medium py-2 pr-3 font-mono">Avg</th>
                      <th className="text-right font-medium py-2 pr-3 font-mono">StdDev</th>
                      <th className="text-right font-medium py-2 pr-3 font-mono">Max</th>
                      <th className="text-right font-medium py-2 pr-3 font-mono">N</th>
                    </tr>
                  </thead>
                  <tbody>
                    {baselines
                      .slice()
                      .sort((a, b) => b.avgHourlyCount - a.avgHourlyCount)
                      .map((b) => (
                        <tr key={b.signalType} className="border-b border-border-subtle">
                          <td className="py-2 pr-3 font-mono">{b.signalType}</td>
                          <td className="py-2 pr-3 text-right font-mono">{b.avgHourlyCount.toFixed(2)}</td>
                          <td className="py-2 pr-3 text-right font-mono">{b.stddevHourlyCount.toFixed(2)}</td>
                          <td className="py-2 pr-3 text-right font-mono">{b.maxHourlyCount.toFixed(0)}</td>
                          <td className="py-2 pr-3 text-right font-mono">{b.observationCount}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
