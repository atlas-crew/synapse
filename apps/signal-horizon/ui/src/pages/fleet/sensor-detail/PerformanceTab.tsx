import { MetricCard, Panel } from '@/ui';
import { InfoRow, formatBytes } from './shared';

interface PerformanceTabProps {
  data: any;
}

interface HistoryPoint {
  timestamp?: string;
  cpu?: number | string | null;
}

interface ValidHistoryPoint {
  point: HistoryPoint;
  pointCpu: number;
}

function asNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function formatPercent(value: unknown): string {
  const numeric = asNumber(value);
  return numeric === null ? '—' : `${numeric.toFixed(1)}%`;
}

function formatLoadAverage(value: unknown): string {
  if (!Array.isArray(value)) return '—';
  const formatted = value
    .map((entry) => asNumber(entry))
    .filter((entry): entry is number => entry !== null)
    .map((entry) => entry.toFixed(2));
  return formatted.length > 0 ? formatted.join(', ') : '—';
}

function formatIoValue(value: unknown, suffix = ''): string {
  const numeric = asNumber(value);
  return numeric === null ? '—' : `${numeric.toFixed(1)}${suffix}`;
}

function formatMilliseconds(value: unknown): string {
  const numeric = asNumber(value);
  return numeric === null ? '—' : `${numeric.toFixed(0)}ms`;
}

export function PerformanceTab({ data }: PerformanceTabProps) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading performance data...</div>;

  const history: HistoryPoint[] = Array.isArray(data.history) ? data.history : [];
  const validHistory = history
    .slice(-60)
    .map((point: HistoryPoint): ValidHistoryPoint | null => {
      const pointCpu = asNumber(point?.cpu);
      return pointCpu === null ? null : { point, pointCpu };
    })
    .filter((entry: ValidHistoryPoint | null): entry is ValidHistoryPoint => entry !== null);
  const benchmarks = Array.isArray(data.benchmarks) ? data.benchmarks : [];
  const diskIO = data.diskIO ?? {};
  const readBytesPerSec = asNumber(diskIO.readBytesPerSec);
  const writeBytesPerSec = asNumber(diskIO.writeBytesPerSec);

  return (
    <div className="space-y-6">
      {/* Current Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        <MetricCard label="CPU Usage" value={formatPercent(data.current?.cpu)} description="Current CPU utilization across all cores" className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory Usage" value={formatPercent(data.current?.memory)} description="Resident memory usage as a percentage of total RAM" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk Usage" value={formatPercent(data.current?.disk)} description="Disk space used on the primary partition" className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="Latency" value={formatMilliseconds(data.current?.latencyAvg)} description="Average response latency reported by the sensor heartbeat" className="border-l-2 border-l-ac-magenta" labelClassName="text-ac-magenta dark:text-ac-magenta" valueClassName="text-ac-magenta dark:text-ac-magenta" />
        <MetricCard label="Latency P99" value={formatMilliseconds(data.current?.latencyP99)} description="99th percentile response latency — 99% of requests are faster than this" className="border-l-2 border-l-ac-red" labelClassName="text-ac-red dark:text-ac-red" valueClassName="text-ac-red dark:text-ac-red" />
        <MetricCard label="Load Average" value={formatLoadAverage(data.current?.loadAverage)} description="System load averages for 1, 5, and 15 minute intervals" className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      {/* CPU Chart */}
      <Panel tone="info" padding="md">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">CPU Utilization (Last Hour)</h3>
        {validHistory.length === 0 ? (
          <div className="text-sm text-ink-secondary">No historical performance data yet.</div>
        ) : (
          <>
            <div className="h-48 flex items-end gap-1">
              {validHistory.map(({ point, pointCpu }: ValidHistoryPoint, idx: number) => {
                const timestampLabel = point.timestamp
                  ? new Date(point.timestamp).toLocaleTimeString()
                  : 'unknown time';

                return (
                  <div
                    key={idx}
                    className="flex-1 bg-ac-blue"
                    style={{ height: `${pointCpu}%` }}
                    title={`${pointCpu.toFixed(1)}% at ${timestampLabel}`}
                  />
                );
              })}
            </div>
            <div className="flex justify-between text-xs text-ink-secondary mt-2">
              <span>60 min ago</span>
              <span>Now</span>
            </div>
          </>
        )}
      </Panel>

      {/* Disk I/O */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Panel tone="info" padding="md">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Disk I/O</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Read Throughput" value={readBytesPerSec === null ? '—' : formatBytes(readBytesPerSec) + '/s'} />
            <InfoRow label="Write Throughput" value={writeBytesPerSec === null ? '—' : formatBytes(writeBytesPerSec) + '/s'} />
            <InfoRow label="IOPS" value={formatIoValue(diskIO.iops)} />
            <InfoRow label="I/O Wait" value={formatIoValue(diskIO.ioWait, '%')} />
          </dl>
        </Panel>

        {/* Benchmarks */}
        <Panel tone="info" padding="md">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Performance Benchmarks</h3>
          {benchmarks.length === 0 ? (
            <div className="text-sm text-ink-secondary">No benchmark samples available yet.</div>
          ) : (
            <div className="space-y-3">
              {benchmarks.map((b: any) => (
                <div key={b.name} className="flex items-center justify-between">
                  <span className="text-sm text-ink-secondary">{b.name}</span>
                  <span className="inline-flex items-center gap-2 text-sm font-medium text-ink-primary">
                    <span className={`inline-block w-2 h-2 ${b.status === 'good' ? 'bg-status-success' : b.status === 'warning' ? 'bg-status-warning' : 'bg-status-error'}`} />
                    {b.value} {b.unit}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
