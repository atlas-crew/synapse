import { MetricCard } from '../../../components/fleet';
import { InfoRow, formatBytes } from './shared';

interface PerformanceTabProps {
  data: any;
}

export function PerformanceTab({ data }: PerformanceTabProps) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading performance data...</div>;

  return (
    <div className="space-y-6">
      {/* Current Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="CPU Usage" value={`${data.current.cpu.toFixed(1)}%`} description="Current CPU utilization across all cores" className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory Usage" value={`${data.current.memory.toFixed(1)}%`} description="Resident memory usage as a percentage of total RAM" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk Usage" value={`${data.current.disk.toFixed(1)}%`} description="Disk space used on the primary partition" className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="Load Average" value={data.current.loadAverage.map((l: number) => l.toFixed(2)).join(', ')} description="System load averages for 1, 5, and 15 minute intervals" className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      {/* CPU Chart */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">CPU Utilization (Last Hour)</h3>
        <div className="h-48 flex items-end gap-1">
          {data.history.slice(-60).map((point: any, idx: number) => (
            <div
              key={idx}
              className="flex-1 bg-ac-blue"
              style={{ height: `${point.cpu}%` }}
              title={`${point.cpu.toFixed(1)}% at ${new Date(point.timestamp).toLocaleTimeString()}`}
            />
          ))}
        </div>
        <div className="flex justify-between text-xs text-ink-secondary mt-2">
          <span>60 min ago</span>
          <span>Now</span>
        </div>
      </div>

      {/* Disk I/O */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Disk I/O</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Read Throughput" value={formatBytes(data.diskIO.readBytesPerSec) + '/s'} />
            <InfoRow label="Write Throughput" value={formatBytes(data.diskIO.writeBytesPerSec) + '/s'} />
            <InfoRow label="IOPS" value={data.diskIO.iops.toString()} />
            <InfoRow label="I/O Wait" value={`${data.diskIO.ioWait.toFixed(1)}%`} />
          </dl>
        </div>

        {/* Benchmarks */}
      <div className="card border border-border-subtle border-t-2 border-t-info p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Performance Benchmarks</h3>
          <div className="space-y-3">
            {data.benchmarks.map((b: any) => (
              <div key={b.name} className="flex items-center justify-between">
                <span className="text-sm text-ink-secondary">{b.name}</span>
                <span className="inline-flex items-center gap-2 text-sm font-medium text-ink-primary">
                  <span className={`inline-block w-2 h-2 ${b.status === 'good' ? 'bg-status-success' : b.status === 'warning' ? 'bg-status-warning' : 'bg-status-error'}`} />
                  {b.value} {b.unit}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
