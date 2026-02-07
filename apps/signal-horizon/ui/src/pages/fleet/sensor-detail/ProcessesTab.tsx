import { MetricCard } from '../../../components/fleet';
import { formatUptime } from './shared';

interface ProcessesTabProps {
  data: any;
}

export function ProcessesTab({ data }: ProcessesTabProps) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading process data...</div>;

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Total Processes" value={data.summary.totalProcesses.toString()} description="Number of running processes on this sensor host" className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Total Threads" value={data.summary.totalThreads.toString()} description="Aggregate thread count across all processes" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Services Healthy" value={`${data.summary.systemServicesHealthy}/${data.services.length}`} description="System services passing health checks vs total monitored services" className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Open Files" value={data.summary.openFiles.toLocaleString()} description="Number of open file descriptors (sockets, pipes, and files)" className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      {/* Services */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">System Services</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {data.services.map((svc: any) => (
            <div key={svc.name} className="flex items-center justify-between p-3 bg-surface-subtle">
              <div>
                <div className="font-medium text-ink-primary">{svc.name}</div>
                <div className="text-xs text-ink-secondary">PID: {svc.pid} • Uptime: {formatUptime(svc.uptime)}</div>
              </div>
              <span className={`px-2 py-1 text-xs border ${svc.health === 'healthy' ? 'bg-status-success/10 border-status-success/30 text-ink-primary' : 'bg-status-error/10 border-status-error/30 text-ink-primary'}`}>
                {svc.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Process List */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Running Processes</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Running processes with resource usage and status</caption>
            <thead className="bg-surface-inset text-ac-navy dark:text-ac-sky-light border-b border-ac-blue/20 dark:border-ac-sky-light/40">
              <tr className="text-left">
                <th className="pb-2">PID</th>
                <th className="pb-2">Name</th>
                <th className="pb-2">User</th>
                <th className="pb-2">CPU %</th>
                <th className="pb-2">MEM %</th>
                <th className="pb-2">Threads</th>
                <th className="pb-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.processes.map((proc: any) => (
                <tr key={proc.pid} className="border-t border-border-subtle hover:bg-ac-blue/5 dark:hover:bg-ac-blue/10">
                  <td className="py-2 font-mono">{proc.pid}</td>
                  <td className="py-2 font-medium">{proc.name}</td>
                  <td className="py-2 text-ink-secondary">{proc.user}</td>
                  <td className="py-2">
                    <span className={proc.cpu > 50 ? 'text-ink-primary bg-status-error/10 px-1' : proc.cpu > 20 ? 'text-ink-primary bg-status-warning/10 px-1' : 'text-ink-primary'}>
                      {proc.cpu.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-2">
                    <span className={proc.memory > 50 ? 'text-ink-primary bg-status-error/10 px-1' : proc.memory > 20 ? 'text-ink-primary bg-status-warning/10 px-1' : 'text-ink-primary'}>
                      {proc.memory.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-2">{proc.threads}</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 text-xs border ${proc.status === 'running' ? 'bg-status-success/10 border-status-success/30 text-ink-primary' : 'bg-surface-subtle border-border-subtle text-ink-primary'}`}>
                      {proc.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
