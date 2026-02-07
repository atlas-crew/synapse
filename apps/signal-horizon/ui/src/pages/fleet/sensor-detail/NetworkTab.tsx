import { MetricCard } from '../../../components/fleet';
import { InfoRow, formatDuration } from './shared';

interface NetworkTabProps {
  data: any;
}

export function NetworkTab({ data }: NetworkTabProps) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading network data...</div>;

  return (
    <div className="space-y-6">
      {/* Traffic Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Inbound Traffic" value={`${data.traffic.inboundMbps.toFixed(1)} Mbps`} description="Data received by this sensor from upstream clients" className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Outbound Traffic" value={`${data.traffic.outboundMbps.toFixed(1)} Mbps`} description="Data sent from this sensor to backend upstreams" className="border-l-2 border-l-info" labelClassName="text-ac-sky-blue dark:text-ac-sky-light" valueClassName="text-ac-sky-blue dark:text-ac-sky-light" />
        <MetricCard label="Active Connections" value={data.traffic.activeConnections.toLocaleString()} description="Currently open TCP connections being handled" className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Packets/Sec" value={data.traffic.packetsPerSec.toLocaleString()} description="Network packets processed per second at the interface level" className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
      </div>

      {/* Traffic Chart */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Traffic (Last Hour)</h3>
        <div className="h-48 flex items-end gap-1">
          {data.history.slice(-60).map((point: any, idx: number) => (
            <div key={idx} className="flex-1 flex flex-col gap-px">
              <div
                className="bg-ac-blue"
                style={{ height: `${(point.inboundMbps / 150) * 100}%` }}
                title={`In: ${point.inboundMbps.toFixed(1)} Mbps`}
              />
              <div
                className="bg-info"
                style={{ height: `${(point.outboundMbps / 150) * 100}%` }}
                title={`Out: ${point.outboundMbps.toFixed(1)} Mbps`}
              />
            </div>
          ))}
        </div>
        <div className="flex justify-between text-xs text-ink-secondary mt-2">
          <span>60 min ago</span>
          <div className="flex gap-4">
            <span><span className="inline-block w-3 h-3 bg-ac-blue mr-1" />Inbound</span>
            <span><span className="inline-block w-3 h-3 bg-info mr-1" />Outbound</span>
          </div>
          <span>Now</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network Interfaces */}
        <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6 dark:border-ac-blue/40">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Interfaces</h3>
          <table className="w-full text-sm">
            <caption className="sr-only">Sensor network interfaces with traffic and status</caption>
            <thead className="bg-surface-inset text-ac-navy dark:text-ac-sky-light border-b border-ac-blue/20 dark:border-ac-sky-light/40">
              <tr className="text-left">
                <th className="pb-2">Interface</th>
                <th className="pb-2">IP Address</th>
                <th className="pb-2">RX</th>
                <th className="pb-2">AC</th>
                <th className="pb-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.interfaces.map((iface: any) => (
                <tr key={iface.name} className="border-t border-border-subtle hover:bg-ac-blue/5 dark:hover:bg-ac-blue/10">
                  <td className="py-2 font-mono">{iface.name}</td>
                  <td className="py-2 font-mono">{iface.ip}</td>
                  <td className="py-2">{iface.rxMbps.toFixed(1)} Mbps</td>
                  <td className="py-2">{iface.txMbps.toFixed(1)} Mbps</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 text-xs border ${iface.status === 'up' ? 'bg-status-success/10 border-status-success/30 text-ink-primary' : 'bg-status-error/10 border-status-error/30 text-ink-primary'}`}>
                      {iface.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* DNS Configuration */}
        <div className="card border border-border-subtle border-t-2 border-t-info p-6 dark:border-ac-sky-light/40">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">DNS Configuration</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Primary DNS" value={data.dns.primary} />
            <InfoRow label="Secondary DNS" value={data.dns.secondary} />
            <InfoRow label="DNS Latency" value={`${data.dns.latencyMs.toFixed(1)}ms`} />
          </dl>
        </div>
      </div>

      {/* Active Connections */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 dark:border-ac-sky-light/40">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Active Connections</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <caption className="sr-only">Active network connections with state and program details</caption>
            <thead className="bg-surface-inset text-ac-navy dark:text-ac-sky-light border-b border-ac-blue/20 dark:border-ac-sky-light/40">
              <tr className="text-left">
                <th className="pb-2">Protocol</th>
                <th className="pb-2">Local Address</th>
                <th className="pb-2">Remote Address</th>
                <th className="pb-2">State</th>
                <th className="pb-2">Program</th>
                <th className="pb-2">Duration</th>
              </tr>
            </thead>
            <tbody>
              {data.connections.map((conn: any, idx: number) => (
                <tr key={idx} className="border-t border-border-subtle hover:bg-ac-blue/5 dark:hover:bg-ac-blue/10">
                  <td className="py-2">{conn.protocol}</td>
                  <td className="py-2 font-mono text-xs">{conn.localAddress}</td>
                  <td className="py-2 font-mono text-xs">{conn.remoteAddress}</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 text-xs border ${conn.state === 'ESTABLISHED' ? 'bg-status-success/10 border-status-success/30 text-ink-primary' : 'bg-status-warning/10 border-status-warning/30 text-ink-primary'}`}>
                      {conn.state}
                    </span>
                  </td>
                  <td className="py-2">{conn.program}</td>
                  <td className="py-2">{formatDuration(conn.duration)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
