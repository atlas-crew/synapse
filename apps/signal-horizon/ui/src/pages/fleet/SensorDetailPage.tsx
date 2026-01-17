import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { SensorStatusBadge, MetricCard } from '../../components/fleet';
import { RemoteShell } from '../../components/fleet/RemoteShell';
import { FileBrowser } from '../../components/fleet/FileBrowser';

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';

const authHeaders = {
  Authorization: `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

type TabType = 'overview' | 'performance' | 'network' | 'processes' | 'logs' | 'configuration' | 'remote-shell' | 'files';

// ======================== API Functions ========================

async function fetchSensorDetail(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch sensor details');
  return response.json();
}

async function fetchSystemInfo(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/system`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch system info');
  return response.json();
}

async function fetchPerformance(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/performance`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch performance');
  return response.json();
}

async function fetchNetwork(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/network`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch network');
  return response.json();
}

async function fetchProcesses(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/processes`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch processes');
  return response.json();
}

async function fetchLogs(id: string, type: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/logs?type=${type}&limit=50`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch logs');
  return response.json();
}

async function runDiagnostics(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/diagnostics/run`, {
    method: 'POST',
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to run diagnostics');
  return response.json();
}

// ======================== Main Component ========================

export function SensorDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [logType, setLogType] = useState<'access' | 'error' | 'system'>('access');

  // Core sensor data
  const { data: sensor, isLoading } = useQuery({
    queryKey: ['fleet', 'sensor', id],
    queryFn: () => fetchSensorDetail(id!),
    enabled: !!id,
    refetchInterval: 5000,
  });

  // System info for overview tab
  const { data: systemInfo } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'system'],
    queryFn: () => fetchSystemInfo(id!),
    enabled: !!id && activeTab === 'overview',
    refetchInterval: 10000,
  });

  // Performance data
  const { data: performance } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'performance'],
    queryFn: () => fetchPerformance(id!),
    enabled: !!id && activeTab === 'performance',
    refetchInterval: 5000,
  });

  // Network data
  const { data: network } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'network'],
    queryFn: () => fetchNetwork(id!),
    enabled: !!id && activeTab === 'network',
    refetchInterval: 5000,
  });

  // Processes data
  const { data: processes } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'processes'],
    queryFn: () => fetchProcesses(id!),
    enabled: !!id && activeTab === 'processes',
    refetchInterval: 5000,
  });

  // Logs data
  const { data: logs } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'logs', logType],
    queryFn: () => fetchLogs(id!, logType),
    enabled: !!id && activeTab === 'logs',
    refetchInterval: 10000,
  });

  // Mutations
  const restartMutation = useMutation({
    mutationFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/actions/restart`, {
        method: 'POST',
        headers: authHeaders,
      });
      if (!response.ok) throw new Error('Failed to restart sensor');
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id] }),
  });

  const diagnosticsMutation = useMutation({
    mutationFn: () => runDiagnostics(id!),
  });

  if (isLoading || !sensor) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-ink-muted">Loading sensor details...</div>
      </div>
    );
  }

  const tabs: { key: TabType; label: string }[] = [
    { key: 'overview', label: 'Overview' },
    { key: 'performance', label: 'Performance' },
    { key: 'network', label: 'Network' },
    { key: 'processes', label: 'Processes' },
    { key: 'logs', label: 'Logs' },
    { key: 'configuration', label: 'Configuration' },
    { key: 'remote-shell', label: 'Remote Shell' },
    { key: 'files', label: 'Files' },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <button
            onClick={() => navigate('/fleet')}
            className="mb-2 text-sm text-accent-primary hover:underline flex items-center gap-1"
          >
            ← Back to Fleet
          </button>
          <h1 className="text-2xl font-bold text-ink-primary">{sensor.name}</h1>
          <div className="mt-2 flex items-center gap-4">
            <SensorStatusBadge status={sensor.connectionState} />
            <span className="text-sm text-ink-secondary">ID: {sensor.id.slice(0, 8)}...</span>
            <span className="text-sm text-ink-secondary">v{sensor.version}</span>
            <span className="text-sm text-ink-secondary">{sensor.region}</span>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => diagnosticsMutation.mutate()}
            disabled={diagnosticsMutation.isPending}
            className="px-4 py-2 text-sm border border-border-subtle rounded-lg hover:bg-surface-subtle transition-colors"
          >
            {diagnosticsMutation.isPending ? 'Running...' : 'Run Diagnostics'}
          </button>
          <button
            onClick={() => restartMutation.mutate()}
            disabled={restartMutation.isPending}
            className="px-4 py-2 text-sm bg-accent-primary text-white rounded-lg hover:bg-accent-primary/90 transition-colors"
          >
            {restartMutation.isPending ? 'Restarting...' : 'Restart Sensor'}
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-border-subtle">
        <nav className="-mb-px flex gap-8">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === tab.key
                  ? 'border-accent-primary text-accent-primary'
                  : 'border-transparent text-ink-muted hover:text-ink-primary hover:border-border-subtle'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && <OverviewTab sensor={sensor} systemInfo={systemInfo} diagnostics={diagnosticsMutation.data} />}
      {activeTab === 'performance' && <PerformanceTab data={performance} />}
      {activeTab === 'network' && <NetworkTab data={network} />}
      {activeTab === 'processes' && <ProcessesTab data={processes} />}
      {activeTab === 'logs' && <LogsTab data={logs} logType={logType} setLogType={setLogType} />}
      {activeTab === 'configuration' && <ConfigurationTab sensor={sensor} />}
      {activeTab === 'remote-shell' && (
        <div className="h-[600px]">
          <RemoteShell sensorId={id!} sensorName={sensor.name} />
        </div>
      )}
      {activeTab === 'files' && (
        <div className="h-[600px]">
          <FileBrowser sensorId={id!} sensorName={sensor.name} height="100%" />
        </div>
      )}
    </div>
  );
}

// ======================== Tab Components ========================

function OverviewTab({ sensor, systemInfo, diagnostics }: { sensor: any; systemInfo: any; diagnostics: any }) {
  const meta = sensor.metadata || {};

  return (
    <div className="space-y-6">
      {/* Resource Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard label="CPU" value={`${(meta.cpu ?? 0).toFixed(1)}%`} />
        <MetricCard label="Memory" value={`${(meta.memory ?? 0).toFixed(1)}%`} />
        <MetricCard label="Disk" value={`${(meta.disk ?? 50).toFixed(0)}%`} />
        <MetricCard label="REQ/SEC" value={(meta.rps ?? 0).toLocaleString()} />
        <MetricCard label="Latency P99" value={`${(meta.latency ?? 0).toFixed(0)}ms`} />
        <MetricCard label="Uptime" value={formatUptime(sensor.uptime || systemInfo?.uptime || 0)} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Information */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">System Information</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Hostname" value={systemInfo?.hostname || sensor.name} />
            <InfoRow label="Sensor ID" value={sensor.id} />
            <InfoRow label="Version" value={sensor.version} />
            <InfoRow label="OS" value={systemInfo?.os || 'Unknown'} />
            <InfoRow label="Kernel" value={systemInfo?.kernel || 'Unknown'} />
            <InfoRow label="Architecture" value={systemInfo?.architecture || 'x86_64'} />
            <InfoRow label="Public IP" value={systemInfo?.publicIp || 'N/A'} />
            <InfoRow label="Private IP" value={systemInfo?.privateIp || 'N/A'} />
            <InfoRow label="Region" value={sensor.region} />
            <InfoRow label="Instance Type" value={systemInfo?.instanceType || 'Unknown'} />
            <InfoRow label="Last Boot" value={systemInfo?.lastBoot ? new Date(systemInfo.lastBoot).toLocaleString() : 'Unknown'} />
            <InfoRow label="Last Check-in" value={sensor.lastHeartbeat ? new Date(sensor.lastHeartbeat).toLocaleString() : 'Never'} />
          </dl>
        </div>

        {/* Connection Status */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Connection Status</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Cloud Connection" value={sensor.connectionState} />
            <InfoRow label="Tunnel Active" value={systemInfo?.connection?.tunnelActive ? 'Yes' : 'No'} />
            <InfoRow label="Connection Latency" value={systemInfo?.connection?.latencyMs ? `${systemInfo.connection.latencyMs}ms` : 'N/A'} />
          </dl>

          {/* Key Processes */}
          <h4 className="text-md font-semibold text-ink-primary mt-6 mb-3">Key Processes</h4>
          <div className="space-y-2">
            {['atlascrew-waf', 'atlascrew-agent', 'atlascrew-collector', 'synapse-pingora'].map((proc) => (
              <div key={proc} className="flex items-center justify-between">
                <span className="text-ink-secondary">{proc}</span>
                <span className="text-status-success text-xs">● Running</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <ActionButton icon="🔄" label="Restart Services" />
          <ActionButton icon="🗑️" label="Clear Logs" />
          <ActionButton icon="⬆️" label="Update Sensor" />
          <ActionButton icon="🌐" label="Test Connectivity" />
          <ActionButton icon="🔌" label="Restart Sensor" />
        </div>
      </div>

      {/* Diagnostic Results */}
      {diagnostics && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">
            Diagnostic Results <span className="text-sm text-ink-muted font-normal">({new Date(diagnostics.runAt).toLocaleTimeString()})</span>
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {diagnostics.checks.map((check: any) => (
              <div key={check.name} className="flex items-start gap-2">
                <span className={check.status === 'passed' ? 'text-status-success' : check.status === 'warning' ? 'text-status-warning' : 'text-status-error'}>
                  {check.status === 'passed' ? '✓' : check.status === 'warning' ? '⚠' : '✗'}
                </span>
                <div>
                  <div className="text-sm font-medium text-ink-primary">{check.name}</div>
                  <div className="text-xs text-ink-muted">{check.message}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PerformanceTab({ data }: { data: any }) {
  if (!data) return <div className="text-center py-12 text-ink-muted">Loading performance data...</div>;

  return (
    <div className="space-y-6">
      {/* Current Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="CPU Usage" value={`${data.current.cpu.toFixed(1)}%`} />
        <MetricCard label="Memory Usage" value={`${data.current.memory.toFixed(1)}%`} />
        <MetricCard label="Disk Usage" value={`${data.current.disk.toFixed(1)}%`} />
        <MetricCard label="Load Average" value={data.current.loadAverage.map((l: number) => l.toFixed(2)).join(', ')} />
      </div>

      {/* CPU Chart */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">CPU Utilization (Last Hour)</h3>
        <div className="h-48 flex items-end gap-1">
          {data.history.slice(-60).map((point: any, idx: number) => (
            <div
              key={idx}
              className="flex-1 bg-accent-primary rounded-t"
              style={{ height: `${point.cpu}%` }}
              title={`${point.cpu.toFixed(1)}% at ${new Date(point.timestamp).toLocaleTimeString()}`}
            />
          ))}
        </div>
        <div className="flex justify-between text-xs text-ink-muted mt-2">
          <span>60 min ago</span>
          <span>Now</span>
        </div>
      </div>

      {/* Disk I/O */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Disk I/O</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Read Throughput" value={formatBytes(data.diskIO.readBytesPerSec) + '/s'} />
            <InfoRow label="Write Throughput" value={formatBytes(data.diskIO.writeBytesPerSec) + '/s'} />
            <InfoRow label="IOPS" value={data.diskIO.iops.toString()} />
            <InfoRow label="I/O Wait" value={`${data.diskIO.ioWait.toFixed(1)}%`} />
          </dl>
        </div>

        {/* Benchmarks */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Performance Benchmarks</h3>
          <div className="space-y-3">
            {data.benchmarks.map((b: any) => (
              <div key={b.name} className="flex items-center justify-between">
                <span className="text-sm text-ink-secondary">{b.name}</span>
                <span className={`text-sm font-medium ${b.status === 'good' ? 'text-status-success' : b.status === 'warning' ? 'text-status-warning' : 'text-status-error'}`}>
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

function NetworkTab({ data }: { data: any }) {
  if (!data) return <div className="text-center py-12 text-ink-muted">Loading network data...</div>;

  return (
    <div className="space-y-6">
      {/* Traffic Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Inbound Traffic" value={`${data.traffic.inboundMbps.toFixed(1)} Mbps`} />
        <MetricCard label="Outbound Traffic" value={`${data.traffic.outboundMbps.toFixed(1)} Mbps`} />
        <MetricCard label="Active Connections" value={data.traffic.activeConnections.toLocaleString()} />
        <MetricCard label="Packets/Sec" value={data.traffic.packetsPerSec.toLocaleString()} />
      </div>

      {/* Traffic Chart */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Traffic (Last Hour)</h3>
        <div className="h-48 flex items-end gap-1">
          {data.history.slice(-60).map((point: any, idx: number) => (
            <div key={idx} className="flex-1 flex flex-col gap-px">
              <div
                className="bg-status-success rounded-t"
                style={{ height: `${(point.inboundMbps / 150) * 100}%` }}
                title={`In: ${point.inboundMbps.toFixed(1)} Mbps`}
              />
              <div
                className="bg-accent-primary rounded-b"
                style={{ height: `${(point.outboundMbps / 150) * 100}%` }}
                title={`Out: ${point.outboundMbps.toFixed(1)} Mbps`}
              />
            </div>
          ))}
        </div>
        <div className="flex justify-between text-xs text-ink-muted mt-2">
          <span>60 min ago</span>
          <div className="flex gap-4">
            <span><span className="inline-block w-3 h-3 bg-status-success rounded mr-1" />Inbound</span>
            <span><span className="inline-block w-3 h-3 bg-accent-primary rounded mr-1" />Outbound</span>
          </div>
          <span>Now</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network Interfaces */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Interfaces</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted">
                <th className="pb-2">Interface</th>
                <th className="pb-2">IP Address</th>
                <th className="pb-2">RX</th>
                <th className="pb-2">AC</th>
                <th className="pb-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {data.interfaces.map((iface: any) => (
                <tr key={iface.name} className="border-t border-border-subtle">
                  <td className="py-2 font-mono">{iface.name}</td>
                  <td className="py-2 font-mono">{iface.ip}</td>
                  <td className="py-2">{iface.rxMbps.toFixed(1)} Mbps</td>
                  <td className="py-2">{iface.txMbps.toFixed(1)} Mbps</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${iface.status === 'up' ? 'bg-status-success/10 text-status-success' : 'bg-status-error/10 text-status-error'}`}>
                      {iface.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* DNS Configuration */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">DNS Configuration</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Primary DNS" value={data.dns.primary} />
            <InfoRow label="Secondary DNS" value={data.dns.secondary} />
            <InfoRow label="DNS Latency" value={`${data.dns.latencyMs.toFixed(1)}ms`} />
          </dl>
        </div>
      </div>

      {/* Active Connections */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Active Connections</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted">
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
                <tr key={idx} className="border-t border-border-subtle">
                  <td className="py-2">{conn.protocol}</td>
                  <td className="py-2 font-mono text-xs">{conn.localAddress}</td>
                  <td className="py-2 font-mono text-xs">{conn.remoteAddress}</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${conn.state === 'ESTABLISHED' ? 'bg-status-success/10 text-status-success' : 'bg-status-warning/10 text-status-warning'}`}>
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

function ProcessesTab({ data }: { data: any }) {
  if (!data) return <div className="text-center py-12 text-ink-muted">Loading process data...</div>;

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Total Processes" value={data.summary.totalProcesses.toString()} />
        <MetricCard label="Total Threads" value={data.summary.totalThreads.toString()} />
        <MetricCard label="Services Healthy" value={`${data.summary.systemServicesHealthy}/${data.services.length}`} />
        <MetricCard label="Open Files" value={data.summary.openFiles.toLocaleString()} />
      </div>

      {/* Services */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">System Services</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          {data.services.map((svc: any) => (
            <div key={svc.name} className="flex items-center justify-between p-3 bg-surface-subtle rounded-lg">
              <div>
                <div className="font-medium text-ink-primary">{svc.name}</div>
                <div className="text-xs text-ink-muted">PID: {svc.pid} • Uptime: {formatUptime(svc.uptime)}</div>
              </div>
              <span className={`px-2 py-1 rounded text-xs ${svc.health === 'healthy' ? 'bg-status-success/10 text-status-success' : 'bg-status-error/10 text-status-error'}`}>
                {svc.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Process List */}
      <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Running Processes</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted">
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
                <tr key={proc.pid} className="border-t border-border-subtle hover:bg-surface-subtle">
                  <td className="py-2 font-mono">{proc.pid}</td>
                  <td className="py-2 font-medium">{proc.name}</td>
                  <td className="py-2 text-ink-secondary">{proc.user}</td>
                  <td className="py-2">
                    <span className={proc.cpu > 50 ? 'text-status-error' : proc.cpu > 20 ? 'text-status-warning' : ''}>
                      {proc.cpu.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-2">
                    <span className={proc.memory > 50 ? 'text-status-error' : proc.memory > 20 ? 'text-status-warning' : ''}>
                      {proc.memory.toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-2">{proc.threads}</td>
                  <td className="py-2">
                    <span className={`px-2 py-0.5 rounded text-xs ${proc.status === 'running' ? 'bg-status-success/10 text-status-success' : 'bg-surface-subtle text-ink-muted'}`}>
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

function LogsTab({ data, logType, setLogType }: { data: any; logType: string; setLogType: (t: any) => void }) {
  const logTypes = ['access', 'error', 'system'] as const;

  return (
    <div className="space-y-6">
      {/* Log Type Selector */}
      <div className="flex gap-2">
        {logTypes.map((type) => (
          <button
            key={type}
            onClick={() => setLogType(type)}
            className={`px-4 py-2 text-sm rounded-lg capitalize ${
              logType === type
                ? 'bg-accent-primary text-white'
                : 'bg-surface-subtle text-ink-secondary hover:bg-surface-card'
            }`}
          >
            {type} Logs
          </button>
        ))}
      </div>

      {/* Log Viewer */}
      <div className="bg-surface-card border border-border-subtle rounded-xl">
        <div className="p-4 border-b border-border-subtle flex items-center justify-between">
          <h3 className="text-lg font-semibold text-ink-primary capitalize">{logType} Logs</h3>
          <span className="text-sm text-ink-muted">{data?.total || 0} entries</span>
        </div>
        <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
          {!data ? (
            <div className="p-4 text-center text-ink-muted">Loading logs...</div>
          ) : logType === 'access' ? (
            <table className="w-full text-sm font-mono">
              <thead className="sticky top-0 bg-surface-card">
                <tr className="text-left text-ink-muted text-xs">
                  <th className="p-2">Time</th>
                  <th className="p-2">Method</th>
                  <th className="p-2">Path</th>
                  <th className="p-2">Status</th>
                  <th className="p-2">Size</th>
                  <th className="p-2">Duration</th>
                  <th className="p-2">IP</th>
                </tr>
              </thead>
              <tbody>
                {data.logs.map((log: any, idx: number) => (
                  <tr key={idx} className="border-t border-border-subtle hover:bg-surface-subtle">
                    <td className="p-2 text-ink-muted whitespace-nowrap">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="p-2">
                      <span className={`px-1.5 py-0.5 rounded text-xs ${log.method === 'GET' ? 'bg-blue-500/10 text-blue-400' : log.method === 'POST' ? 'bg-green-500/10 text-green-400' : 'bg-orange-500/10 text-orange-400'}`}>
                        {log.method}
                      </span>
                    </td>
                    <td className="p-2 text-ink-secondary">{log.path}</td>
                    <td className="p-2">
                      <span className={`${log.status >= 500 ? 'text-status-error' : log.status >= 400 ? 'text-status-warning' : 'text-status-success'}`}>
                        {log.status}
                      </span>
                    </td>
                    <td className="p-2 text-ink-muted">{formatBytes(log.size)}</td>
                    <td className="p-2 text-ink-muted">{log.duration.toFixed(1)}ms</td>
                    <td className="p-2 text-ink-muted">{log.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="divide-y divide-border-subtle">
              {data.logs.map((log: any, idx: number) => (
                <div key={idx} className="p-3 hover:bg-surface-subtle">
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${log.level === 'ERROR' || log.level === 'CRIT' ? 'bg-status-error/10 text-status-error' : log.level === 'WARN' ? 'bg-status-warning/10 text-status-warning' : 'bg-surface-subtle text-ink-muted'}`}>
                      {log.level}
                    </span>
                    <span className="text-xs text-ink-muted">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className="text-xs text-ink-muted">[{log.source}]</span>
                  </div>
                  <div className="mt-1 text-sm text-ink-primary font-mono">{log.message}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ConfigurationTab({ sensor: _sensor }: { sensor: any }) {
  const [configTab, setConfigTab] = useState<'general' | 'kernel' | 'pingora' | 'history'>('general');

  const mockConfig = {
    general: {
      autoUpdates: true,
      verboseLogging: false,
      healthCheckReporting: true,
      collectionInterval: 5000,
      bufferSize: 10000,
      compression: true,
    },
    network: {
      upstreamTimeout: 60,
      maxConnections: 1024,
      keepalive: 300,
      bufferSize: '16k',
    },
    kernel: {
      'net.core.somaxconn': '65535',
      'net.ipv4.tcp_max_syn_backlog': '65535',
      'net.ipv4.tcp_fin_timeout': '30',
      'net.ipv4.tcp_keepalive_time': '300',
      'vm.swappiness': '10',
    },
  };

  return (
    <div className="space-y-6">
      {/* Config Tabs */}
      <div className="flex gap-2">
        {(['general', 'kernel', 'pingora', 'history'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setConfigTab(tab)}
            className={`px-4 py-2 text-sm rounded-lg capitalize ${
              configTab === tab
                ? 'bg-accent-primary text-white'
                : 'bg-surface-subtle text-ink-secondary hover:bg-surface-card'
            }`}
          >
            {tab === 'pingora' ? 'Synapse-Pingora Config' : tab === 'history' ? 'Change History' : tab}
          </button>
        ))}
      </div>

      {configTab === 'general' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
            <h3 className="text-lg font-semibold text-ink-primary mb-4">General Settings</h3>
            <div className="space-y-4">
              {Object.entries(mockConfig.general).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                  {typeof value === 'boolean' ? (
                    <div className={`w-10 h-6 rounded-full ${value ? 'bg-status-success' : 'bg-surface-subtle'} relative cursor-pointer`}>
                      <div className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-all ${value ? 'right-1' : 'left-1'}`} />
                    </div>
                  ) : (
                    <span className="text-sm font-mono text-ink-primary">{value}</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
            <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Settings</h3>
            <div className="space-y-4">
              {Object.entries(mockConfig.network).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                  <span className="text-sm font-mono text-ink-primary">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {configTab === 'kernel' && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Kernel Parameters (sysctl)</h3>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted">
                <th className="pb-2">Parameter</th>
                <th className="pb-2">Value</th>
                <th className="pb-2"></th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(mockConfig.kernel).map(([key, value]) => (
                <tr key={key} className="border-t border-border-subtle">
                  <td className="py-3 font-mono text-ink-secondary">{key}</td>
                  <td className="py-3 font-mono text-ink-primary">{value}</td>
                  <td className="py-3 text-right">
                    <button className="text-xs text-accent-primary hover:underline">Edit</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {configTab === 'pingora' && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-ink-primary">Synapse-Pingora Configuration</h3>
            <div className="flex gap-2">
              <button className="px-3 py-1.5 text-xs border border-border-subtle rounded hover:bg-surface-subtle">Validate</button>
              <button className="px-3 py-1.5 text-xs border border-border-subtle rounded hover:bg-surface-subtle">Download</button>
              <button className="px-3 py-1.5 text-xs bg-accent-primary text-white rounded hover:bg-accent-primary/90">Save Changes</button>
            </div>
          </div>
          <pre className="bg-surface-base border border-border-subtle rounded-lg p-4 font-mono text-sm text-ink-secondary overflow-x-auto">
{`# /etc/synapse-pingora/config.yaml
server:
  listen: "0.0.0.0:443"

upstreams:
  - host: "127.0.0.1"
    port: 3003

logging:
  level: "info"
  access_log: true

tls:
  enabled: true
  cert_path: "/etc/ssl/certs/signal-horizon.crt"
  key_path: "/etc/ssl/private/signal-horizon.key"
`}
          </pre>
        </div>
      )}

      {configTab === 'history' && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Recent Configuration Changes</h3>
          <div className="space-y-4">
            {[
              { date: '2024-01-15 14:30', user: 'admin', change: 'Updated synapse-pingora upstream keepalive from 60 to 65', revertable: true },
              { date: '2024-01-14 09:15', user: 'admin', change: 'Enabled verbose logging', revertable: true },
              { date: '2024-01-12 16:45', user: 'system', change: 'Auto-update: agent version 4.2.0 → 4.2.1', revertable: false },
              { date: '2024-01-10 11:20', user: 'admin', change: 'Modified kernel parameter net.core.somaxconn', revertable: true },
            ].map((entry, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-surface-subtle rounded-lg">
                <div>
                  <div className="text-sm font-medium text-ink-primary">{entry.change}</div>
                  <div className="text-xs text-ink-muted">{entry.date} by {entry.user}</div>
                </div>
                {entry.revertable && (
                  <button className="text-xs text-accent-primary hover:underline">Revert</button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ======================== Helper Components ========================

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="text-ink-primary font-mono text-xs">{value}</dd>
    </div>
  );
}

function ActionButton({ icon, label }: { icon: string; label: string }) {
  return (
    <button className="flex items-center gap-2 px-4 py-3 bg-surface-subtle border border-border-subtle rounded-lg hover:bg-surface-card transition-colors">
      <span className="text-lg">{icon}</span>
      <span className="text-sm text-ink-primary">{label}</span>
    </button>
  );
}

// ======================== Helper Functions ========================

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}
