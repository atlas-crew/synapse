import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Settings, RefreshCw, AlertCircle } from 'lucide-react';
import { SensorStatusBadge, MetricCard } from '../../components/fleet';
import { SensorDetailSkeleton, ConfigPanelSkeleton, LoadingSpinner } from '../../components/LoadingStates';
import { RemoteShell } from '../../components/fleet/RemoteShell';
import { FileBrowser } from '../../components/fleet/FileBrowser';
import { LogViewer } from '../../components/fleet/LogViewer';
import { ConfigDriftViewer } from '../../components/fleet/ConfigDriftViewer';
import { WafConfig, type WafConfigData } from '../../components/fleet/pingora/WafConfig';
import { RateLimitConfig, type RateLimitData } from '../../components/fleet/pingora/RateLimitConfig';
import { AccessControlConfig, type AccessControlData } from '../../components/fleet/pingora/AccessControlConfig';
import { ServiceControls } from '../../components/fleet/pingora/ServiceControls';

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

async function fetchSensorConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch sensor configuration');
  return response.json();
}

async function fetchConfigHistory(sensorId: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/commands?limit=50`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch configuration history');
  const data = await response.json();
  const commands = Array.isArray(data?.commands) ? data.commands : [];
  return commands.filter((command: { sensorId?: string; commandType?: string }) =>
    command?.sensorId === sensorId && command?.commandType === 'push_config'
  );
}

async function runDiagnostics(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/diagnostics/run`, {
    method: 'POST',
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to run diagnostics');
  return response.json();
}

async function fetchKernelConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config?section=kernel`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch kernel config');
  return response.json();
}

async function updateKernelConfig(id: string, params: Record<string, string>, persist: boolean) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config`, {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify({
      section: 'kernel',
      config: { params, persist },
    }),
  });
  if (!response.ok) throw new Error('Failed to update kernel config');
  return response.json();
}

async function fetchPingoraConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch Pingora config');
  return response.json();
}

async function updatePingoraConfig(id: string, config: any) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(config),
  });
  if (!response.ok) throw new Error('Failed to update Pingora config');
  return response.json();
}

async function runPingoraAction(id: string, action: 'test' | 'reload' | 'restart') {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/actions/pingora`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ action }),
  });
  if (!response.ok) throw new Error('Failed to run Pingora action');
  return response.json();
}

// ======================== Main Component ========================

export function SensorDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('overview');

  // Core sensor data
  const {
    data: sensor,
    isLoading: isSensorLoading,
    error: sensorError,
    refetch: refetchSensor,
    isFetching: isSensorFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id],
    queryFn: () => fetchSensorDetail(id!),
    enabled: !!id,
    refetchInterval: 5000,
  });

  // System info for overview tab
  const {
    data: systemInfo,
    isLoading: isSystemLoading,
    error: systemError,
    refetch: refetchSystem,
    isFetching: isSystemFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'system'],
    queryFn: () => fetchSystemInfo(id!),
    enabled: !!id && activeTab === 'overview',
    refetchInterval: 10000,
  });

  // Performance data
  const {
    data: performance,
    isLoading: isPerformanceLoading,
    error: performanceError,
    refetch: refetchPerformance,
    isFetching: isPerformanceFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'performance'],
    queryFn: () => fetchPerformance(id!),
    enabled: !!id && activeTab === 'performance',
    refetchInterval: 5000,
  });

  // Network data
  const {
    data: network,
    isLoading: isNetworkLoading,
    error: networkError,
    refetch: refetchNetwork,
    isFetching: isNetworkFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'network'],
    queryFn: () => fetchNetwork(id!),
    enabled: !!id && activeTab === 'network',
    refetchInterval: 5000,
  });

  // Processes data
  const {
    data: processes,
    isLoading: isProcessesLoading,
    error: processesError,
    refetch: refetchProcesses,
    isFetching: isProcessesFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'processes'],
    queryFn: () => fetchProcesses(id!),
    enabled: !!id && (activeTab === 'processes' || activeTab === 'overview'),
    refetchInterval: 5000,
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

  if (isSensorLoading) {
    return <SensorDetailSkeleton />;
  }

  if (sensorError) {
    return (
      <div className="p-12">
        <ErrorState
          message={(sensorError as Error).message || 'Failed to load sensor details.'}
          onRetry={() => refetchSensor()}
          isRetrying={isSensorFetching}
        />
      </div>
    );
  }

  if (!sensor) {
    return (
      <div className="p-12">
        <ErrorState message="Sensor not found." />
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
      {activeTab === 'overview' && (
        <OverviewTab
          sensor={sensor}
          systemInfo={systemInfo}
          diagnostics={diagnosticsMutation.data}
          isSystemLoading={isSystemLoading}
          systemError={systemError}
          onRetrySystem={() => refetchSystem()}
          isSystemRetrying={isSystemFetching}
          services={processes?.services}
          isServicesLoading={isProcessesLoading}
          servicesError={processesError}
          onRetryServices={() => refetchProcesses()}
          isServicesRetrying={isProcessesFetching}
        />
      )}
      {activeTab === 'performance' && (
        <PerformanceTab
          data={performance}
          isLoading={isPerformanceLoading}
          error={performanceError}
          onRetry={() => refetchPerformance()}
          isRetrying={isPerformanceFetching}
        />
      )}
      {activeTab === 'network' && (
        <NetworkTab
          data={network}
          isLoading={isNetworkLoading}
          error={networkError}
          onRetry={() => refetchNetwork()}
          isRetrying={isNetworkFetching}
        />
      )}
      {activeTab === 'processes' && (
        <ProcessesTab
          data={processes}
          isLoading={isProcessesLoading}
          error={processesError}
          onRetry={() => refetchProcesses()}
          isRetrying={isProcessesFetching}
        />
      )}
      {activeTab === 'logs' && (
        <LogViewer
          sensorId={sensor.id}
          sensorName={sensor.name}
          height="600px"
        />
      )}
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

function OverviewTab({
  sensor,
  systemInfo,
  diagnostics,
  isSystemLoading,
  systemError,
  onRetrySystem,
  isSystemRetrying,
  services,
  isServicesLoading,
  servicesError,
  onRetryServices,
  isServicesRetrying,
}: {
  sensor: any;
  systemInfo: any;
  diagnostics: any;
  isSystemLoading: boolean;
  systemError: unknown;
  onRetrySystem: () => void;
  isSystemRetrying: boolean;
  services: Array<{ name: string; status: string; health?: string }> | undefined;
  isServicesLoading: boolean;
  servicesError: unknown;
  onRetryServices: () => void;
  isServicesRetrying: boolean;
}) {
  const meta = sensor.metadata || {};
  const keyProcesses = ['atlascrew-waf', 'atlascrew-agent', 'atlascrew-collector', 'synapse-pingora'];
  const systemValue = (value: string) => {
    if (isSystemLoading) return 'Loading...';
    if (systemError) return 'Unavailable';
    return value;
  };

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
          {isSystemLoading ? (
            <LoadingSpinner message="Loading system info..." size="sm" />
          ) : systemError ? (
            <ErrorState
              message={(systemError as Error).message || 'Failed to load system info.'}
              onRetry={onRetrySystem}
              isRetrying={isSystemRetrying}
            />
          ) : (
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
          )}
        </div>

        {/* Connection Status */}
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Connection Status</h3>
          <dl className="space-y-3 text-sm">
            <InfoRow label="Cloud Connection" value={sensor.connectionState} />
            <InfoRow
              label="Tunnel Active"
              value={systemValue(
                systemInfo?.connection?.tunnelActive === undefined
                  ? 'N/A'
                  : systemInfo?.connection?.tunnelActive
                    ? 'Yes'
                    : 'No'
              )}
            />
            <InfoRow
              label="Connection Latency"
              value={systemValue(
                systemInfo?.connection?.latencyMs ? `${systemInfo.connection.latencyMs}ms` : 'N/A'
              )}
            />
          </dl>

          {/* Key Processes */}
          <h4 className="text-md font-semibold text-ink-primary mt-6 mb-3">Key Processes</h4>
          {isServicesLoading ? (
            <LoadingSpinner message="Loading services..." size="sm" />
          ) : servicesError ? (
            <ErrorState
              message={(servicesError as Error).message || 'Failed to load services.'}
              onRetry={onRetryServices}
              isRetrying={isServicesRetrying}
            />
          ) : (
            <div className="space-y-2">
              {keyProcesses.map((proc) => {
                const match = services?.find((svc) => svc.name === proc);
                const status = match?.health || match?.status;
                const statusLabel = status ? status.toString() : 'Unknown';
                const statusClass =
                  statusLabel === 'healthy' || statusLabel === 'active'
                    ? 'text-status-success'
                    : statusLabel === 'degraded'
                      ? 'text-status-warning'
                      : statusLabel === 'unhealthy'
                        ? 'text-status-error'
                        : 'text-ink-muted';

                return (
                  <div key={proc} className="flex items-center justify-between">
                    <span className="text-ink-secondary">{proc}</span>
                    <span className={`${statusClass} text-xs`}>● {statusLabel}</span>
                  </div>
                );
              })}
            </div>
          )}
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

function PerformanceTab({
  data,
  isLoading,
  error,
  onRetry,
  isRetrying,
}: {
  data: any;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
  isRetrying: boolean;
}) {
  if (isLoading) return <LoadingSpinner message="Loading performance data..." />;
  if (error) {
    return (
      <ErrorState
        message={(error as Error).message || 'Failed to load performance data.'}
        onRetry={onRetry}
        isRetrying={isRetrying}
      />
    );
  }
  if (!data) return <div className="text-center py-12 text-ink-muted">No performance data available.</div>;

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

function NetworkTab({
  data,
  isLoading,
  error,
  onRetry,
  isRetrying,
}: {
  data: any;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
  isRetrying: boolean;
}) {
  if (isLoading) return <LoadingSpinner message="Loading network data..." />;
  if (error) {
    return (
      <ErrorState
        message={(error as Error).message || 'Failed to load network data.'}
        onRetry={onRetry}
        isRetrying={isRetrying}
      />
    );
  }
  if (!data) return <div className="text-center py-12 text-ink-muted">No network data available.</div>;

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

function ProcessesTab({
  data,
  isLoading,
  error,
  onRetry,
  isRetrying,
}: {
  data: any;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
  isRetrying: boolean;
}) {
  if (isLoading) return <LoadingSpinner message="Loading process data..." />;
  if (error) {
    return (
      <ErrorState
        message={(error as Error).message || 'Failed to load process data.'}
        onRetry={onRetry}
        isRetrying={isRetrying}
      />
    );
  }
  if (!data) return <div className="text-center py-12 text-ink-muted">No process data available.</div>;

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

function ConfigurationTab({ sensor }: { sensor: any }) {
  const id = sensor.id;
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [configTab, setConfigTab] = useState<'general' | 'kernel' | 'pingora' | 'drift' | 'history'>('general');

  const {
    data: remoteConfig,
    isLoading: isConfigLoading,
    error: configError,
    refetch: refetchConfig,
    isFetching: isConfigFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'synapse'],
    queryFn: () => fetchSensorConfig(id),
    enabled: !!id && configTab === 'general',
  });

  const {
    data: configHistory,
    isLoading: isHistoryLoading,
    error: historyError,
    refetch: refetchHistory,
    isFetching: isHistoryFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'history'],
    queryFn: () => fetchConfigHistory(id),
    enabled: !!id && configTab === 'history',
  });

  const { data: remoteKernelConfig, isLoading: isKernelLoading, error: kernelError, refetch: refetchKernel, isFetching: isKernelFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'kernel'],
    queryFn: () => fetchKernelConfig(id),
    enabled: !!id && configTab === 'kernel',
  });

  // Load real Pingora config
  const { data: remotePingoraConfig, isLoading, error: pingoraError, refetch: refetchPingora, isFetching: isPingoraFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'pingora'],
    queryFn: () => fetchPingoraConfig(id),
    enabled: !!id && configTab === 'pingora',
  });

  // Local state for editing
  const [wafConfig, setWafConfig] = useState<WafConfigData>({
    enabled: true,
    threshold: 0.5,
    rule_overrides: {}
  });

  const [rateLimitConfig, setRateLimitConfig] = useState<RateLimitData>({
    enabled: true,
    requests_per_second: 100,
    burst: 50
  });

  const [aclConfig, setAccessConfig] = useState<AccessControlData>({
    allow: [],
    deny: []
  });
  const [kernelDraft, setKernelDraft] = useState<Record<string, string>>({});
  const [persistKernel, setPersistKernel] = useState(false);

  const kernelParams = (remoteKernelConfig?.data?.parameters || remoteKernelConfig?.parameters || {}) as Record<string, string>;
  const resolvedConfig = unwrapConfig(remoteConfig);
  const serverConfig = (resolvedConfig.server || {}) as Record<string, unknown>;
  const rateLimitSummary = (resolvedConfig.rate_limit || {}) as Record<string, unknown>;
  const sites = Array.isArray(resolvedConfig.sites) ? resolvedConfig.sites : [];
  const primarySite = (sites[0] || {}) as Record<string, unknown>;
  const primaryUpstreams = Array.isArray(primarySite.upstreams) ? primarySite.upstreams : [];
  const generalSettings = [
    { label: 'HTTP Address', value: serverConfig.http_addr },
    { label: 'HTTPS Address', value: serverConfig.https_addr },
    { label: 'Workers', value: serverConfig.workers },
    { label: 'Log Level', value: serverConfig.log_level },
    { label: 'WAF Enabled', value: serverConfig.waf_enabled },
    { label: 'WAF Threshold', value: serverConfig.waf_threshold },
  ];
  const networkSettings = [
    { label: 'Sites', value: sites.length },
    { label: 'Primary Hostname', value: primarySite.hostname },
    { label: 'Upstreams', value: primaryUpstreams.length },
    { label: 'Rate Limit Enabled', value: rateLimitSummary.enabled },
    { label: 'Rate Limit (RPS)', value: rateLimitSummary.rps },
    { label: 'Burst', value: rateLimitSummary.burst },
  ];

  // Sync local state when remote data loads
  useEffect(() => {
    if (remotePingoraConfig) {
      setWafConfig(remotePingoraConfig.waf);
      setRateLimitConfig(remotePingoraConfig.rateLimit);
      setAccessConfig(remotePingoraConfig.accessControl);
    }
  }, [remotePingoraConfig]);

  useEffect(() => {
    if (remoteKernelConfig) {
      setKernelDraft(kernelParams);
    }
  }, [kernelParams, remoteKernelConfig]);

  // Mutations
  const updateMutation = useMutation({
    mutationFn: (config: any) => updatePingoraConfig(id, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'pingora'] });
      alert('Configuration updated and push initiated');
    },
  });

  const updateKernelMutation = useMutation({
    mutationFn: (params: Record<string, string>) => updateKernelConfig(id, params, persistKernel),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'kernel'] });
      const appliedCount = Object.keys(result?.data?.applied || {}).length;
      alert(`Kernel configuration applied (${appliedCount} parameters).`);
    },
  });

  const handlePingoraAction = async (action: 'test' | 'reload' | 'restart') => {
    await runPingoraAction(id, action);
  };

  const handleSaveAll = () => {
    updateMutation.mutate({
      waf: wafConfig,
      rateLimit: rateLimitConfig,
      accessControl: aclConfig,
    });
  };

  const driftData = {
    expected: JSON.stringify(remotePingoraConfig || {}, null, 2),
    actual: JSON.stringify({
      ...remotePingoraConfig,
      // Mock drift for visualization if needed
    }, null, 2)
  };

  return (
    <div className="space-y-6">
      {/* Config Tabs */}
      <div className="flex justify-between items-center">
        <div className="flex gap-2">
          {(['general', 'kernel', 'pingora', 'drift', 'history'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setConfigTab(tab)}
              className={`px-4 py-2 text-sm rounded-lg capitalize ${
                configTab === tab
                  ? 'bg-accent-primary text-white'
                  : 'bg-surface-subtle text-ink-secondary hover:bg-surface-card'
              }`}
            >
              {tab === 'pingora' ? 'Synapse-Pingora' : tab === 'drift' ? 'Drift Analysis' : tab}
            </button>
          ))}
        </div>
        
        <div className="flex gap-3">
          <button
            onClick={() => navigate(`/fleet/sensors/${id}/config`)}
            className="px-4 py-2 text-sm border border-border-subtle rounded-lg hover:bg-surface-subtle flex items-center gap-2"
          >
            <Settings className="w-4 h-4" />
            Advanced JSON Editor
          </button>
          {configTab === 'pingora' && (
            <button 
              onClick={handleSaveAll}
              disabled={updateMutation.isPending}
              className="btn-primary h-10 px-6 text-sm"
            >
              {updateMutation.isPending ? 'Saving...' : 'Save & Push Changes'}
            </button>
          )}
        </div>
      </div>

      {configTab === 'drift' && (
        <ConfigDriftViewer 
          expectedConfig={driftData.expected}
          actualConfig={driftData.actual}
          lastSync="Just now"
          driftDetected={false}
        />
      )}

      {configTab === 'pingora' && (
        <div className="space-y-6">
          {isLoading ? (
            <ConfigPanelSkeleton />
          ) : pingoraError ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="flex items-center gap-2 text-status-error">
                <AlertCircle className="w-5 h-5" />
                <span>Error: {(pingoraError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchPingora()}
                disabled={isPingoraFetching}
                className="flex items-center gap-2 px-4 py-2 text-sm bg-accent-primary text-white rounded-lg hover:bg-accent-primary/90 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${isPingoraFetching ? 'animate-spin' : ''}`} />
                {isPingoraFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : (
            <>
              <ServiceControls onAction={handlePingoraAction} />
              
              <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
                <WafConfig config={wafConfig} onChange={setWafConfig} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
                  <RateLimitConfig config={rateLimitConfig} onChange={setRateLimitConfig} />
                </div>
                
                <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
                  <AccessControlConfig config={aclConfig} onChange={setAccessConfig} />
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {configTab === 'general' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
            <h3 className="text-lg font-semibold text-ink-primary mb-4">General Settings</h3>
            {isConfigLoading ? (
              <LoadingSpinner message="Loading configuration..." size="sm" />
            ) : configError ? (
              <ErrorState
                message={(configError as Error).message || 'Failed to load configuration.'}
                onRetry={() => refetchConfig()}
                isRetrying={isConfigFetching}
              />
            ) : (
              <div className="space-y-4">
                {generalSettings.map((setting) => {
                  const displayValue = normalizeSettingValue(setting.value);
                  return (
                    <div key={setting.label} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary">{setting.label}</span>
                      {typeof displayValue === 'boolean' ? (
                        <div className={`w-10 h-6 rounded-full ${displayValue ? 'bg-status-success' : 'bg-surface-subtle'} relative`}>
                          <div className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-all ${displayValue ? 'right-1' : 'left-1'}`} />
                        </div>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{displayValue}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
            <h3 className="text-lg font-semibold text-ink-primary mb-4">Network Settings</h3>
            {isConfigLoading ? (
              <LoadingSpinner message="Loading configuration..." size="sm" />
            ) : configError ? (
              <ErrorState
                message={(configError as Error).message || 'Failed to load configuration.'}
                onRetry={() => refetchConfig()}
                isRetrying={isConfigFetching}
              />
            ) : (
              <div className="space-y-4">
                {networkSettings.map((setting) => {
                  const displayValue = normalizeSettingValue(setting.value);
                  return (
                    <div key={setting.label} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary">{setting.label}</span>
                      {typeof displayValue === 'boolean' ? (
                        <div className={`w-10 h-6 rounded-full ${displayValue ? 'bg-status-success' : 'bg-surface-subtle'} relative`}>
                          <div className={`w-4 h-4 rounded-full bg-white absolute top-1 transition-all ${displayValue ? 'right-1' : 'left-1'}`} />
                        </div>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{displayValue}</span>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {configTab === 'kernel' && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-ink-primary">Kernel Parameters (sysctl)</h3>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-xs text-ink-muted">
                <input
                  type="checkbox"
                  checked={persistKernel}
                  onChange={(event) => setPersistKernel(event.target.checked)}
                />
                Persist changes
              </label>
              <button
                className="px-3 py-1.5 text-xs rounded-lg border border-border-subtle text-ink-secondary hover:bg-surface-subtle"
                onClick={() => refetchKernel()}
                disabled={isKernelFetching}
              >
                Refresh
              </button>
              <button
                className="px-3 py-1.5 text-xs rounded-lg bg-accent-primary text-white disabled:opacity-60"
                onClick={() => updateKernelMutation.mutate(kernelDraft)}
                disabled={updateKernelMutation.isPending || isKernelLoading}
              >
                Save Changes
              </button>
            </div>
          </div>
          {kernelError && (
            <ErrorState
              message={(kernelError as Error).message || 'Failed to load kernel config.'}
              onRetry={() => refetchKernel()}
              isRetrying={isKernelFetching}
            />
          )}
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-ink-muted">
                <th className="pb-2">Parameter</th>
                <th className="pb-2">Value</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(kernelDraft).map(([key, value]) => (
                <tr key={key} className="border-t border-border-subtle">
                  <td className="py-3 font-mono text-ink-secondary">{key}</td>
                  <td className="py-3">
                    <input
                      className="w-full rounded-md border border-border-subtle bg-surface-subtle px-2 py-1 text-sm font-mono text-ink-primary"
                      value={value ?? ''}
                      onChange={(event) =>
                        setKernelDraft((current) => ({ ...current, [key]: event.target.value }))
                      }
                    />
                  </td>
                </tr>
              ))}
              {Object.keys(kernelDraft).length === 0 && !isKernelLoading && (
                <tr>
                  <td className="py-4 text-sm text-ink-muted" colSpan={2}>
                    No kernel parameters available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {configTab === 'history' && (
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Recent Configuration Changes</h3>
          {isHistoryLoading ? (
            <LoadingSpinner message="Loading configuration history..." size="sm" />
          ) : historyError ? (
            <ErrorState
              message={(historyError as Error).message || 'Failed to load configuration history.'}
              onRetry={() => refetchHistory()}
              isRetrying={isHistoryFetching}
            />
          ) : configHistory?.length ? (
            <div className="space-y-4">
              {configHistory.map((entry: Record<string, any>) => (
                <div key={entry.id} className="flex items-center justify-between p-3 bg-surface-subtle rounded-lg">
                  <div>
                    <div className="text-sm font-medium text-ink-primary">{formatCommandSummary(entry)}</div>
                    <div className="text-xs text-ink-muted">{formatCommandTimestamp(entry)}</div>
                  </div>
                  <span className={`text-xs font-medium ${statusBadgeClass(entry.status)}`}>
                    {entry.status || 'unknown'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-ink-muted">No configuration changes recorded.</div>
          )}
        </div>
      )}
    </div>
  );
}

// ======================== Helper Components ========================

function ErrorState({
  message,
  onRetry,
  isRetrying,
}: {
  message: string;
  onRetry?: () => void;
  isRetrying?: boolean;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-6">
      <div className="flex items-center gap-2 text-status-error text-sm">
        <AlertCircle className="w-5 h-5" />
        <span>{message}</span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          disabled={isRetrying}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-accent-primary text-white rounded-lg hover:bg-accent-primary/90 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isRetrying ? 'animate-spin' : ''}`} />
          {isRetrying ? 'Retrying...' : 'Retry'}
        </button>
      )}
    </div>
  );
}

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

function unwrapConfig(payload: unknown): Record<string, unknown> {
  if (payload && typeof payload === 'object' && 'data' in (payload as Record<string, unknown>)) {
    const data = (payload as { data?: unknown }).data;
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      return data as Record<string, unknown>;
    }
    return {};
  }
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return payload as Record<string, unknown>;
  }
  return {};
}

function normalizeSettingValue(value: unknown): string | boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'string' && value.trim().length > 0) return value;
  return 'Not reported';
}

function formatCommandSummary(command: Record<string, any>): string {
  const payload = (command.payload || {}) as Record<string, unknown>;
  const component = typeof payload.component === 'string' ? payload.component : undefined;
  const policyName = typeof payload.policyName === 'string' ? payload.policyName : undefined;
  const version = typeof payload.version === 'string' ? payload.version : undefined;
  const templateId = typeof payload.templateId === 'string' ? payload.templateId : undefined;

  let summary = command.commandType === 'push_config' ? 'Configuration push' : (command.commandType || 'Command');
  if (component) summary += ` • ${component}`;
  if (policyName) summary += ` • ${policyName}`;
  if (version) summary += ` • v${version}`;
  if (templateId && !policyName) summary += ` • template ${templateId.slice(0, 8)}`;
  return summary;
}

function formatCommandTimestamp(command: Record<string, any>): string {
  const timestamp = command.createdAt || command.queuedAt || command.sentAt || command.completedAt;
  if (!timestamp) return 'Timestamp unavailable';
  return new Date(timestamp).toLocaleString();
}

function statusBadgeClass(status?: string): string {
  switch (status) {
    case 'success':
      return 'text-status-success';
    case 'failed':
    case 'timeout':
      return 'text-status-error';
    case 'pending':
    case 'sent':
      return 'text-status-warning';
    default:
      return 'text-ink-muted';
  }
}

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
