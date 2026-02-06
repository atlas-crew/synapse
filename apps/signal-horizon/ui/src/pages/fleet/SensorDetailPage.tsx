import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb } from '../../components/ui/Breadcrumb';
import {
  AlertCircle,
  AlertTriangle,
  ArrowUpCircle,
  CheckCircle2,
  Globe2,
  Plug,
  RefreshCw,
  RotateCcw,
  Settings,
  Trash2,
  WifiOff,
  XCircle,
  type LucideIcon,
} from 'lucide-react';
import { useToast } from '../../components/ui/Toast';
import { ConfirmDialog } from '../../components/ui/ConfirmDialog';
import { SensorStatusBadge, MetricCard } from '../../components/fleet';
import { SensorDetailSkeleton, ConfigPanelSkeleton } from '../../components/LoadingStates';
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

async function fetchSystemConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${id}/config`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch system config');
  return response.json();
}

async function fetchCommandHistory(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/commands?limit=100&offset=0`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch command history');
  const data = await response.json();
  const commands = (data?.commands || []).filter((command: any) => command.sensorId === id);
  return { ...data, commands };
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
  useDocumentTitle('Sensor Detail');
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('overview');

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
    return <SensorDetailSkeleton />;
  }

  const status = sensor.connectionState === 'CONNECTED'
    ? 'online'
    : sensor.connectionState === 'RECONNECTING'
      ? 'warning'
      : 'offline';

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
      <Breadcrumb items={[
        { label: 'Fleet', to: '/fleet' },
        { label: sensor.name || 'Sensor Detail' },
      ]} />
      {/* Header */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue">
        <div className="flex items-start justify-between gap-6 p-6 bg-surface-inset">
          <div>
            <button
              onClick={() => navigate('/fleet')}
              className="mb-2 text-xs uppercase tracking-[0.25em] text-ac-blue hover:text-ac-blue/80 flex items-center gap-2 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
            >
              <span className="text-ink-secondary">←</span>
              Back to Fleet
            </button>
            <h1 className="text-2xl font-light text-ink-primary">{sensor.name}</h1>
            <div className="mt-3 flex flex-wrap items-center gap-4 text-xs uppercase tracking-[0.18em] text-ink-secondary">
              <SensorStatusBadge status={status} />
              <span>ID {sensor.id.slice(0, 8)}...</span>
              <span>v{sensor.version}</span>
              <span>{sensor.region}</span>
            </div>
          </div>
          <div className="flex flex-wrap gap-3">
            <button
              onClick={() => diagnosticsMutation.mutate()}
              disabled={diagnosticsMutation.isPending}
              className="btn-outline h-10 px-4 text-xs uppercase tracking-[0.2em]"
            >
              {diagnosticsMutation.isPending ? 'Running...' : 'Run Diagnostics'}
            </button>
            <button
              onClick={() => restartMutation.mutate()}
              disabled={restartMutation.isPending}
              className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]"
            >
              {restartMutation.isPending ? 'Restarting...' : 'Restart Sensor'}
            </button>
          </div>
        </div>
      </div>

      {/* Tabs — WCAG 1.3.1 ARIA tab pattern */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-navy">
        <nav role="tablist" aria-label="Sensor details" className="flex flex-wrap gap-6 px-6 py-3 bg-surface-inset border-b border-border-subtle">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              role="tab"
              id={`tab-${tab.key}`}
              aria-selected={activeTab === tab.key}
              aria-controls={`tabpanel-${tab.key}`}
              onClick={() => setActiveTab(tab.key)}
              className={`px-1 py-2 text-xs uppercase tracking-[0.2em] border-b-2 transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                activeTab === tab.key
                  ? 'border-ac-blue text-ac-blue'
                  : 'border-transparent text-ink-secondary hover:text-ink-primary hover:border-border-subtle'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
        {activeTab === 'overview' && <OverviewTab sensor={sensor} systemInfo={systemInfo} diagnostics={diagnosticsMutation.data} onRestartSensor={() => restartMutation.mutate()} />}
        {activeTab === 'performance' && <PerformanceTab data={performance} />}
        {activeTab === 'network' && <NetworkTab data={network} />}
        {activeTab === 'processes' && <ProcessesTab data={processes} />}
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
    </div>
  );
}

// ======================== Tab Components ========================

function OverviewTab({ sensor, systemInfo, diagnostics, onRestartSensor }: { sensor: any; systemInfo: any; diagnostics: any; onRestartSensor: () => void }) {
  const meta = sensor.metadata || {};
  const { toast, Toasts } = useToast();
  const [confirmAction, setConfirmAction] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    action: () => void;
  } | null>(null);

  const API_BASE_LOCAL = import.meta.env.VITE_API_URL || '';
  const API_KEY_LOCAL = import.meta.env.VITE_API_KEY || 'demo-key';
  const headers = {
    Authorization: `Bearer ${API_KEY_LOCAL}`,
    'Content-Type': 'application/json',
  };

  const requestAction = useCallback(async (endpoint: string, successMsg: string) => {
    try {
      const response = await fetch(`${API_BASE_LOCAL}/api/v1/fleet/sensors/${sensor.id}/actions/${endpoint}`, {
        method: 'POST',
        headers,
      });
      if (!response.ok) throw new Error(`Failed to ${endpoint}`);
      toast.success(successMsg);
    } catch (err) {
      toast.error((err as Error).message);
    }
  }, [sensor.id, toast, API_BASE_LOCAL, headers]);

  const handleRestartServices = () => {
    setConfirmAction({
      title: 'Restart Services',
      description: 'This will restart all WAF services on this sensor. Active connections will be dropped and the sensor will be briefly unavailable. Are you sure?',
      confirmLabel: 'Restart Services',
      action: () => requestAction('restart-services', 'Services restart initiated'),
    });
  };

  const handleClearLogs = () => {
    setConfirmAction({
      title: 'Clear Logs',
      description: 'This will permanently delete all local log files on this sensor. This action cannot be undone. Are you sure?',
      confirmLabel: 'Clear Logs',
      action: () => requestAction('clear-logs', 'Log clearing initiated'),
    });
  };

  const handleRestartSensor = () => {
    setConfirmAction({
      title: 'Restart Sensor',
      description: 'This will fully restart the sensor process. The sensor will be offline during restart and all active connections will be terminated. Are you sure?',
      confirmLabel: 'Restart Sensor',
      action: onRestartSensor,
    });
  };

  return (
    <div className="space-y-6">
      {Toasts}
      <ConfirmDialog
        open={confirmAction !== null}
        title={confirmAction?.title ?? ''}
        description={confirmAction?.description ?? ''}
        confirmLabel={confirmAction?.confirmLabel}
        variant="danger"
        onConfirm={() => {
          confirmAction?.action();
          setConfirmAction(null);
        }}
        onCancel={() => setConfirmAction(null)}
      />

      {/* Resource Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <MetricCard label="CPU" value={`${(meta.cpu ?? 0).toFixed(1)}%`} className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory" value={`${(meta.memory ?? 0).toFixed(1)}%`} className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk" value={`${(meta.disk ?? 50).toFixed(0)}%`} className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="REQ/SEC" value={(meta.rps ?? 0).toLocaleString()} className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Latency P99" value={`${(meta.latency ?? 0).toFixed(0)}ms`} className="border-l-2 border-l-ac-red" labelClassName="text-ac-red dark:text-ac-red" valueClassName="text-ac-red dark:text-ac-red" />
        <MetricCard label="Uptime" value={formatUptime(sensor.uptime || systemInfo?.uptime || 0)} className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* System Information */}
        <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
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
        <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
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
                <span className="inline-flex items-center gap-2 text-xs text-ink-primary">
                  <span className="inline-block w-2 h-2 bg-status-success" />
                  Running
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-magenta p-6">
        <h3 className="text-lg font-semibold text-ink-primary mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <ActionButton icon={RotateCcw} label="Restart Services" onClick={handleRestartServices} />
          <ActionButton icon={Trash2} label="Clear Logs" onClick={handleClearLogs} />
          <ActionButton icon={ArrowUpCircle} label="Update Sensor" />
          <ActionButton icon={Globe2} label="Test Connectivity" />
          <ActionButton icon={Plug} label="Restart Sensor" onClick={handleRestartSensor} />
        </div>
      </div>

      {/* Diagnostic Results */}
      {diagnostics && (
        <div className="card border border-border-subtle border-t-2 border-t-info p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">
            Diagnostic Results <span className="text-sm text-ink-secondary font-normal">({new Date(diagnostics.runAt).toLocaleTimeString()})</span>
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {diagnostics.checks.map((check: any) => (
              <div key={check.name} className="flex items-start gap-2">
                <span className={check.status === 'passed' ? 'text-status-success' : check.status === 'warning' ? 'text-status-warning' : 'text-status-error'}>
                  {check.status === 'passed' ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : check.status === 'warning' ? (
                    <AlertTriangle className="w-4 h-4" />
                  ) : (
                    <XCircle className="w-4 h-4" />
                  )}
                </span>
                <div>
                  <div className="text-sm font-medium text-ink-primary">{check.name}</div>
                  <div className="text-xs text-ink-secondary">{check.message}</div>
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
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading performance data...</div>;

  return (
    <div className="space-y-6">
      {/* Current Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="CPU Usage" value={`${data.current.cpu.toFixed(1)}%`} className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Memory Usage" value={`${data.current.memory.toFixed(1)}%`} className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Disk Usage" value={`${data.current.disk.toFixed(1)}%`} className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
        <MetricCard label="Load Average" value={data.current.loadAverage.map((l: number) => l.toFixed(2)).join(', ')} className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
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

function NetworkTab({ data }: { data: any }) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading network data...</div>;

  return (
    <div className="space-y-6">
      {/* Traffic Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Inbound Traffic" value={`${data.traffic.inboundMbps.toFixed(1)} Mbps`} className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Outbound Traffic" value={`${data.traffic.outboundMbps.toFixed(1)} Mbps`} className="border-l-2 border-l-info" labelClassName="text-ac-sky-blue dark:text-ac-sky-light" valueClassName="text-ac-sky-blue dark:text-ac-sky-light" />
        <MetricCard label="Active Connections" value={data.traffic.activeConnections.toLocaleString()} className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Packets/Sec" value={data.traffic.packetsPerSec.toLocaleString()} className="border-l-2 border-l-ac-orange" labelClassName="text-ac-orange dark:text-ac-orange" valueClassName="text-ac-orange dark:text-ac-orange" />
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

function ProcessesTab({ data }: { data: any }) {
  if (!data) return <div className="text-center py-12 text-ink-secondary">Loading process data...</div>;

  return (
    <div className="space-y-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard label="Total Processes" value={data.summary.totalProcesses.toString()} className="border-l-2 border-l-ac-navy" labelClassName="text-ac-navy dark:text-ac-sky-light" valueClassName="text-ac-navy dark:text-ac-sky-light" />
        <MetricCard label="Total Threads" value={data.summary.totalThreads.toString()} className="border-l-2 border-l-ac-blue" labelClassName="text-ac-blue dark:text-ac-sky-light" valueClassName="text-ac-blue dark:text-ac-sky-light" />
        <MetricCard label="Services Healthy" value={`${data.summary.systemServicesHealthy}/${data.services.length}`} className="border-l-2 border-l-ac-green" labelClassName="text-ac-green dark:text-ac-green" valueClassName="text-ac-green dark:text-ac-green" />
        <MetricCard label="Open Files" value={data.summary.openFiles.toLocaleString()} className="border-l-2 border-l-ac-purple" labelClassName="text-ac-purple dark:text-ac-purple" valueClassName="text-ac-purple dark:text-ac-purple" />
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

function ConfigurationTab({ sensor }: { sensor: any }) {
  const id = sensor.id;
  const isTunnelActive = Boolean(sensor?.tunnelActive);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast, Toasts } = useToast();
  const [configTab, setConfigTab] = useState<'general' | 'kernel' | 'pingora' | 'drift' | 'history'>('general');

  const {
    data: systemConfig,
    isLoading: isSystemConfigLoading,
    error: systemConfigError,
    refetch: refetchSystemConfig,
    isFetching: isSystemConfigFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'system'],
    queryFn: () => fetchSystemConfig(id),
    enabled: !!id && configTab === 'general' && isTunnelActive,
  });

  const { data: remoteKernelConfig, isLoading: isKernelLoading, error: kernelError, refetch: refetchKernel, isFetching: isKernelFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'kernel'],
    queryFn: () => fetchKernelConfig(id),
    enabled: !!id && configTab === 'kernel' && isTunnelActive,
  });

  // Load real Pingora config
  const { data: remotePingoraConfig, isLoading, error: pingoraError, refetch: refetchPingora, isFetching: isPingoraFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'pingora'],
    queryFn: () => fetchPingoraConfig(id),
    enabled: !!id && (configTab === 'pingora' || configTab === 'drift'),
  });

  const {
    data: commandHistory,
    isLoading: isHistoryLoading,
    error: historyError,
    refetch: refetchHistory,
    isFetching: isHistoryFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'commands'],
    queryFn: () => fetchCommandHistory(id),
    enabled: !!id && configTab === 'history',
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
  const lastPingoraHashRef = useRef<string | null>(null);
  const lastKernelHashRef = useRef<string | null>(null);

  const kernelParams = (remoteKernelConfig?.data?.parameters || {}) as Record<string, string>;

  // Sync local state when remote data loads
  useEffect(() => {
    if (remotePingoraConfig) {
      const nextHash = JSON.stringify(remotePingoraConfig);
      if (lastPingoraHashRef.current === nextHash) {
        return;
      }
      lastPingoraHashRef.current = nextHash;
      setWafConfig(remotePingoraConfig.waf);
      setRateLimitConfig(remotePingoraConfig.rateLimit);
      setAccessConfig(remotePingoraConfig.accessControl);
    }
  }, [remotePingoraConfig]);

  useEffect(() => {
    if (kernelParams) {
      const nextHash = JSON.stringify(kernelParams);
      if (lastKernelHashRef.current === nextHash) {
        return;
      }
      lastKernelHashRef.current = nextHash;
      setKernelDraft(kernelParams);
    }
  }, [kernelParams]);

  const systemConfigData = systemConfig?.data || {};
  const generalSettings = {
    ...(systemConfigData.general || {}),
    ...(systemConfigData.features || {}),
  } as Record<string, unknown>;

  const formatSectionEntries = (label: string, section?: Record<string, unknown>) =>
    Object.entries(section || {}).map(([key, value]) => [`${label} ${key}`, value] as const);

  const runtimeEntries = [
    ...formatSectionEntries('Risk', systemConfigData.runtimeConfig?.risk),
    ...formatSectionEntries('State', systemConfigData.runtimeConfig?.state),
    ...formatSectionEntries('Session', systemConfigData.runtimeConfig?.session),
  ];

  const describeCommand = (command: any) => {
    const payload = command?.payload || {};
    if (payload.templateId) return `Pushed config template ${payload.templateId}`;
    if (payload.policyTemplateId) return `Applied policy template ${payload.policyTemplateId}`;
    if (payload.config) return 'Updated sensor configuration';
    return `Sent ${command.commandType}`;
  };

  const configHistoryEntries = (commandHistory?.commands || [])
    .filter((command: any) => command.commandType === 'push_config')
    .map((command: any) => ({
      id: command.id,
      date: new Date(command.createdAt).toLocaleString(),
      change: describeCommand(command),
      status: command.status,
    }));

  // Mutations
  const updateMutation = useMutation({
    mutationFn: (config: any) => updatePingoraConfig(id, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'pingora'] });
      toast.success('Configuration updated and push initiated');
    },
  });

  const updateKernelMutation = useMutation({
    mutationFn: (params: Record<string, string>) => updateKernelConfig(id, params, persistKernel),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'kernel'] });
      const appliedCount = Object.keys(result?.data?.applied || {}).length;
      toast.success(`Kernel configuration applied (${appliedCount} parameters).`);
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

  const renderTunnelInactive = (label: string) => (
    <div className="card border border-border-subtle border-t-2 border-t-info p-6">
      <div className="flex items-start gap-3">
        <WifiOff className="w-5 h-5 text-status-warning" />
        <div className="space-y-2">
          <div className="text-sm font-semibold text-ink-primary">{label} unavailable</div>
          <div className="text-xs text-ink-secondary">
            Sensor tunnel is not connected. Connect the sensor to load live configuration data.
          </div>
          <button
            onClick={() => navigate('/fleet/connectivity')}
            className="btn-secondary h-9 px-3 text-xs uppercase tracking-[0.2em]"
          >
            View Connectivity
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {Toasts}
      {/* Config Tabs — ARIA tab pattern */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue">
        <div className="flex justify-between items-center gap-4 p-4 bg-surface-inset">
          <div role="tablist" aria-label="Configuration sections" className="flex gap-2">
          {(['general', 'kernel', 'pingora', 'drift', 'history'] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              id={`tab-config-${tab}`}
              aria-selected={configTab === tab}
              aria-controls={`tabpanel-config-${tab}`}
              onClick={() => setConfigTab(tab)}
              className={`px-4 py-2 text-xs uppercase tracking-[0.2em] border transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                configTab === tab
                  ? 'border-ac-blue text-ac-blue bg-ac-blue/10'
                  : 'border-border-subtle text-ink-secondary hover:border-ac-blue/50 hover:text-ink-primary'
              }`}
            >
              {tab === 'pingora' ? 'Synapse-Pingora' : tab === 'drift' ? 'Drift Analysis' : tab}
            </button>
          ))}
          </div>
        
          <div className="flex gap-3">
          <button
            onClick={() => navigate(`/fleet/sensors/${id}/config`)}
            className="btn-secondary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
          >
            <Settings className="w-4 h-4" />
            Advanced JSON Editor
          </button>
          {configTab === 'pingora' && (
            <button 
              onClick={handleSaveAll}
              disabled={updateMutation.isPending || !isTunnelActive}
              className="btn-primary h-10 px-6 text-sm"
            >
              {!isTunnelActive
                ? 'Tunnel Required'
                : updateMutation.isPending
                  ? 'Saving...'
                  : 'Save & Push Changes'}
            </button>
          )}
          </div>
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
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(pingoraError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchPingora()}
                disabled={isPingoraFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isPingoraFetching ? 'animate-spin' : ''}`} />
                {isPingoraFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : (
            <>
              {isTunnelActive ? (
                <ServiceControls onAction={handlePingoraAction} />
              ) : (
                renderTunnelInactive('Pingora controls')
              )}
              
              <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
                <WafConfig config={wafConfig} onChange={setWafConfig} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="card border border-border-subtle border-t-2 border-t-info p-6">
                  <RateLimitConfig config={rateLimitConfig} onChange={setRateLimitConfig} />
                </div>
                
                <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
                  <AccessControlConfig config={aclConfig} onChange={setAccessConfig} />
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {configTab === 'general' && (
        <div className="space-y-4">
          {!isTunnelActive ? (
            renderTunnelInactive('System configuration')
          ) : isSystemConfigLoading ? (
            <ConfigPanelSkeleton />
          ) : systemConfigError ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(systemConfigError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchSystemConfig()}
                disabled={isSystemConfigFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isSystemConfigFetching ? 'animate-spin' : ''}`} />
                {isSystemConfigFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
                <h3 className="text-lg font-semibold text-ink-primary mb-4">General Settings</h3>
                <div className="space-y-4">
                  {Object.entries(generalSettings).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                      {typeof value === 'boolean' ? (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={value}
                          aria-label={key.replace(/([A-Z])/g, ' $1').trim()}
                          className={`w-10 h-6 border border-border-subtle ${value ? 'bg-status-success' : 'bg-surface-subtle'} relative cursor-pointer`}
                        >
                          <span className={`block w-4 h-4 bg-white absolute top-1 transition-all ${value ? 'right-1' : 'left-1'}`} />
                        </button>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{String(value)}</span>
                      )}
                    </div>
                  ))}
                  {Object.keys(generalSettings).length === 0 && (
                    <div className="text-sm text-ink-secondary">No general settings available.</div>
                  )}
                </div>
              </div>

              <div className="card border border-border-subtle border-t-2 border-t-info p-6">
                <h3 className="text-lg font-semibold text-ink-primary mb-4">Runtime Settings</h3>
                <div className="space-y-4">
                  {runtimeEntries.map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                      {typeof value === 'boolean' ? (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={value}
                          aria-label={key.replace(/([A-Z])/g, ' $1').trim()}
                          className={`w-10 h-6 border border-border-subtle ${value ? 'bg-status-success' : 'bg-surface-subtle'} relative cursor-pointer`}
                        >
                          <span className={`block w-4 h-4 bg-white absolute top-1 transition-all ${value ? 'right-1' : 'left-1'}`} />
                        </button>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{String(value)}</span>
                      )}
                    </div>
                  ))}
                  {runtimeEntries.length === 0 && (
                    <div className="text-sm text-ink-secondary">No runtime settings available.</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {configTab === 'kernel' && (
        !isTunnelActive ? (
          renderTunnelInactive('Kernel parameters')
        ) : (
          <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-ink-primary">Kernel Parameters (sysctl)</h3>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-ink-secondary">
                  <input
                    type="checkbox"
                    checked={persistKernel}
                    onChange={(event) => setPersistKernel(event.target.checked)}
                  />
                  Persist changes
                </label>
                <button
                  className="px-3 py-1.5 text-xs border border-border-subtle text-ink-secondary hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                  onClick={() => refetchKernel()}
                  disabled={isKernelFetching}
                >
                  Refresh
                </button>
                <button
                  className="px-3 py-1.5 text-xs bg-accent-primary text-white disabled:opacity-60 focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
                  onClick={() => updateKernelMutation.mutate(kernelDraft)}
                  disabled={updateKernelMutation.isPending || isKernelLoading}
                >
                  Save Changes
                </button>
              </div>
            </div>
            {kernelError && (
              <div className="text-sm text-ink-primary border-l-2 border-l-ac-red pl-2">Failed to load kernel config.</div>
            )}
            <table className="w-full text-sm">
              <thead className="bg-surface-inset text-ink-secondary border-b border-ac-blue/20">
                <tr className="text-left">
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
                        className="w-full border border-border-subtle bg-surface-subtle px-2 py-1 text-sm font-mono text-ink-primary"
                        value={value ?? ''}
                        aria-label={`Value for ${key}`}
                        onChange={(event) =>
                          setKernelDraft((current) => ({ ...current, [key]: event.target.value }))
                        }
                      />
                    </td>
                  </tr>
                ))}
                {Object.keys(kernelDraft).length === 0 && !isKernelLoading && (
                  <tr>
                    <td className="py-4 text-sm text-ink-secondary" colSpan={2}>
                      No kernel parameters available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )
      )}

      {configTab === 'history' && (
        <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Recent Configuration Changes</h3>
          {isHistoryLoading ? (
            <ConfigPanelSkeleton />
          ) : historyError ? (
            <div className="flex flex-col items-center justify-center py-8 gap-3">
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(historyError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchHistory()}
                disabled={isHistoryFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isHistoryFetching ? 'animate-spin' : ''}`} />
                {isHistoryFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : configHistoryEntries.length === 0 ? (
            <div className="text-sm text-ink-secondary">No configuration changes recorded yet.</div>
          ) : (
            <div className="space-y-4">
              {configHistoryEntries.map((entry: any) => (
                <div key={entry.id} className="flex items-center justify-between p-3 bg-surface-subtle">
                  <div>
                    <div className="text-sm font-medium text-ink-primary">{entry.change}</div>
                    <div className="text-xs text-ink-secondary">{entry.date} • {entry.status}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ======================== Helper Components ========================

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between">
      <dt className="text-ink-secondary">{label}</dt>
      <dd className="text-ink-primary font-mono text-xs">{value}</dd>
    </div>
  );
}

function ActionButton({ icon: Icon, label, onClick }: { icon: LucideIcon; label: string; onClick?: () => void }) {
  return (
    <button
      onClick={onClick}
      className="group flex items-center gap-2 px-4 py-3 bg-surface-subtle border border-border-subtle hover:border-ac-blue/60 hover:bg-surface-card transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
    >
      <Icon className="w-4 h-4 text-ac-blue group-hover:text-ac-magenta transition-colors" />
      <span className="text-xs uppercase tracking-[0.2em] text-ink-secondary group-hover:text-ink-primary">
        {label}
      </span>
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
