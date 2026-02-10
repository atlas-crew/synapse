import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb } from '@/ui';
import { SensorStatusBadge } from '../../components/fleet';
import { SensorDetailSkeleton } from '../../components/LoadingStates';
import { RemoteShell } from '../../components/fleet/RemoteShell';
import { FileBrowser } from '../../components/fleet/FileBrowser';
import { LogViewer } from '../../components/fleet/LogViewer';
import {
  OverviewTab,
  PerformanceTab,
  NetworkTab,
  ProcessesTab,
  ConfigurationTab,
  fetchSensorDetail,
  fetchSystemInfo,
  fetchPerformance,
  fetchNetwork,
  fetchProcesses,
  runDiagnostics,
  type TabType,
} from './sensor-detail';
import { apiFetch } from '../../lib/api';

export function SensorDetailPage() {
  useDocumentTitle('Sensor Detail');
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
    enabled: !!id && (activeTab === 'processes' || activeTab === 'overview'),
    refetchInterval: 5000,
  });

  // Mutations
  const restartMutation = useMutation({
    mutationFn: async () => {
      await apiFetch(`/fleet/sensors/${id}/actions/restart`, { method: 'POST' });
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
      <div className="p-12 text-center">
        <p className="text-status-error mb-4">{(sensorError as Error).message || 'Failed to load sensor details.'}</p>
        <button
          onClick={() => refetchSensor()}
          disabled={isSensorFetching}
          className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]"
        >
          {isSensorFetching ? 'Retrying...' : 'Retry'}
        </button>
      </div>
    );
  }

  if (!sensor) {
    return (
      <div className="p-12 text-center">
        <p className="text-ink-secondary">Sensor not found.</p>
      </div>
    );
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
