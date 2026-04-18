import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import {
  Alert,
  Breadcrumb,
  Button,
  EmptyState,
  SectionHeader,
  Stack,
  Tabs,
  Box,
  Text,
  PAGE_TITLE_STYLE,
} from '@/ui';
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

const PAGE_HEADER_STYLE = { marginBottom: 0 };

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
    enabled: !!id && (activeTab === 'overview' || activeTab === 'performance'),
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
      <Box p="3xl" style={{ textAlign: 'center' }}>
        <Alert status="error" title="Failed to load sensor details" style={{ textAlign: 'left' }}>
          {(sensorError as Error).message || 'Failed to load sensor details.'}
        </Alert>
        <Stack direction="row" justify="center" style={{ marginTop: 16 }}>
          <Button
            onClick={() => refetchSensor()}
            disabled={isSensorFetching}
            loading={isSensorFetching}
          >
            Retry
          </Button>
        </Stack>
      </Box>
    );
  }

  if (!sensor) {
    return (
      <EmptyState
        title="Sensor Not Found"
        description="The requested sensor could not be located. It may have been deleted or you may not have access."
        action={
          <Button variant="outlined" onClick={() => navigate('/fleet')}>
            Back to Fleet
          </Button>
        }
      />
    );
  }

  const status =
    sensor.connectionState === 'CONNECTED'
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
  const tabOptions = tabs.map((tab) => ({ key: tab.key, label: tab.label }));
  const isTabType = (key: string): key is TabType => tabs.some((tab) => tab.key === key);

  return (
    <Box p="xl">
      <Stack gap="xl">
        <Breadcrumb
          items={[{ label: 'Fleet', to: '/fleet' }, { label: sensor.name || 'Sensor Detail' }]}
        />
        
        {/* Header */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)">
          <Box p="lg" bg="surface-inset">
            <Stack
              direction="row"
              align="start"
              justify="space-between"
              gap="lg"
              wrap
            >
              <Stack gap="sm">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => navigate('/fleet')}
                  icon={
                    <span aria-hidden="true" style={{ color: 'var(--text-muted)' }}>
                      ←
                    </span>
                  }
                  style={{ width: 'fit-content' }}
                >
                  Back to Fleet
                </Button>
                {/* Restored correct page-level title size via variant="h2" */}
                <SectionHeader
                  title={sensor.name}
                  size="h2"
                  style={PAGE_HEADER_STYLE}
                  titleStyle={PAGE_TITLE_STYLE}
                />
                <Stack direction="row" align="center" gap="md" wrap>
                  <SensorStatusBadge status={status} />
                  <Text variant="caption" color="secondary" style={{ letterSpacing: '0.18em' }}>
                    ID {sensor.id.slice(0, 8)}...
                  </Text>
                  <Text variant="caption" color="secondary" style={{ letterSpacing: '0.18em' }}>
                    v{sensor.version}
                  </Text>
                  <Text variant="caption" color="secondary" style={{ letterSpacing: '0.18em' }}>
                    {sensor.region}
                  </Text>
                </Stack>
              </Stack>
              <Stack direction="row" gap="sm" wrap>
                <Button
                  variant="outlined"
                  onClick={() => diagnosticsMutation.mutate()}
                  disabled={diagnosticsMutation.isPending}
                >
                  {diagnosticsMutation.isPending ? 'Running...' : 'Run Diagnostics'}
                </Button>
                <Button onClick={() => restartMutation.mutate()} disabled={restartMutation.isPending}>
                  {restartMutation.isPending ? 'Restarting...' : 'Restart Sensor'}
                </Button>
              </Stack>
            </Stack>
          </Box>
        </Box>

        {/* Tabs and Content */}
        <Box bg="card" border="top" borderColor="var(--ac-navy)">
          <Box px="lg" py="sm" bg="surface-inset" border="bottom" borderColor="subtle">
            <Tabs
              tabs={tabOptions}
              active={activeTab}
              onChange={(key) => {
                if (isTabType(key)) setActiveTab(key);
              }}
              size="sm"
              ariaLabel="Sensor details"
              idPrefix="tab-"
              panelIdPrefix="tabpanel-"
            />
          </Box>
          <Box id={`tabpanel-${activeTab}`} p="lg">
            {activeTab === 'overview' && (
              <OverviewTab
                sensor={sensor}
                systemInfo={systemInfo}
                performance={performance}
                diagnostics={diagnosticsMutation.data}
                onRestartSensor={() => restartMutation.mutate()}
              />
            )}
            {activeTab === 'performance' && <PerformanceTab data={performance} />}
            {activeTab === 'network' && <NetworkTab data={network} />}
            {activeTab === 'processes' && <ProcessesTab data={processes} />}
            {activeTab === 'logs' && (
              <LogViewer sensorId={sensor.id} sensorName={sensor.name} height="600px" />
            )}
            {activeTab === 'configuration' && <ConfigurationTab sensor={sensor} />}
            {activeTab === 'remote-shell' && (
              <Box style={{ height: 600 }}>
                <RemoteShell sensorId={id!} sensorName={sensor.name} />
              </Box>
            )}
            {activeTab === 'files' && (
              <Box style={{ height: 600 }}>
                <FileBrowser sensorId={id!} sensorName={sensor.name} height="100%" />
              </Box>
            )}
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}
