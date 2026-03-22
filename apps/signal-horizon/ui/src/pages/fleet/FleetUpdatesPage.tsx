import { useCallback, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { useSensors } from '../../hooks/fleet';
import { 
  Button, 
  SectionHeader, 
  Stack, 
  alpha, 
  colors,
  Box,
  Text,
  StatusBadge,
  CARD_HEADER_TITLE_STYLE,
  PAGE_TITLE_STYLE
} from '@/ui';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = { Authorization: `Bearer ${API_KEY}` };

interface SensorVersion {
  sensorId: string;
  name: string;
  currentVersion: string;
  targetVersion?: string;
  updateStatus: 'up_to_date' | 'update_available' | 'updating' | 'failed';
  lastUpdated?: string;
}

interface AvailableUpdate {
  version: string;
  releaseDate: string;
  changelog: string[];
  critical: boolean;
}

async function fetchVersions(): Promise<SensorVersion[]> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/updates/versions`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch versions');
  return response.json();
}

async function fetchAvailableUpdates(): Promise<AvailableUpdate[]> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/updates/available`, {
    headers: authHeaders,
  });
  if (!response.ok) throw new Error('Failed to fetch updates');
  return response.json();
}

async function triggerUpdate(sensorIds: string[], version: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/updates/trigger`, {
    method: 'POST',
    headers: { ...authHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify({ sensorIds, version }),
  });
  if (!response.ok) throw new Error('Failed to trigger update');
}

export function FleetUpdatesPage() {
  const queryClient = useQueryClient();
  const [selectedSensors, setSelectedSensors] = useState<Set<string>>(new Set());
  const [targetVersion, setTargetVersion] = useState<string>('');

  const { data: sensors = [] } = useSensors();

  const { data: versions = [] } = useQuery({
    queryKey: ['fleet', 'updates', 'versions'],
    queryFn: fetchVersions,
    refetchInterval: 30000,
  });

  const { data: availableUpdates = [] } = useQuery({
    queryKey: ['fleet', 'updates', 'available'],
    queryFn: fetchAvailableUpdates,
  });

  const updateMutation = useMutation({
    mutationFn: () => triggerUpdate(Array.from(selectedSensors), targetVersion),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'updates'] });
      setSelectedSensors(new Set());
    },
  });

  const toggleSensor = useCallback((sensorId: string) => {
    setSelectedSensors((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(sensorId)) newSet.delete(sensorId);
      else newSet.add(sensorId);
      return newSet;
    });
  }, []);

  // Single-pass optimization for sensor versions + status counts
  const { sensorVersions, statusCounts } = useMemo(() => {
    const merged = sensors.map((sensor) => {
      const version = versions.find((v) => v.sensorId === sensor.id);
      return {
        ...sensor,
        currentVersion: version?.currentVersion ?? sensor.version,
        updateStatus: version?.updateStatus ?? 'up_to_date',
        lastUpdated: version?.lastUpdated,
      };
    });

    const counts = merged.reduce(
      (acc, s) => {
        acc[s.updateStatus]++;
        return acc;
      },
      { up_to_date: 0, update_available: 0, updating: 0, failed: 0 },
    );

    return {
      sensorVersions: merged,
      statusCounts: {
        upToDate: counts.up_to_date,
        needsUpdate: counts.update_available,
        updating: counts.updating,
        failed: counts.failed,
      },
    };
  }, [sensors, versions]);

  const { upToDate, needsUpdate, updating, failed } = statusCounts;

  const statusTypeMap: Record<SensorVersion['updateStatus'], 'success' | 'warning' | 'info' | 'error'> = {
    up_to_date: 'success',
    update_available: 'warning',
    updating: 'info',
    failed: 'error',
  };

  const statusLabels = {
    up_to_date: 'Up to Date',
    update_available: 'Update Available',
    updating: 'Updating...',
    failed: 'Update Failed',
  };

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          title="Fleet Updates"
          description="Manage sensor firmware and software updates"
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            <Button
              onClick={() => updateMutation.mutate()}
              disabled={selectedSensors.size === 0 || !targetVersion || updateMutation.isPending}
              size="lg"
            >
              {updateMutation.isPending ? 'Updating...' : `Update Selected (${selectedSensors.size})`}
            </Button>
          }
        />

        {/* Status Overview */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
          <MetricCard label="Up to Date" value={upToDate} />
          <MetricCard label="Needs Update" value={needsUpdate} />
          <MetricCard label="Updating" value={updating} />
          <MetricCard label="Failed" value={failed} />
        </div>

        {/* Available Updates */}
        {availableUpdates.length > 0 && (
          <Box bg="card" border="subtle" p="lg">
            <Text variant="h3" weight="medium" style={{ marginBottom: '24px' }}>Available Updates</Text>
            <Stack gap="md">
              {availableUpdates.map((update) => (
                <Box
                  key={update.version}
                  p="lg"
                  bg="surface-inset"
                  border="left"
                  borderColor={update.critical ? 'var(--ac-red)' : 'var(--border-subtle)'}
                  style={{
                    background: update.critical ? 'color-mix(in srgb, var(--ac-red), transparent 95%)' : 'var(--bg-surface-inset)',
                  }}
                >
                  <Stack direction="row" align="center" justify="space-between" style={{ marginBottom: '16px' }}>
                    <Stack direction="row" align="center" gap="md">
                      <Text variant="h3" weight="medium" noMargin>
                        Version {update.version}
                      </Text>
                      {update.critical && (
                        <Box
                          px="sm"
                          py="none"
                          style={{
                            border: '1px solid',
                            background: 'var(--ac-red-dim)',
                            color: 'var(--ac-red)',
                            borderColor: alpha(colors.red, 0.3),
                          }}
                        >
                          <Text variant="tag" style={{ fontSize: '9px' }}>Critical</Text>
                        </Box>
                      )}
                      <Text variant="caption" color="secondary" noMargin>
                        Released {new Date(update.releaseDate).toLocaleDateString()}
                      </Text>
                    </Stack>
                    <Button
                      onClick={() => setTargetVersion(update.version)}
                      variant={targetVersion === update.version ? 'primary' : 'outlined'}
                      size="sm"
                    >
                      {targetVersion === update.version ? 'Selected' : 'Select'}
                    </Button>
                  </Stack>
                  <Stack gap="xs">
                    {update.changelog.map((item, idx) => (
                      <Stack key={idx} direction="row" gap="sm" align="start">
                        <Text variant="body" color="secondary" noMargin>•</Text>
                        <Text variant="body" color="secondary" noMargin>{item}</Text>
                      </Stack>
                    ))}
                  </Stack>
                </Box>
              ))}
            </Stack>
          </Box>
        )}

        {/* Sensor Versions Table */}
        <Box bg="card" border="subtle">
          <Box p="md" border="bottom" borderColor="subtle" bg="surface-inset">
            <SectionHeader
              title="Sensor Versions"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Stack direction="row" gap="sm">
                  <Button
                    variant="outlined"
                    size="sm"
                    onClick={() =>
                      setSelectedSensors(
                        new Set(
                          sensorVersions
                            .filter((s) => s.updateStatus === 'update_available')
                            .map((s) => s.id),
                        ),
                      )
                    }
                  >
                    Select Outdated
                  </Button>
                  <Button variant="outlined" size="sm" onClick={() => setSelectedSensors(new Set())}>
                    Clear Selection
                  </Button>
                </Stack>
              }
            />
          </Box>

          <Box style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <caption className="sr-only">Fleet sensor versions and update status</caption>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Select</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Sensor</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Status</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Current Version</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Update Status</Text>
                  </th>
                  <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                    <Text variant="label" color="secondary" noMargin>Last Updated</Text>
                  </th>
                </tr>
              </thead>
              <tbody>
                {sensorVersions.map((sensor) => (
                  <tr key={sensor.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <input
                        type="checkbox"
                        checked={selectedSensors.has(sensor.id)}
                        onChange={() => toggleSensor(sensor.id)}
                        disabled={sensor.updateStatus === 'updating'}
                        className="w-4 h-4"
                        style={{ accentColor: 'var(--ac-blue)' }}
                      />
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Stack direction="row" align="center" gap="md">
                        <Text variant="body" weight="medium" noMargin>{sensor.name}</Text>
                        <Text variant="caption" color="secondary" noMargin>{sensor.region}</Text>
                      </Stack>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <SensorStatusBadge status={sensor.status} />
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="code" noMargin>{sensor.currentVersion}</Text>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <StatusBadge
                        status={statusTypeMap[sensor.updateStatus]}
                        variant="subtle"
                        size="sm"
                      >
                        {statusLabels[sensor.updateStatus]}
                      </StatusBadge>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <Text variant="body" color="secondary" noMargin>
                        {sensor.lastUpdated ? new Date(sensor.lastUpdated).toLocaleDateString() : '-'}
                      </Text>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}
