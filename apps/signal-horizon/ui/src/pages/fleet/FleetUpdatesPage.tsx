import { useCallback, useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { useSensors } from '../../hooks/fleet';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3003';

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
  const response = await fetch(`${API_BASE}/api/fleet/updates/versions`);
  if (!response.ok) throw new Error('Failed to fetch versions');
  return response.json();
}

async function fetchAvailableUpdates(): Promise<AvailableUpdate[]> {
  const response = await fetch(`${API_BASE}/api/fleet/updates/available`);
  if (!response.ok) throw new Error('Failed to fetch updates');
  return response.json();
}

async function triggerUpdate(sensorIds: string[], version: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/fleet/updates/trigger`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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
      { up_to_date: 0, update_available: 0, updating: 0, failed: 0 }
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

  const statusColors = {
    up_to_date: 'bg-ac-green/10 text-ac-green border-ac-green/30',
    update_available: 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
    updating: 'bg-ac-blue/10 text-ac-blue border-ac-blue/30',
    failed: 'bg-ac-red/10 text-ac-red border-ac-red/30',
  };

  const statusLabels = {
    up_to_date: 'Up to Date',
    update_available: 'Update Available',
    updating: 'Updating...',
    failed: 'Update Failed',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Fleet Updates</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Manage sensor firmware and software updates
          </p>
        </div>
        <button
          onClick={() => updateMutation.mutate()}
          disabled={selectedSensors.size === 0 || !targetVersion || updateMutation.isPending}
          className="btn-primary h-12 px-6 text-sm"
        >
          {updateMutation.isPending
            ? 'Updating...'
            : `Update Selected (${selectedSensors.size})`}
        </button>
      </div>

      {/* Status Overview */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard label="Up to Date" value={upToDate} className="border-ac-green/40" />
        <MetricCard
          label="Needs Update"
          value={needsUpdate}
          className={needsUpdate > 0 ? 'border-ac-orange/40' : ''}
        />
        <MetricCard
          label="Updating"
          value={updating}
          className={updating > 0 ? 'border-ac-blue/40' : ''}
        />
        <MetricCard
          label="Failed"
          value={failed}
          className={failed > 0 ? 'border-ac-red/40' : ''}
        />
      </div>

      {/* Available Updates */}
      {availableUpdates.length > 0 && (
        <div className="card p-6">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Available Updates</h3>
          <div className="space-y-4">
            {availableUpdates.map((update) => (
              <div
                key={update.version}
                className={`p-4 border ${
                  update.critical ? 'border-ac-red/40 bg-ac-red/10' : 'border-border-subtle'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <span className="text-lg font-medium text-ink-primary">
                        Version {update.version}
                      </span>
                      {update.critical && (
                        <span className="px-2 py-0.5 text-xs font-medium bg-ac-red/15 text-ac-red border border-ac-red/30">
                          Critical
                        </span>
                      )}
                    </div>
                    <div className="text-sm text-ink-muted mt-1">
                      Released {new Date(update.releaseDate).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={() => setTargetVersion(update.version)}
                    className={`px-3 py-1.5 text-sm font-medium border ${
                      targetVersion === update.version
                        ? 'bg-ac-blue text-ac-white border-ac-blue'
                        : 'border-ac-blue text-ac-blue hover:bg-ac-blue hover:text-ac-white'
                    }`}
                  >
                    {targetVersion === update.version ? 'Selected' : 'Select'}
                  </button>
                </div>
                <ul className="mt-3 space-y-1">
                  {update.changelog.map((item, idx) => (
                    <li key={idx} className="text-sm text-ink-secondary flex items-start gap-2">
                      <span className="text-ink-muted">•</span>
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sensor Versions Table */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-medium text-ink-primary">Sensor Versions</h2>
          <div className="flex gap-2">
            <button
              onClick={() =>
                setSelectedSensors(
                  new Set(
                    sensorVersions
                      .filter((s) => s.updateStatus === 'update_available')
                      .map((s) => s.id)
                  )
                )
              }
              className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle"
            >
              Select Outdated
            </button>
            <button
              onClick={() => setSelectedSensors(new Set())}
              className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle"
            >
              Clear Selection
            </button>
          </div>
        </div>

        <table className="min-w-full divide-y divide-border-subtle">
          <thead className="bg-surface-subtle">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Select
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Sensor
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Current Version
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Update Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                Last Updated
              </th>
            </tr>
          </thead>
          <tbody className="bg-surface-base divide-y divide-border-subtle">
            {sensorVersions.map((sensor) => (
              <tr key={sensor.id} className="hover:bg-surface-subtle">
                <td className="px-6 py-4">
                  <input
                    type="checkbox"
                    checked={selectedSensors.has(sensor.id)}
                    onChange={() => toggleSensor(sensor.id)}
                    disabled={sensor.updateStatus === 'updating'}
                    className="w-4 h-4 text-ac-blue border-border-subtle disabled:opacity-50"
                  />
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-3">
                    <span className="font-medium text-ink-primary">{sensor.name}</span>
                    <span className="text-sm text-ink-muted">{sensor.region}</span>
                  </div>
                </td>
                <td className="px-6 py-4">
                  <SensorStatusBadge status={sensor.status} />
                </td>
                <td className="px-6 py-4 text-sm text-ink-primary font-mono">
                  {sensor.currentVersion}
                </td>
                <td className="px-6 py-4">
                  <span
                    className={`px-2 py-1 text-xs font-medium border ${statusColors[sensor.updateStatus]}`}
                  >
                    {statusLabels[sensor.updateStatus]}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-ink-muted">
                  {sensor.lastUpdated
                    ? new Date(sensor.lastUpdated).toLocaleDateString()
                    : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
