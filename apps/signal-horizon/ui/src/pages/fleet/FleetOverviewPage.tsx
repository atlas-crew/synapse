import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { MetricCard, SensorTable } from '../../components/fleet';
import { useFleetMetrics, useSensors } from '../../hooks/fleet';
import type { SensorSummary } from '../../types/fleet';

export function FleetOverviewPage() {
  const navigate = useNavigate();
  const { data: metrics, isLoading: metricsLoading } = useFleetMetrics();
  const { data: sensors = [], isLoading: sensorsLoading } = useSensors();

  const handleSensorClick = useCallback((sensor: SensorSummary) => {
    navigate(`/fleet/sensors/${sensor.id}`);
  }, [navigate]);

  if (metricsLoading || sensorsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-ink-muted">Loading fleet data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-light text-ink-primary">Fleet Overview</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Monitor and manage your distributed sensor infrastructure
        </p>
      </div>

      {/* Status Cards */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
        <MetricCard label="Total Sensors" value={metrics?.totalSensors ?? 0} />
        <MetricCard label="Online" value={metrics?.onlineCount ?? 0} />
        <MetricCard label="Warning" value={metrics?.warningCount ?? 0} />
        <MetricCard label="Offline" value={metrics?.offlineCount ?? 0} />
      </div>

      {/* Aggregate Metrics */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <MetricCard
          label="Total Requests/sec"
          value={metrics?.totalRps.toLocaleString() ?? '0'}
        />
        <MetricCard
          label="Average Latency"
          value={`${metrics?.avgLatencyMs.toFixed(0) ?? '0'}ms`}
        />
      </div>

      {/* Sensor Table */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle">
          <h2 className="text-lg font-medium text-ink-primary">Sensor Fleet</h2>
        </div>
        <SensorTable sensors={sensors} onSensorClick={handleSensorClick} />
      </div>
    </div>
  );
}
