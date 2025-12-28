import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { ResourceBarGroup } from '../../components/fleet/ResourceBar';
import { useFleetMetrics, useSensors } from '../../hooks/fleet';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3003';

interface HealthSummary {
  overallScore: number;
  criticalAlerts: number;
  warningAlerts: number;
  recentIncidents: Array<{
    id: string;
    sensorId: string;
    type: string;
    message: string;
    timestamp: string;
  }>;
}

async function fetchHealthSummary(): Promise<HealthSummary> {
  const response = await fetch(`${API_BASE}/api/fleet/health`);
  if (!response.ok) throw new Error('Failed to fetch health summary');
  return response.json();
}

export function FleetHealthPage() {
  const navigate = useNavigate();
  const { data: metrics } = useFleetMetrics();
  const { data: sensors = [] } = useSensors();

  const { data: health } = useQuery({
    queryKey: ['fleet', 'health'],
    queryFn: fetchHealthSummary,
    refetchInterval: 10000,
  });

  // Memoize online sensors
  const onlineSensors = useMemo(
    () => sensors.filter((s) => s.status !== 'offline'),
    [sensors]
  );

  // Memoize average CPU calculation
  const avgCpu = useMemo(
    () => onlineSensors.length > 0
      ? onlineSensors.reduce((sum, s) => sum + s.cpu, 0) / onlineSensors.length
      : 0,
    [onlineSensors]
  );

  // Memoize average memory calculation
  const avgMemory = useMemo(
    () => onlineSensors.length > 0
      ? onlineSensors.reduce((sum, s) => sum + s.memory, 0) / onlineSensors.length
      : 0,
    [onlineSensors]
  );

  // Memoize critical sensors
  const criticalSensors = useMemo(
    () => sensors.filter((s) => s.status === 'offline' || s.cpu > 90 || s.memory > 90),
    [sensors]
  );

  // Memoize warning sensors
  const warningSensors = useMemo(
    () => sensors.filter(
      (s) => s.status === 'warning' || (s.cpu > 75 && s.cpu <= 90) || (s.memory > 75 && s.memory <= 90)
    ),
    [sensors]
  );

  // Memoize health score
  const healthScore = useMemo(
    () => metrics
      ? Math.round(((metrics.onlineCount / Math.max(metrics.totalSensors, 1)) * 100))
      : 0,
    [metrics]
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-light text-ink-primary">Fleet Health</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Monitor the health and performance of your sensor fleet
        </p>
      </div>

      {/* Health Score */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <div className="card p-6 md:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-ink-secondary">Overall Health Score</p>
              <p className="mt-2 text-5xl font-light text-ink-primary">{healthScore}%</p>
            </div>
            <div
              className={`w-20 h-20 flex items-center justify-center text-ac-white text-2xl font-semibold ${
                healthScore >= 90 ? 'bg-ac-green' : healthScore >= 70 ? 'bg-ac-orange' : 'bg-ac-red'
              }`}
            >
              {healthScore >= 90 ? '✓' : healthScore >= 70 ? '!' : '✕'}
            </div>
          </div>
        </div>

        <MetricCard
          label="Critical Alerts"
          value={health?.criticalAlerts ?? criticalSensors.length}
          className={criticalSensors.length > 0 ? 'border-ac-red/40 bg-ac-red/10' : ''}
        />
        <MetricCard
          label="Warnings"
          value={health?.warningAlerts ?? warningSensors.length}
          className={warningSensors.length > 0 ? 'border-ac-orange/40 bg-ac-orange/10' : ''}
        />
      </div>

      {/* Resource Usage */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="card p-6">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Fleet Resource Usage</h3>
          <ResourceBarGroup cpu={avgCpu} memory={avgMemory} disk={35} size="lg" />
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Status Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-green" />
                <span className="text-sm text-ink-secondary">Online</span>
              </div>
              <span className="text-sm font-medium text-ink-primary">{metrics?.onlineCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-orange" />
                <span className="text-sm text-ink-secondary">Warning</span>
              </div>
              <span className="text-sm font-medium text-ink-primary">{metrics?.warningCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-gray-mid" />
                <span className="text-sm text-ink-secondary">Offline</span>
              </div>
              <span className="text-sm font-medium text-ink-primary">{metrics?.offlineCount ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Sensors Requiring Attention */}
      {criticalSensors.length > 0 && (
        <div className="card border-ac-red/40 p-6">
          <h3 className="text-lg font-medium text-ac-red mb-4">
            Critical Issues ({criticalSensors.length})
          </h3>
          <div className="space-y-3">
            {criticalSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 bg-ac-red/10 cursor-pointer hover:bg-ac-red/15"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
              >
                <div className="flex items-center gap-4">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-ink-primary">{sensor.name}</span>
                </div>
                <div className="text-sm text-ink-secondary">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Warning Sensors */}
      {warningSensors.length > 0 && (
        <div className="card border-ac-orange/40 p-6">
          <h3 className="text-lg font-medium text-ac-orange mb-4">
            Warnings ({warningSensors.length})
          </h3>
          <div className="space-y-3">
            {warningSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 bg-ac-orange/10 cursor-pointer hover:bg-ac-orange/15"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
              >
                <div className="flex items-center gap-4">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-ink-primary">{sensor.name}</span>
                </div>
                <div className="text-sm text-ink-secondary">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Healthy */}
      {criticalSensors.length === 0 && warningSensors.length === 0 && sensors.length > 0 && (
        <div className="card border-ac-green/40 p-6 text-center">
          <div className="text-ac-green text-4xl mb-2">✓</div>
          <h3 className="text-lg font-medium text-ac-green">All Systems Healthy</h3>
          <p className="text-sm text-ink-secondary mt-1">
            All {sensors.length} sensors are operating normally
          </p>
        </div>
      )}
    </div>
  );
}
