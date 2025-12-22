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
        <h1 className="text-3xl font-bold text-gray-900">Fleet Health</h1>
        <p className="mt-1 text-sm text-gray-600">
          Monitor the health and performance of your sensor fleet
        </p>
      </div>

      {/* Health Score */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <div className="bg-white border border-gray-200 p-6 md:col-span-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Overall Health Score</p>
              <p className="mt-2 text-5xl font-bold text-gray-900">{healthScore}%</p>
            </div>
            <div
              className={`w-20 h-20 flex items-center justify-center text-white text-2xl font-bold ${
                healthScore >= 90 ? 'bg-green-500' : healthScore >= 70 ? 'bg-yellow-500' : 'bg-red-500'
              }`}
            >
              {healthScore >= 90 ? '✓' : healthScore >= 70 ? '!' : '✕'}
            </div>
          </div>
        </div>

        <MetricCard
          label="Critical Alerts"
          value={health?.criticalAlerts ?? criticalSensors.length}
          className={criticalSensors.length > 0 ? 'border-red-300 bg-red-50' : ''}
        />
        <MetricCard
          label="Warnings"
          value={health?.warningAlerts ?? warningSensors.length}
          className={warningSensors.length > 0 ? 'border-yellow-300 bg-yellow-50' : ''}
        />
      </div>

      {/* Resource Usage */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="bg-white border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Fleet Resource Usage</h3>
          <ResourceBarGroup cpu={avgCpu} memory={avgMemory} disk={35} size="lg" />
        </div>

        <div className="bg-white border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Status Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-green-500" />
                <span className="text-sm text-gray-700">Online</span>
              </div>
              <span className="text-sm font-medium text-gray-900">{metrics?.onlineCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-yellow-500" />
                <span className="text-sm text-gray-700">Warning</span>
              </div>
              <span className="text-sm font-medium text-gray-900">{metrics?.warningCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-gray-400" />
                <span className="text-sm text-gray-700">Offline</span>
              </div>
              <span className="text-sm font-medium text-gray-900">{metrics?.offlineCount ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Sensors Requiring Attention */}
      {criticalSensors.length > 0 && (
        <div className="bg-white border border-red-200 p-6">
          <h3 className="text-lg font-semibold text-red-700 mb-4">
            Critical Issues ({criticalSensors.length})
          </h3>
          <div className="space-y-3">
            {criticalSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 bg-red-50 cursor-pointer hover:bg-red-100"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
              >
                <div className="flex items-center gap-4">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-gray-900">{sensor.name}</span>
                </div>
                <div className="text-sm text-gray-600">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Warning Sensors */}
      {warningSensors.length > 0 && (
        <div className="bg-white border border-yellow-200 p-6">
          <h3 className="text-lg font-semibold text-yellow-700 mb-4">
            Warnings ({warningSensors.length})
          </h3>
          <div className="space-y-3">
            {warningSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 bg-yellow-50 cursor-pointer hover:bg-yellow-100"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
              >
                <div className="flex items-center gap-4">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-gray-900">{sensor.name}</span>
                </div>
                <div className="text-sm text-gray-600">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Healthy */}
      {criticalSensors.length === 0 && warningSensors.length === 0 && sensors.length > 0 && (
        <div className="bg-green-50 border border-green-200 p-6 text-center">
          <div className="text-green-600 text-4xl mb-2">✓</div>
          <h3 className="text-lg font-semibold text-green-700">All Systems Healthy</h3>
          <p className="text-sm text-green-600 mt-1">
            All {sensors.length} sensors are operating normally
          </p>
        </div>
      )}
    </div>
  );
}
