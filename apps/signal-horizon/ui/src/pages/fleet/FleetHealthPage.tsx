import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { ResourceBarGroup } from '../../components/fleet/ResourceBar';
import { useFleetMetrics, useSensors } from '../../hooks/fleet';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

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
  const response = await fetch(`${API_BASE}/api/v1/fleet/health`, {
    headers: { 'Authorization': `Bearer ${API_KEY}` },
  });
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
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-light text-ink-primary">Fleet Health</h1>
        <p className="mt-1 text-sm text-ink-secondary">
          Monitor the health and performance of your sensor fleet
        </p>
      </div>

      {/* Health Score */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <div className={`card border border-border-subtle border-l-2 p-6 md:col-span-2 ${
          healthScore >= 90 ? 'border-l-ac-green' : healthScore >= 70 ? 'border-l-ac-orange' : 'border-l-ac-red'
        }`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-ink-secondary">Overall Health Score</p>
              <p className={`mt-2 text-5xl font-light ${
                healthScore >= 90 ? 'text-ac-green' : healthScore >= 70 ? 'text-ac-orange' : 'text-ac-red'
              }`}>{healthScore}%</p>
            </div>
            <div className="w-20 h-20 flex items-center justify-center border border-border-subtle">
              {healthScore >= 90 ? (
                <CheckCircle2 className="w-8 h-8 text-ac-green" />
              ) : healthScore >= 70 ? (
                <AlertTriangle className="w-8 h-8 text-ac-orange" />
              ) : (
                <XCircle className="w-8 h-8 text-ac-red" />
              )}
            </div>
          </div>
        </div>

        <MetricCard
          label="Critical Alerts"
          value={health?.criticalAlerts ?? criticalSensors.length}
          description="Sensors offline or with CPU/memory above 90% requiring immediate attention"
          className="border-l-2 border-l-ac-red"
          labelClassName="text-ac-red"
          valueClassName="text-ac-red"
        />
        <MetricCard
          label="Warnings"
          value={health?.warningAlerts ?? warningSensors.length}
          description="Sensors with degraded status or resource usage between 75-90%"
          className="border-l-2 border-l-ac-orange"
          labelClassName="text-ac-orange"
          valueClassName="text-ac-orange"
        />
      </div>

      {/* Resource Usage */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="card border border-border-subtle border-t-2 border-t-ac-blue dark:border-t-ac-sky-light p-6">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Fleet Resource Usage</h3>
          <ResourceBarGroup cpu={avgCpu} memory={avgMemory} disk={35} size="lg" />
        </div>

        <div className="card border border-border-subtle border-t-2 border-t-ac-navy dark:border-t-ac-sky-light p-6">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Status Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-green" />
                <span className="text-sm text-ink-secondary">Online</span>
              </div>
              <span className="text-sm font-medium text-ac-green">{metrics?.onlineCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-orange" />
                <span className="text-sm text-ink-secondary">Warning</span>
              </div>
              <span className="text-sm font-medium text-ac-orange">{metrics?.warningCount ?? 0}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-4 h-4 bg-ac-gray-mid" />
                <span className="text-sm text-ink-secondary">Offline</span>
              </div>
              <span className="text-sm font-medium text-ac-red">{metrics?.offlineCount ?? 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Sensors Requiring Attention */}
      {criticalSensors.length > 0 && (
        <div className="card border border-border-subtle border-t-2 border-t-ac-red p-6">
          <h3 className="text-lg font-medium text-ac-red mb-4">
            Critical Issues ({criticalSensors.length})
          </h3>
          <div className="space-y-3">
            {criticalSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 border border-ac-red/20 bg-ac-red/10 cursor-pointer hover:bg-ac-red/15 focus:outline-none focus:ring-2 focus:ring-ac-red/50"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/fleet/sensors/${sensor.id}`); } }}
                tabIndex={0}
                role="link"
                aria-label={`View critical sensor ${sensor.name}`}
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
        <div className="card border border-border-subtle border-t-2 border-t-ac-orange p-6">
          <h3 className="text-lg font-medium text-ac-orange mb-4">
            Warnings ({warningSensors.length})
          </h3>
          <div className="space-y-3">
            {warningSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 border border-ac-orange/20 bg-ac-orange/10 cursor-pointer hover:bg-ac-orange/15 focus:outline-none focus:ring-2 focus:ring-ac-orange/50"
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); navigate(`/fleet/sensors/${sensor.id}`); } }}
                tabIndex={0}
                role="link"
                aria-label={`View warning sensor ${sensor.name}`}
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
        <div className="card border border-border-subtle border-t-2 border-t-ac-green p-6 text-center">
          <div className="flex items-center justify-center mb-2">
            <CheckCircle2 className="w-10 h-10 text-ac-green" />
          </div>
          <h3 className="text-lg font-medium text-ac-green">All Systems Healthy</h3>
          <p className="text-sm text-ink-secondary mt-1">
            All {sensors.length} sensors are operating normally
          </p>
        </div>
      )}
    </div>
  );
}
