import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { ResourceBarGroup } from '../../components/fleet/ResourceBar';
import { useFleetMetrics, useSensors } from '../../hooks/fleet';
import { apiFetch } from '../../lib/api';
import { Box, SectionHeader, Stack, alpha, colors } from '@/ui';

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
  return apiFetch<HealthSummary>('/fleet/health');
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
  const onlineSensors = useMemo(() => sensors.filter((s) => s.status !== 'offline'), [sensors]);

  // Memoize average CPU calculation
  const avgCpu = useMemo(
    () =>
      onlineSensors.length > 0
        ? onlineSensors.reduce((sum, s) => sum + s.cpu, 0) / onlineSensors.length
        : 0,
    [onlineSensors],
  );

  // Memoize average memory calculation
  const avgMemory = useMemo(
    () =>
      onlineSensors.length > 0
        ? onlineSensors.reduce((sum, s) => sum + s.memory, 0) / onlineSensors.length
        : 0,
    [onlineSensors],
  );

  // Memoize critical sensors
  const criticalSensors = useMemo(
    () => sensors.filter((s) => s.status === 'offline' || s.cpu > 90 || s.memory > 90),
    [sensors],
  );

  // Memoize warning sensors
  const warningSensors = useMemo(
    () =>
      sensors.filter(
        (s) =>
          s.status === 'warning' ||
          (s.cpu > 75 && s.cpu <= 90) ||
          (s.memory > 75 && s.memory <= 90),
      ),
    [sensors],
  );

  // Memoize health score
  const healthScore = useMemo(
    () =>
      metrics ? Math.round((metrics.onlineCount / Math.max(metrics.totalSensors, 1)) * 100) : 0,
    [metrics],
  );
  const healthColor =
    healthScore >= 90 ? colors.green : healthScore >= 70 ? colors.orange : colors.red;

  return (
    <div className="space-y-6 p-6">
      <SectionHeader
        title="Fleet Health"
        description="Monitor the health and performance of your sensor fleet"
      />

      {/* Health Score */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <Box
          bg="card"
          border="left"
          borderColor={healthColor}
          p="lg"
          style={{ gridColumn: 'span 2 / span 2' }}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-ink-secondary">Overall Health Score</p>
              <p className="mt-2 text-5xl font-light" style={{ color: healthColor }}>
                {healthScore}%
              </p>
            </div>
            <div className="w-20 h-20 flex items-center justify-center border border-border-subtle">
              {healthScore >= 90 ? (
                <CheckCircle2
                  aria-hidden="true"
                  className="w-8 h-8"
                  style={{ color: colors.green }}
                />
              ) : healthScore >= 70 ? (
                <AlertTriangle
                  aria-hidden="true"
                  className="w-8 h-8"
                  style={{ color: colors.orange }}
                />
              ) : (
                <XCircle aria-hidden="true" className="w-8 h-8" style={{ color: colors.red }} />
              )}
            </div>
          </div>
        </Box>

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
        <Box bg="card" border="top" borderColor={colors.blue} p="lg">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Fleet Resource Usage</h3>
          <ResourceBarGroup cpu={avgCpu} memory={avgMemory} disk={35} size="lg" />
        </Box>

        <Box bg="card" border="top" borderColor={colors.navy} p="lg">
          <h3 className="text-lg font-medium text-ink-primary mb-4">Status Distribution</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Stack direction="row" align="center" gap="smPlus">
                <div className="w-4 h-4" style={{ background: colors.green }} />
                <span className="text-sm text-ink-secondary">Online</span>
              </Stack>
              <span className="text-sm font-medium" style={{ color: colors.green }}>
                {metrics?.onlineCount ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <Stack direction="row" align="center" gap="smPlus">
                <div className="w-4 h-4" style={{ background: colors.orange }} />
                <span className="text-sm text-ink-secondary">Warning</span>
              </Stack>
              <span className="text-sm font-medium" style={{ color: colors.orange }}>
                {metrics?.warningCount ?? 0}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <Stack direction="row" align="center" gap="smPlus">
                <div className="w-4 h-4" style={{ background: colors.gray.mid }} />
                <span className="text-sm text-ink-secondary">Offline</span>
              </Stack>
              <span className="text-sm font-medium" style={{ color: colors.red }}>
                {metrics?.offlineCount ?? 0}
              </span>
            </div>
          </div>
        </Box>
      </div>

      {/* Sensors Requiring Attention */}
      {criticalSensors.length > 0 && (
        <Box bg="card" border="top" borderColor={colors.red} p="lg">
          <h3 className="text-lg font-medium mb-4" style={{ color: colors.red }}>
            Critical Issues ({criticalSensors.length})
          </h3>
          <div className="space-y-3">
            {criticalSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 cursor-pointer focus:outline-none focus:ring-2"
                style={{
                  border: `1px solid ${alpha(colors.red, 0.3)}`,
                  background: alpha(colors.red, 0.1),
                }}
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigate(`/fleet/sensors/${sensor.id}`);
                  }
                }}
                tabIndex={0}
                role="link"
                aria-label={`View critical sensor ${sensor.name}`}
              >
                <Stack direction="row" align="center" gap="md">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-ink-primary">{sensor.name}</span>
                </Stack>
                <div className="text-sm text-ink-secondary">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </Box>
      )}

      {/* Warning Sensors */}
      {warningSensors.length > 0 && (
        <Box bg="card" border="top" borderColor={colors.orange} p="lg">
          <h3 className="text-lg font-medium mb-4" style={{ color: colors.orange }}>
            Warnings ({warningSensors.length})
          </h3>
          <div className="space-y-3">
            {warningSensors.slice(0, 5).map((sensor) => (
              <div
                key={sensor.id}
                className="flex items-center justify-between p-3 cursor-pointer focus:outline-none focus:ring-2"
                style={{
                  border: `1px solid ${alpha(colors.orange, 0.3)}`,
                  background: alpha(colors.orange, 0.1),
                }}
                onClick={() => navigate(`/fleet/sensors/${sensor.id}`)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    navigate(`/fleet/sensors/${sensor.id}`);
                  }
                }}
                tabIndex={0}
                role="link"
                aria-label={`View warning sensor ${sensor.name}`}
              >
                <Stack direction="row" align="center" gap="md">
                  <SensorStatusBadge status={sensor.status} />
                  <span className="font-medium text-ink-primary">{sensor.name}</span>
                </Stack>
                <div className="text-sm text-ink-secondary">
                  CPU: {sensor.cpu.toFixed(1)}% | Memory: {sensor.memory.toFixed(1)}%
                </div>
              </div>
            ))}
          </div>
        </Box>
      )}

      {/* All Healthy */}
      {criticalSensors.length === 0 && warningSensors.length === 0 && sensors.length > 0 && (
        <Box
          bg="card"
          border="top"
          borderColor={colors.green}
          p="lg"
          style={{ textAlign: 'center' }}
        >
          <div className="flex items-center justify-center mb-2">
            <CheckCircle2
              aria-hidden="true"
              className="w-10 h-10"
              style={{ color: colors.green }}
            />
          </div>
          <h3 className="text-lg font-medium" style={{ color: colors.green }}>
            All Systems Healthy
          </h3>
          <p className="text-sm text-ink-secondary mt-1">
            All {sensors.length} sensors are operating normally
          </p>
        </Box>
      )}
    </div>
  );
}
