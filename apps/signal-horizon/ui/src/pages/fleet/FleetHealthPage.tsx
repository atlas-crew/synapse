import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { CheckCircle2, AlertTriangle, XCircle, ArrowRight, Activity } from 'lucide-react';
import { MetricCard } from '../../components/fleet';
import { ResourceBar } from '../../components/fleet/ResourceBar';
import { useFleetMetrics, useSensors } from '../../hooks/fleet';
import { apiFetch } from '../../lib/api';
import type { SensorSummary } from '../../types/fleet';
import {
  Box,
  SectionHeader,
  Stack,
  Grid,
  Text,
  alpha,
  colors,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
} from '@/ui';

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
  const { data: sensors = [], isLoading: sensorsLoading } = useSensors();

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
  
  // P1-001 Fix: Distinguish between "Healthy" and "Empty"
  const isFleetHealthy = sensors.length > 0 && criticalSensors.length === 0 && warningSensors.length === 0;
  const isFleetEmpty = !sensorsLoading && sensors.length === 0;

  const healthColor = isFleetEmpty 
    ? 'var(--text-muted)' 
    : healthScore >= 90 ? 'var(--ac-green)' : healthScore >= 70 ? 'var(--ac-orange)' : 'var(--ac-red)';

  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          title="Fleet Health"
          description="Monitor the health and performance of your sensor fleet"
          titleStyle={PAGE_TITLE_STYLE}
        />

        {/* Health Score and Alert KPI Cards */}
        <Grid cols={4} gap="xl">
          <Box
            bg="card"
            border="left"
            borderColor={healthColor}
            p="lg"
            style={{ gridColumn: 'span 2 / span 2' }}
          >
            <Stack direction="row" align="center" justify="space-between">
              <Box>
                <Text variant="small" weight="medium" color="secondary">
                  Overall Health Score
                </Text>
                <Text variant="h1" weight="light" style={{ color: healthColor, marginTop: '8px' }}>
                  {isFleetEmpty ? '--' : `${healthScore}%`}
                </Text>
              </Box>
              <Box
                style={{
                  width: '80px',
                  height: '80px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: `1px solid ${alpha(colors.border.subtle, 0.5)}`,
                }}
              >
                {isFleetEmpty ? (
                  <Activity aria-hidden="true" className="w-8 h-8 text-ink-muted" />
                ) : healthScore >= 90 ? (
                  <CheckCircle2
                    aria-hidden="true"
                    className="w-8 h-8"
                    style={{ color: 'var(--ac-green)' }}
                  />
                ) : healthScore >= 70 ? (
                  <AlertTriangle
                    aria-hidden="true"
                    className="w-8 h-8"
                    style={{ color: 'var(--ac-orange)' }}
                  />
                ) : (
                  <XCircle aria-hidden="true" className="w-8 h-8" style={{ color: 'var(--ac-red)' }} />
                )}
              </Box>
            </Stack>
          </Box>

          <MetricCard
            label="Critical Alerts"
            value={health?.criticalAlerts ?? criticalSensors.length}
            description="Sensors offline or with CPU/memory above 90%"
            className="border-l-2 border-l-ac-red"
            labelClassName="text-ac-red"
            valueClassName="text-ac-red"
          />
          <MetricCard
            label="Warnings"
            value={health?.warningAlerts ?? warningSensors.length}
            description="Sensors with degraded status or 75-90% usage"
            className="border-l-2 border-l-ac-orange"
            labelClassName="text-ac-orange"
            valueClassName="text-ac-orange"
          />
        </Grid>

        {/* Actionable Sensor Lists or Healthy/Empty States */}
        {!isFleetHealthy && !isFleetEmpty ? (
          <Grid cols={2} gap="xl">
            {criticalSensors.length > 0 && (
              <Box bg="card" border="left" borderColor="var(--ac-red)" p="lg">
                <SectionHeader
                  title="Critical Sensors"
                  size="h4"
                  titleStyle={CARD_HEADER_TITLE_STYLE}
                  actions={criticalSensors.length > 5 && (
                    <Text variant="caption" color="secondary" style={{ cursor: 'pointer' }} onClick={() => navigate('/fleet/sensors?status=offline')}>
                      View All {criticalSensors.length}
                    </Text>
                  )}
                />
                <Stack gap="sm" style={{ marginTop: '16px' }}>
                  {/* P2-001: Added slice(0, 5) */}
                  {criticalSensors.slice(0, 5).map((s) => (
                    <SensorIssueItem key={s.id} sensor={s} colorVar="--ac-red" onClick={() => navigate(`/fleet/sensors/${s.id}`)} />
                  ))}
                </Stack>
              </Box>
            )}
            {warningSensors.length > 0 && (
              <Box bg="card" border="left" borderColor="var(--ac-orange)" p="lg">
                <SectionHeader
                  title="Warning Sensors"
                  size="h4"
                  titleStyle={CARD_HEADER_TITLE_STYLE}
                  actions={warningSensors.length > 5 && (
                    <Text variant="caption" color="secondary" style={{ cursor: 'pointer' }} onClick={() => navigate('/fleet/sensors?status=warning')}>
                      View All {warningSensors.length}
                    </Text>
                  )}
                />
                <Stack gap="sm" style={{ marginTop: '16px' }}>
                  {/* P2-001: Added slice(0, 5) */}
                  {warningSensors.slice(0, 5).map((s) => (
                    <SensorIssueItem key={s.id} sensor={s} colorVar="--ac-orange" onClick={() => navigate(`/fleet/sensors/${s.id}`)} />
                  ))}
                </Stack>
              </Box>
            )}
          </Grid>
        ) : isFleetEmpty ? (
          <Box bg="card" border="subtle" p="xl" style={{ textAlign: 'center' }}>
            <Stack align="center" gap="md">
              <Activity size={48} className="text-ink-muted" />
              <Box>
                <Text variant="h3" weight="semibold">No Sensors Detected</Text>
                <Text variant="body" color="secondary">Deploy your first sensor to start monitoring fleet health.</Text>
              </Box>
            </Stack>
          </Box>
        ) : (
          <Box bg="card" border="all" borderColor="var(--ac-green)" p="xl" style={{ textAlign: 'center' }}>
            <Stack align="center" gap="md">
              <CheckCircle2 size={48} style={{ color: 'var(--ac-green)' }} />
              <Box>
                <Text variant="h3" weight="semibold">All Systems Healthy</Text>
                <Text variant="body" color="secondary">No critical or warning sensors detected in the fleet.</Text>
              </Box>
            </Stack>
          </Box>
        )}

        {/* Resource Usage */}
        <Grid cols={2} gap="xl">
          <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
            <SectionHeader
              title="CPU Allocation"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
            />
            <Box style={{ marginTop: '24px' }}>
              <ResourceBar
                label="Average CPU Load"
                value={avgCpu}
              />
            </Box>
          </Box>

          <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
            <SectionHeader
              title="Memory Allocation"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
            />
            <Box style={{ marginTop: '24px' }}>
              <ResourceBar
                label="Average Memory Usage"
                value={avgMemory}
              />
            </Box>
          </Box>
        </Grid>

        {/* Recent Incidents */}
        <Box bg="card" border="top" borderColor="var(--ac-purple)" p="lg">
          <SectionHeader
            title="Recent Health Incidents"
            size="h4"
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
          <Box style={{ marginTop: '16px' }}>
            <Stack gap="sm">
              {(health?.recentIncidents || []).length === 0 ? (
                <Text variant="small" color="secondary" style={{ textAlign: 'center', padding: '32px 0' }}>
                  No recent health incidents detected
                </Text>
              ) : (
                health?.recentIncidents.map((incident) => (
                  <Box
                    key={incident.id}
                    p="md"
                    bg="surface-subtle"
                    className="hover:bg-surface-inset transition-colors"
                  >
                    <Stack direction="row" gap="md" align="center">
                      <XCircle size={18} style={{ color: 'var(--ac-red)' }} />
                      <Box style={{ flex: 1 }}>
                        <Text variant="body" weight="medium">
                          {incident.type}
                        </Text>
                        <Text variant="small" color="secondary">
                          Sensor: {incident.sensorId} • {incident.message}
                        </Text>
                      </Box>
                      <Text variant="small" color="secondary">
                        {new Date(incident.timestamp).toLocaleTimeString()}
                      </Text>
                    </Stack>
                  </Box>
                ))
              )}
            </Stack>
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}

function SensorIssueItem({ sensor, colorVar, onClick }: { sensor: SensorSummary; colorVar: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: '100%',
        textAlign: 'left',
        background: 'var(--bg-surface-subtle)',
        border: 'none',
        padding: '12px 16px',
        cursor: 'pointer',
        transition: 'background 0.2s ease',
      }}
      className="hover:bg-surface-inset group"
      aria-label={`View details for ${sensor.name}`}
    >
      <Stack direction="row" align="center" justify="space-between">
        <Box>
          <Text variant="body" weight="medium">{sensor.name}</Text>
          <Text variant="small" color="secondary">
            CPU: {sensor.cpu.toFixed(1)}% • MEM: {sensor.memory.toFixed(1)}%
          </Text>
        </Box>
        {/* P2-002 Fix: Use CSS variable for icon color to support dark mode */}
        <ArrowRight size={16} style={{ color: `var(${colorVar})` }} className="opacity-0 group-hover:opacity-100 transition-opacity" />
      </Stack>
    </button>
  );
}
