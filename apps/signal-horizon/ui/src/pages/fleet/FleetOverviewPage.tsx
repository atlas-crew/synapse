import { useState, useCallback, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { useQuery } from '@tanstack/react-query';
import {
  CheckCircle,
  AlertTriangle,
  XCircle,
  Zap,
  Search,
  Shield,
  Settings,
  Globe,
  type LucideIcon,
} from 'lucide-react';
import { SensorTable } from '../../components/fleet/SensorTable';
import { FleetOverviewSkeleton } from '../../components/LoadingStates';
import { useFleetStore } from '../../stores/fleetStore';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';
import type { SensorSummary } from '../../types/fleet';
import { useRelativeTime } from '../../hooks/useRelativeTime';
import { apiFetch } from '../../lib/api';
import {
  Box,
  Button,
  Input,
  KpiStrip,
  SectionHeader,
  Select,
  Stack,
  Grid,
  Text,
  PAGE_TITLE_STYLE,
  CARD_HEADER_TITLE_STYLE,
} from '@/ui';

interface FleetOverview {
  summary: {
    totalSensors: number;
    onlineCount: number;
    warningCount: number;
    offlineCount: number;
    healthScore: number;
  };
  fleetMetrics: {
    totalRps: number;
    avgLatency: number;
    avgCpu: number;
    avgMemory: number;
  };
  regionDistribution: Array<{
    region: string;
    online: number;
    warning: number;
    offline: number;
    total: number;
  }>;
  recentAlerts: Array<{
    id: string;
    sensorName: string;
    type: string;
    error: string | null;
    createdAt: string;
  }>;
}

async function fetchFleetOverview(): Promise<FleetOverview> {
  return apiFetch<FleetOverview>('/fleet/overview');
}

async function fetchSensors(): Promise<SensorSummary[]> {
  const data = await apiFetch<any>('/fleet/sensors');
  return data.sensors.map((s: any) => ({
    id: s.id,
    name: s.name,
    status:
      s.connectionState === 'CONNECTED'
        ? 'online'
        : s.connectionState === 'RECONNECTING'
          ? 'warning'
          : 'offline',
    cpu: s.metadata?.cpu ?? 0,
    memory: s.metadata?.memory ?? 0,
    rps: s.metadata?.rps ?? 0,
    latencyMs: s.metadata?.latency ?? 0,
    version: s.version,
    region: s.region,
  }));
}

export function FleetOverviewPage() {
  useDocumentTitle('Fleet Overview');
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const { filters, setStatusFilter } = useFleetStore();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);
  const lastUpdatedText = useRelativeTime(lastUpdated);

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['fleet', 'overview', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        const demoData = getDemoData(scenario);
        return demoData.fleet.overview as FleetOverview;
      }
      return fetchFleetOverview();
    },
    refetchInterval: isDemoMode ? false : 10000,
    staleTime: isDemoMode ? Infinity : 9000,
  });

  const { data: sensors = [], isLoading: sensorsLoading } = useQuery({
    queryKey: ['fleet', 'sensors', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        const demoData = getDemoData(scenario);
        return demoData.fleet.sensors as SensorSummary[];
      }
      return fetchSensors();
    },
    refetchInterval: isDemoMode ? false : 5000,
    staleTime: isDemoMode ? Infinity : 4000,
  });

  // Track when data finishes loading
  useEffect(() => {
    if (!overviewLoading && !sensorsLoading && (overview || sensors.length > 0)) {
      setLastUpdated(Date.now());
    }
  }, [overviewLoading, sensorsLoading, overview, sensors.length]);

  const filteredSensors = sensors.filter((s) => {
    if (searchQuery && !s.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    if (filters.status && s.status !== filters.status) return false;
    if (filters.region && s.region !== filters.region) return false;
    return true;
  });

  const handleSensorClick = useCallback(
    (sensor: SensorSummary) => {
      navigate(`/fleet/sensors/${sensor.id}`);
    },
    [navigate],
  );

  const handleConfigureClick = useCallback(
    (sensor: SensorSummary) => {
      navigate(`/fleet/sensors/${sensor.id}/config`);
    },
    [navigate],
  );

  if (overviewLoading || sensorsLoading) {
    return (
      <Box p="xl">
        <FleetOverviewSkeleton />
      </Box>
    );
  }

  const summary = overview?.summary || {
    totalSensors: 0,
    onlineCount: 0,
    warningCount: 0,
    offlineCount: 0,
    healthScore: 100,
  };
  const fleetMetrics = overview?.fleetMetrics || {
    totalRps: 0,
    avgLatency: 0,
    avgCpu: 0,
    avgMemory: 0,
  };
  const headerDescription = `Sensor Fleet Command & Health Monitoring${
    lastUpdatedText ? ` · Updated ${lastUpdatedText}` : ''
  }`;

  const kpiMetrics = [
    {
      label: 'Sensors Online',
      value: formatNumber(summary.onlineCount),
      subtitle: 'Connected and reporting telemetry',
      borderColor: 'var(--ac-green)',
      valueColor: 'var(--ac-green)',
      icon: <CheckCircle aria-hidden="true" className="w-4 h-4" style={{ color: 'var(--ac-green)' }} />,
    },
    {
      label: 'Needs Attention',
      value: formatNumber(summary.warningCount),
      subtitle: 'Degraded performance or reconnecting',
      borderColor: 'var(--ac-orange)',
      valueColor: 'var(--ac-orange)',
      icon: (
        <AlertTriangle aria-hidden="true" className="w-4 h-4" style={{ color: 'var(--ac-orange)' }} />
      ),
    },
    {
      label: 'Offline',
      value: formatNumber(summary.offlineCount),
      subtitle: 'Not reporting; investigate',
      borderColor: 'var(--ac-red)',
      valueColor: 'var(--ac-red)',
      icon: <XCircle aria-hidden="true" className="w-4 h-4" style={{ color: 'var(--ac-red)' }} />,
    },
    {
      label: 'Requests/Min',
      value: formatNumber(fleetMetrics.totalRps),
      subtitle: 'Total across online sensors',
      borderColor: 'var(--ac-purple)',
      valueColor: 'var(--ac-purple)',
      icon: <Zap aria-hidden="true" className="w-4 h-4" style={{ color: 'var(--ac-purple)' }} />,
    },
  ];

  return (
    <Box p="xl">
      <Stack gap="xl">
        {/* Header */}
        <SectionHeader
          title="Fleet Overview"
          description={headerDescription}
          titleStyle={PAGE_TITLE_STYLE}
          actions={
            <Stack direction="row" gap="sm">
              <Button variant="outlined" size="md">
                Export Report
              </Button>
              <Button variant="magenta" size="md">
                Deploy Sensor
              </Button>
            </Stack>
          }
        />

        {/* KPI Strip (@/ui) */}
        <KpiStrip metrics={kpiMetrics} cols={4} />

        {/* Quick Actions */}
        <Grid cols={4} gap="md">
          <QuickAction
            icon={Search}
            title="Run Diagnostics"
            description="Check sensor health & connectivity"
            accentColorVar="--ac-blue"
          />
          <QuickAction
            icon={Shield}
            title="DLP Management"
            description="Monitor sensitive data leaks"
            onClick={() => navigate('/dlp')}
            accentColorVar="--ac-green"
          />
          <QuickAction
            icon={Settings}
            title="Configure Sensors"
            description="Kernel params & Synapse-Pingora config"
            onClick={() => navigate('/fleet/config')}
            accentColorVar="--ac-orange"
          />
          <QuickAction
            icon={Globe}
            title="Test Connectivity"
            description="Run network connectivity tests"
            accentColorVar="--ac-purple"
          />
        </Grid>

        {/* Alerts and Distribution */}
        <Grid cols={2} gap="xl">
          <Box bg="card" border="top" borderColor="var(--ac-blue)" p="lg">
            <SectionHeader
              title="Recent Alerts"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Button variant="ghost" size="sm">
                  View All
                </Button>
              }
            />
            <Stack gap="sm" style={{ marginTop: '16px' }}>
              {(overview?.recentAlerts || []).length === 0 ? (
                <Text variant="small" color="secondary" style={{ textAlign: 'center', padding: '16px 0' }}>
                  No recent alerts
                </Text>

              ) : (
                overview?.recentAlerts
                  .slice(0, 5)
                  .map((alert) => <AlertItem key={alert.id} alert={alert} />)
              )}
            </Stack>
          </Box>

          <Box bg="card" border="top" borderColor="var(--ac-navy)" p="lg">
            <SectionHeader
              title="Fleet Distribution"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
            />
            <Stack gap="md" style={{ marginTop: '16px' }}>
              {(overview?.regionDistribution || []).length === 0 ? (
                <Text variant="small" color="secondary" style={{ textAlign: 'center', padding: '16px 0' }}>
                  No region data
                </Text>
              ) : (
                overview?.regionDistribution.map((region) => (
                  <RegionBar key={region.region} region={region} />
                ))
              )}
            </Stack>
          </Box>
        </Grid>

        {/* Sensor Fleet Table */}
        <Box bg="card" border="top" borderColor="var(--ac-blue)">
          <Box p="md" bg="surface-inset" border="bottom">
            <SectionHeader
              title="Sensor Fleet"
              size="h4"
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Stack direction="row" gap="md" align="center">
                  <Box style={{ width: 260 }}>
                    <Input
                      placeholder="Search sensors..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      aria-label="Search sensors by name"
                      size="sm"
                    />
                  </Box>
                  <Box style={{ width: 160 }}>
                    <Select
                      value={filters.status || ''}
                      onChange={(e) => setStatusFilter((e.target.value as any) || undefined)}
                      aria-label="Filter sensors by status"
                      size="sm"
                      options={[
                        { value: '', label: 'All Status' },
                        { value: 'online', label: 'Online' },
                        { value: 'warning', label: 'Warning' },
                        { value: 'offline', label: 'Offline' },
                      ]}
                    />
                  </Box>
                </Stack>
              }
            />
          </Box>
          <SensorTable
            sensors={filteredSensors}
            onSensorClick={handleSensorClick}
            onConfigureClick={handleConfigureClick}
          />
          <Box p="md" border="top">
            <Text variant="small" color="secondary">
              Showing {filteredSensors.length} of {sensors.length} sensors
            </Text>
          </Box>
        </Box>
      </Stack>
    </Box>
  );
}

function QuickAction({
  icon: Icon,
  title,
  description,
  onClick,
  accentColorVar,
  disabled = false,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  onClick?: () => void;
  accentColorVar: string;
  disabled?: boolean;
}) {
  const isDisabled = disabled || !onClick;
  return (
    <Box
      bg="card"
      border="left"
      borderColor={`var(${accentColorVar})`}
      style={{ opacity: isDisabled ? 0.6 : 1, transition: 'all 0.2s ease' }}
    >
      <button
        onClick={isDisabled ? undefined : onClick}
        disabled={isDisabled}
        title={isDisabled ? `${title} (coming soon)` : title}
        aria-disabled={isDisabled}
        style={{
          width: '100%',
          textAlign: 'left',
          background: 'transparent',
          border: 'none',
          padding: '16px',
          cursor: isDisabled ? 'not-allowed' : 'pointer',
          outline: 'none',
        }}
        className="group hover:bg-surface-subtle focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ac-blue/50 dark:focus-visible:ring-ac-sky-light/50"
      >
        <Stack direction="row" gap="md" align="center">
          <Box
            p="sm"
            bg="surface-subtle"
            style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 40, height: 40 }}
          >
            <Icon className="w-5 h-5" style={{ color: `var(${accentColorVar})` }} />
          </Box>
          <Box>
            <Text variant="body" weight="semibold">
              {title}
            </Text>
            <Text variant="small" color="secondary">
              {description}
            </Text>
          </Box>
        </Stack>
      </button>
    </Box>
  );
}

function AlertItem({
  alert,
}: {
  alert: { id: string; sensorName: string; type: string; error: string | null; createdAt: string };
}) {
  const timeAgo = getTimeAgo(new Date(alert.createdAt));
  return (
    <Box p="sm" className="hover:bg-surface-subtle transition-colors" style={{ cursor: 'default' }}>
      <Stack direction="row" gap="md" align="start">
        <AlertTriangle
          aria-hidden="true"
          className="w-5 h-5 flex-shrink-0 mt-0.5"
          style={{ color: 'var(--ac-red)' }}
        />
        <Box style={{ flex: 1, minWidth: 0 }}>
          <Text variant="body" weight="medium" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {alert.type.replace(/_/g, ' ')}
          </Text>
          <Text variant="small" color="secondary" style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {alert.sensorName}: {alert.error || 'Command failed'}
          </Text>
        </Box>
        <Text variant="small" color="secondary" style={{ whiteSpace: 'nowrap' }}>
          {timeAgo}
        </Text>
      </Stack>
    </Box>
  );
}

function RegionBar({
  region,
}: {
  region: { region: string; online: number; warning: number; offline: number; total: number };
}) {
  const total = region.total || 1;
  const onlinePct = (region.online / total) * 100;
  const warningPct = (region.warning / total) * 100;
  const offlinePct = (region.offline / total) * 100;

  return (
    <Box>
      <Stack direction="row" align="center" justify="space-between" style={{ marginBottom: '4px' }}>
        <Text variant="small" weight="medium">
          {formatRegion(region.region)}
        </Text>
        <Text variant="small" color="secondary">
          {region.total} sensors
        </Text>
      </Stack>
      <Box
        style={{
          height: '24px',
          display: 'flex',
          overflow: 'hidden',
          background: 'var(--bg-surface-subtle)',
          border: '1px solid var(--border-subtle)',
        }}
      >
        {onlinePct > 0 && (
          <Box style={{ width: `${onlinePct}%`, background: 'var(--ac-green)' }} />
        )}
        {warningPct > 0 && (
          <Box style={{ width: `${warningPct}%`, background: 'var(--ac-orange)' }} />
        )}
        {offlinePct > 0 && (
          <Box style={{ width: `${offlinePct}%`, background: 'var(--ac-red)' }} />
        )}
      </Box>
    </Box>
  );
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toFixed(1);
}

function formatRegion(region: string): string {
  const names: Record<string, string> = {
    'us-east-1': 'US East',
    'us-west-1': 'US West',
    'us-west-2': 'US West 2',
    'eu-west-1': 'EU West',
    'eu-central-1': 'EU Central',
    'ap-southeast-1': 'Asia Pacific',
  };
  return names[region] || region;
}

function getTimeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}
