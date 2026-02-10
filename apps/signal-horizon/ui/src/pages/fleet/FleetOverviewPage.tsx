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
import { KpiStrip, colors } from '@/ui';

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
    status: s.connectionState === 'CONNECTED' ? 'online' : s.connectionState === 'RECONNECTING' ? 'warning' : 'offline',
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

  const handleSensorClick = useCallback((sensor: SensorSummary) => {
    navigate(`/fleet/sensors/${sensor.id}`);
  }, [navigate]);

  const handleConfigureClick = useCallback((sensor: SensorSummary) => {
    navigate(`/fleet/sensors/${sensor.id}/config`);
  }, [navigate]);

  if (overviewLoading || sensorsLoading) {
    return (
      <div className="p-6">
        <FleetOverviewSkeleton />
      </div>
    );
  }

  const summary = overview?.summary || { totalSensors: 0, onlineCount: 0, warningCount: 0, offlineCount: 0, healthScore: 100 };
  const fleetMetrics = overview?.fleetMetrics || { totalRps: 0, avgLatency: 0, avgCpu: 0, avgMemory: 0 };

  const kpiMetrics = [
    {
      label: 'Sensors Online',
      value: formatNumber(summary.onlineCount),
      subtitle: 'Connected and reporting telemetry',
      borderColor: colors.green,
      valueColor: colors.green,
      icon: <CheckCircle className="w-4 h-4" style={{ color: colors.green }} />,
    },
    {
      label: 'Needs Attention',
      value: formatNumber(summary.warningCount),
      subtitle: 'Degraded performance or reconnecting',
      borderColor: colors.orange,
      valueColor: colors.orange,
      icon: <AlertTriangle className="w-4 h-4" style={{ color: colors.orange }} />,
    },
    {
      label: 'Offline',
      value: formatNumber(summary.offlineCount),
      subtitle: 'Not reporting; investigate',
      borderColor: colors.red,
      valueColor: colors.red,
      icon: <XCircle className="w-4 h-4" style={{ color: colors.red }} />,
    },
    {
      label: 'Requests/Min',
      value: formatNumber(fleetMetrics.totalRps),
      subtitle: 'Total across online sensors',
      borderColor: colors.purple,
      valueColor: colors.purple,
      icon: <Zap className="w-4 h-4" style={{ color: colors.purple }} />,
    },
  ];

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-light text-ink-primary">Signal Array</h1>
          <p className="text-ink-secondary">
            Sensor Fleet Command & Health Monitoring
            {lastUpdatedText && (
              <span className="ml-2 text-xs text-ink-muted">
                &middot; Updated {lastUpdatedText}
              </span>
            )}
          </p>
        </div>
        <div className="flex gap-3">
          <button className="btn-outline h-10 px-4 text-xs uppercase tracking-[0.2em]">
            Export Report
          </button>
          <button className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]">
            Deploy Sensor
          </button>
        </div>
      </div>

      {/* KPI Strip (@/ui) */}
      <KpiStrip metrics={kpiMetrics} cols={4} />

      {/* Quick Actions */}
      <div className="grid grid-cols-4 gap-4">
        <QuickAction icon={Search} title="Run Diagnostics" description="Check sensor health & connectivity" accentClassName="border-l-ac-blue dark:border-l-ac-sky-light" iconClassName="text-ac-blue dark:text-ac-sky-light" />
        <QuickAction icon={Shield} title="DLP Management" description="Monitor sensitive data leaks" onClick={() => navigate('/fleet/dlp')} accentClassName="border-l-ac-green" iconClassName="text-ac-green" />
        <QuickAction icon={Settings} title="Configure Sensors" description="Kernel params & Synapse-Pingora config" onClick={() => navigate('/fleet/config')} accentClassName="border-l-ac-orange" iconClassName="text-ac-orange" />
        <QuickAction icon={Globe} title="Test Connectivity" description="Run network connectivity tests" accentClassName="border-l-ac-purple" iconClassName="text-ac-purple" />
      </div>

      {/* Alerts and Distribution */}
      <div className="grid grid-cols-2 gap-6">
        <div className="card border border-border-subtle border-t-2 border-t-ac-blue dark:border-t-ac-sky-light p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-ink-primary">Recent Alerts</h2>
            <button className="text-sm text-ac-blue dark:text-ac-sky-light hover:underline focus:outline-none focus:ring-2 focus:ring-ac-blue/50 dark:focus:ring-ac-sky-light/50">View All</button>
          </div>
          <div className="space-y-3">
            {(overview?.recentAlerts || []).length === 0 ? (
              <div className="text-ink-secondary text-sm py-4 text-center">No recent alerts</div>
            ) : (
              overview?.recentAlerts.slice(0, 5).map((alert) => (
                <AlertItem key={alert.id} alert={alert} />
              ))
            )}
          </div>
        </div>

        <div className="card border border-border-subtle border-t-2 border-t-ac-navy dark:border-t-ac-sky-light p-6">
          <h2 className="text-lg font-semibold text-ink-primary mb-4">Fleet Distribution</h2>
          <div className="space-y-3">
            {(overview?.regionDistribution || []).length === 0 ? (
              <div className="text-ink-secondary text-sm py-4 text-center">No region data</div>
            ) : (
              overview?.regionDistribution.map((region) => (
                <RegionBar key={region.region} region={region} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Sensor Fleet Table */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue dark:border-t-ac-sky-light">
        <div className="p-4 border-b border-border-subtle flex items-center justify-between bg-surface-inset">
          <h2 className="text-lg font-semibold text-ink-primary">Sensor Fleet</h2>
          <div className="flex items-center gap-4">
            <input
              type="text"
              placeholder="Search sensors..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search sensors by name"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base focus:outline-none focus:ring-2 focus:ring-ac-blue/50 dark:focus:ring-ac-sky-light/50"
            />
            <select
              value={filters.status || ''}
              onChange={(e) => setStatusFilter((e.target.value as any) || undefined)}
              aria-label="Filter sensors by status"
              className="px-3 py-2 text-sm border border-border-subtle bg-surface-base focus:outline-none focus:ring-2 focus:ring-ac-blue/50 dark:focus:ring-ac-sky-light/50"
            >
              <option value="">All Status</option>
              <option value="online">Online</option>
              <option value="warning">Warning</option>
              <option value="offline">Offline</option>
            </select>
          </div>
        </div>
        <SensorTable 
          sensors={filteredSensors} 
          onSensorClick={handleSensorClick}
          onConfigureClick={handleConfigureClick}
        />
        <div className="p-4 border-t border-border-subtle text-sm text-ink-secondary">
          Showing {filteredSensors.length} of {sensors.length} sensors
        </div>
      </div>
    </div>
  );
}

function QuickAction({ icon: Icon, title, description, onClick, accentClassName, iconClassName, disabled = false }: { icon: LucideIcon; title: string; description: string; onClick?: () => void; accentClassName: string; iconClassName: string; disabled?: boolean }) {
  const isDisabled = disabled || !onClick;
  return (
    <button
      onClick={isDisabled ? undefined : onClick}
      disabled={isDisabled}
      title={isDisabled ? `${title} (coming soon)` : title}
      aria-disabled={isDisabled}
      className={`card border border-border-subtle border-l-2 p-4 text-left transition-colors group focus:outline-none focus:ring-2 focus:ring-ac-blue/50 dark:focus:ring-ac-sky-light/50 ${accentClassName} ${isDisabled ? 'opacity-60 cursor-not-allowed' : 'hover:bg-surface-subtle'}`}
    >
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-surface-subtle flex items-center justify-center">
          <Icon className={`w-5 h-5 ${iconClassName}`} />
        </div>
        <div>
          <div className="font-semibold text-ink-primary group-hover:text-ink-primary transition-colors">{title}</div>
          <div className="text-sm text-ink-secondary">{description}</div>
        </div>
      </div>
    </button>
  );
}

function AlertItem({ alert }: { alert: { id: string; sensorName: string; type: string; error: string | null; createdAt: string } }) {
  const timeAgo = getTimeAgo(new Date(alert.createdAt));
  return (
    <div className="flex items-start gap-3 p-3 hover:bg-surface-subtle transition-colors">
      <AlertTriangle className="w-5 h-5 text-status-error flex-shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <div className="font-medium text-ink-primary truncate">{alert.type.replace(/_/g, ' ')}</div>
        <div className="text-sm text-ink-secondary truncate">{alert.sensorName}: {alert.error || 'Command failed'}</div>
      </div>
      <div className="text-sm text-ink-secondary whitespace-nowrap">{timeAgo}</div>
    </div>
  );
}

function RegionBar({ region }: { region: { region: string; online: number; warning: number; offline: number; total: number } }) {
  const total = region.total || 1;
  const onlinePct = (region.online / total) * 100;
  const warningPct = (region.warning / total) * 100;
  const offlinePct = (region.offline / total) * 100;

  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-sm font-medium text-ink-primary">{formatRegion(region.region)}</span>
        <span className="text-sm text-ink-secondary">{region.total} sensors</span>
      </div>
      <div className="h-6 flex overflow-hidden bg-surface-subtle border border-border-subtle">
        {onlinePct > 0 && <div className="bg-status-success" style={{ width: `${onlinePct}%` }} />}
        {warningPct > 0 && <div className="bg-status-warning" style={{ width: `${warningPct}%` }} />}
        {offlinePct > 0 && <div className="bg-status-error" style={{ width: `${offlinePct}%` }} />}
      </div>
    </div>
  );
}

function formatNumber(n: number): string {
  if (n >= 1000000) return `${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return n.toFixed(1);
}

function formatRegion(region: string): string {
  const names: Record<string, string> = { 'us-east-1': 'US East', 'us-west-1': 'US West', 'us-west-2': 'US West 2', 'eu-west-1': 'EU West', 'eu-central-1': 'EU Central', 'ap-southeast-1': 'Asia Pacific' };
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
