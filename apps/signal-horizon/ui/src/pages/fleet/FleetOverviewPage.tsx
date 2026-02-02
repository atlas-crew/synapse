import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
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

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

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
  const response = await fetch(`${API_BASE}/api/v1/fleet/overview`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  if (!response.ok) throw new Error('Failed to fetch fleet overview');
  return response.json();
}

async function fetchSensors(): Promise<SensorSummary[]> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  if (!response.ok) throw new Error('Failed to fetch sensors');
  const data = await response.json();
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
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const { filters, setStatusFilter } = useFleetStore();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

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

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Signal Array</h1>
          <p className="text-ink-secondary">Sensor Fleet Command & Health Monitoring</p>
        </div>
        <div className="flex gap-3">
          <button className="px-4 py-2 text-sm border border-border-subtle rounded-lg hover:bg-surface-subtle transition-colors">
            Export Report
          </button>
          <button className="px-4 py-2 text-sm bg-accent-primary text-white rounded-lg hover:bg-accent-primary/90 transition-colors">
            + Deploy Sensor
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatsCard icon={CheckCircle} iconBg="bg-status-success/10" iconColor="text-status-success" value={summary.onlineCount} label="SENSORS ONLINE" />
        <StatsCard icon={AlertTriangle} iconBg="bg-status-warning/10" iconColor="text-status-warning" value={summary.warningCount} label="NEEDS ATTENTION" />
        <StatsCard icon={XCircle} iconBg="bg-status-error/10" iconColor="text-status-error" value={summary.offlineCount} label="OFFLINE" />
        <StatsCard icon={Zap} iconBg="bg-accent-primary/10" iconColor="text-accent-primary" value={formatNumber(fleetMetrics.totalRps)} label="REQUESTS/MIN" />
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-4 gap-4">
        <QuickAction icon={Search} title="Run Diagnostics" description="Check sensor health & connectivity" />
        <QuickAction icon={Shield} title="DLP Management" description="Monitor sensitive data leaks" onClick={() => navigate('/fleet/dlp')} />
        <QuickAction icon={Settings} title="Configure Sensors" description="Kernel params & Synapse-Pingora config" onClick={() => navigate('/fleet/config')} />
        <QuickAction icon={Globe} title="Test Connectivity" description="Run network connectivity tests" />
      </div>

      {/* Alerts and Distribution */}
      <div className="grid grid-cols-2 gap-6">
        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-ink-primary">Recent Alerts</h2>
            <button className="text-sm text-accent-primary hover:underline">View All</button>
          </div>
          <div className="space-y-3">
            {(overview?.recentAlerts || []).length === 0 ? (
              <div className="text-ink-muted text-sm py-4 text-center">No recent alerts</div>
            ) : (
              overview?.recentAlerts.slice(0, 5).map((alert) => (
                <AlertItem key={alert.id} alert={alert} />
              ))
            )}
          </div>
        </div>

        <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
          <h2 className="text-lg font-semibold text-ink-primary mb-4">Fleet Distribution</h2>
          <div className="space-y-3">
            {(overview?.regionDistribution || []).length === 0 ? (
              <div className="text-ink-muted text-sm py-4 text-center">No region data</div>
            ) : (
              overview?.regionDistribution.map((region) => (
                <RegionBar key={region.region} region={region} />
              ))
            )}
          </div>
        </div>
      </div>

      {/* Sensor Fleet Table */}
      <div className="bg-surface-card border border-border-subtle rounded-xl">
        <div className="p-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-semibold text-ink-primary">Sensor Fleet</h2>
          <div className="flex items-center gap-4">
            <input
              type="text"
              placeholder="Search sensors..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="px-3 py-2 text-sm border border-border-subtle rounded-lg bg-surface-base focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
            />
            <select
              value={filters.status || ''}
              onChange={(e) => setStatusFilter((e.target.value as any) || undefined)}
              className="px-3 py-2 text-sm border border-border-subtle rounded-lg bg-surface-base"
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
        <div className="p-4 border-t border-border-subtle text-sm text-ink-muted">
          Showing {filteredSensors.length} of {sensors.length} sensors
        </div>
      </div>
    </div>
  );
}

function StatsCard({ icon: Icon, iconBg, iconColor, value, label }: { icon: LucideIcon; iconBg: string; iconColor: string; value: number | string; label: string }) {
  return (
    <div className="bg-surface-card border border-border-subtle rounded-xl p-6">
      <div className={`w-10 h-10 rounded-lg ${iconBg} flex items-center justify-center mb-3`}>
        <Icon className={`w-5 h-5 ${iconColor}`} />
      </div>
      <div className="text-3xl font-bold text-ink-primary">{value}</div>
      <div className="text-xs font-semibold text-ink-muted uppercase tracking-wide mt-1">{label}</div>
    </div>
  );
}

function QuickAction({ icon: Icon, title, description, onClick }: { icon: LucideIcon; title: string; description: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} className="bg-surface-card border border-border-subtle rounded-xl p-4 text-left hover:bg-surface-subtle transition-colors group">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-lg bg-accent-primary/10 flex items-center justify-center">
          <Icon className="w-5 h-5 text-accent-primary" />
        </div>
        <div>
          <div className="font-semibold text-ink-primary group-hover:text-accent-primary transition-colors">{title}</div>
          <div className="text-sm text-ink-secondary">{description}</div>
        </div>
      </div>
    </button>
  );
}

function AlertItem({ alert }: { alert: { id: string; sensorName: string; type: string; error: string | null; createdAt: string } }) {
  const timeAgo = getTimeAgo(new Date(alert.createdAt));
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg hover:bg-surface-subtle transition-colors">
      <AlertTriangle className="w-5 h-5 text-status-error flex-shrink-0 mt-0.5" />
      <div className="flex-1 min-w-0">
        <div className="font-medium text-ink-primary truncate">{alert.type.replace(/_/g, ' ')}</div>
        <div className="text-sm text-ink-secondary truncate">{alert.sensorName}: {alert.error || 'Command failed'}</div>
      </div>
      <div className="text-sm text-ink-muted whitespace-nowrap">{timeAgo}</div>
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
        <span className="text-sm text-ink-muted">{region.total} sensors</span>
      </div>
      <div className="h-6 flex rounded overflow-hidden bg-surface-subtle">
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
  return n.toString();
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
