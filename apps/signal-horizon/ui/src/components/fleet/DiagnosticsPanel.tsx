/**
 * DiagnosticsPanel Component
 *
 * Comprehensive diagnostics dashboard with sections for health,
 * memory, connections, rules, and actors. Supports real-time updates
 * with collapsible sections and refresh controls.
 */

import { memo, useState, useCallback } from 'react';
import {
  Activity,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Cpu,
  Database,
  Network,
  Shield,
  Users,
  Clock,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Wifi,
  WifiOff,
  Zap,
} from 'lucide-react';
import { useDiagnostics, type DiagnosticsData } from '../../hooks/fleet/useDiagnostics';
import { ResourceBar } from './ResourceBar';
import { Spinner, Stack } from '@/ui';

// =============================================================================
// Type Definitions
// =============================================================================

export interface DiagnosticsPanelProps {
  /** Sensor ID to display diagnostics for */
  sensorId: string;
  /** Display name for the sensor */
  sensorName: string;
  /** Auto-refresh interval in ms (0 to disable, default: 5000) */
  refreshInterval?: number;
  /** Use SSE for live updates */
  live?: boolean;
  /** Initial sections to expand (default: all) */
  defaultExpandedSections?: Array<'health' | 'memory' | 'connections' | 'rules' | 'actors'>;
  /** Optional callback when close is requested */
  onClose?: () => void;
  /** Additional CSS classes */
  className?: string;
}

interface SectionProps {
  title: string;
  icon: React.ReactNode;
  isExpanded: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Format uptime in seconds to human-readable string
 */
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0 || parts.length === 0) parts.push(`${minutes}m`);

  return parts.join(' ');
}

/**
 * Format bytes to human-readable string (MB)
 */
function formatMemory(mb: number): string {
  if (mb >= 1024) {
    return `${(mb / 1024).toFixed(1)} GB`;
  }
  return `${mb.toFixed(0)} MB`;
}

/**
 * Format timestamp to relative time
 */
function formatRelativeTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffDays > 0) return `${diffDays}d ago`;
  if (diffHours > 0) return `${diffHours}h ago`;
  if (diffMins > 0) return `${diffMins}m ago`;
  return 'just now';
}

/**
 * Get status color classes based on health status
 */
function getStatusColors(status: 'healthy' | 'degraded' | 'unhealthy'): {
  bg: string;
  text: string;
  border: string;
  icon: React.ReactNode;
} {
  switch (status) {
    case 'healthy':
      return {
        bg: 'bg-ac-green/10',
        text: 'text-ac-green',
        border: 'border-ac-green/30',
        icon: <CheckCircle className="w-4 h-4" />,
      };
    case 'degraded':
      return {
        bg: 'bg-ac-orange/10',
        text: 'text-ac-orange',
        border: 'border-ac-orange/30',
        icon: <AlertTriangle className="w-4 h-4" />,
      };
    case 'unhealthy':
      return {
        bg: 'bg-ac-red/10',
        text: 'text-ac-red',
        border: 'border-ac-red/30',
        icon: <XCircle className="w-4 h-4" />,
      };
  }
}

// =============================================================================
// Section Component
// =============================================================================

const Section = memo(function Section({
  title,
  icon,
  isExpanded,
  onToggle,
  children,
}: SectionProps) {
  return (
    <div className="border border-border-subtle overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-3 bg-surface-raised hover:bg-surface-subtle transition-colors"
      >
        <Stack direction="row" align="center" gap="md">
          <span className="text-ac-blue">{icon}</span>
          <span className="text-sm font-medium text-ink-primary">{title}</span>
        </Stack>
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-ink-muted" />
        ) : (
          <ChevronRight className="w-4 h-4 text-ink-muted" />
        )}
      </button>
      {isExpanded && <div className="px-4 py-4 bg-surface-base">{children}</div>}
    </div>
  );
});

// =============================================================================
// Health Section
// =============================================================================

interface HealthSectionProps {
  health: DiagnosticsData['health'];
}

const HealthSection = memo(function HealthSection({ health }: HealthSectionProps) {
  const statusColors = getStatusColors(health.status);

  return (
    <div className="space-y-4">
      {/* Status Badge */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-ink-secondary">Status</span>
        <Stack
          direction="row"
          align="center"
          gap="sm"
          className={`inline-flex px-3 py-1.5 text-sm font-medium border ${statusColors.bg} ${statusColors.text} ${statusColors.border}`}
        >
          {statusColors.icon}
          <span className="capitalize">{health.status}</span>
        </Stack>
      </div>

      {/* Uptime */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-ink-secondary">Uptime</span>
        <Stack direction="row" align="center" gap="sm">
          <Clock className="w-4 h-4 text-ink-muted" />
          <span className="text-sm font-medium text-ink-primary">{formatUptime(health.uptime)}</span>
        </Stack>
      </div>

      {/* Version */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-ink-secondary">Version</span>
        <span className="text-sm font-mono text-ink-primary bg-surface-subtle px-2 py-0.5">
          v{health.version}
        </span>
      </div>
    </div>
  );
});

// =============================================================================
// Memory Section
// =============================================================================

interface MemorySectionProps {
  memory: DiagnosticsData['memory'];
}

const MemorySection = memo(function MemorySection({ memory }: MemorySectionProps) {
  const totalMemory = memory.rss;
  const categories = [
    { label: 'Heap', value: memory.heap, color: 'bg-ac-blue' },
    { label: 'Actor Cache', value: memory.actorCache, color: 'bg-ac-green' },
    { label: 'Session Cache', value: memory.sessionCache, color: 'bg-ac-orange' },
    { label: 'Rule Index', value: memory.ruleIndex, color: 'bg-ac-purple' },
  ];

  return (
    <div className="space-y-4">
      {/* Total Memory */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <span className="text-sm text-ink-secondary">Total RSS</span>
        <span className="text-lg font-semibold text-ink-primary">{formatMemory(totalMemory)}</span>
      </div>

      {/* Memory Breakdown */}
      <div className="space-y-3">
        {categories.map(({ label, value, color }) => (
          <div key={label}>
            <div className="flex justify-between items-center mb-1">
              <span className="text-sm text-ink-secondary">{label}</span>
              <span className="text-sm text-ink-muted">{formatMemory(value)}</span>
            </div>
            <div className="w-full h-2 bg-surface-subtle overflow-hidden">
              <div
                className={`h-full ${color} transition-all duration-300`}
                style={{ width: `${Math.min(100, (value / totalMemory) * 100)}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Memory Distribution Legend */}
      <div className="flex flex-wrap gap-3 pt-2 border-t border-border-subtle">
        {categories.map(({ label, value, color }) => (
          <Stack key={label} direction="row" align="center" className="text-xs text-ink-muted" style={{ gap: '0.375rem' }}>
            <span className={`w-2.5 h-2.5  ${color}`} />
            <span>{label}</span>
            <span className="text-ink-secondary">({((value / totalMemory) * 100).toFixed(1)}%)</span>
          </Stack>
        ))}
      </div>
    </div>
  );
});

// =============================================================================
// Connections Section
// =============================================================================

interface ConnectionsSectionProps {
  connections: DiagnosticsData['connections'];
}

const ConnectionsSection = memo(function ConnectionsSection({ connections }: ConnectionsSectionProps) {
  return (
    <div className="space-y-4">
      {/* Active Clients */}
      <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
        <Stack direction="row" align="center" gap="sm">
          <Users className="w-4 h-4 text-ink-muted" />
          <span className="text-sm text-ink-secondary">Active Clients</span>
        </Stack>
        <span className="text-lg font-semibold text-ink-primary">{connections.activeClients.toLocaleString()}</span>
      </div>

      {/* Upstream Pools */}
      <div>
        <h4 className="text-xs font-medium text-ink-muted uppercase tracking-wider mb-3">Upstream Pools</h4>
        <div className="space-y-2">
          {connections.upstreamPools.map((pool) => (
            <div
              key={pool.name}
              className="flex items-center justify-between p-3 bg-surface-subtle"
            >
              <span className="text-sm font-medium text-ink-primary">{pool.name}</span>
              <Stack direction="row" align="center" gap="md" className="text-sm">
                <span className="text-ac-green">
                  <span className="text-ink-muted">Active:</span> {pool.active}
                </span>
                <span className="text-ink-secondary">
                  <span className="text-ink-muted">Idle:</span> {pool.idle}
                </span>
              </Stack>
            </div>
          ))}
        </div>
      </div>

      {/* Horizon Tunnel */}
      <div className="pt-3 border-t border-border-subtle">
        <div className="flex items-center justify-between">
          <Stack direction="row" align="center" gap="sm">
            {connections.horizonTunnel.connected ? (
              <Wifi className="w-4 h-4 text-ac-green" />
            ) : (
              <WifiOff className="w-4 h-4 text-ac-red" />
            )}
            <span className="text-sm text-ink-secondary">Horizon Tunnel</span>
          </Stack>
          <Stack direction="row" align="center" gap="sm">
            <span
              className={`px-2.5 py-1  text-xs font-medium ${
                connections.horizonTunnel.connected
                  ? 'bg-ac-green/10 text-ac-green'
                  : 'bg-ac-red/10 text-ac-red'
              }`}
            >
              {connections.horizonTunnel.connected ? 'Connected' : 'Disconnected'}
            </span>
            {connections.horizonTunnel.connected && connections.horizonTunnel.uptime && (
              <span className="text-xs text-ink-muted">
                {formatUptime(connections.horizonTunnel.uptime)}
              </span>
            )}
          </Stack>
        </div>
      </div>
    </div>
  );
});

// =============================================================================
// Rules Section
// =============================================================================

interface RulesSectionProps {
  rules: DiagnosticsData['rules'];
}

const RulesSection = memo(function RulesSection({ rules }: RulesSectionProps) {
  const enabledPercentage = (rules.enabled / rules.total) * 100;

  return (
    <div className="space-y-4">
      {/* Rule Counts */}
      <div className="grid grid-cols-2 gap-4">
        <div className="p-3 bg-surface-subtle text-center">
          <p className="text-2xl font-semibold text-ink-primary">{rules.total}</p>
          <p className="text-xs text-ink-muted mt-1">Total Rules</p>
        </div>
        <div className="p-3 bg-surface-subtle text-center">
          <p className="text-2xl font-semibold text-ac-green">{rules.enabled}</p>
          <p className="text-xs text-ink-muted mt-1">Enabled</p>
        </div>
      </div>

      {/* Enabled Progress */}
      <ResourceBar
        label="Rules Enabled"
        value={enabledPercentage}
        showPercentage={true}
        size="md"
      />

      {/* Last Updated */}
      <div className="flex items-center justify-between pt-3 border-t border-border-subtle">
        <span className="text-sm text-ink-secondary">Last Updated</span>
        <span className="text-sm text-ink-muted">{formatRelativeTime(rules.lastUpdated)}</span>
      </div>
    </div>
  );
});

// =============================================================================
// Actors Section
// =============================================================================

interface ActorsSectionProps {
  actors: DiagnosticsData['actors'];
}

const ActorsSection = memo(function ActorsSection({ actors }: ActorsSectionProps) {
  return (
    <div className="space-y-4">
      {/* Tracked Count with Gauge */}
      <div className="text-center pb-4 border-b border-border-subtle">
        <p className="text-3xl font-semibold text-ink-primary">{actors.tracked.toLocaleString()}</p>
        <p className="text-sm text-ink-muted mt-1">Tracked Actors</p>
      </div>

      {/* Cache Usage */}
      <div>
        <div className="flex justify-between items-center mb-2">
          <span className="text-sm text-ink-secondary">Cache Usage</span>
          <span className="text-sm font-medium text-ink-primary">
            {actors.cacheUsage}% of {actors.cacheCapacity.toLocaleString()}
          </span>
        </div>
        <div className="w-full h-3 bg-surface-subtle overflow-hidden">
          <div
            className={`h-full transition-all duration-300 ${
              actors.cacheUsage >= 90
                ? 'bg-ac-red'
                : actors.cacheUsage >= 75
                  ? 'bg-ac-orange'
                  : 'bg-ac-blue'
            }`}
            style={{ width: `${actors.cacheUsage}%` }}
          />
        </div>
      </div>

      {/* Evictions */}
      <div className="flex items-center justify-between pt-3 border-t border-border-subtle">
        <Stack direction="row" align="center" gap="sm">
          <Zap className="w-4 h-4 text-ink-muted" />
          <span className="text-sm text-ink-secondary">Evictions (1h)</span>
        </Stack>
        <span
          className={`text-sm font-medium ${
            actors.evictions1h > 100 ? 'text-ac-orange' : 'text-ink-primary'
          }`}
        >
          {actors.evictions1h.toLocaleString()}
        </span>
      </div>
    </div>
  );
});

// =============================================================================
// Main Component
// =============================================================================

export function DiagnosticsPanel({
  sensorId,
  sensorName,
  refreshInterval = 5000,
  live = false,
  defaultExpandedSections = ['health', 'memory', 'connections', 'rules', 'actors'],
  onClose,
  className = '',
}: DiagnosticsPanelProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(
    new Set(defaultExpandedSections)
  );

  const { data, isLoading, error, refresh, lastUpdated, isConnected } = useDiagnostics({
    sensorId,
    refreshInterval,
    live,
  });

  const toggleSection = useCallback((section: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(section)) {
        next.delete(section);
      } else {
        next.add(section);
      }
      return next;
    });
  }, []);

  const handleRefresh = useCallback(() => {
    refresh();
  }, [refresh]);

  return (
    <div className={`flex flex-col bg-surface-base  border border-border-subtle overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border-subtle bg-surface-raised">
        <Stack direction="row" align="center" gap="md">
          <Activity className="w-5 h-5 text-ac-blue" />
          <div>
            <h3 className="text-sm font-semibold text-ink-primary">{sensorName}</h3>
            <p className="text-xs text-ink-muted">Diagnostics</p>
          </div>
        </Stack>

        <Stack direction="row" align="center" gap="md">
          {/* Connection/Live indicator */}
          {live && (
            <Stack
              direction="row"
              align="center"
              style={{ gap: '0.375rem' }}
              className={`text-xs ${
                isConnected ? 'text-ac-green' : 'text-ac-red'
              }`}
            >
              <span
                className={`w-2 h-2  ${
                  isConnected ? 'bg-ac-green animate-pulse' : 'bg-ac-red'
                }`}
              />
              {isConnected ? 'Live' : 'Disconnected'}
            </Stack>
          )}

          {/* Last updated */}
          {lastUpdated && (
            <span className="text-xs text-ink-muted">
              Updated {formatRelativeTime(lastUpdated.toISOString())}
            </span>
          )}

          {/* Refresh button */}
          <button
            onClick={handleRefresh}
            disabled={isLoading}
            className={`p-1.5  hover:bg-surface-subtle transition-colors ${
              isLoading ? 'opacity-50 cursor-not-allowed' : ''
            }`}
            title="Refresh"
          >
            {isLoading ? (
              <Spinner size={16} color="#7F7F7F" />
            ) : (
              <RefreshCw className="w-4 h-4 text-ink-secondary" />
            )}
          </button>

          {/* Close button */}
          {onClose && (
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-surface-subtle transition-colors"
              title="Close"
            >
              <XCircle className="w-4 h-4 text-ink-muted hover:text-ink-primary" />
            </button>
          )}
        </Stack>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {/* Loading State */}
        {isLoading && !data && (
          <div className="flex flex-col items-center justify-center py-12">
            <Spinner size={32} color="#7F7F7F" style={{ marginBottom: '12px' }} />
            <p className="text-sm text-ink-muted">Loading diagnostics...</p>
          </div>
        )}

        {/* Error State */}
        {error && !data && (
          <div className="flex flex-col items-center justify-center py-12">
            <XCircle className="w-8 h-8 text-ac-red mb-3" />
            <p className="text-sm text-ink-primary font-medium">Failed to load diagnostics</p>
            <p className="text-xs text-ink-muted mt-1">{error.message}</p>
            <button
              onClick={handleRefresh}
              className="mt-4 px-4 py-2 text-sm font-medium text-white bg-ac-blue hover:bg-ac-blue/90 transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* Data Display */}
        {data && (
          <div className="space-y-3">
            {/* Health Section */}
            <Section
              title="Health"
              icon={<Cpu className="w-4 h-4" />}
              isExpanded={expandedSections.has('health')}
              onToggle={() => toggleSection('health')}
            >
              <HealthSection health={data.health} />
            </Section>

            {/* Memory Section */}
            <Section
              title="Memory"
              icon={<Database className="w-4 h-4" />}
              isExpanded={expandedSections.has('memory')}
              onToggle={() => toggleSection('memory')}
            >
              <MemorySection memory={data.memory} />
            </Section>

            {/* Connections Section */}
            <Section
              title="Connections"
              icon={<Network className="w-4 h-4" />}
              isExpanded={expandedSections.has('connections')}
              onToggle={() => toggleSection('connections')}
            >
              <ConnectionsSection connections={data.connections} />
            </Section>

            {/* Rules Section */}
            <Section
              title="Rules"
              icon={<Shield className="w-4 h-4" />}
              isExpanded={expandedSections.has('rules')}
              onToggle={() => toggleSection('rules')}
            >
              <RulesSection rules={data.rules} />
            </Section>

            {/* Actors Section */}
            <Section
              title="Actors"
              icon={<Users className="w-4 h-4" />}
              isExpanded={expandedSections.has('actors')}
              onToggle={() => toggleSection('actors')}
            >
              <ActorsSection actors={data.actors} />
            </Section>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-border-subtle bg-surface-raised">
        <div className="flex items-center justify-between text-xs text-ink-muted">
          <span>Sensor ID: <span className="font-mono">{sensorId}</span></span>
          {refreshInterval > 0 && !live && (
            <span>Auto-refresh: {(refreshInterval / 1000).toFixed(0)}s</span>
          )}
        </div>
      </div>
    </div>
  );
}

export default DiagnosticsPanel;
