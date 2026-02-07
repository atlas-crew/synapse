/**
 * Schema Changes Page
 * API schema drift detection and versioning timeline
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import { TOOLTIP_CONTENT_STYLE, TOOLTIP_LABEL_STYLE } from '../../../lib/chartTheme';
import { useDocumentTitle } from '../../../hooks/useDocumentTitle';
import {
  GitBranch,
  AlertTriangle,
  Plus,
  Minus,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Clock,
  Filter,
} from 'lucide-react';
import { clsx } from 'clsx';
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { useApiIntelligence } from '../../../hooks/useApiIntelligence';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type ChangeType = 'added' | 'removed' | 'modified' | 'deprecated';

type SchemaChangeView = {
  id: string;
  endpoint: string;
  method: string;
  service: string;
  changeType: ChangeType;
  field: string;
  fieldType: string;
  description: string;
  detectedAt: string;
  breaking: boolean;
  riskLevel: string;
};

const CHANGE_TYPE_MAP: Record<string, ChangeType> = {
  added: 'added',
  removed: 'removed',
  modified: 'modified',
  deprecated: 'deprecated',
  field_added: 'added',
  field_removed: 'removed',
  type_changed: 'modified',
};

function normalizeChangeType(value: string): ChangeType {
  return CHANGE_TYPE_MAP[value] ?? 'modified';
}

function formatFieldType(oldValue: string | null, newValue: string | null): string {
  if (oldValue && newValue) {
    return `${oldValue} → ${newValue}`;
  }
  return newValue ?? oldValue ?? 'n/a';
}

const CHANGE_TYPE_CONFIG: Record<ChangeType, { icon: React.ElementType; color: string; label: string }> = {
  added: { icon: Plus, color: 'text-green-400 bg-green-500/20', label: 'Added' },
  removed: { icon: Minus, color: 'text-red-400 bg-red-500/20', label: 'Removed' },
  modified: { icon: RefreshCw, color: 'text-sky-400 bg-sky-500/20', label: 'Modified' },
  deprecated: { icon: AlertTriangle, color: 'text-orange-400 bg-orange-500/20', label: 'Deprecated' },
};

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400',
  POST: 'text-blue-400',
  PUT: 'text-sky-400',
  PATCH: 'text-orange-400',
  DELETE: 'text-red-400',
};

const TREND_COLORS = ['#529EEC', '#D62598', '#E35205'];

// Stat Card
function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-horizon-400',
}: {
  label: string;
  value: string;
  icon: React.ElementType;
  color?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-ink-secondary">{label}</p>
          <p className="mt-1 text-2xl font-bold text-ink-primary">{value}</p>
        </div>
        <div className="p-3 bg-surface-subtle/50">
          <Icon className={clsx('w-6 h-6', color)} />
        </div>
      </div>
    </motion.div>
  );
}

// Format relative time
function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();

  const minutes = Math.floor(diff / (1000 * 60));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// Schema Change Card
function SchemaChangeCard({
  change,
  isExpanded,
  onToggle,
}: {
  change: SchemaChangeView;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const config = CHANGE_TYPE_CONFIG[change.changeType];
  const ChangeIcon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={clsx(
        'bg-surface-card border overflow-hidden transition-colors',
        change.breaking ? 'border-red-500/50' : 'border-border-subtle'
      )}
    >
      <button
        onClick={onToggle}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-surface-subtle transition-colors"
      >
        <div className="flex items-center gap-4">
          <div className={clsx('p-2', config.color)}>
            <ChangeIcon className="w-4 h-4" />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <span className={clsx('text-sm font-medium', METHOD_COLORS[change.method])}>
                {change.method}
              </span>
              <code className="text-blue-400 text-sm">{change.endpoint}</code>
            </div>
            <p className="text-sm text-ink-secondary mt-0.5">
              <span className="font-mono text-ink-secondary">{change.field}</span>
              <span className="mx-2">→</span>
              <span className="text-ink-muted">{change.fieldType}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {change.breaking && (
            <span className="px-2 py-0.5 text-xs font-medium text-red-400 bg-red-500/20">
              Breaking
            </span>
          )}
          <span className="text-sm text-ink-secondary flex items-center gap-1">
            <Clock className="w-4 h-4" />
            {formatRelativeTime(change.detectedAt)}
          </span>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-ink-secondary" />
          ) : (
            <ChevronRight className="w-5 h-5 text-ink-secondary" />
          )}
        </div>
      </button>

      {isExpanded && (
        <div className="px-5 py-4 border-t border-border-subtle bg-surface-subtle">
          <div className="space-y-3">
            <div>
              <p className="text-sm text-ink-secondary">Description</p>
              <p className="text-ink-primary mt-1">{change.description}</p>
            </div>
            <div className="flex items-center gap-6">
              <div>
                <p className="text-sm text-ink-secondary">Service</p>
                <p className="text-ink-primary mt-1">{change.service}</p>
              </div>
              <div>
                <p className="text-sm text-ink-secondary">Change Type</p>
                <p className="text-ink-primary mt-1 capitalize">{change.changeType}</p>
              </div>
              <div>
                <p className="text-sm text-ink-secondary">Risk Level</p>
                <p className="text-ink-primary mt-1 capitalize">{change.riskLevel}</p>
              </div>
              <div>
                <p className="text-sm text-ink-secondary">Detected</p>
                <p className="text-ink-primary mt-1">
                  {new Date(change.detectedAt).toLocaleString()}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function SchemaChangesPage() {
  useDocumentTitle('Beam - Schema Changes');
  const [expandedChanges, setExpandedChanges] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [showBreakingOnly, setShowBreakingOnly] = useState(false);

  const { schemaChanges, endpointDriftTrends, isLoading } = useApiIntelligence();

  const allChanges = useMemo<SchemaChangeView[]>(
    () =>
      schemaChanges.map((change) => ({
        id: change.id,
        endpoint: change.endpoint,
        method: change.method,
        service: change.service,
        changeType: normalizeChangeType(change.changeType),
        field: change.field,
        fieldType: formatFieldType(change.oldValue, change.newValue),
        description: `${change.service} (${change.riskLevel})`,
        detectedAt: change.detectedAt,
        breaking: change.breaking,
        riskLevel: change.riskLevel,
      })),
    [schemaChanges]
  );

  // Filter changes
  const filteredChanges = useMemo(() => {
    let result = [...allChanges];

    if (typeFilter) {
      result = result.filter((c) => c.changeType === typeFilter);
    }

    if (showBreakingOnly) {
      result = result.filter((c) => c.breaking);
    }

    return result;
  }, [allChanges, typeFilter, showBreakingOnly]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = allChanges.length;
    const breaking = allChanges.filter((c) => c.breaking).length;
    const highRisk = allChanges.filter((c) => ['high', 'critical'].includes(c.riskLevel.toLowerCase())).length;
    const thisWeek = allChanges.filter((c) => {
      const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      return new Date(c.detectedAt).getTime() > weekAgo;
    }).length;

    return { total, breaking, highRisk, thisWeek };
  }, [allChanges]);

  const topEndpointTrends = useMemo(() => endpointDriftTrends.slice(0, 3), [endpointDriftTrends]);

  const trendLabels = useMemo(
    () => topEndpointTrends.map((trend) => `${trend.method} ${trend.endpoint}`),
    [topEndpointTrends]
  );

  const trendChartData = useMemo(() => {
    const dateMap = new Map<string, Record<string, number | string>>();

    topEndpointTrends.forEach((trend) => {
      const key = `${trend.method} ${trend.endpoint}`;
      trend.series.forEach((point) => {
        const entry = dateMap.get(point.date) ?? { date: point.date };
        entry[key] = point.count;
        dateMap.set(point.date, entry);
      });
    });

    return Array.from(dateMap.values()).sort((a, b) => String(a.date).localeCompare(String(b.date)));
  }, [topEndpointTrends]);

  const toggleChange = (changeId: string) => {
    const newExpanded = new Set(expandedChanges);
    if (newExpanded.has(changeId)) {
      newExpanded.delete(changeId);
    } else {
      newExpanded.add(changeId);
    }
    setExpandedChanges(newExpanded);
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-light text-ink-primary">Schema Changes</h1>
          <p className="text-ink-secondary mt-1">Loading schema change data...</p>
        </div>
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-light text-ink-primary">Schema Changes</h1>
        <p className="text-ink-secondary mt-1">API schema drift detection and versioning</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Changes" value={stats.total.toString()} icon={GitBranch} />
        <StatCard
          label="Breaking Changes"
          value={stats.breaking.toString()}
          icon={AlertTriangle}
          color="text-red-400"
        />
        <StatCard
          label="High Risk"
          value={stats.highRisk.toString()}
          icon={Clock}
          color="text-sky-400"
        />
        <StatCard
          label="This Week"
          value={stats.thisWeek.toString()}
          icon={RefreshCw}
          color="text-green-400"
        />
      </div>

      {/* Endpoint Drift Trends */}
      <div className="card h-[320px]">
        <div className="card-header">
          <h2 className="font-medium text-ink-primary">Schema Drift Trends (Top Endpoints)</h2>
        </div>
        <div className="card-body h-full">
          {trendChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendChartData}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(0, 87, 183, 0.15)" />
                <XAxis dataKey="date" stroke="#7B8FA8" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#7B8FA8" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={TOOLTIP_CONTENT_STYLE}
                  labelStyle={TOOLTIP_LABEL_STYLE}
                />
                {trendLabels.map((label, index) => (
                  <Line
                    key={label}
                    type="monotone"
                    dataKey={label}
                    stroke={TREND_COLORS[index % TREND_COLORS.length]}
                    strokeWidth={2}
                    dot={false}
                  />
                ))}
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-ink-muted">
              No drift trend data available.
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-ink-secondary" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 bg-surface-card border border-border-subtle text-ink-primary focus:outline-none focus:ring-2 focus:ring-horizon-500"
          >
            <option value="">All Types</option>
            <option value="added">Added</option>
            <option value="removed">Removed</option>
            <option value="modified">Modified</option>
            <option value="deprecated">Deprecated</option>
          </select>
        </div>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={showBreakingOnly}
            onChange={(e) => setShowBreakingOnly(e.target.checked)}
            className="w-4 h-4 border-border-subtle bg-surface-card text-horizon-600 focus:ring-horizon-500"
          />
          <span className="text-sm text-ink-secondary">Breaking only</span>
        </label>
      </div>

      {/* Changes Timeline */}
      <div className="space-y-3">
        {filteredChanges.map((change) => (
          <SchemaChangeCard
            key={change.id}
            change={change}
            isExpanded={expandedChanges.has(change.id)}
            onToggle={() => toggleChange(change.id)}
          />
        ))}
        {filteredChanges.length === 0 && (
          <div className="bg-surface-card border border-border-subtle p-8 text-center">
            <p className="text-ink-secondary">No schema changes match your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}
