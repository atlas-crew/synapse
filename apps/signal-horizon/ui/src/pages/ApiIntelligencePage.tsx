import { useState, useMemo } from 'react';
import { TOOLTIP_CONTENT_STYLE, TOOLTIP_LABEL_STYLE, TOOLTIP_ITEM_STYLE } from '../lib/chartTheme';
import { useDocumentTitle } from '../hooks/useDocumentTitle';
import {
  BarChart3,
  Search,
  ShieldAlert,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Filter,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  AreaChart,
  Area,
} from 'recharts';
import { useApiIntelligence } from '../hooks/useApiIntelligence';
import { StatsGridSkeleton, TableSkeleton } from '../components/LoadingStates';
import { StatsCard, EndpointsTable, ViolationsFeed } from '../components/api-intelligence';
import { ApiTreemap } from '../components/api-intelligence/ApiTreemap';
import { SchemaDriftDiff } from '../components/api-intelligence/SchemaDriftDiff';

export default function ApiIntelligencePage() {
  useDocumentTitle('API Intelligence');
  const {
    stats,
    endpoints,
    signals,
    inventory,
    schemaChanges,
    isLoading,
    error,
    refetch,
    lastUpdated,
    pagination,
    setPagination,
    totalEndpoints,
    hasMore,
  } = useApiIntelligence({ pollInterval: 30000 });
  const [searchQuery, setSearchQuery] = useState('');

  const schemaDriftGroups = useMemo(() => {
    if (!schemaChanges || schemaChanges.length === 0) return [];

    const groups = new Map<string, {
      endpoint: string;
      method: string;
      detectedAt: string;
      changes: Array<{
        field: string;
        oldType?: string;
        newType?: string;
        description: string;
        severity: 'low' | 'medium' | 'high';
      }>;
    }>();

    const toSeverity = (riskLevel: string): 'low' | 'medium' | 'high' => {
      const normalized = riskLevel.toLowerCase();
      if (normalized === 'high' || normalized === 'critical') return 'high';
      if (normalized === 'medium') return 'medium';
      return 'low';
    };

    schemaChanges.forEach((change) => {
      const key = `${change.method}:${change.endpoint}`;
      const entry = groups.get(key) ?? {
        endpoint: change.endpoint,
        method: change.method,
        detectedAt: change.detectedAt,
        changes: [],
      };

      entry.changes.push({
        field: change.field,
        oldType: change.oldValue ?? undefined,
        newType: change.newValue ?? undefined,
        description: `${change.changeType} change detected for ${change.field}`,
        severity: toSeverity(change.riskLevel),
      });

      if (new Date(change.detectedAt) > new Date(entry.detectedAt)) {
        entry.detectedAt = change.detectedAt;
      }

      groups.set(key, entry);
    });

    return Array.from(groups.values())
      .map((group) => ({
        ...group,
        changes: group.changes.slice(0, 3),
      }))
      .sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime())
      .slice(0, 2);
  }, [schemaChanges]);

  const filteredEndpoints = useMemo(() =>
    endpoints.filter(ep =>
      ep.path.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ep.service.toLowerCase().includes(searchQuery.toLowerCase())
    ),
    [endpoints, searchQuery]
  );

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-light text-ink-primary">API Intelligence</h1>
            <p className="text-ink-secondary mt-1">Discover endpoints and monitor schema compliance</p>
          </div>
        </div>
        <StatsGridSkeleton />
        <TableSkeleton rows={5} />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 text-center text-ac-red">
        <AlertTriangle className="w-12 h-12 mx-auto mb-2" aria-hidden="true" />
        <h2 className="text-xl">Failed to load API Intelligence</h2>
        <p>{error.message}</p>
        <button
          onClick={() => refetch()}
          className="mt-4 px-4 py-2 bg-ac-blue text-white hover:bg-ac-blue/90 transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
          aria-label="Retry loading API intelligence data"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">API Intelligence</h1>
          <div className="flex items-center gap-3 mt-1">
            <p className="text-ink-secondary">
              Fleet-wide endpoint discovery and schema validation
            </p>
            {lastUpdated && (
              <span className="text-xs text-ink-muted">
                Last updated: {new Date(lastUpdated).toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-outline h-9 px-3 text-xs" aria-label="Filter endpoints">
            <Filter className="w-4 h-4 mr-2" aria-hidden="true" />
            Filter
          </button>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-ink-muted" aria-hidden="true" />
            <input
              type="text"
              placeholder="Search endpoints..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search endpoints"
              className="h-9 pl-9 pr-4 bg-surface-base border border-border-subtle text-sm w-64 focus:border-link focus:ring-1 focus:ring-link outline-none"
            />
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          label="Total Endpoints"
          value={stats?.totalEndpoints ?? 0}
          sublabel={`+${stats?.newThisWeek ?? 0} new this week`}
          icon={FileCode}
          tone="text-ac-blue"
        />
        <StatsCard
          label="Schema Violations (24h)"
          value={stats?.schemaViolations24h ?? 0}
          sublabel={`${stats?.schemaViolations7d ?? 0} in 7 days`}
          icon={ShieldAlert}
          tone="text-ac-orange"
        />
        <StatsCard
          label="Coverage"
          value={`${stats?.coveragePercent ?? 0}%`}
          sublabel="Endpoints with schema"
          icon={CheckCircle}
          tone="text-ac-green"
        />
        <StatsCard
          label="Discovery Rate"
          value={`+${stats?.newToday ?? 0}`}
          sublabel="New endpoints today"
          icon={BarChart3}
          tone="text-ac-purple"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ApiTreemap services={inventory?.services} />
        
        <div className="card h-[400px]">
          <div className="card-header">
            <h2 className="font-medium text-ink-primary">Discovery Trend (7 Days)</h2>
          </div>
          <div className="card-body h-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats?.discoveryTrend ?? []}>
                <defs>
                  <linearGradient id="colorDiscovery" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#529EEC" stopOpacity={0.5} />
                    <stop offset="50%" stopColor="#0057B7" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#0057B7" stopOpacity={0.05} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(0, 87, 183, 0.15)" />
                <XAxis dataKey="date" stroke="#7B8FA8" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#7B8FA8" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={TOOLTIP_CONTENT_STYLE}
                  labelStyle={TOOLTIP_LABEL_STYLE}
                  itemStyle={TOOLTIP_ITEM_STYLE}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#529EEC"
                  strokeWidth={2.5}
                  fillOpacity={1}
                  fill="url(#colorDiscovery)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Drift Analysis & Violations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="space-y-4">
          <h2 className="font-medium text-ink-primary">Recent Schema Drift</h2>
          {schemaDriftGroups.length > 0 ? (
            schemaDriftGroups.map((group) => (
              <SchemaDriftDiff
                key={`${group.method}:${group.endpoint}`}
                endpoint={group.endpoint}
                method={group.method}
                detectedAt={group.detectedAt}
                changes={group.changes}
              />
            ))
          ) : (
            <div className="card border border-border-subtle p-6 text-sm text-ink-muted">
              No schema drift events detected yet.
            </div>
          )}
        </div>

        <div className="card h-full">
          <div className="card-header">
            <h2 className="font-medium text-ink-primary">Top Violating Endpoints</h2>
          </div>
          <div className="card-body h-96">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.topViolatingEndpoints ?? []} layout="vertical" margin={{ left: 40 }}>
                <defs>
                  <linearGradient id="violationGradient" x1="0" y1="0" x2="1" y2="0">
                    <stop offset="0%" stopColor="#D62598" stopOpacity={0.9} />
                    <stop offset="100%" stopColor="#E35205" stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" horizontal={true} vertical={false} stroke="rgba(0, 87, 183, 0.15)" />
                <XAxis type="number" stroke="#7B8FA8" fontSize={12} hide />
                <YAxis dataKey="endpoint" type="category" width={150} stroke="#7B8FA8" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(0, 87, 183, 0.1)' }}
                  contentStyle={TOOLTIP_CONTENT_STYLE}
                  labelStyle={TOOLTIP_LABEL_STYLE}
                  itemStyle={TOOLTIP_ITEM_STYLE}
                />
                <Bar dataKey="violationCount" fill="url(#violationGradient)" radius={[0, 0, 0, 0]} barSize={18} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Endpoints Table and Violations Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <EndpointsTable
            endpoints={filteredEndpoints}
            totalCount={totalEndpoints}
            emptyMessage={searchQuery ? 'No endpoints match your search' : undefined}
          />
          {/* Pagination Controls */}
          {totalEndpoints > pagination.limit && (
            <div className="flex justify-between items-center p-4 border-t border-border-subtle bg-surface-base">
              <span className="text-sm text-ink-muted">
                Showing {pagination.offset + 1}-{Math.min(pagination.offset + pagination.limit, totalEndpoints)} of {totalEndpoints}
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => setPagination(p => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
                  disabled={pagination.offset === 0}
                  className="btn-outline text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  aria-label="Go to previous page"
                >
                  Previous
                </button>
                <button
                  onClick={() => setPagination(p => ({ ...p, offset: p.offset + p.limit }))}
                  disabled={!hasMore}
                  className="btn-outline text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                  aria-label="Go to next page"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
        <ViolationsFeed signals={signals} />
      </div>
    </div>
  );
}
