/**
 * API Catalog Page
 * Discovered endpoints and API inventory
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Shield,
  Clock,
  Activity,
} from 'lucide-react';
import { clsx } from 'clsx';
// import { useApexEndpoints } from '../../../stores/apexStore';
import { StatsGridSkeleton, TableSkeleton } from '../../../components/LoadingStates';

type SortField = 'path' | 'method' | 'requestCount' | 'lastSeenAt' | 'avgLatencyMs';
type SortDirection = 'asc' | 'desc';

// Demo data - discovered endpoints
const DEMO_ENDPOINTS = [
  {
    id: '1',
    method: 'GET',
    path: '/api/v1/users',
    pathTemplate: '/api/v1/users',
    service: 'user-service',
    firstSeenAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    requestCount: 125000,
    avgLatencyMs: 45,
    p95LatencyMs: 120,
    errorRate: 0.5,
    hasSchema: true,
    authRequired: true,
    sensitiveData: false,
  },
  {
    id: '2',
    method: 'POST',
    path: '/api/v1/users',
    pathTemplate: '/api/v1/users',
    service: 'user-service',
    firstSeenAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    requestCount: 45000,
    avgLatencyMs: 85,
    p95LatencyMs: 250,
    errorRate: 1.2,
    hasSchema: true,
    authRequired: true,
    sensitiveData: true,
  },
  {
    id: '3',
    method: 'GET',
    path: '/api/v1/products',
    pathTemplate: '/api/v1/products',
    service: 'product-service',
    firstSeenAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 1 * 60 * 1000).toISOString(),
    requestCount: 890000,
    avgLatencyMs: 32,
    p95LatencyMs: 95,
    errorRate: 0.2,
    hasSchema: true,
    authRequired: false,
    sensitiveData: false,
  },
  {
    id: '4',
    method: 'GET',
    path: '/api/v1/products/:id',
    pathTemplate: '/api/v1/products/{id}',
    service: 'product-service',
    firstSeenAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 30 * 1000).toISOString(),
    requestCount: 450000,
    avgLatencyMs: 28,
    p95LatencyMs: 85,
    errorRate: 0.8,
    hasSchema: true,
    authRequired: false,
    sensitiveData: false,
  },
  {
    id: '5',
    method: 'POST',
    path: '/api/v1/orders',
    pathTemplate: '/api/v1/orders',
    service: 'order-service',
    firstSeenAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    requestCount: 78000,
    avgLatencyMs: 120,
    p95LatencyMs: 380,
    errorRate: 2.1,
    hasSchema: true,
    authRequired: true,
    sensitiveData: true,
  },
  {
    id: '6',
    method: 'GET',
    path: '/api/v1/search',
    pathTemplate: '/api/v1/search',
    service: 'search-service',
    firstSeenAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 15 * 1000).toISOString(),
    requestCount: 1200000,
    avgLatencyMs: 180,
    p95LatencyMs: 520,
    errorRate: 0.3,
    hasSchema: false,
    authRequired: false,
    sensitiveData: false,
  },
  {
    id: '7',
    method: 'POST',
    path: '/api/v1/auth/login',
    pathTemplate: '/api/v1/auth/login',
    service: 'auth-service',
    firstSeenAt: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000).toISOString(),
    lastSeenAt: new Date(Date.now() - 5 * 1000).toISOString(),
    requestCount: 320000,
    avgLatencyMs: 95,
    p95LatencyMs: 280,
    errorRate: 3.5,
    hasSchema: true,
    authRequired: false,
    sensitiveData: true,
  },
];

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400 bg-green-500/20',
  POST: 'text-blue-400 bg-blue-500/20',
  PUT: 'text-yellow-400 bg-yellow-500/20',
  PATCH: 'text-orange-400 bg-orange-500/20',
  DELETE: 'text-red-400 bg-red-500/20',
};

// Stat Card
function StatCard({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ElementType;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        </div>
        <div className="p-3 bg-gray-700/50 rounded-lg">
          <Icon className="w-6 h-6 text-horizon-400" />
        </div>
      </div>
    </motion.div>
  );
}

// Search and Filter Bar
function SearchFilterBar({
  search,
  onSearchChange,
  methodFilter,
  onMethodFilterChange,
  serviceFilter,
  onServiceFilterChange,
  services,
}: {
  search: string;
  onSearchChange: (v: string) => void;
  methodFilter: string;
  onMethodFilterChange: (v: string) => void;
  serviceFilter: string;
  onServiceFilterChange: (v: string) => void;
  services: string[];
}) {
  return (
    <div className="flex items-center gap-4">
      <div className="relative flex-1 max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
        <input
          type="text"
          placeholder="Search endpoints..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-horizon-500 focus:border-transparent"
        />
      </div>
      <div className="flex items-center gap-2">
        <Filter className="w-4 h-4 text-gray-400" />
        <select
          value={methodFilter}
          onChange={(e) => onMethodFilterChange(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-horizon-500"
        >
          <option value="">All Methods</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="PATCH">PATCH</option>
          <option value="DELETE">DELETE</option>
        </select>
        <select
          value={serviceFilter}
          onChange={(e) => onServiceFilterChange(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-horizon-500"
        >
          <option value="">All Services</option>
          {services.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

// Sortable Table Header
function SortableHeader({
  label,
  field,
  sortField,
  sortDirection,
  onSort,
  align = 'left',
}: {
  label: string;
  field: SortField;
  sortField: SortField;
  sortDirection: SortDirection;
  onSort: (field: SortField) => void;
  align?: 'left' | 'right';
}) {
  const isActive = sortField === field;
  return (
    <th
      className={clsx(
        'px-5 py-3 font-medium cursor-pointer hover:text-white transition-colors',
        align === 'right' && 'text-right'
      )}
      onClick={() => onSort(field)}
    >
      <div className={clsx('flex items-center gap-1', align === 'right' && 'justify-end')}>
        <span>{label}</span>
        {isActive && (
          sortDirection === 'asc' ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )
        )}
      </div>
    </th>
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
  if (days < 30) return `${days}d ago`;

  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

// Endpoint Table Row
function EndpointRow({ endpoint }: { endpoint: typeof DEMO_ENDPOINTS[0] }) {
  return (
    <tr className="border-b border-gray-700/50 hover:bg-gray-750 transition-colors">
      <td className="px-5 py-4">
        <div className="flex items-center gap-3">
          <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', METHOD_COLORS[endpoint.method])}>
            {endpoint.method}
          </span>
          <div>
            <code className="text-blue-400 text-sm">{endpoint.pathTemplate}</code>
            <p className="text-xs text-gray-500 mt-0.5">{endpoint.service}</p>
          </div>
        </div>
      </td>
      <td className="px-5 py-4 text-right text-gray-300">
        {endpoint.requestCount.toLocaleString()}
      </td>
      <td className="px-5 py-4 text-right">
        <div>
          <span className="text-white font-medium">{endpoint.avgLatencyMs}ms</span>
          <span className="text-gray-500 text-xs ml-2">P95: {endpoint.p95LatencyMs}ms</span>
        </div>
      </td>
      <td className="px-5 py-4 text-right">
        <span
          className={clsx(
            'px-2 py-0.5 rounded text-xs font-medium',
            endpoint.errorRate < 1
              ? 'text-green-400 bg-green-500/20'
              : endpoint.errorRate < 2
              ? 'text-yellow-400 bg-yellow-500/20'
              : 'text-red-400 bg-red-500/20'
          )}
        >
          {endpoint.errorRate.toFixed(1)}%
        </span>
      </td>
      <td className="px-5 py-4 text-right text-gray-400 text-sm">
        {formatRelativeTime(endpoint.lastSeenAt)}
      </td>
      <td className="px-5 py-4">
        <div className="flex items-center justify-end gap-2">
          {endpoint.authRequired && (
            <span className="text-yellow-400" title="Auth Required">
              <Shield className="w-4 h-4" />
            </span>
          )}
          {endpoint.sensitiveData && (
            <span className="text-red-400" title="Contains Sensitive Data">
              <ExternalLink className="w-4 h-4" />
            </span>
          )}
          {endpoint.hasSchema && (
            <span className="text-green-400" title="Schema Detected">
              <Activity className="w-4 h-4" />
            </span>
          )}
        </div>
      </td>
    </tr>
  );
}

export default function ApiCatalogPage() {
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [serviceFilter, setServiceFilter] = useState('');
  const [sortField, setSortField] = useState<SortField>('requestCount');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');

  // Store integration will be added when backend is ready
  // const storeEndpoints = useApexEndpoints();
  const isLoading = false;

  // Use demo data for now (store types will be aligned later)
  const endpoints = DEMO_ENDPOINTS;

  // Get unique services
  const services = useMemo(() => {
    return [...new Set(endpoints.map((e) => e.service))].sort();
  }, [endpoints]);

  // Filter and sort endpoints
  const filteredEndpoints = useMemo(() => {
    let result = [...endpoints];

    // Apply search filter
    if (search) {
      const lowerSearch = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.path.toLowerCase().includes(lowerSearch) ||
          e.service.toLowerCase().includes(lowerSearch)
      );
    }

    // Apply method filter
    if (methodFilter) {
      result = result.filter((e) => e.method === methodFilter);
    }

    // Apply service filter
    if (serviceFilter) {
      result = result.filter((e) => e.service === serviceFilter);
    }

    // Apply sorting
    result.sort((a, b) => {
      let aVal: number | string;
      let bVal: number | string;

      switch (sortField) {
        case 'path':
          aVal = a.path;
          bVal = b.path;
          break;
        case 'method':
          aVal = a.method;
          bVal = b.method;
          break;
        case 'requestCount':
          aVal = a.requestCount;
          bVal = b.requestCount;
          break;
        case 'lastSeenAt':
          aVal = new Date(a.lastSeenAt).getTime();
          bVal = new Date(b.lastSeenAt).getTime();
          break;
        case 'avgLatencyMs':
          aVal = a.avgLatencyMs;
          bVal = b.avgLatencyMs;
          break;
        default:
          return 0;
      }

      if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });

    return result;
  }, [endpoints, search, methodFilter, serviceFilter, sortField, sortDirection]);

  // Calculate stats
  const stats = useMemo(() => {
    const totalEndpoints = endpoints.length;
    const totalRequests = endpoints.reduce((sum, e) => sum + e.requestCount, 0);
    const avgLatency = Math.round(
      endpoints.reduce((sum, e) => sum + e.avgLatencyMs, 0) / endpoints.length
    );
    const withSchema = endpoints.filter((e) => e.hasSchema).length;

    return { totalEndpoints, totalRequests, avgLatency, withSchema };
  }, [endpoints]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">API Catalog</h1>
          <p className="text-gray-400 mt-1">Loading endpoint data...</p>
        </div>
        <StatsGridSkeleton />
        <TableSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">API Catalog</h1>
        <p className="text-gray-400 mt-1">Discovered endpoints and API inventory</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Endpoints" value={stats.totalEndpoints.toString()} icon={Activity} />
        <StatCard
          label="Total Requests"
          value={`${(stats.totalRequests / 1000000).toFixed(1)}M`}
          icon={ExternalLink}
        />
        <StatCard label="Avg Latency" value={`${stats.avgLatency}ms`} icon={Clock} />
        <StatCard
          label="Schema Coverage"
          value={`${Math.round((stats.withSchema / stats.totalEndpoints) * 100)}%`}
          icon={Shield}
        />
      </div>

      {/* Search and Filters */}
      <SearchFilterBar
        search={search}
        onSearchChange={setSearch}
        methodFilter={methodFilter}
        onMethodFilterChange={setMethodFilter}
        serviceFilter={serviceFilter}
        onServiceFilterChange={setServiceFilter}
        services={services}
      />

      {/* Endpoints Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="text-left text-sm text-gray-400 border-b border-gray-700 bg-gray-800/50">
                <SortableHeader
                  label="Endpoint"
                  field="path"
                  sortField={sortField}
                  sortDirection={sortDirection}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Requests"
                  field="requestCount"
                  sortField={sortField}
                  sortDirection={sortDirection}
                  onSort={handleSort}
                  align="right"
                />
                <SortableHeader
                  label="Latency"
                  field="avgLatencyMs"
                  sortField={sortField}
                  sortDirection={sortDirection}
                  onSort={handleSort}
                  align="right"
                />
                <th className="px-5 py-3 font-medium text-right">Error Rate</th>
                <SortableHeader
                  label="Last Seen"
                  field="lastSeenAt"
                  sortField={sortField}
                  sortDirection={sortDirection}
                  onSort={handleSort}
                  align="right"
                />
                <th className="px-5 py-3 font-medium text-right">Flags</th>
              </tr>
            </thead>
            <tbody>
              {filteredEndpoints.map((endpoint) => (
                <EndpointRow key={endpoint.id} endpoint={endpoint} />
              ))}
            </tbody>
          </table>
        </div>
        {filteredEndpoints.length === 0 && (
          <div className="p-8 text-center text-gray-400">
            No endpoints match your filters
          </div>
        )}
      </div>
    </div>
  );
}
