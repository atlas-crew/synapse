/**
 * Schema Changes Page
 * API schema drift detection and versioning timeline
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  GitBranch,
  AlertTriangle,
  CheckCircle,
  Plus,
  Minus,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Clock,
  Filter,
} from 'lucide-react';
import { clsx } from 'clsx';
// import { useSchemaChanges } from '../../../stores/apexStore';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type ChangeType = 'added' | 'removed' | 'modified' | 'deprecated';

// Demo data - schema changes
const DEMO_SCHEMA_CHANGES = [
  {
    id: '1',
    endpoint: '/api/v1/users',
    method: 'POST',
    service: 'user-service',
    changeType: 'added' as ChangeType,
    field: 'profile.preferences.notifications',
    fieldType: 'object',
    description: 'Added notification preferences to user profile',
    detectedAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    breaking: false,
    acknowledged: false,
  },
  {
    id: '2',
    endpoint: '/api/v1/orders',
    method: 'POST',
    service: 'order-service',
    changeType: 'modified' as ChangeType,
    field: 'items[].quantity',
    fieldType: 'integer → number',
    description: 'Changed quantity from integer to float to support fractional units',
    detectedAt: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString(),
    breaking: true,
    acknowledged: true,
  },
  {
    id: '3',
    endpoint: '/api/v1/products/:id',
    method: 'GET',
    service: 'product-service',
    changeType: 'added' as ChangeType,
    field: 'inventory.warehouse_locations',
    fieldType: 'array',
    description: 'Added warehouse location tracking to product response',
    detectedAt: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    breaking: false,
    acknowledged: true,
  },
  {
    id: '4',
    endpoint: '/api/v1/auth/login',
    method: 'POST',
    service: 'auth-service',
    changeType: 'deprecated' as ChangeType,
    field: 'remember_me',
    fieldType: 'boolean',
    description: 'Deprecated in favor of token-based session management',
    detectedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    breaking: false,
    acknowledged: false,
  },
  {
    id: '5',
    endpoint: '/api/v1/payments',
    method: 'POST',
    service: 'payment-service',
    changeType: 'removed' as ChangeType,
    field: 'legacy_payment_method',
    fieldType: 'string',
    description: 'Removed legacy payment method field after migration',
    detectedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
    breaking: true,
    acknowledged: true,
  },
  {
    id: '6',
    endpoint: '/api/v1/search',
    method: 'GET',
    service: 'search-service',
    changeType: 'added' as ChangeType,
    field: 'filters.date_range',
    fieldType: 'object',
    description: 'Added date range filtering support',
    detectedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    breaking: false,
    acknowledged: true,
  },
];

const CHANGE_TYPE_CONFIG: Record<ChangeType, { icon: React.ElementType; color: string; label: string }> = {
  added: { icon: Plus, color: 'text-green-400 bg-green-500/20', label: 'Added' },
  removed: { icon: Minus, color: 'text-red-400 bg-red-500/20', label: 'Removed' },
  modified: { icon: RefreshCw, color: 'text-yellow-400 bg-yellow-500/20', label: 'Modified' },
  deprecated: { icon: AlertTriangle, color: 'text-orange-400 bg-orange-500/20', label: 'Deprecated' },
};

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400',
  POST: 'text-blue-400',
  PUT: 'text-yellow-400',
  PATCH: 'text-orange-400',
  DELETE: 'text-red-400',
};

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
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        </div>
        <div className="p-3 bg-gray-700/50 rounded-lg">
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
  change: typeof DEMO_SCHEMA_CHANGES[0];
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
        'bg-gray-800 border rounded-xl overflow-hidden transition-colors',
        change.breaking && !change.acknowledged
          ? 'border-red-500/50'
          : 'border-gray-700'
      )}
    >
      <button
        onClick={onToggle}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-4">
          <div className={clsx('p-2 rounded-lg', config.color)}>
            <ChangeIcon className="w-4 h-4" />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <span className={clsx('text-sm font-medium', METHOD_COLORS[change.method])}>
                {change.method}
              </span>
              <code className="text-blue-400 text-sm">{change.endpoint}</code>
            </div>
            <p className="text-sm text-gray-400 mt-0.5">
              <span className="font-mono text-gray-300">{change.field}</span>
              <span className="mx-2">→</span>
              <span className="text-gray-500">{change.fieldType}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          {change.breaking && (
            <span className="px-2 py-0.5 rounded text-xs font-medium text-red-400 bg-red-500/20">
              Breaking
            </span>
          )}
          {change.acknowledged ? (
            <span className="text-green-400">
              <CheckCircle className="w-4 h-4" />
            </span>
          ) : (
            <span className="px-2 py-0.5 rounded text-xs font-medium text-yellow-400 bg-yellow-500/20">
              Unacknowledged
            </span>
          )}
          <span className="text-sm text-gray-400 flex items-center gap-1">
            <Clock className="w-4 h-4" />
            {formatRelativeTime(change.detectedAt)}
          </span>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
      </button>

      {isExpanded && (
        <div className="px-5 py-4 border-t border-gray-700 bg-gray-800/50">
          <div className="space-y-3">
            <div>
              <p className="text-sm text-gray-400">Description</p>
              <p className="text-white mt-1">{change.description}</p>
            </div>
            <div className="flex items-center gap-6">
              <div>
                <p className="text-sm text-gray-400">Service</p>
                <p className="text-white mt-1">{change.service}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Change Type</p>
                <p className="text-white mt-1 capitalize">{change.changeType}</p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Detected</p>
                <p className="text-white mt-1">
                  {new Date(change.detectedAt).toLocaleString()}
                </p>
              </div>
            </div>
            {!change.acknowledged && (
              <button className="px-4 py-2 bg-horizon-600 hover:bg-horizon-500 text-white rounded-lg text-sm font-medium transition-colors">
                Acknowledge Change
              </button>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function SchemaChangesPage() {
  const [expandedChanges, setExpandedChanges] = useState<Set<string>>(new Set());
  const [typeFilter, setTypeFilter] = useState<string>('');
  const [showBreakingOnly, setShowBreakingOnly] = useState(false);
  const [showUnacknowledgedOnly, setShowUnacknowledgedOnly] = useState(false);

  // Store integration will be added when backend is ready
  // const storeChanges = useSchemaChanges();
  const isLoading = false;

  // Use demo data for now
  const allChanges = DEMO_SCHEMA_CHANGES;

  // Filter changes
  const filteredChanges = useMemo(() => {
    let result = [...allChanges];

    if (typeFilter) {
      result = result.filter((c) => c.changeType === typeFilter);
    }

    if (showBreakingOnly) {
      result = result.filter((c) => c.breaking);
    }

    if (showUnacknowledgedOnly) {
      result = result.filter((c) => !c.acknowledged);
    }

    return result;
  }, [allChanges, typeFilter, showBreakingOnly, showUnacknowledgedOnly]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = allChanges.length;
    const breaking = allChanges.filter((c) => c.breaking).length;
    const unacknowledged = allChanges.filter((c) => !c.acknowledged).length;
    const thisWeek = allChanges.filter((c) => {
      const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      return new Date(c.detectedAt).getTime() > weekAgo;
    }).length;

    return { total, breaking, unacknowledged, thisWeek };
  }, [allChanges]);

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
          <h1 className="text-2xl font-bold text-white">Schema Changes</h1>
          <p className="text-gray-400 mt-1">Loading schema change data...</p>
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
        <h1 className="text-2xl font-bold text-white">Schema Changes</h1>
        <p className="text-gray-400 mt-1">API schema drift detection and versioning</p>
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
          label="Unacknowledged"
          value={stats.unacknowledged.toString()}
          icon={Clock}
          color="text-yellow-400"
        />
        <StatCard
          label="This Week"
          value={stats.thisWeek.toString()}
          icon={RefreshCw}
          color="text-green-400"
        />
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-400" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-horizon-500"
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
            className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-horizon-600 focus:ring-horizon-500"
          />
          <span className="text-sm text-gray-300">Breaking only</span>
        </label>
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={showUnacknowledgedOnly}
            onChange={(e) => setShowUnacknowledgedOnly(e.target.checked)}
            className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-horizon-600 focus:ring-horizon-500"
          />
          <span className="text-sm text-gray-300">Unacknowledged only</span>
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
          <div className="bg-gray-800 border border-gray-700 rounded-xl p-8 text-center">
            <p className="text-gray-400">No schema changes match your filters</p>
          </div>
        )}
      </div>
    </div>
  );
}
