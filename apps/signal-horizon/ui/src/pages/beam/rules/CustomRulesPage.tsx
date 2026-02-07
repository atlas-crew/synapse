/**
 * Custom Rules Page
 * Create and manage custom protection rules
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Plus,
  Shield,
  Pencil,
  Trash2,
  Copy,
  Play,
  Pause,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  Code,
  Activity,
} from 'lucide-react';
import { clsx } from 'clsx';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type RuleStatus = 'active' | 'draft' | 'testing' | 'paused';

// Demo data - custom rules
const DEMO_CUSTOM_RULES = [
  {
    id: '1',
    name: 'Block Known Bad IPs',
    description: 'Custom IP blocklist for known malicious actors',
    status: 'active' as RuleStatus,
    action: 'block',
    conditions: [
      { type: 'ip', operator: 'in', value: 'bad-ip-list' },
    ],
    triggers: 4500,
    blocks: 4500,
    lastModified: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'admin@company.com',
  },
  {
    id: '2',
    name: 'Rate Limit API Export',
    description: 'Limit bulk data export endpoints to prevent scraping',
    status: 'active' as RuleStatus,
    action: 'rate-limit',
    conditions: [
      { type: 'path', operator: 'contains', value: '/export' },
      { type: 'method', operator: 'equals', value: 'GET' },
    ],
    triggers: 1200,
    blocks: 350,
    lastModified: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'security@company.com',
  },
  {
    id: '3',
    name: 'Block Admin API from External',
    description: 'Restrict admin endpoints to internal network only',
    status: 'active' as RuleStatus,
    action: 'block',
    conditions: [
      { type: 'path', operator: 'starts-with', value: '/api/admin' },
      { type: 'ip', operator: 'not-in', value: 'internal-ips' },
    ],
    triggers: 890,
    blocks: 890,
    lastModified: new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'admin@company.com',
  },
  {
    id: '4',
    name: 'Detect Large Payload Uploads',
    description: 'Alert on unusually large request payloads',
    status: 'testing' as RuleStatus,
    action: 'alert',
    conditions: [
      { type: 'content-length', operator: 'greater-than', value: '10485760' },
    ],
    triggers: 45,
    blocks: 0,
    lastModified: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString(),
    createdBy: 'security@company.com',
  },
  {
    id: '5',
    name: 'Block Deprecated API Versions',
    description: 'Block requests to deprecated API versions',
    status: 'draft' as RuleStatus,
    action: 'block',
    conditions: [
      { type: 'path', operator: 'matches', value: '/api/v[0-1]/' },
    ],
    triggers: 0,
    blocks: 0,
    lastModified: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(),
    createdBy: 'dev@company.com',
  },
];

const STATUS_CONFIG: Record<RuleStatus, { color: string; bg: string; label: string }> = {
  active: { color: 'text-green-400', bg: 'bg-green-500/20', label: 'Active' },
  draft: { color: 'text-gray-400', bg: 'bg-gray-500/20', label: 'Draft' },
  testing: { color: 'text-blue-400', bg: 'bg-blue-500/20', label: 'Testing' },
  paused: { color: 'text-sky-400', bg: 'bg-sky-500/20', label: 'Paused' },
};

const ACTION_CONFIG: Record<string, { color: string; label: string }> = {
  block: { color: 'text-red-400', label: 'Block' },
  'rate-limit': { color: 'text-sky-400', label: 'Rate Limit' },
  alert: { color: 'text-blue-400', label: 'Alert' },
  log: { color: 'text-gray-400', label: 'Log' },
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
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// Custom Rule Card
function CustomRuleCard({
  rule,
  isExpanded,
  onToggle,
  onDelete,
  onDuplicate,
  onToggleStatus,
}: {
  rule: typeof DEMO_CUSTOM_RULES[0];
  isExpanded: boolean;
  onToggle: () => void;
  onDelete: () => void;
  onDuplicate: () => void;
  onToggleStatus: () => void;
}) {
  const statusConfig = STATUS_CONFIG[rule.status];
  const actionConfig = ACTION_CONFIG[rule.action];

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle overflow-hidden"
    >
      <div className="px-5 py-4 flex items-center justify-between">
        <button
          onClick={onToggle}
          className="flex items-center gap-4 flex-1 text-left"
        >
          <div className="p-2 bg-surface-subtle">
            <Code className="w-5 h-5 text-horizon-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-ink-primary font-medium">{rule.name}</h3>
              <span className={clsx('px-2 py-0.5 text-xs font-medium', statusConfig.color, statusConfig.bg)}>
                {statusConfig.label}
              </span>
              <span className={clsx('px-2 py-0.5 text-xs font-medium', actionConfig.color, 'bg-surface-subtle')}>
                {actionConfig.label}
              </span>
            </div>
            <p className="text-sm text-ink-secondary mt-0.5">{rule.description}</p>
          </div>
        </button>

        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-sm text-ink-secondary">Triggers</p>
            <p className="text-ink-primary font-medium">{rule.triggers.toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-ink-secondary">Blocks</p>
            <p className="text-ink-primary font-medium">{rule.blocks.toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-ink-secondary">Modified</p>
            <p className="text-ink-secondary text-sm">{formatRelativeTime(rule.lastModified)}</p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onToggleStatus();
              }}
              className="p-2 text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              title={rule.status === 'active' ? 'Pause' : 'Activate'}
            >
              {rule.status === 'active' ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDuplicate();
              }}
              className="p-2 text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              title="Duplicate"
            >
              <Copy className="w-4 h-4" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDelete();
              }}
              className="p-2 text-ink-secondary hover:text-red-400 hover:bg-surface-subtle transition-colors"
              title="Delete"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
          <button onClick={onToggle}>
            {isExpanded ? (
              <ChevronDown className="w-5 h-5 text-ink-secondary" />
            ) : (
              <ChevronRight className="w-5 h-5 text-ink-secondary" />
            )}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="px-5 py-4 border-t border-border-subtle bg-surface-subtle">
          <div className="space-y-4">
            <div>
              <p className="text-sm text-ink-secondary mb-2">Conditions</p>
              <div className="space-y-2">
                {rule.conditions.map((condition, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 text-sm"
                  >
                    <span className="px-2 py-1 bg-surface-subtle text-blue-400 font-mono">
                      {condition.type}
                    </span>
                    <span className="text-ink-secondary">{condition.operator}</span>
                    <span className="px-2 py-1 bg-surface-subtle text-green-400 font-mono">
                      {condition.value}
                    </span>
                    {idx < rule.conditions.length - 1 && (
                      <span className="text-ink-muted">AND</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm text-ink-secondary">
              <span>Created by: {rule.createdBy}</span>
            </div>
            <div className="flex items-center gap-3">
              <button className="px-4 py-2 bg-surface-subtle hover:bg-surface-card text-ink-primary text-sm font-medium transition-colors flex items-center gap-2">
                <Pencil className="w-4 h-4" />
                Edit Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function CustomRulesPage() {
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());
  const [rules, setRules] = useState(DEMO_CUSTOM_RULES);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const isLoading = false;

  // Filter rules
  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      if (search && !r.name.toLowerCase().includes(search.toLowerCase())) {
        return false;
      }
      if (statusFilter && r.status !== statusFilter) {
        return false;
      }
      return true;
    });
  }, [rules, search, statusFilter]);

  // Calculate stats
  const stats = useMemo(() => {
    const total = rules.length;
    const active = rules.filter((r) => r.status === 'active').length;
    const totalTriggers = rules.reduce((sum, r) => sum + r.triggers, 0);
    const totalBlocks = rules.reduce((sum, r) => sum + r.blocks, 0);

    return { total, active, totalTriggers, totalBlocks };
  }, [rules]);

  const toggleRule = (ruleId: string) => {
    const newExpanded = new Set(expandedRules);
    if (newExpanded.has(ruleId)) {
      newExpanded.delete(ruleId);
    } else {
      newExpanded.add(ruleId);
    }
    setExpandedRules(newExpanded);
  };

  const handleDelete = (ruleId: string) => {
    setRules((prev) => prev.filter((r) => r.id !== ruleId));
  };

  const handleDuplicate = (ruleId: string) => {
    const ruleToDuplicate = rules.find((r) => r.id === ruleId);
    if (ruleToDuplicate) {
      const newRule = {
        ...ruleToDuplicate,
        id: String(Date.now()),
        name: `${ruleToDuplicate.name} (Copy)`,
        status: 'draft' as RuleStatus,
        triggers: 0,
        blocks: 0,
        lastModified: new Date().toISOString(),
      };
      setRules((prev) => [newRule, ...prev]);
    }
  };

  const handleToggleStatus = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) =>
        r.id === ruleId
          ? { ...r, status: r.status === 'active' ? 'paused' : 'active' as RuleStatus }
          : r
      )
    );
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-light text-ink-primary">Custom Rules</h1>
          <p className="text-ink-secondary mt-1">Loading rules...</p>
        </div>
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-light text-ink-primary">Custom Rules</h1>
          <p className="text-ink-secondary mt-1">Custom rule creation and management</p>
        </div>
        <button className="px-4 py-2 bg-horizon-600 hover:bg-horizon-500 text-white font-medium transition-colors flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Create Rule
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Rules" value={stats.total.toString()} icon={Shield} />
        <StatCard
          label="Active Rules"
          value={stats.active.toString()}
          icon={Activity}
          color="text-green-400"
        />
        <StatCard
          label="Total Triggers"
          value={stats.totalTriggers.toLocaleString()}
          icon={Activity}
          color="text-sky-400"
        />
        <StatCard
          label="Total Blocks"
          value={stats.totalBlocks.toLocaleString()}
          icon={Shield}
          color="text-red-400"
        />
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-secondary" />
          <input
            type="text"
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search rules"
            className="w-full pl-10 pr-4 py-2 bg-surface-card border border-border-subtle text-ink-primary placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-horizon-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-ink-secondary" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 bg-surface-card border border-border-subtle text-ink-primary focus:outline-none focus:ring-2 focus:ring-horizon-500"
          >
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="draft">Draft</option>
            <option value="testing">Testing</option>
            <option value="paused">Paused</option>
          </select>
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {filteredRules.map((rule) => (
          <CustomRuleCard
            key={rule.id}
            rule={rule}
            isExpanded={expandedRules.has(rule.id)}
            onToggle={() => toggleRule(rule.id)}
            onDelete={() => handleDelete(rule.id)}
            onDuplicate={() => handleDuplicate(rule.id)}
            onToggleStatus={() => handleToggleStatus(rule.id)}
          />
        ))}
      </div>

      {filteredRules.length === 0 && (
        <div className="bg-surface-card border border-border-subtle p-8 text-center">
          <p className="text-ink-secondary">No custom rules found</p>
          <button className="mt-4 px-4 py-2 bg-horizon-600 hover:bg-horizon-500 text-white font-medium transition-colors">
            Create Your First Rule
          </button>
        </div>
      )}
    </div>
  );
}
