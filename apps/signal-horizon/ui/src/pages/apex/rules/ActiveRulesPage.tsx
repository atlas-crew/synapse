/**
 * Active Rules Page
 * Protection rules currently deployed across sensors
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Play,
  Pause,
  Settings,
  ChevronDown,
  ChevronRight,
  Activity,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { clsx } from 'clsx';
// import { useActiveRules } from '../../../stores/apexStore';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

type RuleStatus = 'active' | 'paused' | 'deploying' | 'failed';
type RuleSeverity = 'critical' | 'high' | 'medium' | 'low';

// Demo data - active rules
const DEMO_ACTIVE_RULES = [
  {
    id: '1',
    name: 'SQL Injection Prevention',
    description: 'Detects and blocks SQL injection attempts in query parameters and request bodies',
    category: 'Injection',
    severity: 'critical' as RuleSeverity,
    status: 'active' as RuleStatus,
    enabled: true,
    triggers: 1250,
    blocks: 1180,
    lastTriggered: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
    deployedSensors: 12,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '2',
    name: 'XSS Attack Detection',
    description: 'Identifies cross-site scripting attempts in user inputs',
    category: 'Injection',
    severity: 'high' as RuleSeverity,
    status: 'active' as RuleStatus,
    enabled: true,
    triggers: 890,
    blocks: 850,
    lastTriggered: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
    deployedSensors: 12,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 85 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '3',
    name: 'Rate Limiting - Auth Endpoints',
    description: 'Limits authentication attempts to prevent brute force attacks',
    category: 'Rate Limiting',
    severity: 'high' as RuleSeverity,
    status: 'active' as RuleStatus,
    enabled: true,
    triggers: 4500,
    blocks: 3200,
    lastTriggered: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
    deployedSensors: 12,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '4',
    name: 'Bot Detection - Credential Stuffing',
    description: 'Detects automated credential stuffing attacks',
    category: 'Bot Protection',
    severity: 'critical' as RuleSeverity,
    status: 'deploying' as RuleStatus,
    enabled: true,
    triggers: 0,
    blocks: 0,
    lastTriggered: null,
    deployedSensors: 8,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '5',
    name: 'Path Traversal Prevention',
    description: 'Blocks directory traversal attacks in file paths',
    category: 'Injection',
    severity: 'medium' as RuleSeverity,
    status: 'paused' as RuleStatus,
    enabled: false,
    triggers: 120,
    blocks: 115,
    lastTriggered: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    deployedSensors: 0,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: '6',
    name: 'API Key Exposure Detection',
    description: 'Monitors for accidental API key exposure in responses',
    category: 'Data Protection',
    severity: 'high' as RuleSeverity,
    status: 'failed' as RuleStatus,
    enabled: true,
    triggers: 0,
    blocks: 0,
    lastTriggered: null,
    deployedSensors: 3,
    totalSensors: 12,
    createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
  },
];

const SEVERITY_CONFIG: Record<RuleSeverity, { color: string; bg: string }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-500/20' },
  high: { color: 'text-orange-400', bg: 'bg-orange-500/20' },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-500/20' },
  low: { color: 'text-blue-400', bg: 'bg-blue-500/20' },
};

const STATUS_CONFIG: Record<RuleStatus, { icon: React.ElementType; color: string; label: string }> = {
  active: { icon: ShieldCheck, color: 'text-green-400', label: 'Active' },
  paused: { icon: ShieldOff, color: 'text-gray-400', label: 'Paused' },
  deploying: { icon: Clock, color: 'text-blue-400', label: 'Deploying' },
  failed: { icon: ShieldAlert, color: 'text-red-400', label: 'Failed' },
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
function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return 'Never';
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

// Rule Card Component
function RuleCard({
  rule,
  isExpanded,
  onToggle,
  onToggleEnabled,
}: {
  rule: typeof DEMO_ACTIVE_RULES[0];
  isExpanded: boolean;
  onToggle: () => void;
  onToggleEnabled: () => void;
}) {
  const severityConfig = SEVERITY_CONFIG[rule.severity];
  const statusConfig = STATUS_CONFIG[rule.status];
  const StatusIcon = statusConfig.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={clsx(
        'bg-gray-800 border rounded-xl overflow-hidden',
        rule.status === 'failed'
          ? 'border-red-500/50'
          : rule.status === 'deploying'
          ? 'border-blue-500/50'
          : 'border-gray-700'
      )}
    >
      <div className="px-5 py-4 flex items-center justify-between">
        <button
          onClick={onToggle}
          className="flex items-center gap-4 flex-1 text-left"
        >
          <div className="p-2 bg-gray-700 rounded-lg">
            <Shield className="w-5 h-5 text-horizon-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-white font-medium">{rule.name}</h3>
              <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityConfig.color, severityConfig.bg)}>
                {rule.severity}
              </span>
            </div>
            <p className="text-sm text-gray-400 mt-0.5">{rule.category}</p>
          </div>
        </button>

        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-sm text-gray-400">Triggers</p>
            <p className="text-white font-medium">{rule.triggers.toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Blocks</p>
            <p className="text-white font-medium">{rule.blocks.toLocaleString()}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Last Triggered</p>
            <p className="text-gray-300 text-sm">{formatRelativeTime(rule.lastTriggered)}</p>
          </div>
          <div className={clsx('flex items-center gap-1', statusConfig.color)}>
            <StatusIcon className="w-4 h-4" />
            <span className="text-sm">{statusConfig.label}</span>
            {rule.status === 'deploying' && (
              <span className="text-xs text-gray-400">
                ({rule.deployedSensors}/{rule.totalSensors})
              </span>
            )}
          </div>
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggleEnabled();
            }}
            className={clsx(
              'relative w-12 h-6 rounded-full transition-colors',
              rule.enabled ? 'bg-horizon-600' : 'bg-gray-600'
            )}
          >
            <span
              className={clsx(
                'absolute top-1 w-4 h-4 bg-white rounded-full transition-transform',
                rule.enabled ? 'left-7' : 'left-1'
              )}
            />
          </button>
          <button onClick={onToggle}>
            {isExpanded ? (
              <ChevronDown className="w-5 h-5 text-gray-400" />
            ) : (
              <ChevronRight className="w-5 h-5 text-gray-400" />
            )}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="px-5 py-4 border-t border-gray-700 bg-gray-800/50">
          <div className="space-y-4">
            <div>
              <p className="text-sm text-gray-400">Description</p>
              <p className="text-white mt-1">{rule.description}</p>
            </div>
            <div className="flex items-center gap-8">
              <div>
                <p className="text-sm text-gray-400">Deployed Sensors</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-32 h-2 bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={clsx(
                        'h-full rounded-full',
                        rule.deployedSensors === rule.totalSensors
                          ? 'bg-green-500'
                          : rule.deployedSensors > 0
                          ? 'bg-yellow-500'
                          : 'bg-gray-600'
                      )}
                      style={{ width: `${(rule.deployedSensors / rule.totalSensors) * 100}%` }}
                    />
                  </div>
                  <span className="text-white text-sm">
                    {rule.deployedSensors}/{rule.totalSensors}
                  </span>
                </div>
              </div>
              <div>
                <p className="text-sm text-gray-400">Block Rate</p>
                <p className="text-white mt-1">
                  {rule.triggers > 0 ? ((rule.blocks / rule.triggers) * 100).toFixed(1) : 0}%
                </p>
              </div>
              <div>
                <p className="text-sm text-gray-400">Created</p>
                <p className="text-white mt-1">
                  {new Date(rule.createdAt).toLocaleDateString()}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {rule.status === 'paused' && (
                <button className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                  <Play className="w-4 h-4" />
                  Resume
                </button>
              )}
              {rule.status === 'active' && (
                <button className="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                  <Pause className="w-4 h-4" />
                  Pause
                </button>
              )}
              {rule.status === 'failed' && (
                <button className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                  <Play className="w-4 h-4" />
                  Retry Deployment
                </button>
              )}
              <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2">
                <Settings className="w-4 h-4" />
                Configure
              </button>
            </div>
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function ActiveRulesPage() {
  const [expandedRules, setExpandedRules] = useState<Set<string>>(new Set());
  const [rules, setRules] = useState(DEMO_ACTIVE_RULES);

  // Store integration will be added when backend is ready
  // const storeRules = useActiveRules();
  const isLoading = false;

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

  const toggleRuleEnabled = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) =>
        r.id === ruleId
          ? { ...r, enabled: !r.enabled, status: r.enabled ? 'paused' : 'active' as RuleStatus }
          : r
      )
    );
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Active Rules</h1>
          <p className="text-gray-400 mt-1">Loading rules...</p>
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
        <h1 className="text-2xl font-bold text-white">Active Rules</h1>
        <p className="text-gray-400 mt-1">Protection rules and policies</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Rules" value={stats.total.toString()} icon={Shield} />
        <StatCard
          label="Active Rules"
          value={stats.active.toString()}
          icon={ShieldCheck}
          color="text-green-400"
        />
        <StatCard
          label="Total Triggers"
          value={stats.totalTriggers.toLocaleString()}
          icon={Activity}
          color="text-yellow-400"
        />
        <StatCard
          label="Total Blocks"
          value={stats.totalBlocks.toLocaleString()}
          icon={AlertTriangle}
          color="text-red-400"
        />
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {rules.map((rule) => (
          <RuleCard
            key={rule.id}
            rule={rule}
            isExpanded={expandedRules.has(rule.id)}
            onToggle={() => toggleRule(rule.id)}
            onToggleEnabled={() => toggleRuleEnabled(rule.id)}
          />
        ))}
      </div>
    </div>
  );
}
