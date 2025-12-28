import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard, SensorStatusBadge } from '../../components/fleet';
import { useSensors } from '../../hooks/fleet';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3003';

interface Rule {
  id: string;
  name: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  enabled: boolean;
  category: string;
  createdAt: string;
}

interface RuleSyncStatus {
  sensorId: string;
  totalRules: number;
  syncedRules: number;
  pendingRules: number;
  failedRules: number;
  lastSync?: string;
}

type RolloutStrategy = 'immediate' | 'canary' | 'scheduled';

async function fetchRules(): Promise<Rule[]> {
  const response = await fetch(`${API_BASE}/api/fleet/rules`);
  if (!response.ok) throw new Error('Failed to fetch rules');
  return response.json();
}

async function fetchRuleSyncStatus(): Promise<RuleSyncStatus[]> {
  const response = await fetch(`${API_BASE}/api/fleet/rules/sync-status`);
  if (!response.ok) throw new Error('Failed to fetch sync status');
  return response.json();
}

async function pushRules(
  ruleIds: string[],
  sensorIds: string[],
  strategy: RolloutStrategy
): Promise<void> {
  const response = await fetch(`${API_BASE}/api/fleet/rules/push`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ruleIds, sensorIds, strategy }),
  });
  if (!response.ok) throw new Error('Failed to push rules');
}

export function RuleDistributionPage() {
  const queryClient = useQueryClient();
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());
  const [selectedSensors, setSelectedSensors] = useState<Set<string>>(new Set());
  const [rolloutStrategy, setRolloutStrategy] = useState<RolloutStrategy>('immediate');
  const [showDeployModal, setShowDeployModal] = useState(false);

  const { data: rules = [], isLoading: rulesLoading } = useQuery({
    queryKey: ['fleet', 'rules'],
    queryFn: fetchRules,
  });

  const { data: syncStatus = [] } = useQuery({
    queryKey: ['fleet', 'rules', 'sync-status'],
    queryFn: fetchRuleSyncStatus,
    refetchInterval: 10000,
  });

  const { data: sensors = [] } = useSensors();

  const pushMutation = useMutation({
    mutationFn: () =>
      pushRules(Array.from(selectedRules), Array.from(selectedSensors), rolloutStrategy),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'rules'] });
      setShowDeployModal(false);
      setSelectedRules(new Set());
      setSelectedSensors(new Set());
    },
  });

  const toggleRule = useCallback((ruleId: string) => {
    setSelectedRules((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(ruleId)) newSet.delete(ruleId);
      else newSet.add(ruleId);
      return newSet;
    });
  }, []);

  const toggleSensor = useCallback((sensorId: string) => {
    setSelectedSensors((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(sensorId)) newSet.delete(sensorId);
      else newSet.add(sensorId);
      return newSet;
    });
  }, []);

  const totalSynced = syncStatus.reduce((sum, s) => sum + s.syncedRules, 0);
  const totalPending = syncStatus.reduce((sum, s) => sum + s.pendingRules, 0);
  const totalFailed = syncStatus.reduce((sum, s) => sum + s.failedRules, 0);

  const severityColors = {
    low: 'bg-surface-subtle text-ink-secondary border-border-subtle',
    medium: 'bg-ac-blue/10 text-ac-blue border-ac-blue/30',
    high: 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
    critical: 'bg-ac-red/10 text-ac-red border-ac-red/30',
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Rule Distribution</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Deploy and manage WAF rules across your sensor fleet
          </p>
        </div>
        <button
          onClick={() => setShowDeployModal(true)}
          disabled={selectedRules.size === 0}
          className="btn-primary h-12 px-6 text-sm"
        >
          Deploy Selected ({selectedRules.size})
        </button>
      </div>

      {/* Sync Status */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard label="Total Rules" value={rules.length} />
        <MetricCard label="Synced" value={totalSynced} className="border-ac-green/40" />
        <MetricCard
          label="Pending"
          value={totalPending}
          className={totalPending > 0 ? 'border-ac-orange/40' : ''}
        />
        <MetricCard
          label="Failed"
          value={totalFailed}
          className={totalFailed > 0 ? 'border-ac-red/40' : ''}
        />
      </div>

      {/* Rules Table */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-medium text-ink-primary">WAF Rules</h2>
          <div className="flex gap-2">
            <button
              onClick={() => setSelectedRules(new Set(rules.map((r) => r.id)))}
              className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle"
            >
              Select All
            </button>
            <button
              onClick={() => setSelectedRules(new Set())}
              className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle"
            >
              Clear Selection
            </button>
          </div>
        </div>

        {rulesLoading ? (
          <div className="p-12 text-center text-ink-muted">Loading rules...</div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center text-ink-muted">No rules found.</div>
        ) : (
          <table className="min-w-full divide-y divide-border-subtle">
            <thead className="bg-surface-subtle">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                  Select
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                  Name
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                  Category
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                  Severity
                </th>
                <th className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="bg-surface-base divide-y divide-border-subtle">
              {rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-surface-subtle">
                  <td className="px-6 py-4">
                    <input
                      type="checkbox"
                      checked={selectedRules.has(rule.id)}
                      onChange={() => toggleRule(rule.id)}
                      className="w-4 h-4 text-ac-blue border-border-subtle"
                    />
                  </td>
                  <td className="px-6 py-4">
                    <div className="font-medium text-ink-primary">{rule.name}</div>
                    {rule.description && (
                      <div className="text-sm text-ink-muted">{rule.description}</div>
                    )}
                  </td>
                  <td className="px-6 py-4 text-sm text-ink-secondary">{rule.category}</td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-2 py-1 text-xs font-medium border ${severityColors[rule.severity]}`}
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <span
                      className={`px-2 py-1 text-xs font-medium ${
                        rule.enabled
                          ? 'bg-ac-green/10 text-ac-green border border-ac-green/30'
                          : 'bg-surface-subtle text-ink-secondary border border-border-subtle'
                      }`}
                    >
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Deploy Modal */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50">
          <div className="bg-surface-base border border-border-subtle p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto">
            <h2 className="text-xl font-light text-ink-primary mb-4">
              Deploy Rules ({selectedRules.size} selected)
            </h2>

            {/* Rollout Strategy */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-ink-secondary mb-2">
                Rollout Strategy
              </label>
              <div className="grid grid-cols-3 gap-4">
                {(['immediate', 'canary', 'scheduled'] as const).map((strategy) => (
                  <button
                    key={strategy}
                    onClick={() => setRolloutStrategy(strategy)}
                    className={`p-4 border text-left ${
                      rolloutStrategy === strategy
                        ? 'border-ac-blue bg-ac-blue/10'
                        : 'border-border-subtle hover:border-border-strong'
                    }`}
                  >
                    <div className="font-medium text-ink-primary capitalize">{strategy}</div>
                    <div className="text-xs text-ink-muted mt-1">
                      {strategy === 'immediate' && 'Deploy to all sensors at once'}
                      {strategy === 'canary' && '10% → 50% → 100% rollout'}
                      {strategy === 'scheduled' && 'Deploy at a specific time'}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Target Sensors */}
            <div className="mb-6">
              <label className="block text-sm font-medium text-ink-secondary mb-2">
                Target Sensors ({selectedSensors.size === 0 ? 'All' : selectedSensors.size})
              </label>
              <div className="max-h-48 overflow-y-auto border border-border-subtle divide-y divide-border-subtle">
                {sensors.map((sensor) => (
                  <label
                    key={sensor.id}
                    className="flex items-center gap-3 p-3 hover:bg-surface-subtle cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selectedSensors.has(sensor.id)}
                      onChange={() => toggleSensor(sensor.id)}
                      className="w-4 h-4 text-ac-blue border-border-subtle"
                    />
                    <SensorStatusBadge status={sensor.status} />
                    <span className="font-medium text-ink-primary">{sensor.name}</span>
                    <span className="text-sm text-ink-muted">{sensor.region}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowDeployModal(false)}
                className="btn-outline h-10 px-4 text-sm"
              >
                Cancel
              </button>
              <button
                onClick={() => pushMutation.mutate()}
                disabled={pushMutation.isPending}
                className="btn-primary h-10 px-4 text-sm"
              >
                {pushMutation.isPending ? 'Deploying...' : 'Deploy Rules'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
