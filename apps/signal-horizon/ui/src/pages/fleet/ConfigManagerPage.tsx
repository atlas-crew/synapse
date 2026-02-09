import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard } from '../../components/fleet';
import { SynapseConfigEditor, getDefaultConfigYaml } from '../../components/fleet/SynapseConfigEditor';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';
import { apiFetch } from '../../lib/api';
import { useSensors } from '../../hooks/fleet';
import { useToast } from '../../components/ui/Toast';

interface ConfigTemplate {
  id: string;
  name: string;
  description?: string;
  environment: 'production' | 'staging' | 'dev';
  version: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

interface SyncStatus {
  totalSensors: number;
  syncedSensors: number;
  outOfSyncSensors: number;
  errorSensors: number;
  syncPercentage: number;
}

interface ConfigAuditLog {
  id: string;
  action: 'CONFIG_CREATED' | 'CONFIG_UPDATED' | 'CONFIG_DELETED';
  resource?: string;
  resourceId?: string | null;
  userId?: string | null;
  createdAt: string;
  details?: Record<string, unknown>;
}

interface ConfigAuditResponse {
  logs: ConfigAuditLog[];
  total: number;
  limit: number;
  offset: number;
}

async function fetchTemplates(): Promise<ConfigTemplate[]> {
  const data = await apiFetch<any>('/fleet/config/templates');
  return data.templates || [];
}

async function fetchSyncStatus(): Promise<SyncStatus> {
  return apiFetch<SyncStatus>('/fleet/config/sync-status');
}

async function fetchConfigAudit(): Promise<ConfigAuditResponse> {
  return apiFetch<ConfigAuditResponse>('/fleet/config/audit?limit=25&offset=0');
}

async function pushConfig(templateId: string, sensorIds: string[]): Promise<void> {
  await apiFetch('/fleet/config/push', { method: 'POST', body: { templateId, sensorIds } });
}

export function ConfigManagerPage() {
  const queryClient = useQueryClient();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const { toast } = useToast();
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  
  // Create Modal State
  const [newName, setNewName] = useState('');
  const [newEnv, setNewEnv] = useState('production');
  const [newDesc, setNewDesc] = useState('');
  const [newConfig, setNewConfig] = useState(getDefaultConfigYaml);

  // Pingora upstream preset: Apparatus echo
  const { data: sensors = [] } = useSensors();
  const [echoHost, setEchoHost] = useState('demo.site');
  const [echoPort, setEchoPort] = useState(80);
  const [selectedEchoSensors, setSelectedEchoSensors] = useState<Set<string>>(new Set());
  const echoSelectedIds = useMemo(() => Array.from(selectedEchoSensors), [selectedEchoSensors]);

  const { data: templates = [], isLoading: templatesLoading } = useQuery({
    queryKey: ['fleet', 'config', 'templates', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return getDemoData(scenario).fleet.configTemplates;
      }
      return fetchTemplates();
    },
  });

  const { data: syncStatus } = useQuery({
    queryKey: ['fleet', 'config', 'sync-status', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return getDemoData(scenario).fleet.syncStatus;
      }
      return fetchSyncStatus();
    },
    refetchInterval: isDemoMode ? false : 10000,
  });

  const { data: auditData, isLoading: auditLoading } = useQuery({
    queryKey: ['fleet', 'config', 'audit', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return { logs: [], total: 0, limit: 25, offset: 0 };
      }
      return fetchConfigAudit();
    },
    refetchInterval: isDemoMode ? false : 15000,
  });

  const pushMutation = useMutation({
    mutationFn: ({ templateId, sensorIds }: { templateId: string; sensorIds: string[] }) =>
      pushConfig(templateId, sensorIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config'] });
    },
  });

  const echoPresetMutation = useMutation({
    mutationFn: async () => {
      const host = echoHost.trim();
      const port = Number(echoPort);
      return apiFetch('/fleet/pingora/presets/apparatus-echo', {
        method: 'POST',
        body: { sensorIds: echoSelectedIds, host, port },
      });
    },
    onSuccess: (data: any) => {
      const ok = (data?.results || []).filter((r: any) => r?.ok).length;
      const total = (data?.results || []).length;
      toast.success(`Preset pushed: ${ok}/${total} sensors`);
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensors'] });
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Failed to push upstream preset');
    },
  });

  const envColors = {
    production: 'bg-ac-red/10 text-ac-red border-ac-red/30',
    staging: 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
    dev: 'bg-ac-blue/10 text-ac-blue border-ac-blue/30',
  };

  const auditLogs = auditData?.logs ?? [];
  const formatAuditAction = (action: ConfigAuditLog['action']) =>
    action.replace('CONFIG_', '').toLowerCase();

  const resolveResourceLabel = (log: ConfigAuditLog) => {
    const details = log.details as { details?: { resourceType?: string } } | undefined;
    const resourceType = details?.details?.resourceType;
    return (resourceType ?? log.resource ?? 'configuration').replace(/_/g, ' ');
  };

  const resolveChangeCount = (log: ConfigAuditLog) => {
    const details = log.details as { details?: { changeCount?: number; changes?: unknown[] } } | undefined;
    return details?.details?.changeCount ?? details?.details?.changes?.length ?? 0;
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Configuration Manager</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Manage and deploy configuration templates across your fleet
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn-primary h-12 px-6 text-sm"
        >
          Create Template
        </button>
      </div>

      {/* Sync Status */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard label="Total Sensors" value={syncStatus?.totalSensors ?? 0} />
        <MetricCard
          label="In Sync"
          value={syncStatus?.syncedSensors ?? 0}
          className="border-ac-green/40"
        />
        <MetricCard
          label="Out of Sync"
          value={syncStatus?.outOfSyncSensors ?? 0}
          className={syncStatus?.outOfSyncSensors ? 'border-ac-orange/40' : ''}
        />
        <MetricCard
          label="Sync Errors"
          value={syncStatus?.errorSensors ?? 0}
          className={syncStatus?.errorSensors ? 'border-ac-red/40' : ''}
        />
      </div>

      {/* Sync Progress */}
      {syncStatus && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg font-medium text-ink-primary">Fleet Sync Status</h3>
            <span className="text-sm text-ink-secondary">{syncStatus.syncPercentage.toFixed(1)}%</span>
          </div>
          <div className="w-full h-3 bg-surface-subtle">
            <div
              className="h-3 bg-ac-blue transition-all duration-500"
              style={{ width: `${syncStatus.syncPercentage}%` }}
            />
          </div>
        </div>
      )}

      {/* Pingora Presets */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle">
          <h2 className="text-lg font-medium text-ink-primary">Pingora Upstream Presets</h2>
          <p className="mt-1 text-sm text-ink-secondary">
            Deploy upstream rewrites to existing sensor configs (pushes immediately).
          </p>
        </div>

        <div className="p-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="lg:col-span-1 space-y-3">
            <div className="text-xs font-bold uppercase tracking-[0.2em] text-ink-secondary">
              Apparatus Echo Target
            </div>
            <div className="text-sm text-ink-secondary">
              Local stack: <span className="font-mono">just dev-waf-echo</span> exposes{' '}
              <span className="font-mono">demo.site</span>.
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="block text-[10px] font-bold uppercase tracking-[0.2em] text-ink-secondary">
                  Host
                </label>
                <input
                  value={echoHost}
                  onChange={(e) => setEchoHost(e.target.value)}
                  className="h-10 w-full bg-surface-subtle border border-border-subtle px-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                />
              </div>
              <div className="space-y-1">
                <label className="block text-[10px] font-bold uppercase tracking-[0.2em] text-ink-secondary">
                  Port
                </label>
                <input
                  type="number"
                  value={echoPort}
                  onChange={(e) => setEchoPort(Number(e.target.value))}
                  className="h-10 w-full bg-surface-subtle border border-border-subtle px-3 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                />
              </div>
            </div>

            <button
              type="button"
              disabled={isDemoMode || echoSelectedIds.length === 0 || echoPresetMutation.isPending}
              onClick={() => {
                const host = echoHost.trim();
                const port = Number(echoPort);
                if (!host) {
                  toast.error('Host is required');
                  return;
                }
                if (!Number.isFinite(port) || port < 1 || port > 65535) {
                  toast.error('Port must be 1-65535');
                  return;
                }
                echoPresetMutation.mutate();
              }}
              className="h-11 w-full px-4 text-xs font-bold uppercase tracking-[0.2em] border-2 border-ac-magenta text-ac-magenta hover:bg-ac-magenta hover:text-white transition-colors disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
            >
              {echoPresetMutation.isPending ? 'Pushing...' : `Push To Selected (${echoSelectedIds.length})`}
            </button>

            {isDemoMode && <div className="text-xs text-ink-muted">Disabled in demo mode.</div>}
          </div>

          <div className="lg:col-span-2">
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-bold uppercase tracking-[0.2em] text-ink-secondary">
                Target Sensors
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedEchoSensors(new Set(sensors.map((s: any) => s.id)))}
                  className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                >
                  Select All
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedEchoSensors(new Set())}
                  className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="border border-border-subtle bg-surface-base max-h-[320px] overflow-auto">
              <table className="min-w-full divide-y divide-border-subtle">
                <thead className="bg-surface-subtle">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                      Select
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                      Sensor
                    </th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest">
                      Status
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {sensors.map((sensor: any) => (
                    <tr key={sensor.id} className="hover:bg-surface-subtle">
                      <td className="px-4 py-2">
                        <input
                          type="checkbox"
                          checked={selectedEchoSensors.has(sensor.id)}
                          onChange={() => {
                            setSelectedEchoSensors((prev) => {
                              const next = new Set(prev);
                              if (next.has(sensor.id)) next.delete(sensor.id);
                              else next.add(sensor.id);
                              return next;
                            });
                          }}
                          className="w-4 h-4 text-ac-blue border-border-subtle"
                        />
                      </td>
                      <td className="px-4 py-2">
                        <div className="font-medium text-ink-primary">{sensor.name}</div>
                        <div className="text-xs text-ink-muted font-mono">{sensor.id}</div>
                      </td>
                      <td className="px-4 py-2 text-sm text-ink-secondary">
                        {sensor.connectionState || 'UNKNOWN'}
                      </td>
                    </tr>
                  ))}
                  {sensors.length === 0 && (
                    <tr>
                      <td className="px-4 py-6 text-center text-ink-muted" colSpan={3}>
                        No sensors available.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Templates */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-medium text-ink-primary">Configuration Templates</h2>
          <div className="flex gap-2">
            {['all', 'production', 'staging', 'dev'].map((env) => (
              <button
                key={env}
                className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle capitalize focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
              >
                {env}
              </button>
            ))}
          </div>
        </div>

        {templatesLoading ? (
          <div className="p-12 text-center text-ink-muted">Loading templates...</div>
        ) : templates.length === 0 ? (
          <div className="p-12 text-center text-ink-muted">
            No templates found. Create your first template to get started.
          </div>
        ) : (
          <div className="divide-y divide-border-subtle">
            {templates.map((template) => (
              <div
                key={template.id}
                role="button"
                tabIndex={0}
                aria-pressed={selectedTemplate === template.id}
                aria-label={`Select template: ${template.name}`}
                className={`w-full p-6 text-left hover:bg-surface-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-inset ${
                  selectedTemplate === template.id ? 'bg-ac-blue/10' : ''
                }`}
                onClick={() => setSelectedTemplate(template.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    setSelectedTemplate(template.id);
                  }
                }}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-medium text-ink-primary">{template.name}</h3>
                      <span
                        className={`px-2 py-0.5 text-xs font-medium border ${envColors[template.environment]}`}
                      >
                        {template.environment}
                      </span>
                      {template.isActive && (
                        <span className="px-2 py-0.5 text-xs font-medium bg-ac-green/10 text-ac-green border border-ac-green/30">
                          Active
                        </span>
                      )}
                    </div>
                    {template.description && (
                      <p className="mt-1 text-sm text-ink-secondary">{template.description}</p>
                    )}
                    <div className="mt-2 text-xs text-ink-muted">
                      Version {template.version} • Updated{' '}
                      {new Date(template.updatedAt).toLocaleDateString()}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        pushMutation.mutate({ templateId: template.id, sensorIds: [] });
                      }}
                      disabled={pushMutation.isPending}
                      className="px-3 py-1.5 text-sm font-medium text-ac-white bg-ac-blue hover:bg-ac-blue-dark disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    >
                      {pushMutation.isPending ? 'Pushing...' : 'Push to All'}
                    </button>
                    <button
                      type="button"
                      className="px-3 py-1.5 text-sm font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    >
                      Edit
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Audit Trail */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <div>
            <h2 className="text-lg font-medium text-ink-primary">Configuration Audit Trail</h2>
            <p className="text-xs text-ink-muted">Recent config changes across the fleet</p>
          </div>
          <span className="text-xs text-ink-muted">
            {auditData?.total ?? auditLogs.length} events
          </span>
        </div>

        {isDemoMode ? (
          <div className="p-6 text-sm text-ink-muted">Audit trail is disabled in demo mode.</div>
        ) : auditLoading ? (
          <div className="p-6 text-sm text-ink-muted">Loading audit trail...</div>
        ) : auditLogs.length === 0 ? (
          <div className="p-6 text-sm text-ink-muted">No configuration changes recorded yet.</div>
        ) : (
          <div className="divide-y divide-border-subtle">
            {auditLogs.map((log) => {
              const changeCount = resolveChangeCount(log);
              const summary = `${resolveResourceLabel(log)} ${formatAuditAction(log.action)}`;
              return (
                <div key={log.id} className="p-4 flex items-start justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm font-medium text-ink-primary">{summary}</div>
                    <div className="text-xs text-ink-muted">
                      {log.resourceId ? (
                        <span className="font-mono">{log.resourceId}</span>
                      ) : (
                        <span>unknown resource</span>
                      )}
                      {changeCount > 0 && <span> • {changeCount} changes</span>}
                      <span> • {log.userId ?? 'system'}</span>
                    </div>
                  </div>
                  <div className="text-xs text-ink-muted">
                    {new Date(log.createdAt).toLocaleString()}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Create Modal Placeholder */}
      {showCreateModal && (
        <div
          className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50"
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-template-title"
        >
          <div className="bg-surface-base border border-border-subtle p-6 w-full max-w-4xl h-[80vh] flex flex-col">
            <h2 id="create-template-title" className="text-xl font-light text-ink-primary mb-4">Create Configuration Template</h2>
            
            <div className="grid grid-cols-3 gap-6 flex-1 overflow-hidden">
              {/* Left Column: Metadata */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">Name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue"
                    placeholder="Template name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">Environment</label>
                  <select 
                    value={newEnv}
                    onChange={(e) => setNewEnv(e.target.value)}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue"
                  >
                    <option value="dev">Development</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">Description</label>
                  <textarea
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue resize-none h-32"
                    placeholder="Optional description"
                  />
                </div>
              </div>

              {/* Right Column: Config Editor */}
              <div className="col-span-2 flex flex-col h-full overflow-hidden">
                <label className="block text-sm font-medium text-ink-secondary mb-2">Sensor Configuration</label>
                <div className="flex-1 overflow-hidden">
                  <SynapseConfigEditor
                    value={newConfig}
                    onChange={setNewConfig}
                  />
                </div>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-4 border-t border-border-subtle">
              <button
                onClick={() => setShowCreateModal(false)}
                className="btn-outline h-10 px-4 text-sm"
              >
                Cancel
              </button>
              <button className="btn-primary h-10 px-4 text-sm">
                Create Template
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
