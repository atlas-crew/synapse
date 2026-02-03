import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard } from '../../components/fleet';
import { CodeEditor } from '../../components/ctrlx/CodeEditor';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const authHeaders = { 'Authorization': `Bearer ${API_KEY}` };

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

async function fetchTemplates(): Promise<ConfigTemplate[]> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/config/templates`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch templates');
  const data = await response.json();
  return data.templates || [];
}

async function fetchSyncStatus(): Promise<SyncStatus> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/config/sync-status`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch sync status');
  return response.json();
}

async function pushConfig(templateId: string, sensorIds: string[]): Promise<void> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/config/push`, {
    method: 'POST',
    headers: { ...authHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify({ templateId, sensorIds }),
  });
  if (!response.ok) throw new Error('Failed to push config');
}

export function ConfigManagerPage() {
  const queryClient = useQueryClient();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  
  // Create Modal State
  const [newName, setNewName] = useState('');
  const [newEnv, setNewEnv] = useState('production');
  const [newDesc, setNewDesc] = useState('');
  const [newConfig, setNewConfig] = useState('{\n  "version": "1.0.0",\n  "settings": {\n    "logLevel": "info"\n  }\n}');

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

  const pushMutation = useMutation({
    mutationFn: ({ templateId, sensorIds }: { templateId: string; sensorIds: string[] }) =>
      pushConfig(templateId, sensorIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config'] });
    },
  });

  const envColors = {
    production: 'bg-ac-red/10 text-ac-red border-ac-red/30',
    staging: 'bg-ac-orange/10 text-ac-orange border-ac-orange/30',
    dev: 'bg-ac-blue/10 text-ac-blue border-ac-blue/30',
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

      {/* Templates */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-medium text-ink-primary">Configuration Templates</h2>
          <div className="flex gap-2">
            {['all', 'production', 'staging', 'dev'].map((env) => (
              <button
                key={env}
                className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle capitalize"
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
              <button
                key={template.id}
                type="button"
                aria-pressed={selectedTemplate === template.id}
                aria-label={`Select template: ${template.name}`}
                className={`w-full p-6 text-left hover:bg-surface-subtle focus:outline-none focus-visible:ring-2 focus-visible:ring-ac-blue focus-visible:ring-inset ${
                  selectedTemplate === template.id ? 'bg-ac-blue/10' : ''
                }`}
                onClick={() => setSelectedTemplate(template.id)}
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
                      className="px-3 py-1.5 text-sm font-medium text-ac-white bg-ac-blue hover:bg-ac-blue-dark disabled:opacity-50"
                    >
                      {pushMutation.isPending ? 'Pushing...' : 'Push to All'}
                    </button>
                    <button
                      type="button"
                      className="px-3 py-1.5 text-sm font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle"
                    >
                      Edit
                    </button>
                  </div>
                </div>
              </button>
            ))}
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

              {/* Right Column: JSON Editor */}
              <div className="col-span-2 flex flex-col h-full">
                <label className="block text-sm font-medium text-ink-secondary mb-1">Configuration (JSON)</label>
                <div className="flex-1 border border-border-subtle">
                  <CodeEditor
                    value={newConfig}
                    onChange={setNewConfig}
                    language="json"
                    height="100%"
                    className="h-full"
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
