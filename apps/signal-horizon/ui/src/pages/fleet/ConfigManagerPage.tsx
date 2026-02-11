import { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { MetricCard } from '../../components/fleet';
import {
  SynapseConfigEditor,
  getDefaultConfigYaml,
} from '../../components/fleet/SynapseConfigEditor';
import {
  AdvancedConfigPanel,
  defaultAdvancedConfig,
  type AdvancedConfigData,
} from '../../components/fleet/pingora';
import { CodeEditor } from '../../components/ctrlx/CodeEditor';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';
import { apiFetch } from '../../lib/api';
import { useSensors } from '../../hooks/fleet';
import { useToast } from '../../components/ui/Toast';
import { deepMergeConfig } from '../../utils';
import YAML from 'yaml';
import { Modal, SectionHeader, Stack } from '@/ui';

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

interface ConfigTemplateDetail extends ConfigTemplate {
  config: Record<string, unknown>;
  hash: string;
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
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const PAGE_HEADER_TITLE_STYLE = {
  fontSize: '20px',
  lineHeight: '28px',
  color: 'var(--text-primary)',
};
const CARD_HEADER_TITLE_STYLE = {
  fontSize: '18px',
  lineHeight: '28px',
  fontWeight: 500,
  color: 'var(--text-primary)',
};

async function fetchTemplates(): Promise<ConfigTemplate[]> {
  const data = await apiFetch<any>('/fleet/config/templates');
  return data.templates || [];
}

async function fetchTemplateDetail(templateId: string): Promise<ConfigTemplateDetail> {
  return apiFetch<ConfigTemplateDetail>(`/fleet/config/templates/${templateId}`);
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

type TemplateEditorMode = 'create' | 'edit';
type TemplateConfigView = 'base' | 'advanced' | 'json';

function parseYamlConfig(yamlText: string): Record<string, unknown> {
  const parsed = YAML.parse(yamlText);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Config must be a YAML mapping (object at root)');
  }
  return parsed as Record<string, unknown>;
}

function extractAdvancedConfig(fullConfig: Record<string, unknown>): AdvancedConfigData {
  return {
    dlp: (fullConfig.dlp as AdvancedConfigData['dlp']) || defaultAdvancedConfig.dlp,
    block_page:
      (fullConfig.block_page as AdvancedConfigData['block_page']) ||
      defaultAdvancedConfig.block_page,
    crawler: (fullConfig.crawler as AdvancedConfigData['crawler']) || defaultAdvancedConfig.crawler,
    tarpit: (fullConfig.tarpit as AdvancedConfigData['tarpit']) || defaultAdvancedConfig.tarpit,
    entity: (fullConfig.entity as AdvancedConfigData['entity']) || defaultAdvancedConfig.entity,
    travel: (fullConfig.travel as AdvancedConfigData['travel']) || defaultAdvancedConfig.travel,
  };
}

function mergeAdvancedConfig(
  fullConfig: Record<string, unknown>,
  advancedConfig: AdvancedConfigData,
): Record<string, unknown> {
  return {
    ...fullConfig,
    dlp: deepMergeConfig((fullConfig.dlp as Record<string, unknown>) || {}, advancedConfig.dlp),
    block_page: deepMergeConfig(
      (fullConfig.block_page as Record<string, unknown>) || {},
      advancedConfig.block_page,
    ),
    crawler: deepMergeConfig(
      (fullConfig.crawler as Record<string, unknown>) || {},
      advancedConfig.crawler,
    ),
    tarpit: deepMergeConfig(
      (fullConfig.tarpit as Record<string, unknown>) || {},
      advancedConfig.tarpit,
    ),
    entity: deepMergeConfig(
      (fullConfig.entity as Record<string, unknown>) || {},
      advancedConfig.entity,
    ),
    travel: deepMergeConfig(
      (fullConfig.travel as Record<string, unknown>) || {},
      advancedConfig.travel,
    ),
  };
}

function extractBaseConfig(fullConfig: Record<string, unknown>): Record<string, unknown> {
  const base: Record<string, unknown> = {};
  for (const key of ['server', 'sites', 'rate_limit', 'profiler']) {
    if (Object.prototype.hasOwnProperty.call(fullConfig, key)) {
      base[key] = fullConfig[key];
    }
  }
  return base;
}

export function ConfigManagerPage() {
  const queryClient = useQueryClient();
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const { toast } = useToast();
  const [selectedTemplate, setSelectedTemplate] = useState<string | null>(null);
  const [envFilter, setEnvFilter] = useState<'all' | 'production' | 'staging' | 'dev'>('all');

  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [templateModalMode, setTemplateModalMode] = useState<TemplateEditorMode>('create');
  const [editingTemplateId, setEditingTemplateId] = useState<string | null>(null);
  const [templateDetailLoading, setTemplateDetailLoading] = useState(false);
  const [templateDetailError, setTemplateDetailError] = useState<string | null>(null);
  const [templateConfigView, setTemplateConfigView] = useState<TemplateConfigView>('base');
  const [templateBaseYamlError, setTemplateBaseYamlError] = useState<string | null>(null);
  const [templateJsonError, setTemplateJsonError] = useState<string | null>(null);

  const [showPushModal, setShowPushModal] = useState(false);
  const [pushTemplateId, setPushTemplateId] = useState<string | null>(null);
  const [pushSelectedSensors, setPushSelectedSensors] = useState<Set<string>>(new Set());

  // Create Modal State
  const [newName, setNewName] = useState('');
  const [newEnv, setNewEnv] = useState<'production' | 'staging' | 'dev'>('production');
  const [newDesc, setNewDesc] = useState('');
  const [newConfig, setNewConfig] = useState(getDefaultConfigYaml);
  const [templateConfigJson, setTemplateConfigJson] = useState('{\n}\n');
  const [templateConfigObject, setTemplateConfigObject] = useState<Record<string, unknown>>({});
  const [templateAdvancedConfig, setTemplateAdvancedConfig] =
    useState<AdvancedConfigData>(defaultAdvancedConfig);

  // Pingora upstream preset: Apparatus echo
  const { data: sensors = [] } = useSensors();
  const [echoHost, setEchoHost] = useState('demo.site');
  const [echoPort, setEchoPort] = useState(80);
  const [selectedEchoSensors, setSelectedEchoSensors] = useState<Set<string>>(new Set());
  const echoSelectedIds = useMemo(() => Array.from(selectedEchoSensors), [selectedEchoSensors]);

  const {
    data: templates = [],
    isLoading: templatesLoading,
    isError: templatesIsError,
    error: templatesError,
    refetch: refetchTemplates,
  } = useQuery({
    queryKey: ['fleet', 'config', 'templates', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return getDemoData(scenario).fleet.configTemplates;
      }
      return fetchTemplates();
    },
    retry: false,
  });

  const {
    data: syncStatus,
    isLoading: syncLoading,
    isError: syncIsError,
    error: syncError,
    refetch: refetchSyncStatus,
  } = useQuery({
    queryKey: ['fleet', 'config', 'sync-status', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return getDemoData(scenario).fleet.syncStatus;
      }
      return fetchSyncStatus();
    },
    refetchInterval: isDemoMode ? false : 10000,
    retry: false,
  });

  const {
    data: auditData,
    isLoading: auditLoading,
    isError: auditIsError,
    error: auditError,
    refetch: refetchAudit,
  } = useQuery({
    queryKey: ['fleet', 'config', 'audit', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return { logs: [], total: 0, limit: 25, offset: 0 };
      }
      return fetchConfigAudit();
    },
    refetchInterval: isDemoMode ? false : 15000,
    retry: false,
  });

  const pushMutation = useMutation({
    mutationFn: ({ templateId, sensorIds }: { templateId: string; sensorIds: string[] }) =>
      pushConfig(templateId, sensorIds),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config'] });
      toast.success('Config push queued.');
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Failed to push config');
    },
  });

  const templateCreateMutation = useMutation({
    mutationFn: async (input: {
      name: string;
      description?: string;
      environment: 'production' | 'staging' | 'dev';
      config: Record<string, unknown>;
    }) =>
      apiFetch<ConfigTemplateDetail>('/fleet/config/templates', { method: 'POST', body: input }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config', 'templates'] });
      toast.success('Template created.');
      setShowTemplateModal(false);
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Failed to create template');
    },
  });

  const templateUpdateMutation = useMutation({
    mutationFn: async (params: {
      id: string;
      updates: Partial<{
        name: string;
        description?: string;
        environment: 'production' | 'staging' | 'dev';
        config: Record<string, unknown>;
      }>;
    }) =>
      apiFetch<ConfigTemplateDetail>(`/fleet/config/templates/${params.id}`, {
        method: 'PUT',
        body: params.updates,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config', 'templates'] });
      toast.success('Template updated.');
      setShowTemplateModal(false);
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Failed to update template');
    },
  });

  const templateDeleteMutation = useMutation({
    mutationFn: async (id: string) =>
      apiFetch<void>(`/fleet/config/templates/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'config', 'templates'] });
      toast.success('Template deleted.');
      setShowTemplateModal(false);
      if (selectedTemplate === editingTemplateId) setSelectedTemplate(null);
    },
    onError: (err: any) => {
      toast.error(err?.message || 'Failed to delete template');
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
    const details = log.details as
      | { details?: { changeCount?: number; changes?: unknown[] } }
      | undefined;
    return details?.details?.changeCount ?? details?.details?.changes?.length ?? 0;
  };

  const filteredTemplates = useMemo(() => {
    if (envFilter === 'all') return templates;
    return templates.filter((t) => t.environment === envFilter);
  }, [templates, envFilter]);

  const allSensorIds = useMemo(() => sensors.map((s: any) => String(s.id)), [sensors]);

  const openCreateModal = () => {
    setTemplateModalMode('create');
    setEditingTemplateId(null);
    setTemplateDetailLoading(false);
    setTemplateDetailError(null);
    setTemplateConfigView('base');
    setTemplateBaseYamlError(null);
    setTemplateJsonError(null);
    setNewName('');
    setNewDesc('');
    setNewEnv('production');
    try {
      const seedYaml = getDefaultConfigYaml();
      setNewConfig(seedYaml);
      const parsed = parseYamlConfig(seedYaml);
      setTemplateConfigObject(parsed);
      setTemplateAdvancedConfig(extractAdvancedConfig(parsed));
      setTemplateConfigJson(JSON.stringify(parsed, null, 2));
    } catch {
      setNewConfig(getDefaultConfigYaml());
      setTemplateConfigObject({});
      setTemplateAdvancedConfig(defaultAdvancedConfig);
      setTemplateConfigJson('{\n}\n');
    }
    setShowTemplateModal(true);
  };

  const openEditModal = async (id: string) => {
    setTemplateModalMode('edit');
    setEditingTemplateId(id);
    setTemplateDetailError(null);
    setTemplateDetailLoading(true);
    setTemplateConfigView('base');
    setTemplateBaseYamlError(null);
    setTemplateJsonError(null);
    // Reset fields so stale state doesn't flash while detail loads.
    setNewName('');
    setNewDesc('');
    setNewEnv('production');
    setNewConfig(getDefaultConfigYaml());
    setTemplateConfigObject({});
    setTemplateAdvancedConfig(defaultAdvancedConfig);
    setTemplateConfigJson('{\n}\n');
    setShowTemplateModal(true);

    if (isDemoMode) {
      const demoTemplate: any = (getDemoData(scenario).fleet.configTemplates || []).find(
        (t: any) => t.id === id,
      );
      if (!demoTemplate) {
        setTemplateDetailLoading(false);
        toast.error('Template not found');
        setShowTemplateModal(false);
        return;
      }
      try {
        const cfg = (demoTemplate.config ?? {}) as Record<string, unknown>;
        setNewName(demoTemplate.name ?? '');
        setNewDesc(demoTemplate.description ?? '');
        setNewEnv((demoTemplate.environment ?? 'production') as any);
        setTemplateConfigObject(cfg);
        setTemplateAdvancedConfig(extractAdvancedConfig(cfg));
        setTemplateConfigJson(JSON.stringify(cfg, null, 2));
        setNewConfig(YAML.stringify(extractBaseConfig(cfg), { indent: 2 }));
      } catch {
        setNewConfig(getDefaultConfigYaml());
      }
      setTemplateDetailLoading(false);
      return;
    }

    try {
      const detail = await fetchTemplateDetail(id);
      const cfg = (detail.config ?? {}) as Record<string, unknown>;
      setNewName(detail.name ?? '');
      setNewDesc(detail.description ?? '');
      setNewEnv((detail.environment ?? 'production') as any);
      setTemplateConfigObject(cfg);
      setTemplateAdvancedConfig(extractAdvancedConfig(cfg));
      setTemplateConfigJson(JSON.stringify(cfg, null, 2));
      setNewConfig(YAML.stringify(extractBaseConfig(cfg), { indent: 2 }));
    } catch (err: any) {
      const message = err?.message || 'Failed to load template';
      setTemplateDetailError(message);
      toast.error(message);
    }
    setTemplateDetailLoading(false);
  };

  const handleBaseYamlChange = (yamlText: string) => {
    setNewConfig(yamlText);
    try {
      const parsed = parseYamlConfig(yamlText);
      setTemplateBaseYamlError(null);
      setTemplateConfigObject((prev) => {
        const merged = deepMergeConfig(prev, parsed);
        setTemplateAdvancedConfig(extractAdvancedConfig(merged));
        setTemplateConfigJson(JSON.stringify(merged, null, 2));
        return merged;
      });
    } catch (err: any) {
      setTemplateBaseYamlError(err?.message || 'Invalid YAML config');
      // Keep last good object/json/advanced in place.
    }
  };

  const handleAdvancedConfigChange = (nextAdvanced: AdvancedConfigData) => {
    setTemplateAdvancedConfig(nextAdvanced);
    setTemplateConfigObject((prev) => {
      const merged = mergeAdvancedConfig(prev, nextAdvanced);
      setTemplateConfigJson(JSON.stringify(merged, null, 2));
      return merged;
    });
  };

  const handleJsonChange = (jsonText: string) => {
    setTemplateConfigJson(jsonText);
    try {
      const parsed = JSON.parse(jsonText) as Record<string, unknown>;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Config must be a JSON object at root');
      }
      setTemplateJsonError(null);
      setTemplateConfigObject(parsed);
      setTemplateAdvancedConfig(extractAdvancedConfig(parsed));
      setNewConfig(YAML.stringify(extractBaseConfig(parsed), { indent: 2 }));
    } catch (err: any) {
      setTemplateJsonError(err?.message || 'Invalid JSON config');
      // Keep last good object/yaml/advanced in place.
    }
  };

  const submitTemplateModal = async () => {
    if (isDemoMode) {
      toast.error('Template mutations are disabled in demo mode.');
      return;
    }

    const name = newName.trim();
    if (!name) {
      toast.error('Name is required');
      return;
    }

    if (templateConfigView === 'base' && templateBaseYamlError) {
      toast.error(templateBaseYamlError);
      return;
    }
    if (templateConfigView === 'json' && templateJsonError) {
      toast.error(templateJsonError);
      return;
    }

    const config = templateConfigObject;

    if (templateModalMode === 'create') {
      await templateCreateMutation.mutateAsync({
        name,
        description: newDesc.trim() ? newDesc.trim() : undefined,
        environment: newEnv,
        config,
      });
      return;
    }

    if (!editingTemplateId) return;
    await templateUpdateMutation.mutateAsync({
      id: editingTemplateId,
      updates: {
        name,
        description: newDesc.trim() ? newDesc.trim() : undefined,
        environment: newEnv,
        config,
      },
    });
  };

  const openPushModal = (templateId: string) => {
    setPushTemplateId(templateId);
    setPushSelectedSensors(new Set());
    setShowPushModal(true);
  };

  const submitPushModal = async () => {
    if (isDemoMode) {
      toast.error('Config pushes are disabled in demo mode.');
      return;
    }
    if (!pushTemplateId) return;
    const ids = Array.from(pushSelectedSensors);
    if (ids.length === 0) {
      toast.error('Select at least one sensor');
      return;
    }
    await pushMutation.mutateAsync({ templateId: pushTemplateId, sensorIds: ids });
    setShowPushModal(false);
  };

  const selectedPushCount = pushSelectedSensors.size;

  const templatesErrorMessage =
    templatesError instanceof Error ? templatesError.message : 'Failed to load templates';
  const syncErrorMessage =
    syncError instanceof Error ? syncError.message : 'Failed to load sync status';
  const auditErrorMessage =
    auditError instanceof Error ? auditError.message : 'Failed to load audit trail';

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <SectionHeader
          title="Configuration Manager"
          description="Manage and deploy configuration templates across your fleet"
          size="h1"
          style={PAGE_HEADER_STYLE}
          titleStyle={PAGE_HEADER_TITLE_STYLE}
        />
        <button
          onClick={openCreateModal}
          disabled={isDemoMode}
          className="btn-primary h-12 px-6 text-sm"
        >
          Create Template
        </button>
      </div>

      {/* Sync Status */}
      {syncIsError ? (
        <div className="card p-6">
          <div className="text-sm text-ac-red">Sync status unavailable: {syncErrorMessage}</div>
          <button
            type="button"
            onClick={() => refetchSyncStatus()}
            className="mt-3 px-3 py-1.5 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
          >
            Retry
          </button>
        </div>
      ) : (
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
      )}

      {/* Sync Progress */}
      {syncStatus && !syncLoading && !syncIsError && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-lg font-medium text-ink-primary">Fleet Sync Status</h3>
            <span className="text-sm text-ink-secondary">
              {Math.round(syncStatus.syncPercentage)}%
            </span>
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
          <SectionHeader
            title="Pingora Upstream Presets"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
          />
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
              {echoPresetMutation.isPending
                ? 'Pushing...'
                : `Push To Selected (${echoSelectedIds.length})`}
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
          <SectionHeader
            title="Configuration Templates"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
            actions={
              <div className="flex gap-2">
                {['all', 'production', 'staging', 'dev'].map((env) => (
                  <button
                    key={env}
                    type="button"
                    onClick={() => setEnvFilter(env as any)}
                    className={`px-3 py-1 text-xs font-medium border border-border-subtle hover:bg-surface-subtle capitalize focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                      envFilter === env ? 'bg-surface-subtle text-ink-primary' : 'text-ink-secondary'
                    }`}
                  >
                    {env}
                  </button>
                ))}
              </div>
            }
          />
        </div>

        {templatesLoading ? (
          <div className="p-12 text-center text-ink-muted">Loading templates...</div>
        ) : templatesIsError ? (
          <div className="p-6">
            <div className="text-sm text-ac-red">
              Templates unavailable: {templatesErrorMessage}
            </div>
            <button
              type="button"
              onClick={() => refetchTemplates()}
              className="mt-3 px-3 py-1.5 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
            >
              Retry
            </button>
          </div>
        ) : filteredTemplates.length === 0 ? (
          <div className="p-12 text-center text-ink-muted">
            No templates found. Create your first template to get started.
          </div>
        ) : (
          <div className="divide-y divide-border-subtle">
            {filteredTemplates.map((template) => (
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
                        if (isDemoMode) {
                          toast.error('Config pushes are disabled in demo mode.');
                          return;
                        }
                        if (allSensorIds.length === 0) {
                          toast.error('No sensors available');
                          return;
                        }
                        pushMutation.mutate({ templateId: template.id, sensorIds: allSensorIds });
                      }}
                      disabled={pushMutation.isPending || isDemoMode || allSensorIds.length === 0}
                      className="px-3 py-1.5 text-sm font-medium text-ac-white bg-ac-blue hover:bg-ac-blue-dark disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    >
                      {pushMutation.isPending ? 'Pushing...' : 'Push to All'}
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        openPushModal(template.id);
                      }}
                      disabled={isDemoMode}
                      className="px-3 py-1.5 text-sm font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    >
                      Push to Selected
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        openEditModal(template.id);
                      }}
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
          <SectionHeader
            title="Configuration Audit Trail"
            description="Recent config changes across the fleet"
            size="h4"
            style={{ marginBottom: 0 }}
            titleStyle={CARD_HEADER_TITLE_STYLE}
            actions={<span className="text-xs text-ink-muted">{auditData?.total ?? auditLogs.length} events</span>}
          />
        </div>

        {isDemoMode ? (
          <div className="p-6 text-sm text-ink-muted">Audit trail is disabled in demo mode.</div>
        ) : auditIsError ? (
          <div className="p-6">
            <div className="text-sm text-ac-red">Audit trail unavailable: {auditErrorMessage}</div>
            <button
              type="button"
              onClick={() => refetchAudit()}
              className="mt-3 px-3 py-1.5 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
            >
              Retry
            </button>
          </div>
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

      {/* Push Modal */}
      {showPushModal && (
        <Modal
          open
          onClose={() => setShowPushModal(false)}
          size="1200px"
          title="Push Template To Sensors"
          style={{ height: '80vh', maxHeight: '80vh' }}
        >
          <div className="h-full flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs font-bold uppercase tracking-[0.2em] text-ink-secondary">
                Target Sensors
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() =>
                    setPushSelectedSensors(new Set(sensors.map((s: any) => String(s.id))))
                  }
                  className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                >
                  Select All
                </button>
                <button
                  type="button"
                  onClick={() => setPushSelectedSensors(new Set())}
                  className="px-3 py-1 text-xs font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="border border-border-subtle bg-surface-base flex-1 overflow-auto">
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
                          checked={pushSelectedSensors.has(String(sensor.id))}
                          onChange={() => {
                            setPushSelectedSensors((prev) => {
                              const next = new Set(prev);
                              const id = String(sensor.id);
                              if (next.has(id)) next.delete(id);
                              else next.add(id);
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

            <div className="mt-6 flex justify-end gap-3 pt-4 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => setShowPushModal(false)}
                className="btn-outline h-10 px-4 text-sm"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={pushMutation.isPending || sensors.length === 0 || selectedPushCount === 0}
                onClick={submitPushModal}
                className="btn-primary h-10 px-4 text-sm disabled:opacity-50"
              >
                {pushMutation.isPending ? 'Pushing...' : `Push (${selectedPushCount})`}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Template Modal */}
      {showTemplateModal && (
        <Modal
          open
          onClose={() => setShowTemplateModal(false)}
          size="1200px"
          title={
            templateModalMode === 'create'
              ? 'Create Configuration Template'
              : 'Edit Configuration Template'
          }
          style={{ height: '80vh', maxHeight: '80vh' }}
        >
          <div className="h-full flex flex-col relative">
            {templateDetailError && templateModalMode === 'edit' && (
              <div className="mb-4 border border-ac-red/30 bg-ac-red/10 px-4 py-2 text-sm text-ac-red">
                {templateDetailError}
              </div>
            )}

            <div
              className={`grid grid-cols-3 gap-6 flex-1 overflow-hidden ${
                templateDetailLoading ? 'opacity-60 pointer-events-none' : ''
              }`}
            >
              {/* Left Column: Metadata */}
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">Name</label>
                  <input
                    type="text"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    disabled={templateDetailLoading}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue"
                    placeholder="Template name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">
                    Environment
                  </label>
                  <select
                    value={newEnv}
                    onChange={(e) => setNewEnv(e.target.value as any)}
                    disabled={templateDetailLoading}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue"
                  >
                    <option value="dev">Development</option>
                    <option value="staging">Staging</option>
                    <option value="production">Production</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-ink-secondary mb-1">
                    Description
                  </label>
                  <textarea
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    disabled={templateDetailLoading}
                    className="w-full px-3 py-2 border border-border-subtle bg-surface-inset text-ink-primary focus:outline-none focus:border-ac-blue resize-none h-32"
                    placeholder="Optional description"
                  />
                </div>
              </div>

              {/* Right Column: Config Editor */}
              <div className="col-span-2 flex flex-col h-full overflow-hidden">
                <div className="flex items-center justify-between gap-4 mb-2">
                  <label className="block text-sm font-medium text-ink-secondary">
                    Sensor Configuration
                  </label>
                  <div className="flex items-center bg-surface-subtle p-1">
                    <button
                      type="button"
                      onClick={() => setTemplateConfigView('base')}
                      className={`px-3 py-1.5 text-xs font-bold uppercase tracking-[0.2em] transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                        templateConfigView === 'base'
                          ? 'bg-surface-card text-ink-primary shadow-sm'
                          : 'text-ink-secondary hover:text-ink-primary'
                      }`}
                    >
                      Base
                    </button>
                    <button
                      type="button"
                      onClick={() => setTemplateConfigView('advanced')}
                      className={`px-3 py-1.5 text-xs font-bold uppercase tracking-[0.2em] transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                        templateConfigView === 'advanced'
                          ? 'bg-surface-card text-ink-primary shadow-sm'
                          : 'text-ink-secondary hover:text-ink-primary'
                      }`}
                    >
                      Advanced
                    </button>
                    <button
                      type="button"
                      onClick={() => setTemplateConfigView('json')}
                      className={`px-3 py-1.5 text-xs font-bold uppercase tracking-[0.2em] transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                        templateConfigView === 'json'
                          ? 'bg-surface-card text-ink-primary shadow-sm'
                          : 'text-ink-secondary hover:text-ink-primary'
                      }`}
                    >
                      JSON
                    </button>
                  </div>
                </div>

                {templateConfigView === 'base' && (
                  <div className="flex-1 overflow-hidden flex flex-col min-h-0">
                    {templateBaseYamlError && (
                      <div className="mb-2 border border-ac-red/30 bg-ac-red/10 px-3 py-2 text-xs text-ac-red">
                        {templateBaseYamlError}
                      </div>
                    )}
                    <div className="flex-1 overflow-hidden min-h-0">
                      <SynapseConfigEditor value={newConfig} onChange={handleBaseYamlChange} />
                    </div>
                  </div>
                )}

                {templateConfigView === 'advanced' && (
                  <div className="flex-1 overflow-auto min-h-0 border border-border-subtle bg-surface-base">
                    <AdvancedConfigPanel
                      config={templateAdvancedConfig}
                      onChange={handleAdvancedConfigChange}
                    />
                  </div>
                )}

                {templateConfigView === 'json' && (
                  <Stack
                    direction="column"
                    className="flex-1 overflow-hidden min-h-0"
                    style={{ gap: '12px' }}
                  >
                    <div className="border border-ac-magenta/30 bg-ac-magenta/10 px-4 py-3 text-xs text-ink-secondary">
                      <div className="text-xs font-bold uppercase tracking-[0.2em] text-ac-magenta mb-1">
                        Raw Config
                      </div>
                      Edit the full sensor configuration object. Invalid JSON will block save.
                    </div>

                    {templateJsonError && (
                      <div className="border border-ac-red/30 bg-ac-red/10 px-3 py-2 text-xs text-ac-red">
                        {templateJsonError}
                      </div>
                    )}

                    <div className="flex-1 min-h-0 border border-border-subtle overflow-hidden shadow-sm">
                      <CodeEditor
                        value={templateConfigJson}
                        onChange={handleJsonChange}
                        language="json"
                        height="100%"
                        className="h-full font-mono text-sm"
                      />
                    </div>
                  </Stack>
                )}
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3 pt-4 border-t border-border-subtle">
              <button
                type="button"
                onClick={() => setShowTemplateModal(false)}
                className="btn-outline h-10 px-4 text-sm"
              >
                Cancel
              </button>
              {templateModalMode === 'edit' && (
                <button
                  type="button"
                  disabled={
                    isDemoMode ||
                    templateDeleteMutation.isPending ||
                    !editingTemplateId ||
                    templateDetailLoading
                  }
                  onClick={() => {
                    if (!editingTemplateId) return;
                    const ok = window.confirm('Delete this template? This cannot be undone.');
                    if (!ok) return;
                    templateDeleteMutation.mutate(editingTemplateId);
                  }}
                  className="h-10 px-4 text-sm font-medium border border-ac-red text-ac-red hover:bg-ac-red hover:text-white transition-colors disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                >
                  {templateDeleteMutation.isPending ? 'Deleting...' : 'Delete'}
                </button>
              )}
              <button
                type="button"
                disabled={
                  isDemoMode ||
                  templateCreateMutation.isPending ||
                  templateUpdateMutation.isPending ||
                  templateDetailLoading
                }
                onClick={submitTemplateModal}
                className="btn-primary h-10 px-4 text-sm disabled:opacity-50"
              >
                {templateModalMode === 'create'
                  ? templateCreateMutation.isPending
                    ? 'Creating...'
                    : 'Create Template'
                  : templateUpdateMutation.isPending
                    ? 'Saving...'
                    : 'Save Changes'}
              </button>
            </div>

            {templateDetailLoading && templateModalMode === 'edit' && (
              <div className="absolute inset-0 flex items-center justify-center bg-ac-black/20">
                <div className="bg-surface-base border border-border-subtle px-4 py-2 text-sm text-ink-secondary">
                  Loading template...
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
