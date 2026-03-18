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
import { 
  Alert,
  Modal, 
  SectionHeader, 
  Stack, 
  Box, 
  Text, 
  Button, 
  Input, 
  Select, 
  Tabs,
  Grid,
  alpha,
  colors,
  CARD_HEADER_TITLE_STYLE 
} from '@/ui';

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

  const envColorTokens = {
    production: colors.red,
    staging: colors.orange,
    dev: colors.blue,
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
    <Box p="xl">
      <Stack gap="xl">
        <Box flex direction="row" align="center" justify="space-between">
          <SectionHeader
            eyebrow="Signal Horizon"
            title="Configuration Manager"
            description="Manage and deploy configuration templates across your fleet"
          />
          <Button
            onClick={openCreateModal}
            disabled={isDemoMode}
            size="lg"
          >
            Create Template
          </Button>
        </Box>

        {/* Sync Status */}
        {syncIsError ? (
          <Box bg="card" border="subtle" p="lg">
            <Text variant="small" style={{ color: 'var(--ac-red)' }}>Sync status unavailable: {syncErrorMessage}</Text>
            <Box style={{ marginTop: '12px' }}>
              <Button
                variant="outlined"
                size="sm"
                onClick={() => refetchSyncStatus()}
              >
                Retry
              </Button>
            </Box>
          </Box>
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
          <Box bg="card" border="subtle" p="lg">
            <Box flex direction="row" align="center" justify="space-between" style={{ marginBottom: '8px' }}>
              <Text variant="h3" weight="medium" noMargin>Fleet Sync Status</Text>
              <Text variant="body" color="secondary" noMargin>
                {Math.round(syncStatus.syncPercentage)}%
              </Text>
            </Box>
            <Box style={{ width: '100%', height: '12px', background: 'var(--surface-inset)' }}>
              <Box
                style={{
                  height: '100%',
                  background: 'var(--ac-blue)',
                  width: `${syncStatus.syncPercentage}%`,
                  transition: 'width 0.5s ease',
                }}
              />
            </Box>
          </Box>
        )}

        {/* Pingora Presets */}
        <Box bg="card" border="subtle">
          <Box p="lg" border="bottom" borderColor="subtle">
            <SectionHeader
              title="Pingora Upstream Presets"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
            />
            <Text variant="small" color="secondary" style={{ marginTop: '4px' }}>
              Deploy upstream rewrites to existing sensor configs (pushes immediately).
            </Text>
          </Box>

          <Box p="lg">
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <Box style={{ gridColumn: 'span 1' }}>
                <Stack gap="lg">
                  <Box>
                    <Text variant="label" color="secondary" style={{ marginBottom: '4px' }}>
                      Apparatus Echo Target
                    </Text>
                    <Text variant="body" color="secondary">
                      Local stack: <Text as="span" variant="code">just dev-waf-echo</Text> exposes{' '}
                      <Text as="span" variant="code">demo.site</Text>.
                    </Text>
                  </Box>

                  <Grid cols={2} gap="md">
                    <Input
                      label="Host"
                      value={echoHost}
                      onChange={(e) => setEchoHost(e.target.value)}
                      size="sm"
                      style={{ fontFamily: 'var(--font-mono)' }}
                    />
                    <Input
                      label="Port"
                      type="number"
                      value={echoPort}
                      onChange={(e) => setEchoPort(Number(e.target.value))}
                      size="sm"
                      style={{ fontFamily: 'var(--font-mono)' }}
                    />
                  </Grid>

                  <Button
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
                    variant="outlined"
                    style={{ 
                      borderColor: colors.magenta, 
                      color: colors.magenta,
                      textTransform: 'uppercase',
                      letterSpacing: '0.15em',
                      fontWeight: 700
                    }}
                  >
                    {echoPresetMutation.isPending
                      ? 'Pushing...'
                      : `Push To Selected (${echoSelectedIds.length})`}
                  </Button>

                  {isDemoMode && <Text variant="caption" color="secondary">Disabled in demo mode.</Text>}
                </Stack>
              </Box>

              <Box style={{ gridColumn: 'span 2' }}>
                <Box flex direction="row" align="center" justify="space-between" style={{ marginBottom: '12px' }}>
                  <Text variant="label" color="secondary">Target Sensors</Text>
                  <Stack direction="row" gap="sm">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedEchoSensors(new Set(sensors.map((s: any) => s.id)))}
                    >
                      Select All
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setSelectedEchoSensors(new Set())}
                    >
                      Clear
                    </Button>
                  </Stack>
                </Box>

                <Box border="subtle" bg="bg" style={{ maxHeight: '320px', overflow: 'auto' }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                          <Text variant="label" color="secondary" noMargin>Select</Text>
                        </th>
                        <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                          <Text variant="label" color="secondary" noMargin>Sensor</Text>
                        </th>
                        <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                          <Text variant="label" color="secondary" noMargin>Status</Text>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {sensors.map((sensor: any) => (
                        <tr key={sensor.id} style={{ borderBottom: '1px solid var(--border)' }}>
                          <td style={{ padding: '12px 16px' }}>
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
                              className="w-4 h-4"
                              style={{ accentColor: 'var(--ac-blue)' }}
                            />
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Text variant="body" weight="medium" noMargin>{sensor.name}</Text>
                            <Text variant="caption" color="secondary" noMargin style={{ fontFamily: 'var(--font-mono)' }}>
                              {sensor.id}
                            </Text>
                          </td>
                          <td style={{ padding: '12px 16px' }}>
                            <Text variant="small" color="secondary" noMargin>
                              {sensor.connectionState || 'UNKNOWN'}
                            </Text>
                          </td>
                        </tr>
                      ))}
                      {sensors.length === 0 && (
                        <tr>
                          <td colSpan={3} style={{ padding: '32px', textAlign: 'center' }}>
                            <Text variant="body" color="secondary" noMargin>No sensors available.</Text>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </Box>
              </Box>
            </div>
          </Box>
        </Box>

        {/* Templates */}
        <Box bg="card" border="subtle">
          <Box p="lg" border="bottom" borderColor="subtle">
            <SectionHeader
              title="Configuration Templates"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Stack direction="row" gap="xsPlus">
                  {['all', 'production', 'staging', 'dev'].map((env) => (
                    <Button
                      key={env}
                      variant={envFilter === env ? 'primary' : 'outlined'}
                      size="sm"
                      onClick={() => setEnvFilter(env as any)}
                      style={{ textTransform: 'capitalize' }}
                    >
                      {env}
                    </Button>
                  ))}
                </Stack>
              }
            />
          </Box>

          {templatesLoading ? (
            <Box p="xl" style={{ textAlign: 'center' }}>
              <Text variant="body" color="secondary">Loading templates...</Text>
            </Box>
          ) : templatesIsError ? (
            <Box p="lg">
              <Text variant="small" style={{ color: 'var(--ac-red)' }}>
                Templates unavailable: {templatesErrorMessage}
              </Text>
              <Box style={{ marginTop: '12px' }}>
                <Button
                  variant="outlined"
                  size="sm"
                  onClick={() => refetchTemplates()}
                >
                  Retry
                </Button>
              </Box>
            </Box>
          ) : filteredTemplates.length === 0 ? (
            <Box p="xl" style={{ textAlign: 'center' }}>
              <Text variant="body" color="secondary">
                No templates found. Create your first template to get started.
              </Text>
            </Box>
          ) : (
            <Stack gap="none">
              {filteredTemplates.map((template, index) => (
                <Box
                  key={template.id}
                  p="lg"
                  border={index > 0 ? 'top' : 'none'}
                  borderColor="subtle"
                  className="hover:bg-surface-subtle transition-colors"
                  style={{ 
                    cursor: 'pointer',
                    background: selectedTemplate === template.id ? 'var(--ac-blue-dim)' : 'transparent'
                  }}
                  onClick={() => setSelectedTemplate(template.id)}
                >
                  <Box flex direction="row" align="start" justify="space-between">
                    <Stack gap="xs" style={{ flex: 1 }}>
                      <Stack direction="row" align="center" gap="md">
                        <Text variant="h3" weight="medium" noMargin>{template.name}</Text>
                        <Box
                          px="sm"
                          py="none"
                          style={{
                            border: '1px solid',
                            background: `color-mix(in srgb, ${envColorTokens[template.environment]}, transparent 90%)`,
                            color: envColorTokens[template.environment],
                            borderColor: `color-mix(in srgb, ${envColorTokens[template.environment]}, transparent 70%)`,
                          }}
                        >
                          <Text variant="tag" style={{ fontSize: '9px' }}>{template.environment}</Text>
                        </Box>
                        {template.isActive && (
                          <Box
                            px="sm"
                            py="none"
                            style={{
                              border: '1px solid',
                              background: 'var(--ac-green-dim)',
                              color: 'var(--ac-green)',
                              borderColor: alpha(colors.green, 0.3),
                            }}
                          >
                            <Text variant="tag" style={{ fontSize: '9px' }}>Active</Text>
                          </Box>
                        )}
                      </Stack>
                      {template.description && (
                        <Text variant="body" color="secondary" noMargin>{template.description}</Text>
                      )}
                      <Text variant="caption" color="secondary" noMargin>
                        Version {template.version} • Updated{' '}
                        {new Date(template.updatedAt).toLocaleDateString()}
                      </Text>
                    </Stack>
                    <Stack direction="row" gap="sm">
                      <Button
                        size="sm"
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
                      >
                        {pushMutation.isPending ? 'Pushing...' : 'Push to All'}
                      </Button>
                      <Button
                        variant="outlined"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          openPushModal(template.id);
                        }}
                        disabled={isDemoMode}
                      >
                        Push to Selected
                      </Button>
                      <Button
                        variant="outlined"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          openEditModal(template.id);
                        }}
                      >
                        Edit
                      </Button>
                    </Stack>
                  </Box>
                </Box>
              ))}
            </Stack>
          )}
        </Box>

        {/* Audit Trail */}
        <Box bg="card" border="subtle">
          <Box p="lg" border="bottom" borderColor="subtle">
            <SectionHeader
              title="Configuration Audit Trail"
              description="Recent config changes across the fleet"
              size="h4"
              style={{ marginBottom: 0 }}
              titleStyle={CARD_HEADER_TITLE_STYLE}
              actions={
                <Text variant="caption" color="secondary" noMargin>
                  {auditData?.total ?? auditLogs.length} events
                </Text>
              }
            />
          </Box>

          {isDemoMode ? (
            <Box p="lg">
              <Text variant="body" color="secondary">Audit trail is disabled in demo mode.</Text>
            </Box>
          ) : auditIsError ? (
            <Box p="lg">
              <Text variant="small" style={{ color: 'var(--ac-red)' }}>
                Audit trail unavailable: {auditErrorMessage}
              </Text>
              <Box style={{ marginTop: '12px' }}>
                <Button
                  variant="outlined"
                  size="sm"
                  onClick={() => refetchAudit()}
                >
                  Retry
                </Button>
              </Box>
            </Box>
          ) : auditLoading ? (
            <Box p="xl" style={{ textAlign: 'center' }}>
              <Text variant="body" color="secondary">Loading audit trail...</Text>
            </Box>
          ) : auditLogs.length === 0 ? (
            <Box p="xl" style={{ textAlign: 'center' }}>
              <Text variant="body" color="secondary">No configuration changes recorded yet.</Text>
            </Box>
          ) : (
            <Stack gap="none">
              {auditLogs.map((log, index) => {
                const changeCount = resolveChangeCount(log);
                const summary = `${resolveResourceLabel(log)} ${formatAuditAction(log.action)}`;
                return (
                  <Box
                    key={log.id}
                    p="md"
                    border={index > 0 ? 'top' : 'none'}
                    borderColor="subtle"
                    flex 
                    direction="row" 
                    align="start" 
                    justify="space-between"
                  >
                    <Stack gap="xs">
                      <Text variant="body" weight="medium" noMargin>{summary}</Text>
                      <Stack direction="row" align="center" gap="sm" wrap>
                        {log.resourceId ? (
                          <Text variant="code" noMargin>{log.resourceId}</Text>
                        ) : (
                          <Text variant="caption" color="secondary" noMargin>unknown resource</Text>
                        )}
                        {changeCount > 0 && (
                          <Text variant="caption" color="secondary" noMargin>• {changeCount} changes</Text>
                        )}
                        <Text variant="caption" color="secondary" noMargin>• {log.userId ?? 'system'}</Text>
                      </Stack>
                    </Stack>
                    <Text variant="caption" color="secondary" noMargin>
                      {new Date(log.createdAt).toLocaleString()}
                    </Text>
                  </Box>
                );
              })}
            </Stack>
          )}
        </Box>
      </Stack>

      {/* Push Modal */}
      {showPushModal && (
        <Modal
          open
          onClose={() => setShowPushModal(false)}
          size="1200px"
          title="Push Template To Sensors"
          style={{ height: '80vh', maxHeight: '80vh' }}
        >
          <Box flex direction="column" style={{ height: '100%' }}>
            <Box flex direction="row" align="center" justify="space-between" style={{ marginBottom: '12px' }}>
              <Text variant="label" color="secondary">Target Sensors</Text>
              <Stack direction="row" gap="sm">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setPushSelectedSensors(new Set(sensors.map((s: any) => String(s.id))))}
                >
                  Select All
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setPushSelectedSensors(new Set())}
                >
                  Clear
                </Button>
              </Stack>
            </Box>

            <Box border="subtle" bg="bg" style={{ flex: 1, overflow: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Select</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Sensor</Text>
                    </th>
                    <th style={{ textAlign: 'left', padding: '12px 16px', background: 'var(--surface-inset)', borderBottom: '1px solid var(--border-accent)' }}>
                      <Text variant="label" color="secondary" noMargin>Status</Text>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sensors.map((sensor: any) => (
                    <tr key={sensor.id} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '12px 16px' }}>
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
                          className="w-4 h-4"
                          style={{ accentColor: 'var(--ac-blue)' }}
                        />
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="body" weight="medium" noMargin>{sensor.name}</Text>
                        <Text variant="caption" color="secondary" noMargin style={{ fontFamily: 'var(--font-mono)' }}>
                          {sensor.id}
                        </Text>
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <Text variant="small" color="secondary" noMargin>
                          {sensor.connectionState || 'UNKNOWN'}
                        </Text>
                      </td>
                    </tr>
                  ))}
                  {sensors.length === 0 && (
                    <tr>
                      <td colSpan={3} style={{ padding: '32px', textAlign: 'center' }}>
                        <Text variant="body" color="secondary" noMargin>No sensors available.</Text>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </Box>

            <Box p="lg" border="top" style={{ marginTop: '24px' }}>
              <Stack direction="row" gap="md" justify="end">
                <Button variant="outlined" onClick={() => setShowPushModal(false)}>
                  Cancel
                </Button>
                <Button
                  disabled={pushMutation.isPending || sensors.length === 0 || selectedPushCount === 0}
                  onClick={submitPushModal}
                >
                  {pushMutation.isPending ? 'Pushing...' : `Push (${selectedPushCount})`}
                </Button>
              </Stack>
            </Box>
          </Box>
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
          <Box flex direction="column" style={{ height: '100%', position: 'relative' }}>
            {templateDetailError && templateModalMode === 'edit' && (
              <Box p="md" style={{ marginBottom: '16px' }}>
                <Alert status="error" title="Load Error">{templateDetailError}</Alert>
              </Box>
            )}

            <Box flex direction="row" gap="lg" style={{ flex: 1, overflow: 'hidden', opacity: templateDetailLoading ? 0.6 : 1 }}>
              {/* Left Column: Metadata */}
              <Box style={{ width: 320 }}>
                <Stack gap="lg">
                  <Input
                    label="Name"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    disabled={templateDetailLoading}
                    placeholder="Template name"
                    size="md"
                  />
                  <Select
                    label="Environment"
                    value={newEnv}
                    onChange={(e) => setNewEnv(e.target.value as any)}
                    disabled={templateDetailLoading}
                    options={[
                      { value: 'dev', label: 'Development' },
                      { value: 'staging', label: 'Staging' },
                      { value: 'production', label: 'Production' },
                    ]}
                    size="md"
                  />
                  <Input
                    label="Description"
                    value={newDesc}
                    onChange={(e) => setNewDesc(e.target.value)}
                    disabled={templateDetailLoading}
                    placeholder="Optional description"
                    multiline
                    rows={4}
                    size="md"
                  />
                </Stack>
              </Box>

              {/* Right Column: Config Editor */}
              <Box flex direction="column" style={{ flex: 1, overflow: 'hidden' }}>
                <Box flex direction="row" align="center" justify="space-between" style={{ marginBottom: '12px' }}>
                  <Text variant="label" color="secondary">Sensor Configuration</Text>
                  <Tabs
                    variant="pills"
                    size="sm"
                    active={templateConfigView}
                    onChange={(key) => setTemplateConfigView(key as any)}
                    tabs={[
                      { key: 'base', label: 'Base' },
                      { key: 'advanced', label: 'Advanced' },
                      { key: 'json', label: 'JSON' },
                    ]}
                  />
                </Box>

                {templateConfigView === 'base' && (
                  <Box flex direction="column" style={{ flex: 1, overflow: 'hidden' }}>
                    {templateBaseYamlError && (
                      <Box p="sm" style={{ marginBottom: '8px' }}>
                        <Alert status="error">
{templateBaseYamlError}</Alert>
                      </Box>
                    )}
                    <Box style={{ flex: 1, overflow: 'hidden' }}>
                      <SynapseConfigEditor value={newConfig} onChange={handleBaseYamlChange} />
                    </Box>
                  </Box>
                )}

                {templateConfigView === 'advanced' && (
                  <Box border="subtle" bg="bg" style={{ flex: 1, overflow: 'auto' }}>
                    <AdvancedConfigPanel
                      config={templateAdvancedConfig}
                      onChange={handleAdvancedConfigChange}
                    />
                  </Box>
                )}

                {templateConfigView === 'json' && (
                  <Stack gap="md" style={{ height: '100%' }}>
                    <Box p="md" bg="surface-inset" border="subtle">
                      <Text variant="label" color="magenta" style={{ marginBottom: '4px' }}>RAW CONFIG</Text>
                      <Text variant="caption" color="secondary">Edit the full sensor configuration object. Invalid JSON will block save.</Text>
                    </Box>

                    {templateJsonError && (
                      <Alert status="error">
{templateJsonError}</Alert>
                    )}

                    <Box border="subtle" shadow="subtle" style={{ flex: 1, overflow: 'hidden' }}>
                      <CodeEditor
                        value={templateConfigJson}
                        onChange={handleJsonChange}
                        language="json"
                        height="100%"
                      />
                    </Box>
                  </Stack>
                )}
              </Box>
            </Box>

            <Box p="lg" border="top" style={{ marginTop: '24px' }}>
              <Stack direction="row" gap="md" justify="end">
                <Button variant="outlined" onClick={() => setShowTemplateModal(false)}>
                  Cancel
                </Button>
                {templateModalMode === 'edit' && (
                  <Button
                    variant="outlined"
                    disabled={isDemoMode || templateDeleteMutation.isPending || !editingTemplateId || templateDetailLoading}
                    onClick={() => {
                      if (!editingTemplateId) return;
                      const ok = window.confirm('Delete this template? This cannot be undone.');
                      if (!ok) return;
                      templateDeleteMutation.mutate(editingTemplateId);
                    }}
                    style={{ borderColor: colors.red, color: colors.red }}
                  >
                    {templateDeleteMutation.isPending ? 'Deleting...' : 'Delete'}
                  </Button>
                )}
                <Button
                  disabled={isDemoMode || templateCreateMutation.isPending || templateUpdateMutation.isPending || templateDetailLoading}
                  onClick={submitTemplateModal}
                >
                  {templateModalMode === 'create'
                    ? templateCreateMutation.isPending
                      ? 'Creating...'
                      : 'Create Template'
                    : templateUpdateMutation.isPending
                      ? 'Saving...'
                      : 'Save Changes'}
                </Button>
              </Stack>
            </Box>

            {templateDetailLoading && templateModalMode === 'edit' && (
              <Box 
                style={{ 
                  position: 'absolute', 
                  inset: 0, 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  background: 'rgba(0,0,0,0.2)',
                  zIndex: 10
                }}
              >
                <Box bg="card" border="subtle" px="lg" py="md">
                  <Text variant="body" color="secondary" noMargin>Loading template...</Text>
                </Box>
              </Box>
            )}
          </Box>
        </Modal>
      )}
    </Box>
  );
}
