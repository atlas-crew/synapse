import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Settings, Code2, RefreshCw, AlertCircle } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb, SectionHeader, Spinner, Stack } from '@/ui';
import { useToast } from '../../components/ui/Toast';
import { CodeEditor } from '../../components/ctrlx/CodeEditor';
import { ConfigPanelSkeleton, Skeleton } from '../../components/LoadingStates';
import {
  AdvancedConfigPanel,
  defaultAdvancedConfig,
  type AdvancedConfigData,
} from '../../components/fleet/pingora/AdvancedConfigPanel';
import { deepMergeConfig } from '../../utils';
import { apiFetch, formatApiError } from '../../lib/api';

async function fetchFullConfig(id: string) {
  return apiFetch(`/fleet/sensors/${id}/config/pingora`);
}

async function updateFullConfig(id: string, config: unknown) {
  return apiFetch(`/fleet/sensors/${id}/config/pingora`, { method: 'POST', body: config });
}

type ViewMode = 'guided' | 'json';
const PAGE_HEADER_STYLE = { marginBottom: 0 };
const PAGE_HEADER_TITLE_STYLE = {
  fontSize: '20px',
  lineHeight: '28px',
  color: 'var(--text-primary)',
};

type UpstreamPresetResult = { json: string; sitesUpdated: number };

function applyUpstreamPreset(rawJson: string, host: string, port: number): UpstreamPresetResult {
  const parsed = JSON.parse(rawJson) as Record<string, unknown>;

  const next = { ...parsed } as any;
  const upstream = [{ host, port, weight: 1 }];

  if (Array.isArray(next.sites) && next.sites.length > 0) {
    let sitesUpdated = 0;
    next.sites = next.sites.map((site: any) => {
      if (!site || typeof site !== 'object') return site;
      sitesUpdated++;
      return { ...site, upstreams: upstream };
    });
    return { json: JSON.stringify(next, null, 2), sitesUpdated };
  }

  next.sites = [
    {
      hostname: 'demo.site',
      upstreams: upstream,
    },
  ];
  return { json: JSON.stringify(next, null, 2), sitesUpdated: 1 };
}

// Extract advanced config sections from full pingora config
function extractAdvancedConfig(fullConfig: Record<string, unknown>): AdvancedConfigData {
  return {
    dlp: (fullConfig.dlp as AdvancedConfigData['dlp']) || defaultAdvancedConfig.dlp,
    block_page: (fullConfig.block_page as AdvancedConfigData['block_page']) || defaultAdvancedConfig.block_page,
    crawler: (fullConfig.crawler as AdvancedConfigData['crawler']) || defaultAdvancedConfig.crawler,
    tarpit: (fullConfig.tarpit as AdvancedConfigData['tarpit']) || defaultAdvancedConfig.tarpit,
    entity: (fullConfig.entity as AdvancedConfigData['entity']) || defaultAdvancedConfig.entity,
    travel: (fullConfig.travel as AdvancedConfigData['travel']) || defaultAdvancedConfig.travel,
  };
}

// Merge advanced config back into full config
// Uses deepMergeConfig to preserve nested properties that aren't in the UI
function mergeAdvancedConfig(
  fullConfig: Record<string, unknown>,
  advancedConfig: AdvancedConfigData
): Record<string, unknown> {
  return {
    ...fullConfig,
    dlp: deepMergeConfig(fullConfig.dlp as Record<string, unknown> || {}, advancedConfig.dlp),
    block_page: deepMergeConfig(fullConfig.block_page as Record<string, unknown> || {}, advancedConfig.block_page),
    crawler: deepMergeConfig(fullConfig.crawler as Record<string, unknown> || {}, advancedConfig.crawler),
    tarpit: deepMergeConfig(fullConfig.tarpit as Record<string, unknown> || {}, advancedConfig.tarpit),
    entity: deepMergeConfig(fullConfig.entity as Record<string, unknown> || {}, advancedConfig.entity),
    travel: deepMergeConfig(fullConfig.travel as Record<string, unknown> || {}, advancedConfig.travel),
  };
}

export function SensorConfigPage() {
  useDocumentTitle('Sensor Configuration');
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<ViewMode>('guided');
  const [configJson, setConfigJson] = useState('');
  const [advancedConfig, setAdvancedConfig] = useState<AdvancedConfigData>(defaultAdvancedConfig);
  const [fullConfigRef, setFullConfigRef] = useState<Record<string, unknown>>({});
  const [isDirty, setIsDirty] = useState(false);
  const [apparatusHost, setApparatusHost] = useState('demo.site');
  const [apparatusPort, setApparatusPort] = useState<number>(80);

  const { data: sensor } = useQuery({
    queryKey: ['fleet', 'sensor', id],
    queryFn: async () => {
      return apiFetch(`/fleet/sensors/${id}`);
    },
    enabled: !!id,
  });

  const { data: remoteConfig, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'full'],
    queryFn: () => fetchFullConfig(id!),
    enabled: !!id,
  });

  useEffect(() => {
    if (remoteConfig) {
      const configData = (remoteConfig.data || remoteConfig) as Record<string, unknown>;
      setFullConfigRef(configData);
      setConfigJson(JSON.stringify(configData, null, 2));
      setAdvancedConfig(extractAdvancedConfig(configData));
      setIsDirty(false);
    }
  }, [remoteConfig]);

  const updateMutation = useMutation({
    mutationFn: (config: unknown) => updateFullConfig(id!, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config'] });
      setIsDirty(false);
      toast.success('Configuration updated successfully and push initiated');
    },
    onError: (err: unknown) => {
      toast.error(`Update failed: ${formatApiError(err, 'Unknown error')}`);
    }
  });

  const handleAdvancedConfigChange = useCallback((newAdvancedConfig: AdvancedConfigData) => {
    setAdvancedConfig(newAdvancedConfig);
    const merged = mergeAdvancedConfig(fullConfigRef, newAdvancedConfig);
    setFullConfigRef(merged);
    setConfigJson(JSON.stringify(merged, null, 2));
    setIsDirty(true);
  }, [fullConfigRef]);

  const handleJsonChange = useCallback((value: string) => {
    setConfigJson(value);
    setIsDirty(true);
    // Try to sync back to guided view
    try {
      const parsed = JSON.parse(value) as Record<string, unknown>;
      setFullConfigRef(parsed);
      setAdvancedConfig(extractAdvancedConfig(parsed));
    } catch {
      // Invalid JSON - don't update guided view
    }
  }, []);

  const handleSave = () => {
    try {
      const parsed = JSON.parse(configJson);
      updateMutation.mutate(parsed);
    } catch {
      toast.error('Invalid JSON configuration');
    }
  };

  const handleModeChange = (mode: ViewMode) => {
    if (mode === 'json' && viewMode === 'guided') {
      // Sync guided changes to JSON before switching
      const merged = mergeAdvancedConfig(fullConfigRef, advancedConfig);
      setConfigJson(JSON.stringify(merged, null, 2));
    }
    setViewMode(mode);
  };

  if (isLoading) return (
    <Stack direction="column" className="h-full bg-surface-base min-h-[calc(100vh-64px)]">
      <div className="px-6 py-4 border-b border-border-subtle bg-surface-card">
        <Skeleton className="h-4 w-48 mb-2" />
        <Skeleton className="h-6 w-64" />
      </div>
      <ConfigPanelSkeleton />
    </Stack>
  );
  if (error) return (
    <Stack direction="column" align="center" justify="center" gap="md" className="p-12">
      <Stack direction="row" align="center" gap="sm" className="text-status-error">
        <AlertCircle className="w-5 h-5" />
        <span>Error: {formatApiError(error, 'Failed to load configuration')}</span>
      </Stack>
      <button
        onClick={() => refetch()}
        disabled={isFetching}
        className="px-4 py-2 text-sm bg-accent-primary text-white hover:bg-accent-primary/90 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
      >
        <Stack as="span" inline direction="row" align="center" gap="sm">
          {isFetching ? <Spinner size={16} color="#FFFFFF" /> : <RefreshCw className="w-4 h-4" />}
          {isFetching ? 'Retrying...' : 'Retry'}
        </Stack>
      </button>
    </Stack>
  );

  return (
    <div className="flex flex-col h-full bg-surface-base min-h-[calc(100vh-64px)]">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-card">
        <div>
          <Breadcrumb items={[
            { label: 'Fleet', to: '/fleet' },
            { label: sensor?.name || 'Sensor', to: `/fleet/sensors/${id}` },
            { label: 'Advanced Configuration' },
          ]} />
          <SectionHeader
            title="Advanced Configuration"
            size="h1"
            style={PAGE_HEADER_STYLE}
            titleStyle={PAGE_HEADER_TITLE_STYLE}
          />
        </div>
        <Stack direction="row" align="center" gap="smPlus">
          {/* View Mode Tabs */}
          <div className="flex items-center bg-surface-subtle p-1">
            <button
              onClick={() => handleModeChange('guided')}
              className={`px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                viewMode === 'guided'
                  ? 'bg-surface-card text-ink-primary shadow-sm'
                  : 'text-ink-secondary hover:text-ink-primary'
              }`}
            >
              <Stack as="span" inline direction="row" align="center" gap="xsPlus">
                <Settings className="w-4 h-4" />
                Guided
              </Stack>
            </button>
            <button
              onClick={() => handleModeChange('json')}
              className={`px-3 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                viewMode === 'json'
                  ? 'bg-surface-card text-ink-primary shadow-sm'
                  : 'text-ink-secondary hover:text-ink-primary'
              }`}
            >
              <Stack as="span" inline direction="row" align="center" gap="xsPlus">
                <Code2 className="w-4 h-4" />
                JSON
              </Stack>
            </button>
          </div>

          {isDirty && <span className="text-xs text-status-warning font-medium">Unsaved Changes</span>}
          <button
            onClick={() => navigate(`/fleet/sensors/${id}`)}
            className="px-4 py-2 text-sm border border-border-subtle hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={!isDirty || updateMutation.isPending}
            className="px-4 py-2 text-sm bg-accent-primary text-white hover:bg-accent-primary/90 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
          >
            {updateMutation.isPending ? 'Saving...' : 'Save & Push'}
          </button>
        </Stack>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden">
        {viewMode === 'guided' ? (
          <AdvancedConfigPanel
            config={advancedConfig}
            onChange={handleAdvancedConfigChange}
          />
	        ) : (
	          <Stack direction="column" gap="md" className="h-full p-6">
	            <div className="bg-status-info/10 border border-status-info/20 p-4 flex items-start gap-3 flex-shrink-0">
	              <span className="text-status-info text-xl">&#x2139;&#xFE0F;</span>
	              <div className="text-sm text-ink-secondary">
	                <p className="font-semibold text-ink-primary mb-1">DANGER ZONE: Raw Configuration Access</p>
	                <p>You are editing the full runtime configuration for this sensor. Changes will be pushed immediately to the device via WebSocket. Invalid configuration may cause the sensor to malfunction or disconnect.</p>
	              </div>
	            </div>

              <Stack
                direction="row"
                align="flex-start"
                justify="space-between"
                gap="md"
                className="border border-border-subtle bg-surface-card p-4 flex-shrink-0"
              >
                <div className="space-y-1">
                  <div className="text-xs font-bold uppercase tracking-[0.2em] text-ink-secondary">
                    Preset: Apparatus Echo Target (13 protocols)
                  </div>
                  <div className="text-xs text-ink-muted">
                    Docker: `just dev-waf-echo` (target host `demo.site`). Default HTTP/1 upstream: `demo.site:80`.
                  </div>
                  <div className="text-[11px] font-mono text-ink-muted">
                    Ports: 80 http1, 443 http2, 81 h2c, 9000 tcp, 9001 udp, 50051 grpc, 1883 mqtt, 1344 icap, 6379 redis,
                    2525 smtp, 5140 syslog
                  </div>
                </div>

                <div className="flex items-end gap-2">
                  <div className="space-y-1">
                    <label className="block text-[10px] font-bold uppercase tracking-[0.2em] text-ink-secondary">
                      Host
                    </label>
                    <input
                      value={apparatusHost}
                      onChange={(e) => setApparatusHost(e.target.value)}
                      className="h-9 w-44 bg-surface-subtle border border-border-subtle px-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="block text-[10px] font-bold uppercase tracking-[0.2em] text-ink-secondary">
                      Port
                    </label>
                    <input
                      type="number"
                      value={apparatusPort}
                      onChange={(e) => setApparatusPort(Number(e.target.value))}
                      className="h-9 w-24 bg-surface-subtle border border-border-subtle px-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                    />
                  </div>
                  <button
                    onClick={() => {
                      try {
                        const host = apparatusHost.trim();
                        if (!host) {
                          toast.error('Host is required');
                          return;
                        }

                        const port = Number(apparatusPort);
                        if (!Number.isFinite(port) || port < 1 || port > 65535) {
                          toast.error('Port must be 1-65535');
                          return;
                        }

                        const res = applyUpstreamPreset(configJson, host, port);
                        handleJsonChange(res.json);
                        toast.success(`Updated upstreams for ${res.sitesUpdated} site(s)`);
                      } catch (err) {
                        toast.error(formatApiError(err, 'Failed to apply upstream preset'));
                      }
                    }}
                    className="h-9 px-3 text-xs font-bold uppercase tracking-[0.2em] border-2 border-ac-magenta text-ac-magenta hover:bg-ac-magenta hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                  >
                    Apply Upstream
                  </button>
                </div>
              </Stack>
	
	            <div className="flex-1 min-h-0 border border-border-subtle overflow-hidden shadow-sm">
	              <CodeEditor
	                value={configJson}
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
  );
}
