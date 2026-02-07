import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Settings, Code2, RefreshCw, AlertCircle } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { Breadcrumb } from '../../components/ui/Breadcrumb';
import { useToast } from '../../components/ui/Toast';
import { CodeEditor } from '../../components/ctrlx/CodeEditor';
import { ConfigPanelSkeleton, Skeleton } from '../../components/LoadingStates';
import {
  AdvancedConfigPanel,
  defaultAdvancedConfig,
  type AdvancedConfigData,
} from '../../components/fleet/pingora/AdvancedConfigPanel';
import { deepMergeConfig } from '../../utils';
import { ApiError, formatApiError } from '../../lib/api';

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';

const authHeaders = {
  Authorization: `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
};

async function fetchFullConfig(id: string) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, { headers: authHeaders });
  if (!response.ok) {
    let serverMessage: string | undefined;
    try {
      const body = await response.json();
      serverMessage = body.error ?? body.message;
    } catch { /* no parseable body */ }
    throw new ApiError(
      response.status,
      serverMessage
        ? `Failed to fetch configuration (${response.status}: ${serverMessage})`
        : `Failed to fetch configuration (${response.status} ${response.statusText})`,
      serverMessage,
    );
  }
  return response.json();
}

async function updateFullConfig(id: string, config: unknown) {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}/config/pingora`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify(config),
  });
  if (!response.ok) {
    let serverMessage: string | undefined;
    try {
      const body = await response.json();
      serverMessage = body.error ?? body.message;
    } catch { /* no parseable body */ }
    throw new ApiError(
      response.status,
      serverMessage || `Failed to update configuration (${response.status} ${response.statusText})`,
      serverMessage,
    );
  }
  return response.json();
}

type ViewMode = 'guided' | 'json';

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
  const { toast, Toasts } = useToast();
  const [viewMode, setViewMode] = useState<ViewMode>('guided');
  const [configJson, setConfigJson] = useState('');
  const [advancedConfig, setAdvancedConfig] = useState<AdvancedConfigData>(defaultAdvancedConfig);
  const [fullConfigRef, setFullConfigRef] = useState<Record<string, unknown>>({});
  const [isDirty, setIsDirty] = useState(false);

  const { data: sensor } = useQuery({
    queryKey: ['fleet', 'sensor', id],
    queryFn: async () => {
      const response = await fetch(`${API_BASE}/api/v1/fleet/sensors/${id}`, { headers: authHeaders });
      return response.json();
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
    <div className="flex flex-col h-full bg-surface-base min-h-[calc(100vh-64px)]">
      <div className="px-6 py-4 border-b border-border-subtle bg-surface-card">
        <Skeleton className="h-4 w-48 mb-2" />
        <Skeleton className="h-6 w-64" />
      </div>
      <ConfigPanelSkeleton />
    </div>
  );
  if (error) return (
    <div className="p-12 flex flex-col items-center justify-center gap-4">
      <div className="flex items-center gap-2 text-status-error">
        <AlertCircle className="w-5 h-5" />
        <span>Error: {formatApiError(error, 'Failed to load configuration')}</span>
      </div>
      <button
        onClick={() => refetch()}
        disabled={isFetching}
        className="flex items-center gap-2 px-4 py-2 text-sm bg-accent-primary text-white hover:bg-accent-primary/90 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
      >
        <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
        {isFetching ? 'Retrying...' : 'Retry'}
      </button>
    </div>
  );

  return (
    <div className="flex flex-col h-full bg-surface-base min-h-[calc(100vh-64px)]">
      {Toasts}
      {/* Header */}
      <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-card">
        <div>
          <Breadcrumb items={[
            { label: 'Fleet', to: '/fleet' },
            { label: sensor?.name || 'Sensor', to: `/fleet/sensors/${id}` },
            { label: 'Advanced Configuration' },
          ]} />
          <h1 className="text-xl font-light text-ink-primary">Advanced Configuration</h1>
        </div>
        <div className="flex items-center gap-3">
          {/* View Mode Tabs */}
          <div className="flex items-center bg-surface-subtle p-1">
            <button
              onClick={() => handleModeChange('guided')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium  transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                viewMode === 'guided'
                  ? 'bg-surface-card text-ink-primary shadow-sm'
                  : 'text-ink-secondary hover:text-ink-primary'
              }`}
            >
              <Settings className="w-4 h-4" />
              Guided
            </button>
            <button
              onClick={() => handleModeChange('json')}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium  transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                viewMode === 'json'
                  ? 'bg-surface-card text-ink-primary shadow-sm'
                  : 'text-ink-secondary hover:text-ink-primary'
              }`}
            >
              <Code2 className="w-4 h-4" />
              JSON
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
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-hidden">
        {viewMode === 'guided' ? (
          <AdvancedConfigPanel
            config={advancedConfig}
            onChange={handleAdvancedConfigChange}
          />
        ) : (
          <div className="h-full p-6 flex flex-col gap-4">
            <div className="bg-status-info/10 border border-status-info/20 p-4 flex items-start gap-3 flex-shrink-0">
              <span className="text-status-info text-xl">&#x2139;&#xFE0F;</span>
              <div className="text-sm text-ink-secondary">
                <p className="font-semibold text-ink-primary mb-1">DANGER ZONE: Raw Configuration Access</p>
                <p>You are editing the full runtime configuration for this sensor. Changes will be pushed immediately to the device via WebSocket. Invalid configuration may cause the sensor to malfunction or disconnect.</p>
              </div>
            </div>

            <div className="flex-1 min-h-0 border border-border-subtle overflow-hidden shadow-sm">
              <CodeEditor
                value={configJson}
                onChange={handleJsonChange}
                language="json"
                height="100%"
                className="h-full font-mono text-sm"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
