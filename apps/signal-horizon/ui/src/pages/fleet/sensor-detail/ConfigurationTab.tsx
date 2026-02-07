import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertCircle,
  RefreshCw,
  Settings,
  WifiOff,
} from 'lucide-react';
import { useToast } from '../../../components/ui/Toast';
import { ConfigPanelSkeleton } from '../../../components/LoadingStates';
import { ConfigDriftViewer } from '../../../components/fleet/ConfigDriftViewer';
import { WafConfig, type WafConfigData } from '../../../components/fleet/pingora/WafConfig';
import { RateLimitConfig, type RateLimitData } from '../../../components/fleet/pingora/RateLimitConfig';
import { AccessControlConfig, type AccessControlData } from '../../../components/fleet/pingora/AccessControlConfig';
import { ServiceControls } from '../../../components/fleet/pingora/ServiceControls';
import {
  fetchKernelConfig,
  updateKernelConfig,
  fetchSystemConfig,
  fetchCommandHistory,
  fetchPingoraConfig,
  updatePingoraConfig,
  runPingoraAction,
} from './shared';

interface ConfigurationTabProps {
  sensor: any;
}

export function ConfigurationTab({ sensor }: ConfigurationTabProps) {
  const id = sensor.id;
  const isTunnelActive = Boolean(sensor?.tunnelActive);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast, Toasts } = useToast();
  const [configTab, setConfigTab] = useState<'general' | 'kernel' | 'pingora' | 'drift' | 'history'>('general');

  const {
    data: systemConfig,
    isLoading: isSystemConfigLoading,
    error: systemConfigError,
    refetch: refetchSystemConfig,
    isFetching: isSystemConfigFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'system'],
    queryFn: () => fetchSystemConfig(id),
    enabled: !!id && configTab === 'general' && isTunnelActive,
  });

  const { data: remoteKernelConfig, isLoading: isKernelLoading, error: kernelError, refetch: refetchKernel, isFetching: isKernelFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'kernel'],
    queryFn: () => fetchKernelConfig(id),
    enabled: !!id && configTab === 'kernel' && isTunnelActive,
  });

  // Load real Pingora config
  const { data: remotePingoraConfig, isLoading, error: pingoraError, refetch: refetchPingora, isFetching: isPingoraFetching } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'config', 'pingora'],
    queryFn: () => fetchPingoraConfig(id),
    enabled: !!id && (configTab === 'pingora' || configTab === 'drift'),
  });

  const {
    data: commandHistory,
    isLoading: isHistoryLoading,
    error: historyError,
    refetch: refetchHistory,
    isFetching: isHistoryFetching,
  } = useQuery({
    queryKey: ['fleet', 'sensor', id, 'commands'],
    queryFn: () => fetchCommandHistory(id),
    enabled: !!id && configTab === 'history',
  });

  // Local state for editing
  const [wafConfig, setWafConfig] = useState<WafConfigData>({
    enabled: true,
    threshold: 0.5,
    rule_overrides: {}
  });

  const [rateLimitConfig, setRateLimitConfig] = useState<RateLimitData>({
    enabled: true,
    requests_per_second: 100,
    burst: 50
  });

  const [aclConfig, setAccessConfig] = useState<AccessControlData>({
    allow: [],
    deny: []
  });
  const [kernelDraft, setKernelDraft] = useState<Record<string, string>>({});
  const [persistKernel, setPersistKernel] = useState(false);
  const lastPingoraHashRef = useRef<string | null>(null);
  const lastKernelHashRef = useRef<string | null>(null);

  const kernelParams = (remoteKernelConfig?.data?.parameters || {}) as Record<string, string>;

  // Sync local state when remote data loads
  useEffect(() => {
    if (remotePingoraConfig) {
      const nextHash = JSON.stringify(remotePingoraConfig);
      if (lastPingoraHashRef.current === nextHash) {
        return;
      }
      lastPingoraHashRef.current = nextHash;
      setWafConfig(remotePingoraConfig.waf);
      setRateLimitConfig(remotePingoraConfig.rateLimit);
      setAccessConfig(remotePingoraConfig.accessControl);
    }
  }, [remotePingoraConfig]);

  useEffect(() => {
    if (kernelParams) {
      const nextHash = JSON.stringify(kernelParams);
      if (lastKernelHashRef.current === nextHash) {
        return;
      }
      lastKernelHashRef.current = nextHash;
      setKernelDraft(kernelParams);
    }
  }, [kernelParams]);

  const systemConfigData = systemConfig?.data || {};
  const generalSettings = {
    ...(systemConfigData.general || {}),
    ...(systemConfigData.features || {}),
  } as Record<string, unknown>;

  const formatSectionEntries = (label: string, section?: Record<string, unknown>) =>
    Object.entries(section || {}).map(([key, value]) => [`${label} ${key}`, value] as const);

  const runtimeEntries = [
    ...formatSectionEntries('Risk', systemConfigData.runtimeConfig?.risk),
    ...formatSectionEntries('State', systemConfigData.runtimeConfig?.state),
    ...formatSectionEntries('Session', systemConfigData.runtimeConfig?.session),
  ];

  const describeCommand = (command: any) => {
    const payload = command?.payload || {};
    if (payload.templateId) return `Pushed config template ${payload.templateId}`;
    if (payload.policyTemplateId) return `Applied policy template ${payload.policyTemplateId}`;
    if (payload.config) return 'Updated sensor configuration';
    return `Sent ${command.commandType}`;
  };

  const configHistoryEntries = (commandHistory?.commands || [])
    .filter((command: any) => command.commandType === 'push_config')
    .map((command: any) => ({
      id: command.id,
      date: new Date(command.createdAt).toLocaleString(),
      change: describeCommand(command),
      status: command.status,
    }));

  // Mutations
  const updateMutation = useMutation({
    mutationFn: (config: any) => updatePingoraConfig(id, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'pingora'] });
      toast.success('Configuration updated and push initiated');
    },
  });

  const updateKernelMutation = useMutation({
    mutationFn: (params: Record<string, string>) => updateKernelConfig(id, params, persistKernel),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['fleet', 'sensor', id, 'config', 'kernel'] });
      const appliedCount = Object.keys(result?.data?.applied || {}).length;
      toast.success(`Kernel configuration applied (${appliedCount} parameters).`);
    },
  });

  const handlePingoraAction = async (action: 'test' | 'reload' | 'restart') => {
    await runPingoraAction(id, action);
  };

  const handleSaveAll = () => {
    updateMutation.mutate({
      waf: wafConfig,
      rateLimit: rateLimitConfig,
      accessControl: aclConfig,
    });
  };

  const driftData = {
    expected: JSON.stringify(remotePingoraConfig || {}, null, 2),
    actual: JSON.stringify({
      ...remotePingoraConfig,
      // Mock drift for visualization if needed
    }, null, 2)
  };

  const renderTunnelInactive = (label: string) => (
    <div className="card border border-border-subtle border-t-2 border-t-info p-6">
      <div className="flex items-start gap-3">
        <WifiOff className="w-5 h-5 text-status-warning" />
        <div className="space-y-2">
          <div className="text-sm font-semibold text-ink-primary">{label} unavailable</div>
          <div className="text-xs text-ink-secondary">
            Sensor tunnel is not connected. Connect the sensor to load live configuration data.
          </div>
          <button
            onClick={() => navigate('/fleet/connectivity')}
            className="btn-secondary h-9 px-3 text-xs uppercase tracking-[0.2em]"
          >
            View Connectivity
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      {Toasts}
      {/* Config Tabs — ARIA tab pattern */}
      <div className="card border border-border-subtle border-t-2 border-t-ac-blue">
        <div className="flex justify-between items-center gap-4 p-4 bg-surface-inset">
          <div role="tablist" aria-label="Configuration sections" className="flex gap-2">
          {(['general', 'kernel', 'pingora', 'drift', 'history'] as const).map((tab) => (
            <button
              key={tab}
              role="tab"
              id={`tab-config-${tab}`}
              aria-selected={configTab === tab}
              aria-controls={`tabpanel-config-${tab}`}
              onClick={() => setConfigTab(tab)}
              className={`px-4 py-2 text-xs uppercase tracking-[0.2em] border transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50 ${
                configTab === tab
                  ? 'border-ac-blue text-ac-blue bg-ac-blue/10'
                  : 'border-border-subtle text-ink-secondary hover:border-ac-blue/50 hover:text-ink-primary'
              }`}
            >
              {tab === 'pingora' ? 'Synapse-Pingora' : tab === 'drift' ? 'Drift Analysis' : tab}
            </button>
          ))}
          </div>

          <div className="flex gap-3">
          <button
            onClick={() => navigate(`/fleet/sensors/${id}/config`)}
            className="btn-secondary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
          >
            <Settings className="w-4 h-4" />
            Advanced JSON Editor
          </button>
          {configTab === 'pingora' && (
            <button
              onClick={handleSaveAll}
              disabled={updateMutation.isPending || !isTunnelActive}
              className="btn-primary h-10 px-6 text-sm"
            >
              {!isTunnelActive
                ? 'Tunnel Required'
                : updateMutation.isPending
                  ? 'Saving...'
                  : 'Save & Push Changes'}
            </button>
          )}
          </div>
        </div>
      </div>

      {configTab === 'drift' && (
        <ConfigDriftViewer
          expectedConfig={driftData.expected}
          actualConfig={driftData.actual}
          lastSync="Just now"
          driftDetected={false}
        />
      )}

      {configTab === 'pingora' && (
        <div className="space-y-6">
          {isLoading ? (
            <ConfigPanelSkeleton />
          ) : pingoraError ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(pingoraError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchPingora()}
                disabled={isPingoraFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isPingoraFetching ? 'animate-spin' : ''}`} />
                {isPingoraFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : (
            <>
              {isTunnelActive ? (
                <ServiceControls onAction={handlePingoraAction} />
              ) : (
                renderTunnelInactive('Pingora controls')
              )}

              <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
                <WafConfig config={wafConfig} onChange={setWafConfig} />
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="card border border-border-subtle border-t-2 border-t-info p-6">
                  <RateLimitConfig config={rateLimitConfig} onChange={setRateLimitConfig} />
                </div>

                <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
                  <AccessControlConfig config={aclConfig} onChange={setAccessConfig} />
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {configTab === 'general' && (
        <div className="space-y-4">
          {!isTunnelActive ? (
            renderTunnelInactive('System configuration')
          ) : isSystemConfigLoading ? (
            <ConfigPanelSkeleton />
          ) : systemConfigError ? (
            <div className="flex flex-col items-center justify-center py-12 gap-4">
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(systemConfigError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchSystemConfig()}
                disabled={isSystemConfigFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isSystemConfigFetching ? 'animate-spin' : ''}`} />
                {isSystemConfigFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6">
                <h3 className="text-lg font-semibold text-ink-primary mb-4">General Settings</h3>
                <div className="space-y-4">
                  {Object.entries(generalSettings).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                      {typeof value === 'boolean' ? (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={value}
                          aria-label={key.replace(/([A-Z])/g, ' $1').trim()}
                          className={`w-10 h-6 border border-border-subtle ${value ? 'bg-status-success' : 'bg-surface-subtle'} relative cursor-pointer`}
                        >
                          <span className={`block w-4 h-4 bg-white absolute top-1 transition-all ${value ? 'right-1' : 'left-1'}`} />
                        </button>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{String(value)}</span>
                      )}
                    </div>
                  ))}
                  {Object.keys(generalSettings).length === 0 && (
                    <div className="text-sm text-ink-secondary">No general settings available.</div>
                  )}
                </div>
              </div>

              <div className="card border border-border-subtle border-t-2 border-t-info p-6">
                <h3 className="text-lg font-semibold text-ink-primary mb-4">Runtime Settings</h3>
                <div className="space-y-4">
                  {runtimeEntries.map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-sm text-ink-secondary capitalize">{key.replace(/([A-Z])/g, ' $1')}</span>
                      {typeof value === 'boolean' ? (
                        <button
                          type="button"
                          role="switch"
                          aria-checked={value}
                          aria-label={key.replace(/([A-Z])/g, ' $1').trim()}
                          className={`w-10 h-6 border border-border-subtle ${value ? 'bg-status-success' : 'bg-surface-subtle'} relative cursor-pointer`}
                        >
                          <span className={`block w-4 h-4 bg-white absolute top-1 transition-all ${value ? 'right-1' : 'left-1'}`} />
                        </button>
                      ) : (
                        <span className="text-sm font-mono text-ink-primary">{String(value)}</span>
                      )}
                    </div>
                  ))}
                  {runtimeEntries.length === 0 && (
                    <div className="text-sm text-ink-secondary">No runtime settings available.</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {configTab === 'kernel' && (
        !isTunnelActive ? (
          renderTunnelInactive('Kernel parameters')
        ) : (
          <div className="card border border-border-subtle border-t-2 border-t-ac-blue p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-ink-primary">Kernel Parameters (sysctl)</h3>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-xs text-ink-secondary">
                  <input
                    type="checkbox"
                    checked={persistKernel}
                    onChange={(event) => setPersistKernel(event.target.checked)}
                  />
                  Persist changes
                </label>
                <button
                  className="px-3 py-1.5 text-xs border border-border-subtle text-ink-secondary hover:bg-surface-subtle focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                  onClick={() => refetchKernel()}
                  disabled={isKernelFetching}
                >
                  Refresh
                </button>
                <button
                  className="px-3 py-1.5 text-xs bg-accent-primary text-white disabled:opacity-60 focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
                  onClick={() => updateKernelMutation.mutate(kernelDraft)}
                  disabled={updateKernelMutation.isPending || isKernelLoading}
                >
                  Save Changes
                </button>
              </div>
            </div>
            {kernelError && (
              <div className="text-sm text-ink-primary border-l-2 border-l-ac-red pl-2">Failed to load kernel config.</div>
            )}
            <table className="w-full text-sm">
              <caption className="sr-only">Kernel parameters and their current values</caption>
              <thead className="bg-surface-inset text-ink-secondary border-b border-ac-blue/20">
                <tr className="text-left">
                  <th className="pb-2">Parameter</th>
                  <th className="pb-2">Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(kernelDraft).map(([key, value]) => (
                  <tr key={key} className="border-t border-border-subtle">
                    <td className="py-3 font-mono text-ink-secondary">{key}</td>
                    <td className="py-3">
                      <input
                        className="w-full border border-border-subtle bg-surface-subtle px-2 py-1 text-sm font-mono text-ink-primary"
                        value={value ?? ''}
                        aria-label={`Value for ${key}`}
                        onChange={(event) =>
                          setKernelDraft((current) => ({ ...current, [key]: event.target.value }))
                        }
                      />
                    </td>
                  </tr>
                ))}
                {Object.keys(kernelDraft).length === 0 && !isKernelLoading && (
                  <tr>
                    <td className="py-4 text-sm text-ink-secondary" colSpan={2}>
                      No kernel parameters available.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )
      )}

      {configTab === 'history' && (
        <div className="card border border-border-subtle border-t-2 border-t-ac-navy p-6">
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Recent Configuration Changes</h3>
          {isHistoryLoading ? (
            <ConfigPanelSkeleton />
          ) : historyError ? (
            <div className="flex flex-col items-center justify-center py-8 gap-3">
              <div className="flex items-center gap-2 text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(historyError as Error).message}</span>
              </div>
              <button
                onClick={() => refetchHistory()}
                disabled={isHistoryFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em] flex items-center gap-2"
              >
                <RefreshCw className={`w-4 h-4 ${isHistoryFetching ? 'animate-spin' : ''}`} />
                {isHistoryFetching ? 'Retrying...' : 'Retry'}
              </button>
            </div>
          ) : configHistoryEntries.length === 0 ? (
            <div className="text-sm text-ink-secondary">No configuration changes recorded yet.</div>
          ) : (
            <div className="space-y-4">
              {configHistoryEntries.map((entry: any) => (
                <div key={entry.id} className="flex items-center justify-between p-3 bg-surface-subtle">
                  <div>
                    <div className="text-sm font-medium text-ink-primary">{entry.change}</div>
                    <div className="text-xs text-ink-secondary">{entry.date} • {entry.status}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
