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
  AdvancedConfigPanel,
  defaultAdvancedConfig,
  type AdvancedConfigData,
} from '../../../components/fleet/pingora/AdvancedConfigPanel';
import {
  fetchKernelConfig,
  updateKernelConfig,
  fetchSystemConfig,
  fetchCommandHistory,
  fetchPingoraConfig,
  updatePingoraConfig,
  runPingoraAction,
} from './shared';
import { Panel, Spinner, Stack, Tabs, colors } from '@/ui';

interface ConfigurationTabProps {
  sensor: any;
}

type ConfigTab = 'general' | 'kernel' | 'pingora' | 'drift' | 'history';

const CONFIG_TABS: { key: ConfigTab; label: string }[] = [
  { key: 'general', label: 'General' },
  { key: 'kernel', label: 'Kernel' },
  { key: 'pingora', label: 'Synapse-Pingora' },
  { key: 'drift', label: 'Drift Analysis' },
  { key: 'history', label: 'History' },
];

const isConfigTab = (key: string): key is ConfigTab =>
  CONFIG_TABS.some((tab) => tab.key === key);

export function ConfigurationTab({ sensor }: ConfigurationTabProps) {
  const id = sensor.id;
  const isTunnelActive = Boolean(sensor?.tunnelActive);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [configTab, setConfigTab] = useState<ConfigTab>('general');

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
  // Advanced Pingora config: DLP / Block Page / Crawler / Tarpit /
  // Entity / Travel. These components live under components/fleet/pingora/
  // and used to be dead code — `AdvancedConfigPanel` ties them together
  // in a sub-tabbed editor. Initial state is the module's published
  // defaults; the useEffect below hydrates from remotePingoraConfig.advanced
  // when the sensor returns it.
  const [advancedConfig, setAdvancedConfig] =
    useState<AdvancedConfigData>(defaultAdvancedConfig);
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
      // Hydrate advanced config from remote if present. Falls back to
      // the module defaults if the API hasn't stored this block yet —
      // keeps the UI editable even when the backend round-trip for
      // advanced config isn't plumbed through.
      if (remotePingoraConfig.advanced) {
        setAdvancedConfig({
          ...defaultAdvancedConfig,
          ...remotePingoraConfig.advanced,
        });
      }
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
      advanced: advancedConfig,
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
    <Panel tone="warning" padding="md">
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
    </Panel>
  );
  return (
    <div className="space-y-6">
      {/* Config Tabs — ARIA tab pattern */}
      <Panel tone="info" padding="none" spacing="none">
        <Stack
          direction="row"
          align="center"
          justify="space-between"
          gap="md"
          className="p-4 bg-surface-inset"
        >
          <div className="min-w-0 flex-1">
            <Tabs
              tabs={CONFIG_TABS}
              active={configTab}
              onChange={(key) => {
                if (isConfigTab(key)) setConfigTab(key);
              }}
              size="sm"
              ariaLabel="Configuration sections"
              idPrefix="tab-config-"
              panelIdPrefix="tabpanel-config-"
            />
          </div>

          <div className="flex gap-3">
          <button
            onClick={() => navigate(`/fleet/sensors/${id}/config`)}
            className="btn-secondary h-10 px-4 text-xs uppercase tracking-[0.2em]"
          >
            <Stack as="span" direction="row" inline align="center" gap="sm">
              <Settings className="w-4 h-4" />
              Advanced JSON Editor
            </Stack>
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
        </Stack>
      </Panel>

      {configTab === 'drift' && (
        <div id="tabpanel-config-drift">
          <ConfigDriftViewer
            expectedConfig={driftData.expected}
            actualConfig={driftData.actual}
            lastSync="Just now"
            driftDetected={false}
          />
        </div>
      )}

      {configTab === 'pingora' && (
        <div id="tabpanel-config-pingora" className="space-y-6">
          {isLoading ? (
            <ConfigPanelSkeleton />
          ) : pingoraError ? (
            <Stack direction="column" align="center" justify="center" gap="md" className="py-12">
              <Stack direction="row" align="center" gap="sm" className="text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(pingoraError as Error).message}</span>
              </Stack>
              <button
                onClick={() => refetchPingora()}
                disabled={isPingoraFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]"
              >
                <Stack as="span" direction="row" inline align="center" gap="sm">
                  {isPingoraFetching ? (
                    <Spinner size={16} color={colors.white} />
                  ) : (
                    <RefreshCw className="w-4 h-4" />
                  )}
                  {isPingoraFetching ? 'Retrying...' : 'Retry'}
                </Stack>
              </button>
            </Stack>
          ) : (
            <>
              {isTunnelActive ? (
                <ServiceControls onAction={handlePingoraAction} />
              ) : (
                renderTunnelInactive('Pingora controls')
              )}

              <Panel tone="info" padding="md">
                <WafConfig config={wafConfig} onChange={setWafConfig} />
              </Panel>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Panel tone="info" padding="md">
                  <RateLimitConfig config={rateLimitConfig} onChange={setRateLimitConfig} />
                </Panel>

                <Panel tone="info" padding="md">
                  <AccessControlConfig config={aclConfig} onChange={setAccessConfig} />
                </Panel>
              </div>

              {/* Advanced config — surfaces DLP / Block Page / Crawler /
                  Tarpit / Entity & Travel editors that were built but
                  previously unwired. AdvancedConfigPanel owns the
                  sub-tab navigation; we provide state + persistence.
                  Uses padding="none" so the panel's own sidebar layout
                  can extend edge-to-edge. min-height keeps the left
                  sidebar navigation readable when one tab has less
                  content than the others. */}
              <Panel tone="info" padding="none" spacing="none" style={{ minHeight: 520 }}>
                <AdvancedConfigPanel
                  config={advancedConfig}
                  onChange={setAdvancedConfig}
                />
              </Panel>
            </>
          )}
        </div>
      )}

      {configTab === 'general' && (
        <div id="tabpanel-config-general" className="space-y-4">
          {!isTunnelActive ? (
            renderTunnelInactive('System configuration')
          ) : isSystemConfigLoading ? (
            <ConfigPanelSkeleton />
          ) : systemConfigError ? (
            <Stack direction="column" align="center" justify="center" gap="md" className="py-12">
              <Stack direction="row" align="center" gap="sm" className="text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(systemConfigError as Error).message}</span>
              </Stack>
              <button
                onClick={() => refetchSystemConfig()}
                disabled={isSystemConfigFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]"
              >
                <Stack as="span" direction="row" inline align="center" gap="sm">
                  {isSystemConfigFetching ? (
                    <Spinner size={16} color={colors.white} />
                  ) : (
                    <RefreshCw className="w-4 h-4" />
                  )}
                  {isSystemConfigFetching ? 'Retrying...' : 'Retry'}
                </Stack>
              </button>
            </Stack>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Panel tone="info" padding="md">
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
              </Panel>

              <Panel tone="info" padding="md">
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
              </Panel>
            </div>
          )}
        </div>
      )}

      {configTab === 'kernel' && (
        <div id="tabpanel-config-kernel">
          {!isTunnelActive ? (
            renderTunnelInactive('Kernel parameters')
          ) : (
            <Panel tone="info" padding="md" className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-ink-primary">Kernel Parameters (sysctl)</h3>
                <Stack direction="row" align="center" gap="smPlus">
                  <Stack as="label" direction="row" align="center" gap="sm" className="text-xs text-ink-secondary">
                    <input
                      type="checkbox"
                      checked={persistKernel}
                      onChange={(event) => setPersistKernel(event.target.checked)}
                    />
                    Persist changes
                  </Stack>
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
                </Stack>
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
            </Panel>
          )}
        </div>
      )}

      {configTab === 'history' && (
        <Panel
          tone="info"
          padding="md"
          as="div"
          id="tabpanel-config-history"
        >
          <h3 className="text-lg font-semibold text-ink-primary mb-4">Recent Configuration Changes</h3>
          {isHistoryLoading ? (
            <ConfigPanelSkeleton />
          ) : historyError ? (
            <Stack direction="column" align="center" justify="center" gap="sm" className="py-8">
              <Stack direction="row" align="center" gap="sm" className="text-ink-primary">
                <AlertCircle className="w-5 h-5 text-status-error" />
                <span>Error: {(historyError as Error).message}</span>
              </Stack>
              <button
                onClick={() => refetchHistory()}
                disabled={isHistoryFetching}
                className="btn-primary h-10 px-4 text-xs uppercase tracking-[0.2em]"
              >
                <Stack as="span" direction="row" inline align="center" gap="sm">
                  {isHistoryFetching ? (
                    <Spinner size={16} color={colors.white} />
                  ) : (
                    <RefreshCw className="w-4 h-4" />
                  )}
                  {isHistoryFetching ? 'Retrying...' : 'Retry'}
                </Stack>
              </button>
            </Stack>
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
        </Panel>
      )}
    </div>
  );
}
