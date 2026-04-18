import { useEffect, useId, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  EmptyState,
  Input,
  Select,
  Spinner,
  Stack,
  Tabs,
  Text,
  colors,
  spacing,
} from '@atlascrew/signal-ui';

type ApiEnvelope<T> = {
  success: boolean;
  data?: T;
  error?: string;
};

type ApiReadResult<T> = {
  data: T;
  etag: string | null;
};

type HealthResponse = {
  status?: string;
  healthy?: boolean;
  [key: string]: unknown;
};

type StatusResponse = {
  running?: boolean;
  mode?: string;
  active_connections?: number;
  blocked_requests?: number;
  requests_seen?: number;
  [key: string]: unknown;
};

type SensorSiteInfo = {
  hostname?: string;
  upstreams?: string[];
  tls_enabled?: boolean;
  waf_enabled?: boolean;
  [key: string]: unknown;
};

type SensorConfigResponse = {
  success?: boolean;
  data?: {
    sites?: SensorSiteInfo[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

type TrapConfig = {
  enabled?: boolean;
  paths?: string[];
  apply_max_risk?: boolean;
  extended_tarpit_ms?: number | null;
  alert_telemetry?: boolean;
  [key: string]: unknown;
};

type GlobalConfig = {
  http_addr?: string;
  https_addr?: string;
  workers?: number;
  shutdown_timeout_secs?: number;
  waf_threshold?: number;
  waf_enabled?: boolean;
  log_level?: string;
  admin_api_key?: string | null;
  trap_config?: TrapConfig | null;
  waf_regex_timeout_ms?: number;
  [key: string]: unknown;
};

type SiteConfig = {
  hostname?: string;
  upstreams?: Array<{ host?: string; port?: number; [key: string]: unknown }>;
  waf?: {
    enabled?: boolean;
    rule_overrides?: Record<string, string>;
    [key: string]: unknown;
  };
  headers?: Record<string, unknown>;
  shadow_mirror?: unknown;
  tls?: unknown;
  [key: string]: unknown;
};

type ConfigFile = {
  server: GlobalConfig;
  sites: SiteConfig[];
  rate_limit: Record<string, unknown>;
  profiler: Record<string, unknown>;
  [key: string]: unknown;
};

type MutationResult = {
  applied: boolean;
  persisted: boolean;
  rebuild_required: boolean;
  warnings?: string[];
  [key: string]: unknown;
};

type ServerFormState = {
  http_addr: string;
  https_addr: string;
  workers: string;
  shutdown_timeout_secs: string;
  waf_threshold: string;
  waf_enabled: boolean;
  log_level: string;
  admin_api_key: string;
  replace_admin_api_key: boolean;
  clear_admin_api_key: boolean;
  waf_regex_timeout_ms: string;
  trap_present: boolean;
  trap_enabled: boolean;
  trap_paths: string;
  trap_apply_max_risk: boolean;
  trap_extended_tarpit_ms: string;
  trap_alert_telemetry: boolean;
};

type SaveState =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'success'; message: string; sticky?: boolean }
  | { kind: 'error'; message: string };

type LoadState =
  | { kind: 'loading' }
  | {
      kind: 'ready';
      health?: HealthResponse;
      status?: StatusResponse;
      fullConfig?: ConfigFile;
      configEtag?: string | null;
      sensorConfig?: SensorConfigResponse;
      loadedAt: string;
      warnings: string[];
    };

const tabs = [
  { key: 'overview', label: 'Overview' },
  { key: 'server', label: 'Server' },
  { key: 'sites', label: 'Sites' },
  { key: 'roadmap', label: 'Roadmap' },
] as const;

const logLevelOptions = [
  { value: 'trace', label: 'trace' },
  { value: 'debug', label: 'debug' },
  { value: 'info', label: 'info' },
  { value: 'warn', label: 'warn' },
  { value: 'error', label: 'error' },
];

const defaultTrapPaths = [
  '/.git/*',
  '/.env',
  '/.env.*',
  '/admin/backup*',
  '/wp-admin/*',
  '/phpmyadmin/*',
  '/.svn/*',
  '/.htaccess',
  '/web.config',
  '/config.php',
];

type TabKey = (typeof tabs)[number]['key'];

function extractMessage(data: unknown, fallback: string): string {
  if (typeof data === 'string') return data;
  if (data && typeof data === 'object') {
    if ('error' in data && typeof data.error === 'string') return data.error;
    if ('message' in data && typeof data.message === 'string') return data.message;
    if ('detail' in data && typeof data.detail === 'string') return data.detail;
  }
  return fallback;
}

async function requestJsonWithMeta<T>(
  path: string,
  init?: RequestInit,
): Promise<{ data: T; headers: Headers }> {
  const response = await fetch(path, init);
  const contentType = response.headers.get('content-type') ?? '';
  const text = await response.text();
  let data: unknown = text;

  if (contentType.includes('json')) {
    try {
      data = JSON.parse(text);
    } catch (error) {
      throw new Error(
        response.ok
          ? `Received malformed JSON from ${path}: ${error instanceof Error ? error.message : 'parse failure'}`
          : text,
      );
    }
  }

  if (!response.ok) {
    const fallbackMessage =
      response.status === 401
        ? 'Authentication expired or missing. Re-authenticate and retry.'
        : response.status === 403
          ? 'This session does not have permission for that action.'
          : `Request to ${path} failed with status ${response.status}.`;
    throw new Error(extractMessage(data, fallbackMessage));
  }

  return { data: data as T, headers: response.headers };
}

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const result = await requestJsonWithMeta<T>(path, init);
  return result.data;
}

async function readApiWithMeta<T>(path: string): Promise<ApiReadResult<T>> {
  const { data: envelope, headers } = await requestJsonWithMeta<ApiEnvelope<T>>(path);
  if (!envelope.success || envelope.data === undefined) {
    throw new Error(envelope.error ?? `Request to ${path} did not return data.`);
  }
  return {
    data: envelope.data,
    etag: headers.get('etag'),
  };
}

async function writeApi<T>(
  path: string,
  method: 'POST' | 'PUT',
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Promise<T> {
  const envelope = await requestJson<ApiEnvelope<T>>(path, {
    method,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });

  if (!envelope.success || envelope.data === undefined) {
    throw new Error(envelope.error ?? `${method} ${path} failed.`);
  }

  return envelope.data;
}

function formatBoolean(value: boolean | undefined): string {
  if (value === true) return 'Enabled';
  if (value === false) return 'Disabled';
  return 'Unknown';
}

function formatUpstreams(upstreams: SiteConfig['upstreams'] | undefined): string {
  if (!upstreams || upstreams.length === 0) {
    return 'Not configured';
  }

  return upstreams
    .map((upstream) => {
      if (!upstream.host) return 'Unknown upstream';
      return upstream.port ? `${upstream.host}:${upstream.port}` : upstream.host;
    })
    .join(', ');
}

function buildServerForm(server?: GlobalConfig): ServerFormState {
  const trap = server?.trap_config ?? null;

  return {
    http_addr: server?.http_addr ?? '0.0.0.0:80',
    https_addr: server?.https_addr ?? '0.0.0.0:443',
    workers: String(server?.workers ?? 0),
    shutdown_timeout_secs: String(server?.shutdown_timeout_secs ?? 30),
    waf_threshold: String(server?.waf_threshold ?? 70),
    waf_enabled: server?.waf_enabled ?? true,
    log_level: server?.log_level ?? 'info',
    admin_api_key: '',
    replace_admin_api_key: false,
    clear_admin_api_key: false,
    waf_regex_timeout_ms: String(server?.waf_regex_timeout_ms ?? 100),
    trap_present: trap !== null,
    trap_enabled: trap?.enabled ?? true,
    trap_paths: (trap?.paths ?? defaultTrapPaths).join('\n'),
    trap_apply_max_risk: trap?.apply_max_risk ?? true,
    trap_extended_tarpit_ms:
      trap?.extended_tarpit_ms === null || trap?.extended_tarpit_ms === undefined
        ? ''
        : String(trap.extended_tarpit_ms),
    trap_alert_telemetry: trap?.alert_telemetry ?? true,
  };
}

function parseIntegerField(
  value: string,
  label: string,
  options: { min?: number; max?: number } = {},
): number {
  const normalized = value.trim();
  if (normalized === '') {
    throw new Error(`${label} is required.`);
  }
  if (!/^-?\d+$/.test(normalized)) {
    throw new Error(`${label} must be a whole number.`);
  }
  const parsed = Number(normalized);
  if (options.min !== undefined && parsed < options.min) {
    throw new Error(`${label} must be at least ${options.min}.`);
  }
  if (options.max !== undefined && parsed > options.max) {
    throw new Error(`${label} must be at most ${options.max}.`);
  }
  return parsed;
}

function MetricTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string;
}) {
  return (
    <Box
      bg="card"
      p="lg"
      border="top"
      borderColor={tone ?? colors.border.strong}
      style={{ minWidth: 0 }}
    >
      <Stack gap="xs">
        <Text variant="label" color={colors.textSecondary}>
          {label}
        </Text>
        <Text variant="metric" color={colors.text}>
          {value}
        </Text>
      </Stack>
    </Box>
  );
}

function PropertyList({
  entries,
}: {
  entries: Array<{ label: string; value: string }>;
}) {
  return (
    <Stack gap="sm">
      {entries.map((entry) => (
        <Box
          key={entry.label}
          bg="card"
          p="md"
          border="subtle"
          style={{
            display: 'grid',
            gridTemplateColumns: 'minmax(120px, 180px) 1fr',
            gap: spacing.md,
          }}
        >
          <Text variant="label" color={colors.textSecondary}>
            {entry.label}
          </Text>
          <Text variant="data">{entry.value}</Text>
        </Box>
      ))}
    </Stack>
  );
}

function ToggleField({
  label,
  helper,
  checked,
  onChange,
}: {
  label: string;
  helper?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  const inputId = useId();
  const helperId = helper ? `${inputId}-help` : undefined;
  return (
    <div className="console-next-toggle">
      <input
        id={inputId}
        type="checkbox"
        checked={checked}
        aria-describedby={helperId}
        onChange={(event) => onChange(event.currentTarget.checked)}
      />
      <div>
        <label htmlFor={inputId}>
          <Text variant="label">{label}</Text>
        </label>
        {helper ? (
          <span id={helperId}>
            <Text variant="body" color={colors.textSecondary}>
              {helper}
            </Text>
          </span>
        ) : null}
      </div>
    </div>
  );
}

export function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [state, setState] = useState<LoadState>({ kind: 'loading' });
  const [saveState, setSaveState] = useState<SaveState>({ kind: 'idle' });
  const [serverForm, setServerForm] = useState<ServerFormState>(() => buildServerForm());

  async function load() {
    setState({ kind: 'loading' });

    const results = await Promise.allSettled([
      requestJson<HealthResponse>('/health'),
      requestJson<StatusResponse>('/_sensor/status'),
      readApiWithMeta<ConfigFile>('/config'),
      requestJson<SensorConfigResponse>('/_sensor/config'),
    ]);

    const labels = ['Health', 'Status', 'Full config', 'Sensor config'] as const;
    const warnings = results.flatMap((result, index) => {
      if (result.status === 'fulfilled') return [];
      const message =
        result.reason instanceof Error ? result.reason.message : 'Request failed.';
      return [`${labels[index]} failed: ${message}`];
    });

    const health = results[0].status === 'fulfilled' ? results[0].value : undefined;
    const status = results[1].status === 'fulfilled' ? results[1].value : undefined;
    const fullConfigResult = results[2].status === 'fulfilled' ? results[2].value : undefined;
    const fullConfig = fullConfigResult?.data;
    const configEtag = fullConfigResult?.etag ?? null;
    const sensorConfig = results[3].status === 'fulfilled' ? results[3].value : undefined;

    if (fullConfig) {
      setServerForm(buildServerForm(fullConfig.server));
    }

    setState({
      kind: 'ready',
      health,
      status,
      fullConfig,
      configEtag,
      sensorConfig,
      loadedAt: new Date().toLocaleString(),
      warnings,
    });
  }

  useEffect(() => {
    void load();
  }, []);

  useEffect(() => {
    if (saveState.kind !== 'success' || saveState.sticky === true) {
      return;
    }

    const timeoutId = window.setTimeout(() => {
      setSaveState({ kind: 'idle' });
    }, 8000);

    return () => window.clearTimeout(timeoutId);
  }, [saveState]);

  const overview = useMemo(() => {
    if (state.kind !== 'ready') return null;

    const siteCount =
      state.fullConfig?.sites.length ?? state.sensorConfig?.data?.sites?.length ?? 0;
    const blocked = state.status?.blocked_requests ?? 0;
    const mode = state.status?.mode ?? state.health?.status ?? 'unknown';
    const workers = state.fullConfig?.server?.workers ?? 0;

    return { siteCount, blocked, mode, workers };
  }, [state]);

  function updateServerForm<K extends keyof ServerFormState>(
    key: K,
    value: ServerFormState[K],
  ) {
    setServerForm((current) => ({ ...current, [key]: value }));
  }

  async function saveServerConfig() {
    if (saveState.kind === 'saving') {
      return;
    }

    if (state.kind !== 'ready' || !state.fullConfig) {
      setSaveState({
        kind: 'error',
        message:
          'Full config is unavailable. This editor needs both config:write and admin:write scope.',
      });
      return;
    }

    setSaveState({ kind: 'saving' });

    try {
      if (!state.configEtag) {
        throw new Error('Config version is unavailable. Refresh the page and try again.');
      }

      if (serverForm.replace_admin_api_key && serverForm.admin_api_key.trim() === '') {
        throw new Error('Admin API key is required when replacement is enabled.');
      }

      const trapPaths = serverForm.trap_paths
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);

      if (serverForm.trap_present && trapPaths.length === 0) {
        throw new Error('Trap paths cannot be empty when trap configuration is enabled.');
      }

      const { admin_api_key: _currentAdminApiKey, ...serverWithoutAdminApiKey } =
        state.fullConfig.server;
      const nextServer: GlobalConfig = {
        ...serverWithoutAdminApiKey,
        http_addr: serverForm.http_addr.trim(),
        https_addr: serverForm.https_addr.trim(),
        workers: parseIntegerField(serverForm.workers, 'Workers', { min: 0 }),
        shutdown_timeout_secs: parseIntegerField(
          serverForm.shutdown_timeout_secs,
          'Shutdown timeout',
          { min: 1 },
        ),
        waf_threshold: parseIntegerField(serverForm.waf_threshold, 'WAF threshold', {
          min: 0,
          max: 100,
        }),
        waf_enabled: serverForm.waf_enabled,
        log_level: serverForm.log_level,
        waf_regex_timeout_ms: parseIntegerField(
          serverForm.waf_regex_timeout_ms,
          'WAF regex timeout',
          { min: 1, max: 500 },
        ),
        trap_config: serverForm.trap_present
          ? {
              enabled: serverForm.trap_enabled,
              paths: trapPaths,
              apply_max_risk: serverForm.trap_apply_max_risk,
              extended_tarpit_ms: serverForm.trap_extended_tarpit_ms.trim()
                ? parseIntegerField(
                    serverForm.trap_extended_tarpit_ms,
                    'Extended tarpit delay',
                    { min: 0 },
                  )
                : null,
              alert_telemetry: serverForm.trap_alert_telemetry,
            }
          : null,
      };

      if (serverForm.clear_admin_api_key) {
        nextServer.admin_api_key = null;
      } else if (serverForm.replace_admin_api_key) {
        nextServer.admin_api_key = serverForm.admin_api_key.trim();
      } else {
        // The admin server preserves the stored key when this field is omitted from POST /config.
        // That contract is covered by test_config_post_preserves_existing_admin_key_when_omitted.
      }

      const nextConfig: ConfigFile = {
        ...state.fullConfig,
        server: {
          ...nextServer,
        },
      };

      const mutation = await writeApi<MutationResult>('/config', 'POST', nextConfig, {
        'If-Match': state.configEtag,
        ...(serverForm.clear_admin_api_key ? { 'X-Clear-Admin-Api-Key': 'true' } : {}),
      });
      await load();

      const warningSuffix =
        mutation.warnings && mutation.warnings.length > 0
          ? ` Warnings: ${mutation.warnings.join(' ')}`
          : '';

      setSaveState({
        kind: 'success',
        message:
          `Server config saved. Applied=${String(mutation.applied)} persisted=${String(
            mutation.persisted,
          )} rebuild_required=${String(mutation.rebuild_required)}.` + warningSuffix,
        sticky: mutation.rebuild_required === true || Boolean(mutation.warnings?.length),
      });
    } catch (error) {
      setSaveState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Failed to save server config.',
      });
    }
  }

  const fullConfigSites = state.kind === 'ready' ? state.fullConfig?.sites ?? [] : [];
  const sensorFallbackSites =
    state.kind === 'ready' && !state.fullConfig ? state.sensorConfig?.data?.sites ?? [] : [];

  return (
    <main className="console-next-shell">
      <header className="console-next-header">
        <div className="console-next-brand">
          <img src="/console-next/assets/sidebar-lockup.svg" alt="Synapse Fleet" />
          <div>
            <Text variant="subhead" color={colors.textSecondary}>
              Console Next
            </Text>
            <Text as="h1" variant="heading">
              Synapse Operator UI
            </Text>
          </div>
        </div>
        <div className="console-next-actions">
          <a className="console-next-link" href="/console">
            Open legacy console
          </a>
          <Button
            variant="outlined"
            onClick={() => {
              setSaveState({ kind: 'idle' });
              void load();
            }}
          >
            Refresh
          </Button>
        </div>
      </header>

      <Alert status="info" title="Operator surface is live">
        Server configuration editing now runs through the real full-config API. Sites remain
        read-only in this slice while we stand up CRUD and per-site editors next.
      </Alert>

      <div className="console-next-tabs">
        <Tabs
          tabs={tabs.map((tab) => ({ key: tab.key, label: tab.label }))}
          active={activeTab}
          onChange={(key) => setActiveTab(key as TabKey)}
          ariaLabel="Console Next sections"
          idPrefix="tab-"
          panelIdPrefix="panel-"
        />
      </div>

      {state.kind === 'loading' ? (
        <div className="console-next-center">
          <Spinner size={28} />
          <Text variant="body" muted>
            Loading current sensor state…
          </Text>
        </div>
      ) : null}

      {state.kind === 'ready' && state.warnings.length > 0 ? (
        <Alert status="warning" title="Partial data available">
          {state.warnings.join(' ')}
        </Alert>
      ) : null}

      {state.kind === 'ready' && activeTab === 'overview' ? (
        <section role="tabpanel" id="panel-overview" aria-labelledby="tab-overview">
          <Stack gap="lg">
            <div className="console-next-grid">
              <MetricTile
                label="Mode"
                value={overview?.mode ?? 'unknown'}
                tone={colors.blue}
              />
              <MetricTile
                label="Sites"
                value={String(overview?.siteCount ?? 0)}
                tone={colors.green}
              />
              <MetricTile
                label="Workers"
                value={String(overview?.workers ?? 0)}
                tone={colors.magenta}
              />
              <MetricTile
                label="Blocked Requests"
                value={String(overview?.blocked ?? 0)}
                tone={colors.orange}
              />
            </div>
            <PropertyList
              entries={[
                {
                  label: 'Health',
                  value: String(state.health?.status ?? formatBoolean(state.health?.healthy)),
                },
                {
                  label: 'HTTP Bind',
                  value: state.fullConfig?.server?.http_addr ?? 'Unavailable',
                },
                {
                  label: 'HTTPS Bind',
                  value: state.fullConfig?.server?.https_addr ?? 'Unavailable',
                },
                {
                  label: 'Last Loaded',
                  value: state.loadedAt,
                },
              ]}
            />
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'server' ? (
        <section role="tabpanel" id="panel-server" aria-labelledby="tab-server">
          <Stack gap="lg">
            <Box bg="card" p="lg" border="top" borderColor={colors.skyBlue}>
              <Stack gap="sm">
                <Text variant="heading">Server configuration</Text>
                <Text variant="body" color={colors.textSecondary}>
                  This editor reads from `GET /config` and writes via `POST /config`, preserving
                  sites, profiler, and rate-limit blocks while only updating `server.*`.
                </Text>
              </Stack>
            </Box>

            {saveState.kind === 'success' ? (
              <Alert status="success" title="Saved">
                {saveState.message}
              </Alert>
            ) : null}

            {saveState.kind === 'error' ? (
              <Alert status="error" title="Save failed">
                {saveState.message}
              </Alert>
            ) : null}

            {!state.fullConfig ? (
              <Alert status="warning" title="Full config unavailable">
                This tab needs `config:write` to load `GET /config` and `admin:write` to save
                `POST /config`. The current session only has read-only dashboard data.
              </Alert>
            ) : (
              <form
                className="console-next-form"
                onSubmit={(event) => {
                  event.preventDefault();
                  void saveServerConfig();
                }}
              >
                <Stack gap="lg">
                  <div className="console-next-form-grid">
                    <Input
                      fill
                      label="HTTP bind"
                      value={serverForm.http_addr}
                      onChange={(event) => updateServerForm('http_addr', event.currentTarget.value)}
                      helper="Example: 0.0.0.0:80"
                    />
                    <Input
                      fill
                      label="HTTPS bind"
                      value={serverForm.https_addr}
                      onChange={(event) => updateServerForm('https_addr', event.currentTarget.value)}
                      helper="Example: 0.0.0.0:443"
                    />
                    <Input
                      fill
                      label="Workers"
                      type="number"
                      value={serverForm.workers}
                      onChange={(event) => updateServerForm('workers', event.currentTarget.value)}
                      helper="0 means auto-detect"
                    />
                    <Input
                      fill
                      label="Shutdown timeout (seconds)"
                      type="number"
                      value={serverForm.shutdown_timeout_secs}
                      onChange={(event) =>
                        updateServerForm('shutdown_timeout_secs', event.currentTarget.value)
                      }
                    />
                    <Input
                      fill
                      label="WAF threshold"
                      type="number"
                      value={serverForm.waf_threshold}
                      onChange={(event) =>
                        updateServerForm('waf_threshold', event.currentTarget.value)
                      }
                      helper="Backend validates the final range"
                    />
                    <Input
                      fill
                      label="WAF regex timeout (ms)"
                      type="number"
                      value={serverForm.waf_regex_timeout_ms}
                      onChange={(event) =>
                        updateServerForm('waf_regex_timeout_ms', event.currentTarget.value)
                      }
                    />
                    <Select
                      fill
                      label="Log level"
                      options={logLevelOptions}
                      value={serverForm.log_level}
                      onChange={(event) => updateServerForm('log_level', event.currentTarget.value)}
                    />
                    <Input
                      fill
                      label="Admin API key"
                      type="password"
                      value={serverForm.admin_api_key}
                      disabled={!serverForm.replace_admin_api_key || serverForm.clear_admin_api_key}
                      onChange={(event) =>
                        updateServerForm('admin_api_key', event.currentTarget.value)
                      }
                      helper="The current key is never returned to the browser. Enable replacement to set a new one."
                    />
                  </div>

                  <div className="console-next-toggle-grid">
                    <ToggleField
                      label="WAF enabled"
                      helper="Master enable for global WAF enforcement."
                      checked={serverForm.waf_enabled}
                      onChange={(checked) => updateServerForm('waf_enabled', checked)}
                    />
                    <ToggleField
                      label="Trap configuration present"
                      helper="Remove the trap block entirely when unchecked."
                      checked={serverForm.trap_present}
                      onChange={(checked) => {
                        updateServerForm('trap_present', checked);
                        if (checked && serverForm.trap_paths.trim() === '') {
                          updateServerForm('trap_paths', defaultTrapPaths.join('\n'));
                        }
                      }}
                    />
                    <ToggleField
                      label="Replace admin API key"
                      helper="Only when checked will a newly typed key be submitted."
                      checked={serverForm.replace_admin_api_key}
                      onChange={(checked) => {
                        updateServerForm('replace_admin_api_key', checked);
                        if (!checked) {
                          updateServerForm('admin_api_key', '');
                        }
                      }}
                    />
                    <ToggleField
                      label="Clear stored admin API key"
                      helper="Use this only if you want startup-generated rotation instead of preserving the existing key."
                      checked={serverForm.clear_admin_api_key}
                      onChange={(checked) => {
                        updateServerForm('clear_admin_api_key', checked);
                        if (checked) {
                          updateServerForm('replace_admin_api_key', false);
                          updateServerForm('admin_api_key', '');
                        }
                      }}
                    />
                  </div>

                  {serverForm.trap_present ? (
                    <Box bg="card" p="lg" border="top" borderColor={colors.magenta}>
                      <Stack gap="md">
                        <Text variant="heading">Trap configuration</Text>
                        <div className="console-next-toggle-grid">
                          <ToggleField
                            label="Trap matching enabled"
                            checked={serverForm.trap_enabled}
                            onChange={(checked) => updateServerForm('trap_enabled', checked)}
                          />
                          <ToggleField
                            label="Apply max risk"
                            checked={serverForm.trap_apply_max_risk}
                            onChange={(checked) =>
                              updateServerForm('trap_apply_max_risk', checked)
                            }
                          />
                          <ToggleField
                            label="Alert telemetry"
                            checked={serverForm.trap_alert_telemetry}
                            onChange={(checked) =>
                              updateServerForm('trap_alert_telemetry', checked)
                            }
                          />
                        </div>
                        <div className="console-next-form-grid">
                          <Input
                            fill
                            label="Extended tarpit delay (ms)"
                            type="number"
                            value={serverForm.trap_extended_tarpit_ms}
                            onChange={(event) =>
                              updateServerForm(
                                'trap_extended_tarpit_ms',
                                event.currentTarget.value,
                              )
                            }
                            helper="Leave blank to omit the extra delay."
                          />
                          <div />
                        </div>
                        <Input
                          fill
                          multiline
                          rows={8}
                          label="Trap paths"
                          value={serverForm.trap_paths}
                          onChange={(event) => updateServerForm('trap_paths', event.currentTarget.value)}
                          helper="One glob path per line, for example /.git/* or /admin/backup*."
                        />
                      </Stack>
                    </Box>
                  ) : null}

                  <div className="console-next-button-row">
                    <Button type="submit" disabled={saveState.kind === 'saving'}>
                      {saveState.kind === 'saving' ? 'Saving…' : 'Save server config'}
                    </Button>
                    <Button
                      type="button"
                      variant="outlined"
                      onClick={() => {
                        setSaveState({ kind: 'idle' });
                        setServerForm(buildServerForm(state.fullConfig?.server));
                      }}
                      disabled={saveState.kind === 'saving'}
                    >
                      Reset form
                    </Button>
                  </div>
                </Stack>
              </form>
            )}
          </Stack>
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'sites' ? (
        <section role="tabpanel" id="panel-sites" aria-labelledby="tab-sites">
          {fullConfigSites.length > 0 ? (
            <Stack gap="md">
              {fullConfigSites.map((site, index) => (
                  <Box
                    key={String(`${site.hostname ?? 'unnamed'}-${index}`)}
                    bg="card"
                    p="lg"
                    border="subtle"
                    style={{ minWidth: 0 }}
                  >
                    <Stack gap="sm">
                      <Text variant="heading">{site.hostname ?? 'Unnamed site'}</Text>
                      <Text variant="body" color={colors.textSecondary}>
                        Upstreams: {formatUpstreams(site.upstreams)}
                      </Text>
                      <Text variant="body" color={colors.textSecondary}>
                        WAF: {formatBoolean(site.waf?.enabled)}
                      </Text>
                      <Text variant="body" color={colors.textSecondary}>
                        Headers: {site.headers ? Object.keys(site.headers).length : 0}
                      </Text>
                      <Text variant="body" color={colors.textSecondary}>
                        Rule overrides:{' '}
                        {site.waf?.rule_overrides
                          ? Object.keys(site.waf.rule_overrides).length
                          : 0}
                      </Text>
                    </Stack>
                  </Box>
              ))}
            </Stack>
          ) : sensorFallbackSites.length > 0 ? (
            <Stack gap="md">
              {sensorFallbackSites.map((site, index) => (
                <Box
                  key={String(`${site.hostname ?? 'unnamed'}-${index}`)}
                  bg="card"
                  p="lg"
                  border="subtle"
                  style={{ minWidth: 0 }}
                >
                  <Stack gap="sm">
                    <Text variant="heading">{site.hostname ?? 'Unnamed site'}</Text>
                    <Text variant="body" color={colors.textSecondary}>
                      Upstreams:{' '}
                      {site.upstreams && site.upstreams.length > 0
                        ? site.upstreams.join(', ')
                        : 'Not configured'}
                    </Text>
                    <Text variant="body" color={colors.textSecondary}>
                      WAF: {formatBoolean(site.waf_enabled)}
                    </Text>
                    <Text variant="body" color={colors.textSecondary}>
                      TLS: {formatBoolean(site.tls_enabled)}
                    </Text>
                  </Stack>
                </Box>
              ))}
            </Stack>
          ) : (
            <EmptyState
              title="No sites configured"
              description="Once site CRUD lands in the new operator surface, configured virtual hosts will show up here."
            />
          )}
        </section>
      ) : null}

      {activeTab === 'roadmap' ? (
        <section role="tabpanel" id="panel-roadmap" aria-labelledby="tab-roadmap">
          <Stack gap="md">
            <Box bg="card" p="lg" border="top" borderColor={colors.magenta}>
              <Stack gap="sm">
                <Text variant="heading">Next operator slices</Text>
                <Text variant="body" color={colors.textSecondary}>
                  Site CRUD, per-site TLS/WAF/headers controls, and safer config validation flows
                  that expose backend warnings before restart paths are needed.
                </Text>
              </Stack>
            </Box>
            <Box bg="card" p="lg" border="top" borderColor={colors.orange}>
              <Stack gap="xs">
                <Text variant="label" color={colors.textSecondary}>
                  Remaining UI gaps after this slice
                </Text>
                <Text variant="body">Per-site create, update, and delete flows</Text>
                <Text variant="body">Per-site headers and WAF rule override editing</Text>
                <Text variant="body">Per-site TLS and shadow mirror controls</Text>
                <Text variant="body">Profiler and module editors in the SPA shell</Text>
              </Stack>
            </Box>
          </Stack>
        </section>
      ) : null}
    </main>
  );
}
