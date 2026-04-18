import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  EmptyState,
  Spinner,
  Stack,
  Tabs,
  Text,
  colors,
  spacing,
} from '@atlascrew/signal-ui';

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

type SiteConfig = {
  hostname?: string;
  upstream?: string;
  waf?: {
    enabled?: boolean;
    rule_overrides?: Record<string, unknown>;
  };
  headers?: Record<string, string>;
  shadow_mirror?: unknown;
  tls?: unknown;
};

type ConfigResponse = {
  server?: {
    http_addr?: string;
    https_addr?: string;
    workers?: number;
    waf_enabled?: boolean;
    waf_threshold?: number;
    log_level?: string;
    trap_config?: unknown;
  };
  sites?: SiteConfig[];
};

type LoadState =
  | { kind: 'loading' }
  | {
      kind: 'ready';
      health?: HealthResponse;
      status?: StatusResponse;
      config?: ConfigResponse;
      loadedAt: string;
      warnings: string[];
    };

const tabs = [
  { key: 'overview', label: 'Overview' },
  { key: 'server', label: 'Server' },
  { key: 'sites', label: 'Sites' },
  { key: 'roadmap', label: 'Roadmap' },
] as const;

type TabKey = (typeof tabs)[number]['key'];

async function readJson<T>(path: string): Promise<T> {
  const response = await fetch(path);
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
    throw new Error(typeof data === 'string' ? data : JSON.stringify(data));
  }

  return data as T;
}

function formatBoolean(value: boolean | undefined): string {
  if (value === true) return 'Enabled';
  if (value === false) return 'Disabled';
  return 'Unknown';
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

export function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [state, setState] = useState<LoadState>({ kind: 'loading' });

  async function load() {
    setState({ kind: 'loading' });
    const results = await Promise.allSettled([
      readJson<HealthResponse>('/health'),
      readJson<StatusResponse>('/_sensor/status'),
      readJson<ConfigResponse>('/_sensor/config'),
    ]);

    const warnings = results.flatMap((result, index) => {
      if (result.status === 'fulfilled') return [];
      const labels = ['Health', 'Status', 'Config'] as const;
      const message =
        result.reason instanceof Error ? result.reason.message : 'Request failed.';
      return [`${labels[index]} failed: ${message}`];
    });

    const health = results[0].status === 'fulfilled' ? results[0].value : undefined;
    const status = results[1].status === 'fulfilled' ? results[1].value : undefined;
    const config = results[2].status === 'fulfilled' ? results[2].value : undefined;

    setState({
      kind: 'ready',
      health,
      status,
      config,
      loadedAt: new Date().toLocaleString(),
      warnings,
    });
  }

  useEffect(() => {
    void load();
  }, []);

  const overview = useMemo(() => {
    if (state.kind !== 'ready') return null;
    const siteCount = state.config?.sites?.length ?? 0;
    const blocked = state.status?.blocked_requests ?? 0;
    const mode = state.status?.mode ?? state.health?.status ?? 'unknown';
    const workers = state.config?.server?.workers ?? 0;

    return { siteCount, blocked, mode, workers };
  }, [state]);

  return (
    <main className="console-next-shell">
      <header className="console-next-header">
        <div className="console-next-brand">
          <img src="/console-next/assets/sidebar-lockup.svg" alt="Synapse Fleet" />
          <div>
            <Text variant="subhead" color={colors.textSecondary}>
              Console Next
            </Text>
            <Text as="h1" variant="heading">Synapse Operator UI Bootstrap</Text>
          </div>
        </div>
        <div className="console-next-actions">
          <a className="console-next-link" href="/console">
            Open legacy console
          </a>
          <Button variant="outlined" onClick={() => void load()}>
            Refresh
          </Button>
        </div>
      </header>

      <Alert status="info" title="Bootstrap slice">
        This is the first embedded SPA slice. It is intentionally read-only while we stand up the
        app shell, asset pipeline, and protected route surface.
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
                value: state.config?.server?.http_addr ?? 'Not configured',
              },
              {
                label: 'HTTPS Bind',
                value: state.config?.server?.https_addr ?? 'Not configured',
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
          <PropertyList
          entries={[
            {
              label: 'WAF',
              value: formatBoolean(state.config?.server?.waf_enabled),
            },
            {
              label: 'Threshold',
              value: String(state.config?.server?.waf_threshold ?? 'Not configured'),
            },
            {
              label: 'Workers',
              value: String(state.config?.server?.workers ?? 'Not configured'),
            },
            {
              label: 'Log Level',
              value: state.config?.server?.log_level ?? 'Not configured',
            },
            {
              label: 'Trap Config',
              value: state.config?.server?.trap_config ? 'Present' : 'Not configured',
            },
          ]}
        />
        </section>
      ) : null}

      {state.kind === 'ready' && activeTab === 'sites' ? (
        <section role="tabpanel" id="panel-sites" aria-labelledby="tab-sites">
        {!state.config ? (
          <Alert status="warning" title="Configuration unavailable">
            Site inventory could not be loaded from /_sensor/config.
          </Alert>
        ) : state.config.sites && state.config.sites.length > 0 ? (
          <Stack gap="md">
            {state.config.sites.map((site, index) => (
              <Box
                key={site.hostname ?? site.upstream ?? index}
                bg="card"
                p="lg"
                border="subtle"
                style={{ minWidth: 0 }}
              >
                <Stack gap="sm">
                  <Text variant="heading">{site.hostname ?? 'Unnamed site'}</Text>
                  <Text variant="body" color={colors.textSecondary}>
                    Upstream: {site.upstream ?? 'Not configured'}
                  </Text>
                  <Text variant="body" color={colors.textSecondary}>
                    WAF: {formatBoolean(site.waf?.enabled)}
                  </Text>
                  <Text variant="body" color={colors.textSecondary}>
                    Headers: {site.headers ? Object.keys(site.headers).length : 0}
                  </Text>
                  <Text variant="body" color={colors.textSecondary}>
                    Rule overrides: {site.waf?.rule_overrides ? Object.keys(site.waf.rule_overrides).length : 0}
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
                Server configuration editor, site CRUD, per-site TLS/WAF/headers controls, and
                safe config validation flows.
              </Text>
            </Stack>
          </Box>
          <Box bg="card" p="lg" border="top" borderColor={colors.orange}>
            <Stack gap="xs">
              <Text variant="label" color={colors.textSecondary}>
                Missing surfaces to land
              </Text>
              <Text variant="body">`trap_config`</Text>
              <Text variant="body">per-site `headers`</Text>
              <Text variant="body">per-site `waf.rule_overrides`</Text>
              <Text variant="body">true server + sites editing flows</Text>
            </Stack>
          </Box>
        </Stack>
        </section>
      ) : null}
    </main>
  );
}
