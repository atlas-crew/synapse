import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';

type FetchMock = ReturnType<typeof vi.fn>;

const baseConfig = {
  server: {
    http_addr: '0.0.0.0:80',
    https_addr: '0.0.0.0:443',
    workers: 0,
    shutdown_timeout_secs: 30,
    waf_threshold: 70,
    waf_enabled: true,
    log_level: 'info',
    admin_api_key: 'secret-key',
    trap_config: {
      enabled: true,
      paths: ['/.git/*', '/.env'],
      apply_max_risk: true,
      extended_tarpit_ms: 5000,
      alert_telemetry: true,
    },
    waf_regex_timeout_ms: 100,
  },
  sites: [
    {
      hostname: 'example.com',
      upstreams: [{ host: 'origin.internal', port: 8080 }],
      waf: { enabled: true, rule_overrides: { sqli: 'block' } },
      headers: { add: { 'x-test': '1' } },
    },
  ],
  rate_limit: { enabled: true, rps: 1000 },
  profiler: { enabled: true, max_profiles: 1000 },
};

const baseIntegrations = {
  access_mode: 'remote_management',
  sensor_api_key_set: true,
  horizon_hub_url: 'wss://horizon.example.com/ws/sensors',
  horizon_api_key: '',
  horizon_api_key_set: true,
  tunnel_url: 'wss://horizon.example.com/ws/tunnel/sensor',
  tunnel_api_key: '',
  tunnel_api_key_set: true,
  apparatus_url: 'https://apparatus.example.com',
};

const baseModules = {
  dlp: {
    enabled: true,
    fast_mode: false,
    scan_text_only: true,
    max_scan_size: 5242880,
    max_body_inspection_bytes: 8192,
    max_matches: 100,
    custom_keywords: ['pii', 'secret'],
    future_policy: { mode: 'strict' },
  },
  blockPage: {
    company_name: null,
    support_email: null,
    logo_url: null,
    show_request_id: true,
    show_timestamp: true,
    show_client_ip: false,
    show_rule_id: false,
    custom_css: null,
  },
  crawler: {
    enabled: true,
    verify_legitimate_crawlers: true,
    block_bad_bots: true,
    dns_failure_policy: 'apply_risk_penalty',
    dns_cache_ttl_secs: 300,
    dns_timeout_ms: 2000,
    max_concurrent_dns_lookups: 100,
    dns_failure_risk_penalty: 20,
  },
  tarpit: {
    enabled: true,
    base_delay_ms: 1000,
    max_delay_ms: 30000,
    progressive_multiplier: 1.5,
    max_concurrent_tarpits: 1000,
    decay_threshold_ms: 300000,
  },
  travel: {
    max_speed_kmh: 800,
    min_distance_km: 100,
    history_window_ms: 86400000,
    max_history_per_user: 100,
  },
  entity: {
    enabled: true,
    max_entities: 100000,
    risk_decay_per_minute: 10,
    block_threshold: 70,
    max_risk: 100,
    max_rules_per_entity: 50,
  },
  kernel: {
    parameters: {
      'net.ipv4.ip_forward': '0',
      'net.core.somaxconn': '4096',
    },
    errors: {
      'vm.overcommit_memory': 'permission denied',
    },
  },
};

function jsonResponse(body: unknown, init?: ResponseInit) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status: init?.status ?? 200,
      headers: {
        'Content-Type': 'application/json',
        ...(init?.headers ?? {}),
      },
    }),
  );
}

function textResponse(body: string, init?: ResponseInit) {
  return Promise.resolve(
    new Response(body, {
      status: init?.status ?? 200,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        ...(init?.headers ?? {}),
      },
    }),
  );
}

describe('App', () => {
  let currentConfig: any;
  let currentIntegrations: any;
  let currentIntegrationsEtag: string;
  let integrationsPutCount: number;
  let currentModules: any;
  let moduleGetFailures: Record<string, { status: number; body: unknown }>;
  let modulePutFailures: Record<string, { status: number; body: unknown }>;
  let kernelGetFailure: { status: number; body: unknown } | null;
  let kernelPutResponse: { status: number; body: unknown } | null;
  let currentExportPayload: string;
  let fetchMock: FetchMock;

  beforeEach(() => {
    currentConfig = structuredClone(baseConfig);
    currentIntegrations = structuredClone(baseIntegrations);
    currentIntegrationsEtag = '"integrations-v1"';
    integrationsPutCount = 0;
    currentModules = structuredClone(baseModules);
    moduleGetFailures = {};
    modulePutFailures = {};
    kernelGetFailure = null;
    kernelPutResponse = null;
    currentExportPayload = [
      'server:',
      '  http_addr: 0.0.0.0:80',
      'sites:',
      '  - hostname: example.com',
      '    upstreams:',
      '      - host: origin.internal',
      '        port: 8080',
      '',
    ].join('\n');
    fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const moduleRouteMap: Record<string, keyof typeof baseModules> = {
        '/_sensor/config/dlp': 'dlp',
        '/_sensor/config/block-page': 'blockPage',
        '/_sensor/config/crawler': 'crawler',
        '/_sensor/config/tarpit': 'tarpit',
        '/_sensor/config/travel': 'travel',
        '/_sensor/config/entity': 'entity',
      };

      if (url === '/health') {
        return jsonResponse({ healthy: true, status: 'ok' });
      }

      if (url === '/_sensor/status') {
        return jsonResponse({ mode: 'proxy', blocked_requests: 4, running: true });
      }

      if (url === '/reload' && method === 'POST') {
        return jsonResponse({
          success: true,
          data: {
            success: true,
            message: 'Configuration reloaded successfully.',
          },
        });
      }

      if (url === '/test' && method === 'POST') {
        return jsonResponse({
          success: true,
          data: {
            success: true,
            message: 'Configuration syntax OK',
          },
        });
      }

      if (url === '/restart' && method === 'POST') {
        return jsonResponse({
          success: true,
          data: {
            success: true,
            message: 'Restart requested. Synapse WAF will restart using /usr/local/bin/synapse-waf.',
          },
        });
      }

      if (url === '/shutdown' && method === 'POST') {
        return jsonResponse({
          success: true,
          data: {
            success: true,
            message: 'Shutdown requested. Synapse WAF is draining existing connections.',
          },
        });
      }

      if (url === '/_sensor/config/export' && method === 'GET') {
        return textResponse(currentExportPayload, {
          headers: {
            'Content-Type': 'application/x-yaml',
            'Content-Disposition': 'attachment; filename="sensor-config.yaml"',
          },
        });
      }

      if (url === '/_sensor/config/import' && method === 'POST') {
        currentExportPayload = String(init?.body ?? currentExportPayload);
        return jsonResponse({
          success: true,
          message: 'Configuration imported and applied successfully.',
          applied: true,
          persisted: true,
          rebuild_required: true,
          warnings: [],
        });
      }

      if (url === '/_sensor/config') {
        return jsonResponse({
          success: true,
          data: {
            sites: [
              {
                hostname: 'example.com',
                upstreams: ['origin.internal:8080'],
                tls_enabled: true,
                waf_enabled: true,
              },
            ],
          },
        });
      }

      if (url === '/_sensor/config/integrations' && method === 'GET') {
        return jsonResponse(
          {
            success: true,
            data: currentIntegrations,
          },
          { headers: { ETag: currentIntegrationsEtag } },
        );
      }

      if (url === '/_sensor/config/integrations' && method === 'PUT') {
        integrationsPutCount += 1;
        currentIntegrations = {
          ...currentIntegrations,
          ...JSON.parse(String(init?.body ?? '{}')),
        };
        currentIntegrationsEtag = `"integrations-v${integrationsPutCount + 1}"`;
        return jsonResponse(
          {
            success: true,
            data: {
              applied: true,
              persisted: true,
              rebuild_required: true,
              warnings: [],
            },
            message:
              'Integrations configuration updated. Restart synapse-waf to apply live Horizon and Tunnel connections.',
          },
          { headers: { ETag: currentIntegrationsEtag } },
        );
      }

      if (url in moduleRouteMap && method === 'GET') {
        const failure = moduleGetFailures[url];
        if (failure) {
          return jsonResponse(failure.body, { status: failure.status });
        }

        return jsonResponse({
          success: true,
          data: currentModules[moduleRouteMap[url]],
        });
      }

      if (url in moduleRouteMap && method === 'PUT') {
        const failure = modulePutFailures[url];
        if (failure) {
          return jsonResponse(failure.body, { status: failure.status });
        }
        const body = JSON.parse(String(init?.body ?? '{}'));
        const moduleKey = moduleRouteMap[url];
        currentModules[moduleKey] = {
          ...currentModules[moduleKey],
          ...body,
        };
        return jsonResponse({
          success: true,
          message: `${moduleKey} configuration updated`,
        });
      }

      if (url === '/_sensor/config/kernel' && method === 'GET') {
        if (kernelGetFailure) {
          return jsonResponse(kernelGetFailure.body, { status: kernelGetFailure.status });
        }
        return jsonResponse({
          success: true,
          data: currentModules.kernel,
        });
      }

      if (url === '/_sensor/config/kernel' && method === 'PUT') {
        if (kernelPutResponse) {
          return jsonResponse(kernelPutResponse.body, { status: kernelPutResponse.status });
        }
        const body = JSON.parse(String(init?.body ?? '{}'));
        const params = body.params ?? {};
        currentModules.kernel = {
          ...currentModules.kernel,
          parameters: {
            ...currentModules.kernel.parameters,
            ...params,
          },
        };
        return jsonResponse({
          success: true,
          data: {
            applied: params,
            failed: {},
            persisted: body.persist === true,
            persistError: null,
          },
          warnings: [],
        });
      }

      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }

      if (url === '/config' && method === 'POST') {
        const body = JSON.parse(String(init?.body ?? '{}'));
        currentConfig = body;
        return jsonResponse({
          success: true,
          data: {
            applied: true,
            persisted: true,
            rebuild_required: true,
            warnings: [],
          },
        });
      }

      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);
  });

  it('loads the full config and saves server edits without dropping other config blocks', async () => {
    render(<App />);

    await screen.findByText('Synapse Operator UI');

    fireEvent.click(screen.getByRole('tab', { name: 'Server' }));

    const httpBind = await screen.findByLabelText('HTTP bind');
    expect(httpBind).toHaveValue('0.0.0.0:80');
    expect(screen.getByLabelText('Admin API key')).toHaveValue('');

    fireEvent.change(httpBind, { target: { value: '127.0.0.1:8080' } });
    fireEvent.change(screen.getByLabelText('Shutdown timeout (seconds)'), {
      target: { value: '45' },
    });
    fireEvent.change(screen.getByLabelText('Trap paths'), {
      target: { value: '/.git/*\n/admin/backup*' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Save server config' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith('/config', expect.objectContaining({ method: 'POST' }));
    });

    const postCall = fetchMock.mock.calls.find((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });

    expect(postCall).toBeTruthy();

    const savedBody = JSON.parse(String((postCall?.[1] as RequestInit | undefined)?.body ?? '{}'));
    expect(savedBody.server.http_addr).toBe('127.0.0.1:8080');
    expect(savedBody.server.shutdown_timeout_secs).toBe(45);
    expect(savedBody.server.trap_config.paths).toEqual(['/.git/*', '/admin/backup*']);
    expect(savedBody.server).not.toHaveProperty('admin_api_key');
    expect((postCall?.[1] as RequestInit | undefined)?.headers).toMatchObject({
      'Content-Type': 'application/json',
      'If-Match': '"config-v1"',
    });
    expect(savedBody.sites).toEqual(baseConfig.sites);
    expect(savedBody.profiler).toEqual(baseConfig.profiler);
    expect(savedBody.rate_limit).toEqual(baseConfig.rate_limit);
  });

  it('blocks save when admin key replacement is enabled but no value is provided', async () => {
    render(<App />);

    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Server' }));

    fireEvent.click(await screen.findByLabelText('Replace admin API key'));
    fireEvent.click(screen.getByRole('button', { name: 'Save server config' }));

    expect(
      await screen.findByText('Admin API key is required when replacement is enabled.'),
    ).toBeInTheDocument();

    expect(fetchMock).not.toHaveBeenCalledWith(
      '/config',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('sends an explicit clear header when the admin key is cleared', async () => {
    render(<App />);

    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Server' }));

    fireEvent.click(await screen.findByLabelText('Clear stored admin API key'));
    fireEvent.click(screen.getByRole('button', { name: 'Save server config' }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/config',
        expect.objectContaining({ method: 'POST' }),
      );
    });

    const postCall = fetchMock.mock.calls.find((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });

    expect((postCall?.[1] as RequestInit | undefined)?.headers).toMatchObject({
      'If-Match': '"config-v1"',
      'X-Clear-Admin-Api-Key': 'true',
    });

    const savedBody = JSON.parse(String((postCall?.[1] as RequestInit | undefined)?.body ?? '{}'));
    expect(savedBody.server.admin_api_key).toBeNull();
  });

  function lastIntegrationsPutBody(): Record<string, unknown> | null {
    const putCalls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/_sensor/config/integrations' && init?.method === 'PUT';
    });
    if (putCalls.length === 0) return null;
    const last = putCalls[putCalls.length - 1] as [string, RequestInit];
    return JSON.parse(String(last[1].body ?? '{}'));
  }

  function integrationsPutCalls(): Array<[string, RequestInit]> {
    return fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/_sensor/config/integrations' && init?.method === 'PUT';
    }) as Array<[string, RequestInit]>;
  }

  function lastSitesPostBody(): { sites: typeof baseConfig.sites } | null {
    const postCalls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });
    if (postCalls.length === 0) return null;
    const last = postCalls[postCalls.length - 1] as [string, RequestInit];
    return JSON.parse(String(last[1].body ?? '{}'));
  }

  function lastPutBodyForPath(path: string): Record<string, unknown> | null {
    const putCalls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === path && init?.method === 'PUT';
    });
    if (putCalls.length === 0) return null;
    const last = putCalls[putCalls.length - 1] as [string, RequestInit];
    return JSON.parse(String(last[1].body ?? '{}'));
  }

  async function openSitesTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Sites' }));
    await screen.findByRole('button', { name: 'Add site' });
  }

  async function openRateLimitTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Rate Limit' }));
    await screen.findByLabelText('Requests per second');
  }

  async function openProfilerTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Profiler' }));
    await screen.findByLabelText('Max profiles');
  }

  async function openIntegrationsTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Integrations' }));
    await screen.findByLabelText('Access mode');
  }

  async function openModulesTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Modules' }));
    await screen.findByText('Threat-detection modules');
  }

  async function openActionsTab() {
    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Actions' }));
    await screen.findByText('Operator actions');
  }

  function lastRequest(path: string, method: string): [string, RequestInit] | null {
    const calls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === path && (init?.method ?? 'GET') === method;
    }) as Array<[string, RequestInit]>;
    if (calls.length === 0) return null;
    return calls[calls.length - 1] ?? null;
  }

  it('loads the modules tab with generic module editors and kernel parameters', async () => {
    await openModulesTab();

    expect(await screen.findByLabelText('Max matches')).toHaveValue(100);
    expect(screen.getByLabelText('Fast mode')).not.toBeChecked();
    expect(screen.getByLabelText('Show request id')).toBeChecked();
    expect(screen.getByLabelText('net.ipv4.ip_forward')).toHaveValue('0');
    expect(screen.getByText('vm.overcommit_memory')).toBeInTheDocument();
    expect(screen.getByText('permission denied')).toBeInTheDocument();
  });

  it('saves generic module edits through the dedicated module endpoint without dropping opaque fields', async () => {
    await openModulesTab();

    fireEvent.change(await screen.findByLabelText('Max matches'), {
      target: { value: '250' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save DLP module' }));

    await waitFor(() => {
      expect(lastPutBodyForPath('/_sensor/config/dlp')).not.toBeNull();
    });

    expect(lastPutBodyForPath('/_sensor/config/dlp')).toEqual({
      enabled: true,
      fast_mode: false,
      scan_text_only: true,
      max_scan_size: 5242880,
      max_body_inspection_bytes: 8192,
      max_matches: 250,
      custom_keywords: ['pii', 'secret'],
      future_policy: { mode: 'strict' },
    });
    expect(await screen.findByText('dlp configuration updated')).toBeInTheDocument();
  });

  it('preserves module form edits when a generic module save fails', async () => {
    modulePutFailures['/_sensor/config/dlp'] = {
      status: 400,
      body: { success: false, error: 'max_matches must be <= 10000' },
    };

    await openModulesTab();

    fireEvent.change(await screen.findByLabelText('Max matches'), {
      target: { value: '250' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save DLP module' }));

    expect(await screen.findByText('max_matches must be <= 10000')).toBeInTheDocument();
    expect(screen.getByLabelText('Max matches')).toHaveValue(250);
  });

  it('renders float module fields with decimal step and saves decimal values', async () => {
    await openModulesTab();

    const multiplier = await screen.findByLabelText('Progressive multiplier');
    expect(multiplier).toHaveAttribute('step', '0.1');

    fireEvent.change(multiplier, {
      target: { value: '2.25' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save Tarpit module' }));

    await waitFor(() => {
      expect(lastPutBodyForPath('/_sensor/config/tarpit')).not.toBeNull();
    });

    expect(lastPutBodyForPath('/_sensor/config/tarpit')).toMatchObject({
      progressive_multiplier: 2.25,
    });
  });

  it('saves kernel parameter edits via the kernel endpoint', async () => {
    await openModulesTab();

    fireEvent.change(await screen.findByLabelText('net.ipv4.ip_forward'), {
      target: { value: '1' },
    });
    fireEvent.click(screen.getByLabelText('Persist after reboot'));
    fireEvent.click(screen.getByRole('button', { name: 'Save kernel parameters' }));

    await waitFor(() => {
      expect(lastPutBodyForPath('/_sensor/config/kernel')).not.toBeNull();
    });

    expect(lastPutBodyForPath('/_sensor/config/kernel')).toEqual({
      params: {
        'net.ipv4.ip_forward': '1',
      },
      persist: true,
    });
    expect(
      await screen.findByText('Kernel parameters saved. Applied 1 parameter(s).'),
    ).toBeInTheDocument();
  });

  it('surfaces failed kernel parameters without discarding applied changes', async () => {
    kernelPutResponse = {
      status: 200,
      body: {
        success: false,
        data: {
          applied: { 'net.ipv4.ip_forward': '1' },
          failed: { 'net.core.somaxconn': 'read-only' },
          persisted: false,
          persistError: null,
        },
      },
    };

    await openModulesTab();

    fireEvent.change(await screen.findByLabelText('net.ipv4.ip_forward'), {
      target: { value: '1' },
    });
    fireEvent.change(screen.getByLabelText('net.core.somaxconn'), {
      target: { value: '8192' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save kernel parameters' }));

    expect(
      await screen.findByText(
        'Kernel parameter update failed for: net.core.somaxconn.',
      ),
    ).toBeInTheDocument();
    expect(screen.getAllByText('net.core.somaxconn').length).toBeGreaterThan(0);
    expect(screen.getByText('read-only')).toBeInTheDocument();
    expect(screen.getByLabelText('net.ipv4.ip_forward')).toHaveValue('1');
    expect(screen.getByLabelText('net.core.somaxconn')).toHaveValue('8192');
  });

  it('shows a per-card warning when a legacy module endpoint is unavailable', async () => {
    moduleGetFailures['/_sensor/config/dlp'] = {
      status: 503,
      body: { success: false, error: 'DLP module unavailable' },
    };

    await openModulesTab();

    expect(await screen.findByText('DLP module unavailable')).toBeInTheDocument();
    expect(screen.getByText('Block page')).toBeInTheDocument();
  });

  it('shows a dedicated warning when the kernel module endpoint is unavailable', async () => {
    kernelGetFailure = {
      status: 503,
      body: { success: false, error: 'Kernel module unavailable' },
    };

    await openModulesTab();

    expect((await screen.findAllByText('Kernel module unavailable')).length).toBeGreaterThan(0);
    expect(screen.getByLabelText('Max matches')).toBeInTheDocument();
  });

  it('loads the export preview from the legacy config-export endpoint', async () => {
    await openActionsTab();

    fireEvent.click(screen.getByRole('button', { name: 'Export config' }));

    await waitFor(() => {
      expect(lastRequest('/_sensor/config/export', 'GET')).not.toBeNull();
    });

    expect(await screen.findByLabelText('Export preview')).toHaveValue(currentExportPayload);
    expect(await screen.findByText('Loaded export from sensor-config.yaml.')).toBeInTheDocument();
  });

  it('imports raw config payloads with text/plain and surfaces the backend receipt', async () => {
    const importPayload = ['server:', '  http_addr: 127.0.0.1:8080', 'sites: []', ''].join('\n');

    await openActionsTab();

    fireEvent.change(await screen.findByLabelText('Import config payload'), {
      target: { value: importPayload },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Import config' }));

    await waitFor(() => {
      expect(lastRequest('/_sensor/config/import', 'POST')).not.toBeNull();
    });

    const importRequest = lastRequest('/_sensor/config/import', 'POST');
    expect(importRequest?.[1].headers).toMatchObject({
      'Content-Type': 'text/plain; charset=utf-8',
    });
    expect(String(importRequest?.[1].body ?? '')).toBe(importPayload);
    expect(
      await screen.findByText(
        'Configuration imported and applied successfully. Applied=true persisted=true rebuild_required=true.',
      ),
    ).toBeInTheDocument();
  });

  it('runs restart and shutdown actions through the service-manage endpoints', async () => {
    await openActionsTab();

    fireEvent.click(screen.getByRole('button', { name: 'Restart service' }));

    await waitFor(() => {
      expect(lastRequest('/restart', 'POST')).not.toBeNull();
    });

    expect(
      await screen.findByText(
        'Restart requested. Synapse WAF will restart using /usr/local/bin/synapse-waf.',
      ),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Shutdown service' }));

    await waitFor(() => {
      expect(lastRequest('/shutdown', 'POST')).not.toBeNull();
    });

    expect(
      await screen.findByText(
        'Shutdown requested. Synapse WAF is draining existing connections.',
      ),
    ).toBeInTheDocument();
  });

  it('loads the integrations tab and renders the backend fields', async () => {
    await openIntegrationsTab();

    expect(await screen.findByLabelText('Access mode')).toHaveValue('remote_management');
    expect(screen.getByLabelText('Horizon hub URL')).toHaveValue(
      'wss://horizon.example.com/ws/sensors',
    );
    expect(screen.getByLabelText('Tunnel URL')).toHaveValue(
      'wss://horizon.example.com/ws/tunnel/sensor',
    );
    expect(screen.getByLabelText('Apparatus URL')).toHaveValue(
      'https://apparatus.example.com',
    );
    expect(screen.getByLabelText('Sensor key')).toHaveValue('');
    expect(screen.getByText('Stored sensor key present')).toBeInTheDocument();
    expect(screen.getByText('Stored Horizon key present')).toBeInTheDocument();
    expect(screen.getByText('Stored tunnel key present')).toBeInTheDocument();
  });

  it('does not hydrate or resubmit dedicated integration secrets returned by the backend', async () => {
    currentIntegrations = {
      ...structuredClone(baseIntegrations),
      horizon_api_key: 'server-returned-horizon-secret',
      tunnel_api_key: 'server-returned-tunnel-secret',
    };

    await openIntegrationsTab();

    expect(screen.getByLabelText('Horizon key')).toHaveValue('');
    expect(screen.getByLabelText('Tunnel key')).toHaveValue('');

    fireEvent.change(screen.getByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-alt.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(lastIntegrationsPutBody()).not.toBeNull();
    });

    expect(lastIntegrationsPutBody()).toEqual({
      apparatus_url: 'https://apparatus-alt.example.com',
    });
  });

  it('saves integrations edits through the dedicated integrations endpoint', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Access mode'), {
      target: { value: 'tunnel' },
    });
    fireEvent.change(screen.getByLabelText('Tunnel URL'), {
      target: { value: 'wss://tunnel.example.com/ws/sensor' },
    });
    fireEvent.change(screen.getByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-alt.example.com' },
    });
    fireEvent.change(screen.getByLabelText('Sensor key'), {
      target: { value: 'sensor-key-2' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(lastIntegrationsPutBody()).not.toBeNull();
    });

    expect(lastIntegrationsPutBody()).toEqual({
      access_mode: 'tunnel',
      tunnel_url: 'wss://tunnel.example.com/ws/sensor',
      apparatus_url: 'https://apparatus-alt.example.com',
      sensor_api_key: 'sensor-key-2',
    });
    const putCall = fetchMock.mock.calls.find((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/_sensor/config/integrations' && init?.method === 'PUT';
    });
    expect((putCall?.[1] as RequestInit | undefined)?.headers).toMatchObject({
      'Content-Type': 'application/json',
      'If-Match': '"integrations-v1"',
    });
    expect(
      await screen.findByText(
        'Integrations configuration updated. Restart synapse-waf to apply live Horizon and Tunnel connections. Applied=true persisted=true rebuild_required=true.',
      ),
    ).toBeInTheDocument();
  });

  it('advances the integrations etag after save so the next save uses the refreshed version', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-first.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(integrationsPutCalls()).toHaveLength(1);
    });

    fireEvent.change(screen.getByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-second.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(integrationsPutCalls()).toHaveLength(2);
    });

    const [, secondCall] = integrationsPutCalls()[1];
    expect(secondCall.headers).toMatchObject({
      'If-Match': '"integrations-v2"',
    });
    expect(JSON.parse(String(secondCall.body ?? '{}'))).toEqual({
      apparatus_url: 'https://apparatus-second.example.com',
    });
  });

  it('keeps clear-key actions exclusive from replacement-key payloads', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Access mode'), {
      target: { value: 'telemetry' },
    });
    fireEvent.change(screen.getByLabelText('Sensor key'), {
      target: { value: 'sensor-key-2' },
    });
    fireEvent.click(screen.getByLabelText('Clear stored sensor key'));
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(lastIntegrationsPutBody()).not.toBeNull();
    });

    expect(lastIntegrationsPutBody()).toEqual({
      access_mode: 'telemetry',
      clear_sensor_api_key: true,
    });
  });

  it('shows clear-intent copy before integrations credentials are removed', async () => {
    await openIntegrationsTab();

    fireEvent.click(screen.getByLabelText('Clear stored sensor key'));
    fireEvent.click(screen.getByLabelText('Clear stored Horizon key'));
    fireEvent.click(screen.getByLabelText('Clear stored tunnel key'));

    expect(screen.getByText('Stored sensor key will be cleared on save')).toBeInTheDocument();
    expect(screen.getByText('Stored Horizon key will be cleared on save')).toBeInTheDocument();
    expect(screen.getByText('Stored tunnel key will be cleared on save')).toBeInTheDocument();
  });

  it('sends empty strings when integration URLs are explicitly cleared', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Access mode'), {
      target: { value: 'telemetry' },
    });
    fireEvent.change(screen.getByLabelText('Horizon hub URL'), {
      target: { value: '' },
    });
    fireEvent.change(screen.getByLabelText('Tunnel URL'), {
      target: { value: '' },
    });
    fireEvent.change(screen.getByLabelText('Apparatus URL'), {
      target: { value: '' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(lastIntegrationsPutBody()).not.toBeNull();
    });

    expect(lastIntegrationsPutBody()).toEqual({
      access_mode: 'telemetry',
      horizon_hub_url: '',
      tunnel_url: '',
      apparatus_url: '',
    });
  });

  it('pins access mode on first save when the backend did not return one', async () => {
    currentIntegrations = {
      ...structuredClone(baseIntegrations),
      access_mode: undefined,
    };

    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-alt.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    await waitFor(() => {
      expect(lastIntegrationsPutBody()).not.toBeNull();
    });

    expect(lastIntegrationsPutBody()).toEqual({
      access_mode: 'remote_management',
      apparatus_url: 'https://apparatus-alt.example.com',
    });
  });

  it('surfaces backend validation errors from the integrations endpoint', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 4, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/_sensor/config/integrations' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentIntegrations },
          { headers: { ETag: '"integrations-v1"' } },
        );
      }
      if (url === '/_sensor/config/integrations' && method === 'PUT') {
        return jsonResponse(
          { success: false, message: 'Tunnel WebSocket URL is required when Tunnel mode is enabled' },
          { status: 400 },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        return jsonResponse({
          success: true,
          data: { applied: true, persisted: true, rebuild_required: true, warnings: [] },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openIntegrationsTab();
    fireEvent.change(await screen.findByLabelText('Access mode'), {
      target: { value: 'tunnel' },
    });
    fireEvent.change(screen.getByLabelText('Tunnel URL'), { target: { value: '' } });
    fireEvent.click(screen.getByLabelText('Clear stored sensor key'));
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    expect(
      await screen.findByText('Tunnel WebSocket URL is required when Tunnel mode is enabled'),
    ).toBeInTheDocument();
  });

  it('surfaces unsupported-instance errors from the integrations endpoint', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 4, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/_sensor/config/integrations' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentIntegrations },
          { headers: { ETag: '"integrations-v1"' } },
        );
      }
      if (url === '/_sensor/config/integrations' && method === 'PUT') {
        return jsonResponse(
          {
            success: false,
            message: 'Configuration updates not supported by this sensor instance',
          },
          { status: 503 },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        return jsonResponse({
          success: true,
          data: { applied: true, persisted: true, rebuild_required: true, warnings: [] },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openIntegrationsTab();
    fireEvent.change(await screen.findByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus-alt.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    expect(
      await screen.findByText('Configuration updates not supported by this sensor instance'),
    ).toBeInTheDocument();
  });

  it('blocks integrations save on invalid client-side URL input', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Horizon hub URL'), {
      target: { value: 'https://not-websocket.example.com' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    expect(
      await screen.findByText('Horizon hub URL must be a valid ws:// or wss:// URL.'),
    ).toBeInTheDocument();
    expect(lastIntegrationsPutBody()).toBeNull();
  });

  it('blocks integrations save when a URL includes embedded credentials', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Horizon hub URL'), {
      target: { value: 'wss://admin:secret@horizon.example.com/ws/sensors' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    expect(
      await screen.findByText('Horizon hub URL must not include embedded credentials.'),
    ).toBeInTheDocument();
    expect(lastIntegrationsPutBody()).toBeNull();
  });

  it('blocks integrations save when a URL includes a fragment', async () => {
    await openIntegrationsTab();

    fireEvent.change(await screen.findByLabelText('Apparatus URL'), {
      target: { value: 'https://apparatus.example.com#fragment' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save integrations' }));

    expect(
      await screen.findByText('Apparatus URL must not include a URL fragment.'),
    ).toBeInTheDocument();
    expect(lastIntegrationsPutBody()).toBeNull();
  });

  it('adds a new site via POST /config and preserves existing sites', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));

    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'new-site.test' },
    });
    fireEvent.change(screen.getByLabelText('Host #1'), {
      target: { value: 'origin-b.internal' },
    });
    fireEvent.change(screen.getByLabelText('Port #1'), { target: { value: '9090' } });

    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    await waitFor(() => {
      expect(lastSitesPostBody()).not.toBeNull();
    });

    const body = lastSitesPostBody();
    expect(body?.sites).toHaveLength(2);
    expect(body?.sites[0]).toEqual(baseConfig.sites[0]);
    expect(body?.sites[1]).toEqual({
      hostname: 'new-site.test',
      upstreams: [{ host: 'origin-b.internal', port: 9090 }],
    });
    expect((body as typeof baseConfig | null)?.server).toEqual(baseConfig.server);
    expect((body as typeof baseConfig | null)?.profiler).toEqual(baseConfig.profiler);
    expect((body as typeof baseConfig | null)?.rate_limit).toEqual(baseConfig.rate_limit);

    const postCall = fetchMock.mock.calls.find((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });
    expect((postCall?.[1] as RequestInit | undefined)?.headers).toMatchObject({
      'If-Match': '"config-v1"',
    });
  });

  it('edits an existing site while preserving waf, headers, and rule_overrides', async () => {
    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));

    const hostname = await screen.findByLabelText('Hostname');
    expect(hostname).toHaveValue('example.com');

    fireEvent.change(hostname, { target: { value: 'renamed.test' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      expect(lastSitesPostBody()?.sites[0]?.hostname).toBe('renamed.test');
    });

    const body = lastSitesPostBody();
    expect(body?.sites).toHaveLength(1);
    expect(body?.sites[0]).toEqual({
      hostname: 'renamed.test',
      upstreams: [{ host: 'origin.internal', port: 8080 }],
      waf: { enabled: true, rule_overrides: { sqli: 'block' } },
      headers: { add: { 'x-test': '1' } },
    });
  });

  it('edits per-site waf controls, clears threshold, and preserves sibling sites', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [{ host: 'origin.internal', port: 8080 }],
          waf: {
            enabled: true,
            threshold: 91,
            rule_overrides: { sqli: 'block' },
            custom_mode: 'learning',
          },
          headers: {
            request: { add: {}, set: {}, remove: [] },
            response: { add: {}, set: {}, remove: [] },
          },
          tls: { mode: 'strict' },
        },
        {
          hostname: 'untouched.example',
          upstreams: [{ host: 'origin-b.internal', port: 9090, weight: 20 }],
          waf: { enabled: false, rule_overrides: { ja4: 'log' } },
          headers: {
            request: { add: { 'x-existing': '1' }, set: {}, remove: [] },
            response: { add: {}, set: {}, remove: ['server'] },
          },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click((await screen.findAllByRole('button', { name: 'Edit' }))[0]);

    fireEvent.click(await screen.findByLabelText('Site WAF enabled'));
    fireEvent.change(screen.getByLabelText('Site WAF threshold'), {
      target: { value: '' },
    });
    fireEvent.change(screen.getByLabelText('Rule action #1'), {
      target: { value: 'log' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add rule override' }));
    fireEvent.change(screen.getByLabelText('Rule ID #2'), { target: { value: 'ja4' } });
    fireEvent.change(screen.getByLabelText('Rule action #2'), { target: { value: 'allow' } });

    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      const body = lastPostBody() as { sites: Array<Record<string, unknown>> } | null;
      expect(body?.sites[0]?.hostname).toBe('example.com');
    });

    const body = lastPostBody() as {
      server: unknown;
      rate_limit: unknown;
      profiler: unknown;
      sites: Array<Record<string, unknown>>;
    };
    expect(body.server).toEqual(baseConfig.server);
    expect(body.rate_limit).toEqual(baseConfig.rate_limit);
    expect(body.profiler).toEqual(baseConfig.profiler);
    expect(body.sites[0]).toMatchObject({
      hostname: 'example.com',
      upstreams: [{ host: 'origin.internal', port: 8080 }],
      tls: { mode: 'strict' },
      waf: {
        enabled: false,
        custom_mode: 'learning',
        rule_overrides: {
          sqli: 'log',
          ja4: 'allow',
        },
      },
    });
    expect((body.sites[0].waf as Record<string, unknown>)?.threshold).toBeUndefined();
    expect(body.sites[1]).toEqual(currentConfig.sites[1]);
  });

  it('edits all six per-site header operations and preserves opaque nested fields', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [{ host: 'origin.internal', port: 8080 }],
          waf: { enabled: true, rule_overrides: {} },
          headers: {
            request: {
              add: { 'x-trace-id': 'trace-1' },
              set: { 'x-mode': 'monitor' },
              remove: ['x-remove-request'],
              opaque_request_flag: true,
            },
            response: {
              add: { 'x-powered-by': 'synapse' },
              set: { 'cache-control': 'private' },
              remove: ['server'],
              opaque_response_flag: 'preserve-me',
            },
            legacy_extension: { keep: true },
          },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));

    expect(await screen.findByText('Request headers')).toBeInTheDocument();
    expect(screen.getByText('Response headers')).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Request add header value #1'), {
      target: { value: 'trace-2' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add request add header' }));
    fireEvent.change(screen.getByLabelText('Request add header name #2'), {
      target: { value: 'x-request-added' },
    });
    fireEvent.change(screen.getByLabelText('Request add header value #2'), {
      target: { value: 'alpha' },
    });

    fireEvent.change(screen.getByLabelText('Request set header value #1'), {
      target: { value: 'block' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add request set header' }));
    fireEvent.change(screen.getByLabelText('Request set header name #2'), {
      target: { value: 'x-request-set' },
    });
    fireEvent.change(screen.getByLabelText('Request set header value #2'), {
      target: { value: 'bravo' },
    });

    fireEvent.change(screen.getByLabelText('Request remove header #1'), {
      target: { value: 'x-remove-me' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add request remove header' }));
    fireEvent.change(screen.getByLabelText('Request remove header #2'), {
      target: { value: 'x-remove-later' },
    });

    fireEvent.change(screen.getByLabelText('Response add header value #1'), {
      target: { value: 'console-next' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add response add header' }));
    fireEvent.change(screen.getByLabelText('Response add header name #2'), {
      target: { value: 'x-response-added' },
    });
    fireEvent.change(screen.getByLabelText('Response add header value #2'), {
      target: { value: 'charlie' },
    });

    fireEvent.change(screen.getByLabelText('Response set header value #1'), {
      target: { value: 'no-store' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add response set header' }));
    fireEvent.change(screen.getByLabelText('Response set header name #2'), {
      target: { value: 'x-response-set' },
    });
    fireEvent.change(screen.getByLabelText('Response set header value #2'), {
      target: { value: 'delta' },
    });

    fireEvent.change(screen.getByLabelText('Response remove header #1'), {
      target: { value: 'x-hide-me' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Add response remove header' }));
    fireEvent.change(screen.getByLabelText('Response remove header #2'), {
      target: { value: 'x-strip-later' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      const body = lastPostBody() as { sites: Array<Record<string, unknown>> } | null;
      expect(body?.sites[0]?.hostname).toBe('example.com');
    });

    const body = lastPostBody() as { sites: Array<Record<string, unknown>> };
    expect(body.sites[0].headers).toEqual({
      request: {
        add: {
          'x-trace-id': 'trace-2',
          'x-request-added': 'alpha',
        },
        set: {
          'x-mode': 'block',
          'x-request-set': 'bravo',
        },
        remove: ['x-remove-me', 'x-remove-later'],
        opaque_request_flag: true,
      },
      response: {
        add: {
          'x-powered-by': 'console-next',
          'x-response-added': 'charlie',
        },
        set: {
          'cache-control': 'no-store',
          'x-response-set': 'delta',
        },
        remove: ['x-hide-me', 'x-strip-later'],
        opaque_response_flag: 'preserve-me',
      },
      legacy_extension: { keep: true },
    });
  });

  it('validates half-filled rule override rows before POST /config', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [{ host: 'origin.internal', port: 8080 }],
          waf: { enabled: true, rule_overrides: {} },
          headers: {
            request: { add: {}, set: {}, remove: [] },
            response: { add: {}, set: {}, remove: [] },
          },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Add rule override' }));
    fireEvent.change(screen.getByLabelText('Rule ID #1'), {
      target: { value: 'ja4' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    expect(
      await screen.findByText('Rule override #1: action is required.'),
    ).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('validates half-filled header rows before POST /config', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [{ host: 'origin.internal', port: 8080 }],
          waf: { enabled: true, rule_overrides: {} },
          headers: {
            request: { add: {}, set: {}, remove: [] },
            response: { add: {}, set: {}, remove: [] },
          },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add request add header' }));
    fireEvent.change(screen.getByLabelText('Request add header name #1'), {
      target: { value: 'x-request-added' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    expect(
      await screen.findByText('Request add header #1: header value is required.'),
    ).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('rejects duplicate hostnames after normalization', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));

    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'Example.com.' },
    });
    fireEvent.change(screen.getByLabelText('Host #1'), {
      target: { value: 'origin-b.internal' },
    });
    fireEvent.change(screen.getByLabelText('Port #1'), { target: { value: '9090' } });

    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    expect(
      await screen.findByText(/A site with hostname "Example\.com\." already exists\./),
    ).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('rejects duplicate hostnames when editing another site', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        ...baseConfig.sites,
        { hostname: 'second.example', upstreams: [{ host: 'origin-b.internal', port: 9090 }] },
      ],
    });

    await openSitesTab();

    fireEvent.click((await screen.findAllByRole('button', { name: 'Edit' }))[0]);
    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'Second.Example.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    expect(
      await screen.findByText('Another site already uses hostname "Second.Example.".'),
    ).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('requires a hostname before creating a site', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));
    fireEvent.change(await screen.findByLabelText('Host #1'), {
      target: { value: 'origin-b.internal' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    expect(await screen.findByText('Hostname is required.')).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('requires at least one upstream hostname before creating a site', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));
    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'new-site.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    expect(
      await screen.findByText('At least one upstream with a hostname is required.'),
    ).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('disables removing the only upstream row in the site editor', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));

    expect(await screen.findByRole('button', { name: 'Remove upstream' })).toBeDisabled();
  });

  it('cancels site creation without issuing a POST', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));
    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'new-site.test' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    expect(screen.queryByLabelText('Hostname')).not.toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('requires an upstream host when a port is provided', async () => {
    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));
    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'new-site.test' },
    });
    fireEvent.change(screen.getByLabelText('Port #1'), { target: { value: '9090' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    expect(await screen.findByText('Upstream #1: host is required.')).toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('preserves upstream metadata when rows are removed before save', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [
            { host: 'origin-a.internal', port: 8080, weight: 10 },
            { host: 'origin-b.internal', port: 9090, weight: 20, tls_mode: 'strict' },
          ],
          waf: { enabled: true, rule_overrides: { sqli: 'block' } },
          headers: { add: { 'x-test': '1' } },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click((await screen.findAllByRole('button', { name: 'Remove upstream' }))[0]);
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      expect(lastSitesPostBody()?.sites[0]?.upstreams).toEqual([
        { host: 'origin-b.internal', port: 9090, weight: 20, tls_mode: 'strict' },
      ]);
    });
  });

  it('keeps upstream metadata attached to the surviving rows after removing the middle upstream', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [
            { host: 'origin-a.internal', port: 8080, weight: 10 },
            { host: 'origin-b.internal', port: 9090, weight: 20 },
            { host: 'origin-c.internal', port: 10010, weight: 30, tls_mode: 'strict' },
          ],
          waf: { enabled: true, rule_overrides: { sqli: 'block' } },
          headers: { add: { 'x-test': '1' } },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click((await screen.findAllByRole('button', { name: 'Remove upstream' }))[1]);
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      expect(lastSitesPostBody()?.sites[0]?.upstreams).toEqual([
        { host: 'origin-a.internal', port: 8080, weight: 10 },
        {
          host: 'origin-c.internal',
          port: 10010,
          weight: 30,
          tls_mode: 'strict',
        },
      ]);
    });
  });

  it('drops opaque upstream metadata after a surviving row is rewritten to a different host', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      sites: [
        {
          hostname: 'example.com',
          upstreams: [
            { host: 'origin-a.internal', port: 8080, weight: 10 },
            { host: 'origin-b.internal', port: 9090, weight: 20, tls_mode: 'strict' },
          ],
          waf: { enabled: true, rule_overrides: { sqli: 'block' } },
          headers: { add: { 'x-test': '1' } },
        },
      ],
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click((await screen.findAllByRole('button', { name: 'Remove upstream' }))[0]);
    fireEvent.change(screen.getByLabelText('Host #1'), {
      target: { value: 'origin-a.internal' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save site' }));

    await waitFor(() => {
      expect(lastSitesPostBody()?.sites[0]?.upstreams).toEqual([
        { host: 'origin-a.internal', port: 9090 },
      ]);
    });
  });

  it('deletes a site only after inline confirmation', async () => {
    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));

    expect(
      await screen.findByText(/Delete example\.com\? This cannot be undone\./),
    ).toBeInTheDocument();
    expect(
      fetchMock.mock.calls.some((call) => {
        const [url, init] = call as [string, RequestInit | undefined];
        return url === '/config' && init?.method === 'POST';
      }),
    ).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));

    await waitFor(() => {
      expect(lastSitesPostBody()?.sites).toEqual([]);
    });
  });

  it('cancels site deletion without issuing a POST', async () => {
    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));

    expect(
      screen.queryByText(/Delete example\.com\? This cannot be undone\./),
    ).not.toBeInTheDocument();
    expect(lastSitesPostBody()).toBeNull();
  });

  it('surfaces an error alert and leaves state intact when POST /config returns 412', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        return jsonResponse(
          { success: false, error: 'Config version mismatch. Refresh and retry.' },
          { status: 412 },
        );
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openSitesTab();

    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Confirm delete' }));

    expect(
      await screen.findByText('Config version mismatch. Refresh and retry.'),
    ).toBeInTheDocument();

    expect(screen.getByText('example.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Confirm delete' })).toBeInTheDocument();
  });

  function lastPostBody(): Record<string, unknown> | null {
    const postCalls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });
    if (postCalls.length === 0) return null;
    const last = postCalls[postCalls.length - 1] as [string, RequestInit];
    return JSON.parse(String(last[1].body ?? '{}'));
  }

  it('saves rate-limit edits via POST /config and preserves sibling config blocks', async () => {
    await openRateLimitTab();

    const rps = await screen.findByLabelText('Requests per second');
    expect(rps).toHaveValue(1000);
    fireEvent.change(rps, { target: { value: '5000' } });
    fireEvent.change(screen.getByLabelText('Burst capacity'), { target: { value: '7500' } });

    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    await waitFor(() => {
      expect(lastPostBody()).not.toBeNull();
    });

    const body = lastPostBody() as {
      server: unknown;
      sites: unknown;
      profiler: unknown;
      rate_limit: { rps: number; burst: number; enabled: boolean };
    };
    expect(body.rate_limit).toEqual({ rps: 5000, burst: 7500, enabled: true });
    expect(body.server).toEqual(baseConfig.server);
    expect(body.sites).toEqual(baseConfig.sites);
    expect(body.profiler).toEqual(baseConfig.profiler);

    const postCall = fetchMock.mock.calls.find((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });
    expect((postCall?.[1] as RequestInit | undefined)?.headers).toMatchObject({
      'If-Match': '"config-v1"',
    });
  });

  it('renders backend warning suffixes after a successful rate-limit save', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        return jsonResponse({
          success: true,
          data: {
            applied: true,
            persisted: true,
            rebuild_required: false,
            warnings: ['override ignored'],
          },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openRateLimitTab();

    fireEvent.change(screen.getByLabelText('Requests per second'), {
      target: { value: '5000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(await screen.findByText(/Warnings: override ignored/)).toBeInTheDocument();
  });

  it('requires rps >= 1 while rate limiting is enabled', async () => {
    await openRateLimitTab();

    const rps = await screen.findByLabelText('Requests per second');
    fireEvent.change(rps, { target: { value: '0' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(
      await screen.findByText(/Requests per second (must be at least 1|is required)\./),
    ).toBeInTheDocument();
    expect(lastPostBody()).toBeNull();
  });

  it('still requires rps >= 1 when rate limiting is toggled off', async () => {
    await openRateLimitTab();

    fireEvent.click(await screen.findByLabelText('Rate limiting enabled'));
    const rps = await screen.findByLabelText('Requests per second');
    fireEvent.change(rps, { target: { value: '0' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(
      await screen.findByText('Requests per second must be at least 1.'),
    ).toBeInTheDocument();
    expect(lastPostBody()).toBeNull();
  });

  it('omits burst when the rate-limit burst field is left blank', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      rate_limit: { enabled: true, rps: 1000 },
    });

    await openRateLimitTab();

    fireEvent.change(screen.getByLabelText('Requests per second'), {
      target: { value: '5000' },
    });
    fireEvent.change(screen.getByLabelText('Burst capacity'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    await waitFor(() => {
      expect(lastPostBody()).not.toBeNull();
    });

    const body = lastPostBody() as { rate_limit: Record<string, unknown> };
    expect(body.rate_limit.rps).toBe(5000);
    expect('burst' in body.rate_limit).toBe(false);
  });

  it('surfaces a refresh warning when save succeeds but config reload fails', async () => {
    let failReload = false;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        if (failReload) {
          return jsonResponse(
            { success: false, error: 'Config refresh failed.' },
            { status: 503 },
          );
        }
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        failReload = true;
        return jsonResponse({
          success: true,
          data: {
            applied: true,
            persisted: true,
            rebuild_required: false,
            warnings: [],
          },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Rate Limit' }));

    const rps = await screen.findByLabelText('Requests per second');
    fireEvent.change(rps, { target: { value: '5000' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(
      await screen.findByText('Refresh failed. Reload the page before editing again.'),
    ).toBeInTheDocument();
  });

  it('shows the shared refresh warning after a server save when reload fails', async () => {
    let failReload = false;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        if (failReload) {
          return jsonResponse(
            { success: false, error: 'Config refresh failed.' },
            { status: 503 },
          );
        }
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        failReload = true;
        return jsonResponse({
          success: true,
          data: { applied: true, persisted: true, rebuild_required: false, warnings: [] },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Server' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Save server config' }));

    expect(
      await screen.findByText('Refresh failed. Reload the page before editing again.'),
    ).toBeInTheDocument();
  });

  it('shows the shared refresh warning after a site save when reload fails', async () => {
    let failReload = false;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        if (failReload) {
          return jsonResponse(
            { success: false, error: 'Config refresh failed.' },
            { status: 503 },
          );
        }
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        failReload = true;
        return jsonResponse({
          success: true,
          data: { applied: true, persisted: true, rebuild_required: false, warnings: [] },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openSitesTab();

    fireEvent.click(screen.getByRole('button', { name: 'Add site' }));
    fireEvent.change(await screen.findByLabelText('Hostname'), {
      target: { value: 'new-site.test' },
    });
    fireEvent.change(screen.getByLabelText('Host #1'), {
      target: { value: 'origin-b.internal' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Create site' }));

    expect(
      await screen.findByText('Refresh failed. Reload the page before editing again.'),
    ).toBeInTheDocument();
  });

  it('shows the shared refresh warning after a profiler save when reload fails', async () => {
    let failReload = false;
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        if (failReload) {
          return jsonResponse(
            { success: false, error: 'Config refresh failed.' },
            { status: 503 },
          );
        }
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        failReload = true;
        return jsonResponse({
          success: true,
          data: { applied: true, persisted: true, rebuild_required: false, warnings: [] },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openProfilerTab();

    fireEvent.change(screen.getByLabelText('Max profiles'), {
      target: { value: '2500' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save profiler config' }));

    expect(
      await screen.findByText('Refresh failed. Reload the page before editing again.'),
    ).toBeInTheDocument();
  });

  it('shows the cross-form save lock while another save is in flight', async () => {
    let resolvePost: (() => void) | null = null;
    let postCount = 0;

    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        postCount += 1;
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        return new Promise<Response>((resolve) => {
          resolvePost = () => resolve(
            new Response(
              JSON.stringify({
                success: true,
                data: { applied: true, persisted: true, rebuild_required: false, warnings: [] },
              }),
              {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
              },
            ),
          );
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openRateLimitTab();

    fireEvent.change(screen.getByLabelText('Requests per second'), {
      target: { value: '5000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(await screen.findByRole('button', { name: 'Saving…' })).toBeDisabled();

    await waitFor(() => {
      expect(postCount).toBe(1);
    });

    fireEvent.click(screen.getByRole('tab', { name: 'Profiler' }));

    const lockedButton = await screen.findByRole('button', {
      name: 'Another save in progress…',
    });
    expect(lockedButton).toBeDisabled();

    const finishPost = resolvePost as any;
    finishPost?.();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save profiler config' })).toBeEnabled();
    });
  });

  it('surfaces an error when the mutation receipt is missing required flags', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        currentConfig = JSON.parse(String(init?.body ?? '{}'));
        return jsonResponse({
          success: true,
          data: {
            applied: true,
            persisted: true,
          },
        });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Rate Limit' }));

    const rps = await screen.findByLabelText('Requests per second');
    fireEvent.change(rps, { target: { value: '5000' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(
      await screen.findByText('Invalid config mutation response. Reload and retry.'),
    ).toBeInTheDocument();
  });

  it('saves profiler edits via POST /config and preserves sibling config blocks', async () => {
    await openProfilerTab();

    const maxProfiles = await screen.findByLabelText('Max profiles');
    fireEvent.change(maxProfiles, { target: { value: '2500' } });
    fireEvent.change(screen.getByLabelText('Payload z-threshold'), {
      target: { value: '3.5' },
    });
    fireEvent.change(screen.getByLabelText('Freeze after samples'), {
      target: { value: '10000' },
    });
    fireEvent.click(screen.getByLabelText('Redact PII in anomaly descriptions'));

    fireEvent.click(screen.getByRole('button', { name: 'Save profiler config' }));

    await waitFor(() => {
      expect(lastPostBody()).not.toBeNull();
    });

    const body = lastPostBody() as {
      server: unknown;
      sites: unknown;
      rate_limit: unknown;
      profiler: Record<string, unknown>;
    };
    expect(body.profiler.max_profiles).toBe(2500);
    expect(body.profiler.payload_z_threshold).toBe(3.5);
    expect(body.profiler.freeze_after_samples).toBe(10000);
    expect(body.profiler.redact_pii).toBe(false);
    expect(body.profiler.enabled).toBe(true);
    expect(body.server).toEqual(baseConfig.server);
    expect(body.sites).toEqual(baseConfig.sites);
    expect(body.rate_limit).toEqual(baseConfig.rate_limit);
  });

  it('requires profiler float fields before POST', async () => {
    await openProfilerTab();

    fireEvent.change(screen.getByLabelText('Payload z-threshold'), {
      target: { value: '' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save profiler config' }));

    expect(
      await screen.findByText(/Payload z-threshold (is required|must be a number)\./),
    ).toBeInTheDocument();
    expect(lastPostBody()).toBeNull();
  });
  it('preserves unknown fields inside profiler and rate_limit across a save round-trip', async () => {
    currentConfig = structuredClone({
      ...baseConfig,
      profiler: { ...baseConfig.profiler, future_knob: 'alpha' },
      rate_limit: { ...baseConfig.rate_limit, legacy_shadow: true },
    }) as typeof baseConfig;

    render(<App />);
    await screen.findByText('Synapse Operator UI');

    fireEvent.click(screen.getByRole('tab', { name: 'Profiler' }));
    await screen.findByLabelText('Max profiles');
    fireEvent.click(screen.getByRole('button', { name: 'Save profiler config' }));

    await waitFor(() => {
      expect(lastPostBody()).not.toBeNull();
    });

    const body = lastPostBody() as {
      profiler: Record<string, unknown>;
      rate_limit: Record<string, unknown>;
    };
    expect(body.profiler.future_knob).toBe('alpha');
    expect(body.rate_limit.legacy_shadow).toBe(true);
  });

  it('surfaces an error alert when the profiler POST returns 412', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        return jsonResponse(
          { success: false, error: 'Config version mismatch. Refresh and retry.' },
          { status: 412 },
        );
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    render(<App />);
    await screen.findByText('Synapse Operator UI');
    fireEvent.click(screen.getByRole('tab', { name: 'Profiler' }));

    await screen.findByLabelText('Max profiles');
    fireEvent.click(screen.getByRole('button', { name: 'Save profiler config' }));

    expect(
      await screen.findByText('Config version mismatch. Refresh and retry.'),
    ).toBeInTheDocument();
  });
  it('uses the generic concurrency fallback message for 409 responses without an error body', async () => {
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') return jsonResponse({ healthy: true, status: 'ok' });
      if (url === '/_sensor/status')
        return jsonResponse({ mode: 'proxy', blocked_requests: 0, running: true });
      if (url === '/_sensor/config')
        return jsonResponse({ success: true, data: { sites: [] } });
      if (url === '/config' && method === 'GET') {
        return jsonResponse(
          { success: true, data: currentConfig },
          { headers: { ETag: '"config-v1"' } },
        );
      }
      if (url === '/config' && method === 'POST') {
        return jsonResponse({ success: false }, { status: 409 });
      }
      throw new Error(`Unexpected fetch: ${method} ${url}`);
    });

    await openRateLimitTab();

    fireEvent.change(screen.getByLabelText('Requests per second'), {
      target: { value: '5000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Save rate-limit config' }));

    expect(
      await screen.findByText(
        'Config changed elsewhere. Refresh to load the latest version and retry.',
      ),
    ).toBeInTheDocument();
  });
});
