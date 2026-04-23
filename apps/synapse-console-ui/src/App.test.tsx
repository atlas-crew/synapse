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

describe('App', () => {
  let currentConfig: typeof baseConfig;
  let fetchMock: FetchMock;

  beforeEach(() => {
    currentConfig = structuredClone(baseConfig);
    fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';

      if (url === '/health') {
        return jsonResponse({ healthy: true, status: 'ok' });
      }

      if (url === '/_sensor/status') {
        return jsonResponse({ mode: 'proxy', blocked_requests: 4, running: true });
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

  function lastSitesPostBody(): { sites: typeof baseConfig.sites } | null {
    const postCalls = fetchMock.mock.calls.filter((call) => {
      const [url, init] = call as [string, RequestInit | undefined];
      return url === '/config' && init?.method === 'POST';
    });
    if (postCalls.length === 0) return null;
    const last = postCalls[postCalls.length - 1] as [string, RequestInit];
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

    resolvePost?.();

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
