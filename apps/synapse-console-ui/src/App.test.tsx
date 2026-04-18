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
});
