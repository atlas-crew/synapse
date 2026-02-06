import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Logger } from 'pino';
import { SynapseDirectAdapter } from '../synapse-direct.js';

function makeLogger(): Logger {
  const logger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  } as unknown as Logger;
  return logger;
}

describe('SynapseDirectAdapter trace header propagation', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('forwards x-request-id + traceparent to JSON endpoints', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith('/health')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            data: {
              status: 'healthy',
              uptime_secs: 10,
              backends: { healthy: 1, unhealthy: 0, total: 1 },
              waf: { enabled: true, analyzed: 0, blocked: 0, block_rate_percent: 0, avg_detection_us: 0 },
            },
          }),
        } as unknown as Response;
      }
      if (u.endsWith('/stats')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            data: {
              uptime_secs: 10,
              rate_limit: { site_count: 0, total_tracked_keys: 0, global_enabled: false },
              access_list_sites: 0,
            },
          }),
        } as unknown as Response;
      }
      if (u.endsWith('/metrics')) {
        return {
          ok: true,
          status: 200,
          text: async () => 'synapse_requests_total 0\nsynapse_requests_blocked 0\nsynapse_waf_analyzed 0\n',
        } as unknown as Response;
      }
      throw new Error(`unexpected url: ${u}`);
    });

    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const adapter = new SynapseDirectAdapter('http://synapse-admin.local', makeLogger());
    await adapter.getSensorStatus({
      'x-request-id': '550e8400-e29b-41d4-a716-446655440000',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      // Ensure we do not allow arbitrary headers through.
      Accept: 'text/plain',
    } as unknown as Record<string, string>);

    const healthCall = fetchMock.mock.calls.find(([u]) => String(u).endsWith('/health'));
    const statsCall = fetchMock.mock.calls.find(([u]) => String(u).endsWith('/stats'));

    expect(healthCall).toBeTruthy();
    expect(statsCall).toBeTruthy();

    expect(healthCall?.[1]?.headers).toMatchObject({
      'x-request-id': '550e8400-e29b-41d4-a716-446655440000',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      Accept: 'application/json',
    });

    expect(statsCall?.[1]?.headers).toMatchObject({
      'x-request-id': '550e8400-e29b-41d4-a716-446655440000',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      Accept: 'application/json',
    });
  });
});

