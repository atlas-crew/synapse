import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Logger } from 'pino';
import { SynapseDirectAdapter } from '../synapse-direct.js';

function makeLogger(): Logger {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  } as unknown as Logger;
}

/** Helper: build a minimal healthy PingoraHealthResponse */
function healthResponse(overrides: Record<string, unknown> = {}) {
  return {
    success: true,
    data: {
      status: 'healthy',
      uptime_secs: 120,
      backends: { healthy: 1, unhealthy: 0, total: 1 },
      waf: { enabled: true, analyzed: 500, blocked: 10, block_rate_percent: 2, avg_detection_us: 800 },
      ...overrides,
    },
  };
}

/** Helper: build a minimal PingoraStatsResponse */
function statsResponse(overrides: Record<string, unknown> = {}) {
  return {
    success: true,
    data: {
      uptime_secs: 120,
      rate_limit: { site_count: 1, total_tracked_keys: 42, global_enabled: true },
      access_list_sites: 1,
      ...overrides,
    },
  };
}

describe('SynapseDirectAdapter', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // --------------------------------------------------------------------------
  // fetchPrometheusMetrics (exercised via getPrometheusAnalytics / getSensorStatus)
  // --------------------------------------------------------------------------
  describe('fetchPrometheusMetrics()', () => {
    it('returns default/empty metrics when response body is empty', async () => {
      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return { ok: true, status: 200, json: async () => healthResponse() } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return { ok: true, status: 200, json: async () => statsResponse() } as unknown as Response;
        }
        if (u.endsWith('/metrics')) {
          // Empty Prometheus body — no metrics lines at all
          return { ok: true, status: 200, text: async () => '' } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://synapse.local:6191', makeLogger());
      const result = await adapter.getSensorStatus();

      expect(result).not.toBeNull();
      // With empty prometheus, requestsTotal falls back to waf.analyzed (500)
      expect(result!.requestsTotal).toBe(0);
      expect(result!.blocksTotal).toBe(0);
    });

    it('handles malformed Prometheus text gracefully (no crash)', async () => {
      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return { ok: true, status: 200, json: async () => healthResponse() } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return { ok: true, status: 200, json: async () => statsResponse() } as unknown as Response;
        }
        if (u.endsWith('/metrics')) {
          // Malformed — random garbage, not valid Prometheus exposition format
          return {
            ok: true,
            status: 200,
            text: async () => 'NOT_A_METRIC {{{invalid\n@@@garbage 123abc\n# HELP nothing\n',
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://synapse.local:6191', makeLogger());
      const result = await adapter.getSensorStatus();

      // Should not throw; metric values fall back to 0 or WAF fallback
      expect(result).not.toBeNull();
      expect(result!.requestsTotal).toBeTypeOf('number');
      expect(result!.blocksTotal).toBeTypeOf('number');
    });

    it('parses valid Prometheus text correctly', async () => {
      const prometheusText = [
        '# HELP synapse_requests_total Total requests processed',
        '# TYPE synapse_requests_total counter',
        'synapse_requests_total 2500',
        '# HELP synapse_requests_blocked Total requests blocked',
        '# TYPE synapse_requests_blocked counter',
        'synapse_requests_blocked 75',
        '# HELP synapse_waf_analyzed WAF analyzed count',
        '# TYPE synapse_waf_analyzed counter',
        'synapse_waf_analyzed 2400',
        '# HELP synapse_requests_by_status HTTP status codes',
        '# TYPE synapse_requests_by_status counter',
        'synapse_requests_by_status{status="2xx"} 2000',
        'synapse_requests_by_status{status="3xx"} 200',
        'synapse_requests_by_status{status="4xx"} 250',
        'synapse_requests_by_status{status="5xx"} 50',
      ].join('\n');

      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return { ok: true, status: 200, json: async () => healthResponse() } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return { ok: true, status: 200, json: async () => statsResponse() } as unknown as Response;
        }
        if (u.endsWith('/metrics')) {
          return { ok: true, status: 200, text: async () => prometheusText } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://synapse.local:6191', makeLogger());
      const result = await adapter.getSensorStatus();

      expect(result).not.toBeNull();
      expect(result!.requestsTotal).toBe(2500);
      expect(result!.blocksTotal).toBe(75);
      expect(result!.statusCounts).toEqual({
        '2xx': 2000,
        '3xx': 200,
        '4xx': 250,
        '5xx': 50,
      });
    });
  });

  // --------------------------------------------------------------------------
  // getSensorStatus
  // --------------------------------------------------------------------------
  describe('getSensorStatus()', () => {
    it('returns RPS 0 when uptime is 0 (avoids division by zero)', async () => {
      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true, status: 200,
            json: async () => healthResponse({ uptime_secs: 0 }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true, status: 200,
            json: async () => statsResponse({ uptime_secs: 0 }),
          } as unknown as Response;
        }
        if (u.endsWith('/metrics')) {
          return {
            ok: true, status: 200,
            text: async () => 'synapse_requests_total 100\nsynapse_requests_blocked 5\nsynapse_waf_analyzed 100\n',
          } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://synapse.local:6191', makeLogger());
      const result = await adapter.getSensorStatus();

      expect(result).not.toBeNull();
      expect(result!.rps).toBe(0);
      expect(Number.isFinite(result!.rps)).toBe(true);
    });

    it('returns null on network fetch error', async () => {
      const fetchMock = vi.fn(async () => {
        throw new Error('ECONNREFUSED');
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://unreachable:9999', makeLogger());
      const result = await adapter.getSensorStatus();

      expect(result).toBeNull();
    });

    it('returns expected shape on successful fetch', async () => {
      const prometheusText = [
        'synapse_requests_total 3000',
        'synapse_requests_blocked 150',
        'synapse_waf_analyzed 2900',
        'synapse_requests_by_status{status="2xx"} 2500',
        'synapse_requests_by_status{status="3xx"} 100',
        'synapse_requests_by_status{status="4xx"} 300',
        'synapse_requests_by_status{status="5xx"} 100',
      ].join('\n');

      const fetchMock = vi.fn(async (url: string) => {
        const u = String(url);
        if (u.endsWith('/health')) {
          return {
            ok: true, status: 200,
            json: async () => healthResponse({ uptime_secs: 600 }),
          } as unknown as Response;
        }
        if (u.endsWith('/stats')) {
          return {
            ok: true, status: 200,
            json: async () => statsResponse({ uptime_secs: 600 }),
          } as unknown as Response;
        }
        if (u.endsWith('/metrics')) {
          return { ok: true, status: 200, text: async () => prometheusText } as unknown as Response;
        }
        return { ok: false } as Response;
      });
      globalThis.fetch = fetchMock as unknown as typeof fetch;

      const adapter = new SynapseDirectAdapter('http://synapse.local:6191', makeLogger());
      const result = await adapter.getSensorStatus();

      expect(result).not.toBeNull();
      expect(result).toMatchObject({
        requestsTotal: 3000,
        blocksTotal: 150,
        entitiesTracked: 42,
        activeCampaigns: 0,
        uptime: 600,
      });
      // RPS = round((3000/600)*10)/10 = 5.0
      expect(result!.rps).toBe(5);
      expect(result!.latencyP50).toBeTypeOf('number');
      expect(result!.latencyP95).toBeTypeOf('number');
      expect(result!.latencyP99).toBeTypeOf('number');
    });
  });
});
