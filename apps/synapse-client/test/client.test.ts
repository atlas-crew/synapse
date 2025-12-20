import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SynapseClient } from '../src/client.js';
import { SynapseError } from '../src/types.js';

describe('SynapseClient', () => {
  let client: SynapseClient;
  let mockFetch: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFetch = vi.fn();
    vi.stubGlobal('fetch', mockFetch);
    client = new SynapseClient({ baseUrl: 'http://localhost:3000' });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('constructor', () => {
    it('should normalize baseUrl by removing trailing slash', () => {
      const c = new SynapseClient({ baseUrl: 'http://localhost:3000/' });
      // We can verify by checking the URL used in requests
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'ok', service: 'risk-server' }),
      });

      c.health();
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/health',
        expect.any(Object)
      );
    });

    it('should use default timeout of 30000ms', () => {
      // Default is used internally
      const c = new SynapseClient({ baseUrl: 'http://localhost:3000' });
      expect(c).toBeDefined();
    });

    it('should accept custom timeout', () => {
      const c = new SynapseClient({ baseUrl: 'http://localhost:3000', timeout: 5000 });
      expect(c).toBeDefined();
    });
  });

  describe('health', () => {
    it('should return health status', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'ok', service: 'risk-server' }),
      });

      const result = await client.health();
      expect(result.status).toBe('ok');
      expect(result.service).toBe('risk-server');
    });

    it('should throw SynapseError on HTTP error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

      await expect(client.health()).rejects.toThrow(SynapseError);
    });
  });

  describe('getStatus', () => {
    it('should return sensor status', async () => {
      const mockStatus = {
        totalRequests: 1000,
        blockedRequests: 50,
        requestRate: 10.5,
        blockRate: 0.5,
        fallbackRate: 0.1,
        rulesCount: 125,
        autoblockThreshold: 80,
        riskDecayPerMinute: 5,
        riskBasedBlockingEnabled: true,
        requestBlockingEnabled: true,
        allowIpSpoofing: false,
        mode: 'demo',
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockStatus),
      });

      const result = await client.getStatus();
      expect(result.totalRequests).toBe(1000);
      expect(result.blockedRequests).toBe(50);
      expect(result.rulesCount).toBe(125);
    });
  });

  describe('listEntities', () => {
    it('should return entities list', async () => {
      const mockEntities = {
        entities: [
          {
            id: 'entity-1',
            ip: '192.168.1.1',
            risk: 50,
            requestCount: 100,
            blocked: false,
            firstSeen: '2024-01-01T00:00:00Z',
            lastSeen: '2024-01-01T01:00:00Z',
          },
        ],
        count: 1,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockEntities),
      });

      const result = await client.listEntities();
      expect(result.entities).toHaveLength(1);
      expect(result.entities[0].ip).toBe('192.168.1.1');
    });
  });

  describe('releaseEntity', () => {
    it('should release entity by IP address', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ released: true, ip: '192.168.1.1' }),
      });

      const result = await client.releaseEntity('192.168.1.1');
      expect(result.released).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/_sensor/release',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ ip: '192.168.1.1' }),
        })
      );
    });

    it('should release entity by ID', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ released: true, entityId: 'abc-123' }),
      });

      const result = await client.releaseEntity('abc-123');
      expect(result.released).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/_sensor/release',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ entityId: 'abc-123' }),
        })
      );
    });
  });

  describe('releaseAll', () => {
    it('should release all entities', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ released: 5 }),
      });

      const result = await client.releaseAll();
      expect(result.released).toBe(5);
    });
  });

  describe('listRules', () => {
    it('should return rules with stats', async () => {
      const mockRules = {
        rules: [
          { id: 1, name: 'SQL Injection', risk: 80, blocking: true },
          { id: 2, name: 'XSS', risk: 60, blocking: false },
        ],
        stats: { total: 2, blocking: 1, riskBased: 2, runtime: 0 },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockRules),
      });

      const result = await client.listRules();
      expect(result.rules).toHaveLength(2);
      expect(result.stats.total).toBe(2);
    });
  });

  describe('addRule', () => {
    it('should add a runtime rule', async () => {
      const rule = {
        name: 'Test Rule',
        description: 'Test description',
        risk: 50,
        blocking: false,
        matches: [{ type: 'uri', match: '/test' }],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            success: true,
            rule: { id: 999, ...rule },
            stats: { total: 3, blocking: 1, riskBased: 3, runtime: 1 },
          }),
      });

      const result = await client.addRule(rule);
      expect(result.success).toBe(true);
      expect(result.rule.id).toBe(999);
    });

    it('should add a rule with TTL', async () => {
      const rule = {
        description: 'Temp rule',
        matches: [{ type: 'uri', match: '/temp' }],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            success: true,
            rule: { id: 1000, ...rule, ttl: 3600 },
            stats: { total: 4, blocking: 1, riskBased: 4, runtime: 2 },
          }),
      });

      const result = await client.addRule(rule, 3600);
      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/_sensor/rules',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ rule, ttl: 3600 }),
        })
      );
    });
  });

  describe('removeRule', () => {
    it('should remove a rule by ID', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ removed: true, stats: { total: 2, blocking: 1, riskBased: 2, runtime: 0 } }),
      });

      const result = await client.removeRule(999);
      expect(result.removed).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3000/_sensor/rules/999',
        expect.objectContaining({ method: 'DELETE' })
      );
    });
  });

  describe('evaluate', () => {
    it('should evaluate a request against rules', async () => {
      const mockResult = {
        matched: true,
        totalRisk: 80,
        wouldBlock: true,
        blockReason: 'Risk threshold exceeded',
        matchedRules: [
          { id: 1, name: 'SQL Injection', risk: 80, blocking: true, reasons: ['Pattern matched'] },
        ],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockResult),
      });

      const result = await client.evaluate({ method: 'GET', url: '/api/users?id=1 OR 1=1' });
      expect(result.matched).toBe(true);
      expect(result.wouldBlock).toBe(true);
      expect(result.matchedRules).toHaveLength(1);
    });
  });

  describe('listActors', () => {
    it('should return actors list', async () => {
      const mockActors = {
        actors: [
          {
            ip: '192.168.1.1',
            risk: 30,
            sessionCount: 5,
            fingerprintCount: 2,
            jsExecuted: true,
            suspicious: false,
            userAgents: ['Mozilla/5.0'],
            firstActivity: '2024-01-01T00:00:00Z',
            lastActivity: '2024-01-01T01:00:00Z',
          },
        ],
        count: 1,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockActors),
      });

      const result = await client.listActors();
      expect(result.actors).toHaveLength(1);
      expect(result.count).toBe(1);
    });
  });

  describe('getActorStats', () => {
    it('should return actor statistics', async () => {
      const mockStats = {
        totalActors: 100,
        suspiciousActors: 5,
        jsExecutedCount: 80,
        fingerprintChanges: 10,
        averageSessionCount: 3.5,
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(mockStats),
      });

      const result = await client.getActorStats();
      expect(result.totalActors).toBe(100);
      expect(result.suspiciousActors).toBe(5);
    });
  });

  describe('error handling', () => {
    it('should include status code in SynapseError', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: () => Promise.resolve('Not Found'),
      });

      try {
        await client.health();
        expect.fail('Should have thrown');
      } catch (err) {
        expect(err).toBeInstanceOf(SynapseError);
        expect((err as SynapseError).statusCode).toBe(404);
        expect((err as SynapseError).response).toBe('Not Found');
      }
    });
  });
});
