import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SynapseClient } from '../client.js';
import { SynapseError } from '../errors.js';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('SynapseClient', () => {
  let client: SynapseClient;
  const baseUrl = 'http://localhost:3000';

  beforeEach(() => {
    vi.clearAllMocks();
    client = new SynapseClient({ baseUrl });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create client with base URL', () => {
      const c = new SynapseClient({ baseUrl: 'http://example.com' });
      expect(c).toBeInstanceOf(SynapseClient);
      expect(c.baseUrl).toBe('http://example.com');
    });

    it('should remove trailing slash from base URL', () => {
      const c = new SynapseClient({ baseUrl: 'http://example.com/' });
      expect(c.baseUrl).toBe('http://example.com');
    });
  });

  describe('health()', () => {
    it('should return health status', async () => {
      const response = { status: 'ok', service: 'synapse', uptime: 3600 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.health();
      expect(result).toEqual(response);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/health`,
        expect.objectContaining({ method: 'GET' })
      );
    });
  });

  describe('getStatus()', () => {
    it('should return sensor status', async () => {
      const response = { totalRequests: 1000, blockedRequests: 50 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.getStatus();
      expect(result).toEqual(response);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/_sensor/status`,
        expect.objectContaining({ method: 'GET' })
      );
    });
  });

  describe('getMetrics()', () => {
    it('should return prometheus metrics as text', async () => {
      const metrics = '# HELP synapse_requests_total Total requests\nsynapse_requests_total 1000';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: () => Promise.resolve(metrics),
      });

      const result = await client.getMetrics();
      expect(result).toBe(metrics);
    });
  });

  describe('listEntities()', () => {
    it('should return entities list', async () => {
      const response = { entities: [{ ip: '1.2.3.4', riskScore: 75 }] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.listEntities();
      expect(result).toEqual(response);
    });
  });

  describe('listBlocks()', () => {
    it('should return blocks list', async () => {
      const response = { blocks: [{ ip: '1.2.3.4', reason: 'High risk' }] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.listBlocks();
      expect(result).toEqual(response);
    });
  });

  describe('releaseEntity()', () => {
    it('should release entity by IP', async () => {
      const response = { released: true };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.releaseEntity('192.168.1.100');
      expect(result).toEqual(response);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/_sensor/release`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ ip: '192.168.1.100' }),
        })
      );
    });

    it('should release entity by ID', async () => {
      const response = { released: true };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.releaseEntity('entity-abc123');
      expect(result).toEqual(response);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/_sensor/release`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ entityId: 'entity-abc123' }),
        })
      );
    });
  });

  describe('releaseAll()', () => {
    it('should release all entities', async () => {
      const response = { count: 5 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.releaseAll();
      expect(result).toEqual(response);
    });
  });

  describe('getConfig()', () => {
    it('should return configuration', async () => {
      const response = { waf: { threshold: 80 }, system: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.getConfig();
      expect(result).toEqual(response);
    });
  });

  describe('updateConfig()', () => {
    it('should update configuration', async () => {
      const response = { updated: ['autoblockThreshold'], config: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.updateConfig({ autoblockThreshold: 90 });
      expect(result).toEqual(response);
    });
  });

  describe('listRules()', () => {
    it('should return rules list', async () => {
      const response = { rules: [], stats: { total: 100 } };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.listRules();
      expect(result).toEqual(response);
    });
  });

  describe('addRule()', () => {
    it('should add a rule', async () => {
      const rule = { description: 'Test rule', blocking: true, matches: [] };
      const response = { rule: { id: 1, ...rule }, stats: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.addRule(rule);
      expect(result).toEqual(response);
    });

    it('should add a rule with TTL', async () => {
      const rule = { description: 'Test rule', blocking: true, matches: [] };
      const response = { rule: { id: 1, ...rule }, stats: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      await client.addRule(rule, 3600);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/_sensor/rules`,
        expect.objectContaining({
          body: JSON.stringify({ rule, ttl: 3600 }),
        })
      );
    });
  });

  describe('removeRule()', () => {
    it('should remove a rule', async () => {
      const response = { removed: true, stats: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.removeRule(123);
      expect(result).toEqual(response);
      expect(mockFetch).toHaveBeenCalledWith(
        `${baseUrl}/_sensor/rules/123`,
        expect.objectContaining({ method: 'DELETE' })
      );
    });
  });

  describe('clearRules()', () => {
    it('should clear all runtime rules', async () => {
      const response = { cleared: 5, stats: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.clearRules();
      expect(result).toEqual(response);
    });
  });

  describe('reloadRules()', () => {
    it('should reload rules from file', async () => {
      const response = { reloaded: true, stats: {} };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.reloadRules();
      expect(result).toEqual(response);
    });
  });

  describe('evaluate()', () => {
    it('should evaluate a request', async () => {
      const request = { method: 'GET', path: '/api/admin', ip: '1.2.3.4' };
      const response = { wouldBlock: true, riskScore: 95, matchedRules: [] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.evaluate(request);
      expect(result).toEqual(response);
    });
  });

  describe('listActors()', () => {
    it('should return actors list', async () => {
      const response = { actors: [{ ip: '1.2.3.4', fingerprint: 'abc' }] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.listActors();
      expect(result).toEqual(response);
    });
  });

  describe('getActorStats()', () => {
    it('should return actor statistics', async () => {
      const response = { totalActors: 100, uniqueFingerprints: 50 };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.getActorStats();
      expect(result).toEqual(response);
    });
  });

  describe('setActorFingerprint()', () => {
    it('should set fingerprint for actor', async () => {
      const response = { ip: '1.2.3.4', fingerprint: 'newFP' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve(response),
      });

      const result = await client.setActorFingerprint('1.2.3.4', 'newFP');
      expect(result).toEqual(response);
    });
  });

  describe('error handling', () => {
    it('should throw SynapseError on 404', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        text: () => Promise.resolve('Not Found'),
      });

      await expect(client.health()).rejects.toThrow(SynapseError);
    });

    it('should throw SynapseError on 500', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve('Internal Server Error'),
      });

      await expect(client.getStatus()).rejects.toThrow(SynapseError);
    });

    it('should throw SynapseError on network error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network failure'));

      await expect(client.health()).rejects.toThrow(SynapseError);
    });

    it('should handle 204 No Content', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 204,
      });

      const result = await client.releaseAll();
      expect(result).toBeUndefined();
    });
  });

  describe('debug mode', () => {
    it('should log requests when debug is enabled', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const debugClient = new SynapseClient({ baseUrl, debug: true });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'ok' }),
      });

      await debugClient.health();
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[synapse-api]')
      );
    });

    it('should not log when debug is disabled', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const normalClient = new SynapseClient({ baseUrl, debug: false });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'ok' }),
      });

      await normalClient.health();
      expect(consoleSpy).not.toHaveBeenCalled();
    });
  });
});
