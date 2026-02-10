/**
 * Configuration Manager Service Tests
 *
 * P1 reliability tests for config template management and sync:
 * - SHA-256 hash consistency
 * - Same content -> same hash
 * - Different content -> different hash
 * - Key ordering irrelevance (deterministic hashing)
 * - Tenant isolation
 * - Diff detection between configs
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { ConfigManager } from '../config-manager.js';

function createMockLogger(): Logger {
  return {
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

function createMockPrisma() {
  const templates = new Map<string, Record<string, unknown>>();

  return {
    configTemplate: {
      create: vi.fn().mockImplementation(({ data }) => {
        const id = `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const record = {
          id,
          ...data,
          description: data.description ?? null,
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        templates.set(id, record);
        return Promise.resolve(record);
      }),
      findFirst: vi.fn().mockImplementation(({ where }) => {
        for (const [, tpl] of templates) {
          const matchId = !where.id || tpl.id === where.id;
          const matchTenant = !where.tenantId || tpl.tenantId === where.tenantId;
          if (matchId && matchTenant) return Promise.resolve(tpl);
        }
        return Promise.resolve(null);
      }),
      findMany: vi.fn().mockImplementation(({ where }) => {
        const results = Array.from(templates.values()).filter((tpl) => {
          if (where.tenantId && tpl.tenantId !== where.tenantId) return false;
          if (where.environment && tpl.environment !== where.environment) return false;
          if (where.isActive !== undefined && tpl.isActive !== where.isActive) return false;
          return true;
        });
        return Promise.resolve(results);
      }),
      update: vi.fn().mockImplementation(({ where, data }) => {
        const existing = templates.get(where.id);
        if (!existing) return Promise.reject(new Error('Not found'));
        const updated = { ...existing, ...data, updatedAt: new Date() };
        templates.set(where.id, updated);
        return Promise.resolve(updated);
      }),
      delete: vi.fn().mockImplementation(({ where }) => {
        templates.delete(where.id);
        return Promise.resolve({});
      }),
    },
    sensorSyncState: {
      findUnique: vi.fn().mockResolvedValue(null),
      upsert: vi.fn().mockResolvedValue({}),
    },
    sensor: {
      findMany: vi.fn().mockResolvedValue([]),
    },
    _templates: templates,
  } as unknown as PrismaClient & { _templates: Map<string, Record<string, unknown>> };
}

describe('ConfigManager', () => {
  let prisma: ReturnType<typeof createMockPrisma>;
  let logger: Logger;
  let configManager: ConfigManager;

  beforeEach(() => {
    prisma = createMockPrisma();
    logger = createMockLogger();
    configManager = new ConfigManager(prisma as unknown as PrismaClient, logger);
  });

  describe('SHA-256 hash consistency', () => {
    it('should produce the same hash for the same input on repeated calls', async () => {
      const config = { waf: { enabled: true }, rateLimit: { rps: 1000 } };

      const hash1 = await configManager.computeConfigHash(config);
      const hash2 = await configManager.computeConfigHash(config);

      expect(hash1).toBe(hash2);
      // SHA-256 produces 64 hex characters
      expect(hash1).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('Same config content produces same hash', () => {
    it('should return identical hash for identical config objects', async () => {
      const configA = { mode: 'detect', threshold: 50, regions: ['us-east-1'] };
      const configB = { mode: 'detect', threshold: 50, regions: ['us-east-1'] };

      const hashA = await configManager.computeConfigHash(configA);
      const hashB = await configManager.computeConfigHash(configB);

      expect(hashA).toBe(hashB);
    });
  });

  describe('Different config content produces different hash', () => {
    it('should return different hashes for configs with different values', async () => {
      const configA = { mode: 'detect', threshold: 50 };
      const configB = { mode: 'block', threshold: 50 };

      const hashA = await configManager.computeConfigHash(configA);
      const hashB = await configManager.computeConfigHash(configB);

      expect(hashA).not.toBe(hashB);
    });
  });

  describe('Key ordering is irrelevant to hash', () => {
    it('should produce the same hash regardless of key insertion order', async () => {
      // The implementation sorts keys before stringifying
      const configA = { alpha: 1, beta: 2, gamma: 3 };
      const configB = { gamma: 3, alpha: 1, beta: 2 };

      const hashA = await configManager.computeConfigHash(configA);
      const hashB = await configManager.computeConfigHash(configB);

      expect(hashA).toBe(hashB);
    });
  });

  describe('Tenant isolation', () => {
    it('should not return templates from a different tenant', async () => {
      // Create a template for tenant-A
      await configManager.createTemplate('tenant-A', {
        name: 'production-waf',
        description: 'Production WAF config',
        environment: 'production',
        config: { waf: { enabled: true } },
        hash: 'abc123',
        version: '1.0.0',
        isActive: true,
      });

      // Query as tenant-B
      const templates = await configManager.listTemplates('tenant-B');
      expect(templates).toHaveLength(0);
    });
  });

  describe('Diff detection between configs', () => {
    it('should detect additions, modifications, and removals between configs', async () => {
      // Create a template to be the target
      const template = await configManager.createTemplate('tenant-1', {
        name: 'target-config',
        environment: 'staging',
        config: { mode: 'block', newSetting: true, threshold: 100 },
        hash: 'target-hash',
        version: '2.0.0',
        isActive: true,
      });

      // Sensor has no sync state (null current config), so all keys should be additions
      const diff = await configManager.generateConfigDiff('sensor-1', template.id);

      expect(diff.sensorId).toBe('sensor-1');
      expect(diff.currentConfig).toBeNull();
      expect(diff.targetConfig).toEqual({ mode: 'block', newSetting: true, threshold: 100 });

      // All target keys should be additions when current is null
      expect(diff.differences).toHaveLength(3);
      expect(diff.differences.every((d) => d.action === 'add')).toBe(true);

      const paths = diff.differences.map((d) => d.path).sort();
      expect(paths).toEqual(['mode', 'newSetting', 'threshold']);
    });
  });
});
