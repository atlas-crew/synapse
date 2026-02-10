/**
 * Hunt Service — Input Validation Security Tests (P0)
 *
 * Exercises the private validation helpers (validateIpAddress, validateIdentifier,
 * validateRequestId) via the public API surface: getIpActivity, queryTimeline,
 * and getRequestTimeline.
 *
 * Every test targets SQL injection, path traversal, or malformed-input rejection
 * to ensure defense-in-depth on the ClickHouse query path.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HuntService, type HuntQuery } from '../index.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { ClickHouseService } from '../../../storage/clickhouse/index.js';

// =============================================================================
// Mock Factories
// =============================================================================

const mockPrisma = {
  signal: {
    findMany: vi.fn().mockResolvedValue([]),
    count: vi.fn().mockResolvedValue(0),
  },
} as unknown as PrismaClient;

const mockLogger = {
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

const mockClickhouse = {
  isEnabled: vi.fn().mockReturnValue(true),
  queryWithParams: vi.fn().mockResolvedValue([]),
  queryOneWithParams: vi.fn().mockResolvedValue(null),
  query: vi.fn(),
  queryOne: vi.fn(),
  ping: vi.fn(),
} as unknown as ClickHouseService;

// =============================================================================
// Helpers
// =============================================================================

function createService(): HuntService {
  return new HuntService(mockPrisma, mockLogger, mockClickhouse);
}

function recentQuery(overrides: Partial<HuntQuery> = {}): HuntQuery {
  return {
    startTime: new Date(Date.now() - 6 * 60 * 60 * 1000),
    endTime: new Date(),
    ...overrides,
  };
}

// =============================================================================
// Tests
// =============================================================================

describe('HuntService — input validation (security)', () => {
  let service: HuntService;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-06-15T12:00:00Z'));
    service = createService();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ===========================================================================
  // validateIpAddress — exercised via getIpActivity
  // ===========================================================================

  describe('validateIpAddress (via getIpActivity)', () => {
    it('accepts a valid IPv4 address', async () => {
      await expect(service.getIpActivity('192.168.1.1')).resolves.toBeDefined();
    });

    it('accepts a valid IPv6 address', async () => {
      await expect(service.getIpActivity('2001:db8::1')).resolves.toBeDefined();
    });

    it('accepts an IPv4 CIDR notation', async () => {
      await expect(service.getIpActivity('192.168.0.0/24')).resolves.toBeDefined();
    });

    it('accepts an IPv4 prefix filter', async () => {
      await expect(service.getIpActivity('185.228.')).resolves.toBeDefined();
    });

    it('rejects an IP with SQL injection payload', async () => {
      await expect(
        service.getIpActivity("1.1.1.1'; DROP TABLE signals;--")
      ).rejects.toThrow(/Invalid sourceIp/);
    });

    it('rejects an empty string', async () => {
      await expect(service.getIpActivity('')).rejects.toThrow(/Invalid sourceIp/);
    });

    it('rejects an overlong string (>64 chars)', async () => {
      const longIp = '1'.repeat(65);
      await expect(service.getIpActivity(longIp)).rejects.toThrow(/Invalid sourceIp/);
    });

    it('rejects invalid octet values 999.999.999.999', async () => {
      await expect(service.getIpActivity('999.999.999.999')).rejects.toThrow(
        /Invalid sourceIp/
      );
    });

    it('rejects path traversal ../etc/passwd', async () => {
      await expect(service.getIpActivity('../etc/passwd')).rejects.toThrow(
        /Invalid sourceIp/
      );
    });
  });

  // ===========================================================================
  // validateIdentifier — exercised via queryTimeline with tenantId
  // ===========================================================================

  describe('validateIdentifier (via queryTimeline tenantId)', () => {
    // For these tests, route to ClickHouse so validateIdentifier is invoked
    // on tenantId via buildClickHouseQuery.
    function chQuery(tenantId: string): HuntQuery {
      return {
        startTime: new Date(Date.now() - 48 * 60 * 60 * 1000), // 48h ago
        endTime: new Date(Date.now() - 30 * 60 * 60 * 1000),   // 30h ago
        tenantId,
      };
    }

    beforeEach(() => {
      vi.mocked(mockClickhouse.queryWithParams).mockResolvedValue([]);
      vi.mocked(mockClickhouse.queryOneWithParams).mockResolvedValue({ count: '0' });
    });

    it('accepts a valid UUID', async () => {
      await expect(
        service.queryTimeline(chQuery('550e8400-e29b-41d4-a716-446655440000'))
      ).resolves.toBeDefined();
    });

    it('accepts a valid namespaced type (IP_THREAT)', async () => {
      await expect(
        service.queryTimeline(chQuery('IP_THREAT'))
      ).resolves.toBeDefined();
    });

    it('rejects SQL injection in tenantId', async () => {
      await expect(
        service.queryTimeline(chQuery("'; DROP TABLE signals;--"))
      ).rejects.toThrow(/Invalid tenantId: contains disallowed characters/);
    });

    it('treats an empty string tenantId as no filter (falsy guard)', async () => {
      // Empty string is falsy, so buildClickHouseQuery skips the tenantId clause
      // entirely — no validation error, no tenant filter in the query.
      const result = await service.queryTimeline(chQuery(''));
      expect(result).toBeDefined();
      // Verify no tenant filter was applied
      const [sql] = vi.mocked(mockClickhouse.queryWithParams).mock.calls[0] ?? [];
      expect(String(sql)).not.toContain('tenant_id = {tenantId:String}');
    });

    it('rejects a tenantId longer than 256 characters', async () => {
      const longId = 'a'.repeat(257);
      await expect(
        service.queryTimeline(chQuery(longId))
      ).rejects.toThrow(/Invalid tenantId/);
    });

    it('rejects a tenantId containing spaces', async () => {
      await expect(
        service.queryTimeline(chQuery('tenant with spaces'))
      ).rejects.toThrow(/Invalid tenantId: contains disallowed characters/);
    });

    it('rejects a tenantId containing semicolons', async () => {
      await expect(
        service.queryTimeline(chQuery('tenant;injection'))
      ).rejects.toThrow(/Invalid tenantId: contains disallowed characters/);
    });

    it('rejects a tenantId containing null bytes', async () => {
      await expect(
        service.queryTimeline(chQuery('foo\x00bar'))
      ).rejects.toThrow(/Invalid tenantId: contains disallowed characters/);
    });
  });

  // ===========================================================================
  // validateRequestId — exercised via getRequestTimeline
  // ===========================================================================

  describe('validateRequestId (via getRequestTimeline)', () => {
    it('accepts a valid request ID (abc-123.def_456)', async () => {
      await expect(
        service.getRequestTimeline('tenant-1', 'abc-123.def_456')
      ).resolves.toBeDefined();
    });

    it('rejects SQL injection in requestId', async () => {
      await expect(
        service.getRequestTimeline('tenant-1', "abc'; DROP TABLE--")
      ).rejects.toThrow(/Invalid requestId/);
    });

    it('rejects newline injection in requestId', async () => {
      await expect(
        service.getRequestTimeline('tenant-1', 'abc\ndef')
      ).rejects.toThrow(/Invalid requestId/);
    });
  });
});
