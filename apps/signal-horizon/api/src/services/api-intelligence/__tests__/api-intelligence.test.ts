/**
 * APIIntelligenceService Unit Tests
 * Comprehensive tests for signal ingestion, discovery, violations, and statistics
 */

import { describe, it, expect, beforeEach, vi, type Mock } from 'vitest';
import { APIIntelligenceService } from '../index.js';
import type { PrismaClient, SignalType } from '@prisma/client';
import type { Logger } from 'pino';
import type { APIIntelligenceSignal, SignalBatch } from '../../../schemas/api-intelligence.js';

// =============================================================================
// Mock Setup
// =============================================================================

function createMockLogger(): Logger {
  return {
    child: vi.fn().mockReturnThis(),
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    trace: vi.fn(),
    fatal: vi.fn(),
  } as unknown as Logger;
}

function createMockPrisma(): {
  prisma: PrismaClient;
  mocks: {
    signal: {
      create: Mock;
      count: Mock;
      findMany: Mock;
    };
    endpoint: {
      findFirst: Mock;
      findMany: Mock;
      create: Mock;
      update: Mock;
      count: Mock;
      groupBy: Mock;
    };
    endpointSchemaChange: {
      create: Mock;
      findMany: Mock;
      count: Mock;
    };
  };
} {
  const mocks = {
    signal: {
      create: vi.fn().mockResolvedValue({ id: 'signal-1' }),
      count: vi.fn().mockResolvedValue(0),
      findMany: vi.fn().mockResolvedValue([]),
    },
    endpoint: {
      findFirst: vi.fn().mockResolvedValue(null),
      findMany: vi.fn().mockResolvedValue([]),
      create: vi.fn().mockResolvedValue({ id: 'endpoint-1' }),
      update: vi.fn().mockResolvedValue({ id: 'endpoint-1' }),
      count: vi.fn().mockResolvedValue(0),
      groupBy: vi.fn().mockResolvedValue([]),
    },
    endpointSchemaChange: {
      create: vi.fn().mockResolvedValue({ id: 'change-1' }),
      findMany: vi.fn().mockResolvedValue([]),
      count: vi.fn().mockResolvedValue(0),
    },
  };

  const prisma = {
    signal: mocks.signal,
    endpoint: mocks.endpoint,
    endpointSchemaChange: mocks.endpointSchemaChange,
  } as unknown as PrismaClient;

  return { prisma, mocks };
}

// =============================================================================
// Test Fixtures
// =============================================================================

function createTemplateDiscoverySignal(overrides: Partial<APIIntelligenceSignal> = {}): APIIntelligenceSignal {
  return {
    type: 'TEMPLATE_DISCOVERY',
    sensorId: 'sensor-1',
    timestamp: new Date().toISOString(),
    endpoint: '/api/users/123',
    method: 'GET',
    templatePattern: '/api/users/{id}',
    discoveryConfidence: 0.95,
    parameterTypes: { id: 'uuid' },
    ...overrides,
  };
}

function createSchemaViolationSignal(overrides: Partial<APIIntelligenceSignal> = {}): APIIntelligenceSignal {
  return {
    type: 'SCHEMA_VIOLATION',
    sensorId: 'sensor-1',
    timestamp: new Date().toISOString(),
    endpoint: '/api/users/123',
    method: 'POST',
    violationType: 'type_mismatch',
    violationPath: '$.email',
    violationMessage: 'Expected string, got number',
    expectedSchema: { type: 'string' },
    actualPayload: 12345,
    ...overrides,
  };
}

// =============================================================================
// Signal Ingestion Tests
// =============================================================================

describe('APIIntelligenceService', () => {
  let service: APIIntelligenceService;
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockLogger: Logger;

  beforeEach(() => {
    mockPrisma = createMockPrisma();
    mockLogger = createMockLogger();
    service = new APIIntelligenceService(mockPrisma.prisma, mockLogger);
  });

  describe('Signal Ingestion', () => {
    describe('ingestSignal', () => {
      it('should ingest a TEMPLATE_DISCOVERY signal and store it', async () => {
        const signal = createTemplateDiscoverySignal();

        await service.ingestSignal(signal, 'tenant-1');

        expect(mockPrisma.mocks.signal.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            tenantId: 'tenant-1',
            sensorId: 'sensor-1',
            signalType: 'TEMPLATE_DISCOVERY',
            fingerprint: '/api/users/{id}',
            severity: 'LOW',
          }),
        });
      });

      it('should ingest a SCHEMA_VIOLATION signal and store it', async () => {
        const signal = createSchemaViolationSignal();

        await service.ingestSignal(signal, 'tenant-1');

        expect(mockPrisma.mocks.signal.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            tenantId: 'tenant-1',
            sensorId: 'sensor-1',
            signalType: 'SCHEMA_VIOLATION',
            severity: 'MEDIUM',
          }),
        });
      });

      it('should throw error for TEMPLATE_DISCOVERY without templatePattern', async () => {
        const signal = createTemplateDiscoverySignal({ templatePattern: undefined });

        await expect(service.ingestSignal(signal, 'tenant-1')).rejects.toThrow(
          'TEMPLATE_DISCOVERY requires templatePattern'
        );
      });

      it('should emit signal event on ingestion', async () => {
        const signal = createTemplateDiscoverySignal();
        const eventSpy = vi.fn();
        service.on('signal', eventSpy);

        await service.ingestSignal(signal, 'tenant-1');

        expect(eventSpy).toHaveBeenCalledWith({
          signal,
          tenantId: 'tenant-1',
        });
      });

      it('should emit endpointDiscovered event for new endpoints', async () => {
        const signal = createTemplateDiscoverySignal();
        const eventSpy = vi.fn();
        service.on('endpointDiscovered', eventSpy);

        // Endpoint doesn't exist yet (default mock returns null)
        await service.ingestSignal(signal, 'tenant-1');

        expect(eventSpy).toHaveBeenCalledWith({
          templatePattern: '/api/users/{id}',
          method: 'GET',
          tenantId: 'tenant-1',
        });
      });

      it('should emit schemaViolation event for violations', async () => {
        const signal = createSchemaViolationSignal();
        const eventSpy = vi.fn();
        service.on('schemaViolation', eventSpy);

        await service.ingestSignal(signal, 'tenant-1');

        expect(eventSpy).toHaveBeenCalledWith({
          endpoint: '/api/users/123',
          violationType: 'type_mismatch',
          tenantId: 'tenant-1',
        });
      });

      it('should create endpoint record for new discoveries', async () => {
        const signal = createTemplateDiscoverySignal();

        await service.ingestSignal(signal, 'tenant-1');

        expect(mockPrisma.mocks.endpoint.create).toHaveBeenCalled();
      });

      it('should update endpoint record for existing endpoints', async () => {
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue({
          id: 'existing-endpoint',
          requestCount: 5,
        });
        const signal = createTemplateDiscoverySignal();

        await service.ingestSignal(signal, 'tenant-1');

        expect(mockPrisma.mocks.endpoint.update).toHaveBeenCalledWith({
          where: { id: 'existing-endpoint' },
          data: expect.objectContaining({
            lastSeenAt: expect.any(Date),
            requestCount: { increment: 1 },
          }),
        });
      });
    });

    describe('ingestBatch', () => {
      it('should ingest all signals in a batch', async () => {
        const batch: SignalBatch = {
          batchId: 'batch-1',
          sensorId: 'sensor-1',
          timestamp: new Date().toISOString(),
          signals: [
            createTemplateDiscoverySignal(),
            createSchemaViolationSignal(),
            createTemplateDiscoverySignal({ endpoint: '/api/orders' }),
          ],
        };

        const result = await service.ingestBatch(batch, 'tenant-1');

        expect(result.accepted).toBe(3);
        expect(result.rejected).toBe(0);
        expect(result.batchId).toBe('batch-1');
      });

      it('should count rejected signals when errors occur', async () => {
        mockPrisma.mocks.signal.create
          .mockResolvedValueOnce({ id: 'signal-1' })
          .mockRejectedValueOnce(new Error('DB error'))
          .mockResolvedValueOnce({ id: 'signal-3' });

        const batch: SignalBatch = {
          batchId: 'batch-1',
          sensorId: 'sensor-1',
          timestamp: new Date().toISOString(),
          signals: [
            createTemplateDiscoverySignal(),
            createTemplateDiscoverySignal({ endpoint: '/api/fail' }),
            createTemplateDiscoverySignal({ endpoint: '/api/success' }),
          ],
        };

        const result = await service.ingestBatch(batch, 'tenant-1');

        expect(result.accepted).toBe(2);
        expect(result.rejected).toBe(1);
      });

      it('should handle empty batch gracefully', async () => {
        const batch: SignalBatch = {
          batchId: 'batch-1',
          sensorId: 'sensor-1',
          timestamp: new Date().toISOString(),
          signals: [],
        };

        // This would fail Zod validation in production, but testing service directly
        const result = await service.ingestBatch(batch, 'tenant-1');

        expect(result.accepted).toBe(0);
        expect(result.rejected).toBe(0);
      });
    });
  });

  // ===========================================================================
  // Discovery Processing Tests
  // ===========================================================================

  describe('Discovery Processing', () => {
    describe('processDiscoverySignal', () => {
      it('should create new endpoint on first discovery', async () => {
        const result = await service.processDiscoverySignal({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'TEMPLATE_DISCOVERY',
          metadata: {
            method: 'GET',
            template: '/api/users/{id}',
            path: '/api/users/123',
          },
        });

        expect(result?.created).toBe(true);
        expect(result?.endpointId).toBe('endpoint-1');
        expect(mockPrisma.mocks.endpoint.create).toHaveBeenCalled();
      });

      it('should update existing endpoint on repeat discovery', async () => {
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue({
          id: 'existing-endpoint',
          requestCount: 10,
        });
        mockPrisma.mocks.endpoint.update.mockResolvedValue({
          id: 'existing-endpoint',
        });

        const result = await service.processDiscoverySignal({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'TEMPLATE_DISCOVERY',
          metadata: {
            method: 'GET',
            template: '/api/users/{id}',
          },
        });

        expect(result?.created).toBe(false);
        expect(result?.endpointId).toBe('existing-endpoint');
        expect(mockPrisma.mocks.endpoint.update).toHaveBeenCalled();
      });

      it('should record schema violation for SCHEMA_VIOLATION type', async () => {
        await service.processDiscoverySignal({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'SCHEMA_VIOLATION',
          metadata: {
            method: 'POST',
            path: '/api/users',
            field: '$.name',
            expectedType: 'string',
            receivedType: 'number',
          },
        });

        expect(mockPrisma.mocks.endpointSchemaChange.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            changeType: 'violation',
            field: '$.name',
            oldValue: 'string',
            newValue: 'number',
            riskLevel: 'medium',
          }),
        });
      });

      it('should swallow errors when swallowErrors option is true', async () => {
        mockPrisma.mocks.endpoint.create.mockRejectedValue(new Error('DB error'));

        const result = await service.processDiscoverySignal(
          {
            tenantId: 'tenant-1',
            sensorId: 'sensor-1',
            signalType: 'TEMPLATE_DISCOVERY',
            metadata: {},
          },
          { swallowErrors: true }
        );

        expect(result).toBeNull();
      });

      it('should throw errors when swallowErrors option is false', async () => {
        mockPrisma.mocks.endpoint.create.mockRejectedValue(new Error('DB error'));

        await expect(
          service.processDiscoverySignal(
            {
              tenantId: 'tenant-1',
              sensorId: 'sensor-1',
              signalType: 'TEMPLATE_DISCOVERY',
              metadata: {},
            },
            { swallowErrors: false }
          )
        ).rejects.toThrow('DB error');
      });

      it('should emit events when emitEvents option is true', async () => {
        const signalSpy = vi.fn();
        const discoverySpy = vi.fn();
        service.on('signal', signalSpy);
        service.on('endpointDiscovered', discoverySpy);

        await service.processDiscoverySignal(
          {
            tenantId: 'tenant-1',
            sensorId: 'sensor-1',
            signalType: 'TEMPLATE_DISCOVERY',
            metadata: {
              method: 'GET',
              template: '/api/products/{id}',
            },
          },
          { emitEvents: true }
        );

        expect(signalSpy).toHaveBeenCalled();
        expect(discoverySpy).toHaveBeenCalled();
      });

      it('should store HTTP methods as provided', async () => {
        await service.processDiscoverySignal({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'TEMPLATE_DISCOVERY',
          metadata: {
            method: 'get', // lowercase - service stores as-is
            template: '/api/users/{id}',
          },
        });

        expect(mockPrisma.mocks.endpoint.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            method: 'get', // Method stored as provided
          }),
        });
      });

      it('should handle missing metadata gracefully', async () => {
        const result = await service.processDiscoverySignal({
          tenantId: 'tenant-1',
          sensorId: 'sensor-1',
          signalType: 'TEMPLATE_DISCOVERY',
        });

        expect(result?.created).toBe(true);
        expect(mockPrisma.mocks.endpoint.create).toHaveBeenCalledWith({
          data: expect.objectContaining({
            method: 'UNKNOWN',
            pathTemplate: 'unknown',
          }),
        });
      });
    });
  });

  // ===========================================================================
  // Statistics & Analytics Tests
  // ===========================================================================

  describe('Statistics & Analytics', () => {
    describe('getDiscoveryStats', () => {
      it('should return comprehensive discovery statistics', async () => {
        mockPrisma.mocks.endpoint.count
          .mockResolvedValueOnce(100) // total
          .mockResolvedValueOnce(80) // with schema
          .mockResolvedValueOnce(20) // new this week
          .mockResolvedValueOnce(5); // new today

        mockPrisma.mocks.signal.count
          .mockResolvedValueOnce(15) // violations 24h
          .mockResolvedValueOnce(45); // violations 7d

        mockPrisma.mocks.endpoint.groupBy.mockResolvedValue([
          { method: 'GET', _count: { id: 50 } },
          { method: 'POST', _count: { id: 30 } },
          { method: 'PUT', _count: { id: 15 } },
          { method: 'DELETE', _count: { id: 5 } },
        ]);

        mockPrisma.mocks.signal.findMany.mockResolvedValue([
          { metadata: { endpoint: '/api/users', method: 'POST' } },
          { metadata: { endpoint: '/api/users', method: 'POST' } },
          { metadata: { endpoint: '/api/orders', method: 'GET' } },
        ]);

        mockPrisma.mocks.endpoint.findMany.mockResolvedValue([
          { firstSeenAt: new Date() },
          { firstSeenAt: new Date() },
        ]);

        const stats = await service.getDiscoveryStats('tenant-1');

        expect(stats.totalEndpoints).toBe(100);
        expect(stats.newThisWeek).toBe(20);
        expect(stats.newToday).toBe(5);
        expect(stats.schemaViolations24h).toBe(15);
        expect(stats.schemaViolations7d).toBe(45);
        expect(stats.coveragePercent).toBe(80);
        expect(stats.endpointsByMethod).toEqual({
          GET: 50,
          POST: 30,
          PUT: 15,
          DELETE: 5,
        });
      });

      it('should return top violating endpoints', async () => {
        mockPrisma.mocks.signal.findMany.mockResolvedValue([
          { metadata: { endpoint: '/api/users', method: 'POST' } },
          { metadata: { endpoint: '/api/users', method: 'POST' } },
          { metadata: { endpoint: '/api/users', method: 'POST' } },
          { metadata: { endpoint: '/api/orders', method: 'GET' } },
          { metadata: { endpoint: '/api/orders', method: 'GET' } },
        ]);

        const stats = await service.getDiscoveryStats('tenant-1');

        expect(stats.topViolatingEndpoints).toHaveLength(2);
        expect(stats.topViolatingEndpoints[0]).toEqual({
          endpoint: '/api/users',
          method: 'POST',
          violationCount: 3,
        });
      });

      it('should return discovery trend for the past week', async () => {
        const today = new Date();
        const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

        mockPrisma.mocks.endpoint.findMany.mockResolvedValue([
          { firstSeenAt: today },
          { firstSeenAt: today },
          { firstSeenAt: yesterday },
        ]);

        const stats = await service.getDiscoveryStats('tenant-1');

        expect(stats.discoveryTrend).toHaveLength(7);
        expect(stats.discoveryTrend.every((t) => typeof t.date === 'string')).toBe(true);
        expect(stats.discoveryTrend.every((t) => typeof t.count === 'number')).toBe(true);
      });

      it('should handle empty results gracefully', async () => {
        const stats = await service.getDiscoveryStats('tenant-1');

        expect(stats.totalEndpoints).toBe(0);
        expect(stats.newThisWeek).toBe(0);
        expect(stats.schemaViolations24h).toBe(0);
        expect(stats.topViolatingEndpoints).toHaveLength(0);
        expect(stats.endpointsByMethod).toEqual({});
      });
    });

    describe('getViolationTrends', () => {
      it('should return violation trends grouped by date and type', async () => {
        const today = new Date();
        const todayStr = today.toISOString().split('T')[0];

        mockPrisma.mocks.signal.findMany.mockResolvedValue([
          { createdAt: today, metadata: { violationType: 'type_mismatch' } },
          { createdAt: today, metadata: { violationType: 'type_mismatch' } },
          { createdAt: today, metadata: { violationType: 'missing_required_field' } },
        ]);

        const trends = await service.getViolationTrends('tenant-1', 7);

        expect(trends).toContainEqual({
          date: todayStr,
          type: 'type_mismatch',
          count: 2,
        });
        expect(trends).toContainEqual({
          date: todayStr,
          type: 'missing_required_field',
          count: 1,
        });
      });

      it('should handle violations without violationType', async () => {
        mockPrisma.mocks.signal.findMany.mockResolvedValue([
          { createdAt: new Date(), metadata: {} },
          { createdAt: new Date(), metadata: null },
        ]);

        const trends = await service.getViolationTrends('tenant-1', 7);

        const unknownTrends = trends.filter((t) => t.type === 'unknown');
        expect(unknownTrends.length).toBeGreaterThan(0);
      });

      it('should return sorted results by date', async () => {
        const today = new Date();
        const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

        mockPrisma.mocks.signal.findMany.mockResolvedValue([
          { createdAt: today, metadata: { violationType: 'type_mismatch' } },
          { createdAt: yesterday, metadata: { violationType: 'type_mismatch' } },
        ]);

        const trends = await service.getViolationTrends('tenant-1', 7);

        const dates = trends.map((t) => t.date);
        expect(dates).toEqual([...dates].sort());
      });
    });

    describe('getFleetInventory', () => {
      it('should group endpoints by service and compute totals', async () => {
        const now = new Date();
        mockPrisma.mocks.endpoint.findMany.mockResolvedValue([
          {
            id: '1',
            path: '/api/users',
            pathTemplate: '/api/users',
            method: 'GET',
            service: 'user-service',
            sensorId: 'sensor-1',
            requestCount: 10,
            riskLevel: 'low',
            lastSeenAt: now,
          },
          {
            id: '2',
            path: '/api/orders',
            pathTemplate: '/api/orders',
            method: 'POST',
            service: 'order-service',
            sensorId: 'sensor-1',
            requestCount: 5,
            riskLevel: 'high',
            lastSeenAt: now,
          },
          {
            id: '3',
            path: '/api/users/{id}',
            pathTemplate: '/api/users/{id}',
            method: 'GET',
            service: 'user-service',
            sensorId: 'sensor-2',
            requestCount: 20,
            riskLevel: 'medium',
            lastSeenAt: now,
          },
        ]);

        const inventory = await service.getFleetInventory('tenant-1', {
          maxServices: 10,
          maxEndpoints: 10,
        });

        expect(inventory.totalEndpoints).toBe(3);
        expect(inventory.totalRequests).toBe(35);
        expect(inventory.services).toHaveLength(2);

        const userService = inventory.services.find((s) => s.service === 'user-service');
        expect(userService?.endpointCount).toBe(2);
        expect(userService?.totalRequests).toBe(30);
      });
    });

    describe('listSchemaChanges', () => {
      it('should map schema change details with endpoint context', async () => {
        const now = new Date();
        mockPrisma.mocks.endpointSchemaChange.findMany.mockResolvedValue([
          {
            id: 'change-1',
            changeType: 'violation',
            field: 'body.amount',
            oldValue: 'number',
            newValue: 'string',
            riskLevel: 'high',
            detectedAt: now,
            endpoint: {
              path: '/api/checkout',
              pathTemplate: '/api/checkout',
              method: 'POST',
              service: 'payment-service',
            },
          },
        ]);
        mockPrisma.mocks.endpointSchemaChange.count.mockResolvedValue(1);

        const result = await service.listSchemaChanges('tenant-1', {
          limit: 10,
          offset: 0,
        });

        expect(result.total).toBe(1);
        expect(result.changes[0]).toMatchObject({
          endpoint: '/api/checkout',
          method: 'POST',
          service: 'payment-service',
          changeType: 'violation',
          field: 'body.amount',
          breaking: true,
        });
      });
    });

    describe('getSchemaDriftTrends', () => {
      it('should aggregate schema drift trends by endpoint', async () => {
        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        mockPrisma.mocks.endpointSchemaChange.findMany.mockResolvedValue([
          {
            detectedAt: yesterday,
            endpoint: {
              path: '/api/users',
              pathTemplate: '/api/users',
              method: 'GET',
              service: 'user-service',
            },
          },
          {
            detectedAt: yesterday,
            endpoint: {
              path: '/api/users',
              pathTemplate: '/api/users',
              method: 'GET',
              service: 'user-service',
            },
          },
          {
            detectedAt: now,
            endpoint: {
              path: '/api/orders',
              pathTemplate: '/api/orders',
              method: 'POST',
              service: 'order-service',
            },
          },
        ]);

        const trends = await service.getSchemaDriftTrends('tenant-1', 2, 5);

        expect(trends[0].endpoint).toBe('/api/users');
        expect(trends[0].total).toBe(2);
        expect(trends[1].endpoint).toBe('/api/orders');
        expect(trends[1].total).toBe(1);
      });
    });
  });

  // ===========================================================================
  // Listing & Querying Tests
  // ===========================================================================

  describe('Listing & Querying', () => {
    describe('listEndpoints', () => {
      it('should return paginated endpoints', async () => {
        const mockEndpoints = [
          { id: '1', path: '/api/users' },
          { id: '2', path: '/api/orders' },
        ];
        mockPrisma.mocks.endpoint.findMany.mockResolvedValue(mockEndpoints);
        mockPrisma.mocks.endpoint.count.mockResolvedValue(100);

        const result = await service.listEndpoints('tenant-1', {
          limit: 10,
          offset: 0,
        });

        expect(result.endpoints).toEqual(mockEndpoints);
        expect(result.total).toBe(100);
        expect(mockPrisma.mocks.endpoint.findMany).toHaveBeenCalledWith({
          where: { tenantId: 'tenant-1' },
          take: 10,
          skip: 0,
          orderBy: { lastSeenAt: 'desc' },
        });
      });

      it('should filter by method when provided', async () => {
        await service.listEndpoints('tenant-1', {
          method: 'POST',
        });

        expect(mockPrisma.mocks.endpoint.findMany).toHaveBeenCalledWith({
          where: { tenantId: 'tenant-1', method: 'POST' },
          take: 50, // default
          skip: 0, // default
          orderBy: { lastSeenAt: 'desc' },
        });
      });

      it('should use default pagination values', async () => {
        await service.listEndpoints('tenant-1', {});

        expect(mockPrisma.mocks.endpoint.findMany).toHaveBeenCalledWith({
          where: { tenantId: 'tenant-1' },
          take: 50,
          skip: 0,
          orderBy: { lastSeenAt: 'desc' },
        });
      });
    });

    describe('listSignals', () => {
      it('should return paginated signals', async () => {
        const mockSignals = [
          { id: '1', signalType: 'TEMPLATE_DISCOVERY' },
          { id: '2', signalType: 'SCHEMA_VIOLATION' },
        ];
        mockPrisma.mocks.signal.findMany.mockResolvedValue(mockSignals);
        mockPrisma.mocks.signal.count.mockResolvedValue(50);

        const result = await service.listSignals('tenant-1', {
          limit: 20,
          offset: 10,
        });

        expect(result.signals).toEqual(mockSignals);
        expect(result.total).toBe(50);
      });

      it('should filter by signal type when provided', async () => {
        await service.listSignals('tenant-1', {
          type: 'SCHEMA_VIOLATION',
        });

        expect(mockPrisma.mocks.signal.findMany).toHaveBeenCalledWith({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
            signalType: 'SCHEMA_VIOLATION',
          }),
          take: 50,
          skip: 0,
          orderBy: { createdAt: 'desc' },
        });
      });

      it('should filter by sensorId when provided', async () => {
        await service.listSignals('tenant-1', {
          sensorId: 'sensor-42',
        });

        expect(mockPrisma.mocks.signal.findMany).toHaveBeenCalledWith({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
            sensorId: 'sensor-42',
          }),
          take: 50,
          skip: 0,
          orderBy: { createdAt: 'desc' },
        });
      });
    });

    describe('getEndpoint', () => {
      it('should return endpoint by id', async () => {
        const mockEndpoint = { id: 'endpoint-1', path: '/api/users' };
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue(mockEndpoint);

        const result = await service.getEndpoint('endpoint-1', 'tenant-1');

        expect(result).toEqual(mockEndpoint);
        expect(mockPrisma.mocks.endpoint.findFirst).toHaveBeenCalledWith({
          where: { id: 'endpoint-1', tenantId: 'tenant-1' },
        });
      });

      it('should return null for non-existent endpoint', async () => {
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue(null);

        const result = await service.getEndpoint('non-existent', 'tenant-1');

        expect(result).toBeNull();
      });

      it('should enforce tenant isolation', async () => {
        await service.getEndpoint('endpoint-1', 'tenant-1');

        expect(mockPrisma.mocks.endpoint.findFirst).toHaveBeenCalledWith({
          where: { id: 'endpoint-1', tenantId: 'tenant-1' },
        });
      });
    });

    describe('getEndpointByTemplate', () => {
      it('should find endpoint by template pattern and method', async () => {
        const mockEndpoint = {
          id: 'endpoint-1',
          pathTemplate: '/api/users/{id}',
          method: 'GET',
        };
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue(mockEndpoint);

        const result = await service.getEndpointByTemplate(
          'tenant-1',
          '/api/users/{id}',
          'GET'
        );

        expect(result).toEqual(mockEndpoint);
        expect(mockPrisma.mocks.endpoint.findFirst).toHaveBeenCalledWith({
          where: {
            tenantId: 'tenant-1',
            pathTemplate: '/api/users/{id}',
            method: 'GET',
          },
        });
      });

      it('should return null when no match found', async () => {
        mockPrisma.mocks.endpoint.findFirst.mockResolvedValue(null);

        const result = await service.getEndpointByTemplate(
          'tenant-1',
          '/api/non-existent',
          'GET'
        );

        expect(result).toBeNull();
      });
    });
  });

  // ===========================================================================
  // Event Emission Tests
  // ===========================================================================

  describe('Event Emission', () => {
    it('should extend EventEmitter', () => {
      expect(service).toHaveProperty('on');
      expect(service).toHaveProperty('emit');
      expect(service).toHaveProperty('removeListener');
    });

    it('should support multiple listeners', async () => {
      const listener1 = vi.fn();
      const listener2 = vi.fn();
      service.on('signal', listener1);
      service.on('signal', listener2);

      await service.ingestSignal(createTemplateDiscoverySignal(), 'tenant-1');

      expect(listener1).toHaveBeenCalled();
      expect(listener2).toHaveBeenCalled();
    });

    it('should not emit endpointDiscovered for existing endpoints', async () => {
      mockPrisma.mocks.endpoint.findFirst.mockResolvedValue({
        id: 'existing',
        requestCount: 100,
      });

      const discoverySpy = vi.fn();
      service.on('endpointDiscovered', discoverySpy);

      await service.ingestSignal(createTemplateDiscoverySignal(), 'tenant-1');

      expect(discoverySpy).not.toHaveBeenCalled();
    });
  });

  // ===========================================================================
  // Edge Cases & Error Handling
  // ===========================================================================

  describe('Edge Cases & Error Handling', () => {
    it('should handle special characters in endpoint paths', async () => {
      const signal = createTemplateDiscoverySignal({
        endpoint: '/api/users/john%20doe/profile',
        templatePattern: '/api/users/{username}/profile',
      });

      await service.ingestSignal(signal, 'tenant-1');

      expect(mockPrisma.mocks.signal.create).toHaveBeenCalled();
    });

    it('should handle very long endpoint paths', async () => {
      const longPath = '/api/' + 'a'.repeat(1000);
      const signal = createTemplateDiscoverySignal({
        endpoint: longPath,
        templatePattern: longPath,
      });

      await service.ingestSignal(signal, 'tenant-1');

      expect(mockPrisma.mocks.signal.create).toHaveBeenCalled();
    });

    it('should handle unicode in violation messages', async () => {
      const signal = createSchemaViolationSignal({
        violationMessage: '预期字符串，收到数字 🚫',
      });

      await service.ingestSignal(signal, 'tenant-1');

      expect(mockPrisma.mocks.signal.create).toHaveBeenCalled();
    });

    it('should handle null metadata values gracefully', async () => {
      const signal = createSchemaViolationSignal({
        expectedSchema: null,
        actualPayload: null,
      });

      await service.ingestSignal(signal, 'tenant-1');

      expect(mockPrisma.mocks.signal.create).toHaveBeenCalled();
    });

    it('should handle database errors gracefully', async () => {
      mockPrisma.mocks.signal.create.mockRejectedValue(new Error('Database connection lost'));

      await expect(
        service.ingestSignal(createTemplateDiscoverySignal(), 'tenant-1')
      ).rejects.toThrow('Database connection lost');
    });
  });
});
