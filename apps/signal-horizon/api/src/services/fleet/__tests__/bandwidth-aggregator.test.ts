/**
 * Bandwidth Aggregator Service Tests
 *
 * P1 reliability tests for fleet-wide bandwidth metrics aggregation:
 * - Division by zero safety
 * - Empty sensor handling
 * - Multi-sensor aggregation
 * - Billing calculation accuracy
 * - Timeline data generation
 * - Demo/fallback mode data generation
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { BandwidthAggregatorService } from '../bandwidth-aggregator.js';
import type { TunnelBroker } from '../../../websocket/tunnel-broker.js';

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
  return {
    sensor: {
      findMany: vi.fn().mockResolvedValue([]),
      findFirst: vi.fn().mockResolvedValue(null),
    },
  } as unknown as PrismaClient;
}

function createMockTunnelBroker(responses: Map<string, unknown>): TunnelBroker {
  return {
    getSensorTunnelInfo: vi.fn().mockImplementation((sensorId: string) => {
      return responses.has(sensorId) ? { connected: true } : null;
    }),
    sendRequest: vi.fn().mockImplementation((sensorId: string) => {
      const data = responses.get(sensorId);
      if (data) {
        return Promise.resolve({ type: 'bandwidth-stats', payload: data });
      }
      return Promise.reject(new Error('Sensor not connected'));
    }),
  } as unknown as TunnelBroker;
}

describe('BandwidthAggregatorService', () => {
  let prisma: PrismaClient;
  let logger: Logger;

  beforeEach(() => {
    prisma = createMockPrisma();
    logger = createMockLogger();
  });

  describe('Division by zero safety', () => {
    it('should return 0 avgBytesPerRequest when totalRequests is 0', async () => {
      const sensorData = new Map<string, unknown>();
      sensorData.set('sensor-1', {
        totalBytesIn: 0,
        totalBytesOut: 0,
        requestCount: 0,
        maxRequestSize: 0,
        maxResponseSize: 0,
        timeline: [],
        endpointStats: [],
      });

      const broker = createMockTunnelBroker(sensorData);

      vi.mocked(prisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', name: 'test-sensor', region: 'us-east-1', connectionState: 'CONNECTED' },
      ] as any);

      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: false }, broker);
      const result = await service.getFleetBandwidth('tenant-1');

      expect(result.avgBytesPerRequest).toBe(0);
      expect(Number.isNaN(result.avgBytesPerRequest)).toBe(false);
    });
  });

  describe('Empty sensors array', () => {
    it('should return empty fleet stats when tenant has no sensors', async () => {
      vi.mocked(prisma.sensor.findMany).mockResolvedValue([]);

      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: false });
      const result = await service.getFleetBandwidth('tenant-empty');

      expect(result.totalBytesIn).toBe(0);
      expect(result.totalBytesOut).toBe(0);
      expect(result.totalRequests).toBe(0);
      expect(result.avgBytesPerRequest).toBe(0);
      expect(result.peakBytesIn).toBe(0);
      expect(result.peakBytesOut).toBe(0);
      expect(result.sensorCount).toBe(0);
      expect(result.respondedSensors).toBe(0);
    });
  });

  describe('Multi-sensor aggregation', () => {
    it('should correctly aggregate bandwidth across multiple responding sensors', async () => {
      const sensorData = new Map<string, unknown>();
      sensorData.set('sensor-1', {
        totalBytesIn: 1000,
        totalBytesOut: 2000,
        requestCount: 100,
        maxRequestSize: 500,
        maxResponseSize: 1000,
        timeline: [
          { timestamp: Date.now(), bytesIn: 800, bytesOut: 1500, requestCount: 80 },
        ],
        endpointStats: [],
      });
      sensorData.set('sensor-2', {
        totalBytesIn: 3000,
        totalBytesOut: 4000,
        requestCount: 200,
        maxRequestSize: 600,
        maxResponseSize: 1200,
        timeline: [
          { timestamp: Date.now(), bytesIn: 2500, bytesOut: 3500, requestCount: 150 },
        ],
        endpointStats: [],
      });

      const broker = createMockTunnelBroker(sensorData);

      vi.mocked(prisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', name: 'sensor-a', region: 'us-east-1', connectionState: 'CONNECTED' },
        { id: 'sensor-2', name: 'sensor-b', region: 'eu-west-1', connectionState: 'CONNECTED' },
      ] as any);

      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: false }, broker);
      const result = await service.getFleetBandwidth('tenant-1');

      expect(result.totalBytesIn).toBe(4000);
      expect(result.totalBytesOut).toBe(6000);
      expect(result.totalRequests).toBe(300);
      // avgBytesPerRequest = Math.round((4000 + 6000) / 300) = Math.round(33.33) = 33
      expect(result.avgBytesPerRequest).toBe(33);
      expect(result.respondedSensors).toBe(2);
      expect(result.sensorCount).toBe(2);
      // Peak should be the max across all timeline points
      expect(result.peakBytesIn).toBe(2500);
      expect(result.peakBytesOut).toBe(3500);
    });
  });

  describe('Billing calculation accuracy', () => {
    it('should calculate estimatedCost from total data transfer and cost per GB', async () => {
      // Set up a sensor that reports exactly 1 GB in + 1 GB out = 2 GB total
      const oneGb = 1024 * 1024 * 1024;
      const sensorData = new Map<string, unknown>();
      sensorData.set('sensor-1', {
        totalBytesIn: oneGb,
        totalBytesOut: oneGb,
        requestCount: 1000,
        maxRequestSize: 1024,
        maxResponseSize: 2048,
        timeline: [],
        endpointStats: [],
      });

      const broker = createMockTunnelBroker(sensorData);

      vi.mocked(prisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1', name: 'billing-sensor', region: 'us-east-1', connectionState: 'CONNECTED' },
      ] as any);

      const costPerGb = 0.10; // $0.10/GB for easy calculation
      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: false, defaultCostPerGb: costPerGb }, broker);
      const result = await service.getBillingMetrics({
        tenantId: 'tenant-billing',
        start: new Date('2025-01-01'),
        end: new Date('2025-02-01'),
        costPerGb,
      });

      // 2 GB * $0.10/GB = $0.20
      expect(result.totalDataTransfer).toBe(2 * oneGb);
      expect(result.ingressBytes).toBe(oneGb);
      expect(result.egressBytes).toBe(oneGb);
      expect(result.estimatedCost).toBe(0.2);
      expect(result.costPerGb).toBe(costPerGb);
    });
  });

  describe('Timeline data generation', () => {
    it('should bucket timeline data by granularity and sum totals', async () => {
      const bucketSizeMs = 300000; // 5m
      const baseTimestamp = Math.floor(Date.now() / bucketSizeMs) * bucketSizeMs;

      const sensorData = new Map<string, unknown>();
      sensorData.set('sensor-1', {
        totalBytesIn: 500,
        totalBytesOut: 600,
        requestCount: 20,
        maxRequestSize: 100,
        maxResponseSize: 200,
        timeline: [
          { timestamp: baseTimestamp, bytesIn: 100, bytesOut: 200, requestCount: 5 },
          { timestamp: baseTimestamp + bucketSizeMs, bytesIn: 150, bytesOut: 250, requestCount: 7 },
        ],
        endpointStats: [],
      });
      sensorData.set('sensor-2', {
        totalBytesIn: 300,
        totalBytesOut: 400,
        requestCount: 10,
        maxRequestSize: 80,
        maxResponseSize: 150,
        timeline: [
          // Same bucket as sensor-1's first point -- should be summed
          { timestamp: baseTimestamp, bytesIn: 50, bytesOut: 75, requestCount: 3 },
        ],
        endpointStats: [],
      });

      const broker = createMockTunnelBroker(sensorData);

      vi.mocked(prisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-1' },
        { id: 'sensor-2' },
      ] as any);

      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: false }, broker);
      const result = await service.getBandwidthTimeline({
        tenantId: 'tenant-1',
        granularity: '5m',
        durationMinutes: 60,
      });

      // There should be 2 distinct buckets
      expect(result.points.length).toBe(2);

      // First bucket: sensor-1 (100,200,5) + sensor-2 (50,75,3)
      const firstBucket = result.points.find(
        (p) => p.timestamp.getTime() === baseTimestamp
      );
      expect(firstBucket).toBeDefined();
      expect(firstBucket!.bytesIn).toBe(150);
      expect(firstBucket!.bytesOut).toBe(275);
      expect(firstBucket!.requestCount).toBe(8);

      // Totals should sum all points
      expect(result.totalBytesIn).toBe(300); // 150 + 150
      expect(result.totalBytesOut).toBe(525); // 275 + 250
      expect(result.granularity).toBe('5m');
    });
  });

  describe('Demo/fallback mode', () => {
    it('should return demo fleet stats when no sensors respond and demoMode is enabled', async () => {
      // Sensors exist but none have tunnels connected
      vi.mocked(prisma.sensor.findMany).mockResolvedValue([
        { id: 'sensor-offline-1', name: 'offline-1', region: 'us-east-1', connectionState: 'DISCONNECTED' },
        { id: 'sensor-offline-2', name: 'offline-2', region: 'eu-west-1', connectionState: 'DISCONNECTED' },
      ] as any);

      // No tunnel broker at all => all queries return failure
      const service = new BandwidthAggregatorService(prisma, logger, { demoMode: true });
      const result = await service.getFleetBandwidth('tenant-demo');

      // Demo mode should populate with non-zero data
      expect(result.totalBytesIn).toBeGreaterThan(0);
      expect(result.totalBytesOut).toBeGreaterThan(0);
      expect(result.totalRequests).toBeGreaterThan(0);
      expect(result.sensorCount).toBe(2);
      expect(result.respondedSensors).toBe(2); // demo pretends all responded
      expect(result.collectedAt).toBeInstanceOf(Date);
    });
  });
});
