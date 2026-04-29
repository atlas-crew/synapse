import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { PayloadAggregatorService } from './payload-aggregator.js';

function createMockPrisma(): PrismaClient {
  return {
    sensor: {
      findMany: vi.fn(),
    },
    sensorPayloadSnapshot: {
      findMany: vi.fn(),
    },
  } as unknown as PrismaClient;
}

describe('PayloadAggregatorService', () => {
  let prisma: PrismaClient;
  let service: PayloadAggregatorService;

  beforeEach(() => {
    prisma = createMockPrisma();
    service = new PayloadAggregatorService(prisma);
  });

  it('marks sensors without DLP snapshot data as errors instead of zero-filled success', async () => {
    vi.mocked(prisma.sensor.findMany).mockResolvedValue([
      { id: 'sensor-1', name: 'edge-east' },
      { id: 'sensor-2', name: 'edge-west' },
    ] as any);
    vi.mocked(prisma.sensorPayloadSnapshot.findMany).mockResolvedValue([
      {
        sensorId: 'sensor-1',
        capturedAt: new Date('2026-04-18T12:00:00Z'),
        stats: {
          dlp: {
            totalScans: 12,
            totalMatches: 2,
            patternCount: 4,
            violations: [],
          },
        },
        bandwidth: null,
        endpoints: null,
        anomalies: null,
      },
      {
        sensorId: 'sensor-2',
        capturedAt: new Date('2026-04-18T12:01:00Z'),
        stats: {},
        bandwidth: null,
        endpoints: null,
        anomalies: null,
      },
    ] as any);

    const result = await service.getDlpStats('tenant-1');

    expect(result.summary).toEqual({ succeeded: 1, stale: 0, failed: 1 });
    expect(result.aggregate).toEqual({
      totalScans: 12,
      totalMatches: 2,
      patternCount: 4,
    });
    expect(result.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: 'sensor-2',
          status: 'error',
          error: 'No DLP data in payload snapshot',
        }),
      ])
    );
  });

  it('marks malformed endpoint summaries as errors instead of coercing numeric fields to zero', async () => {
    vi.mocked(prisma.sensor.findMany).mockResolvedValue([
      { id: 'sensor-1', name: 'edge-east' },
    ] as any);
    vi.mocked(prisma.sensorPayloadSnapshot.findMany).mockResolvedValue([
      {
        sensorId: 'sensor-1',
        capturedAt: new Date('2026-04-18T12:00:00Z'),
        stats: null,
        bandwidth: null,
        endpoints: [
          {
            template: '/checkout',
            request_count: 'oops',
            avg_request_size: 10,
            avg_response_size: 20,
          },
        ],
        anomalies: null,
      },
    ] as any);

    const result = await service.getPayloadEndpoints('tenant-1');

    expect(result.summary).toEqual({ succeeded: 0, stale: 0, failed: 1 });
    expect(result.aggregate).toEqual([]);
    expect(result.results).toEqual([
      expect.objectContaining({
        sensorId: 'sensor-1',
        status: 'error',
        error: 'Payload endpoint snapshot is unavailable',
      }),
    ]);
  });

  it('merges endpoint averages across more than two sensors using weighted request counts', async () => {
    vi.mocked(prisma.sensor.findMany).mockResolvedValue([
      { id: 'sensor-1', name: 'edge-east' },
      { id: 'sensor-2', name: 'edge-west' },
      { id: 'sensor-3', name: 'edge-central' },
    ] as any);
    vi.mocked(prisma.sensorPayloadSnapshot.findMany).mockResolvedValue([
      {
        sensorId: 'sensor-1',
        capturedAt: new Date('2026-04-18T12:00:00Z'),
        stats: null,
        bandwidth: null,
        endpoints: [{ template: '/checkout', request_count: 100, avg_request_size: 50, avg_response_size: 80 }],
        anomalies: null,
      },
      {
        sensorId: 'sensor-2',
        capturedAt: new Date('2026-04-18T12:01:00Z'),
        stats: null,
        bandwidth: null,
        endpoints: [{ template: '/checkout', request_count: 200, avg_request_size: 80, avg_response_size: 110 }],
        anomalies: null,
      },
      {
        sensorId: 'sensor-3',
        capturedAt: new Date('2026-04-18T12:02:00Z'),
        stats: null,
        bandwidth: null,
        endpoints: [{ template: '/checkout', request_count: 300, avg_request_size: 60, avg_response_size: 95 }],
        anomalies: null,
      },
    ] as any);

    const result = await service.getPayloadEndpoints('tenant-1');

    expect(result.summary).toEqual({ succeeded: 3, stale: 0, failed: 0 });
    expect(result.aggregate).toEqual([
      expect.objectContaining({
        template: '/checkout',
        request_count: 600,
        avg_request_size: 65,
        avg_response_size: 97.5,
      }),
    ]);
  });

  it('uses the snapshot capture time when telemetry entries omit timestamps', async () => {
    const capturedAt = new Date('2026-04-18T12:30:00Z');
    vi.mocked(prisma.sensor.findMany).mockResolvedValue([
      { id: 'sensor-1', name: 'edge-east' },
    ] as any);
    vi.mocked(prisma.sensorPayloadSnapshot.findMany).mockResolvedValue([
      {
        sensorId: 'sensor-1',
        capturedAt,
        stats: {
          dlp: {
            totalScans: 1,
            totalMatches: 1,
            patternCount: 1,
            violations: [
              {
                pattern_name: 'Access Token',
                data_type: 'api_key',
                severity: 'high',
                masked_value: 'tok_********',
                path: '/oauth/token',
              },
            ],
          },
        },
        bandwidth: {
          totalBytes: 10,
          totalBytesIn: 4,
          totalBytesOut: 6,
          avgBytesPerRequest: 10,
          maxRequestSize: 4,
          maxResponseSize: 6,
          requestCount: 1,
          timeline: [
            {
              bytesIn: 4,
              bytesOut: 6,
              requestCount: 1,
            },
          ],
        },
        endpoints: [],
        anomalies: [
          {
            anomaly_type: 'payload',
            severity: 'medium',
            template: '/oauth/token',
            entity_id: 'ent-1',
            description: 'Missing timestamp',
          },
        ],
      },
    ] as any);

    const [violations, bandwidth, anomalies] = await Promise.all([
      service.getDlpViolations('tenant-1'),
      service.getPayloadBandwidth('tenant-1'),
      service.getPayloadAnomalies('tenant-1'),
    ]);

    expect(violations.aggregate[0]?.timestamp).toBe(capturedAt.getTime());
    expect(bandwidth.aggregate.timeline[0]?.timestamp).toBe(capturedAt.getTime());
    expect(anomalies.aggregate[0]?.detected_at_ms).toBe(capturedAt.getTime());
  });
});
