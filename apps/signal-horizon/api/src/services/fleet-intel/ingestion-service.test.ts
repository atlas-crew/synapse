/**
 * Fleet Intel Ingestion Service Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { SynapseProxyService } from '../synapse-proxy.js';
import { FleetIntelIngestionService } from './ingestion-service.js';

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

describe('FleetIntelIngestionService', () => {
  let mockPrisma: Partial<PrismaClient>;
  let mockSynapse: Partial<SynapseProxyService>;

  beforeEach(() => {
    mockPrisma = {
      sensor: {
        findMany: vi.fn().mockResolvedValue([
          { id: 'sensor-1', tenantId: 'tenant-1' },
        ]),
      } as unknown as PrismaClient['sensor'],
      sensorIntelActor: {
        upsert: vi.fn().mockResolvedValue({}),
      } as unknown as PrismaClient['sensorIntelActor'],
      sensorIntelSession: {
        upsert: vi.fn().mockResolvedValue({}),
      } as unknown as PrismaClient['sensorIntelSession'],
      sensorIntelCampaign: {
        upsert: vi.fn().mockResolvedValue({}),
      } as unknown as PrismaClient['sensorIntelCampaign'],
      sensorIntelProfile: {
        upsert: vi.fn().mockResolvedValue({}),
      } as unknown as PrismaClient['sensorIntelProfile'],
      sensorPayloadSnapshot: {
        create: vi.fn().mockResolvedValue({}),
      } as unknown as PrismaClient['sensorPayloadSnapshot'],
    };

    const now = Date.now();
    const nowIso = new Date(now).toISOString();

    mockSynapse = {
      listActors: vi.fn().mockResolvedValue({
        actors: [
          {
            actorId: 'actor-1',
            riskScore: 55,
            isBlocked: false,
            firstSeen: now,
            lastSeen: now,
            ips: ['1.1.1.1'],
            fingerprints: ['fp-1'],
            sessionIds: ['session-1'],
          },
        ],
        stats: null,
      }),
      listSessions: vi.fn().mockResolvedValue({
        sessions: [
          {
            sessionId: 'session-1',
            tokenHash: 'token',
            actorId: 'actor-1',
            creationTime: now,
            lastActivity: now,
            requestCount: 4,
            isSuspicious: false,
            hijackAlerts: [],
          },
        ],
        stats: null,
      }),
      listCampaigns: vi.fn().mockResolvedValue({
        data: [
          {
            id: 'campaign-1',
            status: 'active',
            actorCount: 2,
            confidence: 0.7,
            attackTypes: ['sql_injection'],
            firstSeen: nowIso,
            lastActivity: nowIso,
            totalRequests: 100,
            blockedRequests: 5,
            rulesTriggered: 2,
            riskScore: 70,
          },
        ],
      }),
      listProfiles: vi.fn().mockResolvedValue({
        success: true,
        data: {
          profiles: [
            {
              template: '/login',
              sampleCount: 1,
              firstSeenMs: now,
              lastUpdatedMs: now,
              payloadSize: { mean: 0, variance: 0, stdDev: 0, count: 1 },
              expectedParams: {},
              contentTypes: {},
              statusCodes: {},
              endpointRisk: 0,
              currentRps: 0,
            },
          ],
          count: 1,
        },
      }),
      getPayloadStats: vi.fn().mockResolvedValue({
        success: true,
        data: {
          total_endpoints: 0,
          total_entities: 0,
          total_requests: 10,
          total_request_bytes: 100,
          total_response_bytes: 200,
          avg_request_size: 10,
          avg_response_size: 20,
          active_anomalies: 0,
        },
      }),
      getPayloadEndpoints: vi.fn().mockResolvedValue({ success: true, data: [] }),
      getPayloadAnomalies: vi.fn().mockResolvedValue({ success: true, data: [] }),
      getPayloadBandwidth: vi.fn().mockResolvedValue({
        totalBytes: 0,
        totalBytesIn: 0,
        totalBytesOut: 0,
        avgBytesPerRequest: 0,
        maxRequestSize: 0,
        maxResponseSize: 0,
        requestCount: 0,
        timeline: [],
      }),
    };
  });

  it('ingests connected sensors data', async () => {
    const service = new FleetIntelIngestionService(
      mockPrisma as PrismaClient,
      mockSynapse as SynapseProxyService,
      mockLogger,
      { maxPages: 1 }
    );

    await service.ingestFleet();

    expect(mockPrisma.sensor!.findMany).toHaveBeenCalled();
    expect(mockPrisma.sensorIntelActor!.upsert).toHaveBeenCalled();
    expect(mockPrisma.sensorIntelSession!.upsert).toHaveBeenCalled();
    expect(mockPrisma.sensorIntelCampaign!.upsert).toHaveBeenCalled();
    expect(mockPrisma.sensorIntelProfile!.upsert).toHaveBeenCalled();
    expect(mockPrisma.sensorPayloadSnapshot!.create).toHaveBeenCalled();
  });

  it('continues ingestion when an endpoint fails', async () => {
    vi.mocked(mockSynapse.listSessions!).mockRejectedValue(new Error('timeout'));

    const service = new FleetIntelIngestionService(
      mockPrisma as PrismaClient,
      mockSynapse as SynapseProxyService,
      mockLogger,
      { maxPages: 1 }
    );

    await expect(service.ingestFleet()).resolves.toBeUndefined();
    expect(mockPrisma.sensorIntelActor!.upsert).toHaveBeenCalled();
  });
});
