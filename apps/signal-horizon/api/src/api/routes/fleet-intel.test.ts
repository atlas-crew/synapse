/**
 * Fleet Intel Routes Test Suite
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createFleetIntelRoutes } from './fleet-intel.js';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';

vi.mock('../middleware/auth.js', () => ({
  requireScope: (_scope: string) => (req: Request, _res: Response, next: NextFunction) => {
    if (req.auth?.scopes?.some((s: string) => s.startsWith('fleet:'))) {
      return next();
    }
    _res.status(403).json({ error: 'Forbidden' });
  },
}));

vi.mock('../middleware/validation.js', () => ({
  validateQuery: () => (_req: Request, _res: Response, next: NextFunction) => next(),
}));

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

const injectAuth = (tenantId: string, scopes: string[] = ['fleet:read']) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = { tenantId, scopes } as unknown as typeof req.auth;
    next();
  };
};

describe('Fleet Intel Routes', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    mockPrisma = {
      sensorIntelActor: {
        findMany: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensorIntelActor'],
      sensorIntelSession: {
        findMany: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensorIntelSession'],
      sensorIntelCampaign: {
        findMany: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensorIntelCampaign'],
      sensorIntelProfile: {
        findMany: vi.fn(),
        count: vi.fn(),
      } as unknown as PrismaClient['sensorIntelProfile'],
      sensorPayloadSnapshot: {
        findFirst: vi.fn(),
      } as unknown as PrismaClient['sensorPayloadSnapshot'],
    };

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1'));
    app.use('/fleet/intel', createFleetIntelRoutes(mockPrisma as PrismaClient, mockLogger));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns actor snapshots with pagination', async () => {
    vi.mocked(mockPrisma.sensorIntelActor!.findMany).mockResolvedValue([
      {
        id: 'actor-1',
        tenantId: 'tenant-1',
        sensorId: 'sensor-1',
        actorId: 'actor-1',
        riskScore: 90,
        isBlocked: false,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        ips: [],
        fingerprints: [],
        sessionIds: [],
        raw: {},
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);
    vi.mocked(mockPrisma.sensorIntelActor!.count).mockResolvedValue(1);

    const res = await request(app)
      .get('/fleet/intel/actors?minRisk=80&limit=10&offset=0')
      .expect(200);

    expect(res.body.actors).toHaveLength(1);
    expect(res.body.pagination).toHaveProperty('total', 1);
  });

  it('returns null snapshot when no payload data exists', async () => {
    vi.mocked(mockPrisma.sensorPayloadSnapshot!.findFirst).mockResolvedValue(null);

    const res = await request(app)
      .get('/fleet/intel/payload/stats')
      .expect(200);

    expect(res.body).toHaveProperty('snapshot', null);
  });
});
