/**
 * Threat Routes Test Suite
 *
 * Tests for threat intelligence API endpoints including
 * listing, searching, and feedback.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createThreatRoutes } from './threats.js';
import type { PrismaClient, Threat } from '@prisma/client';
import type { AuthContext } from '../middleware/auth.js';

// Mock the auth middleware module
vi.mock('../middleware/auth.js', () => ({
  requireScope: (scope: string) => (req: Request, _res: Response, next: NextFunction) => {
    if (req.auth?.scopes?.includes(scope)) {
      return next();
    }
    _res.status(403).json({ error: 'Forbidden' });
  },
}));

// Mock validation middleware
vi.mock('../middleware/validation.js', () => ({
  validateParams: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  validateQuery: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  validateBody: () => (_req: Request, _res: Response, next: NextFunction) => next(),
  IdParamSchema: {},
}));

  // Auth middleware to inject auth object
  const injectAuth = (authOverrides: Partial<AuthContext> = {}) => {
    return (req: Request, _res: Response, next: NextFunction) => {
      req.auth = {
        authId: 'auth-1',
        tenantId: 'tenant-1',
        apiKeyId: 'api-key-1',
        userId: 'user-1',
        scopes: ['dashboard:read', 'dashboard:write'],
        isFleetAdmin: false,
        ...authOverrides,
      } as any;
      next();
    };
  };
  const createMockThreat = (overrides: Partial<Threat> = {}): Threat => ({
    id: 'threat-1',
    indicator: '1.2.3.4',
    threatType: 'IP_THREAT' as any,
    riskScore: 50,
    fleetRiskScore: 50,
    tenantId: 'tenant-1',
    isFleetThreat: false,
    metadata: {},
    firstSeenAt: new Date(),
    lastSeenAt: new Date(),
    hitCount: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
    ttl: null,
    tenantsAffected: 1,
    ...overrides,
  } as any);
describe('Threat Routes', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    mockPrisma = {
      threat: {
        findUnique: vi.fn(),
        findMany: vi.fn(),
        count: vi.fn(),
        update: vi.fn(),
      } as unknown as PrismaClient['threat'],
    };

    app = express();
    app.use(express.json());
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('POST /threats/:id/feedback', () => {
    it('should apply feedback and update risk score', async () => {
      app.use(injectAuth());
      app.use('/threats', createThreatRoutes(mockPrisma as PrismaClient));

      const threat = createMockThreat({ riskScore: 50 });
      vi.mocked(mockPrisma.threat!.findUnique).mockResolvedValue(threat);
      vi.mocked(mockPrisma.threat!.update).mockImplementation(({ data }: Parameters<PrismaClient['threat']['update']>[0]) =>
        Promise.resolve({ ...threat, ...data })
      );

      const res = await request(app)
        .post('/threats/threat-1/feedback')
        .send({
          action: 'false_positive',
          impact: 'moderate',
          reason: 'Testing feedback',
        })
        .expect(200);

      expect(res.body.success).toBe(true);
      // moderate impact is 15. 50 - 15 = 35.
      expect(res.body.threat.riskScore).toBe(35);
      expect(mockPrisma.threat!.update).toHaveBeenCalledWith(expect.objectContaining({
        where: { id: 'threat-1' },
        data: expect.objectContaining({
          riskScore: 35,
        }),
      }));
    });

    it('should clamp risk score to 0', async () => {
      app.use(injectAuth());
      app.use('/threats', createThreatRoutes(mockPrisma as PrismaClient));

      const threat = createMockThreat({ riskScore: 10 });
      vi.mocked(mockPrisma.threat!.findUnique).mockResolvedValue(threat);
      vi.mocked(mockPrisma.threat!.update).mockImplementation(({ data }: Parameters<PrismaClient['threat']['update']>[0]) =>
        Promise.resolve({ ...threat, ...data })
      );

      const res = await request(app)
        .post('/threats/threat-1/feedback')
        .send({
          action: 'false_positive',
          impact: 'major', // major is 30. 10 - 30 = -20 -> clamped to 0.
        })
        .expect(200);

      expect(res.body.threat.riskScore).toBe(0);
    });

    it('should return 404 for non-existent threat', async () => {
      app.use(injectAuth());
      app.use('/threats', createThreatRoutes(mockPrisma as PrismaClient));

      vi.mocked(mockPrisma.threat!.findUnique).mockResolvedValue(null);

      await request(app)
        .post('/threats/non-existent/feedback')
        .send({ action: 'false_positive', impact: 'minor' })
        .expect(404);
    });

    it('should return 403 if user tries to update threat from another tenant', async () => {
      app.use(injectAuth({ tenantId: 'tenant-1' }));
      app.use('/threats', createThreatRoutes(mockPrisma as PrismaClient));

      const otherThreat = createMockThreat({ id: 'threat-2', tenantId: 'tenant-2' });
      vi.mocked(mockPrisma.threat!.findUnique).mockResolvedValue(otherThreat);

      await request(app)
        .post('/threats/threat-2/feedback')
        .send({ action: 'false_positive', impact: 'minor' })
        .expect(403);
    });

    it('should allow fleet admins to update any threat', async () => {
      app.use(injectAuth({ tenantId: 'tenant-1', isFleetAdmin: true }));
      app.use('/threats', createThreatRoutes(mockPrisma as PrismaClient));

      const otherThreat = createMockThreat({ id: 'threat-2', tenantId: 'tenant-2' });
      vi.mocked(mockPrisma.threat!.findUnique).mockResolvedValue(otherThreat);
      vi.mocked(mockPrisma.threat!.update).mockImplementation(({ data }: Parameters<PrismaClient['threat']['update']>[0]) =>
        Promise.resolve({ ...otherThreat, ...data })
      );

      const res = await request(app)
        .post('/threats/threat-2/feedback')
        .send({ action: 'false_positive', impact: 'minor' })
        .expect(200);

      expect(res.body.success).toBe(true);
    });
  });
});
