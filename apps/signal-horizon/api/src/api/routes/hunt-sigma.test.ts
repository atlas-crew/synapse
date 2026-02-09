import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../__tests__/test-request.js';
import { createHuntSigmaRoutes } from './hunt-sigma.js';
import type { SigmaHuntService } from '../../services/sigma-hunt/index.js';

// Mock logger
const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

const injectAuth = (tenantId: string, scopes: string[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = { tenantId, scopes } as unknown as typeof req.auth;
    next();
  };
};

describe('Hunt Sigma Routes', () => {
  let app: Express;
  let sigma: SigmaHuntService;

  beforeEach(() => {
    sigma = {
      listRules: vi.fn().mockResolvedValue([]),
      createRule: vi.fn(),
      updateRule: vi.fn(),
      deleteRule: vi.fn(),
      listLeads: vi.fn().mockResolvedValue([]),
      ackLead: vi.fn(),
    } as unknown as SigmaHuntService;

    app = express();
    app.use(express.json());
    app.use(injectAuth('tenant-1', ['hunt:read', 'hunt:write']));
    app.use('/api/v1/hunt/sigma', createHuntSigmaRoutes({} as PrismaClient, mockLogger, sigma));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('GET /api/v1/hunt/sigma/rules lists rules', async () => {
    await request(app).get('/api/v1/hunt/sigma/rules').expect(200);
    expect(vi.mocked(sigma.listRules)).toHaveBeenCalledWith('tenant-1');
  });

  it('POST /api/v1/hunt/sigma/rules creates rule', async () => {
    vi.mocked(sigma.createRule).mockResolvedValue({
      id: 'rule-1',
      tenantId: 'tenant-1',
      name: 'curl',
      enabled: true,
      sqlTemplate: 'SELECT * FROM signal_events WHERE 1=1 ORDER BY timestamp DESC LIMIT 1000',
      whereClause: '1=1',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    } as any);

    const res = await request(app)
      .post('/api/v1/hunt/sigma/rules')
      .send({
        name: 'curl',
        sqlTemplate: 'SELECT * FROM signal_events WHERE 1=1 ORDER BY timestamp DESC LIMIT 1000',
      })
      .expect(201);

    expect(res.body).toMatchObject({ success: true, data: { id: 'rule-1' } });
  });

  it('GET /api/v1/hunt/sigma/leads lists leads', async () => {
    await request(app).get('/api/v1/hunt/sigma/leads?limit=50').expect(200);
    expect(vi.mocked(sigma.listLeads)).toHaveBeenCalledWith('tenant-1', 50);
  });

  it('POST /api/v1/hunt/sigma/leads/:id/ack acks lead', async () => {
    vi.mocked(sigma.ackLead).mockResolvedValue({
      id: 'lead-1',
      tenantId: 'tenant-1',
      ruleId: 'rule-1',
      ruleName: 'curl',
      status: 'ACKED',
      acknowledgedAt: new Date().toISOString(),
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      matchCount: 1,
      pivot: { requestId: null, anonFingerprint: null, sourceIp: null },
      sample: { timestamp: new Date().toISOString(), sensorId: 's', signalType: 't', severity: 'HIGH', confidence: 1 },
    } as any);

    await request(app)
      .post('/api/v1/hunt/sigma/leads/lead-1/ack')
      .expect(200);

    expect(vi.mocked(sigma.ackLead)).toHaveBeenCalledWith('tenant-1', 'lead-1');
  });
});

