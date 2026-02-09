import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import request from '../../__tests__/test-request.js';
import { createHuntSigmaRoutes } from './hunt-sigma.js';
import type { SigmaHuntService } from '../../services/sigma-hunt/index.js';
import { SigmaHuntService as RealSigmaHuntService } from '../../services/sigma-hunt/index.js';
import type { RedisKv } from '../../storage/redis/kv.js';

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

  const createMemoryKv = (): RedisKv => {
    const kv = new Map<string, string>();
    const sets = new Map<string, Set<string>>();
    return {
      get: async (key) => kv.get(key) ?? null,
      set: async (key, value) => {
        kv.set(key, value);
        return true;
      },
      del: async (key) => {
        const existed = kv.delete(key);
        sets.delete(key);
        return existed ? 1 : 0;
      },
      incr: async (key) => {
        const next = (parseInt(kv.get(key) ?? '0', 10) || 0) + 1;
        kv.set(key, String(next));
        return next;
      },
      incrby: async (key, amount) => {
        const next = (parseInt(kv.get(key) ?? '0', 10) || 0) + amount;
        kv.set(key, String(next));
        return next;
      },
      mget: async (keys) => keys.map((k) => kv.get(k) ?? null),
      sadd: async (key, ...members) => {
        const set = sets.get(key) ?? new Set<string>();
        let added = 0;
        for (const m of members) {
          if (!set.has(m)) {
            set.add(m);
            added += 1;
          }
        }
        sets.set(key, set);
        return added;
      },
      srem: async (key, ...members) => {
        const set = sets.get(key);
        if (!set) return 0;
        let removed = 0;
        for (const m of members) {
          if (set.delete(m)) removed += 1;
        }
        return removed;
      },
      smembers: async (key) => Array.from(sets.get(key) ?? []),
    };
  };

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

  it('POST /api/v1/hunt/sigma/rules requires hunt:write scope', async () => {
    const scopedApp = express();
    scopedApp.use(express.json());
    scopedApp.use(injectAuth('tenant-1', ['hunt:read']));
    scopedApp.use('/api/v1/hunt/sigma', createHuntSigmaRoutes({} as PrismaClient, mockLogger, sigma));

    await request(scopedApp)
      .post('/api/v1/hunt/sigma/rules')
      .send({ name: 'curl', sqlTemplate: 'SELECT * FROM signal_events WHERE 1=1 ORDER BY timestamp DESC LIMIT 1000' })
      .expect(403);
  });

  it('POST /api/v1/hunt/sigma/rules rejects malicious sqlTemplate', async () => {
    const kv = createMemoryKv();
    const real = new RealSigmaHuntService(kv, mockLogger as any, null);

    const realApp = express();
    realApp.use(express.json());
    realApp.use(injectAuth('tenant-1', ['hunt:read', 'hunt:write']));
    realApp.use('/api/v1/hunt/sigma', createHuntSigmaRoutes({} as PrismaClient, mockLogger, real as any));

    await request(realApp)
      .post('/api/v1/hunt/sigma/rules')
      .send({
        name: 'evil',
        sqlTemplate: "SELECT * FROM signal_events WHERE remote('h','d','t') = 1 ORDER BY timestamp DESC LIMIT 1000",
      })
      .expect(400);
  });

  it('POST /api/v1/hunt/sigma/rules rejects backticks (400)', async () => {
    const kv = createMemoryKv();
    const real = new RealSigmaHuntService(kv, mockLogger as any, null);

    const realApp = express();
    realApp.use(express.json());
    realApp.use(injectAuth('tenant-1', ['hunt:read', 'hunt:write']));
    realApp.use('/api/v1/hunt/sigma', createHuntSigmaRoutes({} as PrismaClient, mockLogger, real as any));

    await request(realApp)
      .post('/api/v1/hunt/sigma/rules')
      .send({
        name: 'evil-backtick',
        sqlTemplate: 'SELECT * FROM signal_events WHERE `x` = 1 ORDER BY timestamp DESC LIMIT 1000',
      })
      .expect(400);
  });

  it('POST /api/v1/hunt/sigma/rules returns 500 for unexpected errors', async () => {
    const boom = {
      ...sigma,
      createRule: vi.fn().mockRejectedValue(new Error('Redis is down')),
    } as unknown as SigmaHuntService;

    const boomApp = express();
    boomApp.use(express.json());
    boomApp.use(injectAuth('tenant-1', ['hunt:read', 'hunt:write']));
    boomApp.use('/api/v1/hunt/sigma', createHuntSigmaRoutes({} as PrismaClient, mockLogger, boom));

    const res = await request(boomApp)
      .post('/api/v1/hunt/sigma/rules')
      .send({
        name: 'curl',
        sqlTemplate: 'SELECT * FROM signal_events WHERE 1=1 ORDER BY timestamp DESC LIMIT 1000',
      })
      .expect(500);

    expect(res.body).toMatchObject({ error: 'Failed to create sigma rule' });
    expect(res.body.message).toBeUndefined();
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
