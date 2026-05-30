/**
 * Fleet session routes (TASK-80 / ADR-0002 §Decision: Sessions via
 * SensorIntelSession snapshot dedup) — integration tests verifying:
 *
 *   - dedup correctness across >=2 mock sensors
 *   - actorId/suspicious filters are applied at the DB query layer
 *   - stale/no-row sensors are represented in the partial-result envelope
 *   - per-sensor `/synapse/:sensorId/sessions` remains the diagnostic route
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../../__tests__/test-request.js';
import { createSynapseRoutes } from '../synapse.js';
import type { Logger } from 'pino';
import type { SynapseProxyService } from '../../../services/synapse-proxy.js';

const NOW = new Date('2026-04-29T12:00:00Z');
const FRESH = new Date(NOW.getTime() - 30_000);
const STALE = new Date(NOW.getTime() - 6 * 60_000);

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

function injectAuth() {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = {
      tenantId: 'tenant-1',
      apiKeyId: 'key-1',
      scopes: ['fleet:read'],
      isFleetAdmin: false,
      userId: 'user-1',
      userName: 'Test User',
    } as typeof req.auth;
    next();
  };
}

function sessionRow(overrides: {
  sensorId: string;
  sessionId: string;
  actorId?: string | null;
  requestCount?: number;
  isSuspicious?: boolean;
  lastActivity?: number;
  creationTime?: number;
  boundIp?: string | null;
  boundJa4?: string | null;
  hijackAlerts?: Array<Record<string, unknown>>;
  updatedAt?: Date;
}) {
  const lastActivity = overrides.lastActivity ?? 1714391900000;
  const creationTime = overrides.creationTime ?? 1714388300000;
  const hijackAlerts = overrides.hijackAlerts ?? [];
  return {
    id: `${overrides.sensorId}-${overrides.sessionId}`,
    tenantId: 'tenant-1',
    sensorId: overrides.sensorId,
    sessionId: overrides.sessionId,
    actorId: overrides.actorId ?? null,
    requestCount: overrides.requestCount ?? 10,
    isSuspicious: overrides.isSuspicious ?? false,
    lastActivityAt: new Date(lastActivity),
    boundIp: overrides.boundIp ?? null,
    boundJa4: overrides.boundJa4 ?? null,
    hijackAlerts,
    raw: {
      sessionId: overrides.sessionId,
      tokenHash: `tok-${overrides.sessionId}`,
      actorId: overrides.actorId ?? null,
      creationTime,
      lastActivity,
      requestCount: overrides.requestCount ?? 10,
      boundIp: overrides.boundIp ?? null,
      boundJa4: overrides.boundJa4 ?? null,
      isSuspicious: overrides.isSuspicious ?? false,
      hijackAlerts,
    },
    createdAt: new Date(creationTime),
    updatedAt: overrides.updatedAt ?? FRESH,
  };
}

interface BuildAppDeps {
  rows?: ReturnType<typeof sessionRow>[];
  sensors?: { id: string }[];
  proxy?: Partial<SynapseProxyService>;
  staleAfterMs?: number;
  withoutPrisma?: boolean;
}

function buildApp(deps: BuildAppDeps = {}): { app: Express; prisma: any; proxy: any } {
  const rows = deps.rows ?? [];
  const sensors = deps.sensors ?? [{ id: 'sensor-1' }, { id: 'sensor-2' }];

  const prisma = {
    sensorIntelSession: {
      findMany: vi.fn(async ({ where }: any) => {
        return rows.filter((row) => {
          if (where?.tenantId && row.tenantId !== where.tenantId) return false;
          if (typeof where?.sessionId === 'string' && row.sessionId !== where.sessionId) return false;
          if (Array.isArray(where?.sessionId?.in) && !where.sessionId.in.includes(row.sessionId)) return false;
          if (where?.actorId && row.actorId !== where.actorId) return false;
          if (where?.isSuspicious !== undefined && row.isSuspicious !== where.isSuspicious) return false;
          return true;
        });
      }),
    },
    sensor: {
      findMany: vi.fn(async () => sensors),
    },
  };

  const proxy = {
    listSessions: vi.fn(),
    getSession: vi.fn(),
    ...deps.proxy,
  };

  const app = express();
  app.use(express.json());
  app.use(injectAuth());
  app.use(
    '/synapse',
    createSynapseRoutes(proxy as unknown as SynapseProxyService, mockLogger, {
      prisma: deps.withoutPrisma ? undefined : prisma as any,
      fleetViewStaleAfterMs: deps.staleAfterMs,
      fleetViewNow: () => NOW,
    }),
  );
  return { app, prisma, proxy };
}

describe('GET /synapse/sessions — fleet list with snapshot dedup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns deduped sessions across sensors with seenOnSensors attribution', async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({
          sensorId: 'sensor-1',
          sessionId: 'shared-session',
          actorId: 'actor-a',
          requestCount: 3,
          isSuspicious: false,
          boundIp: '203.0.113.10',
          lastActivity: 1714391000000,
        }),
        sessionRow({
          sensorId: 'sensor-2',
          sessionId: 'shared-session',
          actorId: 'actor-a',
          requestCount: 7,
          isSuspicious: true,
          boundJa4: 'ja4-b',
          lastActivity: 1714392000000,
        }),
        sessionRow({
          sensorId: 'sensor-1',
          sessionId: 'unique-session',
          actorId: 'actor-b',
          requestCount: 5,
          lastActivity: 1714391500000,
        }),
      ],
    });

    const res = await request(app).get('/synapse/sessions').expect(200);

    expect(res.body.aggregate).toHaveLength(2);

    const merged = res.body.aggregate.find((s: any) => s.sessionId === 'shared-session');
    expect(merged).toMatchObject({
      sessionId: 'shared-session',
      actorId: 'actor-a',
      requestCount: 10,
      isSuspicious: true,
      boundIp: '203.0.113.10',
      boundJa4: 'ja4-b',
      lastActivity: 1714392000000,
      seenOnSensors: ['sensor-1', 'sensor-2'],
    });

    expect(res.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 0 });
    expect(res.body.total).toBe(2);
  });

  it('applies actorId and suspicious filters after aggregation without dropping contributors', async () => {
    const { app, prisma } = buildApp({
      rows: [
        sessionRow({
          sensorId: 'sensor-1',
          sessionId: 'target',
          actorId: 'actor-a',
          requestCount: 2,
          isSuspicious: false,
          lastActivity: 1714391000000,
        }),
        sessionRow({
          sensorId: 'sensor-2',
          sessionId: 'target',
          actorId: null,
          requestCount: 5,
          isSuspicious: true,
          lastActivity: 1714392000000,
        }),
        sessionRow({ sensorId: 'sensor-1', sessionId: 'other', actorId: 'actor-b', isSuspicious: false }),
      ],
    });

    const res = await request(app)
      .get('/synapse/sessions?actor_id=actor-a&suspicious=true')
      .expect(200);

    expect(res.body.aggregate.map((s: any) => s.sessionId)).toEqual(['target']);
    expect(res.body.aggregate[0]).toMatchObject({
      actorId: 'actor-a',
      requestCount: 7,
      isSuspicious: true,
      seenOnSensors: ['sensor-1', 'sensor-2'],
    });
    expect(res.body.stats).toMatchObject({
      totalSessions: 1,
      suspiciousSessions: 1,
    });
    expect(prisma.sensorIntelSession.findMany).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: 'tenant-1',
          actorId: 'actor-a',
        }),
      }),
    );
    expect(prisma.sensorIntelSession.findMany).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: 'tenant-1',
          isSuspicious: true,
        }),
      }),
    );
    expect(prisma.sensorIntelSession.findMany).toHaveBeenNthCalledWith(
      3,
      expect.objectContaining({
        where: {
          tenantId: 'tenant-1',
          sessionId: { in: ['target'] },
        },
      }),
    );
  });

  it('excludes sessions that are suspicious after aggregation when suspicious=false', async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({ sensorId: 'sensor-1', sessionId: 'mixed', isSuspicious: false }),
        sessionRow({ sensorId: 'sensor-2', sessionId: 'mixed', isSuspicious: true }),
        sessionRow({ sensorId: 'sensor-1', sessionId: 'clean', isSuspicious: false }),
      ],
    });

    const res = await request(app).get('/synapse/sessions?suspicious=false').expect(200);

    expect(res.body.aggregate.map((s: any) => s.sessionId)).toEqual(['clean']);
    expect(res.body.total).toBe(1);
    expect(res.body.stats).toMatchObject({
      totalSessions: 1,
      suspiciousSessions: 0,
    });
  });

  it('accepts the camelCase actorId alias for fleet filters', async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({ sensorId: 'sensor-1', sessionId: 'target', actorId: 'actor-a' }),
        sessionRow({ sensorId: 'sensor-1', sessionId: 'other', actorId: 'actor-b' }),
      ],
    });

    const res = await request(app).get('/synapse/sessions?actorId=actor-a').expect(200);

    expect(res.body.aggregate.map((s: any) => s.sessionId)).toEqual(['target']);
    expect(res.body.total).toBe(1);
  });

  it("reports 'stale' and 'error' sensors in the partial-result envelope", async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({ sensorId: 'sensor-fresh', sessionId: 'fresh', updatedAt: FRESH }),
        sessionRow({ sensorId: 'sensor-stale', sessionId: 'stale', updatedAt: STALE }),
      ],
      sensors: [{ id: 'sensor-fresh' }, { id: 'sensor-stale' }, { id: 'sensor-empty' }],
    });

    const res = await request(app).get('/synapse/sessions').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, stale: 1, failed: 1 });
    expect(res.body.results.find((r: any) => r.sensorId === 'sensor-stale')).toMatchObject({
      status: 'stale',
      lastUpdatedAt: STALE.toISOString(),
    });
    expect(res.body.results.find((r: any) => r.sensorId === 'sensor-empty')).toMatchObject({
      status: 'error',
      error: expect.stringMatching(/no snapshot rows/i),
    });
  });

  it('paginates the deduped result with offset/limit after cross-sensor merge', async () => {
    const rows = Array.from({ length: 8 }, (_, i) =>
      sessionRow({
        sensorId: 'sensor-1',
        sessionId: `session-${i}`,
        lastActivity: 1714390000000 + i,
      }),
    );
    rows.push(sessionRow({
      sensorId: 'sensor-2',
      sessionId: 'session-7',
      requestCount: 99,
      lastActivity: 1714390000010,
    }));
    const { app } = buildApp({ rows });

    const res = await request(app).get('/synapse/sessions?limit=3&offset=2').expect(200);

    expect(res.body.aggregate.map((s: any) => s.sessionId)).toEqual([
      'session-5',
      'session-4',
      'session-3',
    ]);
    expect(res.body.total).toBe(8);
  });

  it('returns 400 for invalid fleet pagination parameters', async () => {
    const { app } = buildApp();

    await request(app).get('/synapse/sessions?limit=0').expect(400);
    await request(app).get('/synapse/sessions?limit=101').expect(400);
    await request(app).get('/synapse/sessions?offset=-1').expect(400);
  });

  it('returns 503 when the fleet session store is unavailable', async () => {
    const { app } = buildApp({ withoutPrisma: true });

    const res = await request(app).get('/synapse/sessions').expect(503);
    expect(res.body).toEqual({ error: 'Fleet session view is unavailable' });
  });

  it('does not collide with the per-sensor /synapse/:sensorId/sessions path', async () => {
    const proxyListSessions = vi.fn().mockResolvedValue({ sessions: [], stats: null });
    const { app } = buildApp({
      proxy: { listSessions: proxyListSessions as any },
    });

    await request(app).get('/synapse/sensor-1/sessions').expect(200);
    expect(proxyListSessions).toHaveBeenCalledWith('sensor-1', 'tenant-1', expect.any(Object));
  });
});

describe('GET /synapse/sessions/:sessionId — fleet detail', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns a merged session when found across the fleet', async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({ sensorId: 'sensor-1', sessionId: 'target', requestCount: 2 }),
        sessionRow({ sensorId: 'sensor-2', sessionId: 'target', requestCount: 4, isSuspicious: true }),
      ],
    });

    const res = await request(app).get('/synapse/sessions/target').expect(200);

    expect(res.body.aggregate).toMatchObject({
      sessionId: 'target',
      requestCount: 6,
      isSuspicious: true,
      seenOnSensors: ['sensor-1', 'sensor-2'],
    });
    expect(res.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 0 });
  });

  it("reports stale and no-row sensors in a detail response's freshness envelope", async () => {
    const { app } = buildApp({
      rows: [
        sessionRow({ sensorId: 'sensor-fresh', sessionId: 'target', updatedAt: FRESH }),
        sessionRow({ sensorId: 'sensor-stale', sessionId: 'target', updatedAt: STALE }),
      ],
      sensors: [{ id: 'sensor-fresh' }, { id: 'sensor-stale' }, { id: 'sensor-empty' }],
    });

    const res = await request(app).get('/synapse/sessions/target').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, stale: 1, failed: 1 });
    expect(res.body.results.find((r: any) => r.sensorId === 'sensor-stale')).toMatchObject({
      status: 'stale',
      lastUpdatedAt: STALE.toISOString(),
    });
    expect(res.body.results.find((r: any) => r.sensorId === 'sensor-empty')).toMatchObject({
      status: 'error',
      error: expect.stringMatching(/no snapshot rows/i),
    });
  });

  it('returns 404 for a sessionId not present in any sensor snapshot', async () => {
    const { app } = buildApp({
      rows: [sessionRow({ sensorId: 'sensor-1', sessionId: 'other' })],
    });

    await request(app).get('/synapse/sessions/missing').expect(404);
  });

  it('returns 503 when the fleet session detail store is unavailable', async () => {
    const { app } = buildApp({ withoutPrisma: true });

    const res = await request(app).get('/synapse/sessions/target').expect(503);
    expect(res.body).toEqual({ error: 'Fleet session view is unavailable' });
  });
});
