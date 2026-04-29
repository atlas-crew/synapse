/**
 * Fleet actor routes (TASK-79 / ADR-0002 §Decision: Actors via SensorIntelActor
 * snapshot dedup) — integration tests verifying:
 *
 *   - dedup correctness across >=2 mock sensors
 *   - same actorId on multiple sensors merges with the per-ADR semantics
 *   - offline-sensor stale handling reports 'stale' in the envelope
 *   - registered sensor with no snapshot rows reports 'error'
 *   - per-sensor `/synapse/:sensorId/actors` route still wins for a real sensorId
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

function actorRow(overrides: {
  sensorId: string;
  actorId: string;
  riskScore?: number;
  isBlocked?: boolean;
  ips?: string[];
  fingerprints?: string[];
  sessionIds?: string[];
  firstSeen?: number;
  lastSeen?: number;
  anomalyCount?: number;
  blockReason?: string | null;
  blockedSince?: number | null;
  updatedAt?: Date;
}) {
  const ips = overrides.ips ?? ['1.1.1.1'];
  const fingerprints = overrides.fingerprints ?? ['fp-a'];
  const sessionIds = overrides.sessionIds ?? ['s-1'];
  const firstSeen = overrides.firstSeen ?? 1714000000;
  const lastSeen = overrides.lastSeen ?? 1714003300;
  return {
    id: `${overrides.sensorId}-${overrides.actorId}`,
    tenantId: 'tenant-1',
    sensorId: overrides.sensorId,
    actorId: overrides.actorId,
    riskScore: overrides.riskScore ?? 0.5,
    isBlocked: overrides.isBlocked ?? false,
    firstSeenAt: new Date(firstSeen * 1000),
    lastSeenAt: new Date(lastSeen * 1000),
    ips,
    fingerprints,
    sessionIds,
    raw: {
      actorId: overrides.actorId,
      riskScore: overrides.riskScore ?? 0.5,
      isBlocked: overrides.isBlocked ?? false,
      ruleMatches: [],
      anomalyCount: overrides.anomalyCount ?? 0,
      sessionIds,
      firstSeen,
      lastSeen,
      ips,
      fingerprints,
      blockReason: overrides.blockReason ?? null,
      blockedSince: overrides.blockedSince ?? null,
    },
    createdAt: new Date(firstSeen * 1000),
    updatedAt: overrides.updatedAt ?? FRESH,
  };
}

interface BuildAppDeps {
  rows?: ReturnType<typeof actorRow>[];
  sensors?: { id: string }[];
  proxy?: Partial<SynapseProxyService>;
  staleAfterMs?: number;
}

function buildApp(deps: BuildAppDeps = {}): { app: Express; prisma: any; proxy: any } {
  const rows = deps.rows ?? [];
  const sensors = deps.sensors ?? [{ id: 'sensor-1' }, { id: 'sensor-2' }];

  const prisma = {
    sensorIntelActor: {
      findMany: vi.fn(async ({ where }: any) => {
        return rows.filter((row) => {
          if (where?.tenantId && row.tenantId !== where.tenantId) return false;
          if (where?.actorId && row.actorId !== where.actorId) return false;
          if (where?.riskScore?.gte !== undefined && row.riskScore < where.riskScore.gte) return false;
          return true;
        });
      }),
    },
    sensor: {
      findMany: vi.fn(async () => sensors),
    },
  };

  const proxy = {
    getActorTimeline: vi.fn(),
    ...deps.proxy,
  };

  const app = express();
  app.use(express.json());
  app.use(injectAuth());
  app.use(
    '/synapse',
    createSynapseRoutes(proxy as unknown as SynapseProxyService, mockLogger, {
      prisma: prisma as any,
      fleetViewStaleAfterMs: deps.staleAfterMs,
      fleetViewNow: () => NOW,
    }),
  );
  return { app, prisma, proxy };
}

describe('GET /synapse/actors — fleet list with snapshot dedup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns deduped merged actors across two sensors with seenOnSensors attribution', async () => {
    const { app } = buildApp({
      rows: [
        actorRow({
          sensorId: 'sensor-1',
          actorId: 'shared-actor',
          riskScore: 0.3,
          ips: ['1.1.1.1'],
          fingerprints: ['fp-a'],
          firstSeen: 1714000000,
          lastSeen: 1714003000,
        }),
        actorRow({
          sensorId: 'sensor-2',
          actorId: 'shared-actor',
          riskScore: 0.9,
          ips: ['2.2.2.2'],
          fingerprints: ['fp-b'],
          firstSeen: 1713999000,
          lastSeen: 1714004000,
        }),
        actorRow({
          sensorId: 'sensor-1',
          actorId: 'unique-to-1',
          riskScore: 0.6,
          firstSeen: 1714002000,
          lastSeen: 1714002500,
        }),
      ],
    });

    const res = await request(app).get('/synapse/actors').expect(200);

    expect(res.body.aggregate).toHaveLength(2);

    const merged = res.body.aggregate.find((a: any) => a.actorId === 'shared-actor');
    expect(merged).toMatchObject({
      riskScore: 0.9,
      seenOnSensors: ['sensor-1', 'sensor-2'],
      ips: ['1.1.1.1', '2.2.2.2'],
      fingerprints: ['fp-a', 'fp-b'],
      firstSeen: 1713999000,
      lastSeen: 1714004000,
    });

    expect(res.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 0 });
  });

  it("reports 'stale' for a sensor whose freshest row exceeds the 5-minute threshold, without dropping its rows", async () => {
    const { app } = buildApp({
      rows: [
        actorRow({ sensorId: 'sensor-1', actorId: 'a', updatedAt: FRESH }),
        actorRow({ sensorId: 'sensor-2', actorId: 'a', riskScore: 0.85, updatedAt: STALE }),
      ],
    });

    const res = await request(app).get('/synapse/actors').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, stale: 1, failed: 0 });

    const sensor2 = res.body.results.find((r: any) => r.sensorId === 'sensor-2');
    expect(sensor2.status).toBe('stale');
    expect(sensor2.lastUpdatedAt).toBe(STALE.toISOString());

    expect(res.body.aggregate).toHaveLength(1);
    expect(res.body.aggregate[0].riskScore).toBe(0.85);
    expect(res.body.aggregate[0].seenOnSensors).toEqual(['sensor-1', 'sensor-2']);
  });

  it("reports 'error' for a registered sensor with no snapshot rows", async () => {
    const { app } = buildApp({
      rows: [actorRow({ sensorId: 'sensor-1', actorId: 'only-on-1' })],
      sensors: [{ id: 'sensor-1' }, { id: 'sensor-3-offline' }],
    });

    const res = await request(app).get('/synapse/actors').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, stale: 0, failed: 1 });

    const offline = res.body.results.find((r: any) => r.sensorId === 'sensor-3-offline');
    expect(offline.status).toBe('error');
    expect(offline.error).toMatch(/no snapshot rows/i);
  });

  it('respects the minRisk filter at the database level', async () => {
    const { app, prisma } = buildApp({
      rows: [
        actorRow({ sensorId: 'sensor-1', actorId: 'low', riskScore: 0.2 }),
        actorRow({ sensorId: 'sensor-1', actorId: 'high', riskScore: 0.9 }),
      ],
    });

    const res = await request(app).get('/synapse/actors?min_risk=0.5').expect(200);

    expect(res.body.aggregate.map((a: any) => a.actorId)).toEqual(['high']);
    expect(prisma.sensorIntelActor.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          riskScore: { gte: 0.5 },
        }),
      }),
    );
  });

  it('paginates the deduped result with offset/limit', async () => {
    const rows = Array.from({ length: 10 }, (_, i) =>
      actorRow({
        sensorId: 'sensor-1',
        actorId: `actor-${i}`,
        lastSeen: 1714000000 + i,
      }),
    );
    const { app } = buildApp({ rows });

    const res = await request(app).get('/synapse/actors?limit=3&offset=2').expect(200);

    expect(res.body.aggregate).toHaveLength(3);
    expect(res.body.total).toBe(10);
    // Sorted lastSeen desc, so offset 2 starts at actor-7
    expect(res.body.aggregate.map((a: any) => a.actorId)).toEqual(['actor-7', 'actor-6', 'actor-5']);
  });
});

describe('GET /synapse/actors/:actorId — fleet detail', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns merged actor when found across the fleet', async () => {
    const { app } = buildApp({
      rows: [
        actorRow({ sensorId: 'sensor-1', actorId: 'target', riskScore: 0.3 }),
        actorRow({ sensorId: 'sensor-2', actorId: 'target', riskScore: 0.8, isBlocked: true, blockReason: 'manual', blockedSince: 1714000500 }),
      ],
    });

    const res = await request(app).get('/synapse/actors/target').expect(200);

    expect(res.body.aggregate).toMatchObject({
      actorId: 'target',
      riskScore: 0.8,
      isBlocked: true,
      blockReason: 'manual',
      blockedSince: 1714000500,
      seenOnSensors: ['sensor-1', 'sensor-2'],
    });
  });

  it('returns 404 for an actorId not present in any sensor snapshot', async () => {
    const { app } = buildApp({
      rows: [actorRow({ sensorId: 'sensor-1', actorId: 'other' })],
    });

    await request(app).get('/synapse/actors/missing').expect(404);
  });

  it('does not collide with the per-sensor /synapse/:sensorId/actors path', async () => {
    // Verifies route-order discipline: /synapse/actors (literal) wins over
    // /synapse/:sensorId/actors only when path is exactly /actors. Hitting a
    // real sensorId should still hit the per-sensor route, which talks to the
    // tunnel proxy.
    const proxyListActors = vi.fn().mockResolvedValue({ actors: [], stats: null });
    const { app } = buildApp({
      proxy: { listActors: proxyListActors as any },
    });

    await request(app).get('/synapse/sensor-1/actors').expect(200);
    expect(proxyListActors).toHaveBeenCalledWith('sensor-1', 'tenant-1', expect.any(Object));
  });
});

describe('GET /synapse/actors/:actorId/timeline — fleet timeline fan-out', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('merges events from each sensor that has the actor, sorted by timestamp desc', async () => {
    const getActorTimeline = vi.fn().mockImplementation(async (sensorId: string) => {
      if (sensorId === 'sensor-1') {
        return {
          actorId: 'target',
          events: [
            { timestamp: 1714000000, eventType: 'rule_match' },
            { timestamp: 1714003000, eventType: 'block' },
          ],
        };
      }
      return {
        actorId: 'target',
        events: [{ timestamp: 1714002000, eventType: 'session_started' }],
      };
    });

    const { app } = buildApp({
      rows: [
        actorRow({ sensorId: 'sensor-1', actorId: 'target' }),
        actorRow({ sensorId: 'sensor-2', actorId: 'target' }),
      ],
      proxy: { getActorTimeline: getActorTimeline as any },
    });

    const res = await request(app).get('/synapse/actors/target/timeline').expect(200);

    expect(getActorTimeline).toHaveBeenCalledTimes(2);
    expect(res.body.aggregate.events.map((e: any) => e.timestamp)).toEqual([
      1714003000,
      1714002000,
      1714000000,
    ]);
    expect(res.body.aggregate.events[0]).toMatchObject({
      sensorId: 'sensor-1',
      eventType: 'block',
    });
    expect(res.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 0 });
  });

  it("marks a sensor's timeline as 'error' when its proxy call fails, without dropping the others", async () => {
    const getActorTimeline = vi.fn().mockImplementation(async (sensorId: string) => {
      if (sensorId === 'sensor-2') {
        throw new Error('tunnel timeout');
      }
      return {
        actorId: 'target',
        events: [{ timestamp: 1714003000, eventType: 'rule_match' }],
      };
    });

    const { app } = buildApp({
      rows: [
        actorRow({ sensorId: 'sensor-1', actorId: 'target' }),
        actorRow({ sensorId: 'sensor-2', actorId: 'target' }),
      ],
      proxy: { getActorTimeline: getActorTimeline as any },
    });

    const res = await request(app).get('/synapse/actors/target/timeline').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, stale: 0, failed: 1 });
    const failed = res.body.results.find((r: any) => r.sensorId === 'sensor-2');
    expect(failed.status).toBe('error');
    expect(failed.error).toMatch(/tunnel timeout/);
    expect(res.body.aggregate.events).toHaveLength(1);
  });

  it('returns 404 when the actor is not present in any sensor snapshot', async () => {
    const { app } = buildApp({ rows: [] });
    await request(app).get('/synapse/actors/ghost/timeline').expect(404);
  });
});
