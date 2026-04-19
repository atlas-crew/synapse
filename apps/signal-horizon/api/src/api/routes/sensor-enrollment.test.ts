/**
 * Sensor Enrollment Route Tests
 *
 * Covers the public announce endpoint and the authenticated candidates list.
 * The announce endpoint is reachable without a user session — its only
 * credential is the registration token in the Authorization header, so the
 * security-relevant cases (missing / invalid / revoked / expired / exhausted
 * tokens) are the bulk of the surface worth testing.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import express, {
  type Express,
  type Request,
  type Response,
  type NextFunction,
} from 'express';
import request from '../../__tests__/test-request.js';
import crypto from 'crypto';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { createSensorEnrollmentRoutes } from './sensor-enrollment.js';
import { createOnboardingRoutes } from './onboarding.js';
import { LiveCommandDeliveryError } from '../../services/fleet/fleet-commander.js';

vi.mock('../../middleware/rate-limiter.js', () => ({
  rateLimiters: new Proxy(
    {},
    {
      get:
        () =>
        (_req: Request, _res: Response, next: NextFunction) =>
          next(),
    }
  ),
}));

vi.mock('../middleware/auth.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../middleware/auth.js')>();
  return {
    ...actual,
    requireScope:
      (_scope: string) =>
      (_req: Request, _res: Response, next: NextFunction) =>
        next(),
  };
});

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

const TEST_TOKEN = 'sh_reg_testtoken_abcdef123456';
const TEST_TOKEN_HASH = hashToken(TEST_TOKEN);
const TEST_TENANT_ID = 'tenant-1';
const TEST_TOKEN_ID = 'token-1';
const BATCH_SENSOR_1 = 'cksensor000000000000000001';
const BATCH_SENSOR_2 = 'cksensor000000000000000002';

const ACTIVE_TOKEN_RECORD = {
  id: TEST_TOKEN_ID,
  tenantId: TEST_TENANT_ID,
  tokenHash: TEST_TOKEN_HASH,
  revoked: false,
  expiresAt: null,
  maxUses: 10,
  _count: { registeredSensors: 0 },
};

const VALID_PAYLOAD = {
  fingerprint: 'fp_abc123def456',
  hostname: 'sensor-01.local',
  os: 'linux',
  version: '1.2.3',
};

describe('POST /api/v1/sensors/announce', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    mockPrisma = {
      registrationToken: {
        findUnique: vi.fn(),
      } as unknown as PrismaClient['registrationToken'],
      sensorCandidate: {
        upsert: vi.fn().mockResolvedValue({
          id: 'cand-1',
          announceCount: 1,
          claimedSensorId: null,
        }),
      } as unknown as PrismaClient['sensorCandidate'],
    };

    app = express();
    app.use(express.json());
    app.use('/sensors', createSensorEnrollmentRoutes(mockPrisma as PrismaClient, mockLogger));
  });

  it('returns 401 when the Authorization header is missing', async () => {
    await request(app).post('/sensors/announce').send(VALID_PAYLOAD).expect(401);
    expect(vi.mocked(mockPrisma.registrationToken!.findUnique)).not.toHaveBeenCalled();
  });

  it('returns 401 for an unknown token', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue(null);
    await request(app)
      .post('/sensors/announce')
      .set('Authorization', 'Bearer bogus')
      .send(VALID_PAYLOAD)
      .expect(401);
  });

  it('returns 401 for a revoked token', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue({
      ...ACTIVE_TOKEN_RECORD,
      revoked: true,
    } as any);

    await request(app)
      .post('/sensors/announce')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send(VALID_PAYLOAD)
      .expect(401);

    expect(vi.mocked(mockPrisma.sensorCandidate!.upsert)).not.toHaveBeenCalled();
  });

  it('returns 401 for an expired token', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue({
      ...ACTIVE_TOKEN_RECORD,
      expiresAt: new Date(Date.now() - 60_000),
    } as any);

    await request(app)
      .post('/sensors/announce')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send(VALID_PAYLOAD)
      .expect(401);
  });

  it('returns 401 when the token has reached maxUses', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue({
      ...ACTIVE_TOKEN_RECORD,
      maxUses: 1,
      _count: { registeredSensors: 1 },
    } as any);

    await request(app)
      .post('/sensors/announce')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send(VALID_PAYLOAD)
      .expect(401);
  });

  it('returns 400 on malformed payload (missing fingerprint)', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue(
      ACTIVE_TOKEN_RECORD as any
    );

    await request(app)
      .post('/sensors/announce')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send({ hostname: 'x' })
      .expect(400);
  });

  it('upserts the candidate and returns 202 for a valid announce', async () => {
    vi.mocked(mockPrisma.registrationToken!.findUnique).mockResolvedValue(
      ACTIVE_TOKEN_RECORD as any
    );

    const res = await request(app)
      .post('/sensors/announce')
      .set('Authorization', `Bearer ${TEST_TOKEN}`)
      .send(VALID_PAYLOAD)
      .expect(202);

    expect(res.body).toMatchObject({
      candidateId: 'cand-1',
      status: 'announced',
      announceCount: 1,
    });
    expect(vi.mocked(mockPrisma.sensorCandidate!.upsert)).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          registrationTokenId_fingerprint: {
            registrationTokenId: TEST_TOKEN_ID,
            fingerprint: VALID_PAYLOAD.fingerprint,
          },
        },
      })
    );
  });
});

describe('GET /api/v1/onboarding/candidates', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;

  beforeEach(() => {
    mockPrisma = {
      registrationToken: {
        findFirst: vi.fn().mockResolvedValue({ id: 'cjld2cjxh0000qzrmn831i7rn' }),
      } as unknown as PrismaClient['registrationToken'],
      sensorCandidate: {
        findMany: vi.fn().mockResolvedValue([]),
      } as unknown as PrismaClient['sensorCandidate'],
    };

    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.auth = { tenantId: TEST_TENANT_ID, scopes: ['fleet:read'] } as any;
      next();
    });
    app.use('/onboarding', createOnboardingRoutes(mockPrisma as PrismaClient, mockLogger));
  });

  it('scopes candidates to the calling tenant', async () => {
    await request(app).get('/onboarding/candidates').expect(200);
    expect(vi.mocked(mockPrisma.sensorCandidate!.findMany)).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ tenantId: TEST_TENANT_ID }) })
    );
  });

  it('filters by tokenId when provided', async () => {
    await request(app)
      .get('/onboarding/candidates?tokenId=cjld2cjxh0000qzrmn831i7rn')
      .expect(200);

    expect(vi.mocked(mockPrisma.sensorCandidate!.findMany)).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          tenantId: TEST_TENANT_ID,
          registrationTokenId: 'cjld2cjxh0000qzrmn831i7rn',
        }),
      })
    );
  });

  it('rejects an invalid `since` timestamp with 400', async () => {
    await request(app).get('/onboarding/candidates?since=not-a-date').expect(400);
  });

  it('rejects a future `since` timestamp with 400', async () => {
    const future = new Date(Date.now() + 60_000).toISOString();
    await request(app)
      .get(`/onboarding/candidates?since=${encodeURIComponent(future)}`)
      .expect(400);
  });

  it('returns serialized candidate items with status field', async () => {
    vi.mocked(mockPrisma.sensorCandidate!.findMany).mockResolvedValue([
      {
        id: 'cand-1',
        registrationTokenId: 'token-1',
        fingerprint: 'fp_123',
        hostname: 'sensor-01',
        os: 'linux',
        kernel: null,
        architecture: null,
        ipAddress: null,
        version: null,
        userAgent: null,
        announceCount: 3,
        firstSeenAt: new Date('2026-04-17T00:00:00Z'),
        lastSeenAt: new Date('2026-04-17T00:05:00Z'),
        claimedSensorId: null,
      } as any,
    ]);

    const res = await request(app).get('/onboarding/candidates').expect(200);

    expect(res.body.items).toHaveLength(1);
    expect(res.body.items[0]).toMatchObject({
      id: 'cand-1',
      fingerprint: 'fp_123',
      hostname: 'sensor-01',
      status: 'announced',
      announceCount: 3,
    });
  });
});

describe('POST /api/v1/onboarding/pending/:sensorId', () => {
  let app: Express;
  let mockPrisma: Partial<PrismaClient>;
  let mockFleetCommander: { sendConnectedCommand: ReturnType<typeof vi.fn> };
  let sensorFindFirst: ReturnType<typeof vi.fn>;
  let sensorFindMany: ReturnType<typeof vi.fn>;
  let sensorUpdate: ReturnType<typeof vi.fn>;
  let sensorApiKeyCreate: ReturnType<typeof vi.fn>;
  let sensorApiKeyDeleteMany: ReturnType<typeof vi.fn>;
  let sensorApiKeyUpdateMany: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockFleetCommander = {
      sendConnectedCommand: vi.fn().mockResolvedValue('cmd-handoff-1'),
    };

    sensorFindFirst = vi.fn().mockResolvedValue({
      id: 'sensor-1',
      tenantId: TEST_TENANT_ID,
      name: 'sensor-pending',
      approvalStatus: 'PENDING',
      metadata: {},
    });
    sensorFindMany = vi.fn().mockResolvedValue([{ id: BATCH_SENSOR_1 }, { id: BATCH_SENSOR_2 }]);
    sensorUpdate = vi.fn().mockResolvedValue({
      id: 'sensor-1',
      name: 'sensor-approved',
      approvalStatus: 'APPROVED',
      approvedAt: new Date('2026-04-18T12:00:00Z'),
    });
    sensorApiKeyCreate = vi.fn().mockResolvedValue({
      id: 'sak-1',
      sensorId: 'sensor-1',
    });
    sensorApiKeyDeleteMany = vi.fn().mockResolvedValue({ count: 1 });
    sensorApiKeyUpdateMany = vi.fn().mockResolvedValue({ count: 1 });

    mockPrisma = {
      $transaction: vi.fn(async (callback: (tx: any) => Promise<unknown>) =>
        callback({
          sensor: { update: sensorUpdate, findFirst: sensorFindFirst },
          sensorApiKey: {
            create: sensorApiKeyCreate,
            deleteMany: sensorApiKeyDeleteMany,
            updateMany: sensorApiKeyUpdateMany,
          },
        })
      ),
      sensor: {
        findFirst: sensorFindFirst,
        findMany: sensorFindMany,
        update: sensorUpdate,
      } as unknown as PrismaClient['sensor'],
      sensorApiKey: {
        create: sensorApiKeyCreate,
        deleteMany: sensorApiKeyDeleteMany,
        updateMany: sensorApiKeyUpdateMany,
      } as unknown as PrismaClient['sensorApiKey'],
    };

    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.auth = {
        tenantId: TEST_TENANT_ID,
        userId: 'user-1',
        scopes: ['fleet:write'],
      } as any;
      next();
    });
    app.use(
      '/onboarding',
      createOnboardingRoutes(mockPrisma as PrismaClient, mockLogger, {
        fleetCommander: mockFleetCommander as any,
      })
    );
  });

  it('approves the sensor, issues a long-lived sensor key, and queues the handoff command', async () => {
    const res = await request(app)
      .post('/onboarding/pending/sensor-1')
      .send({ action: 'approve' })
      .expect(200);

    expect(vi.mocked(mockPrisma.sensor!.findFirst)).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          id: 'sensor-1',
          tenantId: TEST_TENANT_ID,
          approvalStatus: 'PENDING',
        }),
      })
    );
    expect(vi.mocked(mockPrisma.$transaction as any)).toHaveBeenCalled();
    expect(mockFleetCommander.sendConnectedCommand).toHaveBeenCalledWith(
      TEST_TENANT_ID,
      'sensor-1',
      expect.objectContaining({
        type: 'push_config',
        payload: expect.objectContaining({
          action: 'replace_sensor_api_key',
          restartProcess: true,
          source: 'horizon_onboarding_approval',
        }),
      })
    );

    const handoffPayload = mockFleetCommander.sendConnectedCommand.mock.calls[0][2].payload;
    expect(handoffPayload.sensorApiKey).toMatch(/^[A-Za-z0-9_-]{40,}$/);
    expect(res.body.automation).toMatchObject({
      sensorApiKeyIssued: true,
      handoffQueued: true,
    });
    expect(res.body.automation.handoffCommandId).toBeUndefined();
  });

  it('keeps the sensor pending when the live handoff path is unavailable', async () => {
    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.auth = {
        tenantId: TEST_TENANT_ID,
        userId: 'user-1',
        scopes: ['fleet:write'],
      } as any;
      next();
    });
    app.use('/onboarding', createOnboardingRoutes(mockPrisma as PrismaClient, mockLogger));

    const res = await request(app)
      .post('/onboarding/pending/sensor-1')
      .send({ action: 'approve' })
      .expect(503);

    expect(vi.mocked(mockPrisma.$transaction as any)).not.toHaveBeenCalled();
    expect(sensorApiKeyCreate).not.toHaveBeenCalled();
    expect(res.body.error).toMatch(/remains pending approval/i);
  });

  it('rolls approval back when the sensor key handoff cannot be delivered', async () => {
    mockFleetCommander.sendConnectedCommand.mockRejectedValueOnce(
      new LiveCommandDeliveryError('SENSOR_NOT_READY', 'Sensor is not ready for live command delivery')
    );
    sensorUpdate
      .mockResolvedValueOnce({
        id: 'sensor-1',
        name: 'sensor-approved',
        approvalStatus: 'APPROVED',
        approvedAt: new Date('2026-04-18T12:00:00Z'),
      })
      .mockResolvedValueOnce({
        id: 'sensor-1',
        name: 'sensor-pending',
        approvalStatus: 'PENDING',
        approvedAt: null,
      });

    const res = await request(app)
      .post('/onboarding/pending/sensor-1')
      .send({ action: 'approve' })
      .expect(409);

    expect(vi.mocked(mockPrisma.$transaction as any)).toHaveBeenCalledTimes(2);
    expect(sensorApiKeyCreate).toHaveBeenCalledTimes(1);
    expect(sensorUpdate).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        where: { id: 'sensor-1' },
        data: expect.objectContaining({
          approvalStatus: 'PENDING',
          approvedAt: null,
          approvedBy: null,
          name: 'sensor-pending',
        }),
      })
    );
    expect(sensorApiKeyDeleteMany).toHaveBeenCalledWith({
      where: {
        id: 'sak-1',
        sensorId: 'sensor-1',
      },
    });
    expect(res.body.code).toBe('SENSOR_NOT_CONNECTED');
    expect(res.body.error).toMatch(/remains pending approval/i);
  });

  it('returns a manual-remediation error if rollback fails after a handoff error', async () => {
    mockFleetCommander.sendConnectedCommand.mockRejectedValueOnce(
      new Error('websocket send failed')
    );
    vi.mocked(mockPrisma.$transaction as any)
      .mockImplementationOnce(async (callback: (tx: any) => Promise<unknown>) =>
        callback({
          sensor: { update: sensorUpdate, findFirst: sensorFindFirst },
          sensorApiKey: {
            create: sensorApiKeyCreate,
            deleteMany: sensorApiKeyDeleteMany,
            updateMany: sensorApiKeyUpdateMany,
          },
        })
      )
      .mockRejectedValueOnce(new Error('deadlock'));

    const res = await request(app)
      .post('/onboarding/pending/sensor-1')
      .send({ action: 'approve' })
      .expect(500);

    expect(sensorApiKeyUpdateMany).toHaveBeenCalledWith({
      where: { id: 'sak-1', sensorId: 'sensor-1' },
      data: { status: 'REVOKED' },
    });
    expect(res.body.code).toBe('APPROVAL_ROLLBACK_FAILED');
  });

  it('approves multiple pending sensors and returns the shared partial-results envelope', async () => {
    sensorFindFirst.mockImplementation(async ({ where }: any) => ({
      id: where.id,
      tenantId: TEST_TENANT_ID,
      name: `${where.id}-pending`,
      approvalStatus: 'PENDING',
      metadata: {},
    }));

    const res = await request(app)
      .post('/onboarding/pending/approve')
      .send({ sensorIds: [BATCH_SENSOR_1, BATCH_SENSOR_2] })
      .expect(200);

    expect(res.body.summary).toEqual({ succeeded: 2, failed: 0 });
    expect(res.body.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: BATCH_SENSOR_1,
          status: 'ok',
          data: expect.objectContaining({
            message: 'Sensor approved successfully',
          }),
        }),
        expect.objectContaining({
          sensorId: BATCH_SENSOR_2,
          status: 'ok',
          data: expect.objectContaining({
            message: 'Sensor approved successfully',
          }),
        }),
      ])
    );
    expect(mockFleetCommander.sendConnectedCommand).toHaveBeenCalledTimes(2);
  });

  it('returns partial failures for batch approvals without aborting the whole request', async () => {
    sensorFindMany.mockResolvedValue([{ id: BATCH_SENSOR_1 }]);
    sensorFindFirst.mockImplementation(async ({ where }: any) => {
      if (where.id === BATCH_SENSOR_2) return null;
      return {
        id: where.id,
        tenantId: TEST_TENANT_ID,
        name: 'sensor-pending',
        approvalStatus: 'PENDING',
        metadata: {},
      };
    });

    const res = await request(app)
      .post('/onboarding/pending/approve')
      .send({ sensorIds: [BATCH_SENSOR_1, BATCH_SENSOR_2] })
      .expect(200);

    expect(res.body.summary).toEqual({ succeeded: 1, failed: 1 });
    expect(res.body.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: BATCH_SENSOR_1,
          status: 'ok',
        }),
        expect.objectContaining({
          sensorId: BATCH_SENSOR_2,
          status: 'error',
          error: 'Pending sensor not found or not eligible',
        }),
      ])
    );
  });

  it('rejects multiple pending sensors and preserves the shared envelope shape', async () => {
    sensorFindFirst.mockImplementation(async ({ where }: any) => ({
      id: where.id,
      tenantId: TEST_TENANT_ID,
      name: `${where.id}-pending`,
      approvalStatus: 'PENDING',
      metadata: {},
    }));

    const res = await request(app)
      .post('/onboarding/pending/reject')
      .send({ sensorIds: [BATCH_SENSOR_1, BATCH_SENSOR_2], reason: 'duplicate registration' })
      .expect(200);

    expect(res.body.summary).toEqual({ succeeded: 2, failed: 0 });
    expect(res.body.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: BATCH_SENSOR_1,
          status: 'ok',
          data: expect.objectContaining({
            message: 'Sensor rejected',
            sensorId: BATCH_SENSOR_1,
          }),
        }),
        expect.objectContaining({
          sensorId: BATCH_SENSOR_2,
          status: 'ok',
          data: expect.objectContaining({
            message: 'Sensor rejected',
            sensorId: BATCH_SENSOR_2,
          }),
        }),
      ])
    );
    expect(sensorUpdate).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        where: { id: BATCH_SENSOR_1 },
        data: expect.objectContaining({
          approvalStatus: 'REJECTED',
        }),
      })
    );
  });

  it('rejects batch approval requests that do not have an authenticated user id', async () => {
    const appWithoutUser = express();
    appWithoutUser.use(express.json());
    appWithoutUser.use((req, _res, next) => {
      req.auth = {
        tenantId: TEST_TENANT_ID,
        scopes: ['fleet:write'],
      } as any;
      next();
    });
    appWithoutUser.use(
      '/onboarding',
      createOnboardingRoutes(mockPrisma as PrismaClient, mockLogger, {
        fleetCommander: mockFleetCommander as any,
      })
    );

    const res = await request(appWithoutUser)
      .post('/onboarding/pending/approve')
      .send({ sensorIds: [BATCH_SENSOR_1] })
      .expect(401);

    expect(res.body).toMatchObject({
      code: 'USER_CONTEXT_REQUIRED',
    });
  });
});
