import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express, { type Express } from 'express';
import cookieParser from 'cookie-parser';
import { createHmac, createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { RedisKv } from '../../storage/redis/kv.js';
import request from '../../__tests__/test-request.js';
import { createAuthMiddleware } from './auth.js';
import { metrics } from '../../services/metrics.js';

const mockConfig = vi.hoisted(() => ({
  telemetry: { jwtSecret: 'test-secret' as string | undefined },
}));

vi.mock('../../config.js', () => ({
  config: mockConfig,
}));

const base64UrlEncode = (value: string | Buffer): string =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const createJwt = (overrides: Record<string, unknown> = {}): string => {
  const secret = mockConfig.telemetry.jwtSecret ?? 'test-secret';
  const now = Math.floor(Date.now() / 1000);
  const payloadData = {
    tenantId: 'tenant-1',
    userId: 'user-1',
    scopes: ['fleet:read'],
    jti: 'jti-1',
    aud: 'signal-horizon',
    iat: now - 1,
    exp: now + 3600,
    ...overrides,
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payloadData));
  const signature = base64UrlEncode(
    createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest()
  );

  return `${headerB64}.${payloadB64}.${signature}`;
};

describe('Auth middleware JWT', () => {
  let app: Express;
  let prisma: PrismaClient;

  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-secret';

    prisma = {
      tokenBlacklist: {
        findUnique: vi.fn().mockResolvedValue(null),
      },
      apiKey: {
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({}),
      },
    } as unknown as PrismaClient;

    app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(createAuthMiddleware(prisma));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));
  });

  it('rejects revoked jwt tokens', async () => {
    vi.mocked(prisma.tokenBlacklist.findUnique).mockResolvedValue({ jti: 'revoked-jti' } as never);

    const token = createJwt({ jti: 'revoked-jti' });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body).toMatchObject({ code: 'TOKEN_REVOKED' });
  });

  it('accepts valid jwt tokens and sets auth context', async () => {
    const token = createJwt({
      jti: 'valid-jti',
      scopes: ['fleet:admin', 'fleet:read'],
      userId: 'user-42',
    });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(res.body.auth).toEqual({
      tenantId: 'tenant-1',
      authId: 'valid-jti',
      apiKeyId: 'valid-jti',
      scopes: ['fleet:admin', 'fleet:read'],
      isFleetAdmin: true,
      userId: 'user-42',
    });

    expect(prisma.apiKey.findUnique).not.toHaveBeenCalled();
  });

  it('rejects jwt tokens missing jti', async () => {
    const token = createJwt({ jti: undefined });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body).toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('rejects jwt tokens missing tenantId', async () => {
    const token = createJwt({ tenantId: undefined, tenant_id: undefined });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body).toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('rejects jwt tokens with wrong audience (labs-l03r)', async () => {
    // Token issued for a different service should be rejected
    const token = createJwt({ aud: 'other-service' });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`);

    // parseJwt returns null for aud mismatch, so auth falls through to API key
    // lookup which also fails => 401
    expect(res.status).toBe(401);
  });

  it('rejects jwt tokens missing audience claim (labs-l03r)', async () => {
    // Legacy tokens without aud should be rejected once audience check is active
    const token = createJwt({ aud: undefined });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(401);
  });

  it('fails open on blacklist DB errors and records metric', async () => {
    vi.mocked(prisma.tokenBlacklist.findUnique).mockRejectedValue(new Error('db down'));
    const incSpy = vi.spyOn(metrics.authBlacklistDbErrors, 'inc');

    const token = createJwt({ jti: 'valid-jti' });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(res.body.auth.tenantId).toBe('tenant-1');
    expect(incSpy).toHaveBeenCalledWith({ source: 'api' });
  });

  it('falls back to API key when JWT parse fails', async () => {
    const apiKey = 'not.a.jwt';
    const keyHash = createHash('sha256').update(apiKey).digest('hex');

    vi.mocked(prisma.apiKey.findUnique).mockImplementation(async ({ where }) => {
      if (where?.keyHash === keyHash) {
        return {
          id: 'api-key-1',
          tenantId: 'tenant-1',
          isRevoked: false,
          expiresAt: null,
          scopes: ['fleet:read'],
          tenant: { id: 'tenant-1' },
        } as never;
      }
      return null as never;
    });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${apiKey}`)
      .expect(200);

    expect(res.body.auth).toMatchObject({
      tenantId: 'tenant-1',
      apiKeyId: 'api-key-1',
      scopes: ['fleet:read'],
      isFleetAdmin: false,
    });
  });

  it('accepts api key from httpOnly cookie fallback (dev browser flow)', async () => {
    const apiKey = 'dev-cookie-api-key';
    const keyHash = createHash('sha256').update(apiKey).digest('hex');

    vi.mocked(prisma.apiKey.findUnique).mockImplementation(async ({ where }) => {
      if (where?.keyHash === keyHash) {
        return {
          id: 'api-key-1',
          tenantId: 'tenant-1',
          isRevoked: false,
          expiresAt: null,
          scopes: ['hunt:read'],
          tenant: { id: 'tenant-1' },
        } as never;
      }
      return null as never;
    });

    const res = await request(app)
      .get('/secure')
      .set('Cookie', `horizon_api_key=${apiKey}`)
      .expect(200);

    expect(res.body.auth).toMatchObject({
      tenantId: 'tenant-1',
      apiKeyId: 'api-key-1',
      scopes: ['hunt:read'],
      isFleetAdmin: false,
    });
  });
});

describe('Auth middleware epoch validation (labs-wqy1)', () => {
  let prisma: PrismaClient;

  function createMockKv(epochValue: string | null = null): RedisKv {
    return {
      get: vi.fn().mockResolvedValue(epochValue),
      set: vi.fn().mockResolvedValue(true),
      del: vi.fn().mockResolvedValue(1),
    };
  }

  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-secret';

    prisma = {
      tokenBlacklist: {
        findUnique: vi.fn().mockResolvedValue(null),
      },
      apiKey: {
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({}),
      },
    } as unknown as PrismaClient;
  });

  it('rejects token when epoch is behind current tenant epoch', async () => {
    const kv = createMockKv('3'); // Current epoch is 3
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma, kv));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    // Token has epoch 1, which is behind current epoch 3
    const token = createJwt({ epoch: 1 });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);

    expect(res.body).toMatchObject({ code: 'TOKEN_EPOCH_EXPIRED' });
  });

  it('accepts token when epoch matches current tenant epoch', async () => {
    const kv = createMockKv('3');
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma, kv));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const token = createJwt({ epoch: 3 });

    await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('accepts token when epoch is ahead of current tenant epoch', async () => {
    const kv = createMockKv('2');
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma, kv));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const token = createJwt({ epoch: 3 });

    await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('skips epoch check when no kv is provided', async () => {
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma)); // No kv
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const token = createJwt({ epoch: 0 });

    await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('skips epoch check when token has no epoch claim', async () => {
    const kv = createMockKv('5');
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma, kv));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    // Token without epoch claim (legacy tokens)
    const token = createJwt({}); // No epoch in overrides

    await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('returns 503 when Redis errors during epoch check (fail-closed)', async () => {
    const kv = createMockKv();
    vi.mocked(kv.get).mockRejectedValue(new Error('connection refused'));
    const app = express();
    app.use(express.json());
    app.use(createAuthMiddleware(prisma, kv));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const token = createJwt({ epoch: 1 });

    // Should deny with 503 because epoch lookup failed (fail-closed)
    const response = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${token}`)
      .expect(503);

    expect(response.body.code).toBe('EPOCH_SERVICE_UNAVAILABLE');
  });
});

describe('Auth middleware cookie fallback (labs-n6nf)', () => {
  let app: Express;
  let prisma: PrismaClient;

  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-secret';

    prisma = {
      tokenBlacklist: {
        findUnique: vi.fn().mockResolvedValue(null),
      },
      apiKey: {
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({}),
      },
    } as unknown as PrismaClient;

    app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(createAuthMiddleware(prisma));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));
  });

  it('accepts JWT from access_token cookie when no Authorization header', async () => {
    const token = createJwt({
      jti: 'cookie-jti',
      scopes: ['fleet:read'],
      userId: 'user-cookie',
    });

    const res = await request(app)
      .get('/secure')
      .set('Cookie', `access_token=${token}`)
      .expect(200);

    expect(res.body.auth).toMatchObject({
      tenantId: 'tenant-1',
      authId: 'cookie-jti',
      userId: 'user-cookie',
      scopes: ['fleet:read'],
    });
  });

  it('prefers Authorization header over cookie when both present', async () => {
    const headerToken = createJwt({
      jti: 'header-jti',
      userId: 'user-header',
      scopes: ['fleet:admin'],
    });

    const cookieToken = createJwt({
      jti: 'cookie-jti',
      userId: 'user-cookie',
      scopes: ['fleet:read'],
    });

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${headerToken}`)
      .set('Cookie', `access_token=${cookieToken}`)
      .expect(200);

    // Should use the header token, not the cookie
    expect(res.body.auth.authId).toBe('header-jti');
    expect(res.body.auth.userId).toBe('user-header');
  });

  it('rejects when neither Authorization header nor cookie is present', async () => {
    const res = await request(app)
      .get('/secure')
      .expect(401);

    expect(res.body).toMatchObject({ code: 'AUTH_REQUIRED' });
  });

  it('rejects invalid JWT in cookie', async () => {
    const res = await request(app)
      .get('/secure')
      .set('Cookie', 'access_token=not-a-valid-jwt')
      .expect(401);

    // The invalid JWT will fall through to API key lookup which also fails
    expect(res.body).toMatchObject({ code: 'INVALID_API_KEY' });
  });
});

describe('Auth middleware API key expiry boundary', () => {
  let prisma: PrismaClient;

  beforeEach(() => {
    vi.useRealTimers();
    // Disable JWT so auth falls through to the API key path
    mockConfig.telemetry.jwtSecret = undefined;

    prisma = {
      tokenBlacklist: {
        findUnique: vi.fn().mockResolvedValue(null),
      },
      apiKey: {
        findUnique: vi.fn(),
        update: vi.fn().mockResolvedValue({}),
      },
    } as unknown as PrismaClient;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function buildApiKeyRecord(expiresAt: Date | null) {
    const apiKey = 'boundary-test-key';
    const keyHash = createHash('sha256').update(apiKey).digest('hex');
    return {
      apiKey,
      keyHash,
      record: {
        id: 'ak-boundary',
        tenantId: 'tenant-boundary',
        isRevoked: false,
        expiresAt,
        scopes: ['fleet:read'],
        tenant: { id: 'tenant-boundary' },
      },
    };
  }

  it('treats expiresAt exactly at current time as valid (not strictly less than)', async () => {
    // The condition is: expiresAt < new Date()
    // When expiresAt === now, this is false, so key is still valid.
    const now = new Date('2026-02-10T12:00:00.000Z');
    vi.useFakeTimers();
    vi.setSystemTime(now);

    const { apiKey, keyHash, record } = buildApiKeyRecord(new Date('2026-02-10T12:00:00.000Z'));
    vi.mocked(prisma.apiKey.findUnique).mockImplementation(async ({ where }: any) => {
      if (where?.keyHash === keyHash) return record as never;
      return null as never;
    });

    const app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(createAuthMiddleware(prisma));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${apiKey}`)
      .expect(200);

    expect(res.body.auth).toMatchObject({
      tenantId: 'tenant-boundary',
      apiKeyId: 'ak-boundary',
    });
  });

  it('rejects API key expired 1ms in the past with 401 API_KEY_EXPIRED', async () => {
    const now = new Date('2026-02-10T12:00:00.000Z');
    vi.useFakeTimers();
    vi.setSystemTime(now);

    // expiresAt is 1ms before now → expiresAt < new Date() is true
    const { apiKey, keyHash, record } = buildApiKeyRecord(new Date('2026-02-10T11:59:59.999Z'));
    vi.mocked(prisma.apiKey.findUnique).mockImplementation(async ({ where }: any) => {
      if (where?.keyHash === keyHash) return record as never;
      return null as never;
    });

    const app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(createAuthMiddleware(prisma));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${apiKey}`)
      .expect(401);

    expect(res.body).toMatchObject({ code: 'API_KEY_EXPIRED' });
  });

  it('treats null expiresAt as valid (no expiry)', async () => {
    const { apiKey, keyHash, record } = buildApiKeyRecord(null);
    vi.mocked(prisma.apiKey.findUnique).mockImplementation(async ({ where }: any) => {
      if (where?.keyHash === keyHash) return record as never;
      return null as never;
    });

    const app = express();
    app.use(cookieParser());
    app.use(express.json());
    app.use(createAuthMiddleware(prisma));
    app.get('/secure', (req, res) => res.json({ auth: req.auth }));

    const res = await request(app)
      .get('/secure')
      .set('Authorization', `Bearer ${apiKey}`)
      .expect(200);

    expect(res.body.auth).toMatchObject({
      tenantId: 'tenant-boundary',
      apiKeyId: 'ak-boundary',
      scopes: ['fleet:read'],
    });
  });
});
