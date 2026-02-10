/**
 * P0 Security Tests — telemetry-jwt.ts
 *
 * Validates JWT and API key authentication gates for the telemetry ingest path.
 * Covers: JWT validation, revocation, sensor API keys, legacy API keys,
 * fail-open on DB error, deriveSensorIdFromBody, header extraction.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import type { Request, Response } from 'express';

// ---------------------------------------------------------------------------
// Mutable config mock (vi.hoisted ensures it's defined before vi.mock runs)
// ---------------------------------------------------------------------------
const mockConfig = vi.hoisted(() => ({
  telemetry: { jwtSecret: undefined as string | undefined },
}));

vi.mock('../../../config.js', () => ({
  config: mockConfig,
}));

// ---------------------------------------------------------------------------
// parseJwt mock
// ---------------------------------------------------------------------------
const mockParseJwt = vi.hoisted(() => vi.fn());

vi.mock('../../../lib/jwt.js', () => ({
  parseJwt: mockParseJwt,
}));

// ---------------------------------------------------------------------------
// Module under test (imported AFTER mocks are wired)
// ---------------------------------------------------------------------------
import {
  requireTelemetryJwt,
  isTelemetryTokenRevoked,
  type TelemetryAuthContext,
} from '../telemetry-jwt.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function makeReq(overrides: {
  authorization?: string;
  'x-api-key'?: string;
  'x-admin-key'?: string;
  body?: unknown;
} = {}): Request {
  const { authorization, 'x-api-key': xApiKey, 'x-admin-key': xAdminKey, body } = overrides;
  const headers: Record<string, string | undefined> = {};
  if (authorization !== undefined) headers.authorization = authorization;
  if (xApiKey !== undefined) headers['x-api-key'] = xApiKey;
  if (xAdminKey !== undefined) headers['x-admin-key'] = xAdminKey;

  return { headers, body: body ?? {} } as unknown as Request;
}

function makeRes(): Response & {
  _status: number | undefined;
  _json: unknown;
  statusFn: ReturnType<typeof vi.fn>;
  jsonFn: ReturnType<typeof vi.fn>;
} {
  const jsonFn = vi.fn();
  const statusFn = vi.fn();

  const res = {
    _status: undefined as number | undefined,
    _json: undefined as unknown,
    statusFn,
    jsonFn,
    status(code: number) {
      res._status = code;
      statusFn(code);
      return res;
    },
    json(payload: unknown) {
      res._json = payload;
      jsonFn(payload);
      return res;
    },
  } as unknown as Response & {
    _status: number | undefined;
    _json: unknown;
    statusFn: ReturnType<typeof vi.fn>;
    jsonFn: ReturnType<typeof vi.fn>;
  };

  return res;
}

/** Build a minimal mock PrismaClient with the models used by telemetry-jwt. */
function makePrisma() {
  return {
    sensorApiKey: {
      findFirst: vi.fn().mockResolvedValue(null),
    },
    apiKey: {
      findUnique: vi.fn().mockResolvedValue(null),
    },
    tokenBlacklist: {
      findFirst: vi.fn().mockResolvedValue(null),
    },
  } as unknown as PrismaClient & {
    sensorApiKey: { findFirst: ReturnType<typeof vi.fn> };
    apiKey: { findUnique: ReturnType<typeof vi.fn> };
    tokenBlacklist: { findFirst: ReturnType<typeof vi.fn> };
  };
}

// ---------------------------------------------------------------------------
// isTelemetryTokenRevoked
// ---------------------------------------------------------------------------

describe('isTelemetryTokenRevoked', () => {
  it('returns false when prisma is not provided (fail-open)', async () => {
    const result = await isTelemetryTokenRevoked('any-jti');
    expect(result).toBe(false);
  });

  it('returns true when tokenBlacklist entry exists', async () => {
    const prisma = makePrisma();
    (prisma.tokenBlacklist as any).findFirst.mockResolvedValue({ jti: 'revoked-jti' });

    const result = await isTelemetryTokenRevoked('revoked-jti', prisma);
    expect(result).toBe(true);
  });

  it('returns false when tokenBlacklist entry does not exist', async () => {
    const prisma = makePrisma();
    (prisma.tokenBlacklist as any).findFirst.mockResolvedValue(null);

    const result = await isTelemetryTokenRevoked('clean-jti', prisma);
    expect(result).toBe(false);
  });

  it('fails open on DB error — returns false', async () => {
    const prisma = makePrisma();
    (prisma.tokenBlacklist as any).findFirst.mockRejectedValue(new Error('connection refused'));

    const result = await isTelemetryTokenRevoked('any-jti', prisma);
    expect(result).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// requireTelemetryJwt — NO JWT SECRET (dev/demo mode)
// ---------------------------------------------------------------------------

describe('requireTelemetryJwt — no JWT secret configured', () => {
  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = undefined;
    mockParseJwt.mockReset();
  });

  // ---- Case 1: No secret, no API key → 503 ----
  it('returns 503 telemetry_jwt_missing when no API key is provided', async () => {
    const req = makeReq();
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
    expect(res._json).toEqual({ error: 'telemetry_jwt_missing' });
    // Guard: no downstream DB calls for keys
    expect((prisma.sensorApiKey as any).findFirst).not.toHaveBeenCalled();
  });

  it('returns 503 when API key provided but no prisma client', async () => {
    const req = makeReq({ authorization: 'Bearer some-key' });
    const res = makeRes();

    const ctx = await requireTelemetryJwt(req, res);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });

  // ---- Case 2: Valid sensor API key (ACTIVE, signal:write, APPROVED) ----
  it('returns auth context for valid sensor API key with signal:write and APPROVED sensor', async () => {
    const rawKey = 'sensor-key-valid';
    const keyHash = sha256Hex(rawKey);
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-1',
      sensorId: 'sensor-42',
      permissions: ['signal:write', 'signal:read'],
      sensor: { tenantId: 'tenant-abc', approvalStatus: 'APPROVED' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-abc',
      sensorId: 'sensor-42',
      jti: 'sak-1',
    });
    // Should NOT fall through to legacy API key path
    expect((prisma.apiKey as any).findUnique).not.toHaveBeenCalled();
    expect(res.statusFn).not.toHaveBeenCalled();
  });

  // ---- Case 3: Sensor key missing signal:write → falls through to legacy, ultimately 503 ----
  it('returns 503 when sensor key lacks signal:write permission', async () => {
    const rawKey = 'sensor-key-no-write';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-2',
      sensorId: 'sensor-99',
      permissions: ['signal:read'], // missing signal:write
      sensor: { tenantId: 'tenant-abc', approvalStatus: 'APPROVED' },
    });
    // Legacy path also returns nothing
    (prisma.apiKey as any).findUnique.mockResolvedValue(null);

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
    expect(res._json).toEqual({ error: 'telemetry_jwt_missing' });
  });

  // ---- Case 4: Sensor NOT APPROVED → falls through to legacy, ultimately 503 ----
  it('returns 503 when sensor is not APPROVED', async () => {
    const rawKey = 'sensor-key-pending';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-3',
      sensorId: 'sensor-77',
      permissions: ['signal:write'],
      sensor: { tenantId: 'tenant-abc', approvalStatus: 'PENDING' },
    });
    (prisma.apiKey as any).findUnique.mockResolvedValue(null);

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });

  // ---- Case 5: Legacy ApiKey (not revoked, signal:write, not expired) ----
  it('returns context via legacy API key path with sensorId from body', async () => {
    const rawKey = 'legacy-api-key';
    const keyHash = sha256Hex(rawKey);
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { instance_id: 'sensor-from-body' },
    });
    const res = makeRes();
    const prisma = makePrisma();

    // Sensor key lookup returns nothing
    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);

    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-legacy-1',
      tenantId: 'tenant-xyz',
      isRevoked: false,
      expiresAt: null,
      scopes: ['signal:write'],
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-xyz',
      sensorId: 'sensor-from-body',
      jti: 'ak-legacy-1',
    });
    expect(res.statusFn).not.toHaveBeenCalled();
  });

  it('returns 503 when legacy API key is revoked', async () => {
    const rawKey = 'legacy-revoked';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-revoked',
      tenantId: 'tenant-xyz',
      isRevoked: true,
      expiresAt: null,
      scopes: ['signal:write'],
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });

  it('returns 503 when legacy API key is expired', async () => {
    const rawKey = 'legacy-expired';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-expired',
      tenantId: 'tenant-xyz',
      isRevoked: false,
      expiresAt: new Date(Date.now() - 60_000), // expired 1 minute ago
      scopes: ['signal:write'],
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });

  it('returns 503 when legacy API key lacks signal:write scope', async () => {
    const rawKey = 'legacy-no-scope';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-no-scope',
      tenantId: 'tenant-xyz',
      isRevoked: false,
      expiresAt: null,
      scopes: ['fleet:read'],
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });
});

// ---------------------------------------------------------------------------
// requireTelemetryJwt — JWT SECRET SET (production mode)
// ---------------------------------------------------------------------------

describe('requireTelemetryJwt — JWT secret configured', () => {
  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-telemetry-secret-min16';
    mockParseJwt.mockReset();
  });

  // ---- Case 6: No token at all → 401 ----
  it('returns 401 when no token is provided', async () => {
    const req = makeReq(); // no auth header, no x-api-key, no x-admin-key
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
    // Guard: no DB calls when token is missing
    expect((prisma.sensorApiKey as any).findFirst).not.toHaveBeenCalled();
    expect((prisma.apiKey as any).findUnique).not.toHaveBeenCalled();
  });

  // ---- Case 7: Valid JWT with jti, tenantId, sensorId → returns context ----
  it('returns auth context for valid JWT', async () => {
    mockParseJwt.mockReturnValue({
      jti: 'jwt-jti-1',
      tenantId: 'tenant-prod',
      sensorId: 'sensor-prod-1',
    });

    const req = makeReq({ authorization: 'Bearer valid.jwt.token' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-prod',
      sensorId: 'sensor-prod-1',
      jti: 'jwt-jti-1',
    });
    expect(mockParseJwt).toHaveBeenCalledWith(
      'valid.jwt.token',
      'test-telemetry-secret-min16',
      { audience: 'signal-horizon' }
    );
    expect(res.statusFn).not.toHaveBeenCalled();
  });

  it('accepts tenant_id and sensor_id legacy claim aliases', async () => {
    mockParseJwt.mockReturnValue({
      jti: 'jwt-jti-legacy',
      tenant_id: 'tenant-legacy',
      sensor_id: 'sensor-legacy',
    });

    const req = makeReq({ authorization: 'Bearer legacy.jwt.token' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-legacy',
      sensorId: 'sensor-legacy',
      jti: 'jwt-jti-legacy',
    });
  });

  // ---- Case 8: Revoked JWT → 401 token_revoked ----
  it('returns 401 token_revoked when JWT jti is on blacklist', async () => {
    mockParseJwt.mockReturnValue({
      jti: 'revoked-jti',
      tenantId: 'tenant-prod',
      sensorId: 'sensor-prod-1',
    });

    const req = makeReq({ authorization: 'Bearer revoked.jwt.token' });
    const res = makeRes();
    const prisma = makePrisma();
    (prisma.tokenBlacklist as any).findFirst.mockResolvedValue({ jti: 'revoked-jti' });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'token_revoked' });
  });

  // ---- Case 9: JWT missing tenantId/sensorId → 401 ----
  it('returns 401 when JWT payload lacks tenantId', async () => {
    mockParseJwt.mockReturnValue({
      jti: 'jwt-no-tenant',
      sensorId: 'sensor-1',
      // no tenantId, no tenant_id
    });

    const req = makeReq({ authorization: 'Bearer no-tenant.jwt.token' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  it('returns 401 when JWT payload lacks sensorId', async () => {
    mockParseJwt.mockReturnValue({
      jti: 'jwt-no-sensor',
      tenantId: 'tenant-prod',
      // no sensorId, no sensor_id
    });

    const req = makeReq({ authorization: 'Bearer no-sensor.jwt.token' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  // ---- Case 10: Invalid JWT (bad signature) → falls to API key path ----
  it('falls back to sensor API key when JWT parse fails', async () => {
    mockParseJwt.mockReturnValue(null); // bad signature / malformed

    const rawKey = 'bad.jwt.but-valid-apikey';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-fallback',
      sensorId: 'sensor-fallback',
      permissions: ['signal:write'],
      sensor: { tenantId: 'tenant-fallback', approvalStatus: 'APPROVED' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-fallback',
      sensorId: 'sensor-fallback',
      jti: 'sak-fallback',
    });
  });

  it('falls back to legacy API key when JWT and sensor key both fail', async () => {
    mockParseJwt.mockReturnValue(null);

    const rawKey = 'bad.jwt.legacy-key';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { sensorId: 'derived-sensor' },
    });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-legacy-fallback',
      tenantId: 'tenant-legacy',
      isRevoked: false,
      expiresAt: null,
      scopes: ['signal:write'],
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-legacy',
      sensorId: 'derived-sensor',
      jti: 'ak-legacy-fallback',
    });
  });

  it('returns 401 when JWT fails and no API key matches (with secret set)', async () => {
    mockParseJwt.mockReturnValue(null);

    const req = makeReq({ authorization: 'Bearer totally-invalid' });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue(null);

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  it('returns 401 when JWT fails and no prisma provided for fallback', async () => {
    mockParseJwt.mockReturnValue(null);

    const req = makeReq({ authorization: 'Bearer some-token' });
    const res = makeRes();

    const ctx = await requireTelemetryJwt(req, res); // no prisma

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  // ---- API key fallback with unapproved sensor (secret set) → 401 ----
  it('returns 401 when fallback sensor key is not APPROVED (secret set)', async () => {
    mockParseJwt.mockReturnValue(null);

    const rawKey = 'fallback-unapproved';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-unapp',
      sensorId: 'sensor-unapp',
      permissions: ['signal:write'],
      sensor: { tenantId: 'tenant-x', approvalStatus: 'PENDING' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  it('returns 401 when fallback sensor key lacks signal:write (secret set)', async () => {
    mockParseJwt.mockReturnValue(null);

    const rawKey = 'fallback-no-write';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-nowrite',
      sensorId: 'sensor-nowrite',
      permissions: ['signal:read'],
      sensor: { tenantId: 'tenant-x', approvalStatus: 'APPROVED' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });
});

// ---------------------------------------------------------------------------
// Header extraction variants (x-api-key, x-admin-key)
// ---------------------------------------------------------------------------

describe('requireTelemetryJwt — header extraction', () => {
  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = undefined; // dev mode
    mockParseJwt.mockReset();
  });

  // ---- Case 13: x-api-key header works ----
  it('accepts API key via x-api-key header', async () => {
    const rawKey = 'x-api-key-value';
    const req = makeReq({ 'x-api-key': rawKey });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-xapi',
      sensorId: 'sensor-xapi',
      permissions: ['signal:write'],
      sensor: { tenantId: 'tenant-xapi', approvalStatus: 'APPROVED' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-xapi',
      sensorId: 'sensor-xapi',
      jti: 'sak-xapi',
    });
  });

  // ---- Case 14: x-admin-key header works ----
  it('accepts API key via x-admin-key header', async () => {
    const rawKey = 'x-admin-key-value';
    const req = makeReq({ 'x-admin-key': rawKey });
    const res = makeRes();
    const prisma = makePrisma();

    (prisma.sensorApiKey as any).findFirst.mockResolvedValue({
      id: 'sak-xadmin',
      sensorId: 'sensor-xadmin',
      permissions: ['signal:write'],
      sensor: { tenantId: 'tenant-xadmin', approvalStatus: 'APPROVED' },
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-xadmin',
      sensorId: 'sensor-xadmin',
      jti: 'sak-xadmin',
    });
  });

  it('prefers Bearer token over x-api-key', async () => {
    const bearerKey = 'bearer-preferred';
    const xApiKey = 'x-api-key-ignored';
    const req = makeReq({ authorization: `Bearer ${bearerKey}`, 'x-api-key': xApiKey });
    const res = makeRes();
    const prisma = makePrisma();

    const bearerHash = sha256Hex(bearerKey);

    (prisma.sensorApiKey as any).findFirst.mockImplementation(async (args: any) => {
      if (args.where.keyHash === bearerHash) {
        return {
          id: 'sak-bearer',
          sensorId: 'sensor-bearer',
          permissions: ['signal:write'],
          sensor: { tenantId: 'tenant-bearer', approvalStatus: 'APPROVED' },
        };
      }
      return null;
    });

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toEqual({
      tenantId: 'tenant-bearer',
      sensorId: 'sensor-bearer',
      jti: 'sak-bearer',
    });
  });
});

// ---------------------------------------------------------------------------
// deriveSensorIdFromBody (tested indirectly through legacy API key path)
// ---------------------------------------------------------------------------

describe('requireTelemetryJwt — deriveSensorIdFromBody', () => {
  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = undefined;
    mockParseJwt.mockReset();
  });

  function setupLegacyKeyReturning(prisma: ReturnType<typeof makePrisma>) {
    (prisma.sensorApiKey as any).findFirst.mockResolvedValue(null);
    (prisma.apiKey as any).findUnique.mockResolvedValue({
      id: 'ak-derive',
      tenantId: 'tenant-derive',
      isRevoked: false,
      expiresAt: null,
      scopes: ['signal:write'],
    });
  }

  it('extracts sensorId from body.instance_id', async () => {
    const rawKey = 'derive-key';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { instance_id: 'from-instance-id' },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('from-instance-id');
  });

  it('extracts sensorId from body.sensorId', async () => {
    const rawKey = 'derive-key-2';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { sensorId: 'from-sensorId' },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('from-sensorId');
  });

  it('extracts sensorId from events[0].instance_id', async () => {
    const rawKey = 'derive-key-3';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { events: [{ instance_id: 'from-event-instance' }] },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('from-event-instance');
  });

  it('extracts sensorId from events[0].sensorId', async () => {
    const rawKey = 'derive-key-4';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { events: [{ sensorId: 'from-event-sensorId' }] },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('from-event-sensorId');
  });

  it('prefers body.instance_id over body.sensorId', async () => {
    const rawKey = 'derive-key-5';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { instance_id: 'instance-wins', sensorId: 'sensorId-loses' },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('instance-wins');
  });

  it('returns "unknown" when body has no extractable sensorId', async () => {
    const rawKey = 'derive-key-6';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { something: 'else' },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('unknown');
  });

  it('returns "unknown" when body is null/undefined', async () => {
    const rawKey = 'derive-key-7';
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: null,
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toBe('unknown');
  });

  it('truncates sensorId to 255 characters', async () => {
    const rawKey = 'derive-key-8';
    const longId = 'x'.repeat(500);
    const req = makeReq({
      authorization: `Bearer ${rawKey}`,
      body: { instance_id: longId },
    });
    const res = makeRes();
    const prisma = makePrisma();
    setupLegacyKeyReturning(prisma);

    const ctx = await requireTelemetryJwt(req, res, prisma);
    expect(ctx!.sensorId).toHaveLength(255);
  });
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('requireTelemetryJwt — edge cases', () => {
  beforeEach(() => {
    mockParseJwt.mockReset();
  });

  it('ignores empty-string Authorization header', async () => {
    mockConfig.telemetry.jwtSecret = 'test-telemetry-secret-min16';
    const req = makeReq({ authorization: '' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });

  it('ignores whitespace-only x-api-key header', async () => {
    mockConfig.telemetry.jwtSecret = 'test-telemetry-secret-min16';
    const req = makeReq({ 'x-api-key': '   ' });
    const res = makeRes();

    const ctx = await requireTelemetryJwt(req, res);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
  });

  it('handles DB error on sensorApiKey.findFirst gracefully (catches)', async () => {
    mockConfig.telemetry.jwtSecret = undefined;
    const rawKey = 'db-error-key';
    const req = makeReq({ authorization: `Bearer ${rawKey}` });
    const res = makeRes();
    const prisma = makePrisma();

    // sensorApiKey.findFirst rejects (the code uses .catch(() => null))
    (prisma.sensorApiKey as any).findFirst.mockRejectedValue(new Error('db error'));
    (prisma.apiKey as any).findUnique.mockResolvedValue(null);

    const ctx = await requireTelemetryJwt(req, res, prisma);

    // Falls through — sensorKey is null via catch, legacy also null → 503
    expect(ctx).toBeNull();
    expect(res._status).toBe(503);
  });

  it('JWT payload with jti but missing both tenantId variants returns 401', async () => {
    mockConfig.telemetry.jwtSecret = 'test-telemetry-secret-min16';
    mockParseJwt.mockReturnValue({
      jti: 'jwt-no-ids',
      // Missing: tenantId, tenant_id, sensorId, sensor_id
    });

    const req = makeReq({ authorization: 'Bearer token-no-ids' });
    const res = makeRes();
    const prisma = makePrisma();

    const ctx = await requireTelemetryJwt(req, res, prisma);

    expect(ctx).toBeNull();
    expect(res._status).toBe(401);
    expect(res._json).toEqual({ error: 'unauthorized' });
  });
});
