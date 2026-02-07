import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { signJwt, verifyAndDecodeToken } from '../jwt.js';

describe('verifyAndDecodeToken', () => {
  const secret = 'test-secret';
  const now = Math.floor(Date.now() / 1000);

  const prisma = {
    tokenBlacklist: {
      findUnique: vi.fn(),
    },
  } as unknown as PrismaClient;

  beforeEach(() => {
    vi.mocked((prisma as any).tokenBlacklist.findUnique).mockResolvedValue(null);
  });

  it('returns ok for valid token with tenantId+jti', async () => {
    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        jti: 'jti-1',
        tenantId: 'tenant-1',
        userId: 'user-1',
        scopes: ['dashboard:read'],
        aud: 'signal-horizon',
      },
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.tenantId).toBe('tenant-1');
      expect(res.jti).toBe('jti-1');
    }
  });

  it('returns invalid for signature/claim failures', async () => {
    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        jti: 'jti-1',
        tenantId: 'tenant-1',
        aud: 'signal-horizon',
      },
      'wrong-secret'
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'invalid' });
  });

  it('returns invalid_payload when token is missing jti', async () => {
    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        tenantId: 'tenant-1',
        aud: 'signal-horizon',
      },
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'invalid_payload' });
  });

  it('returns invalid_payload when token is missing tenantId', async () => {
    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        jti: 'jti-1',
        aud: 'signal-horizon',
      },
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'invalid_payload' });
  });

  it('returns revoked when token is in blacklist', async () => {
    vi.mocked((prisma as any).tokenBlacklist.findUnique).mockResolvedValue({ jti: 'jti-1', tenantId: 'tenant-1' });

    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        jti: 'jti-1',
        tenantId: 'tenant-1',
        aud: 'signal-horizon',
      },
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'revoked' });
  });

  it('returns invalid when decoded payload types are wrong (tenantId)', async () => {
    const token = signJwt(
      {
        iat: now,
        exp: now + 3600,
        jti: 'jti-1',
        tenantId: 123,
        aud: 'signal-horizon',
      } as any,
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'invalid' });
  });

  it('returns invalid when decoded payload types are wrong (iat)', async () => {
    const token = signJwt(
      {
        iat: 'nope',
        exp: now + 3600,
        jti: 'jti-1',
        tenantId: 'tenant-1',
        aud: 'signal-horizon',
      } as any,
      secret
    );

    const res = await verifyAndDecodeToken(token, secret, prisma, { audience: 'signal-horizon' });
    expect(res).toEqual({ ok: false, error: 'invalid' });
  });
});
