/**
 * Tenant-scoped Rate Limiter Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import {
  createTenantRateLimiter,
  createPlaybookRateLimiters,
  createAuthRateLimiters,
  PlaybookRateLimits,
} from '../rate-limit.js';

interface MockResponse extends Partial<Response> {
  statusCode: number;
  body: unknown;
  headers: Record<string, string | number | string[]>;
  headersSent: boolean;
}

function createMockReq(overrides: Partial<Request & { auth?: { tenantId: string; apiKeyId: string; scopes: string[]; isFleetAdmin: boolean } }> = {}): Request {
  return {
    method: 'POST',
    path: '/api/v1/playbooks',
    ip: '203.0.113.50',
    socket: { remoteAddress: '203.0.113.50' },
    headers: {},
    auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false },
    ...overrides,
  } as Request;
}

function createMockRes(): MockResponse {
  const res: MockResponse = {
    statusCode: 200,
    body: null,
    headers: {},
    headersSent: false,
    setHeader: vi.fn(function (this: MockResponse, name: string, value: string | number | string[]) {
      this.headers[name] = value;
      return this as Response;
    }),
    status: vi.fn(function (this: MockResponse, code: number) {
      this.statusCode = code;
      return this as Response;
    }),
    json: vi.fn(function (this: MockResponse, data: unknown) {
      this.body = data;
      this.headersSent = true;
      return this as Response;
    }),
  };
  return res;
}

describe('createTenantRateLimiter', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('enforces per-tenant limits', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 2 });

    const res1 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res1 as Response, next);

    const res2 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res2 as Response, next);

    const res3 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res3 as Response, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect(res3.statusCode).toBe(429);
    expect(res3.body).toMatchObject({
      error: expect.any(String),
      retryAfter: 1,
    });
    expect(res3.headers['Retry-After']).toBe('1');
  });

  it('isolates limits across tenants', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 1 });

    const res1 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res1 as Response, next);

    const res2 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-b', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res2 as Response, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect(res1.statusCode).toBe(200);
    expect(res2.statusCode).toBe(200);
  });

  it('falls back to IP when tenant ID is missing', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 1 });

    const res1 = createMockRes();
    await limiter(createMockReq({ auth: undefined, ip: '198.51.100.1' }), res1 as Response, next);

    const res2 = createMockRes();
    await limiter(createMockReq({ auth: undefined, ip: '198.51.100.2' }), res2 as Response, next);

    const res3 = createMockRes();
    await limiter(createMockReq({ auth: undefined, ip: '198.51.100.1' }), res3 as Response, next);

    expect(next).toHaveBeenCalledTimes(2);
    expect(res3.statusCode).toBe(429);
  });

  it('ignores spoofed tenant headers when auth context is present', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 1 });

    const res1 = createMockRes();
    await limiter(
      createMockReq({
        auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false },
        headers: { 'x-tenant-id': ['tenant-a', 'tenant-b'] },
      }),
      res1 as Response,
      next
    );

    const res2 = createMockRes();
    await limiter(
      createMockReq({
        auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false },
        headers: { 'x-tenant-id': ['tenant-b', 'tenant-a'] },
      }),
      res2 as Response,
      next
    );

    expect(next).toHaveBeenCalledTimes(1);
    expect(res2.statusCode).toBe(429);
  });

  it('normalizes tenant IDs to prevent case-based bypass', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 1 });

    const res1 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'tenant-1', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res1 as Response, next);

    const res2 = createMockRes();
    await limiter(createMockReq({ auth: { tenantId: 'TENANT-1', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false } }), res2 as Response, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res2.statusCode).toBe(429);
  });

  it('falls back to IP for malformed tenant IDs', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 2 });

    const res1 = createMockRes();
    await limiter(
      createMockReq({ auth: { tenantId: '../tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false }, ip: '198.51.100.9' }),
      res1 as Response,
      next
    );

    const res2 = createMockRes();
    await limiter(
      createMockReq({ auth: { tenantId: '<script>alert(1)</script>', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false }, ip: '198.51.100.9' }),
      res2 as Response,
      next
    );

    const res3 = createMockRes();
    await limiter(
      createMockReq({ auth: { tenantId: '${jndi:ldap://evil}', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false }, ip: '198.51.100.9' }),
      res3 as Response,
      next
    );

    expect(next).toHaveBeenCalledTimes(2);
    expect(res3.statusCode).toBe(429);
  });

  it('does not allow IP rotation to bypass tenant limits', async () => {
    const limiter = createTenantRateLimiter({ windowMs: 1000, maxRequests: 1 });

    const res1 = createMockRes();
    await limiter(
      createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false }, ip: '198.51.100.10' }),
      res1 as Response,
      next
    );

    const res2 = createMockRes();
    await limiter(
      createMockReq({ auth: { tenantId: 'tenant-a', apiKeyId: 'test-key', scopes: ['read'], isFleetAdmin: false }, ip: '198.51.100.11' }),
      res2 as Response,
      next
    );

    expect(next).toHaveBeenCalledTimes(1);
    expect(res2.statusCode).toBe(429);
  });
});

describe('PlaybookRateLimits constants', () => {
  it('defines create limit as 10/min', () => {
    expect(PlaybookRateLimits.create.windowMs).toBe(60_000);
    expect(PlaybookRateLimits.create.maxRequests).toBe(10);
  });

  it('defines execute limit as 30/min', () => {
    expect(PlaybookRateLimits.execute.windowMs).toBe(60_000);
    expect(PlaybookRateLimits.execute.maxRequests).toBe(30);
  });

  it('defines stepComplete limit as 100/min', () => {
    expect(PlaybookRateLimits.stepComplete.windowMs).toBe(60_000);
    expect(PlaybookRateLimits.stepComplete.maxRequests).toBe(100);
  });
});

describe('createPlaybookRateLimiters', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('returns create, execute, and stepComplete limiters', () => {
    const limiters = createPlaybookRateLimiters();
    expect(limiters).toHaveProperty('create');
    expect(limiters).toHaveProperty('execute');
    expect(limiters).toHaveProperty('stepComplete');
    expect(typeof limiters.create).toBe('function');
    expect(typeof limiters.execute).toBe('function');
    expect(typeof limiters.stepComplete).toBe('function');
  });

  it('enforces create limit (10/min per tenant)', async () => {
    const limiters = createPlaybookRateLimiters();
    const auth = { tenantId: 'pb-tenant', apiKeyId: 'k1', scopes: ['write'], isFleetAdmin: false };

    // Send 10 requests (should all pass)
    for (let i = 0; i < 10; i++) {
      const res = createMockRes();
      await limiters.create(createMockReq({ auth }), res as Response, next);
    }
    expect(next).toHaveBeenCalledTimes(10);

    // 11th request should be rate-limited
    const res11 = createMockRes();
    await limiters.create(createMockReq({ auth }), res11 as Response, next);
    expect(res11.statusCode).toBe(429);
    expect(next).toHaveBeenCalledTimes(10);
  });

  it('isolates create limits per tenant', async () => {
    const limiters = createPlaybookRateLimiters();
    const authA = { tenantId: 'iso-tenant-a', apiKeyId: 'k1', scopes: ['write'], isFleetAdmin: false };
    const authB = { tenantId: 'iso-tenant-b', apiKeyId: 'k2', scopes: ['write'], isFleetAdmin: false };

    // Exhaust tenant A's create limit
    for (let i = 0; i < 10; i++) {
      const res = createMockRes();
      await limiters.create(createMockReq({ auth: authA }), res as Response, next);
    }

    // Tenant B should still be allowed
    const resB = createMockRes();
    await limiters.create(createMockReq({ auth: authB }), resB as Response, next);
    expect(resB.statusCode).toBe(200);
    expect(next).toHaveBeenCalledTimes(11);
  });
});

describe('createAuthRateLimiters', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('returns ipBurst, ipFailures, and keyFailures limiters', () => {
    const limiters = createAuthRateLimiters();
    expect(limiters).toHaveProperty('ipBurst');
    expect(limiters).toHaveProperty('ipFailures');
    expect(limiters).toHaveProperty('keyFailures');
    expect(typeof limiters.ipBurst).toBe('function');
    expect(typeof limiters.ipFailures).toBe('function');
    expect(typeof limiters.keyFailures).toBe('function');
  });

  it('enforces ipBurst limit (10/sec per IP by default)', async () => {
    const limiters = createAuthRateLimiters();

    // Send 10 requests from same IP (should all pass)
    for (let i = 0; i < 10; i++) {
      const res = createMockRes();
      await limiters.ipBurst(
        createMockReq({ auth: undefined, ip: '10.0.0.1', headers: {} }),
        res as Response,
        next
      );
    }
    expect(next).toHaveBeenCalledTimes(10);

    // 11th should be rate-limited
    const resOver = createMockRes();
    await limiters.ipBurst(
      createMockReq({ auth: undefined, ip: '10.0.0.1', headers: {} }),
      resOver as Response,
      next
    );
    expect(resOver.statusCode).toBe(429);
    expect(next).toHaveBeenCalledTimes(10);
  });
});
