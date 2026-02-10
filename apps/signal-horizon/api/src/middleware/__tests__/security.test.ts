/**
 * Security Middleware Tests
 *
 * Covers: enforceHttps skip in non-production, reject in production,
 * and HSTS header configuration.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { enforceHttps, hsts } from '../security.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockReq(overrides: Partial<Request> = {}): Request {
  return {
    secure: false,
    headers: {},
    ...overrides,
  } as unknown as Request;
}

function createMockRes() {
  const res = {
    statusCode: 200,
    body: null as unknown,
    responseHeaders: {} as Record<string, string>,
    status: vi.fn(function (this: typeof res, code: number) {
      this.statusCode = code;
      return this;
    }),
    json: vi.fn(function (this: typeof res, data: unknown) {
      this.body = data;
      return this;
    }),
    setHeader: vi.fn(function (this: typeof res, key: string, value: string) {
      this.responseHeaders[key] = value;
    }),
  };
  return res;
}

// ---------------------------------------------------------------------------
// enforceHttps
// ---------------------------------------------------------------------------

describe('enforceHttps', () => {
  const originalEnv = process.env.NODE_ENV;
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('skips enforcement in non-production (test) environment', () => {
    process.env.NODE_ENV = 'test';
    const req = createMockReq();
    const res = createMockRes();

    enforceHttps(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('rejects non-HTTPS requests in production', () => {
    process.env.NODE_ENV = 'production';
    const req = createMockReq({ secure: false, headers: {} });
    const res = createMockRes();

    enforceHttps(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({
      error: 'Forbidden',
      code: 'HTTPS_REQUIRED',
    });
  });

  it('allows HTTPS requests in production (via x-forwarded-proto)', () => {
    process.env.NODE_ENV = 'production';
    const req = createMockReq({
      secure: false,
      headers: { 'x-forwarded-proto': 'https' },
    });
    const res = createMockRes();

    enforceHttps(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// hsts
// ---------------------------------------------------------------------------

describe('hsts', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('sets HSTS header with default max-age', () => {
    const middleware = hsts();
    const req = createMockReq();
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(res.responseHeaders['Strict-Transport-Security']).toBe(
      'max-age=31536000; includeSubDomains; preload'
    );
  });

  it('sets HSTS header with custom max-age', () => {
    const middleware = hsts(86400);
    const req = createMockReq();
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(res.responseHeaders['Strict-Transport-Security']).toBe(
      'max-age=86400; includeSubDomains; preload'
    );
  });
});
