/**
 * API Versioning Middleware Tests
 *
 * Covers: vendor Accept header parsing, unsupported version rejection,
 * default version fallback, and X-API-Version response header.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { apiVersioning } from '../versioning.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockReq(accept?: string): Request {
  return {
    headers: accept !== undefined ? { accept } : {},
    originalUrl: '/api/v1/sensors',
  } as unknown as Request;
}

function createMockRes() {
  const res = {
    statusCode: 200,
    body: null as unknown,
    contentType: null as string | null,
    responseHeaders: {} as Record<string, string>,
    status: vi.fn(function (this: typeof res, code: number) {
      this.statusCode = code;
      return this;
    }),
    type: vi.fn(function (this: typeof res, value: string) {
      this.contentType = value;
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

const defaultOptions = {
  defaultVersion: 1,
  supportedVersions: [1, 2],
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('apiVersioning', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('parses vendor Accept header and extracts version', () => {
    const middleware = apiVersioning(defaultOptions);
    const req = createMockReq('application/vnd.atlascrew.v2+json');
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect((req as any).apiVersion).toBe(2);
    expect(res.responseHeaders['X-API-Version']).toBe('2');
    expect(res.responseHeaders['Content-Type']).toBe('application/vnd.atlascrew.v2+json');
  });

  it('returns 406 for unsupported version', () => {
    const middleware = apiVersioning(defaultOptions);
    const req = createMockReq('application/vnd.atlascrew.v99+json');
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(406);
    expect(res.body).toMatchObject({
      status: 406,
      code: 'UNSUPPORTED_VERSION',
      details: {
        requestedVersion: 99,
        supportedVersions: [1, 2],
      },
    });
  });

  it('uses default version when no Accept header is present', () => {
    const middleware = apiVersioning(defaultOptions);
    const req = createMockReq(undefined);
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect((req as any).apiVersion).toBe(1);
    expect(res.responseHeaders['X-API-Version']).toBe('1');
  });

  it('uses default version for generic application/json Accept', () => {
    const middleware = apiVersioning(defaultOptions);
    const req = createMockReq('application/json');
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect((req as any).apiVersion).toBe(1);
  });
});
