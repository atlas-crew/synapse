/**
 * Request Validation Middleware Tests
 *
 * Covers: validateBody pass/reject, validateParams with UUID and CUID,
 * and PaginationQuerySchema defaults.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { z } from 'zod';
import type { Request, Response, NextFunction } from 'express';
import {
  validateBody,
  validateParams,
  validateQuery,
  IdParamSchema,
  PaginationQuerySchema,
} from '../validation.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockReq(overrides: Partial<Request> = {}): Request {
  return {
    body: {},
    query: {},
    params: {},
    path: '/test',
    method: 'POST',
    originalUrl: '/api/v1/test',
    ...overrides,
  } as unknown as Request;
}

function createMockRes() {
  const res = {
    statusCode: 200,
    body: null as unknown,
    contentType: null as string | null,
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
  };
  return res;
}

// ---------------------------------------------------------------------------
// validateBody
// ---------------------------------------------------------------------------

describe('validateBody', () => {
  const SensorSchema = z.object({
    name: z.string().min(1),
    host: z.string().url(),
  });

  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('calls next on valid body', () => {
    const middleware = validateBody(SensorSchema);
    const req = createMockReq({
      body: { name: 'edge-01', host: 'https://edge.example.com' },
    });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('returns 400 on invalid body', () => {
    const middleware = validateBody(SensorSchema);
    const req = createMockReq({
      body: { name: '', host: 'not-a-url' },
    });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// validateParams — IdParamSchema (UUID + CUID)
// ---------------------------------------------------------------------------

describe('validateParams with IdParamSchema', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('accepts a valid UUID', () => {
    const middleware = validateParams(IdParamSchema);
    const req = createMockReq({
      params: { id: '123e4567-e89b-12d3-a456-426614174000' },
    });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });

  it('accepts a valid CUID', () => {
    const middleware = validateParams(IdParamSchema);
    const req = createMockReq({
      params: { id: 'clh1234567890abcdef12345' },
    });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });

  it('rejects an invalid ID format', () => {
    const middleware = validateParams(IdParamSchema);
    const req = createMockReq({
      params: { id: 'not-valid-id' },
    });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// PaginationQuerySchema defaults
// ---------------------------------------------------------------------------

describe('PaginationQuerySchema via validateQuery', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('applies default limit=50 and offset=0 when omitted', () => {
    const middleware = validateQuery(PaginationQuerySchema);
    const req = createMockReq({ query: {} });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(req.query).toEqual({ limit: 50, offset: 0 });
  });

  it('coerces string query values to numbers', () => {
    const middleware = validateQuery(PaginationQuerySchema);
    const req = createMockReq({ query: { limit: '25', offset: '10' } });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(req.query).toEqual({ limit: 25, offset: 10 });
  });
});
