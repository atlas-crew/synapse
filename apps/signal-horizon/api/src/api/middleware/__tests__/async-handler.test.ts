/**
 * Async Error Handler Middleware Tests
 *
 * Covers: HttpError variants, Prisma error mapping, ZodError handling,
 * default unknown error, and production mode error detail suppression.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { asyncHandler, HttpError, createErrorHandler } from '../async-handler.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockReq(overrides: Partial<Request> = {}): Request {
  return {
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

function createMockLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    child: vi.fn().mockReturnThis(),
  };
}

// ---------------------------------------------------------------------------
// asyncHandler
// ---------------------------------------------------------------------------

describe('asyncHandler', () => {
  it('calls next on rejected promise', async () => {
    const error = new Error('boom');
    const handler = asyncHandler(async () => {
      throw error;
    });

    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    handler(req, res as unknown as Response, next);

    // Give the microtask queue a tick
    await new Promise((r) => setTimeout(r, 0));

    expect(next).toHaveBeenCalledWith(error);
  });

  it('does not call next when handler succeeds', async () => {
    const handler = asyncHandler(async (_req, res) => {
      res.status(200).json({ ok: true });
    });

    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    handler(req, res as unknown as Response, next);

    await new Promise((r) => setTimeout(r, 0));

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// HttpError static factories
// ---------------------------------------------------------------------------

describe('HttpError', () => {
  it('badRequest creates 400 error', () => {
    const err = HttpError.badRequest('bad input', { field: 'name' });
    expect(err.statusCode).toBe(400);
    expect(err.message).toBe('bad input');
    expect(err.code).toBe('BAD_REQUEST');
    expect(err.details).toEqual({ field: 'name' });
  });

  it('unauthorized creates 401 error with default message', () => {
    const err = HttpError.unauthorized();
    expect(err.statusCode).toBe(401);
    expect(err.message).toBe('Unauthorized');
    expect(err.code).toBe('UNAUTHORIZED');
  });

  it('forbidden creates 403 error with default message', () => {
    const err = HttpError.forbidden();
    expect(err.statusCode).toBe(403);
    expect(err.message).toBe('Access denied');
    expect(err.code).toBe('FORBIDDEN');
  });

  it('notFound creates 404 error with resource label', () => {
    const err = HttpError.notFound('Sensor');
    expect(err.statusCode).toBe(404);
    expect(err.message).toBe('Sensor not found');
    expect(err.code).toBe('NOT_FOUND');
  });

  it('internal creates 500 error with default message', () => {
    const err = HttpError.internal();
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe('Internal server error');
    expect(err.code).toBe('INTERNAL_ERROR');
  });
});

// ---------------------------------------------------------------------------
// createErrorHandler
// ---------------------------------------------------------------------------

describe('createErrorHandler', () => {
  const originalEnv = process.env.NODE_ENV;
  let logger: ReturnType<typeof createMockLogger>;
  let errorHandler: (err: Error, req: Request, res: Response, next: NextFunction) => void;
  let next: NextFunction;

  beforeEach(() => {
    logger = createMockLogger();
    errorHandler = createErrorHandler(logger as any);
    next = vi.fn();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  it('handles HttpError and returns problem+json', () => {
    const err = HttpError.badRequest('missing field');
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(400);
    expect(res.contentType).toBe('application/problem+json');
    expect(res.body).toMatchObject({
      status: 400,
      detail: 'missing field',
      code: 'BAD_REQUEST',
      instance: '/api/v1/test',
    });
    expect(logger.error).toHaveBeenCalled();
  });

  it('maps Prisma P2025 to 404', () => {
    const err = Object.assign(new Error('Record not found'), {
      name: 'PrismaClientKnownRequestError',
      code: 'P2025',
    });
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject({
      status: 404,
      code: 'NOT_FOUND',
    });
  });

  it('maps Prisma P2002 to 409', () => {
    const err = Object.assign(new Error('Unique constraint'), {
      name: 'PrismaClientKnownRequestError',
      code: 'P2002',
    });
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(409);
    expect(res.body).toMatchObject({
      status: 409,
      code: 'CONFLICT',
    });
  });

  it('maps ZodError to 400 validation error', () => {
    const err = Object.assign(new Error('Validation'), {
      name: 'ZodError',
      errors: [{ path: ['name'], message: 'Required' }],
    });
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      status: 400,
      code: 'VALIDATION_ERROR',
    });
  });

  it('returns 500 for unknown errors', () => {
    const err = new Error('something unexpected');
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(500);
    expect(res.body).toMatchObject({
      status: 500,
      detail: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  });

  it('includes error details in development mode', () => {
    process.env.NODE_ENV = 'development';
    // Recreate handler to pick up new env
    errorHandler = createErrorHandler(logger as any);

    const err = new Error('dev details');
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(500);
    const body = res.body as Record<string, unknown>;
    expect(body.details).toEqual({ message: 'dev details' });
  });

  it('hides error details in production mode', () => {
    process.env.NODE_ENV = 'production';
    errorHandler = createErrorHandler(logger as any);

    const err = new Error('secret internals');
    const req = createMockReq();
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.statusCode).toBe(500);
    const body = res.body as Record<string, unknown>;
    expect(body.details).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('secret internals');
  });

  it('sets instance to req.originalUrl', () => {
    const err = new Error('oops');
    const req = createMockReq({ originalUrl: '/api/v1/sensors/abc' });
    const res = createMockRes();

    errorHandler(err, req, res as unknown as Response, next);

    expect(res.body).toMatchObject({ instance: '/api/v1/sensors/abc' });
  });
});
