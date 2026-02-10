/**
 * JSON Depth Limiting Middleware Tests (WS4-003)
 *
 * Covers: shallow pass-through, at-limit pass, over-limit rejection,
 * circuit breaker, array nesting, and empty/no-body skip.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { jsonDepthLimit } from '../json-depth.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockReq(body?: unknown): Request {
  return { body } as unknown as Request;
}

function createMockRes() {
  const res = {
    statusCode: 200,
    body: null as unknown,
    status: vi.fn(function (this: typeof res, code: number) {
      this.statusCode = code;
      return this;
    }),
    json: vi.fn(function (this: typeof res, data: unknown) {
      this.body = data;
      return this;
    }),
  };
  return res;
}

/** Build a nested object with the given depth: { a: { a: { ... } } } */
function nested(depth: number): Record<string, unknown> {
  let obj: Record<string, unknown> = { leaf: true };
  for (let i = 1; i < depth; i++) {
    obj = { a: obj };
  }
  return obj;
}

/** Build a nested array to the given depth: [[[ ... ]]] */
function nestedArray(depth: number): unknown {
  let arr: unknown = ['leaf'];
  for (let i = 1; i < depth; i++) {
    arr = [arr];
  }
  return arr;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('jsonDepthLimit', () => {
  let next: NextFunction;

  beforeEach(() => {
    next = vi.fn();
  });

  it('passes shallow JSON through', () => {
    const middleware = jsonDepthLimit(20);
    const req = createMockReq({ name: 'test', value: 42 });
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('passes JSON at exactly the depth limit', () => {
    const maxDepth = 5;
    const middleware = jsonDepthLimit(maxDepth);
    const req = createMockReq(nested(maxDepth));
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });

  it('rejects JSON one level over the limit with 400', () => {
    const maxDepth = 5;
    const middleware = jsonDepthLimit(maxDepth);
    const req = createMockReq(nested(maxDepth + 1));
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({
      error: 'Request payload too deeply nested',
      code: 'JSON_DEPTH_EXCEEDED',
      maxDepth,
    });
  });

  it('triggers circuit breaker for extremely deep payloads', () => {
    // Circuit breaker at depth 100 — build a 101-level nested object
    const middleware = jsonDepthLimit(20);
    const req = createMockReq(nested(101));
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('counts array nesting depth', () => {
    const maxDepth = 3;
    const middleware = jsonDepthLimit(maxDepth);
    // nestedArray(4) creates 4 levels: [ [ [ ['leaf'] ] ] ]
    const req = createMockReq(nestedArray(maxDepth + 1));
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('skips when body is empty/undefined', () => {
    const middleware = jsonDepthLimit(20);
    const req = createMockReq(undefined);
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });

  it('skips when body is a non-object (string)', () => {
    const middleware = jsonDepthLimit(20);
    const req = createMockReq('plain text');
    const res = createMockRes();

    middleware(req, res as unknown as Response, next);

    expect(next).toHaveBeenCalled();
  });
});
