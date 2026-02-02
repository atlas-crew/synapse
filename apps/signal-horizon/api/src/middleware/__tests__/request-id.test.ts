/**
 * Request ID Middleware Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';
import { requestId } from '../request-id.js';

describe('requestId middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      get: vi.fn(),
    };
    mockRes = {
      setHeader: vi.fn(),
    };
    mockNext = vi.fn();
  });

  it('should generate new UUID when no X-Request-ID header', () => {
    vi.mocked(mockReq.get!).mockReturnValue(undefined);

    const middleware = requestId();
    middleware(mockReq as Request, mockRes as Response, mockNext);

    // Should generate a valid UUID v4
    const generatedId = (mockReq as Request & { id: string }).id;
    expect(generatedId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );

    // Should set response header
    expect(mockRes.setHeader).toHaveBeenCalledWith('X-Request-ID', generatedId);

    // Should call next
    expect(mockNext).toHaveBeenCalled();
  });

  it('should use existing X-Request-ID header if valid UUID', () => {
    const existingId = '550e8400-e29b-41d4-a716-446655440000';
    vi.mocked(mockReq.get!).mockReturnValue(existingId);

    const middleware = requestId();
    middleware(mockReq as Request, mockRes as Response, mockNext);

    // Should use existing ID
    const id = (mockReq as Request & { id: string }).id;
    expect(id).toBe(existingId);

    // Should set response header with same ID
    expect(mockRes.setHeader).toHaveBeenCalledWith('X-Request-ID', existingId);

    // Should call next
    expect(mockNext).toHaveBeenCalled();
  });

  it('should generate new UUID when X-Request-ID is invalid', () => {
    vi.mocked(mockReq.get!).mockReturnValue('not-a-valid-uuid');

    const middleware = requestId();
    middleware(mockReq as Request, mockRes as Response, mockNext);

    // Should generate new valid UUID v4
    const generatedId = (mockReq as Request & { id: string }).id;
    expect(generatedId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(generatedId).not.toBe('not-a-valid-uuid');

    // Should set response header with generated ID
    expect(mockRes.setHeader).toHaveBeenCalledWith('X-Request-ID', generatedId);

    // Should call next
    expect(mockNext).toHaveBeenCalled();
  });

  it('should reject UUID v1 format (wrong version)', () => {
    // UUID v1 has version 1 in position 13
    const uuidV1 = '550e8400-e29b-11d4-a716-446655440000';
    vi.mocked(mockReq.get!).mockReturnValue(uuidV1);

    const middleware = requestId();
    middleware(mockReq as Request, mockRes as Response, mockNext);

    // Should generate new UUID, not use v1
    const generatedId = (mockReq as Request & { id: string }).id;
    expect(generatedId).not.toBe(uuidV1);
    expect(generatedId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  it('should reject empty string', () => {
    vi.mocked(mockReq.get!).mockReturnValue('');

    const middleware = requestId();
    middleware(mockReq as Request, mockRes as Response, mockNext);

    // Should generate new UUID
    const generatedId = (mockReq as Request & { id: string }).id;
    expect(generatedId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(generatedId).not.toBe('');
  });
});
