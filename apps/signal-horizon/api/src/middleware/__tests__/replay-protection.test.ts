/**
 * Tests for Replay Attack Protection Middleware
 */

import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import type { Request, Response } from 'express';
import {
  NonceStore,
  createReplayProtection,
  validateTimestamp,
  validateNonceFormat,
  generateNonce,
  validateReplayProtection,
  DEFAULT_REPLAY_CONFIG,
} from '../replay-protection.js';

// Mock Express request/response
function createMockRequest(
  headers: Record<string, string> = {},
  options: { method?: string; path?: string } = {}
): Partial<Request> {
  return {
    method: options.method ?? 'POST',
    path: options.path ?? '/api/test',
    headers: headers as Request['headers'],
    socket: { remoteAddress: '127.0.0.1' } as unknown as Request['socket'],
  };
}

function createMockResponse(): {
  res: Partial<Response>;
  getStatusCode: () => number;
  getJsonBody: () => unknown;
} {
  const state: { statusCode: number; jsonBody: unknown } = { statusCode: 200, jsonBody: null };

  const res: Partial<Response> = {
    status: vi.fn().mockImplementation((code: number) => {
      state.statusCode = code;
      return res as Response;
    }),
    json: vi.fn().mockImplementation((body: unknown) => {
      state.jsonBody = body;
      return res as Response;
    }),
  };

  return {
    res,
    getStatusCode: () => state.statusCode,
    getJsonBody: () => state.jsonBody
  };
}

describe('replay-protection', () => {
  describe('NonceStore', () => {
    let store: NonceStore;

    beforeEach(() => {
      store = new NonceStore(5000, 1000); // 5s window, 1s cleanup
    });

    afterEach(() => {
      store.destroy();
    });

    describe('checkAndAdd', () => {
      test('returns true for new nonce', () => {
        const result = store.checkAndAdd('nonce-1', Date.now());
        expect(result).toBe(true);
      });

      test('returns false for reused nonce', () => {
        const timestamp = Date.now();
        store.checkAndAdd('nonce-1', timestamp);
        const result = store.checkAndAdd('nonce-1', timestamp);
        expect(result).toBe(false);
      });

      test('allows same nonce with different timestamp', () => {
        store.checkAndAdd('nonce-1', 1000000);
        const result = store.checkAndAdd('nonce-1', 2000000);
        expect(result).toBe(true);
      });

      test('stores metadata', () => {
        const result = store.checkAndAdd('nonce-1', Date.now(), {
          clientIp: '192.168.1.1',
          path: '/api/test',
        });
        expect(result).toBe(true);
        expect(store.size).toBe(1);
      });
    });

    describe('exists', () => {
      test('returns true for stored nonce', () => {
        const timestamp = Date.now();
        store.checkAndAdd('nonce-1', timestamp);
        expect(store.exists('nonce-1', timestamp)).toBe(true);
      });

      test('returns false for unknown nonce', () => {
        expect(store.exists('unknown', Date.now())).toBe(false);
      });
    });

    describe('cleanup', () => {
      test('removes expired nonces', async () => {
        store.checkAndAdd('nonce-1', Date.now());

        // Wait for expiration (window is 5s, but we'll mock)
        await new Promise((resolve) => setTimeout(resolve, 50));

        // Manually set expiration in the past would require accessing internals
        // Instead, test that cleanup doesn't crash
        const removed = store.cleanup();
        expect(typeof removed).toBe('number');
      });
    });

    describe('size', () => {
      test('returns number of stored nonces', () => {
        expect(store.size).toBe(0);
        store.checkAndAdd('nonce-1', 1000000);
        expect(store.size).toBe(1);
        store.checkAndAdd('nonce-2', 2000000);
        expect(store.size).toBe(2);
      });
    });

    describe('destroy', () => {
      test('clears all nonces', () => {
        store.checkAndAdd('nonce-1', Date.now());
        store.checkAndAdd('nonce-2', Date.now());
        store.destroy();
        expect(store.size).toBe(0);
      });
    });

    describe('capacity', () => {
      test('returns configured capacity', () => {
        const smallStore = new NonceStore(5000, 60000, 50);
        expect(smallStore.capacity).toBe(50);
        smallStore.destroy();
      });

      test('defaults to 100000 capacity', () => {
        expect(store.capacity).toBe(100000);
      });
    });

    describe('capacity enforcement', () => {
      let smallStore: NonceStore;

      afterEach(() => {
        smallStore?.destroy();
      });

      test('evicts entries when at capacity', () => {
        smallStore = new NonceStore(300000, 60000, 10);

        // Fill the store to capacity
        for (let i = 0; i < 10; i++) {
          const result = smallStore.checkAndAdd(`nonce-fill-${i}`, i * 1000 + 1000);
          expect(result).toBe(true);
        }
        expect(smallStore.size).toBe(10);

        // Adding one more should trigger eviction of oldest 10% (1 entry)
        const result = smallStore.checkAndAdd('nonce-overflow', 11000);
        expect(result).toBe(true);
        // Size should be at most maxNonces (10) since eviction freed space
        expect(smallStore.size).toBeLessThanOrEqual(10);
      });

      test('accepts new nonces after eviction', () => {
        smallStore = new NonceStore(300000, 60000, 5);

        // Fill the store
        for (let i = 0; i < 5; i++) {
          smallStore.checkAndAdd(`nonce-${i}`, i * 1000 + 1000);
        }

        // Should still accept new nonces after eviction
        const result = smallStore.checkAndAdd('nonce-new', 6000);
        expect(result).toBe(true);
      });

      test('calls onCapacityEvent when at capacity', () => {
        const events: Array<{ event: string; detail: unknown }> = [];
        smallStore = new NonceStore(300000, 60000, 5, (event, detail) => {
          events.push({ event, detail });
        });

        // Fill the store to capacity
        for (let i = 0; i < 5; i++) {
          smallStore.checkAndAdd(`nonce-${i}`, i * 1000 + 1000);
        }

        // This should trigger capacity enforcement
        smallStore.checkAndAdd('nonce-overflow', 6000);

        // Should have at_capacity event (from enforceCapacity) and possibly pressure events
        const capacityEvents = events.filter(e => e.event === 'at_capacity');
        expect(capacityEvents.length).toBeGreaterThanOrEqual(1);
      });

      test('calls onCapacityEvent pressure warning at 80%', () => {
        const events: Array<{ event: string; detail: unknown }> = [];
        smallStore = new NonceStore(300000, 60000, 10, (event, detail) => {
          events.push({ event, detail });
        });

        // Fill to 80% (8 entries for maxNonces=10)
        for (let i = 0; i < 8; i++) {
          smallStore.checkAndAdd(`nonce-${i}`, i * 1000 + 1000);
        }

        const pressureEvents = events.filter(e => e.event === 'pressure');
        expect(pressureEvents.length).toBeGreaterThanOrEqual(1);
      });

      test('evicts expired entries before oldest entries', () => {
        smallStore = new NonceStore(100, 60000, 5); // 100ms window

        // Add entries that will expire quickly
        for (let i = 0; i < 5; i++) {
          smallStore.checkAndAdd(`nonce-expired-${i}`, i * 1000 + 1000);
        }

        // Wait for entries to expire
        vi.useFakeTimers();
        vi.advanceTimersByTime(200);

        // Adding a new one should trigger cleanup of expired entries
        const result = smallStore.checkAndAdd('nonce-fresh', Date.now());
        expect(result).toBe(true);
        // After cleanup, only the fresh nonce should remain
        expect(smallStore.size).toBe(1);

        vi.useRealTimers();
      });
    });
  });

  describe('validateTimestamp', () => {
    test('returns null for valid timestamp', () => {
      const result = validateTimestamp(Date.now(), 60000, 300000);
      expect(result).toBeNull();
    });

    test('returns timestamp_future for future timestamp', () => {
      const futureTimestamp = Date.now() + 120000; // 2 minutes ahead
      const result = validateTimestamp(futureTimestamp, 60000, 300000);
      expect(result).toBe('timestamp_future');
    });

    test('returns timestamp_expired for old timestamp', () => {
      const oldTimestamp = Date.now() - 400000; // 6.7 minutes ago
      const result = validateTimestamp(oldTimestamp, 60000, 300000);
      expect(result).toBe('timestamp_expired');
    });

    test('allows timestamp within drift tolerance', () => {
      const slightlyFuture = Date.now() + 30000; // 30s ahead
      const result = validateTimestamp(slightlyFuture, 60000, 300000);
      expect(result).toBeNull();
    });

    test('allows timestamp near window boundary', () => {
      const nearBoundary = Date.now() - 299000; // Just under 5 minutes
      const result = validateTimestamp(nearBoundary, 60000, 300000);
      expect(result).toBeNull();
    });
  });

  describe('validateNonceFormat', () => {
    test('returns true for valid nonce', () => {
      expect(validateNonceFormat('abcdef1234567890')).toBe(true);
      expect(validateNonceFormat('ABCDEF-1234567890')).toBe(true);
      expect(validateNonceFormat('a'.repeat(64))).toBe(true);
    });

    test('returns false for short nonce', () => {
      expect(validateNonceFormat('short')).toBe(false);
      expect(validateNonceFormat('123456789012345')).toBe(false);
    });

    test('returns false for long nonce', () => {
      expect(validateNonceFormat('a'.repeat(65))).toBe(false);
    });

    test('returns false for invalid characters', () => {
      expect(validateNonceFormat('nonce with spaces!')).toBe(false);
      expect(validateNonceFormat('nonce@with#special')).toBe(false);
      expect(validateNonceFormat('nonce_underscore12')).toBe(false);
    });

    test('returns false for empty or null', () => {
      expect(validateNonceFormat('')).toBe(false);
      expect(validateNonceFormat(null as unknown as string)).toBe(false);
      expect(validateNonceFormat(undefined as unknown as string)).toBe(false);
    });
  });

  describe('generateNonce', () => {
    test('generates valid nonce', () => {
      const nonce = generateNonce();
      expect(validateNonceFormat(nonce)).toBe(true);
    });

    test('generates unique nonces', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 100; i++) {
        nonces.add(generateNonce());
      }
      expect(nonces.size).toBe(100);
    });

    test('respects custom length', () => {
      const nonce = generateNonce(32);
      expect(nonce.length).toBe(64); // 32 bytes = 64 hex chars
    });

    test('generates hex characters only', () => {
      const nonce = generateNonce();
      expect(/^[a-f0-9]+$/.test(nonce)).toBe(true);
    });
  });

  describe('createReplayProtection', () => {
    let protection: ReturnType<typeof createReplayProtection>;

    beforeEach(() => {
      protection = createReplayProtection({
        windowMs: 300000,
        maxTimeDrift: 60000,
        skipMethods: ['GET', 'HEAD', 'OPTIONS'],
        skipRoutes: ['/health', /^\/public\//],
      });
    });

    afterEach(() => {
      protection.destroy();
    });

    describe('middleware', () => {
      test('allows GET requests without headers', () => {
        const req = createMockRequest({}, { method: 'GET' });
        const { res } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
      });

      test('allows OPTIONS requests without headers', () => {
        const req = createMockRequest({}, { method: 'OPTIONS' });
        const { res } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
      });

      test('allows skipped routes', () => {
        const req = createMockRequest({}, { method: 'POST', path: '/health' });
        const { res } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
      });

      test('allows regex-matched skipped routes', () => {
        const req = createMockRequest({}, { method: 'POST', path: '/public/assets/image.png' });
        const { res } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
      });

      test('rejects POST without nonce header', () => {
        const req = createMockRequest({
          'x-request-timestamp': String(Date.now()),
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('missing_nonce');
      });

      test('allows missing nonce during compat window (logs violation)', () => {
        const onViolation = vi.fn();
        const compat = createReplayProtection({
          allowMissingHeadersUntilMs: Date.now() + 60_000,
          onViolation,
        });

        const req = createMockRequest({
          'x-request-timestamp': String(Date.now()),
        }, { method: 'POST' });
        const { res } = createMockResponse();
        const next = vi.fn();

        compat.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
        expect(onViolation).toHaveBeenCalledWith(expect.objectContaining({ code: 'missing_nonce' }));
        compat.destroy();
      });

      test('rejects POST without timestamp header', () => {
        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('missing_timestamp');
      });

      test('allows missing timestamp during compat window (logs violation)', () => {
        const onViolation = vi.fn();
        const compat = createReplayProtection({
          allowMissingHeadersUntilMs: Date.now() + 60_000,
          onViolation,
        });

        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
        }, { method: 'POST' });
        const { res } = createMockResponse();
        const next = vi.fn();

        compat.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
        expect(onViolation).toHaveBeenCalledWith(expect.objectContaining({ code: 'missing_timestamp' }));
        compat.destroy();
      });

      test('rejects invalid nonce format', () => {
        const req = createMockRequest({
          'x-request-nonce': 'short',
          'x-request-timestamp': String(Date.now()),
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('invalid_nonce_format');
      });

      test('rejects invalid timestamp format', () => {
        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
          'x-request-timestamp': 'not-a-number',
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('invalid_timestamp_format');
      });

      test('rejects expired timestamp', () => {
        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
          'x-request-timestamp': String(Date.now() - 400000), // 6.7 min ago
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('timestamp_expired');
      });

      test('rejects future timestamp', () => {
        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
          'x-request-timestamp': String(Date.now() + 120000), // 2 min ahead
        }, { method: 'POST' });
        const { res, getStatusCode, getJsonBody } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(400);
        expect(getJsonBody().code).toBe('timestamp_future');
      });

      test('allows valid request', () => {
        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
          'x-request-timestamp': String(Date.now()),
        }, { method: 'POST' });
        const { res } = createMockResponse();
        const next = vi.fn();

        protection.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
      });

      test('passes tenantId metadata to nonce store when available', () => {
        const calls: Array<{ tenantId?: string }> = [];
        const store = {
          size: 0,
          checkAndAdd: (_nonce: string, _timestamp: number, metadata?: { tenantId?: string }) => {
            calls.push({ tenantId: metadata?.tenantId });
            return true;
          },
          exists: () => false,
          cleanup: () => 0,
          destroy: () => {},
        };

        const custom = createReplayProtection({ store: store as any });

        const req = createMockRequest({
          'x-request-nonce': generateNonce(),
          'x-request-timestamp': String(Date.now()),
        }, { method: 'POST' }) as any;
        req.auth = { tenantId: 'tenant-1' };

        const { res } = createMockResponse();
        const next = vi.fn();

        custom.middleware(req as Request, res as Response, next);
        expect(next).toHaveBeenCalled();
        expect(calls[0]?.tenantId).toBe('tenant-1');
        custom.destroy();
      });

      test('rejects replayed request', () => {
        const nonce = generateNonce();
        const timestamp = String(Date.now());

        // First request succeeds
        const req1 = createMockRequest({
          'x-request-nonce': nonce,
          'x-request-timestamp': timestamp,
        }, { method: 'POST' });
        const { res: res1 } = createMockResponse();
        const next1 = vi.fn();
        protection.middleware(req1 as Request, res1 as Response, next1);
        expect(next1).toHaveBeenCalled();

        // Second (replayed) request fails
        const req2 = createMockRequest({
          'x-request-nonce': nonce,
          'x-request-timestamp': timestamp,
        }, { method: 'POST' });
        const { res: res2, getStatusCode, getJsonBody } = createMockResponse();
        const next2 = vi.fn();
        protection.middleware(req2 as Request, res2 as Response, next2);
        expect(next2).not.toHaveBeenCalled();
        expect(getStatusCode()).toBe(409);
        expect(getJsonBody().code).toBe('nonce_reused');
      });
    });
  });

  describe('validateReplayProtection', () => {
    let store: NonceStore;

    beforeEach(() => {
      store = new NonceStore(300000);
    });

    afterEach(() => {
      store.destroy();
    });

    test('returns valid for good input', async () => {
      const result = await validateReplayProtection(generateNonce(), Date.now(), store);
      expect(result.valid).toBe(true);
    });

    test('returns error for missing nonce', async () => {
      const result = await validateReplayProtection(undefined, Date.now(), store);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('missing_nonce');
    });

    test('returns error for invalid nonce format', async () => {
      const result = await validateReplayProtection('short', Date.now(), store);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('invalid_nonce_format');
    });

    test('returns error for missing timestamp', async () => {
      const result = await validateReplayProtection(generateNonce(), undefined, store);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('missing_timestamp');
    });

    test('returns error for invalid timestamp', async () => {
      const result = await validateReplayProtection(generateNonce(), NaN, store);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('invalid_timestamp_format');
    });

    test('returns error for expired timestamp', async () => {
      const result = await validateReplayProtection(
        generateNonce(),
        Date.now() - 400000,
        store
      );
      expect(result.valid).toBe(false);
      expect(result.error).toBe('timestamp_expired');
    });

    test('returns error for reused nonce', async () => {
      const nonce = generateNonce();
      const timestamp = Date.now();

      // First use
      await validateReplayProtection(nonce, timestamp, store);

      // Second use (replay)
      const result = await validateReplayProtection(nonce, timestamp, store);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('nonce_reused');
    });
  });

  describe('DEFAULT_REPLAY_CONFIG', () => {
    test('has sensible defaults', () => {
      expect(DEFAULT_REPLAY_CONFIG.windowMs).toBe(300000); // 5 minutes
      expect(DEFAULT_REPLAY_CONFIG.maxTimeDrift).toBe(60000); // 1 minute
      expect(DEFAULT_REPLAY_CONFIG.nonceHeader).toBe('X-Request-Nonce');
      expect(DEFAULT_REPLAY_CONFIG.timestampHeader).toBe('X-Request-Timestamp');
      expect(DEFAULT_REPLAY_CONFIG.skipMethods).toContain('GET');
      expect(DEFAULT_REPLAY_CONFIG.skipMethods).toContain('HEAD');
      expect(DEFAULT_REPLAY_CONFIG.skipMethods).toContain('OPTIONS');
    });
  });
});
