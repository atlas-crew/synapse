import { describe, expect, it, vi } from 'vitest';
import pino from 'pino';

import {
  RedisUserHistoryStore,
  ResilientUserHistoryStore,
  InMemoryUserHistoryStore,
  type LoginEvent,
} from './impossible-travel.js';
import type { RedisKv } from '../storage/redis/index.js';

const testLogger = pino({ level: 'silent' });

function createEvent(tenantId: string, userId: string, timestampMs: number): LoginEvent {
  return {
    userId,
    tenantId,
    timestamp: new Date(timestampMs),
    ip: '1.2.3.4',
    location: { latitude: 0, longitude: 0, countryCode: 'US', city: 'X' },
  };
}

function createMockKv(backing = new Map<string, string>()): RedisKv {
  return {
    get: vi.fn(async (key) => backing.get(key) ?? null),
    set: vi.fn(async (key, value) => {
      backing.set(key, value);
      return true;
    }),
    del: vi.fn(async (key) => {
      const existed = backing.delete(key);
      return existed ? 1 : 0;
    }),
    incr: vi.fn(async (key) => {
      const cur = Number(backing.get(key) ?? '0');
      const next = cur + 1;
      backing.set(key, String(next));
      return next;
    }),
    mget: vi.fn(async (keys: string[]) => keys.map((k) => backing.get(k) ?? null)),
  };
}

describe('RedisUserHistoryStore', () => {
  it('appends and returns previous history window', async () => {
    const kv = createMockKv();

    const store = new RedisUserHistoryStore(kv, testLogger, { namespace: 'horizon', version: 1 });

    const t0 = Date.now();
    const firstPrev = await store.appendAndGetPrevious(createEvent('tenant-1', 'user-1', t0), {
      historyWindowMs: 24 * 60 * 60 * 1000,
      maxHistoryPerUser: 10,
    });
    expect(firstPrev).toEqual([]);

    const secondPrev = await store.appendAndGetPrevious(createEvent('tenant-1', 'user-1', t0 + 1000), {
      historyWindowMs: 24 * 60 * 60 * 1000,
      maxHistoryPerUser: 10,
    });
    expect(secondPrev).toHaveLength(1);
    expect(secondPrev[0].userId).toBe('user-1');
  });

  it('trims history when exceeding maxHistoryPerUser', async () => {
    const kv = createMockKv();
    const store = new RedisUserHistoryStore(kv, testLogger, { namespace: 'horizon', version: 1 });

    const t0 = Date.now();
    const maxHistory = 3;
    const options = { historyWindowMs: 24 * 60 * 60 * 1000, maxHistoryPerUser: maxHistory };

    // Add maxHistory + 1 events to exceed the limit
    for (let i = 0; i < maxHistory + 1; i++) {
      await store.appendAndGetPrevious(createEvent('tenant-1', 'user-trim', t0 + i * 1000), options);
    }

    // The 5th event should see a trimmed history of at most maxHistory entries
    const prev = await store.appendAndGetPrevious(createEvent('tenant-1', 'user-trim', t0 + (maxHistory + 1) * 1000), options);
    expect(prev.length).toBeLessThanOrEqual(maxHistory);
  });

  it('passes ttlSeconds to kv.set when persisting history', async () => {
    const kv = createMockKv();
    const store = new RedisUserHistoryStore(kv, testLogger, { namespace: 'horizon', version: 1 });

    const t0 = Date.now();
    const historyWindowMs = 2 * 60 * 60 * 1000; // 2 hours
    await store.appendAndGetPrevious(createEvent('tenant-1', 'user-ttl', t0), {
      historyWindowMs,
      maxHistoryPerUser: 10,
    });

    // The history kv.set call (not the lock set) should include ttlSeconds.
    // Lock set uses ifNotExists, so filter for the history set call.
    const setCalls = vi.mocked(kv.set).mock.calls;
    const historySetCall = setCalls.find(
      (call) => call[2] && 'ttlSeconds' in call[2] && !('ifNotExists' in call[2])
    );
    expect(historySetCall).toBeDefined();
    expect(historySetCall![2]!.ttlSeconds).toBeGreaterThan(0);
  });
});

describe('ResilientUserHistoryStore', () => {
  it('falls back to in-memory store when primary (Redis) errors', async () => {
    const failingPrimary: RedisUserHistoryStore = {
      appendAndGetPrevious: vi.fn().mockRejectedValue(new Error('Redis connection lost')),
      delete: vi.fn().mockRejectedValue(new Error('Redis connection lost')),
    } as any;

    const fallback = new InMemoryUserHistoryStore();
    const resilient = new ResilientUserHistoryStore(testLogger, failingPrimary, fallback);

    const t0 = Date.now();
    const options = { historyWindowMs: 24 * 60 * 60 * 1000, maxHistoryPerUser: 10 };

    // First call: no history yet, fallback returns empty
    const prev1 = await resilient.appendAndGetPrevious(createEvent('tenant-1', 'user-r', t0), options);
    expect(prev1).toEqual([]);

    // Second call: fallback has the first event, should return it
    const prev2 = await resilient.appendAndGetPrevious(createEvent('tenant-1', 'user-r', t0 + 1000), options);
    expect(prev2).toHaveLength(1);
    expect(prev2[0].userId).toBe('user-r');
  });

  it('uses primary result when primary succeeds', async () => {
    const primaryStore = new InMemoryUserHistoryStore();
    const fallback = new InMemoryUserHistoryStore();
    const resilient = new ResilientUserHistoryStore(testLogger, primaryStore, fallback);

    const t0 = Date.now();
    const options = { historyWindowMs: 24 * 60 * 60 * 1000, maxHistoryPerUser: 10 };

    await resilient.appendAndGetPrevious(createEvent('tenant-1', 'user-p', t0), options);
    const prev = await resilient.appendAndGetPrevious(createEvent('tenant-1', 'user-p', t0 + 1000), options);

    // Should return primary result (1 previous event)
    expect(prev).toHaveLength(1);
  });
});

