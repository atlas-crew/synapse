import { describe, expect, it, vi } from 'vitest';
import pino from 'pino';

import { RedisUserHistoryStore, type LoginEvent } from './impossible-travel.js';
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

describe('RedisUserHistoryStore', () => {
  it('appends and returns previous history window', async () => {
    const backing = new Map<string, string>();
    const kv: RedisKv = {
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
});

