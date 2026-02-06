import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getEpochForTenant, incrementEpochForTenant, EpochLookupError } from '../epoch.js';
import type { RedisKv } from '../../storage/redis/kv.js';

function createMockKv(store: Map<string, string> = new Map()): RedisKv {
  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
      return true;
    }),
    del: vi.fn(async (key: string) => {
      const had = store.has(key) ? 1 : 0;
      store.delete(key);
      return had;
    }),
    incr: vi.fn(async (key: string) => {
      const current = parseInt(store.get(key) ?? '0', 10);
      const next = current + 1;
      store.set(key, String(next));
      return next;
    }),
    mget: vi.fn(async (keys: string[]) => keys.map((k) => store.get(k) ?? null)),
  };
}

describe('epoch', () => {
  let kv: RedisKv;
  let store: Map<string, string>;

  beforeEach(() => {
    store = new Map();
    kv = createMockKv(store);
  });

  describe('getEpochForTenant', () => {
    it('returns 0 when no epoch is set', async () => {
      expect(await getEpochForTenant('tenant-1', kv)).toBe(0);
    });

    it('returns stored epoch value', async () => {
      // Set a value directly in the backing store
      const key = Array.from(store.keys())[0]; // won't have a key yet
      await kv.set('horizon:v1:tenant-1:auth-epoch:current', '5');
      expect(await getEpochForTenant('tenant-1', kv)).toBe(5);
    });

    it('throws EpochLookupError on Redis error (fail-closed)', async () => {
      const failKv = createMockKv();
      vi.mocked(failKv.get).mockRejectedValue(new Error('connection refused'));
      await expect(getEpochForTenant('tenant-1', failKv)).rejects.toThrow(EpochLookupError);
      await expect(getEpochForTenant('tenant-1', failKv)).rejects.toThrow(
        /Failed to read auth epoch for tenant tenant-1/
      );
    });

    it('returns 0 for non-numeric stored value', async () => {
      await kv.set('horizon:v1:tenant-1:auth-epoch:current', 'garbage');
      // getEpochForTenant uses buildRedisKey internally, so we need to
      // set up the mock to return the garbage value for the correct key
      vi.mocked(kv.get).mockResolvedValue('garbage');
      expect(await getEpochForTenant('tenant-1', kv)).toBe(0);
    });
  });

  describe('incrementEpochForTenant', () => {
    it('increments from 0 to 1 on first call', async () => {
      const result = await incrementEpochForTenant('tenant-1', kv);
      expect(result).toBe(1);
      expect(kv.incr).toHaveBeenCalled();
    });

    it('increments existing epoch', async () => {
      // Pre-set epoch to 3 in the backing store
      store.set('horizon:v1:tenant-1:auth-epoch:current', '3');
      const result = await incrementEpochForTenant('tenant-1', kv);
      expect(result).toBe(4);
    });

    it('isolates epochs between tenants', async () => {
      await incrementEpochForTenant('tenant-a', kv);
      await incrementEpochForTenant('tenant-a', kv);

      const result = await incrementEpochForTenant('tenant-b', kv);
      expect(result).toBe(1);
    });
  });
});
