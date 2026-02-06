import { describe, expect, it, vi } from 'vitest';

import { createIoredisKv, createNodeRedisKv } from './kv.js';

const ioredisBase = () => ({
  get: vi.fn(async () => null),
  del: vi.fn(async () => 0),
  set: vi.fn(async () => 'OK' as const),
  incr: vi.fn(async () => 1),
  expire: vi.fn(async () => 1),
  mget: vi.fn(async (..._keys: string[]) => [] as (string | null)[]),
});

const nodeRedisBase = () => ({
  get: vi.fn(async () => null),
  del: vi.fn(async () => 0),
  set: vi.fn(async () => 'OK' as const),
  incr: vi.fn(async () => 1),
  expire: vi.fn(async () => true as boolean),
  mget: vi.fn(async (_keys: string[]) => [] as (string | null)[]),
});

describe('createIoredisKv', () => {
  it('maps ttlSeconds + ifNotExists to SET EX NX', async () => {
    const client = ioredisBase();
    const kv = createIoredisKv(client);
    await expect(kv.set('k', 'v', { ttlSeconds: 60, ifNotExists: true })).resolves.toBe(true);
    expect(client.set).toHaveBeenCalledWith('k', 'v', 'EX', 60, 'NX');
  });

  it('returns false when NX prevents set', async () => {
    const client = { ...ioredisBase(), set: vi.fn(async () => null) };
    const kv = createIoredisKv(client);
    await expect(kv.set('k', 'v', { ttlSeconds: 60, ifNotExists: true })).resolves.toBe(false);
  });
});

describe('createNodeRedisKv', () => {
  it('maps ttlSeconds + ifNotExists to SET {EX, NX}', async () => {
    const client = nodeRedisBase();
    const kv = createNodeRedisKv(client);
    await expect(kv.set('k', 'v', { ttlSeconds: 60, ifNotExists: true })).resolves.toBe(true);
    expect(client.set).toHaveBeenCalledWith('k', 'v', { EX: 60, NX: true });
  });
});

describe('mget', () => {
  it('ioredis adapter delegates to client.mget', async () => {
    const client = { ...ioredisBase(), mget: vi.fn(async (..._keys: string[]) => ['val1', null, 'val3']) };
    const kv = createIoredisKv(client);
    const result = await kv.mget(['k1', 'k2', 'k3']);
    expect(result).toEqual(['val1', null, 'val3']);
    expect(client.mget).toHaveBeenCalledWith('k1', 'k2', 'k3');
  });

  it('node-redis adapter delegates to client.mget', async () => {
    const client = { ...nodeRedisBase(), mget: vi.fn(async (_keys: string[]) => ['val1', null]) };
    const kv = createNodeRedisKv(client);
    const result = await kv.mget(['k1', 'k2']);
    expect(result).toEqual(['val1', null]);
    expect(client.mget).toHaveBeenCalledWith(['k1', 'k2']);
  });
});
