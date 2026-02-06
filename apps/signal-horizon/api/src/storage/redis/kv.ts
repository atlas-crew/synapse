export interface RedisKvSetOptions {
  ttlSeconds?: number;
  /**
   * Only set if key does not already exist.
   */
  ifNotExists?: boolean;
}

/**
 * Minimal key/value surface used by state stores.
 *
 * Intentionally client-agnostic:
 * - `ioredis` uses SET key val EX <ttl> NX
 * - `redis` (node-redis) uses SET key val { EX, NX }
 */
export interface RedisKv {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: RedisKvSetOptions): Promise<boolean>;
  del(key: string): Promise<number>;
  /**
   * Atomically increment a key by 1, returning the new value.
   * If the key does not exist it is initialised to 0 before incrementing.
   * Optionally sets a TTL (only applied when the key is first created, i.e. result === 1).
   */
  incr(key: string, options?: { ttlSeconds?: number }): Promise<number>;
  /**
   * Atomically increment a key by a specific amount, returning the new value.
   * Optionally sets a TTL (only applied when the key is first created).
   */
  incrby(key: string, amount: number, options?: { ttlSeconds?: number }): Promise<number>;
  /**
   * Fetch multiple keys in a single round-trip (Redis MGET).
   * Returns an array whose order matches `keys`; missing keys are `null`.
   */
  mget(keys: string[]): Promise<(string | null)[]>;
  /** Add members to a set. Returns the number of new members added. */
  sadd(key: string, ...members: string[]): Promise<number>;
  /** Remove members from a set. Returns the number of members removed. */
  srem(key: string, ...members: string[]): Promise<number>;
  /** Get all members of a set. */
  smembers(key: string): Promise<string[]>;
}

export interface IoredisLikeClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    mode?: 'EX',
    ttlSeconds?: number,
    flag?: 'NX'
  ): Promise<'OK' | null>;
  del(key: string): Promise<number>;
  incr(key: string): Promise<number>;
  incrby(key: string, amount: number): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  sadd(key: string, ...members: string[]): Promise<number>;
  srem(key: string, ...members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}

export function createIoredisKv(client: IoredisLikeClient): RedisKv {
  return {
    get: (key) => client.get(key),
    del: (key) => client.del(key),
    mget: (keys) => client.mget(...keys),
    sadd: (key, ...members) => client.sadd(key, ...members),
    srem: (key, ...members) => client.srem(key, ...members),
    smembers: (key) => client.smembers(key),
    async set(key, value, options) {
      const ttlSeconds = options?.ttlSeconds;
      const ifNotExists = options?.ifNotExists ?? false;

      if (ttlSeconds && ifNotExists) return (await client.set(key, value, 'EX', ttlSeconds, 'NX')) === 'OK';
      if (ttlSeconds) return (await client.set(key, value, 'EX', ttlSeconds)) === 'OK';
      if (ifNotExists) return (await client.set(key, value, undefined, undefined, 'NX')) === 'OK';
      return (await client.set(key, value)) === 'OK';
    },
    async incr(key, options) {
      const result = await client.incr(key);
      // Set TTL only when the key is newly created (value becomes 1).
      if (options?.ttlSeconds && result === 1) {
        await client.expire(key, options.ttlSeconds);
      }
      return result;
    },
    async incrby(key, amount, options) {
      const result = await client.incrby(key, amount);
      if (options?.ttlSeconds && result === amount) {
        await client.expire(key, options.ttlSeconds);
      }
      return result;
    },
  };
}

export interface NodeRedisLikeClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string,
    options?: { EX?: number; PX?: number; NX?: boolean; XX?: boolean }
  ): Promise<'OK' | null>;
  del(key: string): Promise<number>;
  incr(key: string): Promise<number>;
  incrby(key: string, amount: number): Promise<number>;
  expire(key: string, seconds: number): Promise<boolean>;
  mget(keys: string[]): Promise<(string | null)[]>;
  sadd(key: string, members: string[]): Promise<number>;
  srem(key: string, members: string[]): Promise<number>;
  smembers(key: string): Promise<string[]>;
}

export function createNodeRedisKv(client: NodeRedisLikeClient): RedisKv {
  return {
    get: (key) => client.get(key),
    del: (key) => client.del(key),
    mget: (keys) => client.mget(keys),
    sadd: (key, ...members) => client.sadd(key, members),
    srem: (key, ...members) => client.srem(key, members),
    smembers: (key) => client.smembers(key),
    async set(key, value, options) {
      const redisOptions: { EX?: number; NX?: boolean } = {};
      if (options?.ttlSeconds) redisOptions.EX = options.ttlSeconds;
      if (options?.ifNotExists) redisOptions.NX = true;

      // If no options, node-redis accepts undefined.
      const result = await client.set(key, value, Object.keys(redisOptions).length ? redisOptions : undefined);
      return result === 'OK';
    },
    async incr(key, options) {
      const result = await client.incr(key);
      if (options?.ttlSeconds && result === 1) {
        await client.expire(key, options.ttlSeconds);
      }
      return result;
    },
    async incrby(key, amount, options) {
      const result = await client.incrby(key, amount);
      if (options?.ttlSeconds && result === amount) {
        await client.expire(key, options.ttlSeconds);
      }
      return result;
    },
  };
}

