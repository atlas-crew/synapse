import type { Logger } from 'pino';
import { buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, applyTtlJitter, type RedisKv } from '../../storage/redis/index.js';
import type { BlocklistUpdate } from '../../types/protocol.js';

/**
 * Store interface for blocklist cache.
 * Allows swapping between in-memory and Redis-backed implementations.
 */
export interface BlocklistStore {
  get(blockType: string, indicator: string): Promise<BlocklistUpdate | undefined>;
  set(block: BlocklistUpdate): Promise<void>;
  delete(blockType: string, indicator: string): Promise<void>;
  getAll(): Promise<BlocklistUpdate[]>;
  size(): Promise<number>;
  clear(): Promise<void>;
}

/**
 * In-memory implementation of BlocklistStore (default).
 */
export class InMemoryBlocklistStore implements BlocklistStore {
  private cache: Map<string, BlocklistUpdate> = new Map();

  async get(blockType: string, indicator: string): Promise<BlocklistUpdate | undefined> {
    return this.cache.get(`${blockType}:${indicator}`);
  }

  async set(block: BlocklistUpdate): Promise<void> {
    this.cache.set(`${block.blockType}:${block.indicator}`, block);
  }

  async delete(blockType: string, indicator: string): Promise<void> {
    this.cache.delete(`${blockType}:${indicator}`);
  }

  async getAll(): Promise<BlocklistUpdate[]> {
    return Array.from(this.cache.values());
  }

  async size(): Promise<number> {
    return this.cache.size;
  }

  async clear(): Promise<void> {
    this.cache.clear();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Redis-backed implementation of BlocklistStore for distributed deployments.
 */
export class RedisBlocklistStore implements BlocklistStore {
  private kv: RedisKv;
  private namespace: string;
  private version: number;
  private dataType: string;
  private indexKeyName: string;
  private lockTtlSeconds: number;

  constructor(
    kv: RedisKv,
    options: {
      namespace?: string;
      version?: number;
      dataType?: string;
      lockTtlSeconds?: number;
    } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'blocklist-cache';
    this.indexKeyName = buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'blocklist-index',
      id: 'all',
    });
    this.lockTtlSeconds = options.lockTtlSeconds ?? TTL_SECONDS.lockMin;
  }

  private entryKey(blockType: string, indicator: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: this.dataType,
      id: [blockType, indicator],
    });
  }

  async get(blockType: string, indicator: string): Promise<BlocklistUpdate | undefined> {
    const raw = await this.kv.get(this.entryKey(blockType, indicator));
    if (!raw) return undefined;
    return jsonDecode<BlocklistUpdate>(raw, { maxBytes: 1024 * 1024 });
  }

  private indexLockKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'lock',
      id: ['blocklist-index', 'all'],
    });
  }

  private async withIndexLock<T>(fn: () => Promise<T>): Promise<T> {
    const lockKey = this.indexLockKey();
    let lockAcquired = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      lockAcquired = await this.kv.set(lockKey, '1', { ttlSeconds: this.lockTtlSeconds, ifNotExists: true });
      if (lockAcquired) break;
      await sleep(25 * (attempt + 1));
    }

    try {
      return await fn();
    } finally {
      if (lockAcquired) await this.kv.del(lockKey);
    }
  }

  async set(block: BlocklistUpdate): Promise<void> {
    const key = this.entryKey(block.blockType, block.indicator);
    const ttlSeconds = applyTtlJitter(TTL_SECONDS.cacheMax); // Blocklist entries are relatively long-lived

    await this.kv.set(key, jsonEncode(block), { ttlSeconds });

    // Add to index for getAll() support
    // Note: In a production environment with millions of blocks, we wouldn't use this index pattern.
    // But for the current fleet-wide intelligence scale, it works.
    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      const index = indexRaw ? jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 }) : [];
      if (!index.includes(key)) {
        index.push(key);
      }
      // Always refresh the index TTL, even if the key already exists
      await this.kv.set(this.indexKeyName, jsonEncode(index), { ttlSeconds: applyTtlJitter(TTL_SECONDS.cacheMax) });
    });
  }

  async delete(blockType: string, indicator: string): Promise<void> {
    const key = this.entryKey(blockType, indicator);
    await this.kv.del(key);

    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      if (indexRaw) {
        const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
        const nextIndex = index.filter((k) => k !== key);
        await this.kv.set(this.indexKeyName, jsonEncode(nextIndex), { ttlSeconds: applyTtlJitter(TTL_SECONDS.cacheMax) });
      }
    });
  }

  async getAll(): Promise<BlocklistUpdate[]> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return [];

    const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
    if (index.length === 0) return [];

    const values = await this.kv.mget(index);
    const results: BlocklistUpdate[] = [];
    const stillPresent: string[] = [];

    for (let i = 0; i < index.length; i++) {
      const raw = values[i];
      if (raw) {
        results.push(jsonDecode<BlocklistUpdate>(raw, { maxBytes: 1024 * 1024 }));
        stillPresent.push(index[i]);
      }
    }

    // Best-effort index cleanup
    if (stillPresent.length !== index.length) {
      await this.kv.set(this.indexKeyName, jsonEncode(stillPresent), { ttlSeconds: applyTtlJitter(TTL_SECONDS.cacheMax) });
    }

    return results;
  }

  async size(): Promise<number> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return 0;
    return jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 }).length;
  }

  async clear(): Promise<void> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (indexRaw) {
      const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
      for (const key of index) {
        await this.kv.del(key);
      }
      await this.kv.del(this.indexKeyName);
    }
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory blocklist tracking to keep blocklist operations functional.
 */
export class ResilientBlocklistStore implements BlocklistStore {
  private logger: Logger;
  private primary: BlocklistStore;
  private fallback: BlocklistStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: BlocklistStore, fallback: BlocklistStore) {
    this.logger = logger.child({ component: 'resilient-blocklist-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'BlocklistStore primary failed; using fallback');
  }

  async get(blockType: string, indicator: string): Promise<BlocklistUpdate | undefined> {
    try {
      return await this.primary.get(blockType, indicator);
    } catch (error) {
      this.warn('get', error);
      return this.fallback.get(blockType, indicator);
    }
  }

  async set(block: BlocklistUpdate): Promise<void> {
    await this.fallback.set(block);
    try {
      await this.primary.set(block);
    } catch (error) {
      this.warn('set', error);
    }
  }

  async delete(blockType: string, indicator: string): Promise<void> {
    await this.fallback.delete(blockType, indicator);
    try {
      await this.primary.delete(blockType, indicator);
    } catch (error) {
      this.warn('delete', error);
    }
  }

  async getAll(): Promise<BlocklistUpdate[]> {
    try {
      return await this.primary.getAll();
    } catch (error) {
      this.warn('getAll', error);
      return this.fallback.getAll();
    }
  }

  async size(): Promise<number> {
    try {
      return await this.primary.size();
    } catch (error) {
      this.warn('size', error);
      return this.fallback.size();
    }
  }

  async clear(): Promise<void> {
    await this.fallback.clear();
    try {
      await this.primary.clear();
    } catch (error) {
      this.warn('clear', error);
    }
  }
}
