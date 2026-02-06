import { buildRedisKey, jsonDecode, jsonEncode, type RedisKv } from '../../storage/redis/index.js';
import type { Logger } from 'pino';

/**
 * Record for tracking trigger counts within a window.
 */
export interface TriggerCountRecord {
  count: number;
  windowStart: number;
}

/**
 * Store interface for per-tenant auto-trigger rate limiting.
 */
export interface TriggerRateLimitStore {
  get(tenantId: string): Promise<TriggerCountRecord | undefined>;
  set(tenantId: string, record: TriggerCountRecord): Promise<void>;
  delete(tenantId: string): Promise<void>;
  entries(): Promise<[string, TriggerCountRecord][]>;
  clear(): Promise<void>;
}

/**
 * In-memory implementation of TriggerRateLimitStore (default).
 */
export class InMemoryTriggerRateLimitStore implements TriggerRateLimitStore {
  private counts = new Map<string, TriggerCountRecord>();

  async get(tenantId: string): Promise<TriggerCountRecord | undefined> {
    return this.counts.get(tenantId);
  }

  async set(tenantId: string, record: TriggerCountRecord): Promise<void> {
    this.counts.set(tenantId, record);
  }

  async delete(tenantId: string): Promise<void> {
    this.counts.delete(tenantId);
  }

  async entries(): Promise<[string, TriggerCountRecord][]> {
    return Array.from(this.counts.entries());
  }

  async clear(): Promise<void> {
    this.counts.clear();
  }
}

/**
 * Redis-backed implementation of TriggerRateLimitStore for distributed deployments.
 */
export class RedisTriggerRateLimitStore implements TriggerRateLimitStore {
  private kv: RedisKv;
  private namespace: string;
  private version: number;
  private dataType: string;
  private indexKeyName: string;

  constructor(
    kv: RedisKv,
    options: {
      namespace?: string;
      version?: number;
      dataType?: string;
    } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'warroom-trigger-rate';
    this.indexKeyName = buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'warroom-trigger-rate-index',
      id: 'all',
    });
  }

  private tenantKey(tenantId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.dataType,
      id: 'count',
    });
  }

  async get(tenantId: string): Promise<TriggerCountRecord | undefined> {
    const raw = await this.kv.get(this.tenantKey(tenantId));
    if (!raw) return undefined;
    return jsonDecode<TriggerCountRecord>(raw);
  }

  async set(tenantId: string, record: TriggerCountRecord): Promise<void> {
    const key = this.tenantKey(tenantId);
    // Rate limit windows are 1 minute, so 5 minutes TTL is plenty of buffer
    const ttlSeconds = 300; 

    await this.kv.set(key, jsonEncode(record), { ttlSeconds });

    // Update index for entries() support
    const indexRaw = await this.kv.get(this.indexKeyName);
    const index = indexRaw ? jsonDecode<string[]>(indexRaw) : [];
    if (!index.includes(tenantId)) {
      index.push(tenantId);
      await this.kv.set(this.indexKeyName, jsonEncode(index), { ttlSeconds });
    }
  }

  async delete(tenantId: string): Promise<void> {
    await this.kv.del(this.tenantKey(tenantId));

    const indexRaw = await this.kv.get(this.indexKeyName);
    if (indexRaw) {
      const index = jsonDecode<string[]>(indexRaw);
      const nextIndex = index.filter((id) => id !== tenantId);
      if (nextIndex.length !== index.length) {
        await this.kv.set(this.indexKeyName, jsonEncode(nextIndex), { ttlSeconds: 300 });
      }
    }
  }

  async entries(): Promise<[string, TriggerCountRecord][]> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return [];

    const index = jsonDecode<string[]>(indexRaw);
    const results: Array<[string, TriggerCountRecord]> = [];
    const stillPresent: string[] = [];

    for (const tenantId of index) {
      const record = await this.get(tenantId);
      if (record) {
        results.push([tenantId, record]);
        stillPresent.push(tenantId);
      }
    }

    if (stillPresent.length !== index.length) {
      await this.kv.set(this.indexKeyName, jsonEncode(stillPresent), { ttlSeconds: 300 });
    }

    return results;
  }

  async clear(): Promise<void> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (indexRaw) {
      const index = jsonDecode<string[]>(indexRaw);
      for (const tenantId of index) {
        await this.kv.del(this.tenantKey(tenantId));
      }
      await this.kv.del(this.indexKeyName);
    }
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory tracking to keep rate limiting functional in degraded mode.
 */
export class ResilientTriggerRateLimitStore implements TriggerRateLimitStore {
  private logger: Logger;
  private primary: TriggerRateLimitStore;
  private fallback: TriggerRateLimitStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: TriggerRateLimitStore, fallback: TriggerRateLimitStore) {
    this.logger = logger.child({ component: 'resilient-trigger-rate-limit-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'TriggerRateLimitStore primary failed; using fallback');
  }

  async get(tenantId: string): Promise<TriggerCountRecord | undefined> {
    try {
      return await this.primary.get(tenantId);
    } catch (error) {
      this.warn('get', error);
      return this.fallback.get(tenantId);
    }
  }

  async set(tenantId: string, record: TriggerCountRecord): Promise<void> {
    await this.fallback.set(tenantId, record);
    try {
      await this.primary.set(tenantId, record);
    } catch (error) {
      this.warn('set', error);
    }
  }

  async delete(tenantId: string): Promise<void> {
    await this.fallback.delete(tenantId);
    try {
      await this.primary.delete(tenantId);
    } catch (error) {
      this.warn('delete', error);
    }
  }

  async entries(): Promise<[string, TriggerCountRecord][]> {
    try {
      return await this.primary.entries();
    } catch (error) {
      this.warn('entries', error);
      return this.fallback.entries();
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
