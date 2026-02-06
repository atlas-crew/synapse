import { randomUUID } from 'node:crypto';
import { buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, applyTtlJitter, type RedisKv } from '../../storage/redis/index.js';
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
  /**
   * Atomically increment the rate counter for a tenant and return the new count.
   * If the window has expired or does not exist, a new window is started.
   * Returns the count *after* incrementing.
   */
  incrementAndGet(tenantId: string, windowMs: number): Promise<number>;
  /** When true, the store handles its own expiry (e.g., Redis TTLs) and periodic cleanup can be skipped. */
  readonly skipCleanup?: boolean;
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

  async incrementAndGet(tenantId: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const existing = this.counts.get(tenantId);

    if (!existing || now - existing.windowStart > windowMs) {
      this.counts.set(tenantId, { count: 1, windowStart: now });
      return 1;
    }

    existing.count++;
    return existing.count;
  }
}

/**
 * Redis-backed implementation of TriggerRateLimitStore for distributed deployments.
 */
export class RedisTriggerRateLimitStore implements TriggerRateLimitStore {
  readonly skipCleanup = true;

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
    } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'warroom-trigger-rate';
    this.lockTtlSeconds = TTL_SECONDS.lockMin;
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

  private indexLockKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'lock',
      id: ['warroom-trigger-rate-index', 'all'],
    });
  }

  private async withIndexLock<T>(fn: () => Promise<T>): Promise<T> {
    const lockKey = this.indexLockKey();
    const lockValue = randomUUID();
    let lockAcquired = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      lockAcquired = await this.kv.set(lockKey, lockValue, { ttlSeconds: this.lockTtlSeconds, ifNotExists: true });
      if (lockAcquired) break;
      await new Promise((resolve) => setTimeout(resolve, 25 * (attempt + 1)));
    }

    try {
      return await fn();
    } finally {
      if (lockAcquired) {
        const current = await this.kv.get(lockKey);
        if (current === lockValue) await this.kv.del(lockKey);
      }
    }
  }

  async get(tenantId: string): Promise<TriggerCountRecord | undefined> {
    const raw = await this.kv.get(this.tenantKey(tenantId));
    if (!raw) return undefined;
    return jsonDecode<TriggerCountRecord>(raw, { maxBytes: 1024 * 1024 });
  }

  async set(tenantId: string, record: TriggerCountRecord): Promise<void> {
    const key = this.tenantKey(tenantId);
    // Rate limit windows are 1 minute, so 5 minutes TTL is plenty of buffer
    const ttlSeconds = applyTtlJitter(300);

    await this.kv.set(key, jsonEncode(record), { ttlSeconds });

    // Update index for entries() support
    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      const index = indexRaw ? jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 }) : [];
      if (!index.includes(tenantId)) {
        index.push(tenantId);
      }
      // Always refresh the index TTL, even if the key already exists
      await this.kv.set(this.indexKeyName, jsonEncode(index), { ttlSeconds });
    });
  }

  async delete(tenantId: string): Promise<void> {
    await this.kv.del(this.tenantKey(tenantId));

    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      if (indexRaw) {
        const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
        const nextIndex = index.filter((id) => id !== tenantId);
        if (nextIndex.length !== index.length) {
          await this.kv.set(this.indexKeyName, jsonEncode(nextIndex), { ttlSeconds: applyTtlJitter(300) });
        }
      }
    });
  }

  async entries(): Promise<[string, TriggerCountRecord][]> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return [];

    const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
    if (index.length === 0) return [];

    const keys = index.map((tenantId) => this.tenantKey(tenantId));
    const rawValues = await this.kv.mget(keys);

    const results: Array<[string, TriggerCountRecord]> = [];
    const stillPresent: string[] = [];

    for (let i = 0; i < index.length; i++) {
      const raw = rawValues[i];
      if (!raw) continue;
      results.push([index[i], jsonDecode<TriggerCountRecord>(raw, { maxBytes: 1024 * 1024 })]);
      stillPresent.push(index[i]);
    }

    if (stillPresent.length !== index.length) {
      await this.kv.set(this.indexKeyName, jsonEncode(stillPresent), { ttlSeconds: applyTtlJitter(300) });
    }

    return results;
  }

  async clear(): Promise<void> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (indexRaw) {
      const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
      for (const tenantId of index) {
        await this.kv.del(this.tenantKey(tenantId));
      }
      await this.kv.del(this.indexKeyName);
    }
  }

  private atomicCounterKey(tenantId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.dataType,
      id: 'atomic-counter',
    });
  }

  async incrementAndGet(tenantId: string, windowMs: number): Promise<number> {
    const ttlSeconds = Math.max(1, Math.ceil(windowMs / 1000));
    // Redis INCR is atomic and single-threaded. The TTL is set only when the
    // key is first created (result === 1), so the window naturally expires.
    return this.kv.incr(this.atomicCounterKey(tenantId), { ttlSeconds });
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

  get skipCleanup(): boolean {
    return this.primary.skipCleanup === true;
  }

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

  async incrementAndGet(tenantId: string, windowMs: number): Promise<number> {
    const fallbackCount = await this.fallback.incrementAndGet(tenantId, windowMs);
    try {
      return await this.primary.incrementAndGet(tenantId, windowMs);
    } catch (error) {
      this.warn('incrementAndGet', error);
      return fallbackCount;
    }
  }
}
