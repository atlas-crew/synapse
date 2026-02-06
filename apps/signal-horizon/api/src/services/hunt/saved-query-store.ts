import type { Logger } from 'pino';
import { buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, applyTtlJitter, type RedisKv } from '../../storage/redis/index.js';
import type { SavedQuery } from './index.js';

/**
 * Store interface for saved hunt queries.
 * Allows swapping between in-memory and Redis-backed implementations.
 */
export interface SavedQueryStore {
  get(id: string): Promise<SavedQuery | null>;
  set(query: SavedQuery): Promise<void>;
  delete(id: string): Promise<boolean>;
  list(createdBy?: string): Promise<SavedQuery[]>;
}

/**
 * In-memory implementation of SavedQueryStore (default).
 */
export class InMemorySavedQueryStore implements SavedQueryStore {
  private queries = new Map<string, SavedQuery>();

  async get(id: string): Promise<SavedQuery | null> {
    return this.queries.get(id) ?? null;
  }

  async set(query: SavedQuery): Promise<void> {
    this.queries.set(query.id, query);
  }

  async delete(id: string): Promise<boolean> {
    return this.queries.delete(id);
  }

  async list(createdBy?: string): Promise<SavedQuery[]> {
    const all = Array.from(this.queries.values());
    return createdBy ? all.filter((q) => q.createdBy === createdBy) : all;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** 30 days in seconds -- saved queries are user-created persistent data. */
const SAVED_QUERY_TTL_SECONDS = 30 * 24 * 60 * 60; // 2_592_000

/**
 * Reconstitute Date fields that become ISO strings after JSON round-tripping.
 */
function reconstituteDates(raw: any): SavedQuery {
  return {
    ...raw,
    createdAt: new Date(raw.createdAt),
    lastRunAt: raw.lastRunAt ? new Date(raw.lastRunAt) : undefined,
    query: {
      ...raw.query,
      startTime: new Date(raw.query.startTime),
      endTime: new Date(raw.query.endTime),
    },
  };
}

/**
 * Redis-backed implementation of SavedQueryStore for distributed deployments.
 */
export class RedisSavedQueryStore implements SavedQueryStore {
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
    this.dataType = options.dataType ?? 'saved-hunt-query';
    this.indexKeyName = buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'saved-hunt-query-index',
      id: 'all',
    });
    this.lockTtlSeconds = options.lockTtlSeconds ?? TTL_SECONDS.lockMin;
  }

  private entryKey(id: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: this.dataType,
      id,
    });
  }

  private indexLockKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'lock',
      id: ['saved-hunt-query-index', 'all'],
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

  async get(id: string): Promise<SavedQuery | null> {
    const raw = await this.kv.get(this.entryKey(id));
    if (!raw) return null;
    return reconstituteDates(jsonDecode<any>(raw, { maxBytes: 1024 * 1024 }));
  }

  async set(query: SavedQuery): Promise<void> {
    const key = this.entryKey(query.id);
    await this.kv.set(key, jsonEncode(query), { ttlSeconds: applyTtlJitter(SAVED_QUERY_TTL_SECONDS) });

    // Update index
    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      const index = indexRaw ? jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 }) : [];
      if (!index.includes(query.id)) {
        index.push(query.id);
      }
      // Always refresh the index TTL, even if the key already exists
      await this.kv.set(this.indexKeyName, jsonEncode(index), { ttlSeconds: applyTtlJitter(SAVED_QUERY_TTL_SECONDS) });
    });
  }

  async delete(id: string): Promise<boolean> {
    const key = this.entryKey(id);
    const deleted = (await this.kv.del(key)) > 0;

    if (deleted) {
      await this.withIndexLock(async () => {
        const indexRaw = await this.kv.get(this.indexKeyName);
        if (indexRaw) {
          const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
          const nextIndex = index.filter((qid) => qid !== id);
          await this.kv.set(this.indexKeyName, jsonEncode(nextIndex), { ttlSeconds: applyTtlJitter(SAVED_QUERY_TTL_SECONDS) });
        }
      });
    }

    return deleted;
  }

  async list(createdBy?: string): Promise<SavedQuery[]> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return [];

    const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
    if (index.length === 0) return [];

    // Batch-fetch all entry keys in a single round-trip
    const entryKeys = index.map((id) => this.entryKey(id));
    const values = await this.kv.mget(entryKeys);
    const results: SavedQuery[] = [];
    const stillPresent: string[] = [];

    for (let i = 0; i < index.length; i++) {
      const raw = values[i];
      if (raw) {
        const query = reconstituteDates(jsonDecode<any>(raw, { maxBytes: 1024 * 1024 }));
        if (!createdBy || query.createdBy === createdBy) {
          results.push(query);
        }
        stillPresent.push(index[i]);
      }
    }

    if (stillPresent.length !== index.length) {
      await this.kv.set(this.indexKeyName, jsonEncode(stillPresent), { ttlSeconds: applyTtlJitter(SAVED_QUERY_TTL_SECONDS) });
    }

    return results;
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory saved query tracking to keep hunt query persistence functional.
 */
export class ResilientSavedQueryStore implements SavedQueryStore {
  private logger: Logger;
  private primary: SavedQueryStore;
  private fallback: SavedQueryStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: SavedQueryStore, fallback: SavedQueryStore) {
    this.logger = logger.child({ component: 'resilient-saved-query-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'SavedQueryStore primary failed; using fallback');
  }

  async get(id: string): Promise<SavedQuery | null> {
    try {
      return await this.primary.get(id);
    } catch (error) {
      this.warn('get', error);
      return this.fallback.get(id);
    }
  }

  async set(query: SavedQuery): Promise<void> {
    await this.fallback.set(query);
    try {
      await this.primary.set(query);
    } catch (error) {
      this.warn('set', error);
    }
  }

  async delete(id: string): Promise<boolean> {
    const fallbackResult = await this.fallback.delete(id);
    try {
      return await this.primary.delete(id);
    } catch (error) {
      this.warn('delete', error);
      return fallbackResult;
    }
  }

  async list(createdBy?: string): Promise<SavedQuery[]> {
    try {
      return await this.primary.list(createdBy);
    } catch (error) {
      this.warn('list', error);
      return this.fallback.list(createdBy);
    }
  }
}
