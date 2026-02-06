import type { Logger } from 'pino';
import { buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, applyTtlJitter, type RedisKv } from '../../storage/redis/index.js';
import type { SensorMetricsSnapshot } from './types.js';

/**
 * Store interface for real-time sensor metrics snapshots.
 */
export interface SensorMetricsStore {
  get(sensorId: string): Promise<SensorMetricsSnapshot | undefined>;
  set(sensorId: string, snapshot: SensorMetricsSnapshot): Promise<void>;
  delete(sensorId: string): Promise<void>;
  getAll(): Promise<SensorMetricsSnapshot[]>;
  clear(): Promise<void>;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * In-memory implementation of SensorMetricsStore.
 */
export class InMemorySensorMetricsStore implements SensorMetricsStore {
  private metrics = new Map<string, SensorMetricsSnapshot>();

  async get(sensorId: string): Promise<SensorMetricsSnapshot | undefined> {
    return this.metrics.get(sensorId);
  }

  async set(sensorId: string, snapshot: SensorMetricsSnapshot): Promise<void> {
    this.metrics.set(sensorId, snapshot);
  }

  async delete(sensorId: string): Promise<void> {
    this.metrics.delete(sensorId);
  }

  async getAll(): Promise<SensorMetricsSnapshot[]> {
    return Array.from(this.metrics.values());
  }

  async clear(): Promise<void> {
    this.metrics.clear();
  }
}

/**
 * Redis-backed implementation of SensorMetricsStore for distributed dashboard metrics.
 */
export class RedisSensorMetricsStore implements SensorMetricsStore {
  private kv: RedisKv;
  private namespace: string;
  private version: number;
  private dataType: string;
  private indexKeyName: string;
  private metricsRetentionSeconds: number;
  private lockTtlSeconds: number;

  constructor(
    kv: RedisKv,
    options: {
      namespace?: string;
      version?: number;
      dataType?: string;
      metricsRetentionSeconds?: number;
      lockTtlSeconds?: number;
    } = {}
  ) {
    this.kv = kv;
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'sensor-metrics';
    this.indexKeyName = buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'sensor-metrics-index',
      id: 'all',
    });
    this.metricsRetentionSeconds = options.metricsRetentionSeconds ?? 300; // 5 minutes default
    this.lockTtlSeconds = options.lockTtlSeconds ?? TTL_SECONDS.lockMin;
  }

  private sensorKey(sensorId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: this.dataType,
      id: sensorId,
    });
  }

  private indexLockKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: 'global',
      dataType: 'lock',
      id: ['sensor-metrics-index', 'all'],
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

  async get(sensorId: string): Promise<SensorMetricsSnapshot | undefined> {
    const raw = await this.kv.get(this.sensorKey(sensorId));
    if (!raw) return undefined;
    const snapshot = jsonDecode<any>(raw, { maxBytes: 1024 * 1024 });
    return {
      ...snapshot,
      lastHeartbeat: new Date(snapshot.lastHeartbeat),
    };
  }

  async set(sensorId: string, snapshot: SensorMetricsSnapshot): Promise<void> {
    const key = this.sensorKey(sensorId);
    const ttlSeconds = applyTtlJitter(this.metricsRetentionSeconds);
    await this.kv.set(key, jsonEncode(snapshot), { ttlSeconds });

    // Update index
    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      const index = indexRaw ? jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 }) : [];
      if (!index.includes(sensorId)) {
        index.push(sensorId);
      }
      // Always refresh the index TTL, even if the key already exists
      await this.kv.set(this.indexKeyName, jsonEncode(index), { ttlSeconds });
    });
  }

  async delete(sensorId: string): Promise<void> {
    await this.kv.del(this.sensorKey(sensorId));

    await this.withIndexLock(async () => {
      const indexRaw = await this.kv.get(this.indexKeyName);
      if (indexRaw) {
        const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
        const nextIndex = index.filter((id) => id !== sensorId);
        await this.kv.set(this.indexKeyName, jsonEncode(nextIndex), { ttlSeconds: applyTtlJitter(this.metricsRetentionSeconds) });
      }
    });
  }

  async getAll(): Promise<SensorMetricsSnapshot[]> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (!indexRaw) return [];

    const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
    if (index.length === 0) return [];

    // Batch-fetch all sensor keys in a single round-trip
    const sensorKeys = index.map((id) => this.sensorKey(id));
    const values = await this.kv.mget(sensorKeys);
    const results: SensorMetricsSnapshot[] = [];
    const stillPresent: string[] = [];

    for (let i = 0; i < index.length; i++) {
      const raw = values[i];
      if (raw) {
        const snapshot = jsonDecode<any>(raw, { maxBytes: 1024 * 1024 });
        results.push({
          ...snapshot,
          lastHeartbeat: new Date(snapshot.lastHeartbeat),
        });
        stillPresent.push(index[i]);
      }
    }

    if (stillPresent.length !== index.length) {
      await this.kv.set(this.indexKeyName, jsonEncode(stillPresent), { ttlSeconds: applyTtlJitter(this.metricsRetentionSeconds) });
    }

    return results;
  }

  async clear(): Promise<void> {
    const indexRaw = await this.kv.get(this.indexKeyName);
    if (indexRaw) {
      const index = jsonDecode<string[]>(indexRaw, { maxBytes: 1024 * 1024 });
      for (const sensorId of index) {
        await this.kv.del(this.sensorKey(sensorId));
      }
      await this.kv.del(this.indexKeyName);
    }
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory metrics tracking to keep sensor metrics functional.
 */
export class ResilientSensorMetricsStore implements SensorMetricsStore {
  private logger: Logger;
  private primary: SensorMetricsStore;
  private fallback: SensorMetricsStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: SensorMetricsStore, fallback: SensorMetricsStore) {
    this.logger = logger.child({ component: 'resilient-sensor-metrics-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'SensorMetricsStore primary failed; using fallback');
  }

  async get(sensorId: string): Promise<SensorMetricsSnapshot | undefined> {
    try {
      return await this.primary.get(sensorId);
    } catch (error) {
      this.warn('get', error);
      return this.fallback.get(sensorId);
    }
  }

  async set(sensorId: string, snapshot: SensorMetricsSnapshot): Promise<void> {
    await this.fallback.set(sensorId, snapshot);
    try {
      await this.primary.set(sensorId, snapshot);
    } catch (error) {
      this.warn('set', error);
    }
  }

  async delete(sensorId: string): Promise<void> {
    await this.fallback.delete(sensorId);
    try {
      await this.primary.delete(sensorId);
    } catch (error) {
      this.warn('delete', error);
    }
  }

  async getAll(): Promise<SensorMetricsSnapshot[]> {
    try {
      return await this.primary.getAll();
    } catch (error) {
      this.warn('getAll', error);
      return this.fallback.getAll();
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
