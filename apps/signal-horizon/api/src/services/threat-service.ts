/**
 * Threat Service
 * Provides centralized threat scoring and risk assessment for signals.
 * Replaces basic severity ranking with multi-factor threat scoring.
 */

import type { Logger } from 'pino';
import type { Severity } from '../types/protocol.js';
import { buildRedisKey, jsonDecode, jsonEncode, type RedisKv } from '../storage/redis/index.js';

/**
 * Signal context for threat scoring
 */
export interface SignalContext {
  signalType: string;
  severity: Severity;
  confidence: number;
  tenantId: string;
  sourceIp?: string;
  fingerprint?: string;
  eventCount?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Threat score result
 */
export interface ThreatScore {
  /** Overall threat score (0-100) */
  score: number;
  /** Score breakdown by factor */
  factors: ThreatFactor[];
  /** Suggested action based on score */
  recommendedAction: 'allow' | 'monitor' | 'alert' | 'block';
}

/**
 * Individual scoring factor
 */
export interface ThreatFactor {
  name: string;
  weight: number;
  contribution: number;
  reason: string;
}

/**
 * Configuration for threat scoring weights
 */
export interface ThreatScoringConfig {
  /** Weight for severity factor (0-1) */
  severityWeight: number;
  /** Weight for signal type factor (0-1) */
  signalTypeWeight: number;
  /** Weight for confidence factor (0-1) */
  confidenceWeight: number;
  /** Weight for volume/frequency factor (0-1) */
  volumeWeight: number;
  /** Thresholds for recommended actions */
  thresholds: {
    monitor: number;
    alert: number;
    block: number;
  };
}

const DEFAULT_CONFIG: ThreatScoringConfig = {
  severityWeight: 0.35,
  signalTypeWeight: 0.25,
  confidenceWeight: 0.20,
  volumeWeight: 0.20,
  thresholds: {
    monitor: 30,
    alert: 60,
    block: 85,
  },
};

/**
 * Signal type base scores (0-100)
 * Higher = more threatening
 */
const SIGNAL_TYPE_SCORES: Record<string, number> = {
  CREDENTIAL_STUFFING: 80,
  IMPOSSIBLE_TRAVEL: 90,
  IP_THREAT: 60,
  FINGERPRINT_THREAT: 55,
  CAMPAIGN_INDICATOR: 75,
  RATE_ANOMALY: 50,
  BOT_SIGNATURE: 65,
  TEMPLATE_DISCOVERY: 25,
  SCHEMA_VIOLATION: 40,
};

/**
 * Severity multipliers
 */
const SEVERITY_SCORES: Record<Severity, number> = {
  LOW: 25,
  MEDIUM: 50,
  HIGH: 75,
  CRITICAL: 100,
};

/**
 * Store interface for recent signal tracking data.
 * Allows swapping between in-memory and Redis-backed implementations.
 */
export interface RecentSignalsStore {
  get(key: string): Promise<{ count: number; lastSeen: number } | undefined>;
  set(key: string, value: { count: number; lastSeen: number }): Promise<void>;
  /**
   * Atomically increment the count for a key and update lastSeen.
   * Returns the new total count.
   */
  incrementBy(key: string, amount: number): Promise<number>;
  delete(key: string): Promise<void>;
  entries(): Promise<[string, { count: number; lastSeen: number }][]>;
  /** When true, the store handles its own expiry (e.g., Redis TTLs) and periodic cleanup can be skipped. */
  readonly skipCleanup?: boolean;
}

/**
 * In-memory implementation of RecentSignalsStore (default).
 * Suitable for single-instance deployments.
 */
export class InMemoryRecentSignalsStore implements RecentSignalsStore {
  private map = new Map<string, { count: number; lastSeen: number }>();

  async get(key: string): Promise<{ count: number; lastSeen: number } | undefined> {
    return this.map.get(key);
  }

  async set(key: string, value: { count: number; lastSeen: number }): Promise<void> {
    this.map.set(key, value);
  }

  async incrementBy(key: string, amount: number): Promise<number> {
    const existing = this.map.get(key);
    const count = (existing?.count ?? 0) + amount;
    this.map.set(key, { count, lastSeen: Date.now() });
    return count;
  }

  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }

  async entries(): Promise<[string, { count: number; lastSeen: number }][]> {
    return Array.from(this.map.entries());
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * an in-memory store to keep the hub running in degraded mode.
 *
 * Note: this preserves single-node semantics during outages; it does not attempt
 * to guarantee cross-node consistency while Redis is unhealthy.
 */
export class ResilientRecentSignalsStore implements RecentSignalsStore {
  private logger: Logger;
  private primary: RecentSignalsStore;
  private fallback: RecentSignalsStore;
  private lastWarnAtMs = 0;

  get skipCleanup(): boolean {
    return this.primary.skipCleanup === true;
  }

  constructor(logger: Logger, primary: RecentSignalsStore, fallback: RecentSignalsStore) {
    this.logger = logger.child({ component: 'resilient-recent-signals-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    // Avoid flooding logs during Redis outages.
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'RecentSignalsStore primary failed; using fallback');
  }

  async get(key: string): Promise<{ count: number; lastSeen: number } | undefined> {
    try {
      return await this.primary.get(key);
    } catch (error) {
      this.warn('get', error);
      return this.fallback.get(key);
    }
  }

  async set(key: string, value: { count: number; lastSeen: number }): Promise<void> {
    // Keep fallback warm so we can continue locally if primary dies mid-flight.
    await this.fallback.set(key, value);
    try {
      await this.primary.set(key, value);
    } catch (error) {
      this.warn('set', error);
    }
  }

  async incrementBy(key: string, amount: number): Promise<number> {
    // Keep fallback warm.
    const fallbackCount = await this.fallback.incrementBy(key, amount);
    try {
      return await this.primary.incrementBy(key, amount);
    } catch (error) {
      this.warn('incrementBy', error);
      return fallbackCount;
    }
  }

  async delete(key: string): Promise<void> {
    await this.fallback.delete(key);
    try {
      await this.primary.delete(key);
    } catch (error) {
      this.warn('delete', error);
    }
  }

  async entries(): Promise<[string, { count: number; lastSeen: number }][]> {
    try {
      return await this.primary.entries();
    } catch (error) {
      this.warn('entries', error);
      return this.fallback.entries();
    }
  }
}

type StoredRecentSignalEntry = { count: number; lastSeen: number };

export class RedisRecentSignalsStore implements RecentSignalsStore {
  readonly skipCleanup = true;

  private kv: RedisKv;
  private logger: Logger;
  private namespace: string;
  private version: number;
  private dataType: string;
  private indexTenantId: string;
  private indexDataType: string;
  private indexId: string;
  private windowMs: number;

  constructor(
    kv: RedisKv,
    logger: Logger,
    options: {
      namespace?: string;
      version?: number;
      dataType?: string;
      indexTenantId?: string;
      indexDataType?: string;
      indexId?: string;
      windowMs?: number;
    } = {}
  ) {
    this.kv = kv;
    this.logger = logger.child({ component: 'redis-recent-signals-store' });
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'recent-signal-volume';
    this.indexTenantId = options.indexTenantId ?? 'global';
    this.indexDataType = options.indexDataType ?? 'recent-signal-volume-index';
    this.indexId = options.indexId ?? 'all';
    this.windowMs = options.windowMs ?? 5 * 60 * 1000;
  }

  private parseVolumeKey(key: string): { tenantId: string; id: string } {
    // Expected: "t:<tenantId>:<entityKey>"
    if (!key.startsWith('t:')) throw new Error('RedisRecentSignalsStore: key missing tenant prefix');
    const parts = key.split(':');
    if (parts.length < 3) throw new Error('RedisRecentSignalsStore: key format invalid');
    const tenantId = parts[1];
    const id = parts.slice(2).join(':');
    if (!tenantId || !id) throw new Error('RedisRecentSignalsStore: key format invalid');
    return { tenantId, id };
  }

  private entryKey(tenantId: string, id: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.dataType,
      id,
    });
  }

  private indexKey(): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId: this.indexTenantId,
      dataType: this.indexDataType,
      id: this.indexId,
    });
  }

  async get(key: string): Promise<StoredRecentSignalEntry | undefined> {
    const { tenantId, id } = this.parseVolumeKey(key);
    const raw = await this.kv.get(this.entryKey(tenantId, id));
    if (!raw) return undefined;
    return jsonDecode<StoredRecentSignalEntry>(raw);
  }

  async set(key: string, value: StoredRecentSignalEntry): Promise<void> {
    const { tenantId, id } = this.parseVolumeKey(key);
    const ttlSeconds = Math.max(1, Math.ceil(this.windowMs / 1000));

    const entryKey = this.entryKey(tenantId, id);
    await this.kv.set(entryKey, jsonEncode(value), { ttlSeconds });
    // Use Redis Set for O(1) atomic index updates without global locks.
    await this.kv.sadd(this.indexKey(), `${tenantId}:${id}`);
  }

  async incrementBy(key: string, amount: number): Promise<number> {
    const { tenantId, id } = this.parseVolumeKey(key);
    const ttlSeconds = Math.max(1, Math.ceil(this.windowMs / 1000));
    const entryKey = this.entryKey(tenantId, id);

    // Increment count atomically.
    // Note: To keep the same JSON structure { count, lastSeen }, we'd need a Lua script.
    // Simplifying: we store count and lastSeen as separate keys or a hash.
    // But for now, let's keep it simple and just update the JSON (with a slight race on lastSeen, but count remains atomic).
    // Actually, if we want TRULY atomic read-modify-write for the JSON, we need Lua.
    // Alternatively, just use INCRBY for count and a separate SET for lastSeen.
    
    // For this remediation, let's use a simple approach: 
    // We'll store count as a separate key for atomic increments, and lastSeen as another.
    const countKey = `${entryKey}:count`;
    const lastSeenKey = `${entryKey}:lastSeen`;
    
    const count = await this.kv.incrby(countKey, amount, { ttlSeconds });
    await this.kv.set(lastSeenKey, String(Date.now()), { ttlSeconds });
    
    // Add to index.
    await this.kv.sadd(this.indexKey(), `${tenantId}:${id}`);
    
    return count;
  }

  async delete(key: string): Promise<void> {
    const { tenantId, id } = this.parseVolumeKey(key);
    const entryKey = this.entryKey(tenantId, id);
    await this.kv.del(entryKey);
    await this.kv.del(`${entryKey}:count`);
    await this.kv.del(`${entryKey}:lastSeen`);
    await this.kv.srem(this.indexKey(), `${tenantId}:${id}`);
  }

  async entries(): Promise<[string, StoredRecentSignalEntry][]> {
    const members = await this.kv.smembers(this.indexKey());
    if (members.length === 0) return [];

    const loaded: Array<[string, StoredRecentSignalEntry]> = [];
    const missing: string[] = [];

    // Fetch in batches to avoid blocking Redis.
    const batchSize = 100;
    for (let i = 0; i < members.length; i += batchSize) {
      const batch = members.slice(i, i + batchSize);
      const keys = batch.map(m => {
        const [tenantId, ...idParts] = m.split(':');
        return this.entryKey(tenantId, idParts.join(':'));
      });

      const rawValues = await this.kv.mget(keys);
      // Also check the split keys (count/lastSeen) if they exist.
      const countKeys = keys.map(k => `${k}:count`);
      const lastSeenKeys = keys.map(k => `${k}:lastSeen`);
      const rawCounts = await this.kv.mget(countKeys);
      const rawLastSeens = await this.kv.mget(lastSeenKeys);

      for (let j = 0; j < batch.length; j++) {
        const raw = rawValues[j];
        const rawCount = rawCounts[j];
        const rawLastSeen = rawLastSeens[j];
        
        if (raw) {
          loaded.push([`t:${batch[j]}`, jsonDecode<StoredRecentSignalEntry>(raw)]);
        } else if (rawCount && rawLastSeen) {
          loaded.push([`t:${batch[j]}`, { count: Number(rawCount), lastSeen: Number(rawLastSeen) }]);
        } else {
          missing.push(batch[j]);
        }
      }
    }

    // Clean up stale index entries.
    if (missing.length > 0) {
      await this.kv.srem(this.indexKey(), ...missing);
    }

    return loaded;
  }
}

export class ThreatService {
  private logger: Logger;
  private config: ThreatScoringConfig;

  /** Track recent signals for volume-based scoring */
  private recentSignals: RecentSignalsStore;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;
  private readonly WINDOW_MS = 5 * 60 * 1000; // 5 minute window

  constructor(logger: Logger, config?: Partial<ThreatScoringConfig>, recentSignalsStore?: RecentSignalsStore) {
    this.logger = logger.child({ service: 'threat-service' });
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.recentSignals = recentSignalsStore ?? new InMemoryRecentSignalsStore();
    this.startCleanup();
  }

  /**
   * Calculate threat score for a signal
   */
  async calculateThreatScore(signal: SignalContext): Promise<ThreatScore> {
    const factors: ThreatFactor[] = [];

    // 1. Severity factor
    const severityScore = SEVERITY_SCORES[signal.severity] ?? 50;
    factors.push({
      name: 'severity',
      weight: this.config.severityWeight,
      contribution: severityScore * this.config.severityWeight,
      reason: `Severity ${signal.severity} = ${severityScore}`,
    });

    // 2. Signal type factor
    const typeScore = SIGNAL_TYPE_SCORES[signal.signalType] ?? 40;
    factors.push({
      name: 'signalType',
      weight: this.config.signalTypeWeight,
      contribution: typeScore * this.config.signalTypeWeight,
      reason: `Signal type ${signal.signalType} = ${typeScore}`,
    });

    // 3. Confidence factor (signal's own confidence scaled)
    const confidenceScore = signal.confidence * 100;
    factors.push({
      name: 'confidence',
      weight: this.config.confidenceWeight,
      contribution: confidenceScore * this.config.confidenceWeight,
      reason: `Confidence ${(signal.confidence * 100).toFixed(0)}%`,
    });

    // 4. Volume factor (repeat offenders score higher)
    const volumeKey = this.buildVolumeKey(signal);
    const volumeScore = await this.updateVolumeTracking(volumeKey, signal.eventCount ?? 1);
    factors.push({
      name: 'volume',
      weight: this.config.volumeWeight,
      contribution: volumeScore * this.config.volumeWeight,
      reason: `Volume score = ${volumeScore}`,
    });

    // Calculate total score
    const totalScore = Math.min(
      100,
      Math.round(factors.reduce((sum, f) => sum + f.contribution, 0))
    );

    // Determine recommended action
    const recommendedAction = this.determineAction(totalScore);

    return {
      score: totalScore,
      factors,
      recommendedAction,
    };
  }

  /**
   * Get severity rank for comparison (for backward compatibility)
   */
  severityRank(severity: Severity): number {
    return SEVERITY_SCORES[severity] ?? 0;
  }

  /**
   * Compare two severities, returning the higher one
   */
  higherSeverity(a: Severity, b: Severity): Severity {
    return this.severityRank(a) >= this.severityRank(b) ? a : b;
  }

  private buildVolumeKey(signal: SignalContext): string {
    // Key by fingerprint, sourceIp, or signal type
    const base = `t:${signal.tenantId}:`;
    if (signal.fingerprint) return `${base}fp:${signal.fingerprint}`;
    if (signal.sourceIp) return `${base}ip:${signal.sourceIp}`;
    return `${base}type:${signal.signalType}`;
  }

  private async updateVolumeTracking(key: string, eventCount: number): Promise<number> {
    try {
      // Use atomic increment to prevent lost updates in distributed deployments.
      const totalCount = await this.recentSignals.incrementBy(key, eventCount);

      // Calculate volume score: logarithmic scaling for repeat offenders
      // 1 signal = 0, 10 signals = 50, 100 signals = 100
      return Math.min(100, Math.round(Math.log10(totalCount + 1) * 50));
    } catch (error) {
      // Fail open: volume factor becomes 0 if state store is unhealthy.
      this.logger.warn({ error, key }, 'Volume tracking update failed');
      return 0;
    }
  }

  private determineAction(score: number): ThreatScore['recommendedAction'] {
    if (score >= this.config.thresholds.block) return 'block';
    if (score >= this.config.thresholds.alert) return 'alert';
    if (score >= this.config.thresholds.monitor) return 'monitor';
    return 'allow';
  }

  private startCleanup(): void {
    // Clean up old entries every minute.
    this.cleanupInterval = setInterval(() => {
      void this.cleanupOnce();
    }, 60_000);
  }

  private async cleanupOnce(): Promise<void> {
    if (this.recentSignals.skipCleanup) return;
    try {
      const cutoff = Date.now() - this.WINDOW_MS;
      const entries = await this.recentSignals.entries();
      for (const [key, value] of entries) {
        if (value.lastSeen < cutoff) {
          await this.recentSignals.delete(key);
        }
      }
    } catch (error) {
      this.logger.warn({ error }, 'ThreatService cleanup failed');
    }
  }

  /**
   * Get current volume statistics
   */
  async getVolumeStats(): Promise<{ trackedEntities: number; totalSignals: number }> {
    const allEntries = await this.recentSignals.entries();
    let totalSignals = 0;
    for (const [, value] of allEntries) {
      totalSignals += value.count;
    }
    return {
      trackedEntities: allEntries.length,
      totalSignals,
    };
  }

  /**
   * Stop the service and clean up
   */
  async stop(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
