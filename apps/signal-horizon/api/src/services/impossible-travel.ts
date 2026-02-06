/**
 * Impossible Travel Detection Service
 * Identifies geographically impossible travel between login events.
 */

import { randomUUID } from 'node:crypto';
import type { Logger } from 'pino';
import type { PrismaClient, Severity } from '@prisma/client';

import { applyTtlJitter, buildRedisKey, jsonDecode, jsonEncode, TTL_SECONDS, type RedisKv } from '../storage/redis/index.js';

export interface GeoLocation {
  latitude: f64;
  longitude: f64;
  city?: string;
  countryCode: string;
}

export interface LoginEvent {
  userId: string;
  tenantId: string;
  timestamp: Date;
  ip: string;
  location: GeoLocation;
  fingerprint?: string;
}

export interface ImpossibleTravelAlert {
  userId: string;
  tenantId: string;
  from: LoginEvent;
  to: LoginEvent;
  distanceKm: number;
  timeDiffHours: number;
  requiredSpeedKmh: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

type f64 = number;

/**
 * Store interface for user login history.
 * Allows swapping between in-memory and Redis-backed implementations.
 */
export interface UserHistoryStore {
  /**
   * Atomically (best-effort) append an event and return the prior history window
   * for evaluation.
   */
  appendAndGetPrevious(
    event: LoginEvent,
    options: { historyWindowMs: number; maxHistoryPerUser: number }
  ): Promise<LoginEvent[]>;
  delete(tenantId: string, userId: string): Promise<void>;
}

/**
 * In-memory implementation of UserHistoryStore (default).
 * Suitable for single-instance deployments.
 */
export class InMemoryUserHistoryStore implements UserHistoryStore {
  private map = new Map<string, LoginEvent[]>();

  async appendAndGetPrevious(
    event: LoginEvent,
    options: { historyWindowMs: number; maxHistoryPerUser: number }
  ): Promise<LoginEvent[]> {
    const key = `${event.tenantId}:${event.userId}`;
    const existing = this.map.get(key) || [];

    const cutoff = Date.now() - options.historyWindowMs;
    const previous = existing.filter((e) => e.timestamp.getTime() > cutoff);

    const updated = [...previous, event];
    if (updated.length > options.maxHistoryPerUser) updated.splice(0, updated.length - options.maxHistoryPerUser);

    this.map.set(key, updated);
    return previous;
  }

  async delete(tenantId: string, userId: string): Promise<void> {
    this.map.delete(`${tenantId}:${userId}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

type StoredLoginEvent = Omit<LoginEvent, 'timestamp'> & { timestamp: string };

function serializeLoginEvent(event: LoginEvent): StoredLoginEvent {
  return { ...event, timestamp: event.timestamp.toISOString() };
}

function deserializeLoginEvent(event: StoredLoginEvent): LoginEvent {
  return { ...event, timestamp: new Date(event.timestamp) };
}

export class RedisUserHistoryStore implements UserHistoryStore {
  private kv: RedisKv;
  private logger: Logger;
  private namespace: string;
  private version: number;
  private dataType: string;
  private lockTtlSeconds: number;

  constructor(
    kv: RedisKv,
    logger: Logger,
    options: {
      namespace?: string;
      version?: number;
      dataType?: string;
      lockTtlSeconds?: number;
    } = {}
  ) {
    this.kv = kv;
    this.logger = logger.child({ component: 'redis-user-history-store' });
    this.namespace = options.namespace ?? 'horizon';
    this.version = options.version ?? 1;
    this.dataType = options.dataType ?? 'impossible-travel-user-history';
    this.lockTtlSeconds = options.lockTtlSeconds ?? TTL_SECONDS.lockMin;
  }

  private historyKey(tenantId: string, userId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: this.dataType,
      id: userId,
    });
  }

  private lockKey(tenantId: string, userId: string): string {
    return buildRedisKey({
      namespace: this.namespace,
      version: this.version,
      tenantId,
      dataType: 'lock',
      id: [this.dataType, userId],
    });
  }

  private async readHistory(key: string): Promise<LoginEvent[]> {
    const raw = await this.kv.get(key);
    if (!raw) return [];
    const parsed = jsonDecode<StoredLoginEvent[]>(raw, { maxBytes: 1024 * 1024 });
    return parsed.map(deserializeLoginEvent);
  }

  async appendAndGetPrevious(
    event: LoginEvent,
    options: { historyWindowMs: number; maxHistoryPerUser: number }
  ): Promise<LoginEvent[]> {
    const key = this.historyKey(event.tenantId, event.userId);
    const lockKey = this.lockKey(event.tenantId, event.userId);

    const ttlSeconds = applyTtlJitter(Math.ceil(options.historyWindowMs / 1000));
    const cutoff = Date.now() - options.historyWindowMs;

    const lockValue = randomUUID();
    let lockAcquired = false;
    for (let attempt = 0; attempt < 5; attempt++) {
      lockAcquired = await this.kv.set(lockKey, lockValue, { ttlSeconds: this.lockTtlSeconds, ifNotExists: true });
      if (lockAcquired) break;
      // Keep latency bounded; prefer making progress over waiting indefinitely.
      await sleep(50 * (attempt + 1));
    }

    if (!lockAcquired) {
      this.logger.warn({ lockKey }, 'Failed to acquire history lock after 5 attempts, proceeding unprotected');
    }

    try {
      const existing = await this.readHistory(key);
      const previous = existing.filter((e) => e.timestamp.getTime() > cutoff);

      const updated = [...previous, event];
      if (updated.length > options.maxHistoryPerUser) updated.splice(0, updated.length - options.maxHistoryPerUser);

      await this.kv.set(key, jsonEncode(updated.map(serializeLoginEvent)), { ttlSeconds });

      return previous;
    } finally {
      if (lockAcquired) {
        const current = await this.kv.get(lockKey);
        if (current === lockValue) await this.kv.del(lockKey);
      }
    }
  }

  async delete(tenantId: string, userId: string): Promise<void> {
    await this.kv.del(this.historyKey(tenantId, userId));
  }
}

/**
 * Best-effort wrapper: if the primary store errors (Redis outage), fall back to
 * in-memory tracking to keep impossible-travel detection running in degraded mode.
 */
export class ResilientUserHistoryStore implements UserHistoryStore {
  private logger: Logger;
  private primary: UserHistoryStore;
  private fallback: UserHistoryStore;
  private lastWarnAtMs = 0;

  constructor(logger: Logger, primary: UserHistoryStore, fallback: UserHistoryStore) {
    this.logger = logger.child({ component: 'resilient-user-history-store' });
    this.primary = primary;
    this.fallback = fallback;
  }

  private warn(op: string, error: unknown): void {
    const now = Date.now();
    if (now - this.lastWarnAtMs < 30_000) return;
    this.lastWarnAtMs = now;
    this.logger.warn({ error, op }, 'UserHistoryStore primary failed; using fallback');
  }

  async appendAndGetPrevious(
    event: LoginEvent,
    options: { historyWindowMs: number; maxHistoryPerUser: number }
  ): Promise<LoginEvent[]> {
    // Keep fallback warm so we can continue locally if primary dies mid-flight.
    const fallbackPrevious = await this.fallback.appendAndGetPrevious(event, options);
    try {
      return await this.primary.appendAndGetPrevious(event, options);
    } catch (error) {
      this.warn('appendAndGetPrevious', error);
      return fallbackPrevious;
    }
  }

  async delete(tenantId: string, userId: string): Promise<void> {
    await this.fallback.delete(tenantId, userId);
    try {
      await this.primary.delete(tenantId, userId);
    } catch (error) {
      this.warn('delete', error);
    }
  }
}

export class ImpossibleTravelService {
  private prisma: PrismaClient;
  private logger: Logger;
  private userHistory: UserHistoryStore;
  private historyWindowMs = 24 * 60 * 60 * 1000; // 24 hours
  private maxHistoryPerUser = 10;
  private maxSpeedKmh = 1000; // Commercial flight speed approx

  constructor(prisma: PrismaClient, logger: Logger, userHistoryStore?: UserHistoryStore) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'impossible-travel' });
    this.userHistory = userHistoryStore ?? new InMemoryUserHistoryStore();
  }

  /**
   * Process a new login event and check for impossible travel
   */
  async processLogin(event: LoginEvent): Promise<ImpossibleTravelAlert | null> {
    const history = await this.userHistory.appendAndGetPrevious(event, {
      historyWindowMs: this.historyWindowMs,
      maxHistoryPerUser: this.maxHistoryPerUser,
    });

    let alert: ImpossibleTravelAlert | null = null;

    // Check against recent logins
    for (const prev of history) {
      const travelAlert = this.checkTravel(prev, event);
      if (travelAlert) {
        // If we found multiple, keep the one with highest speed/severity
        if (!alert || travelAlert.requiredSpeedKmh > alert.requiredSpeedKmh) {
          alert = travelAlert;
        }
      }
    }

    if (alert) {
      this.logger.warn(
        {
          userId: alert.userId,
          speed: alert.requiredSpeedKmh,
          distance: alert.distanceKm,
          severity: alert.severity,
        },
        'Impossible travel detected'
      );
      
      // Persist the alert as a signal or threat (optional, based on project needs)
      await this.persistAlert(alert);
    }

    return alert;
  }

  private checkTravel(from: LoginEvent, to: LoginEvent): ImpossibleTravelAlert | null {
    const distance = this.haversineDistance(
      from.location.latitude,
      from.location.longitude,
      to.location.latitude,
      to.location.longitude
    );

    // Ignore if same area (< 50km)
    if (distance < 50) return null;

    const timeDiffMs = to.timestamp.getTime() - from.timestamp.getTime();
    const timeDiffHours = timeDiffMs / (1000 * 60 * 60);

    // Ignore if too much time passed or events are out of order
    if (timeDiffHours <= 0 || timeDiffHours > 24) return null;

    const requiredSpeed = distance / timeDiffHours;

    if (requiredSpeed > this.maxSpeedKmh) {
      return {
        userId: to.userId,
        tenantId: to.tenantId,
        from,
        to,
        distanceKm: Math.round(distance),
        timeDiffHours: Math.round(timeDiffHours * 100) / 100,
        requiredSpeedKmh: Math.round(requiredSpeed),
        severity: this.calculateSeverity(requiredSpeed),
      };
    }

    return null;
  }

  private calculateSeverity(speed: number): ImpossibleTravelAlert['severity'] {
    if (speed > 5000) return 'critical';
    if (speed > 2000) return 'high';
    if (speed > 1200) return 'medium';
    return 'low';
  }

  private haversineDistance(lat1: f64, lon1: f64, lat2: f64, lon2: f64): number {
    const R = 6371; // Earth radius in km
    const dLat = this.toRad(lat2 - lat1);
    const dLon = this.toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRad(lat1)) *
        Math.cos(this.toRad(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  private toRad(value: number): number {
    return (value * Math.PI) / 180;
  }

  private async persistAlert(alert: ImpossibleTravelAlert): Promise<void> {
    try {
      // Create a signal for this impossible travel
      await this.prisma.signal.create({
        data: {
          tenantId: alert.tenantId,
          sensorId: alert.to.userId, // Using userId as sensor context for now
          signalType: 'IMPOSSIBLE_TRAVEL',
          severity: alert.severity.toUpperCase() as Severity,
          confidence: 0.9,
          metadata: {
            alertType: 'impossible_travel',
            distanceKm: alert.distanceKm,
            speedKmh: alert.requiredSpeedKmh,
            from: {
              ip: alert.from.ip,
              city: alert.from.location.city,
              country: alert.from.location.countryCode,
              timestamp: alert.from.timestamp,
            },
            to: {
              ip: alert.to.ip,
              city: alert.to.location.city,
              country: alert.to.location.countryCode,
              timestamp: alert.to.timestamp,
            },
          },
        },
      });
    } catch (error) {
      this.logger.error({ error }, 'Failed to persist impossible travel alert');
    }
  }
}
