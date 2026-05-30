/**
 * Fleet snapshot aggregator
 *
 * Implements ADR-0002 §Dedup semantics for fleet-view SOC surfaces. Reads
 * per-sensor SensorIntel* snapshot rows and reconciles the same logical
 * entity across sensors:
 *
 *   - scores (risk/severity/confidence) → max
 *   - boolean flags (isBlocked) → OR
 *   - set-typed fields (ips, fingerprints, sessionIds) → union
 *   - times (firstSeen) → min, (lastSeen, lastActivity) → max
 *   - counters (anomalyCount, requestCount) → sum
 *   - attribution → seenOnSensors: string[]
 *
 * Per-sensor freshness is reported separately via the FleetPartialResult
 * envelope: a sensor whose freshest row exceeds the stale threshold is
 * reported as 'stale', not dropped. A registered sensor with no rows in the
 * result is reported as 'error'.
 */

import type { FleetPartialResultEntry } from '../../types/fleet-partial-result.js';
import type { Actor, HijackAlert, Session, SessionStats } from '../synapse-proxy.js';

export const FLEET_VIEW_DEFAULT_STALE_AFTER_MS = 5 * 60 * 1000;

export interface SensorIntelActorRow {
  sensorId: string;
  actorId: string;
  riskScore: number;
  isBlocked: boolean;
  firstSeenAt: Date;
  lastSeenAt: Date;
  ips: unknown;
  fingerprints: unknown;
  sessionIds: unknown;
  raw: unknown;
  updatedAt: Date;
}

export interface SensorIntelSessionRow {
  sensorId: string;
  sessionId: string;
  actorId: string | null;
  requestCount: number;
  isSuspicious: boolean;
  lastActivityAt: Date;
  boundIp: string | null;
  boundJa4: string | null;
  hijackAlerts: unknown;
  raw: unknown;
  createdAt: Date;
  updatedAt: Date;
}

export interface MergedActor extends Actor {
  seenOnSensors: string[];
}

export interface MergedSession extends Session {
  seenOnSensors: string[];
}

export interface PerSensorFreshness {
  rowCount: number;
  freshestUpdatedAt: Date;
}

export interface AggregateActorsOutput {
  actors: MergedActor[];
  perSensor: Map<string, PerSensorFreshness>;
}

export interface AggregateSessionsOutput {
  sessions: MergedSession[];
  perSensor: Map<string, PerSensorFreshness>;
  stats: SessionStats;
}

export function aggregateActorRows(rows: SensorIntelActorRow[]): AggregateActorsOutput {
  const groups = new Map<string, SensorIntelActorRow[]>();
  for (const row of rows) {
    const bucket = groups.get(row.actorId);
    if (bucket) {
      bucket.push(row);
    } else {
      groups.set(row.actorId, [row]);
    }
  }

  const actors: MergedActor[] = [];
  for (const [actorId, group] of groups) {
    actors.push(mergeActor(actorId, group));
  }
  actors.sort((a, b) => b.lastSeen - a.lastSeen);

  const perSensor = buildPerSensorFreshness(rows);

  return { actors, perSensor };
}

export function aggregateSessionRows(rows: SensorIntelSessionRow[], nowMs = Date.now()): AggregateSessionsOutput {
  const groups = new Map<string, SensorIntelSessionRow[]>();
  for (const row of rows) {
    const bucket = groups.get(row.sessionId);
    if (bucket) {
      bucket.push(row);
    } else {
      groups.set(row.sessionId, [row]);
    }
  }

  const sessions: MergedSession[] = [];
  for (const [sessionId, group] of groups) {
    sessions.push(mergeSession(sessionId, group));
  }
  sessions.sort((a, b) => b.lastActivity - a.lastActivity);

  const perSensor = buildPerSensorFreshness(rows);

  return {
    sessions,
    perSensor,
    stats: buildSessionStats(sessions, nowMs),
  };
}

export function buildSessionStats(sessions: Session[], nowMs = Date.now()): SessionStats {
  const hijackAlerts = sessions.reduce((sum, session) => sum + session.hijackAlerts.length, 0);
  const activeSessions = sessions.filter((session) => session.lastActivity > nowMs - 30 * 60 * 1000).length;
  const suspiciousSessions = sessions.filter((session) => session.isSuspicious).length;

  return {
    totalSessions: sessions.length,
    activeSessions,
    suspiciousSessions,
    expiredSessions: Math.max(0, sessions.length - activeSessions),
    hijackAlerts,
    evictions: 0,
    totalCreated: sessions.length,
    totalInvalidated: 0,
  };
}

function mergeActor(actorId: string, rows: SensorIntelActorRow[]): MergedActor {
  const raws = rows.map((r) => (r.raw ?? {}) as Partial<Actor>);

  const riskScore = rows.reduce((max, r) => (r.riskScore > max ? r.riskScore : max), 0);
  const isBlocked = rows.some((r) => r.isBlocked);
  const firstSeen = raws.reduce<number>((min, raw) => {
    const v = Number(raw.firstSeen ?? 0);
    if (v <= 0) return min;
    if (min === 0) return v;
    return v < min ? v : min;
  }, 0);
  const lastSeen = raws.reduce<number>((max, raw) => {
    const v = Number(raw.lastSeen ?? 0);
    return v > max ? v : max;
  }, 0);
  const ips = unionStringArrays(rows.map((r) => toStringArray(r.ips)));
  const fingerprints = unionStringArrays(rows.map((r) => toStringArray(r.fingerprints)));
  const sessionIds = unionStringArrays(rows.map((r) => toStringArray(r.sessionIds)));
  const anomalyCount = raws.reduce((sum, raw) => sum + Number(raw.anomalyCount ?? 0), 0);
  const ruleMatches = raws.flatMap((raw) => raw.ruleMatches ?? []);

  const blockedRaws = raws.filter((raw) => raw.isBlocked);
  const blockReason = blockedRaws.find((raw) => raw.blockReason)?.blockReason ?? null;
  const blockedSinceCandidates = blockedRaws
    .map((raw) => Number(raw.blockedSince ?? 0))
    .filter((t) => t > 0);
  const blockedSince =
    blockedSinceCandidates.length > 0 ? Math.min(...blockedSinceCandidates) : null;

  return {
    actorId,
    riskScore,
    isBlocked,
    ruleMatches,
    anomalyCount,
    sessionIds,
    firstSeen,
    lastSeen,
    ips,
    fingerprints,
    blockReason,
    blockedSince,
    seenOnSensors: rows.map((r) => r.sensorId).sort(),
  };
}

function mergeSession(sessionId: string, rows: SensorIntelSessionRow[]): MergedSession {
  const sortedRows = [...rows].sort((a, b) => b.lastActivityAt.getTime() - a.lastActivityAt.getTime());
  const latest = sortedRows[0];
  const raws = rows.map((r) => (r.raw ?? {}) as Partial<Session>);

  const creationTime = raws.reduce<number>((min, raw, index) => {
    const v = toEpochMs(raw.creationTime, rows[index].createdAt.getTime());
    if (min === 0) return v;
    return v < min ? v : min;
  }, 0);

  const lastActivity = raws.reduce<number>((max, raw, index) => {
    const v = toEpochMs(raw.lastActivity, rows[index].lastActivityAt.getTime());
    return v > max ? v : max;
  }, 0);

  const hijackAlerts = rows.flatMap((row, index) =>
    toHijackAlerts(row.hijackAlerts ?? raws[index].hijackAlerts, row.sessionId),
  );

  return {
    sessionId,
    tokenHash: firstString(raws.map((raw) => raw.tokenHash)) ?? `tok_${sessionId}`,
    actorId: latest.actorId ?? firstString(raws.map((raw) => raw.actorId)) ?? null,
    creationTime,
    lastActivity,
    requestCount: rows.reduce((sum, row) => sum + row.requestCount, 0),
    boundJa4: latest.boundJa4 ?? firstString(raws.map((raw) => raw.boundJa4)) ?? null,
    boundIp: latest.boundIp ?? firstString(raws.map((raw) => raw.boundIp)) ?? null,
    isSuspicious: rows.some((row) => row.isSuspicious),
    hijackAlerts,
    seenOnSensors: [...new Set(rows.map((row) => row.sensorId))].sort(),
  };
}

function buildPerSensorFreshness(rows: Array<{ sensorId: string; updatedAt: Date }>): Map<string, PerSensorFreshness> {
  const perSensor = new Map<string, PerSensorFreshness>();
  for (const row of rows) {
    const existing = perSensor.get(row.sensorId);
    if (!existing) {
      perSensor.set(row.sensorId, { rowCount: 1, freshestUpdatedAt: row.updatedAt });
    } else {
      existing.rowCount += 1;
      if (row.updatedAt > existing.freshestUpdatedAt) {
        existing.freshestUpdatedAt = row.updatedAt;
      }
    }
  }
  return perSensor;
}

export interface BuildFreshnessConfig {
  staleAfterMs?: number;
  now?: () => Date;
}

export interface SensorFreshnessData {
  rowCount: number;
}

export function buildSensorFreshnessEntries(
  registeredSensorIds: string[],
  perSensor: Map<string, PerSensorFreshness>,
  config: BuildFreshnessConfig = {},
): FleetPartialResultEntry<SensorFreshnessData>[] {
  const now = (config.now ?? (() => new Date()))();
  const staleAfterMs = config.staleAfterMs ?? FLEET_VIEW_DEFAULT_STALE_AFTER_MS;

  return registeredSensorIds.map((sensorId) => {
    const entry = perSensor.get(sensorId);
    if (!entry) {
      return {
        sensorId,
        status: 'error',
        error: 'No snapshot rows for this sensor',
      };
    }
    const ageMs = now.getTime() - entry.freshestUpdatedAt.getTime();
    const status: 'ok' | 'stale' = ageMs > staleAfterMs ? 'stale' : 'ok';
    return {
      sensorId,
      status,
      data: { rowCount: entry.rowCount },
      lastUpdatedAt: entry.freshestUpdatedAt.toISOString(),
    };
  });
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string');
}

function toHijackAlerts(value: unknown, sessionId: string): HijackAlert[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
    .map((item) => ({
      sessionId: typeof item.sessionId === 'string' ? item.sessionId : sessionId,
      alertType: typeof item.alertType === 'string' ? item.alertType : 'unknown',
      originalValue: typeof item.originalValue === 'string' ? item.originalValue : '',
      newValue: typeof item.newValue === 'string' ? item.newValue : '',
      timestamp: Number(item.timestamp ?? 0),
      confidence: Number(item.confidence ?? 0),
    }));
}

function toEpochMs(value: unknown, fallbackMs: number): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallbackMs;
  // Sensor session timestamps have existed in both seconds-like and
  // milliseconds-like shapes; normalize fleet UI responses to milliseconds.
  return n < 10_000_000_000 ? n * 1000 : n;
}

function firstString(values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return null;
}

function unionStringArrays(arrays: string[][]): string[] {
  const set = new Set<string>();
  for (const arr of arrays) {
    for (const value of arr) {
      set.add(value);
    }
  }
  return [...set].sort();
}
