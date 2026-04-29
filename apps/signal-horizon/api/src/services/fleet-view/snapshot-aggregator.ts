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
import type { Actor } from '../synapse-proxy.js';

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

export interface MergedActor extends Actor {
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

  return { actors, perSensor };
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

function unionStringArrays(arrays: string[][]): string[] {
  const set = new Set<string>();
  for (const arr of arrays) {
    for (const value of arr) {
      set.add(value);
    }
  }
  return [...set].sort();
}
