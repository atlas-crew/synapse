import { describe, it, expect } from 'vitest';
import {
  aggregateActorRows,
  aggregateSessionRows,
  buildSensorFreshnessEntries,
  FLEET_VIEW_DEFAULT_STALE_AFTER_MS,
  type SensorIntelActorRow,
  type SensorIntelSessionRow,
} from './snapshot-aggregator.js';

const NOW = new Date('2026-04-29T12:00:00Z');
const FRESH = new Date(NOW.getTime() - 30_000);
const STALE = new Date(NOW.getTime() - FLEET_VIEW_DEFAULT_STALE_AFTER_MS - 60_000);

function makeRow(overrides: Partial<SensorIntelActorRow> & { sensorId: string; actorId: string }): SensorIntelActorRow {
  return {
    riskScore: 0.5,
    isBlocked: false,
    firstSeenAt: new Date('2026-04-29T11:00:00Z'),
    lastSeenAt: new Date('2026-04-29T11:55:00Z'),
    ips: ['1.1.1.1'],
    fingerprints: ['fp-a'],
    sessionIds: ['s-1'],
    raw: {
      actorId: overrides.actorId,
      riskScore: overrides.riskScore ?? 0.5,
      isBlocked: overrides.isBlocked ?? false,
      ruleMatches: [],
      anomalyCount: 0,
      sessionIds: overrides.sessionIds ?? ['s-1'],
      firstSeen: 1714000000,
      lastSeen: 1714003300,
      ips: overrides.ips ?? ['1.1.1.1'],
      fingerprints: overrides.fingerprints ?? ['fp-a'],
      blockReason: null,
      blockedSince: null,
    },
    updatedAt: FRESH,
    ...overrides,
  };
}

function makeSessionRow(
  overrides: Partial<SensorIntelSessionRow> & {
    sensorId: string;
    sessionId: string;
  },
): SensorIntelSessionRow {
  const lastActivityAt = overrides.lastActivityAt ?? new Date('2026-04-29T11:55:00Z');
  const createdAt = overrides.createdAt ?? new Date('2026-04-29T11:00:00Z');
  return {
    actorId: 'actor-a',
    requestCount: 1,
    isSuspicious: false,
    lastActivityAt,
    boundIp: null,
    boundJa4: null,
    hijackAlerts: [],
    raw: {
      sessionId: overrides.sessionId,
      tokenHash: `tok-${overrides.sessionId}`,
      actorId: overrides.actorId ?? 'actor-a',
      creationTime: createdAt.getTime(),
      lastActivity: lastActivityAt.getTime(),
      requestCount: overrides.requestCount ?? 1,
      boundIp: overrides.boundIp ?? null,
      boundJa4: overrides.boundJa4 ?? null,
      isSuspicious: overrides.isSuspicious ?? false,
      hijackAlerts: overrides.hijackAlerts ?? [],
    },
    createdAt,
    updatedAt: FRESH,
    ...overrides,
  };
}

describe('aggregateActorRows', () => {
  it('passes a single-sensor row through with seenOnSensors attribution', () => {
    const result = aggregateActorRows([
      makeRow({ sensorId: 'sensor-1', actorId: 'actor-x', riskScore: 0.4 }),
    ]);

    expect(result.actors).toHaveLength(1);
    expect(result.actors[0]).toMatchObject({
      actorId: 'actor-x',
      riskScore: 0.4,
      seenOnSensors: ['sensor-1'],
    });
  });

  it('merges the same actorId across two sensors using max(riskScore)', () => {
    const result = aggregateActorRows([
      makeRow({ sensorId: 'sensor-1', actorId: 'actor-x', riskScore: 0.3 }),
      makeRow({ sensorId: 'sensor-2', actorId: 'actor-x', riskScore: 0.9 }),
    ]);

    expect(result.actors).toHaveLength(1);
    expect(result.actors[0].riskScore).toBe(0.9);
    expect(result.actors[0].seenOnSensors).toEqual(['sensor-1', 'sensor-2']);
  });

  it('unions ips, fingerprints, and sessionIds across sensors', () => {
    const result = aggregateActorRows([
      makeRow({
        sensorId: 'sensor-1',
        actorId: 'actor-x',
        ips: ['1.1.1.1', '2.2.2.2'],
        fingerprints: ['fp-a'],
        sessionIds: ['s-1'],
      }),
      makeRow({
        sensorId: 'sensor-2',
        actorId: 'actor-x',
        ips: ['2.2.2.2', '3.3.3.3'],
        fingerprints: ['fp-b'],
        sessionIds: ['s-2'],
      }),
    ]);

    expect(result.actors[0].ips).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3']);
    expect(result.actors[0].fingerprints).toEqual(['fp-a', 'fp-b']);
    expect(result.actors[0].sessionIds).toEqual(['s-1', 's-2']);
  });

  it('OR-aggregates isBlocked: any blocked sensor blocks the merged actor', () => {
    const result = aggregateActorRows([
      makeRow({ sensorId: 'sensor-1', actorId: 'actor-x', isBlocked: false }),
      makeRow({
        sensorId: 'sensor-2',
        actorId: 'actor-x',
        isBlocked: true,
        raw: {
          actorId: 'actor-x',
          riskScore: 0.5,
          isBlocked: true,
          blockReason: 'manual',
          blockedSince: 1714000500,
          ruleMatches: [],
          anomalyCount: 0,
          sessionIds: [],
          firstSeen: 1714000000,
          lastSeen: 1714003300,
          ips: [],
          fingerprints: [],
        },
      }),
    ]);

    expect(result.actors[0].isBlocked).toBe(true);
    expect(result.actors[0].blockReason).toBe('manual');
    expect(result.actors[0].blockedSince).toBe(1714000500);
  });

  it('uses min(firstSeen) and max(lastSeen) from raw payloads', () => {
    const result = aggregateActorRows([
      makeRow({
        sensorId: 'sensor-1',
        actorId: 'actor-x',
        raw: {
          actorId: 'actor-x',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 0,
          sessionIds: [],
          firstSeen: 1714000000,
          lastSeen: 1714003300,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
      makeRow({
        sensorId: 'sensor-2',
        actorId: 'actor-x',
        raw: {
          actorId: 'actor-x',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 0,
          sessionIds: [],
          firstSeen: 1713999000,
          lastSeen: 1714004000,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
    ]);

    expect(result.actors[0].firstSeen).toBe(1713999000);
    expect(result.actors[0].lastSeen).toBe(1714004000);
  });

  it('sums anomalyCount from raw across sensors', () => {
    const result = aggregateActorRows([
      makeRow({
        sensorId: 'sensor-1',
        actorId: 'actor-x',
        raw: {
          actorId: 'actor-x',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 3,
          sessionIds: [],
          firstSeen: 1714000000,
          lastSeen: 1714003300,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
      makeRow({
        sensorId: 'sensor-2',
        actorId: 'actor-x',
        raw: {
          actorId: 'actor-x',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 7,
          sessionIds: [],
          firstSeen: 1714000000,
          lastSeen: 1714003300,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
    ]);

    expect(result.actors[0].anomalyCount).toBe(10);
  });

  it('keeps distinct actorIds separate and sorts the merged list by lastSeen desc', () => {
    const result = aggregateActorRows([
      makeRow({
        sensorId: 'sensor-1',
        actorId: 'older-actor',
        raw: {
          actorId: 'older-actor',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 0,
          sessionIds: [],
          firstSeen: 1714000000,
          lastSeen: 1714000500,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
      makeRow({
        sensorId: 'sensor-2',
        actorId: 'newer-actor',
        raw: {
          actorId: 'newer-actor',
          riskScore: 0.5,
          isBlocked: false,
          ruleMatches: [],
          anomalyCount: 0,
          sessionIds: [],
          firstSeen: 1714003000,
          lastSeen: 1714004000,
          ips: [],
          fingerprints: [],
          blockReason: null,
          blockedSince: null,
        },
      }),
    ]);

    expect(result.actors.map((a) => a.actorId)).toEqual(['newer-actor', 'older-actor']);
  });

  it('records per-sensor row counts and freshest updatedAt for envelope use', () => {
    const fresher = new Date(NOW.getTime() - 10_000);
    const older = new Date(NOW.getTime() - 60_000);

    const result = aggregateActorRows([
      makeRow({ sensorId: 'sensor-1', actorId: 'a', updatedAt: older }),
      makeRow({ sensorId: 'sensor-1', actorId: 'b', updatedAt: fresher }),
      makeRow({ sensorId: 'sensor-2', actorId: 'a', updatedAt: fresher }),
    ]);

    expect(result.perSensor.get('sensor-1')).toEqual({
      rowCount: 2,
      freshestUpdatedAt: fresher,
    });
    expect(result.perSensor.get('sensor-2')).toEqual({
      rowCount: 1,
      freshestUpdatedAt: fresher,
    });
  });
});

describe('aggregateSessionRows', () => {
  it('computes stats from merged sessions using the supplied now timestamp', () => {
    const result = aggregateSessionRows(
      [
        makeSessionRow({
          sensorId: 'sensor-1',
          sessionId: 'active-shared',
          requestCount: 2,
          isSuspicious: false,
          hijackAlerts: [{ alertType: 'ip_drift' }],
          lastActivityAt: new Date(NOW.getTime() - 5 * 60_000),
          raw: {
            sessionId: 'active-shared',
            tokenHash: 'tok-active',
            creationTime: NOW.getTime() - 2 * 60 * 60_000,
            lastActivity: NOW.getTime() - 5 * 60_000,
            requestCount: 2,
            isSuspicious: false,
            hijackAlerts: [{ alertType: 'ip_drift' }],
          },
        }),
        makeSessionRow({
          sensorId: 'sensor-2',
          sessionId: 'active-shared',
          requestCount: 3,
          isSuspicious: true,
          hijackAlerts: [{ alertType: 'fingerprint_change' }],
          lastActivityAt: new Date(NOW.getTime() - 4 * 60_000),
          raw: {
            sessionId: 'active-shared',
            tokenHash: 'tok-active',
            creationTime: NOW.getTime() - 2 * 60 * 60_000,
            lastActivity: NOW.getTime() - 4 * 60_000,
            requestCount: 3,
            isSuspicious: true,
            hijackAlerts: [{ alertType: 'fingerprint_change' }],
          },
        }),
        makeSessionRow({
          sensorId: 'sensor-1',
          sessionId: 'expired-clean',
          requestCount: 5,
          isSuspicious: false,
          lastActivityAt: new Date(NOW.getTime() - 45 * 60_000),
          raw: {
            sessionId: 'expired-clean',
            tokenHash: 'tok-expired',
            creationTime: NOW.getTime() - 3 * 60 * 60_000,
            lastActivity: NOW.getTime() - 45 * 60_000,
            requestCount: 5,
            isSuspicious: false,
            hijackAlerts: [],
          },
        }),
      ],
      NOW.getTime(),
    );

    expect(result.sessions).toHaveLength(2);
    expect(result.sessions.find((session) => session.sessionId === 'active-shared')).toMatchObject({
      requestCount: 5,
      isSuspicious: true,
      seenOnSensors: ['sensor-1', 'sensor-2'],
    });
    expect(result.stats).toEqual({
      totalSessions: 2,
      activeSessions: 1,
      suspiciousSessions: 1,
      expiredSessions: 1,
      hijackAlerts: 2,
      evictions: 0,
      totalCreated: 2,
      totalInvalidated: 0,
    });
  });

  it('normalizes second-like timestamps and falls back to row dates for invalid raw timestamps', () => {
    const secondsCreation = 1_714_388_300;
    const secondsLastActivity = 1_714_391_900;
    const fallbackCreatedAt = new Date('2026-04-29T10:15:00Z');
    const fallbackLastActivityAt = new Date('2026-04-29T11:15:00Z');

    const result = aggregateSessionRows([
      makeSessionRow({
        sensorId: 'sensor-1',
        sessionId: 'seconds-session',
        createdAt: new Date(secondsCreation * 1000),
        lastActivityAt: new Date(secondsLastActivity * 1000),
        raw: {
          sessionId: 'seconds-session',
          creationTime: secondsCreation,
          lastActivity: secondsLastActivity,
        },
      }),
      makeSessionRow({
        sensorId: 'sensor-2',
        sessionId: 'fallback-session',
        createdAt: fallbackCreatedAt,
        lastActivityAt: fallbackLastActivityAt,
        raw: {
          sessionId: 'fallback-session',
          creationTime: 'not-a-time',
          lastActivity: 0,
        },
      }),
    ]);

    expect(result.sessions.map((session) => session.sessionId)).toEqual([
      'fallback-session',
      'seconds-session',
    ]);
    expect(result.sessions.find((session) => session.sessionId === 'seconds-session')).toMatchObject({
      creationTime: secondsCreation * 1000,
      lastActivity: secondsLastActivity * 1000,
    });
    expect(result.sessions.find((session) => session.sessionId === 'fallback-session')).toMatchObject({
      creationTime: fallbackCreatedAt.getTime(),
      lastActivity: fallbackLastActivityAt.getTime(),
    });
  });
});

describe('buildSensorFreshnessEntries', () => {
  it('marks a sensor with fresh rows as ok', () => {
    const perSensor = new Map([['sensor-1', { rowCount: 3, freshestUpdatedAt: FRESH }]]);
    const entries = buildSensorFreshnessEntries(['sensor-1'], perSensor, { now: () => NOW });
    expect(entries[0]).toMatchObject({
      sensorId: 'sensor-1',
      status: 'ok',
      data: { rowCount: 3 },
    });
    expect(entries[0].lastUpdatedAt).toBe(FRESH.toISOString());
  });

  it("marks a sensor whose freshest row exceeds the stale threshold as 'stale' instead of dropping it", () => {
    const perSensor = new Map([['sensor-1', { rowCount: 2, freshestUpdatedAt: STALE }]]);
    const entries = buildSensorFreshnessEntries(['sensor-1'], perSensor, { now: () => NOW });
    expect(entries[0]).toMatchObject({
      sensorId: 'sensor-1',
      status: 'stale',
      data: { rowCount: 2 },
    });
    expect(entries[0].lastUpdatedAt).toBe(STALE.toISOString());
  });

  it('marks a registered sensor with no rows as error', () => {
    const perSensor = new Map<string, { rowCount: number; freshestUpdatedAt: Date }>();
    const entries = buildSensorFreshnessEntries(['sensor-1'], perSensor, { now: () => NOW });
    expect(entries[0]).toMatchObject({
      sensorId: 'sensor-1',
      status: 'error',
      error: 'No snapshot rows for this sensor',
    });
  });

  it('respects custom staleAfterMs override', () => {
    const tightStale = new Date(NOW.getTime() - 2_000);
    const perSensor = new Map([['sensor-1', { rowCount: 1, freshestUpdatedAt: tightStale }]]);
    const entries = buildSensorFreshnessEntries(['sensor-1'], perSensor, {
      now: () => NOW,
      staleAfterMs: 1_000,
    });
    expect(entries[0].status).toBe('stale');
  });

  it('emits one entry per registered sensor, preserving order', () => {
    const perSensor = new Map([
      ['sensor-2', { rowCount: 1, freshestUpdatedAt: FRESH }],
      ['sensor-1', { rowCount: 4, freshestUpdatedAt: FRESH }],
    ]);
    const entries = buildSensorFreshnessEntries(['sensor-1', 'sensor-2', 'sensor-3'], perSensor, {
      now: () => NOW,
    });
    expect(entries.map((e) => e.sensorId)).toEqual(['sensor-1', 'sensor-2', 'sensor-3']);
    expect(entries.map((e) => e.status)).toEqual(['ok', 'ok', 'error']);
  });
});
