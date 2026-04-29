import { describe, it, expect } from 'vitest';
import {
  aggregateActorRows,
  buildSensorFreshnessEntries,
  FLEET_VIEW_DEFAULT_STALE_AFTER_MS,
  type SensorIntelActorRow,
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
