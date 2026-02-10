/**
 * Fleet Aggregator P1 Reliability Tests
 *
 * Validates resource threshold alerting, heartbeat timeout detection,
 * stale sensor cleanup, and fleet-wide metrics aggregation.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Logger } from 'pino';
import { FleetAggregator } from '../fleet-aggregator.js';
import { InMemorySensorMetricsStore } from '../sensor-metrics-store.js';
import type { SensorHeartbeat, SensorAlert } from '../types.js';

// Stub prometheus metrics so real counters/gauges are never touched during tests
vi.mock('../../metrics.js', () => ({
  metrics: {
    sensorHeartbeatsTotal: { inc: vi.fn() },
    sensorsOnlineGauge: { inc: vi.fn(), dec: vi.fn() },
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createMockLogger(): Logger {
  return {
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

function makeHeartbeat(overrides: Partial<SensorHeartbeat> & { sensorId: string; tenantId: string }): SensorHeartbeat {
  return {
    timestamp: new Date(),
    metrics: { rps: 100, latency: 5, cpu: 40, memory: 50, disk: 30 },
    health: 'healthy',
    requestsTotal: 10000,
    region: 'us-east-1',
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FleetAggregator', () => {
  let logger: Logger;
  let store: InMemorySensorMetricsStore;
  let aggregator: FleetAggregator;

  beforeEach(() => {
    vi.useFakeTimers();
    logger = createMockLogger();
    store = new InMemorySensorMetricsStore();
  });

  afterEach(() => {
    aggregator?.stop();
    vi.useRealTimers();
  });

  // -----------------------------------------------------------------------
  // CPU threshold alerts
  // -----------------------------------------------------------------------

  it('should emit warning alert when CPU reaches 80% threshold', async () => {
    aggregator = new FleetAggregator(logger, { cpuAlertThreshold: 80 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 82, memory: 40, disk: 30 },
    }));

    const cpuAlert = alerts.find(a => a.alertType === 'high_cpu');
    expect(cpuAlert).toBeDefined();
    expect(cpuAlert!.severity).toBe('warning');
    expect(cpuAlert!.value).toBe(82);
    expect(cpuAlert!.threshold).toBe(80);
  });

  it('should emit critical alert when CPU reaches 95%', async () => {
    aggregator = new FleetAggregator(logger, { cpuAlertThreshold: 80 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 96, memory: 40, disk: 30 },
    }));

    const cpuAlert = alerts.find(a => a.alertType === 'high_cpu');
    expect(cpuAlert).toBeDefined();
    expect(cpuAlert!.severity).toBe('critical');
  });

  // -----------------------------------------------------------------------
  // Memory threshold alerts
  // -----------------------------------------------------------------------

  it('should emit warning alert when memory reaches 85% threshold', async () => {
    aggregator = new FleetAggregator(logger, { memoryAlertThreshold: 85 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 20, memory: 88, disk: 30 },
    }));

    const memAlert = alerts.find(a => a.alertType === 'high_memory');
    expect(memAlert).toBeDefined();
    expect(memAlert!.severity).toBe('warning');
    expect(memAlert!.value).toBe(88);
    expect(memAlert!.threshold).toBe(85);
  });

  it('should emit critical alert when memory reaches 95%', async () => {
    aggregator = new FleetAggregator(logger, { memoryAlertThreshold: 85 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 20, memory: 97, disk: 30 },
    }));

    const memAlert = alerts.find(a => a.alertType === 'high_memory');
    expect(memAlert).toBeDefined();
    expect(memAlert!.severity).toBe('critical');
  });

  // -----------------------------------------------------------------------
  // Disk threshold alerts
  // -----------------------------------------------------------------------

  it('should emit warning alert when disk reaches 90% threshold', async () => {
    aggregator = new FleetAggregator(logger, { diskAlertThreshold: 90 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 20, memory: 40, disk: 93 },
    }));

    const diskAlert = alerts.find(a => a.alertType === 'high_disk');
    expect(diskAlert).toBeDefined();
    expect(diskAlert!.severity).toBe('warning');
    expect(diskAlert!.value).toBe(93);
    expect(diskAlert!.threshold).toBe(90);
  });

  it('should emit critical alert when disk reaches 98%', async () => {
    aggregator = new FleetAggregator(logger, { diskAlertThreshold: 90 }, store);

    const alerts: SensorAlert[] = [];
    aggregator.on('sensor-alert', (a: SensorAlert) => alerts.push(a));

    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
      metrics: { rps: 50, latency: 3, cpu: 20, memory: 40, disk: 99 },
    }));

    const diskAlert = alerts.find(a => a.alertType === 'high_disk');
    expect(diskAlert).toBeDefined();
    expect(diskAlert!.severity).toBe('critical');
  });

  // -----------------------------------------------------------------------
  // Heartbeat timeout / offline detection
  // -----------------------------------------------------------------------

  it('should mark sensor as offline after heartbeat timeout', async () => {
    const heartbeatTimeoutMs = 5000;
    aggregator = new FleetAggregator(logger, { heartbeatTimeoutMs }, store);

    // Report healthy heartbeat
    await aggregator.updateSensorMetrics('sensor-1', makeHeartbeat({
      sensorId: 'sensor-1',
      tenantId: 'tenant-1',
    }));

    // Sensor should be online
    let fleetMetrics = await aggregator.getFleetMetrics();
    expect(fleetMetrics.onlineSensors).toBe(1);
    expect(fleetMetrics.offlineSensors).toBe(0);

    // Advance time past heartbeat timeout
    vi.advanceTimersByTime(heartbeatTimeoutMs + 1000);

    // Sensor should now be offline
    fleetMetrics = await aggregator.getFleetMetrics();
    expect(fleetMetrics.onlineSensors).toBe(0);
    expect(fleetMetrics.offlineSensors).toBe(1);
  });

  // -----------------------------------------------------------------------
  // Stale data cleanup
  // -----------------------------------------------------------------------

  it('should clean up stale sensor data after retention period', async () => {
    const metricsRetentionMs = 10000;
    aggregator = new FleetAggregator(logger, { metricsRetentionMs, heartbeatTimeoutMs: 5000 }, store);

    const offlineHandler = vi.fn();
    aggregator.on('sensor-offline', offlineHandler);

    // Add sensor data
    await aggregator.updateSensorMetrics('sensor-stale', makeHeartbeat({
      sensorId: 'sensor-stale',
      tenantId: 'tenant-1',
    }));

    // Verify data exists
    const before = await aggregator.getAllSensorMetrics();
    expect(before).toHaveLength(1);

    // Advance past retention period and trigger cleanup interval (runs every 60s)
    vi.advanceTimersByTime(metricsRetentionMs + 60000);

    // Allow async cleanup to complete
    await vi.advanceTimersByTimeAsync(0);

    // Stale data should be cleaned up
    const after = await aggregator.getAllSensorMetrics();
    expect(after).toHaveLength(0);

    // Should emit sensor-offline for cleaned-up sensor
    expect(offlineHandler).toHaveBeenCalledWith(
      expect.objectContaining({ sensorId: 'sensor-stale', tenantId: 'tenant-1' }),
    );
  });

  // -----------------------------------------------------------------------
  // Fleet metrics totals aggregation
  // -----------------------------------------------------------------------

  it('should correctly aggregate fleet-wide metrics from multiple sensors', async () => {
    aggregator = new FleetAggregator(logger, { heartbeatTimeoutMs: 60000 }, store);

    // Add three sensors with different metrics
    await aggregator.updateSensorMetrics('sensor-a', makeHeartbeat({
      sensorId: 'sensor-a',
      tenantId: 'tenant-1',
      metrics: { rps: 100, latency: 10, cpu: 60, memory: 50, disk: 40 },
    }));

    await aggregator.updateSensorMetrics('sensor-b', makeHeartbeat({
      sensorId: 'sensor-b',
      tenantId: 'tenant-1',
      metrics: { rps: 200, latency: 20, cpu: 80, memory: 70, disk: 60 },
    }));

    await aggregator.updateSensorMetrics('sensor-c', makeHeartbeat({
      sensorId: 'sensor-c',
      tenantId: 'tenant-2',
      metrics: { rps: 300, latency: 30, cpu: 40, memory: 30, disk: 20 },
    }));

    const fleet = await aggregator.getFleetMetrics();

    // Total RPS should be the sum
    expect(fleet.totalRps).toBe(600);
    expect(fleet.totalSensors).toBe(3);
    expect(fleet.onlineSensors).toBe(3);
    expect(fleet.offlineSensors).toBe(0);

    // Weighted average latency: (100*10 + 200*20 + 300*30) / (100+200+300) = 14000/600 = 23.33
    expect(fleet.avgLatency).toBeCloseTo(23.33, 1);

    // Simple averages for resources: (60+80+40)/3 = 60, (50+70+30)/3 = 50, (40+60+20)/3 = 40
    expect(fleet.avgCpu).toBeCloseTo(60, 1);
    expect(fleet.avgMemory).toBeCloseTo(50, 1);
    expect(fleet.avgDisk).toBeCloseTo(40, 1);

    // Health score: 3/3 * 100 = 100
    expect(fleet.healthScore).toBe(100);
  });

  it('should emit sensor-online event when a new sensor reports in', async () => {
    aggregator = new FleetAggregator(logger, {}, store);

    const onlineHandler = vi.fn();
    aggregator.on('sensor-online', onlineHandler);

    await aggregator.updateSensorMetrics('sensor-new', makeHeartbeat({
      sensorId: 'sensor-new',
      tenantId: 'tenant-1',
    }));

    expect(onlineHandler).toHaveBeenCalledWith(
      expect.objectContaining({ sensorId: 'sensor-new', tenantId: 'tenant-1' }),
    );
  });
});
