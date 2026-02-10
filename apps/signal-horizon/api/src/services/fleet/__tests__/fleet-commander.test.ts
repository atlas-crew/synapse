/**
 * Fleet Commander P1 Reliability Tests
 *
 * Validates command timeout, retry exhaustion, adaptive timeout calculation,
 * feature flag enforcement, stop() cleanup, and command-success event emission.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { FleetCommander, CommandFeatureDisabledError } from '../fleet-commander.js';
import { CommandSender } from '../../../protocols/command-sender.js';
import { FleetAggregator } from '../fleet-aggregator.js';
import { InMemorySensorMetricsStore } from '../sensor-metrics-store.js';

// Stub prometheus metrics
vi.mock('../../metrics.js', () => ({
  metrics: {
    fleetCommandsSent: { inc: vi.fn() },
    fleetCommandsSucceeded: { inc: vi.fn() },
    fleetCommandsFailed: { inc: vi.fn() },
    fleetCommandDuration: { observe: vi.fn() },
    sensorHeartbeatsTotal: { inc: vi.fn() },
    sensorsOnlineGauge: { inc: vi.fn(), dec: vi.fn() },
  },
}));

// ---------------------------------------------------------------------------
// Constants and helpers
// ---------------------------------------------------------------------------

const TEST_TENANT_ID = 'tenant-cmd-123';
const TEST_SENSOR_ID = 'sensor-cmd-456';

class MockWebSocket extends EventEmitter {
  readyState = 1; // OPEN
  sentMessages: string[] = [];
  send(data: string): void {
    this.sentMessages.push(data);
  }
  close(): void {
    this.readyState = 3;
    this.emit('close');
  }
}

function createMockPrisma() {
  const commands = new Map<string, any>();
  let commandIdCounter = 0;

  const mock = {
    sensor: {
      findUnique: vi.fn().mockResolvedValue({
        id: TEST_SENSOR_ID,
        tenantId: TEST_TENANT_ID,
        connectionState: 'CONNECTED',
      }),
      findMany: vi.fn().mockResolvedValue([{ id: TEST_SENSOR_ID }]),
    },
    fleetCommand: {
      create: vi.fn().mockImplementation(({ data }) => {
        const id = `cmd-${++commandIdCounter}`;
        const command = { id, queuedAt: new Date(), ...data };
        commands.set(id, command);
        return Promise.resolve(command);
      }),
      findUnique: vi.fn().mockImplementation(({ where: { id } }) => {
        const cmd = commands.get(id);
        if (cmd) {
          return Promise.resolve({ ...cmd, sensor: { id: cmd.sensorId, tenantId: TEST_TENANT_ID } });
        }
        return Promise.resolve(null);
      }),
      findFirst: vi.fn().mockResolvedValue(null),
      findMany: vi.fn().mockImplementation(({ where }) => {
        const results = Array.from(commands.values()).filter(c => {
          if (where?.status?.in && !where.status.in.includes(c.status)) return false;
          if (where?.timeoutAt?.lte && c.timeoutAt > where.timeoutAt.lte) return false;
          return true;
        });
        return Promise.resolve(results);
      }),
      updateMany: vi.fn().mockImplementation(({ where, data }) => {
        const cmd = commands.get(where.id);
        if (!cmd) return Promise.resolve({ count: 0 });
        if (where.status?.in && !where.status.in.includes(cmd.status)) return Promise.resolve({ count: 0 });
        if (where.attempts?.lt !== undefined && (cmd.attempts ?? 0) >= where.attempts.lt) {
          return Promise.resolve({ count: 0 });
        }
        Object.assign(cmd, data);
        if (data.attempts?.increment) {
          cmd.attempts = (cmd.attempts ?? 0) + data.attempts.increment;
        }
        return Promise.resolve({ count: 1 });
      }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
    $transaction: vi.fn(async (fn: any) => fn(mock)),
    _commands: commands,
  };

  return mock as unknown as PrismaClient & { _commands: Map<string, any> };
}

function createMockLogger(): Logger {
  return {
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('FleetCommander', () => {
  let prisma: PrismaClient & { _commands: Map<string, any> };
  let logger: Logger;
  let commander: FleetCommander;
  let commandSender: CommandSender;

  beforeEach(() => {
    vi.useFakeTimers();
    prisma = createMockPrisma();
    logger = createMockLogger();
    commandSender = new CommandSender();
    commandSender.start();
  });

  afterEach(() => {
    commandSender.stop();
    commandSender.removeAllListeners();
    commandSender.clear();
    commander?.stop();
    vi.useRealTimers();
  });

  // -----------------------------------------------------------------------
  // Command timeout
  // -----------------------------------------------------------------------

  it('should mark command as timed out after timeout period', async () => {
    commander = new FleetCommander(prisma, logger, {
      defaultTimeoutMs: 5000,
      timeoutCheckIntervalMs: 1000,
    });

    const timeoutHandler = vi.fn();
    commander.on('command-timeout', timeoutHandler);

    const mockWs = new MockWebSocket();
    commandSender.registerConnection(TEST_SENSOR_ID, mockWs as any);
    commander.setCommandSender(commandSender);

    const commandId = await commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
      type: 'push_config',
      payload: { v: 1 },
    });

    // Advance time past the timeout + check interval
    await vi.advanceTimersByTimeAsync(6000);

    const cmd = prisma._commands.get(commandId);
    expect(cmd.status).toBe('timeout');
    expect(cmd.error).toBe('Command timed out');
    expect(timeoutHandler).toHaveBeenCalledWith(
      expect.objectContaining({ commandId, sensorId: TEST_SENSOR_ID }),
    );
  });

  // -----------------------------------------------------------------------
  // Retry exhaustion
  // -----------------------------------------------------------------------

  it('should retry up to maxRetries then permanently fail', async () => {
    commander = new FleetCommander(prisma, logger, {
      defaultTimeoutMs: 30000,
      maxRetries: 2,
      timeoutCheckIntervalMs: 60000,
    });

    const failedHandler = vi.fn();
    commander.on('command-failed', failedHandler);

    // Send command directly through FleetCommander (no CommandSender wired)
    // so we can drive markCommandFailed manually without WebSocket event chains
    const commandId = await commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
      type: 'push_config',
      payload: { v: 1 },
    });

    // Set initial state: command was sent, attempts = 0 (under maxRetries=2)
    const cmd = prisma._commands.get(commandId);
    cmd.status = 'sent';
    cmd.attempts = 0;

    // First failure: attempts(0) < maxRetries(2), should reset to pending for retry
    await commander.markCommandFailed(commandId, 'Network error');
    expect(prisma._commands.get(commandId).status).toBe('pending');

    // Second failure: bump attempts to maxRetries threshold
    cmd.status = 'sent';
    cmd.attempts = 2;

    // Now attempts(2) >= maxRetries(2), should permanently fail
    await commander.markCommandFailed(commandId, 'Persistent error');
    expect(prisma._commands.get(commandId).status).toBe('failed');
    expect(failedHandler).toHaveBeenCalledWith(
      expect.objectContaining({ commandId, error: 'Persistent error' }),
    );
  });

  // -----------------------------------------------------------------------
  // Adaptive timeout calculation
  // -----------------------------------------------------------------------

  it('should calculate adaptive timeout from sensor latency and clamp to min/max', async () => {
    const store = new InMemorySensorMetricsStore();
    const aggregator = new FleetAggregator(logger, { heartbeatTimeoutMs: 60000 }, store);

    // Seed the aggregator with a sensor whose latency is 50ms
    await aggregator.updateSensorMetrics(TEST_SENSOR_ID, {
      sensorId: TEST_SENSOR_ID,
      tenantId: TEST_TENANT_ID,
      timestamp: new Date(),
      metrics: { rps: 100, latency: 50, cpu: 20, memory: 30, disk: 20 },
      health: 'healthy',
      requestsTotal: 5000,
      region: 'us-east-1',
    });

    commander = new FleetCommander(prisma, logger, {
      enableAdaptiveTimeout: true,
      minAdaptiveTimeoutMs: 5000,
      maxAdaptiveTimeoutMs: 120000,
      timeoutCheckIntervalMs: 60000,
    }, aggregator);

    const mockWs = new MockWebSocket();
    commandSender.registerConnection(TEST_SENSOR_ID, mockWs as any);
    commander.setCommandSender(commandSender);

    await commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
      type: 'push_config',
      payload: {},
    });

    // Adaptive timeout = latency(50) + 10000 = 10050, clamped between 5000 and 120000
    const createCall = vi.mocked(prisma.fleetCommand.create).mock.calls[0][0];
    const timeoutAt = (createCall.data.timeoutAt as Date).getTime();
    const expectedTimeout = 10050; // 50ms latency + 10s buffer
    const now = Date.now();
    expect(timeoutAt).toBeGreaterThanOrEqual(now + expectedTimeout - 100);
    expect(timeoutAt).toBeLessThanOrEqual(now + expectedTimeout + 100);

    aggregator.stop();
  });

  it('should clamp adaptive timeout to minimum when latency is very low', async () => {
    const store = new InMemorySensorMetricsStore();
    const aggregator = new FleetAggregator(logger, { heartbeatTimeoutMs: 60000 }, store);

    // Sensor with 1ms latency: adaptive = 1 + 10000 = 10001, but min is 15000
    await aggregator.updateSensorMetrics(TEST_SENSOR_ID, {
      sensorId: TEST_SENSOR_ID,
      tenantId: TEST_TENANT_ID,
      timestamp: new Date(),
      metrics: { rps: 100, latency: 1, cpu: 20, memory: 30, disk: 20 },
      health: 'healthy',
      requestsTotal: 5000,
    });

    commander = new FleetCommander(prisma, logger, {
      enableAdaptiveTimeout: true,
      minAdaptiveTimeoutMs: 15000,
      maxAdaptiveTimeoutMs: 120000,
      timeoutCheckIntervalMs: 60000,
    }, aggregator);

    const mockWs = new MockWebSocket();
    commandSender.registerConnection(TEST_SENSOR_ID, mockWs as any);
    commander.setCommandSender(commandSender);

    await commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
      type: 'push_config',
      payload: {},
    });

    // Should be clamped to min: 15000
    const createCall = vi.mocked(prisma.fleetCommand.create).mock.calls[0][0];
    const timeoutAt = (createCall.data.timeoutAt as Date).getTime();
    const now = Date.now();
    expect(timeoutAt).toBeGreaterThanOrEqual(now + 14900);
    expect(timeoutAt).toBeLessThanOrEqual(now + 15100);

    aggregator.stop();
  });

  // -----------------------------------------------------------------------
  // Feature flag disable
  // -----------------------------------------------------------------------

  it('should throw CommandFeatureDisabledError when toggle_chaos is disabled', async () => {
    commander = new FleetCommander(prisma, logger, {
      commandFeatures: { toggleChaos: false },
      timeoutCheckIntervalMs: 60000,
    });

    await expect(
      commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: 'toggle_chaos',
        payload: { enabled: true },
      }),
    ).rejects.toThrow(CommandFeatureDisabledError);
  });

  it('should throw CommandFeatureDisabledError when toggle_mtd is disabled', async () => {
    commander = new FleetCommander(prisma, logger, {
      commandFeatures: { toggleMtd: false },
      timeoutCheckIntervalMs: 60000,
    });

    await expect(
      commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: 'toggle_mtd',
        payload: { enabled: true },
      }),
    ).rejects.toThrow(CommandFeatureDisabledError);
  });

  // -----------------------------------------------------------------------
  // stop() cleans up
  // -----------------------------------------------------------------------

  it('should clean up timers and listeners on stop()', async () => {
    commander = new FleetCommander(prisma, logger, {
      timeoutCheckIntervalMs: 500,
    });

    // Attach listeners to verify they are removed
    const handler = vi.fn();
    commander.on('command-sent', handler);

    commander.stop();

    // Listeners should be removed
    expect(commander.listenerCount('command-sent')).toBe(0);
    expect(commander.listenerCount('command-success')).toBe(0);
    expect(commander.listenerCount('command-failed')).toBe(0);
    expect(commander.listenerCount('command-timeout')).toBe(0);
  });

  // -----------------------------------------------------------------------
  // command-success event
  // -----------------------------------------------------------------------

  it('should emit command-success event on successful completion', async () => {
    commander = new FleetCommander(prisma, logger, {
      defaultTimeoutMs: 30000,
      timeoutCheckIntervalMs: 60000,
    });

    const successHandler = vi.fn();
    commander.on('command-success', successHandler);

    // Send command without CommandSender so we can drive markCommandSuccess directly
    const commandId = await commander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
      type: 'push_config',
      payload: { version: '2.0' },
    });

    // Set status to 'sent' so markCommandSuccess can transition it
    const cmd = prisma._commands.get(commandId);
    cmd.status = 'sent';
    cmd.sentAt = new Date();

    // Drive success directly
    await commander.markCommandSuccess(commandId, { applied: true });

    expect(successHandler).toHaveBeenCalledWith(
      expect.objectContaining({
        commandId,
        sensorId: TEST_SENSOR_ID,
        commandType: 'push_config',
      }),
    );

    // Database should reflect success status
    expect(prisma._commands.get(commandId).status).toBe('success');
  });
});
