/**
 * Fleet Management Lifecycle Integration Tests
 *
 * Tests the complete command-ack-result lifecycle between:
 * - FleetCommander: Orchestrates commands and tracks status
 * - CommandSender: Manages reliable delivery over WebSocket
 * - SensorGateway: Handles WebSocket connections and command acknowledgments
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { FleetCommander } from '../fleet-commander.js';
import { CommandSender } from '../../../protocols/command-sender.js';

// Test constants
const TEST_TENANT_ID = 'tenant-test-123';
const TEST_SENSOR_ID = 'sensor-test-456';
const TEST_COMMAND_TYPE = 'push_config';
const TEST_PAYLOAD = { version: '2.0.0', config: { enabled: true } };

// Mock WebSocket
class MockWebSocket extends EventEmitter {
  readyState = 1; // OPEN
  sentMessages: string[] = [];

  send(data: string): void {
    this.sentMessages.push(data);
  }

  close(_code?: number, _reason?: string): void {
    this.readyState = 3; // CLOSED
    this.emit('close');
  }
}

// Create mock Prisma client
function createMockPrisma() {
  const commands = new Map<string, Record<string, unknown>>();
  let commandIdCounter = 0;

  return {
    sensor: {
      findUnique: vi.fn().mockResolvedValue({ id: TEST_SENSOR_ID, tenantId: TEST_TENANT_ID }),
      findMany: vi.fn().mockResolvedValue([{ id: TEST_SENSOR_ID }]),
      update: vi.fn().mockResolvedValue({}),
    },
    fleetCommand: {
      create: vi.fn().mockImplementation(({ data }) => {
        const id = `cmd-${++commandIdCounter}`;
        const command = { id, ...data };
        commands.set(id, command);
        return Promise.resolve(command);
      }),
      findUnique: vi.fn().mockImplementation(({ where: { id } }) => {
        return Promise.resolve(commands.get(id) || null);
      }),
      findMany: vi.fn().mockResolvedValue([]),
      update: vi.fn().mockImplementation(({ where: { id }, data }) => {
        const existing = commands.get(id);
        if (existing) {
          const updated = { ...existing, ...data };
          // Handle increment operations
          if (data.attempts?.increment) {
            updated.attempts = (existing.attempts as number || 0) + data.attempts.increment;
          }
          commands.set(id, updated);
          return Promise.resolve(updated);
        }
        return Promise.resolve(null);
      }),
      updateMany: vi.fn().mockImplementation(({ where, data }) => {
        const existing = commands.get(where.id);
        if (!existing) {
          return Promise.resolve({ count: 0 });
        }
        if (where.status?.in && !where.status.in.includes(existing.status)) {
          return Promise.resolve({ count: 0 });
        }
        if (where.attempts?.lt !== undefined) {
          const attempts = (existing.attempts as number | undefined) ?? 0;
          if (attempts >= where.attempts.lt) {
            return Promise.resolve({ count: 0 });
          }
        }
        const updated = { ...existing, ...data };
        if (data.attempts?.increment) {
          updated.attempts = ((existing.attempts as number | undefined) ?? 0) + data.attempts.increment;
        }
        commands.set(where.id, updated);
        return Promise.resolve({ count: 1 });
      }),
      deleteMany: vi.fn().mockResolvedValue({ count: 0 }),
    },
    _commands: commands, // Expose for test assertions
  } as unknown as PrismaClient & { _commands: Map<string, Record<string, unknown>> };
}

// Create mock logger
function createMockLogger() {
  return {
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
}

describe('Fleet Management Lifecycle', () => {
  let prisma: PrismaClient & { _commands: Map<string, Record<string, unknown>> };
  let logger: Logger;
  let fleetCommander: FleetCommander;
  let commandSender: CommandSender;
  let mockWs: MockWebSocket;

  beforeEach(() => {
    prisma = createMockPrisma();
    logger = createMockLogger();

    // Create CommandSender and FleetCommander
    commandSender = new CommandSender();
    commandSender.start();

    fleetCommander = new FleetCommander(prisma, logger, {
      defaultTimeoutMs: 5000,
      maxRetries: 2,
      timeoutCheckIntervalMs: 60000, // Long interval to avoid test interference
    });

    // Wire them together
    fleetCommander.setCommandSender(commandSender);

    // Create and register mock WebSocket connection
    mockWs = new MockWebSocket();
    commandSender.registerConnection(TEST_SENSOR_ID, mockWs as unknown as WebSocket);
  });

  afterEach(async () => {
    // Stop commandSender first to prevent events from reaching FleetCommander
    // after its prisma mock is stale
    commandSender.stop();
    commandSender.removeAllListeners();
    commandSender.clear();
    fleetCommander.stop();
    // Allow any pending async event handlers to complete
    await new Promise((resolve) => setImmediate(resolve));
  });

  describe('Command Creation and Sending', () => {
    it('should create command in database when sendCommand is called', async () => {
      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      expect(commandId).toBeTruthy();
      expect(prisma.fleetCommand.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          sensorId: TEST_SENSOR_ID,
          commandType: TEST_COMMAND_TYPE,
          payload: TEST_PAYLOAD,
          status: 'pending',
        }),
      });
    });

    it('should send command over WebSocket when sensor is connected', async () => {
      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // CommandSender sends synchronously when connection is available
      // Check that message was sent over WebSocket
      expect(mockWs.sentMessages.length).toBeGreaterThan(0);
      const sentMessage = JSON.parse(mockWs.sentMessages[0]);
      expect(sentMessage.type).toBe(TEST_COMMAND_TYPE);
      expect(sentMessage.payload).toEqual(TEST_PAYLOAD);
    });

    it('should emit command-sent event when command is dispatched', async () => {
      const commandSentHandler = vi.fn();
      fleetCommander.on('command-sent', commandSentHandler);

      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      expect(commandSentHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          sensorId: TEST_SENSOR_ID,
          commandType: TEST_COMMAND_TYPE,
        })
      );
    });

    it('should reject command to sensor owned by different tenant', async () => {
      // Mock sensor belonging to different tenant
      vi.mocked(prisma.sensor.findUnique).mockResolvedValueOnce({
        id: TEST_SENSOR_ID,
        tenantId: 'different-tenant',
      } as unknown as Awaited<ReturnType<PrismaClient['sensor']['findUnique']>>);

      await expect(
        fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
          type: TEST_COMMAND_TYPE,
          payload: TEST_PAYLOAD,
        })
      ).rejects.toThrow(/does not belong to tenant/);
    });
  });

  describe('Command Acknowledgment Flow', () => {
    it('should mark command as success when acknowledgment received', async () => {
      const commandSuccessHandler = vi.fn();
      fleetCommander.on('command-success', commandSuccessHandler);

      // Send command
      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // Simulate sensor acknowledgment - this triggers the event chain
      commandSender.handleResponse(commandId, true);

      // Wait a tick for async event handling
      await new Promise((resolve) => setImmediate(resolve));

      // Verify success handler was called
      expect(commandSuccessHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          commandId,
          sensorId: TEST_SENSOR_ID,
        })
      );

      // Verify database was updated
      expect(prisma.fleetCommand.updateMany).toHaveBeenCalledWith({
        where: { id: commandId, status: { in: ['pending', 'sent'] } },
        data: expect.objectContaining({
          status: 'success',
        }),
      });
    });

    it('should retry command on failure if under max retries', async () => {
      // Send command
      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // Simulate first failure (should trigger retry since attempts < maxRetries)
      commandSender.handleResponse(commandId, false, 'Network error');

      // Wait a tick for async event handling
      await new Promise((resolve) => setImmediate(resolve));

      // Command should be reset to pending for retry
      const command = prisma._commands.get(commandId);
      expect(command?.status).toBe('pending');
    });

    it('should mark command as permanently failed after max retries', async () => {
      const commandFailedHandler = vi.fn();
      fleetCommander.on('command-failed', commandFailedHandler);

      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // Simulate reaching max retries
      const command = prisma._commands.get(commandId);
      if (command) {
        command.attempts = 3; // Already at max
      }

      // Simulate failure
      commandSender.handleResponse(commandId, false, 'Persistent error');

      // Wait a tick for async event handling
      await new Promise((resolve) => setImmediate(resolve));

      // Should be permanently failed
      expect(commandFailedHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          commandId,
          error: 'Persistent error',
        })
      );
    });
  });

  describe('Command Timeout Handling', () => {
    it('should set timeout timestamp when creating command', async () => {
      const beforeCreate = Date.now();

      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
        timeout: 5000,
      });

      // Verify command was created with timeout
      expect(prisma.fleetCommand.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          timeoutAt: expect.any(Date),
        }),
      });

      const createCall = vi.mocked(prisma.fleetCommand.create).mock.calls[0][0];
      const timeoutAt = new Date(createCall.data.timeoutAt as Date).getTime();

      // Timeout should be approximately beforeCreate + 5000ms
      expect(timeoutAt).toBeGreaterThanOrEqual(beforeCreate + 4900);
      expect(timeoutAt).toBeLessThanOrEqual(beforeCreate + 5100);
    });

    it('should use default timeout when not specified', async () => {
      const beforeCreate = Date.now();

      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      const createCall = vi.mocked(prisma.fleetCommand.create).mock.calls[0][0];
      const timeoutAt = new Date(createCall.data.timeoutAt as Date).getTime();

      // Default timeout is 5000ms (set in beforeEach)
      expect(timeoutAt).toBeGreaterThanOrEqual(beforeCreate + 4900);
      expect(timeoutAt).toBeLessThanOrEqual(beforeCreate + 5100);
    });
  });

  describe('Multi-Sensor Commands', () => {
    it('should send commands to multiple sensors', async () => {
      const sensorIds = ['sensor-1', 'sensor-2', 'sensor-3'];

      // Mock all sensors as belonging to test tenant
      vi.mocked(prisma.sensor.findUnique).mockImplementation(({ where: { id } }) => {
        return Promise.resolve({
          id,
          tenantId: TEST_TENANT_ID,
        } as Awaited<ReturnType<PrismaClient['sensor']['findUnique']>>);
      });

      // Register mock connections for all sensors
      for (const sensorId of sensorIds) {
        const ws = new MockWebSocket();
        commandSender.registerConnection(sensorId, ws as unknown as WebSocket);
      }

      const commandIds = await fleetCommander.sendCommandToMultiple(TEST_TENANT_ID, sensorIds, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      expect(commandIds).toHaveLength(3);
      expect(prisma.fleetCommand.create).toHaveBeenCalledTimes(3);
    });

    it('should broadcast command to all connected tenant sensors', async () => {
      const connectedSensors = [
        { id: 'sensor-a' },
        { id: 'sensor-b' },
      ];

      vi.mocked(prisma.sensor.findMany).mockResolvedValueOnce(
        connectedSensors as Awaited<ReturnType<PrismaClient['sensor']['findMany']>>
      );

      vi.mocked(prisma.sensor.findUnique).mockImplementation(({ where: { id } }) => {
        return Promise.resolve({
          id,
          tenantId: TEST_TENANT_ID,
        } as Awaited<ReturnType<PrismaClient['sensor']['findUnique']>>);
      });

      // Register connections
      for (const sensor of connectedSensors) {
        const ws = new MockWebSocket();
        commandSender.registerConnection(sensor.id, ws as unknown as WebSocket);
      }

      const commandIds = await fleetCommander.broadcastCommand(TEST_TENANT_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      expect(commandIds).toHaveLength(2);
    });
  });

  describe('Command Cancellation', () => {
    it('should cancel pending command', async () => {
      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      const cancelled = await fleetCommander.cancelCommand(commandId);

      expect(cancelled).toBe(true);
      expect(prisma.fleetCommand.updateMany).toHaveBeenCalledWith({
        where: { id: commandId, status: { in: ['pending', 'sent'] } },
        data: expect.objectContaining({
          status: 'failed',
          error: 'Cancelled by user',
        }),
      });
    });

    it('should not cancel completed command', async () => {
      const commandId = await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // Mark as completed
      const command = prisma._commands.get(commandId);
      if (command) {
        command.status = 'success';
      }

      const cancelled = await fleetCommander.cancelCommand(commandId);

      expect(cancelled).toBe(false);
    });
  });

  describe('CommandSender Protocol Integration', () => {
    // Use isolated CommandSender for these tests to avoid FleetCommander event interference

    it('should queue commands when sensor is offline', () => {
      const isolated = new CommandSender();
      isolated.start();

      // Don't register any connection - sensor is offline
      const cmdId = isolated.sendCommand(TEST_SENSOR_ID, 'push_config', TEST_PAYLOAD);

      // Check command is pending (queued)
      const cmd = isolated.getCommand(cmdId);
      expect(cmd?.status).toBe('pending');

      isolated.stop();
      isolated.clear();
    });

    it('should flush pending commands when sensor reconnects', () => {
      const isolated = new CommandSender();
      isolated.start();

      // Queue some commands while offline
      const firstId = isolated.sendCommand(TEST_SENSOR_ID, 'push_config', { v: 1 });
      const secondId = isolated.sendCommand(TEST_SENSOR_ID, 'push_config', { v: 2 });

      // Reconnect
      const ws = new MockWebSocket();
      isolated.registerConnection(TEST_SENSOR_ID, ws as unknown as WebSocket);

      // Commands should be flushed
      expect(ws.sentMessages.length).toBe(1);
      const firstPayload = JSON.parse(ws.sentMessages[0]);
      expect(firstPayload.commandId).toBe(firstId);

      isolated.handleResponse(firstId as string, true);

      expect(ws.sentMessages.length).toBe(2);
      const secondPayload = JSON.parse(ws.sentMessages[1]);
      expect(secondPayload.commandId).toBe(secondId);

      isolated.stop();
      isolated.clear();
    });

    it('should track command statistics', () => {
      const isolated = new CommandSender();
      isolated.start();
      const ws = new MockWebSocket();
      isolated.registerConnection(TEST_SENSOR_ID, ws as unknown as WebSocket);

      // Send a command
      const cmdId = isolated.sendCommand(TEST_SENSOR_ID, 'push_config', TEST_PAYLOAD);

      let stats = isolated.getStats();
      expect(stats.sent).toBe(1);
      expect(stats.pending).toBe(0);

      // Complete the command
      isolated.handleResponse(cmdId, true);

      stats = isolated.getStats();
      expect(stats.success).toBe(1);

      isolated.stop();
      isolated.clear();
    });
  });

  describe('Event Propagation', () => {
    it('should emit command-sent event from FleetCommander on send', async () => {
      const fleetSentHandler = vi.fn();
      fleetCommander.on('command-sent', fleetSentHandler);

      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // FleetCommander emits synchronously after creating command
      expect(fleetSentHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          sensorId: TEST_SENSOR_ID,
          commandType: TEST_COMMAND_TYPE,
        })
      );
    });

    it('should emit command-sent event from CommandSender on WebSocket send', async () => {
      const senderSentHandler = vi.fn();
      commandSender.on('command-sent', senderSentHandler);

      await fleetCommander.sendCommand(TEST_TENANT_ID, TEST_SENSOR_ID, {
        type: TEST_COMMAND_TYPE,
        payload: TEST_PAYLOAD,
      });

      // CommandSender emits synchronously when WebSocket is available
      expect(senderSentHandler).toHaveBeenCalled();
    });

    it('should emit command-complete from CommandSender on response', async () => {
      // Create a standalone CommandSender for this test to avoid event pollution
      const isolatedSender = new CommandSender();
      isolatedSender.start();
      const isolatedWs = new MockWebSocket();
      isolatedSender.registerConnection(TEST_SENSOR_ID, isolatedWs as unknown as WebSocket);

      const senderCompleteHandler = vi.fn();
      isolatedSender.on('command-complete', senderCompleteHandler);

      // Send command directly through isolated sender
      const commandId = isolatedSender.sendCommand(TEST_SENSOR_ID, 'push_config', TEST_PAYLOAD);

      isolatedSender.handleResponse(commandId, true);

      expect(senderCompleteHandler).toHaveBeenCalledWith(
        expect.objectContaining({
          id: commandId,
          status: 'success',
        })
      );

      // Clean up
      isolatedSender.stop();
      isolatedSender.removeAllListeners();
      isolatedSender.clear();
    });
  });
});

describe('Command Type Configurations', () => {
  let commandSender: CommandSender;
  let mockWs: MockWebSocket;

  beforeEach(() => {
    commandSender = new CommandSender();
    commandSender.start();
    mockWs = new MockWebSocket();
    commandSender.registerConnection(TEST_SENSOR_ID, mockWs as unknown as WebSocket);
  });

  afterEach(() => {
    commandSender.stop();
  });

  it('should use appropriate timeout for restart commands', () => {
    const cmdId = commandSender.sendCommand(TEST_SENSOR_ID, 'restart', {});
    const cmd = commandSender.getCommand(cmdId);

    expect(cmd?.timeoutMs).toBe(60000); // 1 minute for restart
    expect(cmd?.maxAttempts).toBe(2); // Only 2 attempts for restart
  });

  it('should use appropriate timeout for collect_diagnostics commands', () => {
    const cmdId = commandSender.sendCommand(TEST_SENSOR_ID, 'collect_diagnostics', {});
    const cmd = commandSender.getCommand(cmdId);

    expect(cmd?.timeoutMs).toBe(120000); // 2 minutes
    expect(cmd?.maxAttempts).toBe(2);
  });

  it('should use appropriate timeout for push_config commands', () => {
    const cmdId = commandSender.sendCommand(TEST_SENSOR_ID, 'push_config', {});
    const cmd = commandSender.getCommand(cmdId);

    expect(cmd?.timeoutMs).toBe(30000); // 30 seconds
    expect(cmd?.maxAttempts).toBe(3);
  });

  it('should use appropriate timeout for update commands', () => {
    const cmdId = commandSender.sendCommand(TEST_SENSOR_ID, 'update', {});
    const cmd = commandSender.getCommand(cmdId);

    expect(cmd?.timeoutMs).toBe(300000); // 5 minutes for download/install
    expect(cmd?.maxAttempts).toBe(3);
  });
});
