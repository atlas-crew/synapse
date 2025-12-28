/**
 * Fleet Commander Service
 * Send commands to sensors and track their execution status
 */

import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import { EventEmitter } from 'node:events';
import type { SensorCommand, CommandStatus, Command } from './types.js';

export interface FleetCommanderConfig {
  /**
   * Default command timeout (milliseconds)
   * Default: 30000 (30 seconds)
   */
  defaultTimeoutMs?: number;

  /**
   * Maximum retry attempts for failed commands
   * Default: 3
   */
  maxRetries?: number;

  /**
   * Interval for checking command timeouts (milliseconds)
   * Default: 5000 (5 seconds)
   */
  timeoutCheckIntervalMs?: number;
}

/**
 * FleetCommander Events:
 * - 'command-sent': Emitted when a command is sent to a sensor
 * - 'command-success': Emitted when a command completes successfully
 * - 'command-failed': Emitted when a command fails
 * - 'command-timeout': Emitted when a command times out
 */
export class FleetCommander extends EventEmitter {
  private prisma: PrismaClient;
  private logger: Logger;
  private config: Required<FleetCommanderConfig>;
  private timeoutCheckInterval: NodeJS.Timeout | null = null;

  constructor(prisma: PrismaClient, logger: Logger, config: FleetCommanderConfig = {}) {
    super();
    this.prisma = prisma;
    this.logger = logger.child({ service: 'fleet-commander' });
    this.config = {
      defaultTimeoutMs: config.defaultTimeoutMs ?? 30000, // 30 seconds
      maxRetries: config.maxRetries ?? 3,
      timeoutCheckIntervalMs: config.timeoutCheckIntervalMs ?? 5000, // 5 seconds
    };

    // Start timeout checker
    this.startTimeoutChecker();
  }

  // =============================================================================
  // Send Commands
  // =============================================================================

  /**
   * Send a command to a single sensor
   * Returns the command ID for tracking
   */
  async sendCommand(sensorId: string, command: SensorCommand): Promise<string> {
    this.logger.info({ sensorId, commandType: command.type }, 'Sending command to sensor');

    const timeout = command.timeout ?? this.config.defaultTimeoutMs;
    const timeoutAt = new Date(Date.now() + timeout);

    const created = await this.prisma.fleetCommand.create({
      data: {
        sensorId,
        commandType: command.type,
        payload: command.payload as Prisma.InputJsonValue,
        status: 'pending',
        timeoutAt,
        attempts: 0,
      },
    });

    // Emit command-sent event
    this.emit('command-sent', {
      commandId: created.id,
      sensorId,
      commandType: command.type,
    });

    // In a real implementation, you would send the command via WebSocket here
    // For now, we'll mark it as sent immediately
    await this.markCommandSent(created.id);

    return created.id;
  }

  /**
   * Send a command to multiple sensors
   * Returns array of command IDs
   */
  async sendCommandToMultiple(sensorIds: string[], command: SensorCommand): Promise<string[]> {
    this.logger.info({ sensorCount: sensorIds.length, commandType: command.type }, 'Sending command to multiple sensors');

    const commandIds: string[] = [];

    for (const sensorId of sensorIds) {
      const commandId = await this.sendCommand(sensorId, command);
      commandIds.push(commandId);
    }

    return commandIds;
  }

  /**
   * Broadcast a command to all connected sensors
   */
  async broadcastCommand(command: SensorCommand): Promise<string[]> {
    const sensors = await this.prisma.sensor.findMany({
      where: {
        connectionState: 'CONNECTED',
      },
      select: { id: true },
    });

    const sensorIds = sensors.map((s) => s.id);
    return this.sendCommandToMultiple(sensorIds, command);
  }

  // =============================================================================
  // Track Command Status
  // =============================================================================

  /**
   * Get status of a specific command
   */
  async getCommandStatus(commandId: string): Promise<CommandStatus | null> {
    const command = await this.prisma.fleetCommand.findUnique({
      where: { id: commandId },
    });

    if (!command) {
      return null;
    }

    return this.mapCommandStatus(command);
  }

  /**
   * Get all pending commands for a sensor
   */
  async getPendingCommands(sensorId: string): Promise<Command[]> {
    const commands = await this.prisma.fleetCommand.findMany({
      where: {
        sensorId,
        status: { in: ['pending', 'sent'] },
      },
      orderBy: { queuedAt: 'asc' },
    });

    return commands.map((c) => this.mapCommand(c));
  }

  /**
   * Cancel a pending command
   */
  async cancelCommand(commandId: string): Promise<boolean> {
    try {
      const command = await this.prisma.fleetCommand.findUnique({
        where: { id: commandId },
      });

      if (!command || !['pending', 'sent'].includes(command.status)) {
        return false;
      }

      await this.prisma.fleetCommand.update({
        where: { id: commandId },
        data: {
          status: 'failed',
          error: 'Cancelled by user',
          completedAt: new Date(),
        },
      });

      this.logger.info({ commandId }, 'Command cancelled');
      return true;
    } catch (error) {
      this.logger.error({ error, commandId }, 'Failed to cancel command');
      return false;
    }
  }

  /**
   * Get command history for a sensor
   */
  async getCommandHistory(sensorId: string, limit = 50): Promise<Command[]> {
    const commands = await this.prisma.fleetCommand.findMany({
      where: { sensorId },
      orderBy: { queuedAt: 'desc' },
      take: limit,
    });

    return commands.map((c) => this.mapCommand(c));
  }

  // =============================================================================
  // Update Command Status (called by WebSocket handler)
  // =============================================================================

  /**
   * Mark command as sent
   */
  async markCommandSent(commandId: string): Promise<void> {
    await this.prisma.fleetCommand.update({
      where: { id: commandId },
      data: {
        status: 'sent',
        sentAt: new Date(),
        attempts: { increment: 1 },
      },
    });
  }

  /**
   * Mark command as successful
   */
  async markCommandSuccess(commandId: string, result?: Record<string, unknown>): Promise<void> {
    const command = await this.prisma.fleetCommand.update({
      where: { id: commandId },
      data: {
        status: 'success',
        result: result as Prisma.InputJsonValue | undefined,
        completedAt: new Date(),
      },
    });

    this.logger.info({ commandId, sensorId: command.sensorId }, 'Command succeeded');

    this.emit('command-success', {
      commandId,
      sensorId: command.sensorId,
      commandType: command.commandType,
      result,
    });
  }

  /**
   * Mark command as failed
   */
  async markCommandFailed(commandId: string, error: string): Promise<void> {
    const command = await this.prisma.fleetCommand.findUnique({
      where: { id: commandId },
    });

    if (!command) {
      return;
    }

    // Check if we should retry
    if (command.attempts < this.config.maxRetries) {
      this.logger.warn(
        { commandId, sensorId: command.sensorId, attempts: command.attempts },
        'Command failed, will retry'
      );

      // Reset to pending for retry
      await this.prisma.fleetCommand.update({
        where: { id: commandId },
        data: {
          status: 'pending',
          error,
        },
      });

      return;
    }

    // Max retries reached, mark as permanently failed
    await this.prisma.fleetCommand.update({
      where: { id: commandId },
      data: {
        status: 'failed',
        error,
        completedAt: new Date(),
      },
    });

    this.logger.error({ commandId, sensorId: command.sensorId, error }, 'Command failed permanently');

    this.emit('command-failed', {
      commandId,
      sensorId: command.sensorId,
      commandType: command.commandType,
      error,
    });
  }

  // =============================================================================
  // Timeout Management
  // =============================================================================

  /**
   * Start periodic timeout checker
   */
  private startTimeoutChecker(): void {
    this.timeoutCheckInterval = setInterval(() => {
      void this.checkTimeouts();
    }, this.config.timeoutCheckIntervalMs);
  }

  /**
   * Check for timed out commands and mark them as failed
   */
  private async checkTimeouts(): Promise<void> {
    try {
      const now = new Date();

      const timedOutCommands = await this.prisma.fleetCommand.findMany({
        where: {
          status: { in: ['pending', 'sent'] },
          timeoutAt: { lte: now },
        },
      });

      for (const command of timedOutCommands) {
        this.logger.warn(
          { commandId: command.id, sensorId: command.sensorId },
          'Command timed out'
        );

        await this.prisma.fleetCommand.update({
          where: { id: command.id },
          data: {
            status: 'timeout',
            error: 'Command timed out',
            completedAt: new Date(),
          },
        });

        this.emit('command-timeout', {
          commandId: command.id,
          sensorId: command.sensorId,
          commandType: command.commandType,
        });
      }

      if (timedOutCommands.length > 0) {
        this.logger.info({ count: timedOutCommands.length }, 'Marked timed out commands');
      }
    } catch (error) {
      this.logger.error({ error }, 'Error checking command timeouts');
    }
  }

  // =============================================================================
  // Cleanup
  // =============================================================================

  /**
   * Clean up old completed commands
   * Removes commands older than retentionDays
   */
  async cleanupOldCommands(retentionDays = 30): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await this.prisma.fleetCommand.deleteMany({
      where: {
        status: { in: ['success', 'failed', 'timeout'] },
        completedAt: { lte: cutoffDate },
      },
    });

    this.logger.info({ deletedCount: result.count }, 'Cleaned up old commands');
    return result.count;
  }

  /**
   * Stop the commander and cleanup resources
   */
  stop(): void {
    if (this.timeoutCheckInterval) {
      clearInterval(this.timeoutCheckInterval);
      this.timeoutCheckInterval = null;
    }
    this.removeAllListeners();
    this.logger.info('Fleet commander stopped');
  }

  // =============================================================================
  // Private Helpers
  // =============================================================================

  private mapCommandStatus(command: {
    id: string;
    sensorId: string;
    status: string;
    result: unknown;
    error: string | null;
    queuedAt: Date;
    sentAt: Date | null;
    completedAt: Date | null;
    attempts: number;
  }): CommandStatus {
    return {
      commandId: command.id,
      sensorId: command.sensorId,
      status: command.status as CommandStatus['status'],
      result: command.result as Record<string, unknown> | undefined,
      error: command.error ?? undefined,
      queuedAt: command.queuedAt,
      sentAt: command.sentAt ?? undefined,
      completedAt: command.completedAt ?? undefined,
      attempts: command.attempts,
    };
  }

  private mapCommand(command: {
    id: string;
    sensorId: string;
    commandType: string;
    payload: unknown;
    status: string;
    result: unknown;
    error: string | null;
    queuedAt: Date;
    sentAt: Date | null;
    completedAt: Date | null;
    attempts: number;
    timeoutAt: Date;
  }): Command {
    return {
      id: command.id,
      sensorId: command.sensorId,
      commandType: command.commandType,
      payload: command.payload as Record<string, unknown>,
      status: command.status,
      result: command.result as Record<string, unknown> | undefined,
      error: command.error ?? undefined,
      queuedAt: command.queuedAt,
      sentAt: command.sentAt ?? undefined,
      completedAt: command.completedAt ?? undefined,
      attempts: command.attempts,
      timeoutAt: command.timeoutAt,
    };
  }
}
