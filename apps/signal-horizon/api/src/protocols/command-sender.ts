/**
 * CommandSender manages reliable command delivery to sensors.
 * Queues commands when sensors are offline, retries on failure.
 *
 * Implements global and per-sensor queue limits to prevent memory
 * exhaustion when sensors are offline for extended periods.
 */

import { EventEmitter } from 'events';
import type WebSocket from 'ws';

export type CommandType = 'push_config' | 'push_rules' | 'restart' | 'collect_diagnostics' | 'update' | 'toggle_chaos' | 'toggle_mtd';
export type CommandStatus = 'pending' | 'sent' | 'success' | 'failed' | 'timeout';

/** Configuration for command queue limits */
export interface CommandSenderConfig {
  /** Maximum total commands across all sensors (default: 10000) */
  maxQueueSize: number;
  /** Maximum pending commands per sensor (default: 100) */
  maxPerSensorQueueSize: number;
  /** TTL for pending commands in ms before auto-eviction (default: 1 hour) */
  pendingTTL: number;
}

export const DEFAULT_CONFIG: CommandSenderConfig = {
  maxQueueSize: 10000,
  maxPerSensorQueueSize: 100,
  pendingTTL: 3600000, // 1 hour
};

export interface Command {
  id: string;
  type: CommandType;
  sensorId: string;
  payload: unknown;
  status: CommandStatus;
  createdAt: number;
  sentAt?: number;
  completedAt?: number;
  attempts: number;
  maxAttempts: number;
  timeoutMs: number;
  error?: string;
}

export class CommandSender extends EventEmitter {
  private logger = console;
  private commands = new Map<string, Command>();
  private sensorConnections = new Map<string, WebSocket>();
  private sensorQueues = new Map<string, string[]>();
  private inflightCommands = new Map<string, string>();
  private timeoutHandles = new Map<string, NodeJS.Timeout>();
  private cleanupInterval: NodeJS.Timeout | null = null;
  private config: CommandSenderConfig;
  private droppedCommands = 0;
  private evictedCommands = 0;

  constructor(config: Partial<CommandSenderConfig> = {}) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  start(): void {
    if (this.cleanupInterval) return;
    this.cleanupInterval = setInterval(() => this.cleanupOldCommands(), 60000);
  }

  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    for (const handle of this.timeoutHandles.values()) {
      clearTimeout(handle);
    }
    this.timeoutHandles.clear();
    this.sensorQueues.clear();
    this.inflightCommands.clear();
  }

  registerConnection(sensorId: string, ws: WebSocket): void {
    this.sensorConnections.set(sensorId, ws);
    this.flushPendingCommands(sensorId);
  }

  unregisterConnection(sensorId: string): void {
    this.sensorConnections.delete(sensorId);
  }

  /**
   * Send a command to a sensor.
   * Returns the command ID on success, or null if the command was dropped
   * due to queue limits being exceeded.
   */
  sendCommand(sensorId: string, type: CommandType, payload: unknown, customId?: string): string | null {
    const id = customId ?? `cmd-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    // Check per-sensor limit
    const sensorPending = this.getPendingCommands(sensorId);
    if (sensorPending.length >= this.config.maxPerSensorQueueSize) {
      // Try to evict oldest pending command for this sensor
      const evicted = this.evictOldestPending(sensorId);
      if (!evicted) {
        this.droppedCommands++;
        this.emit('command-dropped', { sensorId, type, reason: 'per_sensor_limit' });
        return null;
      }
    }

    // Check global limit
    if (this.commands.size >= this.config.maxQueueSize) {
      // Try to evict oldest pending command globally
      const evicted = this.evictOldestPendingGlobal();
      if (!evicted) {
        this.droppedCommands++;
        this.emit('command-dropped', { sensorId, type, reason: 'global_limit' });
        return null;
      }
    }

    const command: Command = {
      id,
      type,
      sensorId,
      payload,
      status: 'pending',
      createdAt: Date.now(),
      attempts: 0,
      maxAttempts: this.getMaxAttempts(type),
      timeoutMs: this.getTimeout(type),
    };

    this.commands.set(id, command);
    this.enqueueCommand(command);
    this.trySendNext(sensorId);
    return id;
  }

  /**
   * Evict the oldest pending command for a specific sensor.
   * Returns true if a command was evicted.
   */
  private evictOldestPending(sensorId: string): boolean {
    let oldest: Command | null = null;
    for (const cmd of this.commands.values()) {
      if (cmd.sensorId === sensorId && cmd.status === 'pending') {
        if (!oldest || cmd.createdAt < oldest.createdAt) {
          oldest = cmd;
        }
      }
    }
    if (oldest) {
      this.commands.delete(oldest.id);
      this.removeFromQueue(sensorId, oldest.id);
      this.evictedCommands++;
      this.emit('command-evicted', oldest);
      return true;
    }
    return false;
  }

  /**
   * Evict the oldest pending command globally.
   * Returns true if a command was evicted.
   */
  private evictOldestPendingGlobal(): boolean {
    let oldest: Command | null = null;
    for (const cmd of this.commands.values()) {
      if (cmd.status === 'pending') {
        if (!oldest || cmd.createdAt < oldest.createdAt) {
          oldest = cmd;
        }
      }
    }
    if (oldest) {
      this.commands.delete(oldest.id);
      this.removeFromQueue(oldest.sensorId, oldest.id);
      this.evictedCommands++;
      this.emit('command-evicted', oldest);
      return true;
    }
    return false;
  }

  private getSensorQueue(sensorId: string): string[] {
    const existing = this.sensorQueues.get(sensorId);
    if (existing) {
      return existing;
    }
    const queue: string[] = [];
    this.sensorQueues.set(sensorId, queue);
    return queue;
  }

  private enqueueCommand(cmd: Command): void {
    const queue = this.getSensorQueue(cmd.sensorId);
    queue.push(cmd.id);
  }

  private removeFromQueue(sensorId: string, commandId: string): void {
    const queue = this.sensorQueues.get(sensorId);
    if (!queue) return;
    const index = queue.indexOf(commandId);
    if (index >= 0) {
      queue.splice(index, 1);
    }
    if (queue.length === 0) {
      this.sensorQueues.delete(sensorId);
    }
  }

  private trySendNext(sensorId: string): void {
    if (this.inflightCommands.has(sensorId)) return;
    const queue = this.sensorQueues.get(sensorId);
    if (!queue || queue.length === 0) return;

    const nextId = queue[0];
    const cmd = this.commands.get(nextId);
    if (!cmd) {
      queue.shift();
      this.trySendNext(sensorId);
      return;
    }

    if (cmd.status !== 'pending') {
      queue.shift();
      this.trySendNext(sensorId);
      return;
    }

    this.trySendCommand(cmd);
  }

  handleResponse(commandId: string, success: boolean, error?: string): void {
    const cmd = this.commands.get(commandId);
    if (!cmd) return;

    if (['success', 'failed', 'timeout'].includes(cmd.status)) return;

    const status = success ? 'success' : 'failed';
    this.finalizeCommand(cmd, status, error);
    this.emit(success ? 'command-complete' : 'command-failed', cmd);
  }

  private trySendCommand(cmd: Command): void {
    const ws = this.sensorConnections.get(cmd.sensorId);
    if (!ws || ws.readyState !== 1) return; // WebSocket.OPEN = 1

    const inflight = this.inflightCommands.get(cmd.sensorId);
    if (inflight && inflight !== cmd.id) return;
    if (['success', 'failed', 'timeout'].includes(cmd.status)) return;

    // Keep per-sensor queues pending-only by removing inflight entries on send.
    this.removeFromQueue(cmd.sensorId, cmd.id);

    this.inflightCommands.set(cmd.sensorId, cmd.id);
    cmd.attempts++;
    cmd.sentAt = Date.now();
    cmd.status = 'sent';

    try {
      ws.send(JSON.stringify({
        type: cmd.type,
        commandId: cmd.id,
        payload: cmd.payload,
      }));
    } catch (error) {
      this.logger.error({ error, commandId: cmd.id }, 'WebSocket send failed');
      this.finalizeCommand(cmd, 'failed', 'WebSocket send failed');
      return;
    }

    this.setCommandTimeout(cmd);
    this.emit('command-sent', cmd);
  }

  private setCommandTimeout(cmd: Command): void {
    this.clearCommandTimeout(cmd.id);
    const handle = setTimeout(() => {
      if (cmd.status !== 'sent') return;

      const ws = this.sensorConnections.get(cmd.sensorId);
      const wsReady = !!ws && ws.readyState === 1;
      if (!wsReady) {
        this.clearCommandTimeout(cmd.id);
        this.setCommandTimeout(cmd);
        return;
      }

      if (cmd.attempts < cmd.maxAttempts) {
        this.clearCommandTimeout(cmd.id);
        this.trySendCommand(cmd);
        return;
      }

      this.finalizeCommand(cmd, 'timeout', `Timed out after ${cmd.maxAttempts} attempts`);
      this.emit('command-timeout', cmd);
    }, cmd.timeoutMs);

    this.timeoutHandles.set(cmd.id, handle);
  }

  private clearCommandTimeout(cmdId: string): void {
    const handle = this.timeoutHandles.get(cmdId);
    if (handle) {
      clearTimeout(handle);
      this.timeoutHandles.delete(cmdId);
    }
  }

  private finalizeCommand(cmd: Command, status: CommandStatus, error?: string): void {
    this.clearCommandTimeout(cmd.id);
    cmd.completedAt = Date.now();
    cmd.status = status;
    if (error) cmd.error = error;
    this.removeFromQueue(cmd.sensorId, cmd.id);
    if (this.inflightCommands.get(cmd.sensorId) === cmd.id) {
      this.inflightCommands.delete(cmd.sensorId);
    }
    this.trySendNext(cmd.sensorId);
  }

  private getTimeout(type: CommandType): number {
    const timeouts: Record<CommandType, number> = {
      restart: 60000,
      collect_diagnostics: 120000,
      push_config: 30000,
      push_rules: 30000,
      update: 300000, // 5 minutes for download/install
      toggle_chaos: 10000,
      toggle_mtd: 10000,
    };
    return timeouts[type];
  }

  private getMaxAttempts(type: CommandType): number {
    return type === 'restart' || type === 'collect_diagnostics' ? 2 : 3;
  }

  private flushPendingCommands(sensorId: string): void {
    const inflightId = this.inflightCommands.get(sensorId);

    const pending = Array.from(this.commands.values())
      .filter((cmd) => cmd.sensorId === sensorId && cmd.status === 'pending')
      .sort((a, b) => a.createdAt - b.createdAt);

    if (pending.length > 0) {
      this.sensorQueues.set(sensorId, pending.map((cmd) => cmd.id));
    } else {
      this.sensorQueues.delete(sensorId);
    }

    if (inflightId) {
      const inflightCmd = this.commands.get(inflightId);
      if (
        inflightCmd
        && inflightCmd.sensorId === sensorId
        && (inflightCmd.status === 'sent' || inflightCmd.status === 'pending')
        && inflightCmd.attempts < inflightCmd.maxAttempts
      ) {
        this.trySendCommand(inflightCmd);
      }
    }

    this.trySendNext(sensorId);
  }

  private cleanupOldCommands(): void {
    const now = Date.now();
    const completedTTL = 300000; // 5 minutes for completed commands

    for (const [id, cmd] of this.commands) {
      // Clean up completed commands after TTL
      if (['success', 'failed', 'timeout'].includes(cmd.status) && cmd.completedAt) {
        if (now - cmd.completedAt > completedTTL) {
          this.commands.delete(id);
          this.removeFromQueue(cmd.sensorId, id);
          if (this.inflightCommands.get(cmd.sensorId) === id) {
            this.inflightCommands.delete(cmd.sensorId);
          }
        }
      }
      // Evict pending commands that have exceeded pendingTTL
      else if (cmd.status === 'pending') {
        if (now - cmd.createdAt > this.config.pendingTTL) {
          this.commands.delete(id);
          this.removeFromQueue(cmd.sensorId, id);
          this.evictedCommands++;
          this.emit('command-evicted', { ...cmd, reason: 'ttl_expired' });
        }
      }
    }
  }

  getCommand(id: string): Command | undefined {
    return this.commands.get(id);
  }

  getPendingCommands(sensorId: string): Command[] {
    const queue = this.sensorQueues.get(sensorId);
    if (!queue || queue.length === 0) {
      return Array.from(this.commands.values()).filter(
        (c) => c.sensorId === sensorId && c.status === 'pending'
      );
    }

    return queue
      .map((id) => this.commands.get(id))
      .filter((cmd): cmd is Command => !!cmd && cmd.status === 'pending');
  }

  getStats(): {
    total: number;
    pending: number;
    sent: number;
    success: number;
    failed: number;
    timeout: number;
    dropped: number;
    evicted: number;
    queueCapacity: number;
    queueUtilization: number;
  } {
    const commands = Array.from(this.commands.values());
    const total = commands.length;
    return {
      total,
      pending: commands.filter((c) => c.status === 'pending').length,
      sent: commands.filter((c) => c.status === 'sent').length,
      success: commands.filter((c) => c.status === 'success').length,
      failed: commands.filter((c) => c.status === 'failed').length,
      timeout: commands.filter((c) => c.status === 'timeout').length,
      dropped: this.droppedCommands,
      evicted: this.evictedCommands,
      queueCapacity: this.config.maxQueueSize,
      queueUtilization: total / this.config.maxQueueSize,
    };
  }

  /** Get per-sensor queue statistics */
  getSensorStats(sensorId: string): {
    total: number;
    pending: number;
    capacity: number;
    utilization: number;
  } {
    const commands = Array.from(this.commands.values()).filter(
      (c) => c.sensorId === sensorId
    );
    const pending = commands.filter((c) => c.status === 'pending').length;
    return {
      total: commands.length,
      pending,
      capacity: this.config.maxPerSensorQueueSize,
      utilization: pending / this.config.maxPerSensorQueueSize,
    };
  }

  /** Get the current configuration */
  getConfig(): CommandSenderConfig {
    return { ...this.config };
  }

  cancelCommand(commandId: string): boolean {
    const cmd = this.commands.get(commandId);
    if (!cmd || cmd.status !== 'pending') return false;

    this.finalizeCommand(cmd, 'failed', 'Cancelled');
    this.emit('command-failed', cmd);
    return true;
  }

  clear(): void {
    for (const handle of this.timeoutHandles.values()) {
      clearTimeout(handle);
    }
    this.timeoutHandles.clear();
    this.commands.clear();
    this.sensorQueues.clear();
    this.inflightCommands.clear();
  }

  /** Reset statistics (for testing) */
  resetStats(): void {
    this.droppedCommands = 0;
    this.evictedCommands = 0;
  }
}
