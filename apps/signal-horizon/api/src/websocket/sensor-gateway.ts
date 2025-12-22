/**
 * Sensor Gateway
 * WebSocket server for sensor connections (inbound signals)
 */

import { WebSocketServer, WebSocket } from 'ws';
import type { Server as HTTPServer } from 'node:http';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'node:crypto';
import type { Aggregator } from '../services/aggregator/index.js';
import type { HeartbeatHandler } from '../protocols/heartbeat-handler.js';
import type { CommandSender } from '../protocols/command-sender.js';
import type {
  ThreatSignal,
  BlocklistEntry,
  SensorHeartbeatMessage,
  SensorCommandAckMessage,
} from '../types/protocol.js';
import {
  validateSensorMessage,
  type ValidatedSensorMessage,
} from '../schemas/signal.js';

interface SensorConnection {
  id: string;
  sensorId: string;
  tenantId: string;
  ws: WebSocket;
  connectedAt: number;
  lastHeartbeat: number;
  signalsReceived: number;
  /** Rate limiting: timestamps of recent messages */
  messageTimestamps: number[];
}

interface SensorGatewayConfig {
  path: string;
  heartbeatIntervalMs: number;
  maxConnections: number;
  /** Maximum messages per window (default: 100) */
  rateLimitMessages?: number;
  /** Rate limit window in milliseconds (default: 1000ms) */
  rateLimitWindowMs?: number;
}

/**
 * Simple sliding window rate limiter
 * Tracks message timestamps and rejects if too many in window
 */
class RateLimiter {
  private windowMs: number;
  private maxMessages: number;

  constructor(windowMs: number, maxMessages: number) {
    this.windowMs = windowMs;
    this.maxMessages = maxMessages;
  }

  /**
   * Check if message should be allowed and update timestamps
   * @returns true if allowed, false if rate limited
   */
  checkAndUpdate(timestamps: number[]): boolean {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    // Remove timestamps outside the window (mutates array in place for efficiency)
    while (timestamps.length > 0 && timestamps[0] < windowStart) {
      timestamps.shift();
    }

    // Check if we're at the limit
    if (timestamps.length >= this.maxMessages) {
      return false;
    }

    // Add current timestamp
    timestamps.push(now);
    return true;
  }
}

// Local type aliases for Zod-validated payloads
// Full validation schemas are in ../schemas/signal.ts
interface SensorAuthPayload {
  apiKey: string;
  sensorId: string;
  sensorName?: string;
  version: string;
}

export class SensorGateway {
  private wss: WebSocketServer | null = null;
  private connections: Map<string, SensorConnection> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private prisma: PrismaClient;
  private logger: Logger;
  private aggregator: Aggregator;
  private config: SensorGatewayConfig;
  private sequenceId = 0;
  private rateLimiter: RateLimiter;
  private heartbeatHandler: HeartbeatHandler | null = null;
  private commandSender: CommandSender | null = null;

  constructor(
    httpServer: HTTPServer,
    prisma: PrismaClient,
    logger: Logger,
    aggregator: Aggregator,
    config: SensorGatewayConfig
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ gateway: 'sensor' });
    this.aggregator = aggregator;
    this.config = config;

    // Initialize rate limiter with defaults or config values
    this.rateLimiter = new RateLimiter(
      config.rateLimitWindowMs ?? 1000,  // 1 second window
      config.rateLimitMessages ?? 100     // 100 messages per second max
    );

    this.wss = new WebSocketServer({
      server: httpServer,
      path: config.path,
    });
  }

  /**
   * Wire protocol handlers for fleet management operations
   * Called after protocol handler services are initialized
   */
  setProtocolHandlers(
    heartbeatHandler: HeartbeatHandler,
    commandSender: CommandSender
  ): void {
    this.heartbeatHandler = heartbeatHandler;
    this.commandSender = commandSender;
    this.logger.info('Protocol handlers wired to sensor gateway');
  }

  start(): void {
    if (!this.wss) return;

    this.wss.on('connection', (ws, req) => {
      this.handleConnection(ws, req);
    });

    this.wss.on('error', (error) => {
      this.logger.error({ error }, 'Sensor gateway error');
    });

    this.startHeartbeat();
    this.logger.info({ path: this.config.path }, 'Sensor gateway started');
  }

  stop(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    for (const conn of this.connections.values()) {
      conn.ws.close(1000, 'Server shutting down');
    }
    this.connections.clear();

    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }

    this.logger.info('Sensor gateway stopped');
  }

  private handleConnection(ws: WebSocket, req: unknown): void {
    if (this.connections.size >= this.config.maxConnections) {
      ws.close(1013, 'Max connections reached');
      return;
    }

    const connectionId = randomUUID();
    const tempConnection: SensorConnection = {
      id: connectionId,
      sensorId: '', // Set after auth
      tenantId: '', // Set after auth
      ws,
      connectedAt: Date.now(),
      lastHeartbeat: Date.now(),
      signalsReceived: 0,
      messageTimestamps: [], // For rate limiting
    };

    // Temporarily store pending connection
    this.connections.set(connectionId, tempConnection);

    // Extract IP from request if available
    const remoteAddress = (req as { socket?: { remoteAddress?: string } })?.socket?.remoteAddress;
    this.logger.info(
      { connectionId, ip: remoteAddress },
      'Sensor connecting (pending auth)'
    );

    // Set auth timeout
    const authTimeout = setTimeout(() => {
      if (!tempConnection.sensorId) {
        this.logger.warn({ connectionId }, 'Sensor auth timeout');
        ws.close(4001, 'Auth timeout');
        this.connections.delete(connectionId);
      }
    }, 10000);

    ws.on('message', async (data) => {
      try {
        // Rate limiting check - get connection from map to access messageTimestamps
        const conn = this.connections.get(connectionId);
        if (conn && !this.rateLimiter.checkAndUpdate(conn.messageTimestamps)) {
          this.logger.warn({ connectionId }, 'Rate limit exceeded');
          this.send(conn, {
            type: 'error',
            error: 'Rate limit exceeded. Please reduce message frequency.',
          });
          return;
        }

        const parsed = JSON.parse(data.toString());
        const validation = validateSensorMessage(parsed);

        if (!validation.success) {
          this.logger.warn(
            { connectionId, errors: validation.errors },
            'Invalid sensor message payload'
          );
          this.send(tempConnection, {
            type: 'error',
            error: `Invalid message: ${validation.errors.join(', ')}`,
          });
          return;
        }

        await this.handleMessage(connectionId, validation.data, authTimeout);
      } catch (error) {
        this.logger.error({ error, connectionId }, 'Failed to parse sensor message');
        this.send(tempConnection, { type: 'error', error: 'Invalid JSON' });
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      const conn = this.connections.get(connectionId);
      if (conn?.sensorId) {
        this.updateSensorStatus(conn.sensorId, 'DISCONNECTED');
      }
      this.connections.delete(connectionId);
      this.logger.info({ connectionId }, 'Sensor disconnected');
    });

    ws.on('error', (error) => {
      this.logger.error({ error, connectionId }, 'Sensor connection error');
      clearTimeout(authTimeout);
      this.connections.delete(connectionId);
    });
  }

  private async handleMessage(
    connectionId: string,
    message: ValidatedSensorMessage,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    const conn = this.connections.get(connectionId);
    if (!conn) return;

    switch (message.type) {
      case 'auth':
        await this.handleAuth(conn, message.payload, authTimeout);
        break;

      case 'signal':
        if (!conn.sensorId) {
          this.send(conn, { type: 'error', error: 'Not authenticated' });
          return;
        }
        await this.handleSignal(conn, message.payload);
        break;

      case 'signal-batch':
        if (!conn.sensorId) {
          this.send(conn, { type: 'error', error: 'Not authenticated' });
          return;
        }
        await this.handleSignalBatch(conn, message.payload);
        break;

      case 'pong':
        conn.lastHeartbeat = Date.now();
        break;

      case 'blocklist-sync':
        if (!conn.sensorId) return;
        await this.handleBlocklistSync(conn);
        break;

      case 'heartbeat':
        if (!conn.sensorId) {
          this.send(conn, { type: 'error', error: 'Not authenticated' });
          return;
        }
        await this.handleHeartbeat(conn, message.payload as SensorHeartbeatMessage['payload']);
        break;

      case 'command-ack':
        if (!conn.sensorId) {
          this.send(conn, { type: 'error', error: 'Not authenticated' });
          return;
        }
        await this.handleCommandAck(conn, message.payload as SensorCommandAckMessage['payload']);
        break;
    }
  }

  private async handleAuth(
    conn: SensorConnection,
    payload: SensorAuthPayload,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    const { apiKey, sensorId, sensorName, version } = payload;

    try {
      // Validate API key
      const keyHash = await this.hashApiKey(apiKey);
      const apiKeyRecord = await this.prisma.apiKey.findUnique({
        where: { keyHash },
        include: { tenant: true },
      });

      if (!apiKeyRecord || apiKeyRecord.isRevoked) {
        this.send(conn, { type: 'auth-failed', error: 'Invalid API key' });
        conn.ws.close(4003, 'Invalid API key');
        return;
      }

      // Check scopes
      if (!apiKeyRecord.scopes.includes('signal:write')) {
        this.send(conn, { type: 'auth-failed', error: 'Insufficient permissions' });
        conn.ws.close(4003, 'Insufficient permissions');
        return;
      }

      clearTimeout(authTimeout);

      // Register/update sensor
      const sensor = await this.prisma.sensor.upsert({
        where: {
          tenantId_name: {
            tenantId: apiKeyRecord.tenantId,
            name: sensorName || sensorId,
          },
        },
        create: {
          tenantId: apiKeyRecord.tenantId,
          name: sensorName || sensorId,
          version,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(),
        },
        update: {
          version,
          connectionState: 'CONNECTED',
          lastHeartbeat: new Date(),
        },
      });

      // Update connection with auth info
      conn.sensorId = sensor.id;
      conn.tenantId = apiKeyRecord.tenantId;

      // Update API key last used
      await this.prisma.apiKey.update({
        where: { id: apiKeyRecord.id },
        data: { lastUsedAt: new Date() },
      });

      this.send(conn, {
        type: 'auth-success',
        sensorId: sensor.id,
        tenantId: apiKeyRecord.tenantId,
        capabilities: ['signal', 'blocklist-sync'],
      });

      this.logger.info(
        { sensorId: sensor.id, tenantId: apiKeyRecord.tenantId },
        'Sensor authenticated'
      );
    } catch (error) {
      this.logger.error({ error }, 'Sensor auth failed');
      this.send(conn, { type: 'auth-failed', error: 'Auth error' });
    }
  }

  private async handleSignal(conn: SensorConnection, signal: ThreatSignal): Promise<void> {
    conn.signalsReceived++;

    await this.aggregator.queueSignal({
      ...signal,
      tenantId: conn.tenantId,
      sensorId: conn.sensorId,
    });

    // Acknowledge receipt
    this.send(conn, { type: 'signal-ack', sequenceId: this.nextSequenceId() });
  }

  private async handleSignalBatch(conn: SensorConnection, signals: ThreatSignal[]): Promise<void> {
    conn.signalsReceived += signals.length;

    for (const signal of signals) {
      await this.aggregator.queueSignal({
        ...signal,
        tenantId: conn.tenantId,
        sensorId: conn.sensorId,
      });
    }

    this.send(conn, {
      type: 'batch-ack',
      count: signals.length,
      sequenceId: this.nextSequenceId(),
    });
  }

  private async handleBlocklistSync(conn: SensorConnection): Promise<void> {
    // Fetch blocklist entries for this tenant + fleet-wide blocks
    const entries = await this.prisma.blocklistEntry.findMany({
      where: {
        OR: [{ tenantId: conn.tenantId }, { tenantId: null }],
        propagationStatus: { not: 'FAILED' },
      },
      select: {
        blockType: true,
        indicator: true,
        expiresAt: true,
        source: true,
      },
    });

    this.send(conn, {
      type: 'blocklist-snapshot',
      entries: entries as BlocklistEntry[],
      sequenceId: this.nextSequenceId(),
    });
  }

  private async handleHeartbeat(
    conn: SensorConnection,
    payload: SensorHeartbeatMessage['payload']
  ): Promise<void> {
    try {
      // Update connection heartbeat timestamp
      conn.lastHeartbeat = Date.now();

      // Route heartbeat to HeartbeatHandler if wired
      if (this.heartbeatHandler) {
        await this.heartbeatHandler.handleHeartbeat(
          conn.sensorId,
          conn.tenantId,
          payload
        );
      }

      // Update sensor's last heartbeat in database
      await this.prisma.sensor.update({
        where: { id: conn.sensorId },
        data: {
          lastHeartbeat: new Date(),
          metadata: {
            cpu: payload.cpu,
            memory: payload.memory,
            disk: payload.disk,
            requestsLastMinute: payload.requestsLastMinute,
            avgLatencyMs: payload.avgLatencyMs,
            status: payload.status,
          },
        },
      });

      this.logger.debug(
        { sensorId: conn.sensorId, cpu: payload.cpu, memory: payload.memory },
        'Sensor heartbeat received'
      );
    } catch (error) {
      this.logger.error(
        { error, sensorId: conn.sensorId },
        'Failed to handle heartbeat'
      );
    }
  }

  private async handleCommandAck(
    conn: SensorConnection,
    payload: SensorCommandAckMessage['payload']
  ): Promise<void> {
    try {
      const { commandId, success, message: resultMessage, result } = payload;

      // Route command acknowledgment to CommandSender if wired
      if (this.commandSender) {
        await this.commandSender.handleCommandAck(
          commandId,
          conn.sensorId,
          success,
          resultMessage,
          result
        );
      }

      // Update command status in database
      await this.prisma.fleetCommand.update({
        where: { id: commandId },
        data: {
          status: success ? 'success' : 'failed',
          completedAt: new Date(),
          error: success ? undefined : resultMessage,
          result: success ? result : undefined,
          attempts: { increment: 1 },
        },
      });

      this.logger.info(
        { commandId, sensorId: conn.sensorId, success },
        'Command acknowledgment received'
      );
    } catch (error) {
      this.logger.error(
        { error, commandId: payload.commandId },
        'Failed to handle command acknowledgment'
      );
    }
  }

  private async updateSensorStatus(
    sensorId: string,
    status: 'CONNECTED' | 'DISCONNECTED' | 'RECONNECTING'
  ): Promise<void> {
    try {
      await this.prisma.sensor.update({
        where: { id: sensorId },
        data: { connectionState: status },
      });
    } catch (error) {
      this.logger.error({ error, sensorId }, 'Failed to update sensor status');
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();
      const staleThreshold = this.config.heartbeatIntervalMs * 2;

      for (const [id, conn] of this.connections) {
        if (now - conn.lastHeartbeat > staleThreshold) {
          this.logger.warn({ connectionId: id }, 'Removing stale sensor connection');
          conn.ws.close(1000, 'Heartbeat timeout');
          this.connections.delete(id);
          if (conn.sensorId) {
            this.updateSensorStatus(conn.sensorId, 'DISCONNECTED');
          }
          continue;
        }

        if (conn.sensorId) {
          this.send(conn, { type: 'ping', timestamp: now });
        }
      }
    }, this.config.heartbeatIntervalMs);
  }

  private send(conn: SensorConnection, message: Record<string, unknown>): void {
    if (conn.ws.readyState === WebSocket.OPEN) {
      conn.ws.send(JSON.stringify(message));
    }
  }

  private nextSequenceId(): number {
    this.sequenceId = (this.sequenceId + 1) % Number.MAX_SAFE_INTEGER;
    return this.sequenceId;
  }

  private async hashApiKey(apiKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(apiKey);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  getConnectionCount(): number {
    return this.connections.size;
  }

  getConnectedSensors(): { id: string; tenantId: string; signalsReceived: number }[] {
    return Array.from(this.connections.values())
      .filter((c) => c.sensorId)
      .map((c) => ({
        id: c.sensorId,
        tenantId: c.tenantId,
        signalsReceived: c.signalsReceived,
      }));
  }
}
