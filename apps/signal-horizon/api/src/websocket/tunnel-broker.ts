/**
 * Tunnel Broker
 *
 * Channel multiplexing and routing for remote sensor management.
 * Manages tunnel sessions, routes messages to appropriate handlers,
 * and provides session lifecycle management with rate limiting.
 *
 * This is the Phase 0A implementation of the Tunnel Protocol Extension,
 * providing support for:
 * - Shell: Remote terminal access with PTY support
 * - Logs: Real-time log streaming with filtering
 * - Diag: Diagnostics collection (health, memory, connections, rules, actors)
 * - Control: Service control operations (reload, restart, shutdown, drain, resume)
 * - Files: Secure file transfer and browsing
 *
 * Security Features:
 * 1. Per-session authentication and authorization
 * 2. Channel-specific rate limiting (messages/sec, bytes/sec)
 * 3. Maximum concurrent sessions per sensor
 * 4. Session timeout and cleanup
 * 5. Audit logging for all operations
 *
 * @module tunnel-broker
 */

import { WebSocket } from 'ws';
import { EventEmitter } from 'node:events';
import { randomUUID } from 'node:crypto';
import type { Logger } from 'pino';
import type {
  TunnelChannel,
  TunnelSessionState,
  TunnelMessage,
  TunnelProtocolMessage,
  TunnelSessionInfo,
  ChannelRateLimits,
} from '../types/tunnel.js';
import {
  validateTunnelMessage,
  validateSessionMessage,
  hasValidTunnelStructure,
} from '../schemas/tunnel.js';

// =============================================================================
// Types
// =============================================================================

/**
 * Internal channel session representation.
 */
interface ChannelSession {
  /** Unique session identifier */
  sessionId: string;
  /** Channel type */
  channel: TunnelChannel;
  /** WebSocket connection for the tunnel client */
  clientWs: WebSocket;
  /** WebSocket connection to the sensor (if established) */
  sensorWs: WebSocket | null;
  /** Sensor ID this session connects to */
  sensorId: string;
  /** Tenant ID owning the session */
  tenantId: string;
  /** User ID who opened the session */
  userId: string;
  /** Current session state */
  state: TunnelSessionState;
  /** Session creation timestamp */
  createdAt: number;
  /** Last activity timestamp */
  lastActivityAt: number;
  /** Next expected sequence ID from client */
  clientSequenceId: number;
  /** Next expected sequence ID from sensor */
  sensorSequenceId: number;
  /** Messages sent to sensor */
  messagesSent: number;
  /** Messages received from sensor */
  messagesReceived: number;
  /** Bytes transferred (approximate) */
  bytesTransferred: number;
  /** Rate limiting: message timestamps */
  messageTimestamps: number[];
  /** Rate limiting: bytes in current window */
  bytesInWindow: number;
  /** Rate limit window start */
  windowStart: number;
  /** Cleanup timeout handle */
  cleanupTimeout: NodeJS.Timeout | null;
}

/**
 * Rate limiter for channel-specific throttling.
 */
class ChannelRateLimiter {
  private windowMs = 1000; // 1 second window

  /**
   * Check if a message should be allowed based on rate limits.
   *
   * @param session - The channel session
   * @param limits - Rate limits for the channel
   * @param messageSize - Size of the message in bytes
   * @returns True if allowed, false if rate limited
   */
  checkAndUpdate(
    session: ChannelSession,
    limits: ChannelRateLimits,
    messageSize: number
  ): { allowed: boolean; reason?: string } {
    const now = Date.now();

    // Reset window if expired
    if (now - session.windowStart >= this.windowMs) {
      session.messageTimestamps = [];
      session.bytesInWindow = 0;
      session.windowStart = now;
    }

    // Check message rate
    if (session.messageTimestamps.length >= limits.messagesPerSecond) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${limits.messagesPerSecond} messages/second`,
      };
    }

    // Check byte rate
    if (session.bytesInWindow + messageSize > limits.bytesPerSecond) {
      return {
        allowed: false,
        reason: `Bandwidth limit exceeded: ${limits.bytesPerSecond} bytes/second`,
      };
    }

    // Update counters
    session.messageTimestamps.push(now);
    session.bytesInWindow += messageSize;

    return { allowed: true };
  }
}

/**
 * Handler registration for channel message processing.
 */
interface ChannelHandler {
  channel: TunnelChannel;
  handler: (session: ChannelSession, message: TunnelMessage) => Promise<void>;
}

/**
 * Events emitted by the TunnelBroker.
 */
export interface TunnelBrokerEvents {
  /** Emitted when a new session is created */
  'session-created': (info: TunnelSessionInfo) => void;
  /** Emitted when a session state changes */
  'session-state-changed': (
    sessionId: string,
    oldState: TunnelSessionState,
    newState: TunnelSessionState
  ) => void;
  /** Emitted when a session is closed */
  'session-closed': (
    sessionId: string,
    reason: string,
    stats: { messagesSent: number; messagesReceived: number; bytesTransferred: number }
  ) => void;
  /** Emitted when a message is routed */
  'message-routed': (
    sessionId: string,
    channel: TunnelChannel,
    direction: 'client-to-sensor' | 'sensor-to-client'
  ) => void;
  /** Emitted when rate limiting is triggered */
  'rate-limited': (sessionId: string, channel: TunnelChannel, reason: string) => void;
  /** Emitted on validation errors */
  'validation-error': (sessionId: string, errors: string[]) => void;
  /** @deprecated Legacy: Emitted when a sensor tunnel connects */
  'tunnel:connected': (session: TunnelSession) => void;
  /** @deprecated Legacy: Emitted when a sensor tunnel disconnects */
  'tunnel:disconnected': (sensorId: string, tenantId: string) => void;
  /** @deprecated Legacy: Emitted when a message is received from a sensor */
  'tunnel:message': (sensorId: string, message: LegacyTunnelMessage) => void;
  /** @deprecated Legacy: Emitted when a user session starts */
  'session:started': (session: UserSession) => void;
  /** @deprecated Legacy: Emitted when a user session ends */
  'session:ended': (sessionId: string, reason: string) => void;
}

// =============================================================================
// Legacy Types (Backward Compatibility)
// =============================================================================

/**
 * @deprecated Use TunnelChannel from '../types/tunnel.js' instead
 */
export type TunnelCapability = 'shell' | 'dashboard';

/**
 * @deprecated Use TunnelChannel from '../types/tunnel.js' instead
 */
export type UserSessionType = 'shell' | 'dashboard';

/**
 * @deprecated Use ChannelSession instead
 */
export interface TunnelSession {
  sensorId: string;
  tenantId: string;
  socket: WebSocket;
  capabilities: TunnelCapability[];
  connectedAt: Date;
  lastHeartbeat: Date;
  metadata?: {
    hostname?: string;
    version?: string;
    platform?: string;
  };
}

/**
 * @deprecated Use ChannelSession instead
 */
export interface UserSession {
  sessionId: string;
  userId: string;
  tenantId: string;
  sensorId: string;
  type: UserSessionType;
  socket: WebSocket;
  createdAt: Date;
  lastActivity: Date;
}

/**
 * @deprecated Use TunnelMessage from '../types/tunnel.js' instead
 */
export type TunnelMessageType =
  | 'heartbeat'
  | 'shell-data'
  | 'shell-resize'
  | 'dashboard-request'
  | 'dashboard-response'
  | 'error';

/**
 * @deprecated Use TunnelMessage from '../types/tunnel.js' instead
 */
export interface LegacyTunnelMessage {
  type: TunnelMessageType;
  sessionId?: string;
  requestId?: string;
  payload: unknown;
  timestamp: string;
}

/**
 * Response from a direct sensor request (sendRequest).
 */
export interface TunnelRequestResponse {
  type: string;
  payload: unknown;
  requestId: string;
}

/**
 * Broker statistics for monitoring.
 */
export interface TunnelStats {
  totalTunnels: number;
  activeSessions: number;
  byTenant: Record<string, { tunnels: number; sessions: number }>;
  byType: Record<UserSessionType, number>;
  byChannel: Record<TunnelChannel, number>;
}

// =============================================================================
// TunnelBroker Class
// =============================================================================

/**
 * TunnelBroker manages tunnel sessions and routes messages between
 * dashboard clients and sensors for remote management operations.
 *
 * This class supports both the new channel-based protocol (shell, logs, diag,
 * control, files) and the legacy protocol for backward compatibility.
 *
 * @example
 * ```typescript
 * const broker = new TunnelBroker(logger, {
 *   sessionTimeoutMs: 300000,
 *   maxSessionsPerSensor: 5
 * });
 *
 * // Register channel handlers
 * broker.onChannelMessage('shell', async (session, message) => {
 *   // Forward to shell handler
 * });
 *
 * // Create a session
 * const sessionId = broker.createSession('sensor-1', 'shell', clientWs, {
 *   tenantId: 'tenant-1',
 *   userId: 'user-1'
 * });
 *
 * // Route incoming message
 * broker.routeMessage(sessionId, message);
 *
 * // Clean up on disconnect
 * broker.closeSession(sessionId, 'Client disconnected');
 * ```
 */
export class TunnelBroker extends EventEmitter {
  // New protocol state
  private sessions: Map<string, ChannelSession> = new Map();
  private sensorSessions: Map<string, Set<string>> = new Map();
  private channelHandlers: Map<TunnelChannel, ChannelHandler['handler']> = new Map();
  private rateLimiter: ChannelRateLimiter;
  private rateLimits: Record<TunnelChannel, ChannelRateLimits>;

  // Legacy protocol state (for backward compatibility)
  private legacyTunnels = new Map<string, TunnelSession>();
  private legacySessions = new Map<string, UserSession>();

  // Shared state
  private logger: Logger;
  private sessionTimeoutMs: number;
  private maxSessionsPerSensor: number;
  private cleanupIntervalHandle: NodeJS.Timeout | null = null;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private readonly HEARTBEAT_INTERVAL = 30000;
  private readonly HEARTBEAT_TIMEOUT = 60000;

  constructor(
    logger: Logger,
    options: {
      /** Session timeout in milliseconds (default: 5 minutes) */
      sessionTimeoutMs?: number;
      /** Maximum sessions per sensor (default: 10) */
      maxSessionsPerSensor?: number;
      /** Custom rate limits per channel */
      rateLimits?: Partial<Record<TunnelChannel, ChannelRateLimits>>;
    } = {}
  ) {
    super();
    this.logger = logger.child({ component: 'tunnel-broker' });
    this.sessionTimeoutMs = options.sessionTimeoutMs ?? 300000; // 5 minutes
    this.maxSessionsPerSensor = options.maxSessionsPerSensor ?? 10;
    this.rateLimiter = new ChannelRateLimiter();

    // Default rate limits per channel
    this.rateLimits = {
      shell: {
        messagesPerSecond: 100,
        bytesPerSecond: 65536 * 10, // 10 chunks/sec
        maxSessionsPerSensor: 3,
      },
      logs: {
        messagesPerSecond: 500,
        bytesPerSecond: 1024 * 1024, // 1MB/sec
        maxSessionsPerSensor: 5,
      },
      diag: {
        messagesPerSecond: 10,
        bytesPerSecond: 512 * 1024,
        maxSessionsPerSensor: 2,
      },
      control: {
        messagesPerSecond: 5,
        bytesPerSecond: 64 * 1024,
        maxSessionsPerSensor: 1,
      },
      files: {
        messagesPerSecond: 50,
        bytesPerSecond: 1024 * 1024 * 5, // 5MB/sec
        maxSessionsPerSensor: 2,
      },
      ...options.rateLimits,
    };

    // Start heartbeat monitor for legacy tunnels
    this.startHeartbeatMonitor();
    this.logger.info('TunnelBroker initialized');
  }

  // ==========================================================================
  // New Protocol: Session Management
  // ==========================================================================

  /**
   * Start the broker and begin cleanup intervals.
   */
  start(): void {
    // Start periodic cleanup of stale sessions
    this.cleanupIntervalHandle = setInterval(() => {
      this.cleanupStaleSessions();
    }, 60000); // Every minute

    this.logger.info('Tunnel broker started');
  }

  /**
   * Stop the broker and clean up all sessions.
   */
  stop(): void {
    if (this.cleanupIntervalHandle) {
      clearInterval(this.cleanupIntervalHandle);
      this.cleanupIntervalHandle = null;
    }

    // Close all new protocol sessions
    for (const sessionId of this.sessions.keys()) {
      this.closeSession(sessionId, 'Broker shutting down');
    }

    this.logger.info('Tunnel broker stopped');
  }

  /**
   * Register a handler for a specific channel type.
   *
   * @param channel - The channel to handle
   * @param handler - Async handler function for messages on this channel
   */
  onChannelMessage(
    channel: TunnelChannel,
    handler: (session: ChannelSession, message: TunnelMessage) => Promise<void>
  ): void {
    this.channelHandlers.set(channel, handler);
    this.logger.debug({ channel }, 'Registered channel handler');
  }

  /**
   * Create a new channel session.
   *
   * @param sensorId - ID of the sensor to connect to
   * @param channel - Channel type for this session
   * @param clientWs - Client WebSocket connection
   * @param context - Session context (tenant, user)
   * @returns Session ID or null if creation failed
   */
  createSession(
    sensorId: string,
    channel: TunnelChannel,
    clientWs: WebSocket,
    context: {
      tenantId: string;
      userId: string;
      sessionId?: string;
    }
  ): string | null {
    // Check sensor session limits
    const sensorSessionIds = this.sensorSessions.get(sensorId);
    const channelLimits = this.rateLimits[channel];

    if (sensorSessionIds) {
      // Count sessions of this channel type for this sensor
      let channelCount = 0;
      for (const existingSessionId of sensorSessionIds) {
        const existingSession = this.sessions.get(existingSessionId);
        if (existingSession?.channel === channel) {
          channelCount++;
        }
      }

      if (channelCount >= channelLimits.maxSessionsPerSensor) {
        this.logger.warn(
          { sensorId, channel, count: channelCount, max: channelLimits.maxSessionsPerSensor },
          'Maximum sessions reached for channel on sensor'
        );
        return null;
      }

      if (sensorSessionIds.size >= this.maxSessionsPerSensor) {
        this.logger.warn(
          { sensorId, count: sensorSessionIds.size, max: this.maxSessionsPerSensor },
          'Maximum total sessions reached for sensor'
        );
        return null;
      }
    }

    const sessionId = context.sessionId ?? randomUUID();
    const now = Date.now();

    const session: ChannelSession = {
      sessionId,
      channel,
      clientWs,
      sensorWs: null,
      sensorId,
      tenantId: context.tenantId,
      userId: context.userId,
      state: 'starting',
      createdAt: now,
      lastActivityAt: now,
      clientSequenceId: 0,
      sensorSequenceId: 0,
      messagesSent: 0,
      messagesReceived: 0,
      bytesTransferred: 0,
      messageTimestamps: [],
      bytesInWindow: 0,
      windowStart: now,
      cleanupTimeout: null,
    };

    this.sessions.set(sessionId, session);

    // Track session by sensor
    if (!this.sensorSessions.has(sensorId)) {
      this.sensorSessions.set(sensorId, new Set());
    }
    this.sensorSessions.get(sensorId)!.add(sessionId);

    // Set up client WebSocket handlers
    this.setupClientHandlers(session);

    // Emit session created event
    this.emit('session-created', this.getSessionInfo(session));

    this.logger.info(
      { sessionId, sensorId, channel, tenantId: context.tenantId },
      'Tunnel session created'
    );

    return sessionId;
  }

  /**
   * Set up WebSocket handlers for the client connection.
   */
  private setupClientHandlers(session: ChannelSession): void {
    session.clientWs.on('message', async (data) => {
      try {
        const raw = data.toString();
        const messageSize = Buffer.byteLength(raw, 'utf8');

        // Rate limiting check
        const limits = this.rateLimits[session.channel];
        const rateCheck = this.rateLimiter.checkAndUpdate(session, limits, messageSize);

        if (!rateCheck.allowed) {
          this.emit('rate-limited', session.sessionId, session.channel, rateCheck.reason!);
          this.sendToClient(session, {
            type: 'session-error',
            sessionId: session.sessionId,
            channel: session.channel,
            code: 'RATE_LIMITED',
            message: rateCheck.reason!,
            timestamp: Date.now(),
          });
          return;
        }

        const parsed = JSON.parse(raw);

        // Quick structure check
        if (!hasValidTunnelStructure(parsed)) {
          this.logger.warn(
            { sessionId: session.sessionId },
            'Invalid tunnel message structure'
          );
          return;
        }

        // Route the message
        await this.handleClientMessage(session, parsed);
      } catch (error) {
        this.logger.error(
          { error, sessionId: session.sessionId },
          'Failed to handle client message'
        );
      }
    });

    session.clientWs.on('close', () => {
      this.closeSession(session.sessionId, 'Client disconnected');
    });

    session.clientWs.on('error', (error) => {
      this.logger.error(
        { error, sessionId: session.sessionId },
        'Client WebSocket error'
      );
      this.closeSession(session.sessionId, 'Client error');
    });
  }

  /**
   * Handle a message from the client.
   */
  private async handleClientMessage(
    session: ChannelSession,
    data: unknown
  ): Promise<void> {
    session.lastActivityAt = Date.now();

    // Check if it's a session management message
    const dataObj = data as Record<string, unknown>;
    if (
      dataObj.type === 'session-close' ||
      dataObj.type === 'session-open'
    ) {
      await this.handleSessionMessage(session, data);
      return;
    }

    // Validate as tunnel message
    const validation = validateTunnelMessage(data);
    if (!validation.success) {
      this.emit('validation-error', session.sessionId, validation.errors);
      this.logger.warn(
        { sessionId: session.sessionId, errors: validation.errors },
        'Invalid tunnel message'
      );
      return;
    }

    // Verify channel matches
    if (validation.data.channel !== session.channel) {
      this.logger.warn(
        {
          sessionId: session.sessionId,
          expected: session.channel,
          received: validation.data.channel,
        },
        'Channel mismatch in message'
      );
      return;
    }

    // Route to channel handler
    await this.routeMessage(session.sessionId, validation.data);
  }

  /**
   * Handle session management messages.
   */
  private async handleSessionMessage(
    session: ChannelSession,
    data: unknown
  ): Promise<void> {
    const validation = validateSessionMessage(data);
    if (!validation.success) {
      this.emit('validation-error', session.sessionId, validation.errors);
      return;
    }

    const message = validation.data;

    switch (message.type) {
      case 'session-close':
        this.closeSession(
          session.sessionId,
          message.reason ?? 'Client requested close'
        );
        break;

      case 'session-open':
        // Session already created, acknowledge
        this.updateSessionState(session, 'active');
        this.sendToClient(session, {
          type: 'session-opened',
          channel: session.channel,
          sessionId: session.sessionId,
          capabilities: this.getChannelCapabilities(session.channel),
          timestamp: Date.now(),
        });
        break;
    }
  }

  /**
   * Route an incoming message to the appropriate handler.
   *
   * @param sessionId - Session ID for the message
   * @param message - Validated tunnel message
   */
  async routeMessage(sessionId: string, message: TunnelMessage): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      this.logger.warn({ sessionId }, 'Message for unknown session');
      return;
    }

    // Update activity timestamp
    session.lastActivityAt = Date.now();
    session.messagesSent++;
    session.bytesTransferred += JSON.stringify(message).length;

    // Get handler for channel
    const handler = this.channelHandlers.get(message.channel);
    if (!handler) {
      this.logger.warn(
        { sessionId, channel: message.channel },
        'No handler registered for channel'
      );
      return;
    }

    try {
      await handler(session, message);
      this.emit('message-routed', sessionId, message.channel, 'client-to-sensor');
    } catch (error) {
      this.logger.error(
        { error, sessionId, channel: message.channel },
        'Channel handler error'
      );
    }
  }

  /**
   * Send a message to the sensor for a session.
   *
   * @param sessionId - Session ID
   * @param message - Message to send
   * @returns True if sent, false if session not found or not connected
   */
  sendToSensor(sessionId: string, message: TunnelMessage | LegacyTunnelMessage): boolean {
    // Try new protocol first
    const session = this.sessions.get(sessionId);
    if (session?.sensorWs) {
      if (session.sensorWs.readyState !== WebSocket.OPEN) {
        return false;
      }

      try {
        const data = JSON.stringify(message);
        session.sensorWs.send(data);
        session.messagesSent++;
        session.bytesTransferred += data.length;
        return true;
      } catch (error) {
        this.logger.error({ error, sessionId }, 'Failed to send to sensor');
        return false;
      }
    }

    // Fall back to legacy protocol
    const legacySession = this.legacySessions.get(sessionId);
    if (legacySession) {
      const tunnel = this.legacyTunnels.get(legacySession.sensorId);
      if (!tunnel || tunnel.socket.readyState !== WebSocket.OPEN) {
        return false;
      }

      try {
        tunnel.socket.send(JSON.stringify(message));
        return true;
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Send a message to the client for a session.
   *
   * @param session - Channel session
   * @param message - Message to send
   * @returns True if sent, false otherwise
   */
  sendToClient(
    session: ChannelSession,
    message: TunnelProtocolMessage | Record<string, unknown>
  ): boolean {
    if (session.clientWs.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      const data = JSON.stringify(message);
      session.clientWs.send(data);
      session.messagesReceived++;
      session.bytesTransferred += data.length;
      return true;
    } catch (error) {
      this.logger.error(
        { error, sessionId: session.sessionId },
        'Failed to send to client'
      );
      return false;
    }
  }

  /**
   * Register a sensor WebSocket connection for a session.
   * Called after the broker connects to the sensor.
   *
   * @param sessionId - Session ID
   * @param sensorWs - WebSocket connection to the sensor
   */
  registerSensorConnection(sessionId: string, sensorWs: WebSocket): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      this.logger.warn({ sessionId }, 'Cannot register sensor for unknown session');
      return;
    }

    session.sensorWs = sensorWs;

    // Set up sensor WebSocket handlers
    sensorWs.on('message', async (data) => {
      try {
        const raw = data.toString();
        const parsed = JSON.parse(raw);

        const validation = validateTunnelMessage(parsed);
        if (!validation.success) {
          this.logger.warn(
            { sessionId, errors: validation.errors },
            'Invalid message from sensor'
          );
          return;
        }

        // Forward to client
        session.messagesReceived++;
        session.bytesTransferred += raw.length;
        session.lastActivityAt = Date.now();

        this.sendToClient(session, validation.data);
        this.emit('message-routed', sessionId, validation.data.channel, 'sensor-to-client');
      } catch (error) {
        this.logger.error(
          { error, sessionId },
          'Failed to handle sensor message'
        );
      }
    });

    sensorWs.on('close', () => {
      this.closeSession(sessionId, 'Sensor disconnected');
    });

    sensorWs.on('error', (error) => {
      this.logger.error({ error, sessionId }, 'Sensor WebSocket error');
      this.closeSession(sessionId, 'Sensor error');
    });

    // Transition to active state
    this.updateSessionState(session, 'active');

    this.logger.info(
      { sessionId, sensorId: session.sensorId },
      'Sensor connection registered for session'
    );
  }

  /**
   * Close a session and clean up resources.
   *
   * @param sessionId - Session ID to close
   * @param reason - Reason for closing
   */
  closeSession(sessionId: string, reason?: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return;
    }

    const oldState = session.state;

    // Skip if already closing or closed
    if (oldState === 'closing' || oldState === 'closed') {
      return;
    }

    this.updateSessionState(session, 'closing');

    // Clear cleanup timeout
    if (session.cleanupTimeout) {
      clearTimeout(session.cleanupTimeout);
      session.cleanupTimeout = null;
    }

    // Send close notification to client
    this.sendToClient(session, {
      type: 'session-closed',
      channel: session.channel,
      sessionId: session.sessionId,
      status: reason?.includes('error') ? 'error' : 'normal',
      reason: reason,
      timestamp: Date.now(),
    });

    // Close WebSocket connections
    if (session.clientWs.readyState === WebSocket.OPEN) {
      session.clientWs.close(1000, reason);
    }
    if (session.sensorWs && session.sensorWs.readyState === WebSocket.OPEN) {
      session.sensorWs.close(1000, reason);
    }

    // Remove from tracking
    this.sessions.delete(sessionId);
    const sensorSessions = this.sensorSessions.get(session.sensorId);
    if (sensorSessions) {
      sensorSessions.delete(sessionId);
      if (sensorSessions.size === 0) {
        this.sensorSessions.delete(session.sensorId);
      }
    }

    this.updateSessionState(session, 'closed');

    // Emit close event with stats
    this.emit('session-closed', sessionId, reason ?? 'Unknown', {
      messagesSent: session.messagesSent,
      messagesReceived: session.messagesReceived,
      bytesTransferred: session.bytesTransferred,
    });

    this.logger.info(
      {
        sessionId,
        reason,
        duration: Date.now() - session.createdAt,
        messagesSent: session.messagesSent,
        messagesReceived: session.messagesReceived,
      },
      'Tunnel session closed'
    );
  }

  /**
   * Clean up all sessions for a sensor.
   * Called when a sensor disconnects.
   *
   * @param sensorId - Sensor ID to clean up
   */
  cleanupSensor(sensorId: string): void {
    // Clean up new protocol sessions
    const sessionIds = this.sensorSessions.get(sensorId);
    if (sessionIds) {
      for (const sessionId of sessionIds) {
        this.closeSession(sessionId, 'Sensor cleanup');
      }
      this.sensorSessions.delete(sensorId);
    }

    // Clean up legacy protocol
    this.handleSensorDisconnect(sensorId, 'Sensor cleanup');

    this.logger.info({ sensorId }, 'Cleaned up all sessions for sensor');
  }

  /**
   * Get information about a session.
   *
   * @param sessionId - Session ID
   * @returns Session info or undefined
   */
  getSession(sessionId: string): TunnelSessionInfo | undefined {
    const session = this.sessions.get(sessionId);
    return session ? this.getSessionInfo(session) : undefined;
  }

  /**
   * Get all sessions for a sensor.
   *
   * @param sensorId - Sensor ID
   * @returns Array of session info
   */
  getSensorSessions(sensorId: string): TunnelSessionInfo[] {
    const sessionIds = this.sensorSessions.get(sensorId);
    if (!sessionIds) {
      return [];
    }

    const sessions: TunnelSessionInfo[] = [];
    for (const sessionId of sessionIds) {
      const session = this.sessions.get(sessionId);
      if (session) {
        sessions.push(this.getSessionInfo(session));
      }
    }

    return sessions;
  }

  /**
   * Get total session count.
   */
  getSessionCount(): number {
    return this.sessions.size + this.legacySessions.size;
  }

  /**
   * Get sessions grouped by channel type.
   */
  getSessionsByChannel(): Record<TunnelChannel, number> {
    const counts: Record<TunnelChannel, number> = {
      shell: 0,
      logs: 0,
      diag: 0,
      control: 0,
      files: 0,
    };

    for (const session of this.sessions.values()) {
      counts[session.channel]++;
    }

    // Add legacy sessions
    for (const session of this.legacySessions.values()) {
      if (session.type === 'shell') {
        counts.shell++;
      }
    }

    return counts;
  }

  /**
   * Convert internal session to public info.
   */
  private getSessionInfo(session: ChannelSession): TunnelSessionInfo {
    return {
      sessionId: session.sessionId,
      channel: session.channel,
      sensorId: session.sensorId,
      tenantId: session.tenantId,
      state: session.state,
      createdAt: session.createdAt,
      lastActivityAt: session.lastActivityAt,
      messagesSent: session.messagesSent,
      messagesReceived: session.messagesReceived,
      bytesTransferred: session.bytesTransferred,
    };
  }

  /**
   * Update session state and emit event.
   */
  private updateSessionState(
    session: ChannelSession,
    newState: TunnelSessionState
  ): void {
    const oldState = session.state;
    session.state = newState;
    this.emit('session-state-changed', session.sessionId, oldState, newState);
  }

  /**
   * Get capabilities for a channel type.
   */
  private getChannelCapabilities(channel: TunnelChannel): string[] {
    switch (channel) {
      case 'shell':
        return ['pty', 'resize', 'env'];
      case 'logs':
        return ['subscribe', 'filter', 'backfill'];
      case 'diag':
        return [
          'health',
          'memory',
          'connections',
          'rules',
          'actors',
          'config',
          'metrics',
          'threads',
          'cache',
        ];
      case 'control':
        return ['reload', 'restart', 'shutdown', 'drain', 'resume'];
      case 'files':
        return ['list', 'read', 'write', 'stat'];
      default:
        return [];
    }
  }

  /**
   * Clean up stale sessions that have exceeded timeout.
   */
  private cleanupStaleSessions(): void {
    const now = Date.now();
    const staleThreshold = now - this.sessionTimeoutMs;

    for (const [sessionId, session] of this.sessions) {
      if (session.lastActivityAt < staleThreshold && session.state === 'active') {
        this.logger.warn(
          { sessionId, lastActivity: session.lastActivityAt },
          'Closing stale tunnel session'
        );
        this.closeSession(sessionId, 'Session timeout');
      }
    }
  }

  // ==========================================================================
  // Legacy Protocol: Sensor Tunnel Management
  // ==========================================================================

  /**
   * @deprecated Use createSession() and the new channel-based protocol instead
   */
  handleSensorConnect(
    ws: WebSocket,
    sensorId: string,
    tenantId: string,
    capabilities: TunnelCapability[],
    metadata?: TunnelSession['metadata']
  ): void {
    // Close existing tunnel if reconnecting
    if (this.legacyTunnels.has(sensorId)) {
      this.logger.warn({ sensorId, tenantId }, 'Sensor reconnecting, closing old tunnel');
      this.handleSensorDisconnect(sensorId, 'reconnection');
    }

    const session: TunnelSession = {
      sensorId,
      tenantId,
      socket: ws,
      capabilities,
      connectedAt: new Date(),
      lastHeartbeat: new Date(),
      metadata,
    };

    this.legacyTunnels.set(sensorId, session);

    ws.on('message', (data) => this.handleLegacySensorMessage(sensorId, data));
    // Capture socket reference to prevent closing a newer connection when old socket closes
    ws.on('close', () => {
      const currentTunnel = this.legacyTunnels.get(sensorId);
      if (currentTunnel && currentTunnel.socket === ws) {
        this.handleSensorDisconnect(sensorId, 'socket closed');
      }
    });
    ws.on('error', (error) => this.handleSensorError(sensorId, error));

    this.logger.info({ sensorId, tenantId, capabilities }, 'Sensor tunnel connected');
    this.emit('tunnel:connected', session);
  }

  /**
   * @deprecated Use cleanupSensor() instead
   */
  handleSensorDisconnect(sensorId: string, reason = 'unknown'): void {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (!tunnel) return;

    // Close all legacy user sessions for this sensor
    for (const session of this.legacySessions.values()) {
      if (session.sensorId === sensorId) {
        this.endUserSession(session.sessionId, `Sensor disconnected: ${reason}`);
      }
    }

    // Clean up any pending requests for this sensor to prevent memory leaks
    // Requests would otherwise remain orphaned with their timeouts still firing
    for (const [requestId, pending] of this.pendingRequests.entries()) {
      if (pending.sensorId === sensorId) {
        clearTimeout(pending.timeout);
        this.pendingRequests.delete(requestId);
        pending.reject(new Error(`Sensor disconnected: ${reason}`));
      }
    }

    if (tunnel.socket.readyState === WebSocket.OPEN) {
      tunnel.socket.close(1000, reason);
    }

    this.legacyTunnels.delete(sensorId);
    this.logger.info({ sensorId, reason }, 'Sensor tunnel disconnected');
    this.emit('tunnel:disconnected', sensorId, tunnel.tenantId);
  }

  private handleLegacySensorMessage(sensorId: string, data: unknown): void {
    try {
      const message = this.parseMessage(data);

      // Check if this is a response to a pending request (e.g., bandwidth stats)
      if (this.handleSensorResponse(sensorId, message)) {
        return; // Response handled, no further processing needed
      }

      // Emit event for external listeners (e.g., SynapseProxyService)
      this.emit('tunnel:message', sensorId, message);

      switch (message.type) {
        case 'heartbeat':
          this.handleHeartbeat(sensorId);
          break;
        case 'shell-data':
        case 'dashboard-response':
          this.routeToUser(sensorId, message);
          break;
        case 'error':
          this.logger.error({ sensorId, payload: message.payload }, 'Error from sensor');
          if (message.sessionId) {
            this.endUserSession(message.sessionId, 'Sensor error');
          }
          break;
      }
    } catch (error) {
      this.logger.error({ sensorId, error }, 'Failed to handle sensor message');
    }
  }

  private handleSensorError(sensorId: string, error: Error): void {
    this.logger.error({ sensorId, error: error.message }, 'Sensor socket error');
  }

  private handleHeartbeat(sensorId: string): void {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (tunnel) {
      tunnel.lastHeartbeat = new Date();
    }
  }

  // ==========================================================================
  // Legacy Protocol: User Session Management
  // ==========================================================================

  /**
   * @deprecated Use createSession('shell', ...) instead
   */
  startShellSession(
    ws: WebSocket,
    userId: string,
    tenantId: string,
    sensorId: string
  ): string | null {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (!tunnel || !tunnel.capabilities.includes('shell')) {
      return null;
    }

    if (tunnel.tenantId !== tenantId) {
      this.logger.error({ sensorId, tenantId }, 'Tenant mismatch');
      return null;
    }

    const sessionId = randomUUID();
    const session: UserSession = {
      sessionId,
      userId,
      tenantId,
      sensorId,
      type: 'shell',
      socket: ws,
      createdAt: new Date(),
      lastActivity: new Date(),
    };

    this.legacySessions.set(sessionId, session);

    ws.on('message', (data) => this.handleUserMessage(sessionId, data));
    ws.on('close', () => this.endUserSession(sessionId, 'User disconnected'));
    ws.on('error', () => this.endUserSession(sessionId, 'Socket error'));

    // Notify sensor to start shell
    this.sendToSensor(sessionId, {
      type: 'shell-data',
      sessionId,
      payload: { action: 'start' },
      timestamp: new Date().toISOString(),
    });

    this.logger.info({ sessionId, userId, sensorId }, 'Shell session started');
    this.emit('session:started', session);

    return sessionId;
  }

  /**
   * @deprecated Use createSession() with a dashboard channel instead
   */
  startDashboardProxy(
    ws: WebSocket,
    userId: string,
    tenantId: string,
    sensorId: string
  ): string | null {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (!tunnel || !tunnel.capabilities.includes('dashboard')) {
      return null;
    }

    if (tunnel.tenantId !== tenantId) {
      return null;
    }

    const sessionId = randomUUID();
    const session: UserSession = {
      sessionId,
      userId,
      tenantId,
      sensorId,
      type: 'dashboard',
      socket: ws,
      createdAt: new Date(),
      lastActivity: new Date(),
    };

    this.legacySessions.set(sessionId, session);

    ws.on('message', (data) => this.handleUserMessage(sessionId, data));
    ws.on('close', () => this.endUserSession(sessionId, 'User disconnected'));
    ws.on('error', () => this.endUserSession(sessionId, 'Socket error'));

    this.logger.info({ sessionId, userId, sensorId }, 'Dashboard session started');
    this.emit('session:started', session);

    return sessionId;
  }

  private endUserSession(sessionId: string, reason: string): void {
    const session = this.legacySessions.get(sessionId);
    if (!session) return;

    // Notify sensor
    this.sendToSensor(sessionId, {
      type: session.type === 'shell' ? 'shell-data' : 'dashboard-request',
      sessionId,
      payload: { action: 'end' },
      timestamp: new Date().toISOString(),
    });

    if (session.socket.readyState === WebSocket.OPEN) {
      session.socket.close(1000, reason);
    }

    this.legacySessions.delete(sessionId);
    this.logger.info({ sessionId, reason }, 'User session ended');
    this.emit('session:ended', sessionId, reason);
  }

  private handleUserMessage(sessionId: string, data: unknown): void {
    const session = this.legacySessions.get(sessionId);
    if (!session) return;

    session.lastActivity = new Date();

    try {
      const message = this.parseMessage(data);
      message.sessionId = sessionId;
      this.sendToSensor(sessionId, message);
    } catch (error) {
      this.logger.error({ sessionId, error }, 'Failed to handle user message');
    }
  }

  private routeToUser(sensorId: string, message: LegacyTunnelMessage): void {
    if (!message.sessionId) return;

    const session = this.legacySessions.get(message.sessionId);
    if (!session || session.sensorId !== sensorId) return;

    session.lastActivity = new Date();
    this.sendToLegacyUser(session.sessionId, message);
  }

  private sendToLegacyUser(sessionId: string, message: LegacyTunnelMessage): boolean {
    const session = this.legacySessions.get(sessionId);
    if (!session || session.socket.readyState !== WebSocket.OPEN) {
      return false;
    }

    try {
      session.socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }

  private parseMessage(data: unknown): LegacyTunnelMessage {
    const str = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
    return JSON.parse(str) as LegacyTunnelMessage;
  }

  // ==========================================================================
  // Legacy Protocol: Status & Monitoring
  // ==========================================================================

  /**
   * @deprecated Use getSession() instead
   */
  getTunnelStatus(sensorId: string): TunnelSession | null {
    return this.legacyTunnels.get(sensorId) ?? null;
  }

  /**
   * @deprecated Use getSensorSessions() instead
   */
  getActiveTunnels(tenantId: string): TunnelSession[] {
    return Array.from(this.legacyTunnels.values())
      .filter((t) => t.tenantId === tenantId);
  }

  /**
   * @deprecated Use getSensorSessions() instead
   */
  getActiveSessions(tenantId: string): UserSession[] {
    return Array.from(this.legacySessions.values())
      .filter((s) => s.tenantId === tenantId);
  }

  /**
   * Get combined statistics from both protocols.
   */
  getStats(): TunnelStats {
    const stats: TunnelStats = {
      totalTunnels: this.legacyTunnels.size,
      activeSessions: this.sessions.size + this.legacySessions.size,
      byTenant: {},
      byType: { shell: 0, dashboard: 0 },
      byChannel: {
        shell: 0,
        logs: 0,
        diag: 0,
        control: 0,
        files: 0,
      },
    };

    // Legacy tunnels
    for (const tunnel of this.legacyTunnels.values()) {
      if (!stats.byTenant[tunnel.tenantId]) {
        stats.byTenant[tunnel.tenantId] = { tunnels: 0, sessions: 0 };
      }
      stats.byTenant[tunnel.tenantId].tunnels++;
    }

    // Legacy sessions
    for (const session of this.legacySessions.values()) {
      stats.byType[session.type]++;
      if (stats.byTenant[session.tenantId]) {
        stats.byTenant[session.tenantId].sessions++;
      }
    }

    // New protocol sessions
    for (const session of this.sessions.values()) {
      stats.byChannel[session.channel]++;
      if (!stats.byTenant[session.tenantId]) {
        stats.byTenant[session.tenantId] = { tunnels: 0, sessions: 0 };
      }
      stats.byTenant[session.tenantId].sessions++;
    }

    return stats;
  }

  // ==========================================================================
  // Direct Sensor Communication (for bandwidth aggregation, etc.)
  // ==========================================================================

  /**
   * Pending requests waiting for responses from sensors.
   * Maps requestId -> { resolve, reject, timeout }
   */
  private pendingRequests = new Map<
    string,
    {
      resolve: (value: TunnelRequestResponse) => void;
      reject: (error: Error) => void;
      timeout: NodeJS.Timeout;
      sensorId: string;
    }
  >();

  /**
   * Get information about a sensor's tunnel connection.
   *
   * @param sensorId - The sensor ID to check
   * @returns Tunnel info or null if not connected
   */
  getSensorTunnelInfo(sensorId: string): { connected: boolean; connectedAt?: Date; capabilities?: string[] } | null {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (!tunnel) {
      return null;
    }

    return {
      connected: tunnel.socket.readyState === WebSocket.OPEN,
      connectedAt: tunnel.connectedAt,
      capabilities: tunnel.capabilities,
    };
  }

  /**
   * Send a request to a sensor and wait for a response.
   * This is used for direct sensor queries like bandwidth stats.
   *
   * @param sensorId - The sensor to send the request to
   * @param request - The request payload with type and payload fields
   * @param timeoutMs - Timeout in milliseconds (default: 10000)
   * @returns Promise resolving to the response
   */
  async sendRequest(
    sensorId: string,
    request: { type: string; payload: unknown },
    timeoutMs = 10000
  ): Promise<TunnelRequestResponse> {
    const tunnel = this.legacyTunnels.get(sensorId);
    if (!tunnel || tunnel.socket.readyState !== WebSocket.OPEN) {
      throw new Error('Sensor not connected');
    }

    const requestId = randomUUID();

    return new Promise((resolve, reject) => {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(requestId);
        reject(new Error('Request timeout'));
      }, timeoutMs);

      // Store pending request
      this.pendingRequests.set(requestId, {
        resolve,
        reject,
        timeout,
        sensorId,
      });

      // Send request to sensor
      // Note: We use type assertion here because direct sensor requests
      // may use custom message types not in TunnelMessageType enum
      const message: LegacyTunnelMessage = {
        type: request.type as TunnelMessageType,
        requestId,
        payload: request.payload,
        timestamp: new Date().toISOString(),
      };

      try {
        tunnel.socket.send(JSON.stringify(message));
        this.logger.debug({ sensorId, requestId, type: request.type }, 'Sent request to sensor');
      } catch (error) {
        this.pendingRequests.delete(requestId);
        clearTimeout(timeout);
        reject(error instanceof Error ? error : new Error('Failed to send request'));
      }
    });
  }

  /**
   * Handle a response from a sensor (called from message handler).
   * Matches responses to pending requests by requestId.
   *
   * @param sensorId - The sensor that sent the response
   * @param message - The response message
   * @returns True if the message was handled as a response
   */
  private handleSensorResponse(sensorId: string, message: LegacyTunnelMessage): boolean {
    if (!message.requestId) {
      return false;
    }

    const pending = this.pendingRequests.get(message.requestId);
    if (!pending || pending.sensorId !== sensorId) {
      return false;
    }

    // Clear timeout and remove from pending
    clearTimeout(pending.timeout);
    this.pendingRequests.delete(message.requestId);

    // Resolve with the response
    pending.resolve({
      type: message.type,
      payload: message.payload,
      requestId: message.requestId,
    });

    this.logger.debug({ sensorId, requestId: message.requestId }, 'Received response from sensor');
    return true;
  }

  // ==========================================================================
  // Heartbeat & Cleanup (Legacy Protocol)
  // ==========================================================================

  private startHeartbeatMonitor(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();

      for (const [sensorId, tunnel] of this.legacyTunnels) {
        if (now - tunnel.lastHeartbeat.getTime() > this.HEARTBEAT_TIMEOUT) {
          this.logger.warn({ sensorId }, 'Tunnel heartbeat timeout');
          this.handleSensorDisconnect(sensorId, 'heartbeat timeout');
        }
      }
    }, this.HEARTBEAT_INTERVAL);
  }

  /**
   * Gracefully shutdown the broker.
   */
  async shutdown(): Promise<void> {
    this.logger.info('Shutting down TunnelBroker');

    // Stop intervals
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    this.stop();

    // End legacy sessions
    for (const sessionId of this.legacySessions.keys()) {
      this.endUserSession(sessionId, 'Server shutdown');
    }

    // Disconnect legacy tunnels
    for (const sensorId of this.legacyTunnels.keys()) {
      this.handleSensorDisconnect(sensorId, 'Server shutdown');
    }
  }
}

// =============================================================================
// Type-safe Event Handling
// =============================================================================

// Augment the EventEmitter type for TunnelBroker
export interface TunnelBroker {
  on<K extends keyof TunnelBrokerEvents>(
    event: K,
    listener: TunnelBrokerEvents[K]
  ): this;
  off<K extends keyof TunnelBrokerEvents>(
    event: K,
    listener: TunnelBrokerEvents[K]
  ): this;
  emit<K extends keyof TunnelBrokerEvents>(
    event: K,
    ...args: Parameters<TunnelBrokerEvents[K]>
  ): boolean;
}
