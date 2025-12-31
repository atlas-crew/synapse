/**
 * WebSocket Tunnel Broker
 *
 * Manages bidirectional tunnels between sensors and Signal Horizon.
 * Sensors establish outbound connections, enabling:
 * - Shell access (SSH-over-WebSocket)
 * - Dashboard proxy (HTTP-over-WebSocket)
 */

import { EventEmitter } from 'events';
import type { WebSocket } from 'ws';
import type { Logger } from 'pino';
import { randomUUID } from 'crypto';

// ============================================================================
// Types
// ============================================================================

export type TunnelCapability = 'shell' | 'dashboard';
export type UserSessionType = 'shell' | 'dashboard';

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

export type TunnelMessageType =
  | 'heartbeat'
  | 'shell-data'
  | 'shell-resize'
  | 'dashboard-request'
  | 'dashboard-response'
  | 'error';

export interface TunnelMessage {
  type: TunnelMessageType;
  sessionId?: string;
  payload: unknown;
  timestamp: string;
}

export interface TunnelStats {
  totalTunnels: number;
  activeSessions: number;
  byTenant: Record<string, { tunnels: number; sessions: number }>;
  byType: Record<UserSessionType, number>;
}

// ============================================================================
// TunnelBroker Class
// ============================================================================

export class TunnelBroker extends EventEmitter {
  private tunnels = new Map<string, TunnelSession>();
  private sessions = new Map<string, UserSession>();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private readonly HEARTBEAT_INTERVAL = 30000;
  private readonly HEARTBEAT_TIMEOUT = 60000;

  constructor(private logger: Logger) {
    super();
    this.startHeartbeatMonitor();
    this.logger.info('TunnelBroker initialized');
  }

  // ==========================================================================
  // Sensor Tunnel Management
  // ==========================================================================

  handleSensorConnect(
    ws: WebSocket,
    sensorId: string,
    tenantId: string,
    capabilities: TunnelCapability[],
    metadata?: TunnelSession['metadata']
  ): void {
    // Close existing tunnel if reconnecting
    if (this.tunnels.has(sensorId)) {
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

    this.tunnels.set(sensorId, session);

    ws.on('message', (data) => this.handleSensorMessage(sensorId, data));
    ws.on('close', () => this.handleSensorDisconnect(sensorId, 'socket closed'));
    ws.on('error', (error) => this.handleSensorError(sensorId, error));

    this.logger.info({ sensorId, tenantId, capabilities }, 'Sensor tunnel connected');
    this.emit('tunnel:connected', session);
  }

  handleSensorDisconnect(sensorId: string, reason = 'unknown'): void {
    const tunnel = this.tunnels.get(sensorId);
    if (!tunnel) return;

    // Close all user sessions for this sensor
    for (const session of this.sessions.values()) {
      if (session.sensorId === sensorId) {
        this.endUserSession(session.sessionId, `Sensor disconnected: ${reason}`);
      }
    }

    if (tunnel.socket.readyState === tunnel.socket.OPEN) {
      tunnel.socket.close(1000, reason);
    }

    this.tunnels.delete(sensorId);
    this.logger.info({ sensorId, reason }, 'Sensor tunnel disconnected');
    this.emit('tunnel:disconnected', sensorId, tunnel.tenantId);
  }

  private handleSensorMessage(sensorId: string, data: unknown): void {
    try {
      const message = this.parseMessage(data);

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
    const tunnel = this.tunnels.get(sensorId);
    if (tunnel) {
      tunnel.lastHeartbeat = new Date();
    }
  }

  // ==========================================================================
  // User Session Management
  // ==========================================================================

  startShellSession(
    ws: WebSocket,
    userId: string,
    tenantId: string,
    sensorId: string
  ): string | null {
    const tunnel = this.tunnels.get(sensorId);
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

    this.sessions.set(sessionId, session);

    ws.on('message', (data) => this.handleUserMessage(sessionId, data));
    ws.on('close', () => this.endUserSession(sessionId, 'User disconnected'));
    ws.on('error', () => this.endUserSession(sessionId, 'Socket error'));

    // Notify sensor to start shell
    this.sendToSensor(sensorId, {
      type: 'shell-data',
      sessionId,
      payload: { action: 'start' },
      timestamp: new Date().toISOString(),
    });

    this.logger.info({ sessionId, userId, sensorId }, 'Shell session started');
    this.emit('session:started', session);

    return sessionId;
  }

  startDashboardProxy(
    ws: WebSocket,
    userId: string,
    tenantId: string,
    sensorId: string
  ): string | null {
    const tunnel = this.tunnels.get(sensorId);
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

    this.sessions.set(sessionId, session);

    ws.on('message', (data) => this.handleUserMessage(sessionId, data));
    ws.on('close', () => this.endUserSession(sessionId, 'User disconnected'));
    ws.on('error', () => this.endUserSession(sessionId, 'Socket error'));

    this.logger.info({ sessionId, userId, sensorId }, 'Dashboard session started');
    this.emit('session:started', session);

    return sessionId;
  }

  private endUserSession(sessionId: string, reason: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    // Notify sensor
    this.sendToSensor(session.sensorId, {
      type: session.type === 'shell' ? 'shell-data' : 'dashboard-request',
      sessionId,
      payload: { action: 'end' },
      timestamp: new Date().toISOString(),
    });

    if (session.socket.readyState === session.socket.OPEN) {
      session.socket.close(1000, reason);
    }

    this.sessions.delete(sessionId);
    this.logger.info({ sessionId, reason }, 'User session ended');
    this.emit('session:ended', sessionId, reason);
  }

  private handleUserMessage(sessionId: string, data: unknown): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;

    session.lastActivity = new Date();

    try {
      const message = this.parseMessage(data);
      message.sessionId = sessionId;
      this.sendToSensor(session.sensorId, message);
    } catch (error) {
      this.logger.error({ sessionId, error }, 'Failed to handle user message');
    }
  }

  private routeToUser(sensorId: string, message: TunnelMessage): void {
    if (!message.sessionId) return;

    const session = this.sessions.get(message.sessionId);
    if (!session || session.sensorId !== sensorId) return;

    session.lastActivity = new Date();
    this.sendToUser(session.sessionId, message);
  }

  // ==========================================================================
  // Message Routing
  // ==========================================================================

  sendToSensor(sensorId: string, message: TunnelMessage): boolean {
    const tunnel = this.tunnels.get(sensorId);
    if (!tunnel || tunnel.socket.readyState !== tunnel.socket.OPEN) {
      return false;
    }

    try {
      tunnel.socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }

  private sendToUser(sessionId: string, message: TunnelMessage): boolean {
    const session = this.sessions.get(sessionId);
    if (!session || session.socket.readyState !== session.socket.OPEN) {
      return false;
    }

    try {
      session.socket.send(JSON.stringify(message));
      return true;
    } catch {
      return false;
    }
  }

  private parseMessage(data: unknown): TunnelMessage {
    const str = Buffer.isBuffer(data) ? data.toString('utf8') : String(data);
    return JSON.parse(str) as TunnelMessage;
  }

  // ==========================================================================
  // Status & Monitoring
  // ==========================================================================

  getTunnelStatus(sensorId: string): TunnelSession | null {
    return this.tunnels.get(sensorId) ?? null;
  }

  getActiveTunnels(tenantId: string): TunnelSession[] {
    return Array.from(this.tunnels.values())
      .filter((t) => t.tenantId === tenantId);
  }

  getActiveSessions(tenantId: string): UserSession[] {
    return Array.from(this.sessions.values())
      .filter((s) => s.tenantId === tenantId);
  }

  getStats(): TunnelStats {
    const stats: TunnelStats = {
      totalTunnels: this.tunnels.size,
      activeSessions: this.sessions.size,
      byTenant: {},
      byType: { shell: 0, dashboard: 0 },
    };

    for (const tunnel of this.tunnels.values()) {
      if (!stats.byTenant[tunnel.tenantId]) {
        stats.byTenant[tunnel.tenantId] = { tunnels: 0, sessions: 0 };
      }
      stats.byTenant[tunnel.tenantId].tunnels++;
    }

    for (const session of this.sessions.values()) {
      stats.byType[session.type]++;
      if (stats.byTenant[session.tenantId]) {
        stats.byTenant[session.tenantId].sessions++;
      }
    }

    return stats;
  }

  // ==========================================================================
  // Heartbeat & Cleanup
  // ==========================================================================

  private startHeartbeatMonitor(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();

      for (const [sensorId, tunnel] of this.tunnels) {
        if (now - tunnel.lastHeartbeat.getTime() > this.HEARTBEAT_TIMEOUT) {
          this.logger.warn({ sensorId }, 'Tunnel heartbeat timeout');
          this.handleSensorDisconnect(sensorId, 'heartbeat timeout');
        }
      }
    }, this.HEARTBEAT_INTERVAL);
  }

  async shutdown(): Promise<void> {
    this.logger.info('Shutting down TunnelBroker');

    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    for (const sessionId of this.sessions.keys()) {
      this.endUserSession(sessionId, 'Server shutdown');
    }

    for (const sensorId of this.tunnels.keys()) {
      this.handleSensorDisconnect(sensorId, 'Server shutdown');
    }
  }
}
