/**
 * Dashboard Gateway
 * WebSocket server for UI connections (outbound push to dashboards)
 * Requires authentication via API key with dashboard:read scope
 */

import { WebSocketServer, WebSocket } from 'ws';
import type { IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'node:crypto';
import type {
  CampaignAlert,
  ThreatAlert,
  BlocklistUpdate,
  SharingPreference,
} from '../types/protocol.js';
import {
  validateDashboardMessage,
  type ValidatedDashboardMessage,
} from '../schemas/signal.js';
import { WebSocketRateLimiter } from '../lib/ws-rate-limiter.js';

interface DashboardConnection {
  id: string;
  tenantId: string | null; // null = fleet admin view (requires fleet:admin scope)
  sharingPreference: SharingPreference | null;
  isAuthenticated: boolean;
  isFleetAdmin: boolean; // Can access all tenant data
  ws: WebSocket;
  connectedAt: number;
  lastPong: number;
  subscriptions: Set<string>; // e.g., 'campaigns', 'threats', 'blocklist'
  /** API key ID for periodic revalidation (WS2-002) */
  apiKeyId: string | null;
}

interface DashboardGatewayConfig {
  path: string;
  heartbeatIntervalMs: number;
  maxConnections: number;
}

// Message schema validation is in ../schemas/signal.ts
// ValidatedDashboardMessage type is imported from there

const AUTH_TIMEOUT_MS = 10000;

/** Interval for token revalidation (WS2-002) */
const TOKEN_REVALIDATE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

export class DashboardGateway {
  private wss: WebSocketServer | null = null;
  private connections: Map<string, DashboardConnection> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  /** Interval for checking token validity (WS2-002) */
  private revalidateInterval: NodeJS.Timeout | null = null;
  private prisma: PrismaClient;
  private logger: Logger;
  private config: DashboardGatewayConfig;
  private sequenceId = 0;
  /** Rate limiter for message flooding protection (WS-SEC-001) */
  private rateLimiter: WebSocketRateLimiter;

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    config: DashboardGatewayConfig
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ gateway: 'dashboard' });
    this.config = config;

    // Initialize rate limiter: 50 msg/s with burst of 75 (dashboard sends less than sensors)
    this.rateLimiter = new WebSocketRateLimiter({
      maxMessagesPerSecond: 50,
      burstLimit: 75,
      disconnectOnExceed: true,
    });

    this.wss = new WebSocketServer({
      noServer: true,
    });
  }

  start(): void {
    if (!this.wss) return;

    this.wss.on('connection', (ws, req) => {
      this.handleConnection(ws, req);
    });

    this.wss.on('error', (error) => {
      this.logger.error({ error }, 'Dashboard gateway error');
    });

    this.startHeartbeat();
    this.startTokenRevalidation(); // WS2-002: Periodic token validation
    this.logger.info({ path: this.config.path }, 'Dashboard gateway started');
  }

  handleUpgrade(req: IncomingMessage, socket: Socket, head: Buffer): void {
    if (!this.wss) {
      socket.destroy();
      return;
    }

    this.wss.handleUpgrade(req, socket, head, (ws) => {
      this.wss?.emit('connection', ws, req);
    });
  }

  stop(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }

    if (this.revalidateInterval) {
      clearInterval(this.revalidateInterval);
      this.revalidateInterval = null;
    }

    for (const conn of this.connections.values()) {
      conn.ws.close(1000, 'Server shutting down');
    }
    this.connections.clear();

    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }

    this.logger.info('Dashboard gateway stopped');
  }

  private handleConnection(ws: WebSocket, _req: unknown): void {
    if (this.connections.size >= this.config.maxConnections) {
      ws.close(1013, 'Max connections reached');
      return;
    }

    const connectionId = randomUUID();
    const conn: DashboardConnection = {
      id: connectionId,
      tenantId: null,
      sharingPreference: null,
      isAuthenticated: false,
      isFleetAdmin: false,
      ws,
      connectedAt: Date.now(),
      lastPong: Date.now(),
      subscriptions: new Set(), // Empty until authenticated
      apiKeyId: null, // Set after authentication for revalidation
    };

    this.connections.set(connectionId, conn);

    this.logger.info({ connectionId }, 'Dashboard connecting (pending auth)');

    // Send auth required message
    this.send(conn, {
      type: 'auth-required',
      message: 'Please authenticate with an API key',
      timestamp: Date.now(),
    });

    // Set auth timeout
    const authTimeout = setTimeout(() => {
      if (!conn.isAuthenticated) {
        this.logger.warn({ connectionId }, 'Dashboard auth timeout');
        ws.close(4001, 'Auth timeout');
        this.connections.delete(connectionId);
      }
    }, AUTH_TIMEOUT_MS);

    ws.on('message', async (data) => {
      // Rate limit check (WS-SEC-001: DoS protection)
      const rateLimitResult = this.rateLimiter.checkLimit(connectionId);
      if (!rateLimitResult.allowed) {
        this.logger.warn(
          { connectionId, remaining: rateLimitResult.remaining },
          'Dashboard rate limit exceeded'
        );
        if (rateLimitResult.shouldDisconnect) {
          ws.close(4029, 'Rate limit exceeded');
          this.connections.delete(connectionId);
          this.rateLimiter.removeConnection(connectionId);
          return;
        }
        this.send(conn, {
          type: 'error',
          error: 'Rate limit exceeded, slow down',
          timestamp: Date.now(),
        });
        return;
      }

      try {
        const parsed = JSON.parse(data.toString());
        const validation = validateDashboardMessage(parsed);

        if (!validation.success) {
          this.logger.warn(
            { connectionId, errors: validation.errors },
            'Invalid dashboard message payload'
          );
          this.send(conn, {
            type: 'error',
            error: `Invalid message: ${validation.errors.join(', ')}`,
            timestamp: Date.now(),
          });
          return;
        }

        await this.handleMessage(conn, validation.data, authTimeout);
      } catch (error) {
        this.logger.error({ error, connectionId }, 'Failed to parse dashboard message');
        this.send(conn, { type: 'error', error: 'Invalid JSON', timestamp: Date.now() });
      }
    });

    ws.on('close', () => {
      clearTimeout(authTimeout);
      this.connections.delete(connectionId);
      this.rateLimiter.removeConnection(connectionId); // Clean up rate limiter state
      this.logger.info({ connectionId }, 'Dashboard disconnected');
    });

    ws.on('error', (error) => {
      this.logger.error({ error, connectionId }, 'Dashboard connection error');
      clearTimeout(authTimeout);
      this.connections.delete(connectionId);
    });
  }

  private async handleMessage(
    conn: DashboardConnection,
    message: ValidatedDashboardMessage,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    // Auth message is always allowed
    if (message.type === 'auth') {
      await this.handleAuth(conn, message.payload?.apiKey, authTimeout);
      return;
    }

    // All other messages require authentication
    if (!conn.isAuthenticated) {
      this.send(conn, {
        type: 'error',
        error: 'Not authenticated',
        timestamp: Date.now(),
      });
      return;
    }

    switch (message.type) {
      case 'pong':
        conn.lastPong = Date.now();
        break;

      case 'subscribe':
        if (message.payload?.topic) {
          conn.subscriptions.add(message.payload.topic);
          this.send(conn, {
            type: 'subscribed',
            topic: message.payload.topic,
            timestamp: Date.now(),
          });
        }
        break;

      case 'unsubscribe':
        if (message.payload?.topic) {
          conn.subscriptions.delete(message.payload.topic);
          this.send(conn, {
            type: 'unsubscribed',
            topic: message.payload.topic,
            timestamp: Date.now(),
          });
        }
        break;

      case 'request-snapshot':
        await this.sendSnapshot(conn);
        break;
    }
  }

  private async handleAuth(
    conn: DashboardConnection,
    apiKey: string | undefined,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    if (!apiKey) {
      this.send(conn, { type: 'auth-failed', error: 'API key required' });
      return;
    }

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

      // Check for dashboard:read scope
      if (!apiKeyRecord.scopes.includes('dashboard:read')) {
        this.send(conn, { type: 'auth-failed', error: 'Insufficient permissions' });
        conn.ws.close(4003, 'Insufficient permissions');
        return;
      }

      clearTimeout(authTimeout);

      // Update connection with auth info
      conn.isAuthenticated = true;
      conn.tenantId = apiKeyRecord.tenantId;
      conn.sharingPreference = apiKeyRecord.tenant.sharingPreference as SharingPreference;
      conn.isFleetAdmin = apiKeyRecord.scopes.includes('fleet:admin');
      conn.apiKeyId = apiKeyRecord.id; // Store for revalidation (WS2-002)

      // Set default subscriptions after auth
      conn.subscriptions = new Set(['campaigns', 'threats', 'blocklist']);

      // Update API key last used
      await this.prisma.apiKey.update({
        where: { id: apiKeyRecord.id },
        data: { lastUsedAt: new Date() },
      });

      this.send(conn, {
        type: 'auth-success',
        sessionId: conn.id,
        tenantId: conn.tenantId,
        isFleetAdmin: conn.isFleetAdmin,
        subscriptions: Array.from(conn.subscriptions),
        timestamp: Date.now(),
      });

      this.logger.info(
        { connectionId: conn.id, tenantId: conn.tenantId, isFleetAdmin: conn.isFleetAdmin },
        'Dashboard authenticated'
      );

      // Send initial snapshot after auth
      await this.sendSnapshot(conn);
    } catch (error) {
      this.logger.error({ error }, 'Dashboard auth failed');
      this.send(conn, { type: 'auth-failed', error: 'Auth error' });
    }
  }

  private async sendSnapshot(conn: DashboardConnection): Promise<void> {
    if (!conn.isAuthenticated) return;

    try {
      // Build tenant filter based on permissions and sharing preferences
      // Fleet admins can see all data; regular users only see their tenant + cross-tenant (if opted in)
      const canReceive = conn.isFleetAdmin ||
        conn.sharingPreference === 'CONTRIBUTE_AND_RECEIVE' ||
        conn.sharingPreference === 'RECEIVE_ONLY';

      const tenantFilter = conn.isFleetAdmin
        ? undefined // No filter = see all
        : conn.tenantId
          ? { OR: [{ tenantId: conn.tenantId }, ...(canReceive ? [{ isCrossTenant: true }] : [])] }
          : (canReceive ? { isCrossTenant: true } : { id: 'none' });

      const threatTenantFilter = conn.isFleetAdmin
        ? undefined
        : conn.tenantId
          ? { OR: [{ tenantId: conn.tenantId }, ...(canReceive ? [{ isFleetThreat: true }] : [])] }
          : (canReceive ? { isFleetThreat: true } : { id: 'none' });

      const sensorTenantFilter = conn.isFleetAdmin
        ? undefined
        : conn.tenantId
          ? { tenantId: conn.tenantId }
          : undefined;

      const [activeCampaigns, recentThreats, sensorStats, discoveryCount, violationCount] = await Promise.all([
        this.prisma.campaign.findMany({
          where: {
            status: 'ACTIVE',
            ...tenantFilter,
          },
          take: 50,
          orderBy: { lastActivityAt: 'desc' },
        }),
        this.prisma.threat.findMany({
          where: threatTenantFilter,
          take: 100,
          orderBy: { lastSeenAt: 'desc' },
        }),
        this.prisma.sensor.groupBy({
          by: ['connectionState'],
          _count: { id: true },
          where: sensorTenantFilter,
        }),
        this.prisma.signal.count({
          where: {
            signalType: 'TEMPLATE_DISCOVERY',
            createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            ...(conn.isFleetAdmin ? {} : { tenantId: conn.tenantId || undefined }),
          },
        }),
        this.prisma.signal.count({
          where: {
            signalType: 'SCHEMA_VIOLATION',
            createdAt: { gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
            ...(conn.isFleetAdmin ? {} : { tenantId: conn.tenantId || undefined }),
          },
        }),
      ]);

      this.send(conn, {
        type: 'snapshot',
        data: {
          activeCampaigns,
          recentThreats,
          sensorStats: sensorStats.reduce(
            (acc, s) => ({ ...acc, [s.connectionState]: s._count.id }),
            {} as Record<string, number>
          ),
          apiStats: {
            discoveryEvents: discoveryCount,
            schemaViolations: violationCount,
          },
        },
        timestamp: Date.now(),
        sequenceId: this.nextSequenceId(),
      });
    } catch (error) {
      this.logger.error({ error }, 'Failed to send snapshot');
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      const now = Date.now();
      const staleThreshold = this.config.heartbeatIntervalMs * 2;

      for (const [id, conn] of this.connections) {
        if (now - conn.lastPong > staleThreshold) {
          this.logger.warn({ connectionId: id }, 'Removing stale dashboard connection');
          conn.ws.close(1000, 'Heartbeat timeout');
          this.connections.delete(id);
          continue;
        }

        if (conn.isAuthenticated) {
          this.send(conn, { type: 'ping', timestamp: now });
        }
      }
    }, this.config.heartbeatIntervalMs);
  }

  /**
   * Periodic token revalidation (WS2-002)
   * Checks if API keys have been revoked or expired since authentication.
   * Disconnects clients with invalid tokens within 5 minutes.
   */
  private startTokenRevalidation(): void {
    this.revalidateInterval = setInterval(async () => {
      const authenticatedConns = Array.from(this.connections.entries())
        .filter(([, conn]) => conn.isAuthenticated && conn.apiKeyId);

      if (authenticatedConns.length === 0) return;

      // Batch fetch API key status for all authenticated connections
      const apiKeyIds = authenticatedConns.map(([, conn]) => conn.apiKeyId!);

      try {
        const validKeys = await this.prisma.apiKey.findMany({
          where: {
            id: { in: apiKeyIds },
            isRevoked: false,
            OR: [
              { expiresAt: null },
              { expiresAt: { gt: new Date() } },
            ],
          },
          select: { id: true },
        });

        const validKeyIds = new Set(validKeys.map((k) => k.id));

        // Disconnect connections with invalid tokens
        for (const [id, conn] of authenticatedConns) {
          if (!conn.apiKeyId || !validKeyIds.has(conn.apiKeyId)) {
            this.logger.warn(
              { connectionId: id, apiKeyId: conn.apiKeyId },
              'Disconnecting client with revoked/expired token'
            );
            this.send(conn, {
              type: 'auth-revoked',
              error: 'API key has been revoked or expired',
              timestamp: Date.now(),
            });
            conn.ws.close(4001, 'Token revoked');
            this.connections.delete(id);
            this.rateLimiter.removeConnection(id);
          }
        }
      } catch (error) {
        this.logger.error({ error }, 'Token revalidation failed');
      }
    }, TOKEN_REVALIDATE_INTERVAL_MS);
  }

  private send(conn: DashboardConnection, message: Record<string, unknown>): void {
    this.safeSend(conn, JSON.stringify(message));
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

  // ============================================
  // Broadcast Methods (called by Broadcaster)
  // ============================================

  /**
   * Broadcast campaign alert to authenticated dashboards
   */
  broadcastCampaignAlert(alert: CampaignAlert): void {
    this.broadcast(
      'campaigns',
      {
        type: 'campaign-alert',
        data: alert,
        timestamp: Date.now(),
        sequenceId: this.nextSequenceId(),
      },
      {
        tenantId: alert.campaign.tenantId,
        isFleetEvent: alert.campaign.isCrossTenant,
      }
    );
  }

  /**
   * Broadcast threat alert to dashboards
   */
  broadcastThreatAlert(alert: ThreatAlert): void {
    this.broadcast(
      'threats',
      {
        type: 'threat-alert',
        data: alert,
        timestamp: Date.now(),
        sequenceId: this.nextSequenceId(),
      },
      {
        tenantId: alert.threat.tenantId,
        isFleetEvent: alert.threat.isFleetThreat,
      }
    );
  }

  /**
   * Broadcast blocklist update
   */
  broadcastBlocklistUpdate(update: { updates: BlocklistUpdate[]; campaign?: string }): void {
    // Determine if this is a fleet-wide block (source: FLEET_INTEL)
    // For now, we treat FLEET_INTEL blocks as fleet events
    const isFleetEvent = update.updates.some((u) => u.source === 'FLEET_INTEL');

    this.broadcast(
      'blocklist',
      {
        type: 'blocklist-update',
        data: update,
        timestamp: Date.now(),
        sequenceId: this.nextSequenceId(),
      },
      { isFleetEvent }
    );
  }

  /**
   * Safely send a message to a WebSocket connection
   * Handles errors and removes stale connections
   */
  private safeSend(conn: DashboardConnection, payload: string): boolean {
    try {
      if (conn.ws.readyState !== WebSocket.OPEN) {
        // Connection is not open, remove it
        this.connections.delete(conn.id);
        return false;
      }
      conn.ws.send(payload);
      return true;
    } catch (error) {
      this.logger.error(
        { connectionId: conn.id, error },
        'Failed to send message, removing connection'
      );
      this.connections.delete(conn.id);
      return false;
    }
  }

  /**
   * Broadcast to authenticated connections subscribed to a topic with tenant isolation
   * and sharing preference enforcement.
   */
  private broadcast(
    topic: string,
    message: Record<string, unknown>,
    options: { tenantId?: string; isFleetEvent?: boolean } = {}
  ): void {
    const payload = JSON.stringify(message);

    for (const conn of this.connections.values()) {
      if (!conn.isAuthenticated || !conn.subscriptions.has(topic)) {
        continue;
      }

      // 1. Fleet Admin always gets everything
      if (conn.isFleetAdmin) {
        this.safeSend(conn, payload);
        continue;
      }

      // 2. Handle Fleet Events (cross-tenant campaigns, fleet threats)
      if (options.isFleetEvent) {
        const canReceive =
          conn.sharingPreference === 'CONTRIBUTE_AND_RECEIVE' ||
          conn.sharingPreference === 'RECEIVE_ONLY';

        if (canReceive) {
          this.safeSend(conn, payload);
        }
        continue;
      }

      // 3. Handle Tenant-Specific Events
      if (options.tenantId === conn.tenantId) {
        this.safeSend(conn, payload);
      }
    }
  }

  /**
   * Broadcast to all authenticated connections (regardless of subscriptions)
   */
  broadcastAll(message: Record<string, unknown>): void {
    const payload = JSON.stringify(message);

    for (const conn of this.connections.values()) {
      if (conn.isAuthenticated) {
        this.safeSend(conn, payload);
      }
    }
  }

  /**
   * Broadcast to all authenticated connections for a specific tenant
   * Also sends to fleet admins who can see all tenants
   */
  broadcastToTenant(tenantId: string, message: Record<string, unknown>): void {
    const payload = JSON.stringify(message);

    for (const conn of this.connections.values()) {
      if (
        conn.isAuthenticated &&
        (conn.tenantId === tenantId || conn.isFleetAdmin)
      ) {
        this.safeSend(conn, payload);
      }
    }
  }

  getConnectionCount(): number {
    return Array.from(this.connections.values()).filter((c) => c.isAuthenticated).length;
  }

  getStats(): { total: number; authenticated: number; byTenant: Record<string, number> } {
    const byTenant: Record<string, number> = { fleet: 0 };
    let authenticated = 0;

    for (const conn of this.connections.values()) {
      if (conn.isAuthenticated) {
        authenticated++;
        if (conn.isFleetAdmin) {
          byTenant.fleet++;
        } else if (conn.tenantId) {
          byTenant[conn.tenantId] = (byTenant[conn.tenantId] || 0) + 1;
        }
      }
    }

    return { total: this.connections.size, authenticated, byTenant };
  }
}
