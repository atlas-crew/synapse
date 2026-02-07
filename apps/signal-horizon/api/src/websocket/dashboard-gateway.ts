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
import { config as globalConfig } from '../config.js';
import { verifyAndDecodeToken } from '../lib/jwt.js';
import type {
  CampaignAlert,
  ThreatAlert,
  BlocklistUpdate,
  SharingPreference,
} from '../types/protocol.js';
import {
  validateDashboardMessage,
  DashboardBroadcastEnvelopeSchema,
  type DashboardBroadcastEnvelope,
  type ValidatedDashboardMessage,
} from '../schemas/signal.js';
import { WebSocketRateLimiter } from '../lib/ws-rate-limiter.js';
import type { RedisPubSub } from '../storage/redis/pubsub.js';

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

/**
 * Manages WebSocket subscription rooms for efficient broadcasting. (labs-s2gc)
 */
class SubscriptionManager {
  // topic -> Set of connection IDs
  private topicRooms: Map<string, Set<string>> = new Map();
  // tenantId -> Set of connection IDs
  private tenantRooms: Map<string, Set<string>> = new Map();
  // Set of connection IDs for fleet admins
  private fleetAdminRoom: Set<string> = new Set();

  subscribe(connectionId: string, topic: string, tenantId: string | null, isFleetAdmin: boolean) {
    // Add to topic room
    if (!this.topicRooms.has(topic)) {
      this.topicRooms.set(topic, new Set());
    }
    this.topicRooms.get(topic)!.add(connectionId);

    // Add to tenant room or fleet admin room
    if (isFleetAdmin) {
      this.fleetAdminRoom.add(connectionId);
    } else if (tenantId) {
      if (!this.tenantRooms.has(tenantId)) {
        this.tenantRooms.set(tenantId, new Set());
      }
      this.tenantRooms.get(tenantId)!.add(connectionId);
    }
  }

  unsubscribe(connectionId: string, topic: string) {
    this.topicRooms.get(topic)?.delete(connectionId);
  }

  removeConnection(connectionId: string) {
    for (const room of this.topicRooms.values()) {
      room.delete(connectionId);
    }
    for (const room of this.tenantRooms.values()) {
      room.delete(connectionId);
    }
    this.fleetAdminRoom.delete(connectionId);
  }

  /**
   * Get subscribers for a specific topic and tenant.
   */
  getSubscribers(topic: string, tenantId?: string, isFleetEvent?: boolean): string[] {
    const topicSubscribers = this.topicRooms.get(topic);
    if (!topicSubscribers || topicSubscribers.size === 0) return [];

    const result = new Set<string>();

    // 1. Fleet admins subscribed to this topic get everything
    for (const connId of this.fleetAdminRoom) {
      if (topicSubscribers.has(connId)) {
        result.add(connId);
      }
    }

    // 2. If it's a fleet event, all topic subscribers who can receive fleet data get it
    // Note: Filtering by SharingPreference still needs to happen in broadcast() 
    // unless we track that in rooms too. For now, we'll return all candidates.
    if (isFleetEvent) {
      for (const connId of topicSubscribers) {
        result.add(connId);
      }
    } else if (tenantId) {
      // 3. Tenant-specific event: only subscribers in that tenant's room
      const tenantSubscribers = this.tenantRooms.get(tenantId);
      if (tenantSubscribers) {
        for (const connId of tenantSubscribers) {
          if (topicSubscribers.has(connId)) {
            result.add(connId);
          }
        }
      }
    }

    return Array.from(result);
  }
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

/** labs-2rf9.15: Maximum WebSocket send buffer before applying backpressure (1MB) */
const MAX_SEND_BUFFER_BYTES = 1024 * 1024;

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
  /** Subscription manager for efficient broadcasting (labs-s2gc) */
  private subscriptionManager: SubscriptionManager;
  private pubsub: RedisPubSub | null = null;
  private readonly instanceId = randomUUID();
  private readonly BROADCAST_CHANNEL = 'dashboard-broadcast';

  constructor(
    prisma: PrismaClient,
    logger: Logger,
    config: DashboardGatewayConfig,
    pubsub?: RedisPubSub
  ) {
    this.prisma = prisma;
    this.logger = logger.child({ gateway: 'dashboard' });
    this.config = config;
    this.subscriptionManager = new SubscriptionManager();
    this.pubsub = pubsub ?? null;

    if (this.pubsub) {
      void this.pubsub.subscribe(this.BROADCAST_CHANNEL, (_channel, message) => {
        try {
          const parsed = JSON.parse(message);
          // labs-2rf9.10: Validate broadcast envelope before acting on payload
          const result = DashboardBroadcastEnvelopeSchema.safeParse(parsed);
          if (!result.success) {
            this.logger.warn(
              { errors: result.error.issues.map(i => i.message) },
              'Rejected invalid dashboard broadcast envelope'
            );
            return;
          }
          const envelope = result.data;
          if (envelope.senderId !== this.instanceId) {
            this.handleRemoteBroadcast(envelope);
          }
        } catch (error) {
          this.logger.error({ error }, 'Failed to handle remote broadcast');
        }
      });
    }

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

  async handleUpgrade(req: IncomingMessage, socket: Socket, head: Buffer): Promise<void> {
    if (!this.wss) {
      socket.destroy();
      return;
    }

    try {
      const url = new URL(req.url || '', `http://${req.headers.host}`);
      const apiKey = url.searchParams.get('apiKey');
      const token = url.searchParams.get('token');

      // labs-8awg: Allow unauthenticated upgrade to support first-message auth protocol
      // If no credentials provided, proceed to connection handler which enforces auth via timeout
      if (!apiKey && !token) {
        this.wss.handleUpgrade(req, socket, head, (ws) => {
          this.wss?.emit('connection', ws, req);
        });
        return;
      }

      if (token) {
        const secret = globalConfig.telemetry.jwtSecret;
        if (!secret) throw new Error('Server configuration error');

        const jwtResult = await verifyAndDecodeToken(token, secret, this.prisma, {
          audience: 'signal-horizon',
          source: 'ws-dashboard',
          logger: this.logger,
        });
        if (!jwtResult.ok) throw new Error(jwtResult.error === 'revoked' ? 'Token revoked' : 'Invalid token');
      } else if (apiKey) {
        const keyHash = await this.hashApiKey(apiKey);
        const apiKeyRecord = await this.prisma.apiKey.findUnique({
          where: { keyHash },
          select: { isRevoked: true, scopes: true }
        });

        if (!apiKeyRecord || apiKeyRecord.isRevoked || !apiKeyRecord.scopes.includes('dashboard:read')) {
          throw new Error('Invalid API key');
        }
      }

      this.wss.handleUpgrade(req, socket, head, (ws) => {
        this.wss?.emit('connection', ws, req);
      });
    } catch (error) {
      this.logger.warn({ ip: socket.remoteAddress, error }, 'WebSocket upgrade authentication failed');
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
    }
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
      this.subscriptionManager.removeConnection(connectionId); // labs-s2gc: Clean up subscriptions
      this.rateLimiter.removeConnection(connectionId); // Clean up rate limiter state
      this.logger.info({ connectionId }, 'Dashboard disconnected');
    });

    ws.on('error', (error) => {
      this.logger.error({ error, connectionId }, 'Dashboard connection error');
      clearTimeout(authTimeout);
      this.connections.delete(connectionId);
      this.subscriptionManager.removeConnection(connectionId); // labs-s2gc
    });
  }

  private async handleMessage(
    conn: DashboardConnection,
    message: ValidatedDashboardMessage,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    // Auth message is always allowed
    if (message.type === 'auth') {
      await this.handleAuth(conn, message.payload, authTimeout);
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
          // labs-s2gc: Use room-based subscriptions
          this.subscriptionManager.subscribe(
            conn.id, 
            message.payload.topic, 
            conn.tenantId, 
            conn.isFleetAdmin
          );
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
          // labs-s2gc
          this.subscriptionManager.unsubscribe(conn.id, message.payload.topic);
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
    payload: { apiKey?: string; token?: string } | undefined,
    authTimeout: NodeJS.Timeout
  ): Promise<void> {
    if (!payload || (!payload.apiKey && !payload.token)) {
      this.send(conn, { type: 'auth-failed', error: 'API key or token required' });
      return;
    }

    try {
      let tenantId: string;
      let apiKeyId: string | null = null;
      let sharingPreference: SharingPreference;
      let isFleetAdmin = false;

      if (payload.token) {
        // JWT Authentication (P1-SEC-003)
        const secret = globalConfig.telemetry.jwtSecret; // Reuse telemetry secret for now
        if (!secret) {
          this.send(conn, { type: 'auth-failed', error: 'Server configuration error' });
          return;
        }

        const jwtResult = await verifyAndDecodeToken(payload.token, secret, this.prisma, {
          audience: 'signal-horizon',
          source: 'ws-dashboard',
          logger: this.logger,
        });
        if (!jwtResult.ok) {
          this.send(conn, { type: 'auth-failed', error: jwtResult.error === 'revoked' ? 'Token revoked' : 'Invalid or expired token' });
          return;
        }

        tenantId = jwtResult.tenantId;
        isFleetAdmin = jwtResult.payload.scopes?.includes('fleet:admin') ?? false;

        // Fetch tenant details
        const tenant = await this.prisma.tenant.findUnique({
          where: { id: tenantId },
          select: { sharingPreference: true },
        });

        if (!tenant) {
          this.send(conn, { type: 'auth-failed', error: 'Tenant not found' });
          return;
        }

        sharingPreference = tenant.sharingPreference as SharingPreference;
      } else if (payload.apiKey) {
        // Legacy API Key Authentication
        const keyHash = await this.hashApiKey(payload.apiKey);
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

        tenantId = apiKeyRecord.tenantId;
        apiKeyId = apiKeyRecord.id;
        sharingPreference = apiKeyRecord.tenant.sharingPreference as SharingPreference;
        isFleetAdmin = apiKeyRecord.scopes.includes('fleet:admin');
      } else {
        return; // Should not happen due to guard above
      }

      clearTimeout(authTimeout);

      // Update connection with auth info
      conn.isAuthenticated = true;
      conn.tenantId = tenantId;
      conn.sharingPreference = sharingPreference;
      conn.isFleetAdmin = isFleetAdmin;
      conn.apiKeyId = apiKeyId; // Store for revalidation (WS2-002)

      // labs-s2gc: Initialize room-based subscriptions with defaults
      const defaultTopics = ['campaigns', 'threats', 'blocklist'];
      conn.subscriptions = new Set(defaultTopics);
      for (const topic of defaultTopics) {
        this.subscriptionManager.subscribe(conn.id, topic, conn.tenantId, conn.isFleetAdmin);
      }

      // Update API key last used if applicable
      if (apiKeyId) {
        await this.prisma.apiKey.update({
          where: { id: apiKeyId },
          data: { lastUsedAt: new Date() },
        });
      }

      this.send(conn, {
        type: 'auth-success',
        sessionId: conn.id,
        tenantId: conn.tenantId,
        isFleetAdmin: conn.isFleetAdmin,
        subscriptions: Array.from(conn.subscriptions),
        timestamp: Date.now(),
      });

      this.logger.info(
        { 
          connectionId: conn.id, 
          tenantId: conn.tenantId, 
          isFleetAdmin: conn.isFleetAdmin,
          authType: payload.token ? 'JWT' : 'API_KEY'
        },
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

      // labs-2rf9.15: Check backpressure before sending
      if (conn.ws.bufferedAmount > MAX_SEND_BUFFER_BYTES) {
        this.logger.warn(
          { connectionId: conn.id, bufferedAmount: conn.ws.bufferedAmount },
          'WebSocket backpressure exceeded, disconnecting slow consumer'
        );
        conn.ws.close(1008, 'Backpressure limit exceeded');
        this.connections.delete(conn.id);
        this.subscriptionManager.removeConnection(conn.id);
        this.rateLimiter.removeConnection(conn.id);
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
    // 1. Local broadcast
    this.localBroadcast(topic, message, options);

    // 2. Distributed broadcast (via Redis)
    if (this.pubsub) {
      this.pubsub.publish(this.BROADCAST_CHANNEL, {
        topic,
        message,
        options,
        senderId: this.instanceId,
      }).catch((err) => this.logger.error({ error: err }, 'Failed to publish dashboard broadcast'));
    }
  }

  /**
   * Handle broadcast message received from another instance.
   */
  private handleRemoteBroadcast(envelope: DashboardBroadcastEnvelope): void {
    if (envelope.topic === '*') {
      // Local broadcast all
      const payload = JSON.stringify(envelope.message);
      for (const conn of this.connections.values()) {
        if (conn.isAuthenticated) {
          this.safeSend(conn, payload);
        }
      }
    } else if (envelope.topic === 'tenant-direct' && envelope.options.tenantId) {
      // Local broadcast to tenant
      const payload = JSON.stringify(envelope.message);
      const tenantId = envelope.options.tenantId;
      for (const conn of this.connections.values()) {
        if (
          conn.isAuthenticated &&
          (conn.tenantId === tenantId || conn.isFleetAdmin)
        ) {
          this.safeSend(conn, payload);
        }
      }
    } else {
      this.localBroadcast(envelope.topic, envelope.message as Record<string, unknown>, envelope.options);
    }
  }

  /**
   * Perform local broadcast to connected clients.
   */
  private localBroadcast(
    topic: string,
    message: Record<string, unknown>,
    options: { tenantId?: string; isFleetEvent?: boolean } = {}
  ): void {
    const payload = JSON.stringify(message);

    // labs-s2gc: Use SubscriptionManager to get only relevant connections
    const candidateIds = this.subscriptionManager.getSubscribers(topic, options.tenantId, options.isFleetEvent);

    for (const connId of candidateIds) {
      const conn = this.connections.get(connId);
      if (!conn || !conn.isAuthenticated || !conn.subscriptions.has(topic)) {
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

    // Local
    for (const conn of this.connections.values()) {
      if (conn.isAuthenticated) {
        this.safeSend(conn, payload);
      }
    }

    // Distributed
    if (this.pubsub) {
      this.pubsub.publish(this.BROADCAST_CHANNEL, {
        topic: '*', // special topic for all
        message,
        options: {},
        senderId: this.instanceId,
      }).catch((err) => this.logger.error({ error: err }, 'Failed to publish dashboard broadcast'));
    }
  }

  /**
   * Broadcast to all authenticated connections for a specific tenant
   * Also sends to fleet admins who can see all tenants
   */
  broadcastToTenant(tenantId: string, message: Record<string, unknown>): void {
    const payload = JSON.stringify(message);

    // Local
    for (const conn of this.connections.values()) {
      if (
        conn.isAuthenticated &&
        (conn.tenantId === tenantId || conn.isFleetAdmin)
      ) {
        this.safeSend(conn, payload);
      }
    }

    // Distributed
    if (this.pubsub) {
      this.pubsub.publish(this.BROADCAST_CHANNEL, {
        topic: 'tenant-direct',
        message,
        options: { tenantId },
        senderId: this.instanceId,
      }).catch((err) => this.logger.error({ error: err }, 'Failed to publish dashboard broadcast'));
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
