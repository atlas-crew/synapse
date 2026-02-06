/**
 * Tunnel Session Store
 *
 * Manages user tunnel sessions in the database with:
 * - MAX_SESSIONS limit to prevent unbounded growth
 * - TTL-based expiry for stale sessions from crashed connections
 * - Periodic cleanup interval for expired sessions
 */

import type { PrismaClient, TunnelSession } from '@prisma/client';

export type TunnelUserSessionType = 'shell' | 'dashboard' | 'logs';

export type TunnelUserSessionStatus =
  | 'pending'
  | 'connected'
  | 'disconnected'
  | 'error';

/** Maximum number of active sessions allowed globally */
const MAX_SESSIONS = 1000;

/** Maximum session TTL: 4 hours in milliseconds */
const SESSION_TTL_MS = 4 * 60 * 60 * 1000;

/** How often to run the cleanup sweep (60 seconds) */
const CLEANUP_INTERVAL_MS = 60 * 1000;

export class TunnelSessionStore {
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor(private prisma: PrismaClient) {
    this.startCleanupInterval();
  }

  async create(session: {
    id: string;
    sensorId: string;
    tenantId: string;
    userId: string;
    type: string;
    status: string;
    expiresAt?: number;
  }): Promise<TunnelSession> {
    // Enforce MAX_SESSIONS limit
    const activeCount = await this.prisma.tunnelSession.count({
      where: {
        status: { in: ['pending', 'connected'] },
      },
    });

    if (activeCount >= MAX_SESSIONS) {
      throw new TunnelSessionCapacityError(
        `Maximum tunnel sessions reached (${MAX_SESSIONS}). ` +
          'Please close existing sessions before creating new ones.'
      );
    }

    return this.prisma.tunnelSession.create({
      data: {
        id: session.id,
        sensorId: session.sensorId,
        tenantId: session.tenantId,
        userId: session.userId,
        type: session.type,
        status: session.status,
        expiresAt: session.expiresAt ? new Date(session.expiresAt) : null,
      },
    });
  }

  async get(id: string): Promise<TunnelSession | null> {
    const session = await this.prisma.tunnelSession.findUnique({
      where: { id },
    });

    if (!session) return null;

    // Check TTL expiry
    if (this.isExpired(session)) {
      await this.expireSession(id);
      return null;
    }

    return session;
  }

  async update(
    id: string,
    data: Partial<TunnelSession>
  ): Promise<TunnelSession | null> {
    try {
      return await this.prisma.tunnelSession.update({
        where: { id },
        data,
      });
    } catch {
      return null;
    }
  }

  async remove(id: string): Promise<void> {
    try {
      await this.prisma.tunnelSession.delete({
        where: { id },
      });
    } catch {
      // Ignore if already deleted
    }
  }

  async list(tenantId: string): Promise<TunnelSession[]> {
    return this.prisma.tunnelSession.findMany({
      where: { tenantId },
      orderBy: { createdAt: 'desc' },
    });
  }

  /**
   * Remove expired sessions from the database.
   * A session is expired if:
   * - Its explicit expiresAt has passed, OR
   * - It was created more than SESSION_TTL_MS ago (4 hours)
   *
   * Also marks stale pending/connected sessions as expired.
   */
  async cleanupExpired(): Promise<number> {
    const now = new Date();
    const ttlCutoff = new Date(now.getTime() - SESSION_TTL_MS);

    // Delete sessions that have an explicit expiresAt that has passed
    const explicitExpired = await this.prisma.tunnelSession.deleteMany({
      where: {
        expiresAt: { lt: now },
        NOT: { expiresAt: null },
      },
    });

    // Delete sessions older than the TTL cutoff (catches stale sessions
    // from crashed connections that never got an expiresAt)
    const staleSessions = await this.prisma.tunnelSession.deleteMany({
      where: {
        createdAt: { lt: ttlCutoff },
      },
    });

    return explicitExpired.count + staleSessions.count;
  }

  /**
   * Shut down the cleanup interval. Call on process exit.
   */
  shutdown(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  // ========================================================================
  // Private Helpers
  // ========================================================================

  /**
   * Check if a session has exceeded its TTL or explicit expiry.
   */
  private isExpired(session: TunnelSession): boolean {
    const now = Date.now();

    // Check explicit expiresAt
    if (session.expiresAt && now > session.expiresAt.getTime()) {
      return true;
    }

    // Check TTL from creation time
    if (now - session.createdAt.getTime() > SESSION_TTL_MS) {
      return true;
    }

    return false;
  }

  /**
   * Mark a single session as expired and update its status.
   */
  private async expireSession(id: string): Promise<void> {
    try {
      await this.prisma.tunnelSession.update({
        where: { id },
        data: {
          status: 'disconnected',
          lastActivity: new Date(),
        },
      });
    } catch {
      // Session may have been concurrently deleted
    }
  }

  /**
   * Start the periodic cleanup interval.
   */
  private startCleanupInterval(): void {
    this.cleanupTimer = setInterval(async () => {
      try {
        await this.cleanupExpired();
      } catch {
        // Cleanup failures are non-fatal; will retry next interval
      }
    }, CLEANUP_INTERVAL_MS);

    // Allow the Node.js process to exit even if the interval is active
    if (this.cleanupTimer && typeof this.cleanupTimer === 'object' && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }
}

/**
 * Error thrown when the tunnel session store is at capacity.
 */
export class TunnelSessionCapacityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TunnelSessionCapacityError';
  }
}
