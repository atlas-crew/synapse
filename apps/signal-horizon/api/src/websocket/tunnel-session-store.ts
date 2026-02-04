/**
 * In-memory tunnel session store for user connections.
 *
 * NOTE: This is a temporary in-memory store. Replace with Redis or DB-backed
 * sessions for production to survive restarts and enable horizontal scaling.
 */

export type TunnelUserSessionType = 'shell' | 'dashboard' | 'logs';

export type TunnelUserSessionStatus =
  | 'pending'
  | 'connected'
  | 'disconnected'
  | 'error';

export interface TunnelUserSession {
  sessionId: string;
  sensorId: string;
  tenantId: string;
  userId: string;
  type: TunnelUserSessionType;
  status: TunnelUserSessionStatus;
  createdAt: string;
  lastActivity: string | null;
  expiresAt?: number;
}

const sessions = new Map<string, TunnelUserSession>();

export function createTunnelSession(session: TunnelUserSession): TunnelUserSession {
  sessions.set(session.sessionId, session);
  return session;
}

export function getTunnelSession(sessionId: string): TunnelUserSession | undefined {
  return sessions.get(sessionId);
}

export function listTunnelSessions(tenantId: string): TunnelUserSession[] {
  return Array.from(sessions.values()).filter((session) => session.tenantId === tenantId);
}

export function updateTunnelSession(
  sessionId: string,
  patch: Partial<TunnelUserSession>
): TunnelUserSession | undefined {
  const session = sessions.get(sessionId);
  if (!session) return undefined;
  const updated = { ...session, ...patch };
  sessions.set(sessionId, updated);
  return updated;
}

export function removeTunnelSession(sessionId: string): boolean {
  return sessions.delete(sessionId);
}

export function clearTunnelSessions(): void {
  sessions.clear();
}
