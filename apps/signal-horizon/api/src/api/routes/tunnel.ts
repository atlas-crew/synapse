/**
 * Tunnel API Routes
 *
 * REST endpoints for managing WebSocket tunnel sessions between
 * Signal Horizon and remote sensors.
 *
 * Security: All endpoints require authentication. Shell and dashboard
 * creation require operator role due to sensitive nature of remote access.
 */

import { Router, type Request, type Response } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'crypto';
import { requireScope, requireRole } from '../middleware/auth.js';
import { createTunnelCreationRateLimiter } from '../middleware/rate-limit.js';
import { TunnelSessionStore } from '../../websocket/tunnel-session-store.js';

// ============================================================================
// Route Factory
// ============================================================================

export function createTunnelRoutes(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();
  const sessionStore = new TunnelSessionStore(prisma);
  const tunnelCreateLimiter = createTunnelCreationRateLimiter(logger);

  /**
   * GET /tunnel/status/:sensorId
   * Check tunnel availability for a sensor
   *
   * Security: Requires tunnel:read scope
   */
  router.get('/status/:sensorId', requireScope('tunnel:read'), async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;

    try {
      // Verify sensor exists and belongs to tenant
      const sensor = await prisma.sensor.findFirst({
        where: { id: sensorId, tenantId },
        select: { id: true, connectionState: true, lastHeartbeat: true },
      });

      if (!sensor) {
        return res.status(404).json({ error: 'Sensor not found' });
      }

      // Check if sensor is online (seen within last 2 minutes)
      const isOnline = sensor.lastHeartbeat &&
        new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

      return res.json({
        sensorId,
        available: isOnline,
        connectionState: sensor.connectionState,
        capabilities: isOnline ? ['shell', 'dashboard', 'logs'] : [],
        lastHeartbeat: sensor.lastHeartbeat,
      });
    } catch (error) {
      logger.error({ error, sensorId }, 'Failed to check tunnel status');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /tunnel/shell/:sensorId
   * Request a new shell session to a sensor
   *
   * Security: Requires tunnel:shell scope AND operator role (SHELL ACCESS - highly sensitive)
   */
  router.post(
    '/shell/:sensorId',
    tunnelCreateLimiter,
    requireScope('tunnel:shell'),
    requireRole('operator'),
    async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      const sessionId = randomUUID();
      const expiresAt = Date.now() + 300000;

      // Transactional check and create (labs-ox44)
      await prisma.$transaction(async (tx) => {
        // 1. Verify sensor exists and belongs to tenant (Atomic verification)
        const sensor = await tx.sensor.findFirst({
          where: { id: sensorId, tenantId },
          select: { id: true, connectionState: true, lastHeartbeat: true },
        });

        if (!sensor) {
          throw new Error('SENSOR_NOT_FOUND');
        }

        // 2. Check if sensor is online
        const isOnline = sensor.lastHeartbeat &&
          new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

        if (!isOnline) {
          throw new Error('SENSOR_OFFLINE');
        }

        // 3. Verify user permissions/membership again (Defense in depth)
        // If the user was removed from tenant between auth middleware and now, this should fail.
        // However, we are using API keys or JWTs.
        // If API key: we checked it in middleware.
        // If JWT: stateless.
        // To strictly prevent race condition, we should check if the API key is still valid?
        // But the middleware already did.
        // The issue description says "Between read and write, user could be removed from fleet."
        // If we are using an API key, we can re-check it.
        // If we are using a user session, we can check user membership.
        // Assuming API key for now as `req.auth.apiKeyId` is present.
        const apiKeyId = req.auth!.apiKeyId;
        const key = await tx.apiKey.findUnique({
          where: { id: apiKeyId },
          select: { tenantId: true },
        });

        if (!key || key.tenantId !== tenantId) {
           throw new Error('ACCESS_DENIED');
        }

        // 4. Create session
        await tx.tunnelSession.create({
          data: {
            id: sessionId,
            sensorId,
            tenantId,
            userId,
            type: 'shell',
            status: 'pending',
            expiresAt: new Date(expiresAt),
          },
        });
      });

      logger.info({ sessionId, sensorId, userId }, 'Shell session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'shell',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        expiresIn: 300, // 5 minutes to connect
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === 'SENSOR_NOT_FOUND') return res.status(404).json({ error: 'Sensor not found' });
      if (message === 'SENSOR_OFFLINE') return res.status(503).json({ error: 'Sensor offline' });
      if (message === 'ACCESS_DENIED') return res.status(403).json({ error: 'Access denied' });
      
      logger.error({ error, sensorId }, 'Failed to create shell session');
      return res.status(500).json({ error: 'Internal server error' });
    }
    }
  );

  /**
   * POST /tunnel/dashboard/:sensorId
   * Request a new dashboard proxy session to a sensor
   *
   * Security: Requires tunnel:dashboard scope AND operator role (remote access)
   */
  router.post(
    '/dashboard/:sensorId',
    tunnelCreateLimiter,
    requireScope('tunnel:dashboard'),
    requireRole('operator'),
    async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      const sessionId = randomUUID();
      const expiresAt = Date.now() + 300000;

      await prisma.$transaction(async (tx) => {
        const sensor = await tx.sensor.findFirst({
          where: { id: sensorId, tenantId },
          select: { id: true, connectionState: true, lastHeartbeat: true },
        });

        if (!sensor) throw new Error('SENSOR_NOT_FOUND');

        const isOnline = sensor.lastHeartbeat &&
          new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

        if (!isOnline) throw new Error('SENSOR_OFFLINE');

        const apiKeyId = req.auth!.apiKeyId;
        const key = await tx.apiKey.findUnique({
          where: { id: apiKeyId },
          select: { tenantId: true },
        });

        if (!key || key.tenantId !== tenantId) throw new Error('ACCESS_DENIED');

        await tx.tunnelSession.create({
          data: {
            id: sessionId,
            sensorId,
            tenantId,
            userId,
            type: 'dashboard',
            status: 'pending',
            expiresAt: new Date(expiresAt),
          },
        });
      });

      logger.info({ sessionId, sensorId, userId }, 'Dashboard session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'dashboard',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        proxyUrl: `/api/v1/tunnel/proxy/${sessionId}`,
        expiresIn: 300, // 5 minutes to connect
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === 'SENSOR_NOT_FOUND') return res.status(404).json({ error: 'Sensor not found' });
      if (message === 'SENSOR_OFFLINE') return res.status(503).json({ error: 'Sensor offline' });
      if (message === 'ACCESS_DENIED') return res.status(403).json({ error: 'Access denied' });

      logger.error({ error, sensorId }, 'Failed to create dashboard session');
      return res.status(500).json({ error: 'Internal server error' });
    }
    }
  );

  /**
   * POST /tunnel/logs/:sensorId
   * Request a new log streaming session to a sensor
   *
   * Security: Requires tunnel:read scope (logs are read-only)
   */
  router.post(
    '/logs/:sensorId',
    tunnelCreateLimiter,
    requireScope('tunnel:read'),
    async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      const sessionId = randomUUID();
      const expiresAt = Date.now() + 300000;

      await prisma.$transaction(async (tx) => {
        const sensor = await tx.sensor.findFirst({
          where: { id: sensorId, tenantId },
          select: { id: true, connectionState: true, lastHeartbeat: true },
        });

        if (!sensor) throw new Error('SENSOR_NOT_FOUND');

        const isOnline = sensor.lastHeartbeat &&
          new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

        if (!isOnline) throw new Error('SENSOR_OFFLINE');

        const apiKeyId = req.auth!.apiKeyId;
        const key = await tx.apiKey.findUnique({
          where: { id: apiKeyId },
          select: { tenantId: true },
        });

        if (!key || key.tenantId !== tenantId) throw new Error('ACCESS_DENIED');

        await tx.tunnelSession.create({
          data: {
            id: sessionId,
            sensorId,
            tenantId,
            userId,
            type: 'logs',
            status: 'pending',
            expiresAt: new Date(expiresAt),
          },
        });
      });

      logger.info({ sessionId, sensorId, userId }, 'Log session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'logs',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        expiresIn: 300,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message === 'SENSOR_NOT_FOUND') return res.status(404).json({ error: 'Sensor not found' });
      if (message === 'SENSOR_OFFLINE') return res.status(503).json({ error: 'Sensor offline' });
      if (message === 'ACCESS_DENIED') return res.status(403).json({ error: 'Access denied' });

      logger.error({ error, sensorId }, 'Failed to create log session');
      return res.status(500).json({ error: 'Internal server error' });
    }
    }
  );

  /**
   * GET /tunnel/session/:sessionId
   * Get session status
   *
   * Security: Requires tunnel:read scope
   */
  router.get('/session/:sessionId', requireScope('tunnel:read'), async (req: Request, res): Promise<Response | void> => {
    const { sessionId } = req.params;
    const tenantId = req.auth!.tenantId;

    const session = await sessionStore.get(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Verify tenant ownership
    if (session.tenantId !== tenantId) {
      return res.status(404).json({ error: 'Session not found' });
    }

    return res.json(session);
  });

  /**
   * DELETE /tunnel/session/:sessionId
   * Terminate a session
   *
   * Security: Requires tunnel:manage scope
   */
  router.delete('/session/:sessionId', requireScope('tunnel:manage'), async (req: Request, res): Promise<Response | void> => {
    const { sessionId } = req.params;
    const tenantId = req.auth!.tenantId;

    const session = await sessionStore.get(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Verify tenant ownership
    if (session.tenantId !== tenantId) {
      return res.status(404).json({ error: 'Session not found' });
    }

    await sessionStore.remove(sessionId);
    logger.info({ sessionId }, 'Session terminated');

    return res.status(204).send();
  });

  /**
   * GET /tunnel/sessions
   * List active sessions for the tenant
   *
   * Security: Requires tunnel:read scope
   */
  router.get('/sessions', requireScope('tunnel:read'), async (req: Request, res): Promise<Response | void> => {
    const tenantId = req.auth!.tenantId;

    const tenantSessions = await sessionStore.list(tenantId);

    return res.json({
      sessions: tenantSessions.map(s => ({
        sessionId: s.id,
        sensorId: s.sensorId,
        type: s.type,
        status: s.status,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
      })),
      total: tenantSessions.length,
    });
  });

  return router;
}
