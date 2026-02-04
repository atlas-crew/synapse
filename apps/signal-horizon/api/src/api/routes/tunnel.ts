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
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { randomUUID } from 'crypto';
import { requireScope, requireRole } from '../middleware/auth.js';
import {
  createTunnelSession,
  getTunnelSession,
  listTunnelSessions,
  removeTunnelSession,
} from '../../websocket/tunnel-session-store.js';

// ============================================================================
// Zod Schemas
// ============================================================================

const TunnelSessionSchema = z.object({
  sessionId: z.string().uuid(),
  sensorId: z.string(),
  userId: z.string(),
  tenantId: z.string(),
  type: z.enum(['shell', 'dashboard', 'logs']),
  status: z.enum(['pending', 'connected', 'disconnected', 'error']),
  createdAt: z.string().datetime(),
  lastActivity: z.string().datetime().nullish(),
  expiresAt: z.number().optional(),
});

// ============================================================================
// Route Factory
// ============================================================================

export function createTunnelRoutes(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();

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
  router.post('/shell/:sensorId', requireScope('tunnel:shell'), requireRole('operator'), async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      // Verify sensor exists and belongs to tenant
      const sensor = await prisma.sensor.findFirst({
        where: { id: sensorId, tenantId },
        select: { id: true, connectionState: true, lastHeartbeat: true },
      });

      if (!sensor) {
        return res.status(404).json({ error: 'Sensor not found' });
      }

      // Check if sensor is online
      const isOnline = sensor.lastHeartbeat &&
        new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

      if (!isOnline) {
        return res.status(503).json({
          error: 'Sensor offline',
          lastHeartbeat: sensor.lastHeartbeat,
        });
      }

      // Create session
      const sessionId = randomUUID();
      const session: z.infer<typeof TunnelSessionSchema> = {
        sessionId,
        sensorId,
        userId,
        tenantId,
        type: 'shell',
        status: 'pending',
        createdAt: new Date().toISOString(),
        lastActivity: null,
        expiresAt: Date.now() + 300000,
      };

      createTunnelSession(session);
      logger.info({ sessionId, sensorId, userId }, 'Shell session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'shell',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        expiresIn: 300, // 5 minutes to connect
      });
    } catch (error) {
      logger.error({ error, sensorId }, 'Failed to create shell session');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /tunnel/dashboard/:sensorId
   * Request a new dashboard proxy session to a sensor
   *
   * Security: Requires tunnel:dashboard scope AND operator role (remote access)
   */
  router.post('/dashboard/:sensorId', requireScope('tunnel:dashboard'), requireRole('operator'), async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      // Verify sensor exists and belongs to tenant
      const sensor = await prisma.sensor.findFirst({
        where: { id: sensorId, tenantId },
        select: { id: true, connectionState: true, lastHeartbeat: true },
      });

      if (!sensor) {
        return res.status(404).json({ error: 'Sensor not found' });
      }

      // Check if sensor is online
      const isOnline = sensor.lastHeartbeat &&
        new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

      if (!isOnline) {
        return res.status(503).json({
          error: 'Sensor offline',
          lastHeartbeat: sensor.lastHeartbeat,
        });
      }

      // Create session
      const sessionId = randomUUID();
      const session: z.infer<typeof TunnelSessionSchema> = {
        sessionId,
        sensorId,
        userId,
        tenantId,
        type: 'dashboard',
        status: 'pending',
        createdAt: new Date().toISOString(),
        lastActivity: null,
        expiresAt: Date.now() + 300000,
      };

      createTunnelSession(session);
      logger.info({ sessionId, sensorId, userId }, 'Dashboard session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'dashboard',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        proxyUrl: `/api/v1/tunnel/proxy/${sessionId}`,
        expiresIn: 300, // 5 minutes to connect
      });
    } catch (error) {
      logger.error({ error, sensorId }, 'Failed to create dashboard session');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * POST /tunnel/logs/:sensorId
   * Request a new log streaming session to a sensor
   *
   * Security: Requires tunnel:read scope (logs are read-only)
   */
  router.post('/logs/:sensorId', requireScope('tunnel:read'), async (req: Request, res): Promise<Response | void> => {
    const { sensorId } = req.params;
    const tenantId = req.auth!.tenantId;
    const userId = req.auth!.userId ?? req.auth!.apiKeyId;

    try {
      // Verify sensor exists and belongs to tenant
      const sensor = await prisma.sensor.findFirst({
        where: { id: sensorId, tenantId },
        select: { id: true, connectionState: true, lastHeartbeat: true },
      });

      if (!sensor) {
        return res.status(404).json({ error: 'Sensor not found' });
      }

      // Check if sensor is online
      const isOnline = sensor.lastHeartbeat &&
        new Date().getTime() - new Date(sensor.lastHeartbeat).getTime() < 120000;

      if (!isOnline) {
        return res.status(503).json({
          error: 'Sensor offline',
          lastHeartbeat: sensor.lastHeartbeat,
        });
      }

      const sessionId = randomUUID();
      const session: z.infer<typeof TunnelSessionSchema> = {
        sessionId,
        sensorId,
        userId,
        tenantId,
        type: 'logs',
        status: 'pending',
        createdAt: new Date().toISOString(),
        lastActivity: null,
        expiresAt: Date.now() + 300000,
      };

      createTunnelSession(session);
      logger.info({ sessionId, sensorId, userId }, 'Log session created');

      return res.status(201).json({
        sessionId,
        sensorId,
        type: 'logs',
        wsUrl: `/ws/tunnel/user/${sessionId}`,
        expiresIn: 300,
      });
    } catch (error) {
      logger.error({ error, sensorId }, 'Failed to create log session');
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  /**
   * GET /tunnel/session/:sessionId
   * Get session status
   *
   * Security: Requires tunnel:read scope
   */
  router.get('/session/:sessionId', requireScope('tunnel:read'), (req: Request, res): Response => {
    const { sessionId } = req.params;
    const tenantId = req.auth!.tenantId;

    const session = getTunnelSession(sessionId);

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
  router.delete('/session/:sessionId', requireScope('tunnel:manage'), (req: Request, res): Response => {
    const { sessionId } = req.params;
    const tenantId = req.auth!.tenantId;

    const session = getTunnelSession(sessionId);

    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Verify tenant ownership
    if (session.tenantId !== tenantId) {
      return res.status(404).json({ error: 'Session not found' });
    }

    removeTunnelSession(sessionId);
    logger.info({ sessionId }, 'Session terminated');

    return res.status(204).send();
  });

  /**
   * GET /tunnel/sessions
   * List active sessions for the tenant
   *
   * Security: Requires tunnel:read scope
   */
  router.get('/sessions', requireScope('tunnel:read'), (req: Request, res): Response => {
    const tenantId = req.auth!.tenantId;

    const tenantSessions = listTunnelSessions(tenantId)
      .map(s => ({
        sessionId: s.sessionId,
        sensorId: s.sensorId,
        type: s.type,
        status: s.status,
        createdAt: s.createdAt,
        lastActivity: s.lastActivity,
      }));

    return res.json({
      sessions: tenantSessions,
      total: tenantSessions.length,
    });
  });

  return router;
}
