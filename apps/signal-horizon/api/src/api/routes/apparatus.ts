/**
 * Apparatus Integration Routes
 *
 * Proxies drill, autopilot, and other Apparatus operations through
 * the Horizon API. All routes require authentication and check that
 * the ApparatusService is connected before forwarding requests.
 */

import { Router, type Request, type Response } from 'express';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';
import { sendProblem } from '../../lib/problem-details.js';
import type { ApparatusService } from '../../services/apparatus.js';

// =============================================================================
// Route Factory
// =============================================================================

export interface ApparatusRouteOptions {
  apparatusService: ApparatusService;
}

export function createApparatusRoutes(
  logger: Logger,
  options: ApparatusRouteOptions,
): Router {
  const router = Router();
  const { apparatusService } = options;
  const log = logger.child({ routes: 'apparatus' });

  /** Guard: require Apparatus to be connected */
  function requireApparatus(_req: Request, res: Response, next: () => void): void {
    if (!apparatusService.enabled) {
      sendProblem(res, 503, 'Apparatus integration is not configured (APPARATUS_URL not set)');
      return;
    }
    if (!apparatusService.isConnected) {
      sendProblem(res, 503, 'Apparatus is not connected', {
        details: { state: apparatusService.connectionState },
      });
      return;
    }
    next();
  }

  // ===========================================================================
  // Status
  // ===========================================================================

  /**
   * GET /status — Apparatus connection status (no auth required for health checks)
   */
  router.get('/status', (_req, res) => {
    res.json(apparatusService.getStatus());
  });

  // ===========================================================================
  // Drills
  // ===========================================================================

  /**
   * GET /drills — List available drill definitions
   */
  router.get('/drills', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const drills = await client.drills.list();
      res.json(drills);
    } catch (err) {
      log.error({ err }, 'Failed to list drills');
      sendProblem(res, 502, 'Failed to fetch drills from Apparatus');
    }
  });

  /**
   * POST /drills/:drillId/run — Launch a drill
   */
  router.post('/drills/:drillId/run', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const result = await client.drills.run(req.params.drillId);
      log.info({ drillId: req.params.drillId, runId: result.runId }, 'Drill launched');
      res.status(202).json(result);
    } catch (err) {
      log.error({ err, drillId: req.params.drillId }, 'Failed to launch drill');
      sendProblem(res, 502, 'Failed to launch drill');
    }
  });

  /**
   * GET /drills/:drillId/status — Get drill run status
   */
  router.get('/drills/:drillId/status', requireScope('fleet:read'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const runId = typeof req.query.runId === 'string' ? req.query.runId : undefined;
      const status = await client.drills.status(req.params.drillId, runId);
      res.json(status);
    } catch (err) {
      log.error({ err, drillId: req.params.drillId }, 'Failed to get drill status');
      sendProblem(res, 502, 'Failed to fetch drill status');
    }
  });

  /**
   * POST /drills/:drillId/detect — Mark threat as detected
   */
  router.post('/drills/:drillId/detect', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const runId = typeof req.body?.runId === 'string' ? req.body.runId : undefined;
      const result = await client.drills.markDetected(req.params.drillId, runId);
      log.info({ drillId: req.params.drillId }, 'Drill detection marked');
      res.json(result);
    } catch (err) {
      log.error({ err, drillId: req.params.drillId }, 'Failed to mark detection');
      sendProblem(res, 502, 'Failed to mark detection');
    }
  });

  /**
   * POST /drills/:drillId/cancel — Cancel active drill
   */
  router.post('/drills/:drillId/cancel', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const runId = typeof req.body?.runId === 'string' ? req.body.runId : undefined;
      const result = await client.drills.cancel(req.params.drillId, runId);
      log.info({ drillId: req.params.drillId }, 'Drill cancelled');
      res.json(result);
    } catch (err) {
      log.error({ err, drillId: req.params.drillId }, 'Failed to cancel drill');
      sendProblem(res, 502, 'Failed to cancel drill');
    }
  });

  /**
   * GET /drills/:drillId/debrief — Get post-drill score and timeline
   */
  router.get('/drills/:drillId/debrief', requireScope('fleet:read'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const runId = typeof req.query.runId === 'string' ? req.query.runId : undefined;
      const debrief = await client.drills.debrief(req.params.drillId, runId);
      res.json(debrief);
    } catch (err) {
      log.error({ err, drillId: req.params.drillId }, 'Failed to get debrief');
      sendProblem(res, 502, 'Failed to fetch drill debrief');
    }
  });

  return router;
}
