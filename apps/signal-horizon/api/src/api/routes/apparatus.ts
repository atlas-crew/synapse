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

  // ===========================================================================
  // Autopilot (AI Red Team)
  // ===========================================================================

  /** GET /autopilot/config — available tools and safety defaults */
  router.get('/autopilot/config', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.autopilot.config());
    } catch (err) {
      log.error({ err }, 'Failed to get autopilot config');
      sendProblem(res, 502, 'Failed to fetch autopilot config');
    }
  });

  /** POST /autopilot/start — launch a red team session */
  router.post('/autopilot/start', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const result = await client.autopilot.start(req.body);
      log.info({ sessionId: result.sessionId }, 'Autopilot session started');
      res.status(202).json(result);
    } catch (err) {
      log.error({ err }, 'Failed to start autopilot');
      sendProblem(res, 502, 'Failed to start autopilot session');
    }
  });

  /** GET /autopilot/status — current session state */
  router.get('/autopilot/status', requireScope('fleet:read'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const sessionId = typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined;
      res.json(await client.autopilot.status(sessionId));
    } catch (err) {
      log.error({ err }, 'Failed to get autopilot status');
      sendProblem(res, 502, 'Failed to fetch autopilot status');
    }
  });

  /** POST /autopilot/stop — graceful stop */
  router.post('/autopilot/stop', requireScope('fleet:write'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.autopilot.stop());
    } catch (err) {
      log.error({ err }, 'Failed to stop autopilot');
      sendProblem(res, 502, 'Failed to stop autopilot');
    }
  });

  /** POST /autopilot/kill — force kill */
  router.post('/autopilot/kill', requireScope('fleet:write'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.autopilot.kill());
    } catch (err) {
      log.error({ err }, 'Failed to kill autopilot');
      sendProblem(res, 502, 'Failed to kill autopilot');
    }
  });

  /** GET /autopilot/reports — session reports */
  router.get('/autopilot/reports', requireScope('fleet:read'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const sessionId = typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined;
      res.json(await client.autopilot.reports(sessionId));
    } catch (err) {
      log.error({ err }, 'Failed to get autopilot reports');
      sendProblem(res, 502, 'Failed to fetch autopilot reports');
    }
  });

  // ===========================================================================
  // Scenarios
  // ===========================================================================

  /** GET /scenarios — list saved scenarios */
  router.get('/scenarios', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.scenarios.list());
    } catch (err) {
      log.error({ err }, 'Failed to list scenarios');
      sendProblem(res, 502, 'Failed to fetch scenarios');
    }
  });

  /** POST /scenarios — create/save a scenario */
  router.post('/scenarios', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.status(201).json(await client.scenarios.save(req.body));
    } catch (err) {
      log.error({ err }, 'Failed to save scenario');
      sendProblem(res, 502, 'Failed to save scenario');
    }
  });

  /** POST /scenarios/:id/run — execute a scenario */
  router.post('/scenarios/:id/run', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const result = await client.scenarios.run(req.params.id);
      log.info({ scenarioId: req.params.id, executionId: result.executionId }, 'Scenario started');
      res.status(202).json(result);
    } catch (err) {
      log.error({ err, scenarioId: req.params.id }, 'Failed to run scenario');
      sendProblem(res, 502, 'Failed to run scenario');
    }
  });

  /** GET /scenarios/:id/status — execution progress */
  router.get('/scenarios/:id/status', requireScope('fleet:read'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const executionId = typeof req.query.executionId === 'string' ? req.query.executionId : undefined;
      res.json(await client.scenarios.status(req.params.id, executionId));
    } catch (err) {
      log.error({ err, scenarioId: req.params.id }, 'Failed to get scenario status');
      sendProblem(res, 502, 'Failed to fetch scenario status');
    }
  });

  // ===========================================================================
  // Chaos Engineering
  // ===========================================================================

  /** POST /chaos/cpu-spike — trigger CPU stress */
  router.post('/chaos/cpu-spike', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.chaos.cpuSpike(req.body));
    } catch (err) {
      log.error({ err }, 'Failed to trigger CPU spike');
      sendProblem(res, 502, 'Failed to trigger CPU spike');
    }
  });

  /** POST /chaos/memory-spike — trigger memory pressure */
  router.post('/chaos/memory-spike', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.chaos.memorySpike(req.body));
    } catch (err) {
      log.error({ err }, 'Failed to trigger memory spike');
      sendProblem(res, 502, 'Failed to trigger memory spike');
    }
  });

  /** POST /chaos/memory-clear — release allocated memory */
  router.post('/chaos/memory-clear', requireScope('fleet:write'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.chaos.memoryClear());
    } catch (err) {
      log.error({ err }, 'Failed to clear memory');
      sendProblem(res, 502, 'Failed to clear memory');
    }
  });

  /** GET /chaos/ghost — ghost traffic status */
  router.get('/chaos/ghost', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.traffic.status());
    } catch (err) {
      log.error({ err }, 'Failed to get ghost traffic status');
      sendProblem(res, 502, 'Failed to fetch ghost traffic status');
    }
  });

  /** POST /chaos/ghost/start — start background traffic */
  router.post('/chaos/ghost/start', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.traffic.start(req.body));
    } catch (err) {
      log.error({ err }, 'Failed to start ghost traffic');
      sendProblem(res, 502, 'Failed to start ghost traffic');
    }
  });

  /** POST /chaos/ghost/stop — stop ghost traffic */
  router.post('/chaos/ghost/stop', requireScope('fleet:write'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.traffic.stop());
    } catch (err) {
      log.error({ err }, 'Failed to stop ghost traffic');
      sendProblem(res, 502, 'Failed to stop ghost traffic');
    }
  });

  // ===========================================================================
  // Defense (Tarpit + Deception + MTD)
  // ===========================================================================

  /** GET /defense/tarpit — list trapped IPs */
  router.get('/defense/tarpit', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.defense.listTrapped());
    } catch (err) {
      log.error({ err }, 'Failed to list tarpit');
      sendProblem(res, 502, 'Failed to fetch tarpit data');
    }
  });

  /** POST /defense/tarpit/:ip/release — release an IP */
  router.post('/defense/tarpit/:ip/release', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.defense.release(req.params.ip));
    } catch (err) {
      log.error({ err, ip: req.params.ip }, 'Failed to release IP');
      sendProblem(res, 502, 'Failed to release IP from tarpit');
    }
  });

  /** GET /defense/deception — honeypot event history */
  router.get('/defense/deception', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.defense.deceptionHistory());
    } catch (err) {
      log.error({ err }, 'Failed to get deception history');
      sendProblem(res, 502, 'Failed to fetch deception history');
    }
  });

  /** GET /defense/mtd — MTD status */
  router.get('/defense/mtd', requireScope('fleet:read'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.mtd.status());
    } catch (err) {
      log.error({ err }, 'Failed to get MTD status');
      sendProblem(res, 502, 'Failed to fetch MTD status');
    }
  });

  /** POST /defense/mtd/rotate — force MTD rotation */
  router.post('/defense/mtd/rotate', requireScope('fleet:write'), requireApparatus, async (_req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.mtd.rotate());
    } catch (err) {
      log.error({ err }, 'Failed to rotate MTD');
      sendProblem(res, 502, 'Failed to rotate MTD profile');
    }
  });

  // ===========================================================================
  // Forensics
  // ===========================================================================

  /** POST /forensics/pcap — start packet capture */
  router.post('/forensics/pcap', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      const buffer = await client.forensics.pcap(req.body);
      res.type('application/vnd.tcpdump.pcap').send(Buffer.from(buffer));
    } catch (err) {
      log.error({ err }, 'Failed to start PCAP');
      sendProblem(res, 502, 'Failed to start packet capture');
    }
  });

  /** POST /forensics/har/replay — replay a HAR file */
  router.post('/forensics/har/replay', requireScope('fleet:write'), requireApparatus, async (req, res) => {
    try {
      const client = apparatusService.getClient()!;
      res.json(await client.forensics.replay(req.body));
    } catch (err) {
      log.error({ err }, 'Failed to replay HAR');
      sendProblem(res, 502, 'Failed to replay HAR file');
    }
  });

  return router;
}
