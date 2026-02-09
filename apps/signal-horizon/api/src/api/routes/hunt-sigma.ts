/**
 * Sigma Background Hunting Routes
 *
 * /api/v1/hunt/sigma/...
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { authorize } from '../middleware/auth.js';
import type { SigmaHuntService } from '../../services/sigma-hunt/index.js';

const CreateRuleSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(2000).optional(),
  sqlTemplate: z.string().min(1).max(50000),
  enabled: z.boolean().optional(),
});

const UpdateRuleSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  description: z.string().max(2000).optional(),
  enabled: z.boolean().optional(),
});

const ListLeadsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(1000).optional().default(200),
});

const IdParamSchema = z.object({
  id: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/),
});

export function createHuntSigmaRoutes(
  prisma: PrismaClient,
  logger: Logger,
  sigmaHuntService: SigmaHuntService
): Router {
  const router = Router();
  const routeLogger = logger.child({ route: 'hunt-sigma' });

  const isLikelyValidationError = (error: unknown): boolean => {
    if (!(error instanceof Error)) return false;
    return /^Sigma /.test(error.message)
      || /forbidden fragment/i.test(error.message)
      || /forbidden character/i.test(error.message)
      || /must match: SELECT \*/i.test(error.message)
      || /name is required/i.test(error.message)
      || /description too long/i.test(error.message);
  };

  router.get('/rules', authorize(prisma, { scopes: 'hunt:read' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const rules = await sigmaHuntService.listRules(req.auth.tenantId);
      res.json({ success: true, data: rules, meta: { count: rules.length } });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to list sigma rules');
      res.status(500).json({ error: 'Failed to list sigma rules' });
    }
  });

  router.post('/rules', authorize(prisma, { scopes: 'hunt:write' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const parsed = CreateRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid body', details: parsed.error.errors });
        return;
      }

      const rule = await sigmaHuntService.createRule(req.auth.tenantId, parsed.data);
      res.status(201).json({ success: true, data: rule });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to create sigma rule');
      if (isLikelyValidationError(error)) {
        res.status(400).json({
          error: 'Failed to create sigma rule',
          message: error instanceof Error ? error.message : 'Invalid sigma rule',
        });
        return;
      }

      res.status(500).json({ error: 'Failed to create sigma rule' });
    }
  });

  router.patch('/rules/:id', authorize(prisma, { scopes: 'hunt:write' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const idParsed = IdParamSchema.safeParse(req.params);
      if (!idParsed.success) {
        res.status(400).json({ error: 'Invalid id', details: idParsed.error.errors });
        return;
      }

      const parsed = UpdateRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid body', details: parsed.error.errors });
        return;
      }

      const updated = await sigmaHuntService.updateRule(req.auth.tenantId, idParsed.data.id, parsed.data);
      if (!updated) {
        res.status(404).json({ error: 'Rule not found' });
        return;
      }

      res.json({ success: true, data: updated });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to update sigma rule');
      res.status(500).json({ error: 'Failed to update sigma rule' });
    }
  });

  router.delete('/rules/:id', authorize(prisma, { scopes: 'hunt:write' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const idParsed = IdParamSchema.safeParse(req.params);
      if (!idParsed.success) {
        res.status(400).json({ error: 'Invalid id', details: idParsed.error.errors });
        return;
      }

      const deleted = await sigmaHuntService.deleteRule(req.auth.tenantId, idParsed.data.id);
      if (!deleted) {
        res.status(404).json({ error: 'Rule not found' });
        return;
      }

      res.json({ success: true });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to delete sigma rule');
      res.status(500).json({ error: 'Failed to delete sigma rule' });
    }
  });

  router.get('/leads', authorize(prisma, { scopes: 'hunt:read' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const parsed = ListLeadsQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid query parameters', details: parsed.error.errors });
        return;
      }

      const leads = await sigmaHuntService.listLeads(req.auth.tenantId, parsed.data.limit);
      res.json({ success: true, data: leads, meta: { count: leads.length, limit: parsed.data.limit } });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to list sigma leads');
      res.status(500).json({ error: 'Failed to list sigma leads' });
    }
  });

  router.post('/leads/:id/ack', authorize(prisma, { scopes: 'hunt:write' }), async (req: Request, res: Response) => {
    try {
      if (!req.auth?.tenantId) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const idParsed = IdParamSchema.safeParse(req.params);
      if (!idParsed.success) {
        res.status(400).json({ error: 'Invalid id', details: idParsed.error.errors });
        return;
      }

      const updated = await sigmaHuntService.ackLead(req.auth.tenantId, idParsed.data.id);
      if (!updated) {
        res.status(404).json({ error: 'Lead not found' });
        return;
      }

      res.json({ success: true, data: updated });
    } catch (error) {
      routeLogger.error({ error }, 'Failed to ack sigma lead');
      res.status(500).json({ error: 'Failed to ack sigma lead' });
    }
  });

  return router;
}
