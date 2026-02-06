/**
 * Fleet Policy Management API Routes
 * Endpoints for global security policy template management
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope, requireTenant } from '../middleware/auth.js';
import {
  validateParams,
  validateBody,
  IdParamSchema,
} from '../middleware/validation.js';
import { getErrorMessage } from '../../utils/errors.js';
import {
  PolicyTemplateService,
  PolicyAccessError,
  PolicyNotFoundError,
  DefaultTemplateModificationError,
} from '../../services/fleet/policy-template.js';
import {
  CreatePolicyTemplateSchema,
  UpdatePolicyTemplateSchema,
  ApplyPolicyTemplateSchema,
  type PolicyTemplate,
} from '../../services/fleet/policy-template-types.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import { SecurityAuditService } from '../../services/audit/security-audit.js';

function toPolicyTemplateAuditValues(template: PolicyTemplate): Record<string, unknown> {
  return {
    name: template.name,
    description: template.description ?? null,
    severity: template.severity,
    config: template.config,
    metadata: template.metadata,
    isDefault: template.isDefault,
    isActive: template.isActive,
    version: template.version,
  };
}

// ======================== Route Handler ========================

export interface FleetPolicyRoutesOptions {
  fleetCommander?: FleetCommander;
  policyService?: PolicyTemplateService;
  securityAuditService?: SecurityAuditService;
}

/**
 * Create fleet policy management routes
 */
export function createFleetPolicyRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: FleetPolicyRoutesOptions = {}
): Router {
  const router = Router();
  // Use shared service if provided, otherwise create local instance
  const policyService = options.policyService ?? new PolicyTemplateService(prisma, logger);
  const auditService = options.securityAuditService ?? new SecurityAuditService(prisma, logger);

  // Set fleet commander if available
  if (options.fleetCommander) {
    policyService.setFleetCommander(options.fleetCommander);
  }

  // ======================== List Templates ========================

  /**
   * GET /api/v1/fleet/policies
   * List all policy templates for the tenant
   */
  router.get('/', requireScope('policy:read'), async (req, res) => {
    try {
      const auth = req.auth!;
      const templates = await policyService.listTemplates(auth.tenantId);

      res.json({
        templates,
        count: templates.length,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to list policy templates');
      res.status(500).json({
        error: 'Failed to list policy templates',
        message: getErrorMessage(error),
      });
    }
  });

  // ======================== Get Default Templates ========================

  /**
   * GET /api/v1/fleet/policies/defaults
   * Get default policy templates (Strict, Standard, Dev)
   */
  router.get('/defaults', requireScope('policy:read'), async (req, res) => {
    try {
      const auth = req.auth!;
      const templates = await policyService.getDefaultTemplates(auth.tenantId);

      res.json({
        templates,
        count: templates.length,
      });
    } catch (error) {
      logger.error({ error }, 'Failed to get default policy templates');
      res.status(500).json({
        error: 'Failed to get default policy templates',
        message: getErrorMessage(error),
      });
    }
  });

  // ======================== Get Single Template ========================

  /**
   * GET /api/v1/fleet/policies/:id
   * Get a specific policy template
   */
  router.get(
    '/:id',
    requireScope('policy:read'),
    requireTenant(prisma, 'policy', 'id'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { id } = req.params;

        const template = await policyService.getTemplate(auth.tenantId, id);

        if (!template) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        res.json(template);
      } catch (error) {
        if (error instanceof PolicyAccessError) {
          res.status(403).json({ error: 'Access denied to policy template' });
          return;
        }

        logger.error({ error }, 'Failed to get policy template');
        res.status(500).json({
          error: 'Failed to get policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Create Template ========================

  /**
   * POST /api/v1/fleet/policies
   * Create a new custom policy template
   */
  router.post(
    '/',
    requireScope('policy:write'),
    validateBody(CreatePolicyTemplateSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const input = req.body as z.infer<typeof CreatePolicyTemplateSchema>;

        const template = await policyService.createTemplate(auth.tenantId, input);

        await auditService.logConfigCreated(
          req,
          'policy_template',
          template.id,
          toPolicyTemplateAuditValues(template)
        );

        res.status(201).json(template);
      } catch (error) {
        logger.error({ error }, 'Failed to create policy template');
        res.status(500).json({
          error: 'Failed to create policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Update Template ========================

  /**
   * PUT /api/v1/fleet/policies/:id
   * Update a custom policy template
   */
  router.put(
    '/:id',
    requireScope('policy:write'),
    requireTenant(prisma, 'policy', 'id'),
    validateParams(IdParamSchema),
    validateBody(UpdatePolicyTemplateSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { id } = req.params;
        const input = req.body as z.infer<typeof UpdatePolicyTemplateSchema>;

        const previous = await policyService.getTemplate(auth.tenantId, id);
        if (!previous) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        const template = await policyService.updateTemplate(auth.tenantId, id, input);

        await auditService.logConfigUpdated(
          req,
          'policy_template',
          id,
          toPolicyTemplateAuditValues(previous),
          toPolicyTemplateAuditValues(template)
        );

        res.json(template);
      } catch (error) {
        if (error instanceof PolicyNotFoundError) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        if (error instanceof PolicyAccessError) {
          res.status(403).json({ error: 'Access denied to policy template' });
          return;
        }

        if (error instanceof DefaultTemplateModificationError) {
          res.status(400).json({
            error: 'Cannot modify default policy template',
            message: 'Clone the template to create a custom version instead',
          });
          return;
        }

        logger.error({ error }, 'Failed to update policy template');
        res.status(500).json({
          error: 'Failed to update policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Delete Template ========================

  /**
   * DELETE /api/v1/fleet/policies/:id
   * Delete a custom policy template
   */
  router.delete(
    '/:id',
    requireScope('policy:write'),
    requireTenant(prisma, 'policy', 'id'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { id } = req.params;

        const previous = await policyService.getTemplate(auth.tenantId, id);
        if (!previous) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        await policyService.deleteTemplate(auth.tenantId, id);

        await auditService.logConfigDeleted(
          req,
          'policy_template',
          id,
          toPolicyTemplateAuditValues(previous)
        );

        res.status(204).send();
      } catch (error) {
        if (error instanceof PolicyNotFoundError) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        if (error instanceof PolicyAccessError) {
          res.status(403).json({ error: 'Access denied to policy template' });
          return;
        }

        if (error instanceof DefaultTemplateModificationError) {
          res.status(400).json({
            error: 'Cannot delete default policy template',
          });
          return;
        }

        logger.error({ error }, 'Failed to delete policy template');
        res.status(500).json({
          error: 'Failed to delete policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Apply Template ========================

  /**
   * POST /api/v1/fleet/policies/:id/apply
   * Apply a policy template to sensors with rollout strategy
   */
  router.post(
    '/:id/apply',
    requireScope('policy:write'),
    requireTenant(prisma, 'policy', 'id'),
    validateParams(IdParamSchema),
    validateBody(ApplyPolicyTemplateSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { id } = req.params;
        const input = req.body as z.infer<typeof ApplyPolicyTemplateSchema>;

        const result = await policyService.applyTemplate(auth.tenantId, id, input);

        if (result.success) {
          res.status(202).json({
            message: 'Policy application initiated',
            result,
          });
        } else {
          res.status(207).json({
            message: 'Policy application partially failed',
            result,
          });
        }
      } catch (error) {
        if (error instanceof PolicyNotFoundError) {
          res.status(404).json({ error: 'Policy template not found' });
          return;
        }

        if (error instanceof PolicyAccessError) {
          res.status(403).json({ error: 'Access denied to policy template' });
          return;
        }

        logger.error({ error }, 'Failed to apply policy template');
        res.status(500).json({
          error: 'Failed to apply policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Clone Template ========================

  /**
   * POST /api/v1/fleet/policies/:id/clone
   * Clone an existing policy template
   */
  const CloneTemplateSchema = z.object({
    name: z.string().min(1).max(255),
  });

  router.post(
    '/:id/clone',
    requireScope('policy:write'),
    requireTenant(prisma, 'policy', 'id'),
    validateParams(IdParamSchema),
    validateBody(CloneTemplateSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const { id } = req.params;
        const { name } = req.body as z.infer<typeof CloneTemplateSchema>;

        const template = await policyService.cloneTemplate(auth.tenantId, id, name);

        await auditService.logConfigCreated(
          req,
          'policy_template',
          template.id,
          toPolicyTemplateAuditValues(template)
        );

        res.status(201).json(template);
      } catch (error) {
        if (error instanceof PolicyNotFoundError) {
          res.status(404).json({ error: 'Source policy template not found' });
          return;
        }

        if (error instanceof PolicyAccessError) {
          res.status(403).json({ error: 'Access denied to policy template' });
          return;
        }

        logger.error({ error }, 'Failed to clone policy template');
        res.status(500).json({
          error: 'Failed to clone policy template',
          message: getErrorMessage(error),
        });
      }
    }
  );

  // ======================== Get Default Config by Severity ========================

  /**
   * GET /api/v1/fleet/policies/config/:severity
   * Get the default policy configuration for a severity level
   */
  const SeverityParamSchema = z.object({
    severity: z.enum(['strict', 'standard', 'dev']),
  });

  router.get(
    '/config/:severity',
    requireScope('policy:read'),
    validateParams(SeverityParamSchema),
    async (req, res) => {
      try {
        const { severity } = req.params as z.infer<typeof SeverityParamSchema>;
        const config = policyService.getDefaultConfigBySeverity(severity);

        res.json({
          severity,
          config,
        });
      } catch (error) {
        logger.error({ error }, 'Failed to get default policy config');
        res.status(500).json({
          error: 'Failed to get default policy config',
          message: getErrorMessage(error),
        });
      }
    }
  );

  return router;
}
