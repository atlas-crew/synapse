import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { z } from 'zod';
import { requireScope } from '../middleware/auth.js';
import { validateBody, validateParams, IdParamSchema } from '../middleware/validation.js';
import { createPlaybookRateLimiters } from '../middleware/rate-limit.js';
import { PlaybookService, PlaybookConcurrencyError, type UserInfo } from '../../services/warroom/playbook-service.js';
import { SecurityAuditService } from '../../services/audit/security-audit.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { WarRoomService } from '../../services/warroom/index.js';

export interface PlaybookRoutesOptions {
  fleetCommander?: FleetCommander;
  warRoomService?: WarRoomService;
  securityAuditService?: SecurityAuditService;
  playbookService?: PlaybookService;
}

// Allowed command types for playbook steps
const CommandTypeEnum = z.enum([
  'push_config',
  'push_rules',
  'update',
  'restart',
  'sync_blocklist',
  'isolate',
  'block_ip',
]);

// Target type enum for command targeting
const TargetTypeEnum = z.enum(['all', 'tag', 'specific']);

// Strict step config schema based on step type
const StepConfigSchema = z.object({
  commandType: CommandTypeEnum.optional(),
  payload: z.record(z.unknown()).optional(),
  targetType: TargetTypeEnum.optional(),
  targetValue: z.array(z.string()).optional(),
  // Notification config
  channel: z.string().optional(),
  message: z.string().optional(),
}).strict();

const PlaybookStepSchema = z.object({
  id: z.string().uuid('Step ID must be a valid UUID'),
  type: z.enum(['manual', 'command', 'notification']),
  title: z.string().min(1).max(200),
  description: z.string().max(1000).optional(),
  config: StepConfigSchema.optional(),
}).refine(
  (step) => {
    // Command steps must have commandType in config
    if (step.type === 'command') {
      return step.config?.commandType !== undefined;
    }
    return true;
  },
  { message: 'Command steps must specify a commandType in config' }
);

const CreatePlaybookSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
  triggerType: z.enum(['MANUAL', 'SIGNAL_SEVERITY', 'SIGNAL_TYPE']),
  triggerValue: z.string().max(100).optional(),
  steps: z.array(PlaybookStepSchema).min(1).max(100),
});

const UpdatePlaybookSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(2000).optional(),
  triggerType: z.enum(['MANUAL', 'SIGNAL_SEVERITY', 'SIGNAL_TYPE']).optional(),
  triggerValue: z.string().max(100).optional(),
  steps: z.array(PlaybookStepSchema).min(1).max(100).optional(),
});

const RunPlaybookSchema = z.object({
  warRoomId: z.string().uuid('War room ID must be a valid UUID'),
});

/**
 * Custom error class for playbook-specific errors
 */
class PlaybookError extends Error {
  constructor(
    message: string,
    public readonly code: 'NOT_FOUND' | 'ACCESS_DENIED' | 'INVALID_STATE' | 'VALIDATION_ERROR',
    public readonly statusCode: number = 500
  ) {
    super(message);
    this.name = 'PlaybookError';
  }
}

/**
 * Extract user info from auth context.
 * Throws if userId is missing (required for write operations).
 */
function extractUserInfo(auth: { userId?: string; userName?: string }, operation: string): UserInfo {
  if (!auth.userId) {
    throw new PlaybookError(
      `User ID is required for ${operation}`,
      'ACCESS_DENIED',
      401
    );
  }
  return {
    userId: auth.userId,
    userName: auth.userName ?? 'Unknown User',
  };
}

/**
 * Map error to appropriate HTTP response
 */
function handlePlaybookError(
  error: unknown,
  logger: Logger,
  context: string
): { status: number; body: { error: string } } {
  // Log full error details server-side only
  logger.error({ error, context }, `Playbook operation failed: ${context}`);

  if (error instanceof PlaybookError) {
    return {
      status: error.statusCode,
      body: { error: error.message },
    };
  }

  // Handle concurrency errors
  if (error instanceof PlaybookConcurrencyError) {
    return {
      status: error.statusCode,
      body: { error: error.message },
    };
  }

  // Check for common error patterns without exposing details
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    if (message.includes('user id is required')) {
      return { status: 401, body: { error: 'Authentication required' } };
    }
    if (message.includes('not found')) {
      return { status: 404, body: { error: 'Resource not found' } };
    }
    if (message.includes('not active') || message.includes('already completed')) {
      return { status: 409, body: { error: 'Operation not allowed in current state' } };
    }
    if (message.includes('invalid')) {
      return { status: 400, body: { error: 'Invalid request' } };
    }
  }

  // Generic error for unexpected failures
  return { status: 500, body: { error: 'An unexpected error occurred' } };
}

export function createPlaybookRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: PlaybookRoutesOptions = {}
): Router {
  const router = Router();

  // Initialize security audit service (create if not provided)
  const auditService = options.securityAuditService ?? new SecurityAuditService(prisma, logger);

  // Use shared playbook service if provided, otherwise create local instance
  const service = options.playbookService ?? new PlaybookService(
    prisma,
    logger,
    options.fleetCommander,
    options.warRoomService,
    auditService
  );

  // Initialize tenant-scoped rate limiters
  const rateLimiters = createPlaybookRateLimiters(logger);

  // List playbooks
  router.get(
    '/',
    requireScope('dashboard:read'),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const playbooks = await service.listPlaybooks(auth.tenantId);
        res.json({ playbooks });
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'list playbooks');
        res.status(status).json(body);
      }
    }
  );

  // Get single playbook
  router.get(
    '/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const playbook = await prisma.playbook.findUnique({
          where: { id },
        });

        if (!playbook) {
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        if (playbook.tenantId !== auth.tenantId) {
          // Log security audit for access violation
          await auditService.logPlaybookAccessDenied(req, id, 'read');
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        res.json(playbook);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'get playbook');
        res.status(status).json(body);
      }
    }
  );

  // Create playbook
  router.post(
    '/',
    requireScope('dashboard:write'),
    rateLimiters.create,
    validateBody(CreatePlaybookSchema),
    async (req, res) => {
      try {
        const auth = req.auth!;
        const playbook = await service.createPlaybook({
          tenantId: auth.tenantId,
          ...req.body
        });

        // Audit log: playbook created
        await auditService.logPlaybookCreated(req, playbook.id, playbook.name);

        res.status(201).json(playbook);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'create playbook');
        res.status(status).json(body);
      }
    }
  );

  // Update playbook
  router.patch(
    '/:id',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    validateBody(UpdatePlaybookSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Verify ownership
        const existing = await prisma.playbook.findUnique({
          where: { id },
        });

        if (!existing) {
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        if (existing.tenantId !== auth.tenantId) {
          // Audit log: access denied for update
          await auditService.logPlaybookAccessDenied(req, id, 'update');
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        const updated = await prisma.playbook.update({
          where: { id },
          data: req.body,
        });

        // Audit log: playbook updated
        await auditService.logPlaybookUpdated(req, id, req.body);

        res.json(updated);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'update playbook');
        res.status(status).json(body);
      }
    }
  );

  // Soft delete playbook
  router.delete(
    '/:id',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Verify ownership
        const existing = await prisma.playbook.findUnique({
          where: { id },
        });

        if (!existing) {
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        if (existing.tenantId !== auth.tenantId) {
          // Audit log: access denied for delete
          await auditService.logPlaybookAccessDenied(req, id, 'delete');
          res.status(404).json({ error: 'Playbook not found' });
          return;
        }

        // Soft delete by setting isActive to false
        await prisma.playbook.update({
          where: { id },
          data: { isActive: false },
        });

        // Audit log: playbook deleted
        await auditService.logPlaybookDeleted(req, id);

        res.status(204).send();
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'delete playbook');
        res.status(status).json(body);
      }
    }
  );

  // Run playbook
  router.post(
    '/:id/run',
    requireScope('dashboard:write'),
    rateLimiters.execute,
    validateParams(IdParamSchema),
    validateBody(RunPlaybookSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const { warRoomId } = req.body;
        const auth = req.auth!;

        // Extract and validate user info
        const user = extractUserInfo(auth, 'playbook execution');

        const run = await service.runPlaybook(id, warRoomId, auth.tenantId, user);

        // Audit log: playbook execution started
        await auditService.logPlaybookExecutionStarted(req, run.id, id, warRoomId);

        res.status(201).json(run);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'run playbook');
        res.status(status).json(body);
      }
    }
  );

  // Get run status
  router.get(
    '/runs/:id',
    requireScope('dashboard:read'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        const run = await prisma.playbookRun.findUnique({
          where: { id },
          include: {
            playbook: {
              select: { id: true, name: true, steps: true },
            },
          },
        });

        if (!run) {
          res.status(404).json({ error: 'Playbook run not found' });
          return;
        }

        if (run.tenantId !== auth.tenantId) {
          // Audit log: access denied for run read
          await auditService.logPlaybookRunAccessDenied(req, id, 'read');
          res.status(404).json({ error: 'Playbook run not found' });
          return;
        }

        res.json(run);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'get run status');
        res.status(status).json(body);
      }
    }
  );

  // Cancel running playbook
  router.post(
    '/runs/:id/cancel',
    requireScope('dashboard:write'),
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Extract and validate user info
        const user = extractUserInfo(auth, 'playbook cancellation');

        const updated = await service.cancelPlaybookRun(id, auth.tenantId, user);

        // Audit log: playbook run cancelled
        await auditService.logPlaybookRunCancelled(req, id);

        res.json(updated);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'cancel run');
        res.status(status).json(body);
      }
    }
  );

  // Execute/Complete Step
  router.post(
    '/runs/:id/step',
    requireScope('dashboard:write'),
    rateLimiters.stepComplete,
    validateParams(IdParamSchema),
    async (req, res) => {
      try {
        const { id } = req.params;
        const auth = req.auth!;

        // Extract and validate user info
        const user = extractUserInfo(auth, 'step execution');

        const result = await service.executeStep(id, auth.tenantId, user);
        res.json(result);
      } catch (error) {
        const { status, body } = handlePlaybookError(error, logger, 'execute step');
        res.status(status).json(body);
      }
    }
  );

  return router;
}
