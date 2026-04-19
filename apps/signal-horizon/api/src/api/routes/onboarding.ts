/**
 * Onboarding API Routes
 *
 * Handles sensor registration token generation and pending sensor approval workflow.
 * Enables zero-touch provisioning with secure token-based registration.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import { Prisma } from '@prisma/client';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';
import { rateLimiters } from '../../middleware/rate-limiter.js';
import {
  FleetCommander,
  LiveCommandDeliveryError,
} from '../../services/fleet/fleet-commander.js';
import { ALLOWED_SENSOR_SCOPES, generateApiKey } from '../../services/fleet/sensor-api-keys.js';
import { createFleetPartialResult } from '../../types/fleet-partial-result.js';

// Validation schemas
const createTokenSchema = z.object({
  name: z.string().min(1).max(100),
  maxUses: z.number().int().min(1).max(1000).default(1),
  expiresIn: z.number().int().min(1).max(365).optional(), // Days
  region: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const approvalSchema = z.object({
  action: z.enum(['approve', 'reject']),
  reason: z.string().max(500).optional(),
  assignedName: z.string().max(100).optional(),
});

const candidatesQuerySchema = z.object({
  tokenId: z.string().cuid().optional(),
  since: z.string().datetime().optional(),
});

const batchPendingSchema = z.object({
  sensorIds: z
    .array(z.string().cuid())
    .min(1)
    .max(50)
    .transform((sensorIds) => [...new Set(sensorIds)]),
  reason: z.string().max(500).optional(),
});

const MAX_CANDIDATE_LOOKBACK_MS = 30 * 24 * 60 * 60 * 1000;
const BATCH_PENDING_CONCURRENCY = 5;

// Utility functions
function generateRegistrationToken(): { token: string; hash: string; prefix: string } {
  const tokenBytes = crypto.randomBytes(24);
  const token = `sh_reg_${tokenBytes.toString('base64url')}`;
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const prefix = token.substring(0, 16);
  return { token, hash, prefix };
}

class PendingSensorActionHttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: Record<string, unknown>
  ) {
    super(String(body.error ?? body.message ?? 'Failed to process pending sensor action'));
  }
}

type PendingSensorActionInput = z.infer<typeof approvalSchema>;
type PendingSensorActionResponse =
  | {
      message: string;
      sensor: {
        id: string;
        name: string;
        status: string;
        approvedAt: Date | null;
      };
      automation: {
        sensorApiKeyIssued: boolean;
        handoffQueued: boolean;
      };
    }
  | {
      message: string;
      sensorId: string;
    };

function requireActorUserId(res: Response, userId: string | undefined): string | null {
  if (userId) return userId;
  res.status(401).json({
    error: 'Authenticated user context is required for onboarding approval actions',
    code: 'USER_CONTEXT_REQUIRED',
  });
  return null;
}

async function mapWithConcurrencyLimit<T, TResult>(
  items: readonly T[],
  concurrency: number,
  worker: (item: T) => Promise<TResult>
): Promise<TResult[]> {
  const results = new Array<TResult>(items.length);
  let nextIndex = 0;

  async function consume(): Promise<void> {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await worker(items[currentIndex]);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, () => consume())
  );

  return results;
}

async function listEligiblePendingSensorIds(
  prisma: PrismaClient,
  tenantId: string,
  sensorIds: readonly string[]
): Promise<Set<string>> {
  const sensors = await prisma.sensor.findMany({
    where: {
      id: { in: [...sensorIds] },
      tenantId,
      approvalStatus: 'PENDING',
    },
    select: {
      id: true,
    },
  });

  return new Set(sensors.map((sensor) => sensor.id));
}

async function processPendingSensorAction(params: {
  prisma: PrismaClient;
  logger: Logger;
  fleetCommander?: FleetCommander;
  tenantId: string;
  userId: string;
  sensorId: string;
  input: PendingSensorActionInput;
}): Promise<PendingSensorActionResponse> {
  const { prisma, logger, fleetCommander, tenantId, userId, sensorId, input } = params;
  const { action, reason, assignedName } = input;

  if (action === 'approve') {
    if (!fleetCommander) {
      logger.error({ sensorId, tenantId }, 'FleetCommander unavailable; sensor approval automation cannot continue');
      throw new PendingSensorActionHttpError(503, {
        error: 'Sensor handoff is unavailable right now. The sensor remains pending approval.',
      });
    }

    const { key, hash, prefix } = generateApiKey();
    const approvedAt = new Date();
    const updated = await prisma.$transaction(
      async (tx) => {
        const pendingSensor = await tx.sensor.findFirst({
          where: {
            id: sensorId,
            tenantId,
            approvalStatus: 'PENDING',
          },
        });

        if (!pendingSensor) {
          throw new PendingSensorActionHttpError(404, { error: 'Pending sensor not found' });
        }

        const approvedSensor = await tx.sensor.update({
          where: { id: sensorId },
          data: {
            approvalStatus: 'APPROVED',
            approvedAt,
            approvedBy: userId,
            name: assignedName || pendingSensor.name,
          },
        });

        const sensorApiKey = await tx.sensorApiKey.create({
          data: {
            name: `Auto-issued key for ${approvedSensor.name} (${approvedAt.toISOString()})`,
            keyHash: hash,
            keyPrefix: prefix,
            sensorId,
            expiresAt: null,
            permissions: ALLOWED_SENSOR_SCOPES,
            createdBy: userId,
            status: 'ACTIVE',
          },
        });

        return {
          sensor: approvedSensor,
          sensorApiKeyId: sensorApiKey.id,
          originalName: pendingSensor.name,
        };
      },
      {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      }
    );

    let handoffCommandId: string | null = null;
    try {
      handoffCommandId = await fleetCommander.sendConnectedCommand(tenantId, sensorId, {
        type: 'push_config',
        payload: {
          action: 'replace_sensor_api_key',
          sensorApiKey: key,
          restartProcess: true,
          source: 'horizon_onboarding_approval',
        },
      });
    } catch (handoffError) {
      logger.error(
        { error: handoffError, sensorId, tenantId },
        'Failed to deliver sensor key handoff after approval; rolling back sensor approval'
      );

      let rollbackSucceeded = false;
      try {
        await prisma.$transaction(async (tx) => {
          await tx.sensor.update({
            where: { id: sensorId },
            data: {
              approvalStatus: 'PENDING',
              approvedAt: null,
              approvedBy: null,
              name: updated.originalName,
            },
          });

          await tx.sensorApiKey.deleteMany({
            where: {
              id: updated.sensorApiKeyId,
              sensorId,
            },
          });

        });
        rollbackSucceeded = true;
      } catch (rollbackError) {
        logger.error(
          { error: rollbackError, sensorId, tenantId, originalError: handoffError },
          'Failed to roll back sensor approval after handoff error'
        );

        try {
          await prisma.sensorApiKey.updateMany({
            where: { id: updated.sensorApiKeyId, sensorId },
            data: { status: 'REVOKED' },
          });
        } catch (revokeError) {
          logger.error(
            { error: revokeError, sensorId, tenantId, originalError: handoffError },
            'Failed to revoke auto-issued sensor key after rollback failure'
          );
        }
      }

      if (!rollbackSucceeded) {
        throw new PendingSensorActionHttpError(500, {
          error:
            'Failed to complete automated approval handoff. The issued sensor key was revoked, but manual review is required for this sensor state.',
          code: 'APPROVAL_ROLLBACK_FAILED',
        });
      }

      const liveDeliveryIssue =
        handoffError instanceof LiveCommandDeliveryError && handoffError.code === 'SENSOR_NOT_READY';
      throw new PendingSensorActionHttpError(liveDeliveryIssue ? 409 : 503, {
        error: liveDeliveryIssue
          ? 'The sensor is not connected for live key handoff. It remains pending approval.'
          : 'Failed to deliver the approved sensor key to the connected sensor. The sensor remains pending approval.',
        code: liveDeliveryIssue ? 'SENSOR_NOT_CONNECTED' : 'SENSOR_HANDOFF_FAILED',
      });
    }

    logger.info(
      { sensorId, tenantId, action, handoffCommandId },
      'Sensor approved and automated key handoff queued'
    );
      return {
        message: 'Sensor approved successfully',
        sensor: {
          id: updated.sensor.id,
        name: updated.sensor.name,
        status: updated.sensor.approvalStatus,
        approvedAt: updated.sensor.approvedAt,
      },
      automation: {
        sensorApiKeyIssued: true,
        handoffQueued: handoffCommandId !== null,
      },
    };
  }

  await prisma.$transaction(
    async (tx) => {
      const currentSensor = await tx.sensor.findFirst({
        where: {
          id: sensorId,
          tenantId,
          approvalStatus: 'PENDING',
        },
        select: {
          metadata: true,
        },
      });

      if (!currentSensor) {
        throw new PendingSensorActionHttpError(404, { error: 'Pending sensor not found' });
      }

      const existingMetadata =
        (currentSensor.metadata as Record<string, unknown> | null) ?? {};

      await tx.sensor.update({
        where: { id: sensorId },
        data: {
          approvalStatus: 'REJECTED',
          metadata: {
            ...existingMetadata,
            rejectionReason: reason,
            rejectedAt: new Date().toISOString(),
            rejectedBy: userId,
          } as Prisma.InputJsonValue,
        },
      });
    },
    {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
    }
  );

  logger.info({ sensorId, tenantId, action, reason }, 'Sensor rejected');
  return {
    message: 'Sensor rejected',
    sensorId,
  };
}

/**
 * Create onboarding routes for sensor registration
 */
export function createOnboardingRoutes(
  prisma: PrismaClient,
  logger: Logger,
  options: { fleetCommander?: FleetCommander } = {}
): Router {
  const router = Router();
  const { fleetCommander } = options;

  // =============================================================================
  // Registration Tokens
  // =============================================================================

  /**
   * GET /tokens - List all registration tokens for tenant
   */
  router.get('/tokens', requireScope('fleet:read'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const tokens = await prisma.registrationToken.findMany({
        where: { tenantId },
        orderBy: { createdAt: 'desc' },
        include: {
          _count: {
            select: { registeredSensors: true },
          },
        },
      });

      // Calculate token status and remaining uses
      const enrichedTokens = tokens.map((token) => {
        const isExpired = token.expiresAt ? new Date(token.expiresAt) < new Date() : false;
        const remainingUses = token.maxUses - token._count.registeredSensors;
        const isExhausted = remainingUses <= 0;

        return {
          id: token.id,
          name: token.name,
          tokenPrefix: token.tokenPrefix,
          status: token.revoked ? 'REVOKED' : isExpired ? 'EXPIRED' : isExhausted ? 'EXHAUSTED' : 'ACTIVE',
          maxUses: token.maxUses,
          usedCount: token._count.registeredSensors,
          remainingUses: Math.max(0, remainingUses),
          region: token.region,
          expiresAt: token.expiresAt,
          createdAt: token.createdAt,
          createdBy: token.createdBy,
        };
      });

      res.json({
        tokens: enrichedTokens,
        total: enrichedTokens.length,
        active: enrichedTokens.filter((t) => t.status === 'ACTIVE').length,
      });
    } catch (error) {
      logger.error({ error }, 'Error listing registration tokens');
      res.status(500).json({ error: 'Failed to list registration tokens' });
    }
  });

  /**
   * POST /tokens - Generate new registration token
   */
  router.post('/tokens', rateLimiters.onboarding, requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const userId = req.auth!.userId;

      const parsed = createTokenSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const { name, maxUses, expiresIn, region, metadata } = parsed.data;
      const { token, hash, prefix } = generateRegistrationToken();

      const expiresAt = expiresIn
        ? new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000)
        : null;

      const created = await prisma.registrationToken.create({
        data: {
          tenantId,
          name,
          tokenHash: hash,
          tokenPrefix: prefix,
          maxUses,
          region,
          expiresAt,
          createdBy: userId,
          metadata: (metadata || {}) as Prisma.InputJsonValue,
        },
      });

      logger.info({ tokenId: created.id, tenantId }, 'Registration token created');

      res.status(201).json({
        token, // Only returned once at creation
        id: created.id,
        name: created.name,
        tokenPrefix: prefix,
        maxUses,
        expiresAt,
        createdAt: created.createdAt,
        message: 'Save this token securely. It will not be shown again.',
      });
    } catch (error) {
      logger.error({ error }, 'Error creating registration token');
      res.status(500).json({ error: 'Failed to create registration token' });
    }
  });

  /**
   * DELETE /tokens/:tokenId - Revoke a registration token
   */
  router.delete('/tokens/:tokenId', rateLimiters.onboarding, requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const { tokenId } = req.params;

      const token = await prisma.registrationToken.findFirst({
        where: { id: tokenId, tenantId },
      });

      if (!token) {
        res.status(404).json({ error: 'Token not found' });
        return;
      }

      await prisma.registrationToken.update({
        where: { id: tokenId },
        data: { revoked: true, revokedAt: new Date() },
      });

      logger.info({ tokenId, tenantId }, 'Registration token revoked');
      res.status(204).send();
    } catch (error) {
      logger.error({ error }, 'Error revoking registration token');
      res.status(500).json({ error: 'Failed to revoke token' });
    }
  });

  // =============================================================================
  // Pending Sensors
  // =============================================================================

  /**
   * GET /pending - List sensors awaiting approval
   */
  router.get('/pending', requireScope('fleet:read'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const pendingSensors = await prisma.sensor.findMany({
        where: {
          tenantId,
          approvalStatus: 'PENDING',
        },
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          name: true,
          hostname: true,
          region: true,
          version: true,
          os: true,
          architecture: true,
          publicIp: true,
          privateIp: true,
          registrationMethod: true,
          // SECURITY: Removed registrationToken from response - plaintext token should never be exposed
          registrationTokenId: true, // Reference to hashed token instead
          createdAt: true,
          lastHeartbeat: true,
          metadata: true,
        },
      });

      res.json({
        sensors: pendingSensors,
        total: pendingSensors.length,
      });
    } catch (error) {
      logger.error({ error }, 'Error listing pending sensors');
      res.status(500).json({ error: 'Failed to list pending sensors' });
    }
  });

  router.post(
    '/pending/approve',
    rateLimiters.onboardingBatch,
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const parsed = batchPendingSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({
            error: 'Validation failed',
            details: parsed.error.issues,
          });
          return;
        }

        const tenantId = req.auth!.tenantId;
        const userId = requireActorUserId(res, req.auth!.userId);
        if (!userId) return;
        logger.info(
          { tenantId, userId, sensorIds: parsed.data.sensorIds, action: 'approve' },
          'Processing batch sensor approval request'
        );
        const eligibleSensorIds = await listEligiblePendingSensorIds(
          prisma,
          tenantId,
          parsed.data.sensorIds
        );

        const results = await mapWithConcurrencyLimit(
          parsed.data.sensorIds,
          BATCH_PENDING_CONCURRENCY,
          async (sensorId) => {
            if (!eligibleSensorIds.has(sensorId)) {
              return {
                sensorId,
                status: 'error' as const,
                error: 'Pending sensor not found or not eligible',
              };
            }

            try {
              const data = await processPendingSensorAction({
                prisma,
                logger,
                fleetCommander,
                tenantId,
                userId,
                sensorId,
                input: { action: 'approve' },
              });
              return { sensorId, status: 'ok' as const, data };
            } catch (error) {
              if (error instanceof PendingSensorActionHttpError) {
                return {
                  sensorId,
                  status: 'error' as const,
                  error: String(error.body.error ?? error.body.message ?? error.message),
                };
              }

              logger.error({ error, sensorId }, 'Error processing batch sensor approval');
              return {
                sensorId,
                status: 'error' as const,
                error: 'Failed to process sensor approval',
              };
            }
          }
        );

        res.json(createFleetPartialResult(results));
      } catch (error) {
        logger.error({ error }, 'Error processing batch sensor approval');
        res.status(500).json({ error: 'Failed to process batch sensor approval' });
      }
    }
  );

  router.post(
    '/pending/reject',
    rateLimiters.onboardingBatch,
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const parsed = batchPendingSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({
            error: 'Validation failed',
            details: parsed.error.issues,
          });
          return;
        }

        const tenantId = req.auth!.tenantId;
        const userId = requireActorUserId(res, req.auth!.userId);
        if (!userId) return;
        logger.info(
          { tenantId, userId, sensorIds: parsed.data.sensorIds, action: 'reject' },
          'Processing batch sensor rejection request'
        );
        const eligibleSensorIds = await listEligiblePendingSensorIds(
          prisma,
          tenantId,
          parsed.data.sensorIds
        );

        const results = await mapWithConcurrencyLimit(
          parsed.data.sensorIds,
          BATCH_PENDING_CONCURRENCY,
          async (sensorId) => {
            if (!eligibleSensorIds.has(sensorId)) {
              return {
                sensorId,
                status: 'error' as const,
                error: 'Pending sensor not found or not eligible',
              };
            }

            try {
              const data = await processPendingSensorAction({
                prisma,
                logger,
                fleetCommander,
                tenantId,
                userId,
                sensorId,
                input: { action: 'reject', reason: parsed.data.reason },
              });
              return { sensorId, status: 'ok' as const, data };
            } catch (error) {
              if (error instanceof PendingSensorActionHttpError) {
                return {
                  sensorId,
                  status: 'error' as const,
                  error: String(error.body.error ?? error.body.message ?? error.message),
                };
              }

              logger.error({ error, sensorId }, 'Error processing batch sensor rejection');
              return {
                sensorId,
                status: 'error' as const,
                error: 'Failed to process sensor rejection',
              };
            }
          }
        );

        res.json(createFleetPartialResult(results));
      } catch (error) {
        logger.error({ error }, 'Error processing batch sensor rejection');
        res.status(500).json({ error: 'Failed to process batch sensor rejection' });
      }
    }
  );

  /**
   * POST /pending/:sensorId - Approve or reject a pending sensor
   */
  router.post('/pending/:sensorId', rateLimiters.onboarding, requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const userId = req.auth!.userId;
      const { sensorId } = req.params;

      const parsed = approvalSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const actorUserId = requireActorUserId(res, userId);
      if (!actorUserId) return;

      const response = await processPendingSensorAction({
        prisma,
        logger,
        fleetCommander,
        tenantId,
        userId: actorUserId,
        sensorId,
        input: parsed.data,
      });
      res.json(response);
    } catch (error) {
      if (error instanceof PendingSensorActionHttpError) {
        res.status(error.status).json(error.body);
        return;
      }
      logger.error({ error }, 'Error processing sensor approval');
      res.status(500).json({ error: 'Failed to process sensor approval' });
    }
  });

  /**
   * DELETE /pending/:sensorId - Remove a pending sensor entirely
   */
  router.delete('/pending/:sensorId', rateLimiters.onboarding, requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const { sensorId } = req.params;

      const sensor = await prisma.sensor.findFirst({
        where: {
          id: sensorId,
          tenantId,
          approvalStatus: 'PENDING',
        },
      });

      if (!sensor) {
        res.status(404).json({ error: 'Pending sensor not found' });
        return;
      }

      await prisma.sensor.delete({
        where: { id: sensorId },
      });

      logger.info({ sensorId, tenantId }, 'Pending sensor deleted');
      res.status(204).send();
    } catch (error) {
      logger.error({ error }, 'Error deleting pending sensor');
      res.status(500).json({ error: 'Failed to delete sensor' });
    }
  });

  // =============================================================================
  // Sensor Candidates (pre-enrollment announces)
  // =============================================================================

  /**
   * GET /candidates - List sensor candidates that have hit /sensors/announce
   * but haven't completed enrollment yet. The wizard polls this endpoint to
   * show "we see your sensor" feedback during setup.
   *
   * Optional query params:
   *   tokenId  - Filter to candidates from a single registration token
   *              (scopes the view to the token the wizard just issued).
   *   since    - ISO timestamp; only return candidates seen after this.
   */
  router.get(
    '/candidates',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      try {
        const tenantId = req.auth!.tenantId;
        const parsed = candidatesQuerySchema.safeParse({
          tokenId: typeof req.query.tokenId === 'string' ? req.query.tokenId : undefined,
          since: typeof req.query.since === 'string' ? req.query.since : undefined,
        });
        if (!parsed.success) {
          res.status(400).json({ error: 'Invalid candidates query', details: parsed.error.issues });
          return;
        }

        const { tokenId, since } = parsed.data;
        const sinceDate = since ? new Date(since) : undefined;
        if (sinceDate && sinceDate.getTime() > Date.now()) {
          res.status(400).json({ error: 'The `since` timestamp cannot be in the future' });
          return;
        }
        if (sinceDate && Date.now() - sinceDate.getTime() > MAX_CANDIDATE_LOOKBACK_MS) {
          res.status(400).json({ error: 'The `since` timestamp must be within the last 30 days' });
          return;
        }

        if (tokenId) {
          const token = await prisma.registrationToken.findFirst({
            where: { id: tokenId, tenantId },
            select: { id: true },
          });
          if (!token) {
            res.status(404).json({ error: 'Registration token not found' });
            return;
          }
        }

        const candidates = await prisma.sensorCandidate.findMany({
          where: {
            tenantId,
            ...(tokenId ? { registrationTokenId: tokenId } : {}),
            ...(sinceDate ? { lastSeenAt: { gte: sinceDate } } : {}),
          },
          orderBy: { lastSeenAt: 'desc' },
          take: 100,
        });

        res.json({
          items: candidates.map((c) => ({
            id: c.id,
            tokenId: c.registrationTokenId,
            fingerprint: c.fingerprint,
            hostname: c.hostname,
            os: c.os,
            kernel: c.kernel,
            architecture: c.architecture,
            ipAddress: c.ipAddress,
            version: c.version,
            userAgent: c.userAgent,
            announceCount: c.announceCount,
            firstSeenAt: c.firstSeenAt.toISOString(),
            lastSeenAt: c.lastSeenAt.toISOString(),
            claimedSensorId: c.claimedSensorId,
            status: c.claimedSensorId ? 'claimed' : 'announced',
          })),
        });
      } catch (error) {
        logger.error({ error }, 'Error listing sensor candidates');
        res.status(500).json({ error: 'Failed to list candidates' });
      }
    }
  );

  // =============================================================================
  // Statistics
  // =============================================================================

  /**
   * GET /stats - Get onboarding statistics
   */
  router.get('/stats', requireScope('fleet:read'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const [pendingCount, activeTokens, recentRegistrations] = await Promise.all([
        prisma.sensor.count({
          where: { tenantId, approvalStatus: 'PENDING' },
        }),
        prisma.registrationToken.count({
          where: {
            tenantId,
            revoked: false,
            OR: [
              { expiresAt: null },
              { expiresAt: { gt: new Date() } },
            ],
          },
        }),
        prisma.sensor.count({
          where: {
            tenantId,
            createdAt: { gt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          },
        }),
      ]);

      res.json({
        pendingApprovals: pendingCount,
        activeTokens,
        registrationsLast7Days: recentRegistrations,
      });
    } catch (error) {
      logger.error({ error }, 'Error fetching onboarding stats');
      res.status(500).json({ error: 'Failed to fetch statistics' });
    }
  });

  return router;
}
