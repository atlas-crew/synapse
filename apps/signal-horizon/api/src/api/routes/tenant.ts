/**
 * Tenant Settings API Routes
 *
 * Handles tenant-level configurations, specifically collective defense
 * and privacy settings (SharingPreference).
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { Prisma, PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';
import type { SecurityAuditService } from '../../services/audit/security-audit.js';
import { sendProblem } from '../../lib/problem-details.js';
import type { PreferenceService } from '../../services/fleet/preference-service.js';
import { scrubTenantData } from '../../services/fleet/withdrawal.js';
import { lockTenantPreference } from '../../services/fleet/tenant-lock.js';
import type { SharingPreference } from '../../types/protocol.js';

// Validation schemas
const updateSettingsSchema = z.object({
  sharingPreference: z.enum([
    'CONTRIBUTE_AND_RECEIVE',
    'RECEIVE_ONLY',
    'CONTRIBUTE_ONLY',
    'ISOLATED',
  ]).optional(),
});

const consentSchema = z.object({
  consentType: z.literal('BLOCKLIST_SHARING'),
  acknowledged: z.boolean(),
  version: z.string().default('1.0'),
});

  const withdrawalSchema = z.object({
    since: z.string().datetime().optional(),
    type: z.enum(['CONTRIBUTION', 'GDPR_ERASURE']).default('CONTRIBUTION'),
    reason: z.string().max(1024).optional(),
  });
const isContributingPreference = (preference?: SharingPreference | null): boolean =>
  preference === 'CONTRIBUTE_AND_RECEIVE' || preference === 'CONTRIBUTE_ONLY';

/**
 * Create tenant routes for settings management
 */
export function createTenantRoutes(
  prisma: PrismaClient,
  logger: Logger,
  securityAudit?: SecurityAuditService,
  preferenceService?: PreferenceService
): Router {
  const router = Router();

  /**
   * GET /settings - Get current tenant settings with metadata (labs-216b)
   */
  router.get('/settings', requireScope('fleet:read'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;

      const tenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
        select: {
          id: true,
          name: true,
          tier: true,
          sharingPreference: true,
          preferenceVersion: true,
          preferenceChangedBy: true,
          preferenceChangedAt: true,
          updatedAt: true,
          consents: {
            where: { consentType: 'BLOCKLIST_SHARING' },
            orderBy: { grantedAt: 'desc' },
            take: 1,
          },
        },
      });

      if (!tenant) {
        res.status(404).json({ error: 'Tenant not found' });
        return;
      }

      const consent = tenant.consents[0];

      res.json({
        data: {
          sharingPreference: tenant.sharingPreference,
        },
        metadata: {
          changedAt: tenant.preferenceChangedAt || tenant.updatedAt,
          changedBy: tenant.preferenceChangedBy || 'system',
          consent: {
            status: consent ? (consent.acknowledged ? 'acknowledged' : 'withdrawn') : 'not_given',
            acknowledgedAt: consent?.grantedAt,
          },
          schemaVersion: tenant.preferenceVersion,
        },
      });
    } catch (error) {
      logger.error({ error }, 'Error fetching tenant settings');
      res.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  /**
   * PATCH /settings - Update tenant settings with idempotency (labs-op3w) and consent check (labs-th3o)
   */
  router.patch('/settings', requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const userId = req.auth!.userId || 'system';
      const idempotencyKey = req.headers['idempotency-key'] as string | undefined;

      if (!idempotencyKey) {
        sendProblem(res, 400, 'Idempotency-Key header required', {
          code: 'IDEMPOTENCY_KEY_REQUIRED',
          instance: req.originalUrl,
        });
        return;
      }

      // Check idempotency (labs-op3w)
      const cached = await prisma.idempotencyRequest.findUnique({
        where: { key_tenantId: { key: idempotencyKey, tenantId } },
      });

      if (cached) {
        const responseData = cached.response as Record<string, unknown>;
        res.status(200).json(responseData);
        return;
      }

      const parsed = updateSettingsSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const { sharingPreference } = parsed.data;
      // Fetch current settings to detect downgrade and check consent
      const currentTenant = await prisma.tenant.findUnique({
        where: { id: tenantId },
        select: { 
          sharingPreference: true,
          consents: {
            where: { consentType: 'BLOCKLIST_SHARING', acknowledged: true },
            take: 1,
          }
        },
      });

      if (!currentTenant) {
        res.status(404).json({ error: 'Tenant not found' });
        return;
      }

      const targetPreference = sharingPreference ?? currentTenant.sharingPreference;
      const wasContributing = isContributingPreference(currentTenant.sharingPreference);
      const isContributing = isContributingPreference(targetPreference);
      let withdrawalResult: { performed: boolean; signalsScrubbed: number; blocksWithdrawn: number } | null = null;

      // Check for explicit consent if enabling contribution (labs-th3o)
      const needsConsent = 
        sharingPreference === 'CONTRIBUTE_AND_RECEIVE' || 
        sharingPreference === 'CONTRIBUTE_ONLY';
      
      const hasConsent = currentTenant.consents.length > 0;

                      if (needsConsent && !hasConsent) {

                        sendProblem(res, 403, 'Explicit consent required for data sharing', {

                          code: 'CONSENT_REQUIRED',

                          hint: 'Please accept the data sharing policy via POST /tenant/consent before enabling this mode.',

                          instance: req.originalUrl,

                        });

                        return;

                      }

              

      

              // labs-9yin: Use PreferenceService for atomic transition with consensus

              let updated;

              if (sharingPreference && preferenceService) {

                const result = await preferenceService.updatePreference(tenantId, sharingPreference, userId, {

                  currentPreference: currentTenant.sharingPreference,

                });

                if (!result.success) {

                  sendProblem(res, 500, 'Failed to coordinate preference change across services', {

                    code: 'PREFERENCE_TRANSITION_FAILED',

                    instance: req.originalUrl,

                  });

                  return;

                }

      
        if (result.withdrawal?.performed) {
          withdrawalResult = result.withdrawal;
        }
        
        // Fetch updated state for response
        updated = await prisma.tenant.findUnique({
          where: { id: tenantId },
          select: {
            id: true,
            name: true,
            tier: true,
            sharingPreference: true,
            preferenceVersion: true,
            preferenceChangedBy: true,
            preferenceChangedAt: true,
            updatedAt: true,
          },
        });
      } else {
        const txResult = await prisma.$transaction(async (tx) => {
          await lockTenantPreference(tx, tenantId, logger);

          const next = await tx.tenant.update({
            where: { id: tenantId },
            data: {
              ...(sharingPreference && {
                sharingPreference,
                preferenceChangedBy: userId,
                preferenceChangedAt: new Date(),
              }),
            },
            select: {
              id: true,
              name: true,
              tier: true,
              sharingPreference: true,
              preferenceVersion: true,
              preferenceChangedBy: true,
              preferenceChangedAt: true,
              updatedAt: true,
            },
          });

                      let withdrawal: { performed: boolean; signalsScrubbed: number; blocksWithdrawn: number } | null = null;
                      if (sharingPreference && wasContributing && !isContributing) {
                        const { signalsScrubbed, blocksWithdrawn } = await scrubTenantData(tx, tenantId, {
                          contributionOnly: true,
                        });
                        withdrawal = {
                          performed: true,
                          signalsScrubbed,
                          blocksWithdrawn,
                        };
                      }
                    return { updated: next, withdrawal };
        });

        updated = txResult.updated;
        withdrawalResult = txResult.withdrawal;
      }

      if (!updated) {
        res.status(404).json({ error: 'Tenant not found after update' });
        return;
      }

      const responsePayload = {
        data: {
          sharingPreference: updated.sharingPreference,
        },
        metadata: {
          changedAt: updated.preferenceChangedAt || updated.updatedAt,
          changedBy: updated.preferenceChangedBy,
          schemaVersion: updated.preferenceVersion,
        }
      };

      // Store idempotency response (labs-op3w)
      await prisma.idempotencyRequest.create({
        data: {
          key: idempotencyKey,
          tenantId,
          response: responsePayload as Prisma.InputJsonValue,
          expiresAt: new Date(Date.now() + 24 * 3600000), // 24h retention
        },
      });

      if (withdrawalResult?.performed) {
        logger.info({ tenantId }, 'Privacy preference downgraded - initiating data withdrawal');

        logger.info(
          {
            tenantId,
            signalsScrubbed: withdrawalResult.signalsScrubbed,
            blocksWithdrawn: withdrawalResult.blocksWithdrawn,
          },
          'Data withdrawal complete'
        );

                            // 3. Audit log
                            if (securityAudit) {
                              await securityAudit.logEvent(securityAudit.extractRequestContext(req), {
                                action: 'CONFIG_UPDATED',
                                result: 'SUCCESS',
                                resourceId: tenantId,
                                details: {
                                  previousPreference: currentTenant.sharingPreference,
                                  newPreference: updated.sharingPreference,
                                  signalsScrubbed: withdrawalResult.signalsScrubbed,
                                  blocksWithdrawn: withdrawalResult.blocksWithdrawn,
                                },
                              });
                            }
                          }
                  
                          // Log configuration change (labs-pbmu)
                          if (securityAudit && sharingPreference && sharingPreference !== currentTenant.sharingPreference) {
                            await securityAudit.logEvent(securityAudit.extractRequestContext(req), {
                              action: 'CONFIG_UPDATED',
                              result: 'SUCCESS',
                              resourceId: tenantId,
                              details: {
                                change: 'sharingPreference',
                                from: currentTenant.sharingPreference,
                                to: sharingPreference,
                              },
                            });
                          }
                        logger.info(
        { tenantId, sharingPreference, userId },
        'Tenant settings updated'
      );

      res.json(responsePayload);
    } catch (error) {
      logger.error({ error }, 'Error updating tenant settings');
      res.status(500).json({ error: 'Failed to update settings' });
    }
  });

  /**
   * POST /consent - Record explicit consent for data sharing (labs-th3o)
   */
  router.post('/consent', requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
    try {
      const tenantId = req.auth!.tenantId;
      const userId = req.auth!.userId || 'system';

      const parsed = consentSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const { consentType, acknowledged, version } = parsed.data;

      const consent = await prisma.tenantConsent.create({
        data: {
          tenantId,
          consentType,
          acknowledged,
          grantedBy: userId,
          version,
          ipAddress: req.ip,
          userAgent: req.headers['user-agent'],
        },
      });

      // labs-th3o: Handle consent withdrawal
      if (!acknowledged && consentType === 'BLOCKLIST_SHARING') {
        // If consent is withdrawn, we must ensure tenant is no longer contributing
        const currentTenant = await prisma.tenant.findUnique({
          where: { id: tenantId },
          select: { sharingPreference: true },
        });

        if (currentTenant && isContributingPreference(currentTenant.sharingPreference)) {
          logger.info({ tenantId }, 'Consent withdrawn - downgrading sharing preference to RECEIVE_ONLY');
          let withdrawalResult: { performed: boolean; signalsScrubbed: number; blocksWithdrawn: number } | null = null;

          if (preferenceService) {
            const result = await preferenceService.updatePreference(tenantId, 'RECEIVE_ONLY', userId, {
              currentPreference: currentTenant.sharingPreference,
            });
                          if (!result.success) {
                            sendProblem(res, 500, 'Failed to coordinate preference change across services', {
                              code: 'PREFERENCE_TRANSITION_FAILED',
                              instance: req.originalUrl,
                            });
                            return;
                          }
            
            if (result.withdrawal?.performed) {
              withdrawalResult = result.withdrawal;
            }
          } else {
            const txResult = await prisma.$transaction(async (tx) => {
              await tx.tenant.update({
                where: { id: tenantId },
                data: { sharingPreference: 'RECEIVE_ONLY' },
              });

              const signalUpdate = await tx.signal.updateMany({
                where: { tenantId },
                data: { anonFingerprint: null },
              });

              const blockUpdate = await tx.blocklistEntry.updateMany({
                where: { tenantId },
                data: {
                  propagationStatus: 'WITHDRAWN',
                  withdrawnAt: new Date(),
                },
              });

              return {
                performed: true,
                signalsScrubbed: signalUpdate.count,
                blocksWithdrawn: blockUpdate.count,
              };
            });

            withdrawalResult = txResult;
          }

                      if (withdrawalResult?.performed && securityAudit) {

                        await securityAudit.logEvent(securityAudit.extractRequestContext(req), {

                          action: 'CONFIG_UPDATED',

                          result: 'SUCCESS',

                          resourceId: tenantId,

                          details: {

                            previousPreference: currentTenant.sharingPreference,

                            newPreference: 'RECEIVE_ONLY',

                            signalsScrubbed: withdrawalResult.signalsScrubbed,

                            blocksWithdrawn: withdrawalResult.blocksWithdrawn,

                          },

                        });

                      }

          
        }
      }

              if (securityAudit) {
                await securityAudit.logEvent(securityAudit.extractRequestContext(req), {
                  action: 'CONFIG_UPDATED',
                  result: 'SUCCESS',
                  resourceId: tenantId,
                  details: { consentType, version, acknowledged },
                });
              }
            res.status(201).json({
        id: consent.id,
        status: acknowledged ? 'acknowledged' : 'withdrawn',
        grantedAt: consent.grantedAt,
      });
    } catch (error) {
      logger.error({ error }, 'Error recording consent');
      res.status(500).json({ error: 'Failed to record consent' });
    }
  });

  /**
   * POST /withdrawal-request - Retroactively withdraw contributed data (labs-i8h8)
   */
      router.post('/withdrawal-request', requireScope('fleet:write'), async (req: Request, res: Response): Promise<void> => {
        try {
          const tenantId = req.auth!.tenantId;
  
          const parsed = withdrawalSchema.safeParse(req.body);
  
      if (!parsed.success) {
        res.status(400).json({
          error: 'Validation failed',
          details: parsed.error.issues,
        });
        return;
      }

      const { since, type, reason } = parsed.data;
      const sinceDate = since ? new Date(since) : undefined;

                      logger.info({ tenantId, type, since: sinceDate }, 'Processing retroactive data withdrawal');

              

                      // Use the preference service for comprehensive erasure (labs-4ltv)

                      const scrubResult = await preferenceService!.scrubTenantData(tenantId, {

                        since: sinceDate,

                        contributionOnly: type === 'CONTRIBUTION',

                        logger

                      });

              

                      // 3. Audit log

                      if (securityAudit) {

                        await securityAudit.logEvent(securityAudit.extractRequestContext(req), {

                          action: 'CONFIG_UPDATED',

                          result: 'SUCCESS',

                          resourceId: tenantId,

                          details: { 

                            since,

                            type,

                            reason,

                            blocksWithdrawn: scrubResult.blocksWithdrawn,

                            signalsScrubbed: scrubResult.signalsScrubbed,

                            intelDeleted: scrubResult.intelDeleted,

                            mutations: scrubResult.clickhouseMutations

                          },

                        });

                      }

              

      logger.info(
        { tenantId, blocksWithdrawn: scrubResult.blocksWithdrawn, sinceDate },
        'Retroactive data withdrawal complete'
      );

      res.status(200).json({
        success: true,
        details: scrubResult,
        message: type === 'GDPR_ERASURE' 
          ? 'Comprehensive data erasure initiated' 
          : 'Withdrawal request processed. Peer caches will be updated.',
      });
    } catch (error) {
      logger.error({ error }, 'Error processing withdrawal request');
      res.status(500).json({ error: 'Failed to process withdrawal request' });
    }
  });

  return router;
}
