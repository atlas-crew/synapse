/**
 * Public sensor-enrollment routes (unauthenticated except for registration
 * token in the Authorization header).
 *
 * Powers the onboarding wizard's "we see you" feedback loop. A sensor host
 * runs `POST /api/v1/sensors/announce` with the registration token issued
 * by an operator and its own fingerprint/hostname/OS; Horizon stores a
 * SensorCandidate row that the wizard surfaces live. The actual enrollment
 * still happens via the existing WebSocket handshake — the announce is a
 * UX pre-step, not the security boundary for full sensor registration.
 *
 * Mounted BEFORE the global auth middleware so sensors without a user
 * session can reach it. The registration token itself is the only
 * credential accepted here.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import type { PrismaClient, Prisma } from '@prisma/client';
import type { Logger } from 'pino';
import { rateLimiters } from '../../middleware/rate-limiter.js';

const announceSchema = z.object({
  fingerprint: z.string().min(8).max(128).regex(/^[A-Za-z0-9_:\-]+$/),
  hostname: z.string().min(1).max(253).optional(),
  os: z.string().max(64).optional(),
  kernel: z.string().max(128).optional(),
  architecture: z.string().max(32).optional(),
  ipAddress: z.string().max(45).optional(),
  version: z.string().max(64).optional(),
  metadata: z.record(z.unknown()).optional(),
});

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function extractBearer(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

export function createSensorEnrollmentRoutes(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();

  /**
   * POST /api/v1/sensors/announce
   *
   * Unauthenticated except for `Authorization: Bearer <registration-token>`.
   * Rate-limited per source IP.
   */
  router.post(
    '/announce',
    rateLimiters.onboarding,
    async (req: Request, res: Response): Promise<void> => {
      try {
        const rawToken = extractBearer(req.header('authorization'));
        if (!rawToken) {
          res.status(401).json({ error: 'Missing bearer registration token' });
          return;
        }

        const parsed = announceSchema.safeParse(req.body);
        if (!parsed.success) {
          res.status(400).json({
            error: 'Validation failed',
            details: parsed.error.issues,
          });
          return;
        }

        const tokenHash = hashToken(rawToken);
        const tokenRecord = await prisma.registrationToken.findUnique({
          where: { tokenHash },
          include: { _count: { select: { registeredSensors: true } } },
        });

        if (!tokenRecord) {
          res.status(401).json({ error: 'Invalid registration token' });
          return;
        }
        if (tokenRecord.revoked) {
          res.status(401).json({ error: 'Registration token has been revoked' });
          return;
        }
        if (tokenRecord.expiresAt && new Date(tokenRecord.expiresAt) < new Date()) {
          res.status(401).json({ error: 'Registration token has expired' });
          return;
        }
        if (tokenRecord._count.registeredSensors >= tokenRecord.maxUses) {
          res.status(401).json({ error: 'Registration token has reached its use limit' });
          return;
        }

        const body = parsed.data;
        const userAgent = req.header('user-agent')?.slice(0, 255) ?? null;
        const reportedIp = body.ipAddress ?? (req.ip ?? null);

        const now = new Date();
        const candidate = await prisma.sensorCandidate.upsert({
          where: {
            registrationTokenId_fingerprint: {
              registrationTokenId: tokenRecord.id,
              fingerprint: body.fingerprint,
            },
          },
          create: {
            tenantId: tokenRecord.tenantId,
            registrationTokenId: tokenRecord.id,
            fingerprint: body.fingerprint,
            hostname: body.hostname ?? null,
            os: body.os ?? null,
            kernel: body.kernel ?? null,
            architecture: body.architecture ?? null,
            ipAddress: reportedIp,
            version: body.version ?? null,
            userAgent,
            metadata: (body.metadata ?? {}) as Prisma.InputJsonValue,
          },
          update: {
            hostname: body.hostname ?? null,
            os: body.os ?? null,
            kernel: body.kernel ?? null,
            architecture: body.architecture ?? null,
            ipAddress: reportedIp,
            version: body.version ?? null,
            userAgent,
            metadata: (body.metadata ?? {}) as Prisma.InputJsonValue,
            lastSeenAt: now,
            announceCount: { increment: 1 },
          },
        });

        logger.info(
          {
            candidateId: candidate.id,
            tokenId: tokenRecord.id,
            tenantId: tokenRecord.tenantId,
            fingerprint: body.fingerprint,
          },
          'Sensor candidate announced'
        );

        res.status(202).json({
          candidateId: candidate.id,
          status: candidate.claimedSensorId ? 'claimed' : 'announced',
          announceCount: candidate.announceCount,
          nextStep: {
            action: 'websocket_connect',
            description:
              'Your sensor is visible in the Horizon onboarding wizard. Connect the sensor WebSocket using the same registration token to complete enrollment.',
          },
        });
      } catch (error) {
        logger.error({ error }, 'Error processing sensor announce');
        res.status(500).json({ error: 'Failed to process announce' });
      }
    }
  );

  return router;
}
