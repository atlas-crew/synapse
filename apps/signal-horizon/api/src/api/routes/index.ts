/**
 * API Routes Index
 * Combines all route modules with authentication
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { createAuthMiddleware } from '../middleware/auth.js';
import { createCampaignRoutes } from './campaigns.js';
import { createThreatRoutes } from './threats.js';
import { createBlocklistRoutes } from './blocklist.js';
import { createWarRoomRoutes } from './warroom.js';
import { createIntelRoutes } from './intel.js';

export function createApiRouter(prisma: PrismaClient, logger: Logger): Router {
  const router = Router();
  const authMiddleware = createAuthMiddleware(prisma);

  // All API routes require authentication
  router.use(authMiddleware);

  // Mount route modules
  router.use('/campaigns', createCampaignRoutes(prisma));
  router.use('/threats', createThreatRoutes(prisma));
  router.use('/blocklist', createBlocklistRoutes(prisma));
  router.use('/warrooms', createWarRoomRoutes(prisma, logger));
  router.use('/intel', createIntelRoutes(prisma, logger));

  return router;
}
