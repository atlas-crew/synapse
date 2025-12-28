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
import { createHuntRoutes } from './hunt.js';
import { createFleetRoutes } from './fleet.js';
import { createApexRouter } from './apex/index.js';
import type { HuntService } from '../../services/hunt/index.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';

export interface ApiRouterOptions {
  huntService?: HuntService;
  fleetAggregator?: FleetAggregator;
  configManager?: ConfigManager;
  fleetCommander?: FleetCommander;
  ruleDistributor?: RuleDistributor;
}

export function createApiRouter(
  prisma: PrismaClient,
  logger: Logger,
  options: ApiRouterOptions = {}
): Router {
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

  // Mount hunt routes if HuntService is provided
  if (options.huntService) {
    router.use('/hunt', createHuntRoutes(prisma, logger, options.huntService));
    logger.info('Hunt routes mounted at /api/v1/hunt');
  }

  // Mount fleet management routes if fleet services are provided
  if (options.fleetAggregator || options.configManager || options.fleetCommander || options.ruleDistributor) {
    router.use('/fleet', createFleetRoutes(prisma, logger, options));
    logger.info('Fleet routes mounted at /api/v1/fleet');
  }

  // Mount Apex (Customer Protection Console) routes
  router.use('/apex', createApexRouter(prisma, logger));
  logger.info('Apex routes mounted at /api/v1/apex');

  return router;
}
