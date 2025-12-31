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
import { createBeamRouter } from './beam/index.js';
import { createTunnelRoutes } from './tunnel.js';
import { createManagementRoutes } from './management.js';
import { createOnboardingRoutes } from './onboarding.js';
import { createSynapseRoutes } from './synapse.js';
import type { HuntService } from '../../services/hunt/index.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';
import type { SynapseProxyService } from '../../services/synapse-proxy.js';

export interface ApiRouterOptions {
  huntService?: HuntService;
  fleetAggregator?: FleetAggregator;
  configManager?: ConfigManager;
  fleetCommander?: FleetCommander;
  ruleDistributor?: RuleDistributor;
  synapseProxy?: SynapseProxyService;
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

  // Mount Beam (Customer Protection Console) routes
  router.use('/beam', createBeamRouter(prisma, logger));
  logger.info('Beam routes mounted at /api/v1/beam');

  // Mount Tunnel routes for remote sensor access
  router.use('/tunnel', createTunnelRoutes(prisma, logger));
  logger.info('Tunnel routes mounted at /api/v1/tunnel');

  // Mount Management routes for API keys and connectivity
  router.use('/management', createManagementRoutes(prisma, logger));
  logger.info('Management routes mounted at /api/v1/management');

  // Mount Onboarding routes for sensor registration
  router.use('/onboarding', createOnboardingRoutes(prisma, logger));
  logger.info('Onboarding routes mounted at /api/v1/onboarding');

  // Mount Synapse proxy routes for sensor introspection
  if (options.synapseProxy) {
    router.use('/synapse', createSynapseRoutes(options.synapseProxy, logger));
    logger.info('Synapse routes mounted at /api/v1/synapse');
  }

  return router;
}
