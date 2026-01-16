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
import { createAPIIntelligenceRoutes } from './api-intelligence.js';
import { createFleetControlRoutes } from './fleet-control.js';
import { createFleetFilesRoutes } from './fleet-files.js';
import { createFleetReleasesRoutes } from './fleet-releases.js';
import { createFleetPolicyRoutes } from './fleet-policy.js';
import { createFleetSessionsRoutes } from './fleet-sessions.js';
import { createFleetBandwidthRoutes } from './fleet-bandwidth.js';
import type { FleetSessionQueryService } from '../../services/fleet/session-query.js';
import type { HuntService } from '../../services/hunt/index.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';
import type { SynapseProxyService } from '../../services/synapse-proxy.js';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';

export interface ApiRouterOptions {
  huntService?: HuntService;
  fleetAggregator?: FleetAggregator;
  configManager?: ConfigManager;
  fleetCommander?: FleetCommander;
  ruleDistributor?: RuleDistributor;
  synapseProxy?: SynapseProxyService;
  tunnelBroker?: TunnelBroker;
  sessionQueryService?: FleetSessionQueryService;
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

  // Mount API Intelligence routes for endpoint discovery and schema violations
  router.use('/api-intelligence', createAPIIntelligenceRoutes(prisma, logger));
  logger.info('API Intelligence routes mounted at /api/v1/api-intelligence');

  // Mount Fleet Control routes for remote sensor management
  router.use('/fleet-control', createFleetControlRoutes(prisma, logger, {
    tunnelBroker: options.tunnelBroker,
  }));
  logger.info('Fleet Control routes mounted at /api/v1/fleet-control');

  // Mount Fleet Files routes for secure file transfer
  router.use('/fleet', createFleetFilesRoutes(prisma, logger, {
    tunnelBroker: options.tunnelBroker,
  }));
  logger.info('Fleet Files routes mounted at /api/v1/fleet/:sensorId/files');

  // Mount Fleet Releases routes for firmware/update management
  router.use('/releases', createFleetReleasesRoutes(prisma, logger, {
    tunnelBroker: options.tunnelBroker,
  }));
  logger.info('Fleet Releases routes mounted at /api/v1/releases');

  // Mount Fleet Policy routes for global security policy management
  router.use('/fleet/policies', createFleetPolicyRoutes(prisma, logger, {
    fleetCommander: options.fleetCommander,
  }));
  logger.info('Fleet Policy routes mounted at /api/v1/fleet/policies');

  // Mount Fleet Sessions routes for global session search and management
  router.use('/fleet', createFleetSessionsRoutes(prisma, logger, {
    sessionQueryService: options.sessionQueryService,
  }));
  logger.info('Fleet Sessions routes mounted at /api/v1/fleet/sessions');

  // Mount Fleet Bandwidth routes for bandwidth metrics and billing
  router.use('/fleet/bandwidth', createFleetBandwidthRoutes(prisma, logger, {
    tunnelBroker: options.tunnelBroker,
  }));
  logger.info('Fleet Bandwidth routes mounted at /api/v1/fleet/bandwidth');

  return router;
}
