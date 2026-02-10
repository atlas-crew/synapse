/**
 * API Routes Index
 * Combines all route modules with authentication and security middleware
 *
 * PEN-004: Content-type validation applied globally to all mutation endpoints.
 */

import { Router } from 'express';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { createAuthMiddleware } from '../middleware/auth.js';
import { createAuthRateLimiters } from '../middleware/rate-limit.js';
import { rateLimiters } from '../../middleware/rate-limiter.js';
import { contentTypeValidation } from '../../middleware/content-type.js';
import { apiVersioning } from '../../middleware/versioning.js';
import { csrfProtection, csrfTokenHandler, ensureCsrfToken } from '../../middleware/csrf.js';
import { createReplayProtection, PrismaNonceStore } from '../../middleware/replay-protection.js';
import { createCampaignRoutes } from './campaigns.js';
import { createThreatRoutes } from './threats.js';
import { createBlocklistRoutes } from './blocklist.js';
import { createWarRoomRoutes } from './warroom.js';
import { createIntelRoutes } from './intel.js';
import { createHuntRoutes } from './hunt.js';
import { createHuntSigmaRoutes } from './hunt-sigma.js';
import { createFleetRoutes } from './fleet.js';
import { createFleetIntelRoutes } from './fleet-intel.js';
import { createBeamRouter } from './beam/index.js';
import { createTunnelRoutes } from './tunnel.js';
import { createManagementRoutes } from './management.js';
import { createOnboardingRoutes } from './onboarding.js';
import { createTenantRoutes } from './tenant.js';
import { createAuthRoutes } from './auth.js';
import { createUserRoutes } from './users.js';
import { createSynapseRoutes } from './synapse.js';
import { createAPIIntelligenceRoutes } from './api-intelligence.js';
import { createFleetControlRoutes } from './fleet-control.js';
import { createFleetFilesRoutes } from './fleet-files.js';
import { createFleetReleasesRoutes } from './fleet-releases.js';
import { createFleetPolicyRoutes } from './fleet-policy.js';
import { createFleetSessionsRoutes } from './fleet-sessions.js';
import { createFleetBandwidthRoutes } from './fleet-bandwidth.js';
import { createPlaybookRoutes } from './playbooks.js';
import docsRouter from './docs.js';
import { UserAuthService } from '../../services/user-auth.js';
import { createAuthManagementRoutes } from './auth-management.js';
import type { RedisKv } from '../../storage/redis/kv.js';
import type { FleetSessionQueryService } from '../../services/fleet/session-query.js';
import type { HuntService } from '../../services/hunt/index.js';
import type { SigmaHuntService } from '../../services/sigma-hunt/index.js';
import type { FleetAggregator } from '../../services/fleet/fleet-aggregator.js';
import type { ConfigManager } from '../../services/fleet/config-manager.js';
import type { FleetCommander } from '../../services/fleet/fleet-commander.js';
import type { RuleDistributor } from '../../services/fleet/rule-distributor.js';
import type { SynapseProxyService } from '../../services/synapse-proxy.js';
import type { TunnelBroker } from '../../websocket/tunnel-broker.js';
import type { WarRoomService } from '../../services/warroom/index.js';
import type { APIIntelligenceService } from '../../services/api-intelligence/index.js';
import type { ClickHouseService } from '../../storage/clickhouse/index.js';
import type { PreferenceService } from '../../services/fleet/preference-service.js';

export interface ApiRouterOptions {
  huntService?: HuntService;
  sigmaHuntService?: SigmaHuntService;
  fleetAggregator?: FleetAggregator;
  configManager?: ConfigManager;
  fleetCommander?: FleetCommander;
  ruleDistributor?: RuleDistributor;
  clickhouse?: ClickHouseService | null;
  synapseProxy?: SynapseProxyService;
  tunnelBroker?: TunnelBroker;
  sessionQueryService?: FleetSessionQueryService;
  warRoomService?: WarRoomService;
  apiIntelligenceService?: APIIntelligenceService;
  preferenceService?: PreferenceService;
  /** Redis KV for epoch-based token revocation (labs-wqy1) */
  kv?: RedisKv | null;
  // Additional services for dependency injection
  intelService?: import('../../services/intel/index.js').IntelService;
  policyService?: import('../../services/fleet/policy-template.js').PolicyTemplateService;
  bandwidthService?: import('../../services/fleet/bandwidth-aggregator.js').BandwidthAggregatorService;
  fleetIntelService?: import('../../services/fleet/fleet-intel.js').FleetIntelService;
  playbookService?: import('../../services/warroom/playbook-service.js').PlaybookService;
  securityAuditService?: import('../../services/audit/security-audit.js').SecurityAuditService;
}

export function createApiRouter(
  prisma: PrismaClient,
  logger: Logger,
  options: ApiRouterOptions = {}
): Router {
  const router = Router();
  const kv = options.kv ?? null;
  const authMiddleware = createAuthMiddleware(prisma, kv);
  const authRateLimiters = createAuthRateLimiters(logger);
  const userAuthService = new UserAuthService(prisma, logger, kv);

  // PEN-004: Content-type validation for all mutation endpoints
  // Applied before auth to reject malformed requests early
  router.use(contentTypeValidation({
    requiredType: 'application/json',
    skipRoutes: [
      '/docs',           // Documentation routes may not have bodies
      /^\/fleet\/.*\/files/,  // File upload routes use multipart
    ],
    uploadRoutes: [
      /^\/fleet\/.*\/files/,  // Allow multipart for file uploads
      /^\/releases\/.*\/upload/,  // Allow multipart for release uploads
    ],
  }));

  // CSRF token endpoint (before auth - allows getting token for login flows)
  // Double-submit cookie pattern: client sends token from cookie in X-CSRF-Token header
  router.get('/csrf-token', csrfTokenHandler());

  // Ensure CSRF cookie exists on all requests (sets cookie if missing)
  router.use(ensureCsrfToken());

  // Apply API versioning (labs-2j5u.17)
  router.use(apiVersioning({
    defaultVersion: 1,
    supportedVersions: [1],
  }));

  // Apply global rate limiting to all authenticated routes (labs-mmft.7)
  router.use(rateLimiters.global);

  // Apply auth-specific rate limits only to auth endpoints (labs-tj9l).
  // These limiters use skipSuccessfulRequests; if mounted globally they'd treat any 4xx/5xx
  // (including "Cannot GET" 404s) as "failed auth" and can block unrelated API calls in dev.
  router.use('/auth', authRateLimiters.ipBurst);
  router.use('/auth', authRateLimiters.ipFailures);
  router.use('/auth', authRateLimiters.keyFailures);

  // Mount Auth routes (handled its own auth for public endpoints)
  router.use('/auth', createAuthRoutes(prisma, logger, userAuthService, authMiddleware));

  // All other API routes require authentication
  router.use(authMiddleware);

  // M-3: Replay protection for all non-idempotent requests (headers required by default).
  // Use Prisma-backed store so nonce reuse is detected across instances.
  const allowMissingHeadersUntilMs = process.env.REPLAY_ALLOW_MISSING_UNTIL
    ? Date.parse(process.env.REPLAY_ALLOW_MISSING_UNTIL)
    : undefined;

  const replayProtection = createReplayProtection({
    store: new PrismaNonceStore(prisma, { windowMs: 5 * 60 * 1000 }),
    allowMissingHeadersUntilMs:
      typeof allowMissingHeadersUntilMs === 'number' && Number.isFinite(allowMissingHeadersUntilMs)
        ? allowMissingHeadersUntilMs
        : undefined,
    onViolation: ({ code, method, path, clientIp, tenantId }) => {
      logger.warn(
        { code, method, path, clientIp, tenantId },
        'Replay protection violation'
      );
    },
  });
  router.use(replayProtection.middleware);

  // CSRF protection for mutation endpoints
  // Note: Bearer token auth is inherently CSRF-resistant, but this provides defense-in-depth
  // Skip WebSocket-related routes and file uploads which have their own protection
  router.use(csrfProtection({
    skipRoutes: [
      '/docs',                      // Documentation (read-only)
      '/csrf-token',                // CSRF token endpoint itself
      '/onboarding',                // Onboarding uses API keys, not cookies
      '/hunt',                      // Hunt queries use bearer auth; treat as CSRF-resistant
      /^\/auth\/login/,             // Public auth
      /^\/auth\/refresh/,           // Public auth
      /^\/fleet\/.*\/files/,        // File uploads use multipart + auth
      /^\/releases\/.*\/upload/,    // Release uploads use multipart + auth
      /^\/tunnel/,                  // Tunnel routes use WebSocket auth
      /^\/synapse/,                 // Synapse proxy routes
    ],
  }));

  // Mount Auth Management routes (admin-only token revocation, epoch management)
  router.use('/auth', createAuthManagementRoutes(prisma, logger, kv));

  // Mount route modules
  router.use('/campaigns', createCampaignRoutes(prisma));
  router.use('/threats', createThreatRoutes(prisma));
  router.use('/blocklist', createBlocklistRoutes(prisma));
  router.use('/warrooms', createWarRoomRoutes(prisma, logger, {
    warRoomService: options.warRoomService,
  }));
  router.use('/intel', createIntelRoutes(prisma, logger, {
    intelService: options.intelService,
  }));

  // Mount sigma hunt routes if SigmaHuntService is provided (independent of HuntService).
  if (options.sigmaHuntService) {
    router.use('/hunt/sigma', createHuntSigmaRoutes(prisma, logger, options.sigmaHuntService));
    logger.info('Sigma hunt routes mounted at /api/v1/hunt/sigma');
  }

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

  if (options.fleetIntelService) {
    router.use('/fleet/intel', createFleetIntelRoutes(prisma, logger, {
      fleetIntelService: options.fleetIntelService,
    }));
    logger.info('Fleet intel routes mounted at /api/v1/fleet/intel');
  }

  // Mount Beam (Customer Protection Console) routes
  router.use('/beam', createBeamRouter(prisma, logger, options.securityAuditService));
  logger.info('Beam routes mounted at /api/v1/beam');

  // Mount Tunnel routes for remote sensor access
  router.use('/tunnel', createTunnelRoutes(prisma, logger));
  logger.info('Tunnel routes mounted at /api/v1/tunnel');

  // Mount Management routes for API keys and connectivity
  router.use('/management', createManagementRoutes(prisma, logger, {
    fleetCommander: options.fleetCommander,
  }));
  logger.info('Management routes mounted at /api/v1/management');

  // Mount Tenant routes for settings
  router.use('/tenant', createTenantRoutes(prisma, logger, options.securityAuditService, options.preferenceService));
  logger.info('Tenant routes mounted at /api/v1/tenant');

  // Mount Users routes
  router.use('/users', createUserRoutes(prisma, logger));
  logger.info('User Management routes mounted at /api/v1/users');

  // Mount Onboarding routes for sensor registration
  router.use('/onboarding', createOnboardingRoutes(prisma, logger));
  logger.info('Onboarding routes mounted at /api/v1/onboarding');

  // Mount Synapse proxy routes for sensor introspection
  if (options.synapseProxy) {
    router.use('/synapse', createSynapseRoutes(options.synapseProxy, logger, {
      fleetIntelService: options.fleetIntelService,
      prisma,
    }));
    logger.info('Synapse routes mounted at /api/v1/synapse');
  }

  // Mount API Intelligence routes for endpoint discovery and schema violations
  router.use('/api-intelligence', createAPIIntelligenceRoutes(
    prisma,
    logger,
    options.apiIntelligenceService
  ));
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
    fleetCommander: options.fleetCommander,
  }));
  logger.info('Fleet Releases routes mounted at /api/v1/releases');

  // Mount Fleet Policy routes for global security policy management
  router.use('/fleet/policies', createFleetPolicyRoutes(prisma, logger, {
    fleetCommander: options.fleetCommander,
    policyService: options.policyService,
    securityAuditService: options.securityAuditService,
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
    bandwidthService: options.bandwidthService,
  }));
  logger.info('Fleet Bandwidth routes mounted at /api/v1/fleet/bandwidth');

  // Mount Playbook routes for incident response automation
  router.use('/playbooks', createPlaybookRoutes(prisma, logger, {
    fleetCommander: options.fleetCommander,
    warRoomService: options.warRoomService,
    playbookService: options.playbookService,
    securityAuditService: options.securityAuditService,
  }));
  logger.info('Playbook routes mounted at /api/v1/playbooks');

  // Mount documentation routes
  router.use('/docs', docsRouter);
  logger.info('Documentation routes mounted at /api/v1/docs');

  return router;
}
