/**
 * Synapse Proxy API Routes
 *
 * REST endpoints for interacting with sensor's local Synapse API
 * through the WebSocket tunnel.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import type { Logger } from 'pino';
import { createHash } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { requireScope, requireRole } from '../middleware/auth.js';
import { sendProblem } from '../../lib/problem-details.js';
import {
  SynapseProxyService,
  SynapseProxyError,
  SensorError,
  type Block,
  type Rule,
  type EvalRequest,
  type SensorConfigSection,
} from '../../services/synapse-proxy.js';

// ============================================================================
// Validation Schemas
// ============================================================================

const PaginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(25),
  offset: z.coerce.number().int().min(0).default(0),
});

const EntityFilterSchema = PaginationSchema.extend({
  type: z.enum(['IP', 'FINGERPRINT', 'SESSION', 'USER']).optional(),
});

const BlockFilterSchema = PaginationSchema.extend({
  type: z.enum(['IP', 'FINGERPRINT', 'CIDR', 'USER_AGENT']).optional(),
});

const RuleFilterSchema = PaginationSchema.extend({
  type: z.enum(['BLOCK', 'CHALLENGE', 'RATE_LIMIT', 'MONITOR']).optional(),
  enabled: z.coerce.boolean().optional(),
});

const ActorFilterSchema = PaginationSchema.extend({
  type: z.enum(['human', 'bot', 'crawler', 'suspicious', 'attacker']).optional(),
  minScore: z.coerce.number().min(0).max(100).optional(),
  minRisk: z.coerce.number().min(0).max(100).optional(),
  min_risk: z.coerce.number().min(0).max(100).optional(),
  ip: z.string().optional(),
  fingerprint: z.string().optional(),
});

const TimelineQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

const SessionFilterSchema = PaginationSchema.extend({
  actorId: z.string().optional(),
  actor_id: z.string().optional(),
  suspicious: z.preprocess(
    (val) => {
      // Missing query param must stay `undefined` (do not default to false).
      if (val === undefined || val === null || val === '') return undefined;
      if (val === true || val === 'true' || val === '1') return true;
      if (val === false || val === 'false' || val === '0') return false;
      return undefined;
    },
    z.boolean().optional()
  ),
});

const CampaignFilterSchema = PaginationSchema.extend({
  status: z.string().optional(),
});

const PayloadLimitSchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).optional(),
});
const ProfileTemplateSchema = z.object({
  template: z.string().min(1).max(2048),
});
const ProfileFilterSchema = PaginationSchema;

const AddBlockSchema = z.object({
  type: z.enum(['IP', 'FINGERPRINT', 'CIDR', 'USER_AGENT']),
  value: z.string().min(1),
  source: z.enum(['MANUAL', 'AUTO', 'FLEET_INTEL', 'RULE']).default('MANUAL'),
  reason: z.string().max(500),
  expiresAt: z.string().datetime().optional(),
  ruleId: z.string().optional(),
});

const RuleConditionSchema = z.object({
  field: z.string(),
  operator: z.enum(['eq', 'ne', 'gt', 'lt', 'contains', 'matches', 'in']),
  value: z.unknown().transform((v) => v ?? null),
});

const RuleActionSchema = z.object({
  type: z.enum(['block', 'challenge', 'rate_limit', 'tag', 'log']),
  params: z.record(z.unknown()).optional(),
});

const AddRuleSchema = z.object({
  name: z.string().min(1).max(100),
  type: z.enum(['BLOCK', 'CHALLENGE', 'RATE_LIMIT', 'MONITOR']),
  enabled: z.boolean().default(true),
  priority: z.number().int().min(0).max(1000).default(100),
  conditions: z.array(RuleConditionSchema).min(1),
  actions: z.array(RuleActionSchema).min(1),
  ttl: z.number().int().positive().optional(),
});

const UpdateRuleSchema = AddRuleSchema.partial();

const EvalRequestSchema = z.object({
  method: z.string(),
  path: z.string(),
  headers: z.record(z.string()),
  body: z.string().optional(),
  clientIp: z.string(),
  fingerprint: z.string().optional(),
});

const ConfigSectionSchema = z.enum([
  'dlp',
  'block-page',
  'crawler',
  'tarpit',
  'travel',
  'entity',
  'kernel',
]);

const ConfigQuerySchema = z.object({
  section: ConfigSectionSchema.optional(),
});

const ConfigUpdateSchema = z.object({
  section: ConfigSectionSchema,
  config: z.record(z.unknown()),
});

const GlobalConfigUpdateSchema = ConfigUpdateSchema.extend({
  sensorIds: z.array(z.string().min(1)).optional(),
});

// ============================================================================
// Route Factory
// ============================================================================

export interface SynapseRoutesOptions {
  fleetIntelService?: import('../../services/fleet/fleet-intel.js').FleetIntelService;
  prisma?: PrismaClient;
}

export function createSynapseRoutes(
  synapseProxy: SynapseProxyService,
  logger: Logger,
  options: SynapseRoutesOptions = {}
): Router {
  const router = Router();
  const { fleetIntelService, prisma } = options;

  // ==========================================================================
  // Compatibility: DLP Proxy Endpoints
  // ==========================================================================
  //
  // The UI currently calls these paths, but the hub no longer exposes a generic
  // synapse "proxy" surface. Provide safe, read-only stubs so the page works
  // in local development and the nav doesn't hard-fail with 404s.
  router.get(
    '/:sensorId/proxy/_sensor/dlp/stats',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const tenantId = req.auth!.tenantId;
      const sensorId = (req.params as { sensorId: string }).sensorId;

      const snapshot = prisma
        ? await prisma.sensorPayloadSnapshot.findFirst({
            where: { tenantId, sensorId },
            orderBy: { capturedAt: 'desc' },
            select: { stats: true },
          })
        : null;

      const stats = (snapshot?.stats ?? null) as unknown;
      const obj = typeof stats === 'object' && stats !== null ? (stats as Record<string, unknown>) : null;
      const dlp = obj && typeof obj.dlp === 'object' && obj.dlp !== null ? (obj.dlp as Record<string, unknown>) : null;

      const totalScans = Number(dlp?.totalScans ?? 0);
      const totalMatches = Number(dlp?.totalMatches ?? 0);
      const patternCount = Number(dlp?.patternCount ?? 0);

      res.json({
        totalScans: Number.isFinite(totalScans) ? totalScans : 0,
        totalMatches: Number.isFinite(totalMatches) ? totalMatches : 0,
        patternCount: Number.isFinite(patternCount) ? patternCount : 0,
      });
    }
  );

  router.get(
    '/:sensorId/proxy/_sensor/dlp/violations',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const tenantId = req.auth!.tenantId;
      const sensorId = (req.params as { sensorId: string }).sensorId;

      const snapshot = prisma
        ? await prisma.sensorPayloadSnapshot.findFirst({
            where: { tenantId, sensorId },
            orderBy: { capturedAt: 'desc' },
            select: { stats: true },
          })
        : null;

      const stats = (snapshot?.stats ?? null) as unknown;
      const obj = typeof stats === 'object' && stats !== null ? (stats as Record<string, unknown>) : null;
      const dlp = obj && typeof obj.dlp === 'object' && obj.dlp !== null ? (obj.dlp as Record<string, unknown>) : null;
      const rawViolations = Array.isArray(dlp?.violations) ? (dlp?.violations as unknown[]) : [];

      const violations = rawViolations
        .map((v) => (typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : null))
        .filter((v): v is Record<string, unknown> => !!v)
        .map((v) => ({
          timestamp: Number(v.timestamp ?? Date.now()),
          pattern_name: String(v.pattern_name ?? 'Unknown'),
          data_type: String(v.data_type ?? 'unknown'),
          severity: String(v.severity ?? 'low'),
          masked_value: String(v.masked_value ?? '********'),
          client_ip: v.client_ip === undefined || v.client_ip === null ? undefined : String(v.client_ip),
          path: String(v.path ?? '/'),
        }));

      res.json({ violations });
    }
  );

  /**
   * Helper to handle synapse proxy errors consistently
   * Uses the enhanced SynapseProxyError.toJSON() for structured responses.
   * Now includes optional database fallback for read operations.
   */
  async function handleError(req: Request, res: Response, error: unknown, context: string, sensorId?: string): Promise<void> {
    const isOffline = error instanceof SynapseProxyError && 
      (error.code === 'TUNNEL_NOT_FOUND' || error.code === 'SENSOR_DISCONNECTED' || error.code === 'TIMEOUT');

    const effectiveSensorId = sensorId || 'synapse-waf-1';

    if (isOffline && fleetIntelService) {
      logger.info({ sensorId: effectiveSensorId, context, errorCode: (error as SynapseProxyError).code }, 'Sensor unreachable, attempting database fallback');
      try {
        const tenantId = req.auth!.tenantId;

        // Fleet intel snapshots do not match the SOC UI contract; normalize here.
        const jsonStringArray = (input: unknown): string[] => {
          if (!input) return [];
          if (Array.isArray(input)) return input.map((v) => String(v));
          return [];
        };

        const sha256Hex = (input: string): string =>
          createHash('sha256').update(input).digest('hex');

        const normalizeHijackAlerts = (sessionId: string, input: unknown): unknown[] => {
          if (!input) return [];
          if (!Array.isArray(input)) return [];

          // Support both shapes:
          // - Synapse shape: {sessionId, alertType, originalValue, newValue, timestamp, confidence}
          // - Seed legacy: {type, confidence, ts}
          return input.map((a) => {
            const obj = (a ?? {}) as Record<string, unknown>;
            const alertType = String(obj.alertType ?? obj.type ?? 'unknown');
            const timestamp = Number(obj.timestamp ?? obj.ts ?? Date.now());
            const confidence = Number(obj.confidence ?? 0);
            return {
              sessionId,
              alertType,
              originalValue: String(obj.originalValue ?? 'unknown'),
              newValue: String(obj.newValue ?? 'unknown'),
              timestamp: Number.isFinite(timestamp) ? timestamp : Date.now(),
              confidence: Number.isFinite(confidence) ? confidence : 0,
            };
          });
        };

        const normalizeActorRow = (a: any): Record<string, unknown> => {
          const raw = (a.raw ?? {}) as Record<string, unknown>;
          return {
            actorId: a.actorId,
            riskScore: a.riskScore,
            ruleMatches: Array.isArray(raw.ruleMatches) ? raw.ruleMatches : [],
            anomalyCount: Number(raw.anomalyCount ?? 0),
            sessionIds: jsonStringArray(a.sessionIds ?? raw.sessionIds),
            firstSeen: a.firstSeenAt.getTime(),
            lastSeen: a.lastSeenAt.getTime(),
            ips: jsonStringArray(a.ips ?? raw.ips),
            fingerprints: jsonStringArray(a.fingerprints ?? raw.fingerprints),
            isBlocked: !!a.isBlocked,
            blockReason: raw.blockReason ?? (a.isBlocked ? 'blocked (seeded)' : null),
            blockedSince: raw.blockedSince ?? (a.isBlocked ? a.lastSeenAt.getTime() : null),
          };
        };

        if (context === 'listActors') {
          const parsed = ActorFilterSchema.safeParse(req.query);
          const result = await fleetIntelService.getActors(tenantId, {
            minRisk: parsed.success ? (parsed.data.minRisk ?? parsed.data.min_risk) : undefined,
            limit: parsed.success ? parsed.data.limit : 100,
            offset: parsed.success ? parsed.data.offset : 0,
          });
          // Filter for the effective sensor, or return all if needed
          const sensorActors = result.actors.filter(a => a.sensorId === effectiveSensorId);
          const actorsToReturn = sensorActors.length > 0 ? sensorActors : result.actors;
          
          logger.info({ 
            tenantId, 
            sensorId: effectiveSensorId, 
            totalFound: result.actors.length, 
            returned: actorsToReturn.length 
          }, 'Actors fallback executed');

          res.json({ 
            actors: actorsToReturn.map((a) => normalizeActorRow(a)),
            stats: {
              totalActors: actorsToReturn.length,
              blockedActors: actorsToReturn.filter(a => a.isBlocked).length,
              correlationsMade: 0,
              evictions: 0,
              totalCreated: actorsToReturn.length,
              totalRuleMatches: 0
            },
            _fallback: true,
            _sensorId: effectiveSensorId
          });
          return;
        }
        if (context === 'getActor') {
          const actorId = (req.params as { actorId?: string }).actorId;
          if (!actorId) {
            res.status(400).json({ error: 'Missing actorId', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          // FleetIntelService does not currently support direct actorId lookup; page until found.
          const pageSize = 500;
          let offset = 0;
          let found: any | null = null;
          for (let i = 0; i < 10; i++) {
            const page = await fleetIntelService.getActors(tenantId, { limit: pageSize, offset });
            const match =
              page.actors.find((a) => a.sensorId === effectiveSensorId && a.actorId === actorId) ??
              page.actors.find((a) => a.actorId === actorId);
            if (match) {
              found = match;
              break;
            }
            offset += pageSize;
            if (offset >= page.total) break;
          }

          if (!found) {
            res.status(404).json({ error: 'Actor not found', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          res.json({ actor: normalizeActorRow(found), _fallback: true, _sensorId: effectiveSensorId });
          return;
        }
        if (context === 'getActorTimeline') {
          const actorId = (req.params as { actorId?: string }).actorId;
          const parsed = TimelineQuerySchema.safeParse(req.query);
          const limit = parsed.success ? (parsed.data.limit ?? 100) : 100;

          if (!actorId) {
            res.status(400).json({ error: 'Missing actorId', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          // Best-effort timeline from session activity + hijack alerts.
          const sessionsResult = await fleetIntelService.getSessions(tenantId, {
            actorId,
            limit: Math.min(200, limit),
            offset: 0,
          });

          const events: any[] = [];
          for (const s of sessionsResult.sessions) {
            if (s.sensorId !== effectiveSensorId && sessionsResult.sessions.some((x) => x.sensorId === effectiveSensorId)) {
              continue;
            }

            events.push({
              timestamp: s.lastActivityAt.getTime(),
              eventType: 'session_bind',
              sessionId: s.sessionId,
              actorId,
              boundJa4: s.boundJa4 ?? null,
              boundIp: s.boundIp ?? null,
            });

            const hijackAlerts = normalizeHijackAlerts(s.sessionId, s.hijackAlerts ?? (s.raw as any)?.hijackAlerts);
            for (const a of hijackAlerts) {
              const obj = (a ?? {}) as Record<string, unknown>;
              events.push({
                timestamp: Number(obj.timestamp ?? s.lastActivityAt.getTime()),
                eventType: 'session_alert',
                sessionId: s.sessionId,
                actorId,
                alertType: String(obj.alertType ?? 'unknown'),
                confidence: Number(obj.confidence ?? 0),
              });
            }
          }

          events.sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0));
          res.json({ actorId, events: events.slice(0, limit), _fallback: true, _sensorId: effectiveSensorId });
          return;
        }
        if (context === 'listSessions') {
          const parsed = SessionFilterSchema.safeParse(req.query);
          const actorId = parsed.success ? (parsed.data.actorId ?? parsed.data.actor_id) : undefined;
          const result = await fleetIntelService.getSessions(tenantId, {
            actorId,
            suspicious: parsed.success ? parsed.data.suspicious : undefined,
            limit: parsed.success ? parsed.data.limit : 100,
            offset: parsed.success ? parsed.data.offset : 0,
          });
          const sensorSessions = result.sessions.filter(s => s.sensorId === effectiveSensorId);
          const sessionsToReturn = sensorSessions.length > 0 ? sensorSessions : result.sessions;

          const sessions = sessionsToReturn.map((s) => {
            const raw = (s.raw ?? {}) as Record<string, unknown>;
            const hijackAlerts = normalizeHijackAlerts(s.sessionId, s.hijackAlerts ?? raw.hijackAlerts);
            return {
              sessionId: s.sessionId,
              tokenHash: String(raw.tokenHash ?? `tok_${sha256Hex(s.sessionId).slice(0, 24)}`),
              actorId: s.actorId ?? null,
              creationTime: s.createdAt.getTime(),
              lastActivity: s.lastActivityAt.getTime(),
              requestCount: s.requestCount,
              boundJa4: s.boundJa4 ?? null,
              boundIp: s.boundIp ?? null,
              isSuspicious: !!s.isSuspicious,
              hijackAlerts,
            };
          });

          const now = Date.now();
          const suspiciousSessions = sessions.filter((s) => s.isSuspicious).length;
          const activeSessions = sessions.filter((s) => s.lastActivity > now - 30 * 60 * 1000).length;
          const hijackAlertsCount = sessions.reduce((acc, s) => acc + (s.hijackAlerts?.length ?? 0), 0);

          res.json({ 
            sessions,
            stats: {
              totalSessions: result.total,
              activeSessions,
              suspiciousSessions,
              expiredSessions: Math.max(0, result.total - activeSessions),
              hijackAlerts: hijackAlertsCount,
              evictions: 0,
              totalCreated: result.total,
              totalInvalidated: 0,
            },
            _fallback: true,
            _sensorId: effectiveSensorId
          });
          return;
        }
        if (context === 'listCampaigns') {
          const parsed = CampaignFilterSchema.safeParse(req.query);
          const result = await fleetIntelService.getCampaigns(tenantId, {
            status: parsed.success ? parsed.data.status : undefined,
            limit: parsed.success ? parsed.data.limit : 100,
            offset: parsed.success ? parsed.data.offset : 0,
          });
          const sensorCampaigns = result.campaigns.filter(c => c.sensorId === effectiveSensorId);
          const campaignsToReturn = sensorCampaigns.length > 0 ? sensorCampaigns : result.campaigns;

          res.json({ 
            campaigns: campaignsToReturn.map((c) => {
              const raw = (c.raw ?? {}) as Record<string, unknown>;
              const attackTypes = jsonStringArray(c.attackTypes);
              return {
                campaignId: c.campaignId,
                name: typeof raw.name === 'string' ? raw.name : formatCampaignName(c.campaignId, attackTypes),
                status: normalizeStatus(c.status),
                severity: normalizeSeverity(c.riskScore),
                confidence: normalizeConfidence(c.confidence),
                actorCount: c.actorCount ?? 0,
                firstSeen: c.firstSeenAt.getTime(),
                lastSeen: c.lastActivityAt.getTime(),
                summary: attackTypes.length ? `Attack types: ${attackTypes.join(', ')}` : null,
                correlationTypes: attackTypes,
              };
            }),
            _fallback: true,
            _sensorId: effectiveSensorId
          });
          return;
        }

        if (context === 'getCampaign') {
          const campaignId = (req.params as { campaignId?: string }).campaignId;
          if (!campaignId) {
            res.status(400).json({ error: 'Missing campaignId', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          const result = await fleetIntelService.getCampaigns(tenantId, { limit: 500, offset: 0 });
          const match =
            result.campaigns.find((c) => c.sensorId === effectiveSensorId && c.campaignId === campaignId) ??
            result.campaigns.find((c) => c.campaignId === campaignId);

          if (!match) {
            res.status(404).json({ error: 'Campaign not found', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          const raw = (match.raw ?? {}) as Record<string, unknown>;
          const attackTypes = jsonStringArray(match.attackTypes);
          res.json({
            campaign: {
              campaignId: match.campaignId,
              name: typeof raw.name === 'string' ? raw.name : formatCampaignName(match.campaignId, attackTypes),
              status: normalizeStatus(match.status),
              severity: normalizeSeverity(match.riskScore),
              confidence: normalizeConfidence(match.confidence),
              actorCount: match.actorCount ?? 0,
              firstSeen: match.firstSeenAt.getTime(),
              lastSeen: match.lastActivityAt.getTime(),
              summary: attackTypes.length ? `Attack types: ${attackTypes.join(', ')}` : null,
              correlationTypes: attackTypes,
            },
            signals: [],
            _fallback: true,
            _sensorId: effectiveSensorId,
          });
          return;
        }

        if (context === 'listCampaignActors') {
          const campaignId = (req.params as { campaignId?: string }).campaignId;
          res.json({ campaignId: campaignId ?? 'unknown', actors: [], _fallback: true, _sensorId: effectiveSensorId });
          return;
        }

        if (context === 'getCampaignGraph') {
          const campaignId = (req.params as { campaignId?: string }).campaignId;
          if (!campaignId) {
            res.status(400).json({ error: 'Missing campaignId', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          const campaigns = await fleetIntelService.getCampaigns(tenantId, { limit: 500, offset: 0 });
          const campaign =
            campaigns.campaigns.find((c) => c.sensorId === effectiveSensorId && c.campaignId === campaignId) ??
            campaigns.campaigns.find((c) => c.campaignId === campaignId);

          const raw = (campaign?.raw ?? {}) as Record<string, unknown>;
          const label =
            typeof raw.name === 'string'
              ? raw.name
              : campaign
                ? formatCampaignName(campaign.campaignId, jsonStringArray(campaign.attackTypes))
                : campaignId;

          // Build a small, stable graph from fleet intel snapshots.
          // Cytoscape element ids must be unique and stable; use hashed ids with readable labels.
          const cyId = (prefix: string, value: string): string =>
            `${prefix}_${sha256Hex(`${prefix}:${value}`).slice(0, 16)}`;

          const nodes: any[] = [
            { data: { id: 'campaign', label, type: 'campaign' } },
          ];
          const edges: any[] = [];

          const actors = await fleetIntelService.getActors(tenantId, { limit: 25, offset: 0 });
          const sensorActors = actors.actors.filter((a) => a.sensorId === effectiveSensorId);
          const actorsToUse = (sensorActors.length > 0 ? sensorActors : actors.actors).slice(0, 8);

          for (const a of actorsToUse) {
            const actorNodeId = cyId('actor', a.actorId);
            nodes.push({
              data: { id: actorNodeId, label: a.actorId, type: 'actor', riskScore: a.riskScore },
            });
            edges.push({
              data: { id: cyId('edge', `campaign->${a.actorId}`), source: 'campaign', target: actorNodeId, label: 'attributed' },
            });

            const ips = jsonStringArray(a.ips ?? (a.raw as any)?.ips).slice(0, 3);
            for (const ip of ips) {
              const ipNodeId = cyId('ip', ip);
              if (!nodes.some((n) => n.data?.id === ipNodeId)) {
                nodes.push({ data: { id: ipNodeId, label: ip, type: 'ip' } });
              }
              edges.push({
                data: { id: cyId('edge', `${a.actorId}->${ip}`), source: actorNodeId, target: ipNodeId, label: 'uses' },
              });
            }
          }

          res.json({
            data: { nodes, edges },
            _fallback: true,
            _sensorId: effectiveSensorId,
          });
          return;
        }

        if (context === 'getSession') {
          const sessionId = (req.params as { sessionId?: string }).sessionId;
          if (!sessionId) {
            res.status(400).json({ error: 'Missing sessionId', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          const result = await fleetIntelService.getSessions(tenantId, { limit: 500, offset: 0 });
          const match =
            result.sessions.find((s) => s.sensorId === effectiveSensorId && s.sessionId === sessionId) ??
            result.sessions.find((s) => s.sessionId === sessionId);

          if (!match) {
            res.status(404).json({ error: 'Session not found', _fallback: true, _sensorId: effectiveSensorId });
            return;
          }

          const raw = (match.raw ?? {}) as Record<string, unknown>;
          const hijackAlerts = normalizeHijackAlerts(match.sessionId, match.hijackAlerts ?? raw.hijackAlerts);
          res.json({
            session: {
              sessionId: match.sessionId,
              tokenHash: String(raw.tokenHash ?? `tok_${sha256Hex(match.sessionId).slice(0, 24)}`),
              actorId: match.actorId ?? null,
              creationTime: match.createdAt.getTime(),
              lastActivity: match.lastActivityAt.getTime(),
              requestCount: match.requestCount,
              boundJa4: match.boundJa4 ?? null,
              boundIp: match.boundIp ?? null,
              isSuspicious: !!match.isSuspicious,
              hijackAlerts,
            },
            _fallback: true,
            _sensorId: effectiveSensorId,
          });
          return;
        }
      } catch (fallbackError) {
        logger.error({ fallbackError }, 'Database fallback failed');
      }
    }

    if (error instanceof SensorError) {
      const problem = error.toProblemDetails();
      res.status(problem.status).type('application/problem+json').json(problem);
      return;
    }

    if (error instanceof SynapseProxyError) {
      const statusMap: Record<string, number> = {
        TUNNEL_NOT_FOUND: 503,
        FORBIDDEN: 403,
        TIMEOUT: 504,
        SEND_FAILED: 503,
        SENSOR_DISCONNECTED: 503,
        SENSOR_ERROR: 502,
        HTTP_ERROR: error.status || 502,
        SHUTDOWN: 503,
        INVALID_SENSOR_ID: 400,
        INVALID_ENDPOINT: 400,
        ENDPOINT_NOT_ALLOWED: 403,
        STALE_REQUEST: 504,
      };

      const status = statusMap[error.code] || 500;
      const payload = error.toJSON();
      sendProblem(res, status, payload.error, {
        code: payload.code,
        instance: req.originalUrl,
        details: {
          retryable: payload.retryable,
          suggestion: payload.suggestion,
          upstreamStatus: payload.status,
        },
      });
    } else {
      logger.error({ error, context }, 'Synapse proxy error');
      const isDevelopment = process.env.NODE_ENV === 'development';
      sendProblem(res, 500, 'Internal server error', {
        code: 'INTERNAL_ERROR',
        instance: req.originalUrl,
        details: isDevelopment
          ? { message: error instanceof Error ? error.message : String(error) }
          : { retryable: false },
      });
    }
  }

  function normalizeConfidence(value?: number | null): number {
    if (!value) return 0;
    return value > 1 ? Math.min(1, value / 100) : value;
  }

  function normalizeStatus(value?: string | null): 'ACTIVE' | 'DETECTED' | 'DORMANT' | 'RESOLVED' {
    switch ((value || '').toLowerCase()) {
      case 'active':
        return 'ACTIVE';
      case 'resolved':
        return 'RESOLVED';
      case 'dormant':
        return 'DORMANT';
      case 'detected':
      default:
        return 'DETECTED';
    }
  }

  function normalizeSeverity(score?: number | null): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const risk = score ?? 0;
    if (risk >= 85) return 'CRITICAL';
    if (risk >= 70) return 'HIGH';
    if (risk >= 50) return 'MEDIUM';
    return 'LOW';
  }

  function enforceAdminForKernel(section: string, req: Request, res: Response): boolean {
    if (section !== 'kernel') {
      return true;
    }

    let allowed = false;
    requireRole('admin')(req, res, () => {
      allowed = true;
    });
    return allowed;
  }

  function parseTimestamp(value?: string | null): number {
    if (!value) return Date.now();
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? Date.now() : parsed;
  }

  function formatCampaignName(id: string, attackTypes?: string[] | null): string {
    const primary = attackTypes?.[0];
    if (!primary) return `Campaign ${id}`;
    const title = primary
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
    return `${title} Campaign`;
  }

  // DB CampaignStatus (ACTIVE | MONITORING | RESOLVED | FALSE_POSITIVE) is
  // broader than the SOC UI's (ACTIVE | DETECTED | DORMANT | RESOLVED); map
  // MONITORING -> DETECTED and FALSE_POSITIVE -> DORMANT so existing UI types
  // don't need to change.
  function mapDbCampaignStatus(
    status: string
  ): 'ACTIVE' | 'DETECTED' | 'DORMANT' | 'RESOLVED' {
    switch (status) {
      case 'ACTIVE':
        return 'ACTIVE';
      case 'MONITORING':
        return 'DETECTED';
      case 'RESOLVED':
        return 'RESOLVED';
      case 'FALSE_POSITIVE':
        return 'DORMANT';
      default:
        return 'DETECTED';
    }
  }

  // Reverse of mapDbCampaignStatus for status filter at the DB level.
  function mapUiCampaignStatusToDb(
    status: string
  ): 'ACTIVE' | 'MONITORING' | 'RESOLVED' | 'FALSE_POSITIVE' | null {
    switch (status.toUpperCase()) {
      case 'ACTIVE':
        return 'ACTIVE';
      case 'DETECTED':
        return 'MONITORING';
      case 'RESOLVED':
        return 'RESOLVED';
      case 'DORMANT':
        return 'FALSE_POSITIVE';
      default:
        return null;
    }
  }

  function extractCampaignAttackTypes(
    metadata: unknown,
    correlationSignals: unknown
  ): string[] {
    const meta =
      metadata && typeof metadata === 'object' ? (metadata as Record<string, unknown>) : null;
    if (meta && Array.isArray(meta.attackTypes)) {
      return meta.attackTypes.filter((t): t is string => typeof t === 'string');
    }
    const sig =
      correlationSignals && typeof correlationSignals === 'object'
        ? (correlationSignals as Record<string, unknown>)
        : null;
    if (sig && typeof sig.currentStage === 'string') return [sig.currentStage];
    return [];
  }

  function campaignRowToSoc(row: {
    id: string;
    name: string;
    description: string | null;
    status: string;
    severity: string;
    confidence: number;
    firstSeenAt: Date;
    lastActivityAt: Date;
    correlationSignals: unknown;
    metadata: unknown;
    _count?: { threatLinks: number };
  }) {
    const attackTypes = extractCampaignAttackTypes(row.metadata, row.correlationSignals);
    return {
      campaignId: row.id,
      name: row.name || formatCampaignName(row.id, attackTypes),
      status: mapDbCampaignStatus(row.status),
      severity: row.severity as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
      confidence: row.confidence,
      actorCount: row._count?.threatLinks ?? 0,
      firstSeen: row.firstSeenAt.getTime(),
      lastSeen: row.lastActivityAt.getTime(),
      summary:
        row.description ??
        (attackTypes.length ? `Attack types: ${attackTypes.join(', ')}` : null),
      correlationTypes: attackTypes,
    };
  }

  // ==========================================================================
  // Status Endpoint
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/status
   * Get sensor's current status and health metrics
   */
  router.get(
    '/:sensorId/status',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const status = await synapseProxy.getSensorStatus(sensorId, tenantId);
        res.json(status);
      } catch (error) {
        await handleError(req, res, error, 'getSensorStatus');
      }
    }
  );

  // ==========================================================================
  // Configuration Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/config
   * Fetch sensor configuration (system config view or specific section)
   */
  router.get(
    '/:sensorId/config',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ConfigQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const section = parsed.data.section as SensorConfigSection | undefined;
        const config = section
          ? await synapseProxy.getSensorConfigSection(sensorId, tenantId, section)
          : await synapseProxy.getSensorConfig(sensorId, tenantId);
        res.json(config);
      } catch (error) {
        await handleError(req, res, error, 'getSensorConfig');
      }
    }
  );

  /**
   * PUT /synapse/:sensorId/config
   * Update a specific sensor configuration section
   */
  router.put(
    '/:sensorId/config',
    requireScope('fleet:write'),
    requireRole('operator'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ConfigUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid request body',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const { section, config } = parsed.data;
        if (!enforceAdminForKernel(section, req, res)) {
          return;
        }
        const result = await synapseProxy.updateSensorConfig(
          sensorId,
          tenantId,
          section as SensorConfigSection,
          config
        );
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'updateSensorConfig');
      }
    }
  );

  /**
   * PUT /synapse/config
   * Push a configuration update across all connected sensors for a tenant
   */
  router.put(
    '/config',
    requireScope('fleet:write'),
    requireRole('operator'),
    async (req: Request, res: Response): Promise<void> => {
      const tenantId = req.auth!.tenantId;

      const parsed = GlobalConfigUpdateSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid request body',
          details: parsed.error.issues,
        });
        return;
      }

      const { section, config, sensorIds } = parsed.data;
      if (!enforceAdminForKernel(section, req, res)) {
        return;
      }
      const targets = sensorIds?.length
        ? sensorIds
        : synapseProxy.listActiveSensors(tenantId);

      if (targets.length === 0) {
        res.status(404).json({
          error: 'No connected sensors found for tenant',
          code: 'NO_CONNECTED_SENSORS',
        });
        return;
      }

      const results = await Promise.all(targets.map(async (targetSensorId) => {
        try {
          await synapseProxy.updateSensorConfig(
            targetSensorId,
            tenantId,
            section as SensorConfigSection,
            config
          );
          return { sensorId: targetSensorId, success: true };
        } catch (error) {
          if (error instanceof SynapseProxyError) {
            return {
              sensorId: targetSensorId,
              success: false,
              error: error.message,
              code: error.code,
            };
          }
          return {
            sensorId: targetSensorId,
            success: false,
            error: 'Config update failed',
            code: 'INTERNAL_ERROR',
          };
        }
      }));

      const successCount = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success);

      res.json({
        success: failed.length === 0,
        summary: {
          total: results.length,
          updated: successCount,
          failed: failed.length,
        },
        results,
      });
    }
  );

  // ==========================================================================
  // Entities Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/entities
   * List tracked entities
   */
  router.get(
    '/:sensorId/entities',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = EntityFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listEntities(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listEntities');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/entities/:entityId
   * Get a specific entity
   */
  router.get(
    '/:sensorId/entities/:entityId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, entityId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const entity = await synapseProxy.getEntity(sensorId, tenantId, entityId);
        res.json(entity);
      } catch (error) {
        await handleError(req, res, error, 'getEntity');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/entities/:entityId
   * Release an entity (clear tracking data)
   */
  router.delete(
    '/:sensorId/entities/:entityId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, entityId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.releaseEntity(sensorId, tenantId, entityId);
        logger.info({ sensorId, entityId, tenantId }, 'Entity released');
        res.status(204).send();
      } catch (error) {
        await handleError(req, res, error, 'releaseEntity');
      }
    }
  );

  // ==========================================================================
  // Blocks Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/blocks
   * List active blocks
   */
  router.get(
    '/:sensorId/blocks',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = BlockFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listBlocks(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listBlocks');
      }
    }
  );

  /**
   * POST /synapse/:sensorId/blocks
   * Add a new block
   */
  router.post(
    '/:sensorId/blocks',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = AddBlockSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid block data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const block = await synapseProxy.addBlock(
          sensorId,
          tenantId,
          parsed.data as Omit<Block, 'id' | 'createdAt'>
        );
        logger.info({ sensorId, blockId: block.id, tenantId }, 'Block added');
        res.status(201).json(block);
      } catch (error) {
        await handleError(req, res, error, 'addBlock');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/blocks/:blockId
   * Remove a block
   */
  router.delete(
    '/:sensorId/blocks/:blockId',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, blockId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.removeBlock(sensorId, tenantId, blockId);
        logger.info({ sensorId, blockId, tenantId }, 'Block removed');
        res.status(204).send();
      } catch (error) {
        await handleError(req, res, error, 'removeBlock');
      }
    }
  );

  // ==========================================================================
  // Rules Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/rules
   * List active rules
   */
  router.get(
    '/:sensorId/rules',
    requireScope('fleet:read'),
    requireRole('viewer'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = RuleFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listRules(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listRules');
      }
    }
  );

  /**
   * POST /synapse/:sensorId/rules
   * Add a new rule
   */
  router.post(
    '/:sensorId/rules',
    requireScope('fleet:write'),
    requireRole('admin'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = AddRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid rule data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const { ttl, ...ruleData } = parsed.data;
        const rule = await synapseProxy.addRule(
          sensorId,
          tenantId,
          ruleData as Omit<Rule, 'id' | 'hitCount' | 'createdAt' | 'updatedAt'>,
          ttl
        );
        logger.info({ sensorId, ruleId: rule.id, tenantId }, 'Rule added');
        res.status(201).json(rule);
      } catch (error) {
        await handleError(req, res, error, 'addRule');
      }
    }
  );

  /**
   * PUT /synapse/:sensorId/rules/:ruleId
   * Update an existing rule
   */
  router.put(
    '/:sensorId/rules/:ruleId',
    requireScope('fleet:write'),
    requireRole('admin'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, ruleId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = UpdateRuleSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid rule update data',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const rule = await synapseProxy.updateRule(sensorId, tenantId, ruleId, parsed.data);
        logger.info({ sensorId, ruleId, tenantId }, 'Rule updated');
        res.json(rule);
      } catch (error) {
        await handleError(req, res, error, 'updateRule');
      }
    }
  );

  /**
   * DELETE /synapse/:sensorId/rules/:ruleId
   * Delete a rule
   */
  router.delete(
    '/:sensorId/rules/:ruleId',
    requireScope('fleet:write'),
    requireRole('admin'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, ruleId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        await synapseProxy.deleteRule(sensorId, tenantId, ruleId);
        logger.info({ sensorId, ruleId, tenantId }, 'Rule deleted');
        res.status(204).send();
      } catch (error) {
        await handleError(req, res, error, 'deleteRule');
      }
    }
  );

  // ==========================================================================
  // Actors Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/actors
   * List tracked actors
   */
  router.get(
    '/:sensorId/actors',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ActorFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listActors(sensorId, tenantId, {
          ip: parsed.data.ip,
          fingerprint: parsed.data.fingerprint,
          minRisk: parsed.data.minRisk ?? parsed.data.min_risk ?? parsed.data.minScore,
          minScore: parsed.data.minScore,
          type: parsed.data.type,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listActors', sensorId);
      }
    }
  );

  /**
   * GET /synapse/:sensorId/actors/:actorId
   * Get a specific actor
   */
  router.get(
    '/:sensorId/actors/:actorId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, actorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const actor = await synapseProxy.getActor(sensorId, tenantId, actorId);
        res.json(actor);
      } catch (error) {
        await handleError(req, res, error, 'getActor', sensorId);
      }
    }
  );

  /**
   * GET /synapse/:sensorId/actors/:actorId/timeline
   * Get actor timeline events
   */
  router.get(
    '/:sensorId/actors/:actorId/timeline',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, actorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = TimelineQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const timeline = await synapseProxy.getActorTimeline(
          sensorId,
          tenantId,
          actorId,
          parsed.data
        );
        res.json(timeline);
      } catch (error) {
        await handleError(req, res, error, 'getActorTimeline', sensorId);
      }
    }
  );

  // ==========================================================================
  // Sessions Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/sessions
   * List tracked sessions
   */
  router.get(
    '/:sensorId/sessions',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = SessionFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const actorId = parsed.data.actorId ?? parsed.data.actor_id;
        const result = await synapseProxy.listSessions(sensorId, tenantId, {
          actorId,
          suspicious: parsed.data.suspicious,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listSessions', sensorId);
      }
    }
  );

  // ==========================================================================
  // Fleet Campaign Endpoints (rollup-backed, ADR-0002)
  // ==========================================================================
  //
  // Read from the tenant-scoped `Campaign` table, which the correlator service
  // (services/correlator/index.ts) maintains with live cross-tenant correlation
  // data (isCrossTenant, tenantsAffected, confidence, severity, lastActivityAt).
  // The per-sensor `/synapse/:sensorId/campaigns*` routes below are retained as
  // the sensor-detail drill-down surface.

  /**
   * GET /synapse/campaigns
   * List campaigns across the tenant fleet.
   */
  router.get(
    '/campaigns',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      if (!prisma) {
        res.status(503).json({ error: 'Campaign rollup unavailable' });
        return;
      }
      const tenantId = req.auth!.tenantId;
      const parsed = CampaignFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({ error: 'Invalid query parameters', details: parsed.error.issues });
        return;
      }

      const dbStatus = parsed.data.status
        ? mapUiCampaignStatusToDb(parsed.data.status)
        : null;

      try {
        const rows = await prisma.campaign.findMany({
          where: {
            tenantId,
            ...(dbStatus ? { status: dbStatus } : {}),
          },
          orderBy: { lastActivityAt: 'desc' },
          take: parsed.data.limit,
          skip: parsed.data.offset,
          include: { _count: { select: { threatLinks: true } } },
        });
        res.json({ campaigns: rows.map(campaignRowToSoc) });
      } catch (error) {
        logger.error({ error, tenantId }, 'Fleet campaigns list failed');
        sendProblem(
          res,
          500,
          error instanceof Error ? error.message : 'Unknown error',
          { title: 'Failed to list fleet campaigns' }
        );
      }
    }
  );

  /**
   * GET /synapse/campaigns/:campaignId
   */
  router.get(
    '/campaigns/:campaignId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      if (!prisma) {
        res.status(503).json({ error: 'Campaign rollup unavailable' });
        return;
      }
      const tenantId = req.auth!.tenantId;
      const { campaignId } = req.params;

      try {
        const row = await prisma.campaign.findFirst({
          where: { id: campaignId, tenantId },
          include: { _count: { select: { threatLinks: true } } },
        });
        if (!row) {
          res.status(404).json({ error: 'Campaign not found' });
          return;
        }

        const sig =
          row.correlationSignals && typeof row.correlationSignals === 'object'
            ? (row.correlationSignals as Record<string, unknown>)
            : null;
        const signals = sig
          ? Object.entries(sig)
              .filter(([, v]) => typeof v === 'number' || typeof v === 'string')
              .map(([k, v]) => ({
                type: k,
                confidence:
                  typeof v === 'number' ? normalizeConfidence(v) : 0,
                reason: typeof v === 'string' ? v : null,
              }))
          : [];

        res.json({ campaign: campaignRowToSoc(row), signals });
      } catch (error) {
        logger.error({ error, tenantId, campaignId }, 'Fleet campaign detail failed');
        sendProblem(
          res,
          500,
          error instanceof Error ? error.message : 'Unknown error',
          { title: 'Failed to load campaign detail' }
        );
      }
    }
  );

  /**
   * GET /synapse/campaigns/:campaignId/actors
   * Actors on a campaign = threats linked to the campaign via CampaignThreat.
   */
  router.get(
    '/campaigns/:campaignId/actors',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      if (!prisma) {
        res.status(503).json({ error: 'Campaign rollup unavailable' });
        return;
      }
      const tenantId = req.auth!.tenantId;
      const { campaignId } = req.params;

      try {
        const campaign = await prisma.campaign.findFirst({
          where: { id: campaignId, tenantId },
          include: {
            threatLinks: { include: { threat: true } },
          },
        });
        if (!campaign) {
          res.status(404).json({ error: 'Campaign not found' });
          return;
        }

        const actors = campaign.threatLinks.map((link) => ({
          actorId: link.threat.indicator,
          riskScore: link.threat.riskScore,
          lastSeen: link.threat.lastSeenAt.getTime(),
          ips: link.threat.threatType === 'IP' ? [link.threat.indicator] : [],
        }));

        res.json({ campaignId, actors });
      } catch (error) {
        logger.error({ error, tenantId, campaignId }, 'Fleet campaign actors failed');
        sendProblem(
          res,
          500,
          error instanceof Error ? error.message : 'Unknown error',
          { title: 'Failed to load campaign actors' }
        );
      }
    }
  );

  /**
   * GET /synapse/campaigns/:campaignId/graph
   * Build a simple 2-hop graph from the campaign and its linked threats.
   */
  router.get(
    '/campaigns/:campaignId/graph',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      if (!prisma) {
        res.status(503).json({ error: 'Campaign rollup unavailable' });
        return;
      }
      const tenantId = req.auth!.tenantId;
      const { campaignId } = req.params;

      try {
        const campaign = await prisma.campaign.findFirst({
          where: { id: campaignId, tenantId },
          include: { threatLinks: { include: { threat: true } } },
        });
        if (!campaign) {
          res.status(404).json({ error: 'Campaign not found' });
          return;
        }

        const nodes: Array<Record<string, unknown>> = [
          {
            id: campaign.id,
            label: campaign.name,
            type: 'campaign',
            details: {
              severity: campaign.severity,
              confidence: campaign.confidence,
              tenantsAffected: campaign.tenantsAffected,
            },
          },
          ...campaign.threatLinks.map((link) => ({
            id: link.threat.id,
            label: link.threat.indicator,
            type: link.threat.threatType === 'IP' ? 'ip' : 'actor',
            details: {
              riskScore: link.threat.riskScore,
              hitCount: link.threat.hitCount,
              threatType: link.threat.threatType,
            },
          })),
        ];

        const edges = campaign.threatLinks.map((link) => ({
          source: campaign.id,
          target: link.threat.id,
          type: link.role ?? 'attributed',
        }));

        res.json({ data: { nodes, edges } });
      } catch (error) {
        logger.error({ error, tenantId, campaignId }, 'Fleet campaign graph failed');
        sendProblem(
          res,
          500,
          error instanceof Error ? error.message : 'Unknown error',
          { title: 'Failed to build campaign graph' }
        );
      }
    }
  );

  // ==========================================================================
  // Campaigns Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/campaigns
   * List campaigns
   */
  router.get(
    '/:sensorId/campaigns',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = CampaignFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listCampaigns(sensorId, tenantId, {
          status: parsed.data.status,
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });

        const campaigns = (result.data || []).map((campaign) => ({
          campaignId: campaign.id,
          name: formatCampaignName(campaign.id, campaign.attackTypes),
          status: normalizeStatus(campaign.status),
          severity: normalizeSeverity(campaign.riskScore),
          confidence: normalizeConfidence(campaign.confidence),
          actorCount: campaign.actorCount ?? 0,
          firstSeen: parseTimestamp(campaign.firstSeen),
          lastSeen: parseTimestamp(campaign.lastActivity),
          summary: campaign.attackTypes?.length
            ? `Attack types: ${campaign.attackTypes.join(', ')}`
            : null,
          correlationTypes: campaign.attackTypes ?? [],
        }));

        const filtered = parsed.data.status
          ? campaigns.filter((c) => c.status === normalizeStatus(parsed.data.status))
          : campaigns;

        const offset = parsed.data.offset ?? 0;
        const limit = parsed.data.limit ?? filtered.length;

        res.json({ campaigns: filtered.slice(offset, offset + limit) });
      } catch (error) {
        await handleError(req, res, error, 'listCampaigns', sensorId);
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId
   * Get campaign detail
   */
  router.get(
    '/:sensorId/campaigns/:campaignId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getCampaign(sensorId, tenantId, campaignId);
        const campaign = result.data;

        res.json({
          campaign: {
            campaignId: campaign.id,
            name: formatCampaignName(campaign.id, campaign.attackTypes),
            status: normalizeStatus(campaign.status),
            severity: normalizeSeverity(campaign.riskScore),
            confidence: normalizeConfidence(campaign.confidence),
            actorCount: campaign.actorCount ?? 0,
            firstSeen: parseTimestamp(campaign.firstSeen),
            lastSeen: parseTimestamp(campaign.lastActivity),
            summary: campaign.attackTypes?.length
              ? `Attack types: ${campaign.attackTypes.join(', ')}`
              : null,
            correlationTypes: campaign.attackTypes ?? [],
          },
          signals: campaign.correlationReasons?.map((reason) => ({
            type: reason.type,
            confidence: normalizeConfidence(reason.confidence),
            reason: reason.description ?? null,
          })) ?? [],
        });
      } catch (error) {
        await handleError(req, res, error, 'getCampaign', sensorId);
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId/actors
   * Get campaign actors
   */
  router.get(
    '/:sensorId/campaigns/:campaignId/actors',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.listCampaignActors(sensorId, tenantId, campaignId);
        const actors = (result.actors || []).map((actor) => ({
          actorId: actor.ip,
          riskScore: actor.risk ?? 0,
          lastSeen: parseTimestamp(actor.lastActivity ?? null),
          ips: [actor.ip],
        }));
        res.json({ campaignId, actors });
      } catch (error) {
        await handleError(req, res, error, 'listCampaignActors');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/campaigns/:campaignId/graph
   * Get campaign correlation graph
   */
  router.get(
    '/:sensorId/campaigns/:campaignId/graph',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, campaignId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getCampaignGraph(sensorId, tenantId, campaignId);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'getCampaignGraph');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/sessions/:sessionId
   * Get session detail
   */
  router.get(
    '/:sensorId/sessions/:sessionId',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, sessionId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const session = await synapseProxy.getSession(sensorId, tenantId, sessionId);
        res.json(session);
      } catch (error) {
        await handleError(req, res, error, 'getSession');
      }
    }
  );

  // ==========================================================================
  // Payload & Profiles Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/payload/stats
   * Get payload profiling summary
   */
  router.get(
    '/:sensorId/payload/stats',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getPayloadStats(sensorId, tenantId);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'getPayloadStats');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/endpoints
   * Get payload endpoint summaries
   */
  router.get(
    '/:sensorId/payload/endpoints',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = PayloadLimitSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listPayloadEndpoints(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listPayloadEndpoints');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/anomalies
   * Get recent payload anomalies
   */
  router.get(
    '/:sensorId/payload/anomalies',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = PayloadLimitSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.listPayloadAnomalies(sensorId, tenantId, parsed.data);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listPayloadAnomalies');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/bandwidth
   * Get payload bandwidth statistics
   */
  router.get(
    '/:sensorId/payload/bandwidth',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.getPayloadBandwidth(sensorId, tenantId);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'getPayloadBandwidth');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/profiles
   * List endpoint profiles
   */
  router.get(
    '/:sensorId/profiles',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const result = await synapseProxy.listProfiles(sensorId, tenantId);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'listProfiles');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/profiles/:template
   * Get profile detail by template (template may include slashes)
   */
  router.get(
    '/:sensorId/profiles/:template(*)',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, template } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ProfileTemplateSchema.safeParse({ template });
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid profile template',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.getProfile(sensorId, tenantId, parsed.data.template);
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'getProfile');
      }
    }
  );

  // ==========================================================================
  // Payload & Profiles Endpoints
  // ==========================================================================

  /**
   * GET /synapse/:sensorId/payload/stats
   * Get payload stats
   */
  router.get(
    '/:sensorId/payload/stats',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const payload = await synapseProxy.getPayloadStats(sensorId, tenantId);
        res.json(payload);
      } catch (error) {
        handleError(req, res, error, 'getPayloadStats');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/endpoints
   * Get payload endpoints
   */
  router.get(
    '/:sensorId/payload/endpoints',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const payload = await synapseProxy.getPayloadEndpoints(sensorId, tenantId);
        res.json(payload);
      } catch (error) {
        handleError(req, res, error, 'getPayloadEndpoints');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/anomalies
   * Get payload anomalies
   */
  router.get(
    '/:sensorId/payload/anomalies',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const payload = await synapseProxy.getPayloadAnomalies(sensorId, tenantId);
        res.json(payload);
      } catch (error) {
        handleError(req, res, error, 'getPayloadAnomalies');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/payload/bandwidth
   * Get payload bandwidth
   */
  router.get(
    '/:sensorId/payload/bandwidth',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const payload = await synapseProxy.getPayloadBandwidth(sensorId, tenantId);
        res.json(payload);
      } catch (error) {
        handleError(req, res, error, 'getPayloadBandwidth');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/profiles
   * List payload profiles
   */
  router.get(
    '/:sensorId/profiles',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = ProfileFilterSchema.safeParse(req.query);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid query parameters',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const profiles = await synapseProxy.listProfiles(sensorId, tenantId, {
          limit: parsed.data.limit,
          offset: parsed.data.offset,
        });
        res.json(profiles);
      } catch (error) {
        handleError(req, res, error, 'listProfiles');
      }
    }
  );

  /**
   * GET /synapse/:sensorId/profiles/:template
   * Get profile detail
   */
  router.get(
    '/:sensorId/profiles/:template',
    requireScope('fleet:read'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId, template } = req.params;
      const tenantId = req.auth!.tenantId;

      try {
        const profile = await synapseProxy.getProfile(sensorId, tenantId, template);
        res.json(profile);
      } catch (error) {
        handleError(req, res, error, 'getProfile');
      }
    }
  );

  // ==========================================================================
  // Evaluation Endpoint
  // ==========================================================================

  /**
   * POST /synapse/:sensorId/evaluate
   * Evaluate a request against the sensor's rules
   */
  router.post(
    '/:sensorId/evaluate',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      const parsed = EvalRequestSchema.safeParse(req.body);
      if (!parsed.success) {
        res.status(400).json({
          error: 'Invalid evaluation request',
          details: parsed.error.issues,
        });
        return;
      }

      try {
        const result = await synapseProxy.evaluateRequest(
          sensorId,
          tenantId,
          parsed.data as EvalRequest
        );
        res.json(result);
      } catch (error) {
        await handleError(req, res, error, 'evaluateRequest');
      }
    }
  );

  // ==========================================================================
  // Cache Management Endpoint
  // ==========================================================================

  /**
   * POST /synapse/:sensorId/cache/clear
   * Clear cached data for a sensor
   */
  router.post(
    '/:sensorId/cache/clear',
    requireScope('fleet:write'),
    async (req: Request, res: Response): Promise<void> => {
      const { sensorId } = req.params;
      const tenantId = req.auth!.tenantId;

      // Verify the sensor tunnel exists and belongs to tenant
      try {
        await synapseProxy.getSensorStatus(sensorId, tenantId);
        synapseProxy.clearSensorCache(sensorId);
        logger.info({ sensorId, tenantId }, 'Sensor cache cleared');
        res.json({ message: 'Cache cleared' });
      } catch (error) {
        await handleError(req, res, error, 'clearCache');
      }
    }
  );

  // ==========================================================================
  // Proxy Stats Endpoint
  // ==========================================================================

  /**
   * GET /synapse/stats
   * Get synapse proxy statistics (admin only)
   */
  router.get(
    '/stats',
    requireScope('admin'),
    (_req: Request, res: Response): void => {
      const stats = synapseProxy.getStats();
      res.json(stats);
    }
  );

  return router;
}
