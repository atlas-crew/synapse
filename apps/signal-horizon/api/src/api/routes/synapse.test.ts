/**
 * Synapse Routes Test Suite
 *
 * Focused RBAC tests for /synapse/:sensorId/rules and config endpoints.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import request from '../../__tests__/test-request.js';
import { createSynapseRoutes } from './synapse.js';
import type { Logger } from 'pino';
import type { SynapseProxyService, Rule } from '../../services/synapse-proxy.js';

const mockLogger: Logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
  child: vi.fn().mockReturnThis(),
} as unknown as Logger;

const baseRulePayload = {
  name: 'Block Admin',
  type: 'BLOCK' as const,
  enabled: true,
  priority: 100,
  conditions: [
    {
      field: 'path',
      operator: 'eq' as const,
      value: '/admin',
    },
  ],
  actions: [
    {
      type: 'block' as const,
    },
  ],
};

const baseRuleResponse: Rule = {
  id: 'rule-1',
  hitCount: 0,
  createdAt: '2026-02-04T01:00:00.000Z',
  updatedAt: '2026-02-04T01:00:00.000Z',
  ...baseRulePayload,
};

const baseConfigPayload = {
  section: 'dlp' as const,
  config: {
    enabled: true,
  },
};

const kernelConfigPayload = {
  section: 'kernel' as const,
  config: {
    'net.ipv4.tcp_max_syn_backlog': 2048,
  },
};

const injectAuth = (scopes: string[]) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    req.auth = {
      tenantId: 'tenant-1',
      apiKeyId: 'key-1',
      scopes,
      isFleetAdmin: scopes.includes('fleet:admin'),
      userId: 'user-1',
      userName: 'Test User',
    } as typeof req.auth;
    next();
  };
};

describe('Synapse RBAC', () => {
  let app: Express;
  let synapseProxy: Pick<
    SynapseProxyService,
    'listRules' | 'addRule' | 'updateRule' | 'deleteRule' | 'updateSensorConfig'
  >;

  const buildApp = (scopes?: string[], routeOptions?: Parameters<typeof createSynapseRoutes>[2]) => {
    const expressApp = express();
    expressApp.use(express.json());
    if (scopes) {
      expressApp.use(injectAuth(scopes));
    }
    expressApp.use('/synapse', createSynapseRoutes(synapseProxy as SynapseProxyService, mockLogger, routeOptions));
    return expressApp;
  };

  beforeEach(() => {
    synapseProxy = {
      listRules: vi.fn().mockResolvedValue({ rules: [baseRuleResponse], total: 1 }),
      addRule: vi.fn().mockResolvedValue(baseRuleResponse),
      updateRule: vi.fn().mockResolvedValue({
        ...baseRuleResponse,
        name: 'Updated Rule',
      }),
      deleteRule: vi.fn().mockResolvedValue(undefined),
      updateSensorConfig: vi.fn().mockResolvedValue({ success: true }),
    };
    app = buildApp(['fleet:read']);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('rejects unauthenticated GET /synapse/:sensorId/rules', async () => {
    const unauthApp = buildApp();

    const res = await request(unauthApp)
      .get('/synapse/sensor-1/rules')
      .expect(401);

    expect(res.body).toMatchObject({
      code: 'AUTH_REQUIRED',
    });
  });

  it('rejects GET /synapse/:sensorId/rules without fleet:read scope', async () => {
    const limitedApp = buildApp(['fleet:write']);

    const res = await request(limitedApp)
      .get('/synapse/sensor-1/rules')
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('allows GET /synapse/:sensorId/rules for viewer role', async () => {
    const res = await request(app)
      .get('/synapse/sensor-1/rules')
      .expect(200);

    expect(res.body).toMatchObject({
      rules: [expect.objectContaining({ id: 'rule-1' })],
      total: 1,
    });
    expect(synapseProxy.listRules).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      expect.any(Object)
    );
  });

  it('returns seeded DLP data when payload snapshot is present', async () => {
    const fakePrisma: { sensorPayloadSnapshot: { findFirst: ReturnType<typeof vi.fn> } } = {
      sensorPayloadSnapshot: {
        findFirst: vi.fn().mockResolvedValue({
          stats: {
            dlp: {
              totalScans: 12345,
              totalMatches: 12,
              patternCount: 25,
              violations: [
                {
                  timestamp: 1700000000000,
                  pattern_name: 'Visa Card',
                  data_type: 'credit_card',
                  severity: 'critical',
                  masked_value: '****-****-****-4242',
                  client_ip: '185.228.13.10',
                  path: '/api/v1/payments/checkout',
                },
              ],
            },
          },
        }),
      },
    };

    const seededApp = buildApp(['fleet:read'], { prisma: fakePrisma });

    const statsRes = await request(seededApp)
      .get('/synapse/sensor-1/proxy/_sensor/dlp/stats')
      .expect(200);

    expect(statsRes.body).toMatchObject({
      totalScans: 12345,
      totalMatches: 12,
      patternCount: 25,
    });

    const violationsRes = await request(seededApp)
      .get('/synapse/sensor-1/proxy/_sensor/dlp/violations')
      .expect(200);

    expect(violationsRes.body).toMatchObject({
      violations: [
        expect.objectContaining({
          pattern_name: 'Visa Card',
          data_type: 'credit_card',
          severity: 'critical',
          masked_value: '****-****-****-4242',
          client_ip: '185.228.13.10',
          path: '/api/v1/payments/checkout',
        }),
      ],
    });

    expect(fakePrisma.sensorPayloadSnapshot.findFirst).toHaveBeenCalled();
  });

  it('returns aggregated fleet DLP data with a partial-results envelope', async () => {
    const fakePrisma = {
      sensor: {
        findMany: vi.fn().mockResolvedValue([
          { id: 'sensor-1', name: 'edge-east' },
          { id: 'sensor-2', name: 'edge-west' },
          { id: 'sensor-3', name: 'edge-missing' },
        ]),
      },
      sensorPayloadSnapshot: {
        findMany: vi.fn().mockResolvedValue([
          {
            sensorId: 'sensor-1',
            capturedAt: new Date('2026-04-18T12:00:00Z'),
            stats: {
              dlp: {
                totalScans: 100,
                totalMatches: 2,
                patternCount: 25,
                violations: [
                  {
                    timestamp: 1700000000000,
                    pattern_name: 'Visa Card',
                    data_type: 'credit_card',
                    severity: 'critical',
                    masked_value: '****-****-****-4242',
                    path: '/checkout',
                  },
                ],
              },
            },
          },
          {
            sensorId: 'sensor-2',
            capturedAt: new Date('2026-04-18T12:05:00Z'),
            stats: {
              dlp: {
                totalScans: 40,
                totalMatches: 1,
                patternCount: 25,
                violations: [
                  {
                    timestamp: 1700000005000,
                    pattern_name: 'Access Token',
                    data_type: 'api_key',
                    severity: 'high',
                    masked_value: 'tok_********',
                    path: '/oauth/token',
                  },
                ],
              },
            },
          },
        ]),
      },
    };

    const seededApp = buildApp(['fleet:read'], { prisma: fakePrisma as any });

    const statsRes = await request(seededApp).get('/synapse/dlp/stats').expect(200);
    expect(statsRes.body.aggregate).toMatchObject({
      totalScans: 140,
      totalMatches: 3,
      patternCount: 25,
    });
    expect(statsRes.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 1 });
    expect(statsRes.body.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: 'sensor-3',
          status: 'error',
          error: 'No payload snapshot available',
        }),
      ])
    );

    const violationsRes = await request(seededApp)
      .get('/synapse/dlp/violations?limit=5')
      .expect(200);
    expect(violationsRes.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 1 });
    expect(violationsRes.body.aggregate).toEqual([
      expect.objectContaining({
        sensorId: 'sensor-2',
        sensorName: 'edge-west',
        pattern_name: 'Access Token',
      }),
      expect.objectContaining({
        sensorId: 'sensor-1',
        sensorName: 'edge-east',
        pattern_name: 'Visa Card',
      }),
    ]);
  });

  it('returns a top-level fleet error when no DLP snapshots are usable', async () => {
    const fakePrisma = {
      sensor: {
        findMany: vi.fn().mockResolvedValue([
          { id: 'sensor-1', name: 'edge-east' },
          { id: 'sensor-2', name: 'edge-west' },
        ]),
      },
      sensorPayloadSnapshot: {
        findMany: vi.fn().mockResolvedValue([]),
      },
    };

    const seededApp = buildApp(['fleet:read'], { prisma: fakePrisma as any });

    const res = await request(seededApp).get('/synapse/dlp/stats').expect(200);

    expect(res.body.summary).toEqual({ succeeded: 0, stale: 0, failed: 2 });
    expect(res.body.error).toMatchObject({
      code: 'FLEET_DLP_STATS_UNAVAILABLE',
      message: 'No sensors reported a usable DLP snapshot',
    });
  });

  it('returns aggregated payload snapshot routes with merged data and partial failures', async () => {
    const fakePrisma = {
      sensor: {
        findMany: vi.fn().mockResolvedValue([
          { id: 'sensor-1', name: 'edge-east' },
          { id: 'sensor-2', name: 'edge-west' },
          { id: 'sensor-3', name: 'edge-missing' },
        ]),
      },
      sensorPayloadSnapshot: {
        findMany: vi.fn().mockResolvedValue([
          {
            sensorId: 'sensor-1',
            capturedAt: new Date('2026-04-18T12:00:00Z'),
            stats: {
              total_endpoints: 4,
              total_entities: 3,
              total_requests: 10,
              total_request_bytes: 100,
              total_response_bytes: 200,
              avg_request_size: 10,
              avg_response_size: 20,
              active_anomalies: 1,
            },
            endpoints: [
              {
                template: '/login',
                request_count: 7,
                avg_request_size: 10,
                avg_response_size: 20,
              },
              {
                template: '/checkout',
                request_count: 3,
                avg_request_size: 15,
                avg_response_size: 35,
              },
            ],
            anomalies: [
              {
                anomaly_type: 'schema',
                severity: 'high',
                template: '/checkout',
                entity_id: 'ent-1',
                detected_at_ms: 1700000001000,
                description: 'Mismatch',
              },
            ],
            bandwidth: {
              totalBytes: 300,
              totalBytesIn: 100,
              totalBytesOut: 200,
              avgBytesPerRequest: 30,
              maxRequestSize: 25,
              maxResponseSize: 45,
              requestCount: 10,
              timeline: [{ timestamp: 1700000000000, bytesIn: 100, bytesOut: 200, requestCount: 10 }],
            },
          },
          {
            sensorId: 'sensor-2',
            capturedAt: new Date('2026-04-18T12:05:00Z'),
            stats: {
              total_endpoints: 6,
              total_entities: 5,
              total_requests: 20,
              total_request_bytes: 300,
              total_response_bytes: 500,
              avg_request_size: 15,
              avg_response_size: 25,
              active_anomalies: 2,
            },
            endpoints: [
              {
                template: '/login',
                request_count: 5,
                avg_request_size: 20,
                avg_response_size: 30,
              },
              {
                template: '/orders',
                request_count: 4,
                avg_request_size: 22,
                avg_response_size: 40,
              },
            ],
            anomalies: [
              {
                anomaly_type: 'payload',
                severity: 'medium',
                template: '/orders',
                entity_id: 'ent-2',
                detected_at_ms: 1700000003000,
                description: 'Spike',
              },
            ],
            bandwidth: {
              totalBytes: 800,
              totalBytesIn: 300,
              totalBytesOut: 500,
              avgBytesPerRequest: 40,
              maxRequestSize: 60,
              maxResponseSize: 90,
              requestCount: 20,
              timeline: [
                { timestamp: 1700000000000, bytesIn: 50, bytesOut: 75, requestCount: 5 },
                { timestamp: 1700000060000, bytesIn: 250, bytesOut: 425, requestCount: 15 },
              ],
            },
          },
        ]),
      },
    };

    const seededApp = buildApp(['fleet:read'], { prisma: fakePrisma as any });

    const statsRes = await request(seededApp).get('/synapse/payload/stats').expect(200);
    expect(statsRes.body.aggregate).toMatchObject({
      total_endpoints: 10,
      total_entities: 8,
      total_requests: 30,
      total_request_bytes: 400,
      total_response_bytes: 700,
      active_anomalies: 3,
    });
    expect(statsRes.body.summary).toEqual({ succeeded: 2, stale: 0, failed: 1 });

    const endpointsRes = await request(seededApp)
      .get('/synapse/payload/endpoints?limit=3')
      .expect(200);
    expect(endpointsRes.body.aggregate).toEqual([
      expect.objectContaining({ template: '/login', request_count: 12 }),
      expect.objectContaining({ template: '/orders', request_count: 4 }),
      expect.objectContaining({ template: '/checkout', request_count: 3 }),
    ]);

    const anomaliesRes = await request(seededApp)
      .get('/synapse/payload/anomalies?limit=2')
      .expect(200);
    expect(anomaliesRes.body.aggregate).toEqual([
      expect.objectContaining({ template: '/orders', detected_at_ms: 1700000003000 }),
      expect.objectContaining({ template: '/checkout', detected_at_ms: 1700000001000 }),
    ]);

    const bandwidthRes = await request(seededApp)
      .get('/synapse/payload/bandwidth')
      .expect(200);
    expect(bandwidthRes.body.aggregate).toMatchObject({
      totalBytes: 1100,
      totalBytesIn: 400,
      totalBytesOut: 700,
      requestCount: 30,
      maxRequestSize: 60,
      maxResponseSize: 90,
    });
    expect(bandwidthRes.body.aggregate.timeline).toEqual([
      expect.objectContaining({
        timestamp: 1700000000000,
        bytesIn: 150,
        bytesOut: 275,
        requestCount: 15,
      }),
      expect.objectContaining({
        timestamp: 1700000060000,
        bytesIn: 250,
        bytesOut: 425,
        requestCount: 15,
      }),
    ]);
    expect(bandwidthRes.body.results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          sensorId: 'sensor-3',
          status: 'error',
          error: 'No payload snapshot available',
        }),
      ])
    );
  });

  it('rejects unauthenticated POST /synapse/:sensorId/rules', async () => {
    const unauthApp = buildApp();

    const res = await request(unauthApp)
      .post('/synapse/sensor-1/rules')
      .send(baseRulePayload)
      .expect(401);

    expect(res.body).toMatchObject({
      code: 'AUTH_REQUIRED',
    });
  });

  it('rejects POST /synapse/:sensorId/rules for non-admin role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .post('/synapse/sensor-1/rules')
      .send(baseRulePayload)
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_ROLE',
    });
  });

  it('rejects POST /synapse/:sensorId/rules without fleet:write scope', async () => {
    const adminNoWriteApp = buildApp(['fleet:admin']);

    const res = await request(adminNoWriteApp)
      .post('/synapse/sensor-1/rules')
      .send(baseRulePayload)
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('allows POST /synapse/:sensorId/rules for admin role', async () => {
    const adminApp = buildApp(['fleet:write', 'fleet:admin']);

    const res = await request(adminApp)
      .post('/synapse/sensor-1/rules')
      .send(baseRulePayload)
      .expect(201);

    expect(res.body).toMatchObject({ id: 'rule-1' });
    expect(synapseProxy.addRule).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      expect.any(Object),
      undefined
    );
  });

  it('rejects PUT /synapse/:sensorId/rules/:ruleId for non-admin role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .put('/synapse/sensor-1/rules/rule-1')
      .send({ name: 'Updated Rule' })
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_ROLE',
    });
  });

  it('rejects PUT /synapse/:sensorId/rules/:ruleId without fleet:write scope', async () => {
    const adminNoWriteApp = buildApp(['fleet:admin']);

    const res = await request(adminNoWriteApp)
      .put('/synapse/sensor-1/rules/rule-1')
      .send({ name: 'Updated Rule' })
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('allows PUT /synapse/:sensorId/rules/:ruleId for admin role', async () => {
    const adminApp = buildApp(['fleet:write', 'fleet:admin']);

    const res = await request(adminApp)
      .put('/synapse/sensor-1/rules/rule-1')
      .send({ name: 'Updated Rule' })
      .expect(200);

    expect(res.body).toMatchObject({ id: 'rule-1', name: 'Updated Rule' });
    expect(synapseProxy.updateRule).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      'rule-1',
      expect.any(Object)
    );
  });

  it('rejects DELETE /synapse/:sensorId/rules/:ruleId for non-admin role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .delete('/synapse/sensor-1/rules/rule-1')
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_ROLE',
    });
  });

  it('rejects DELETE /synapse/:sensorId/rules/:ruleId without fleet:write scope', async () => {
    const adminNoWriteApp = buildApp(['fleet:admin']);

    const res = await request(adminNoWriteApp)
      .delete('/synapse/sensor-1/rules/rule-1')
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('allows DELETE /synapse/:sensorId/rules/:ruleId for admin role', async () => {
    const adminApp = buildApp(['fleet:write', 'fleet:admin']);

    await request(adminApp)
      .delete('/synapse/sensor-1/rules/rule-1')
      .expect(204);

    expect(synapseProxy.deleteRule).toHaveBeenCalledWith('sensor-1', 'tenant-1', 'rule-1');
  });

  it('rejects unauthenticated PUT /synapse/:sensorId/config', async () => {
    const unauthApp = buildApp();

    const res = await request(unauthApp)
      .put('/synapse/sensor-1/config')
      .send(baseConfigPayload)
      .expect(401);

    expect(res.body).toMatchObject({
      code: 'AUTH_REQUIRED',
    });
  });

  it('rejects PUT /synapse/:sensorId/config without fleet:write scope', async () => {
    const limitedApp = buildApp(['fleet:read']);

    const res = await request(limitedApp)
      .put('/synapse/sensor-1/config')
      .send(baseConfigPayload)
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_SCOPE',
    });
  });

  it('allows PUT /synapse/:sensorId/config for operator role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .put('/synapse/sensor-1/config')
      .send(baseConfigPayload)
      .expect(200);

    expect(res.body).toMatchObject({ success: true });
    expect(synapseProxy.updateSensorConfig).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      'dlp',
      baseConfigPayload.config
    );
  });

  it('rejects PUT /synapse/:sensorId/config kernel updates for non-admin role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .put('/synapse/sensor-1/config')
      .send(kernelConfigPayload)
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_ROLE',
    });
  });

  it('allows PUT /synapse/:sensorId/config kernel updates for admin role', async () => {
    const adminApp = buildApp(['fleet:write', 'fleet:admin']);

    const res = await request(adminApp)
      .put('/synapse/sensor-1/config')
      .send(kernelConfigPayload)
      .expect(200);

    expect(res.body).toMatchObject({ success: true });
    expect(synapseProxy.updateSensorConfig).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      'kernel',
      kernelConfigPayload.config
    );
  });

  it('rejects PUT /synapse/config kernel updates for non-admin role', async () => {
    const operatorApp = buildApp(['fleet:write']);

    const res = await request(operatorApp)
      .put('/synapse/config')
      .send({
        ...kernelConfigPayload,
        sensorIds: ['sensor-1'],
      })
      .expect(403);

    expect(res.body).toMatchObject({
      code: 'INSUFFICIENT_ROLE',
    });
  });

  it('allows PUT /synapse/config kernel updates for admin role', async () => {
    const adminApp = buildApp(['fleet:write', 'fleet:admin']);

    const res = await request(adminApp)
      .put('/synapse/config')
      .send({
        ...kernelConfigPayload,
        sensorIds: ['sensor-1'],
      })
      .expect(200);

    expect(res.body).toMatchObject({ success: true });
    expect(synapseProxy.updateSensorConfig).toHaveBeenCalledWith(
      'sensor-1',
      'tenant-1',
      'kernel',
      kernelConfigPayload.config
    );
  });

  // ==========================================================================
  // Fleet campaign routes (ADR-0002, rollup-backed)
  // ==========================================================================

  describe('Fleet campaign routes', () => {
    const baseRow = {
      id: 'camp-1',
      tenantId: 'tenant-1',
      name: 'Fleet Campaign abcd1234',
      description: 'Cross-tenant attack detected affecting 3 tenants',
      status: 'ACTIVE' as const,
      severity: 'HIGH' as const,
      confidence: 0.82,
      isCrossTenant: true,
      tenantsAffected: 3,
      firstSeenAt: new Date('2026-04-17T10:00:00Z'),
      lastActivityAt: new Date('2026-04-17T21:00:00Z'),
      correlationSignals: {
        fingerprintMatch: 0.9,
        timingMatch: 0.7,
        tenantCount: 3,
        currentStage: 'credential_stuffing',
      },
      metadata: { anonFingerprint: 'abcd1234' },
      _count: { threatLinks: 5 },
    };

    const buildPrisma = () => ({
      campaign: {
        findMany: vi.fn().mockResolvedValue([baseRow]),
        findFirst: vi.fn().mockResolvedValue({
          ...baseRow,
          threatLinks: [
            {
              role: 'primary_actor',
              threat: {
                id: 'threat-1',
                threatType: 'IP',
                indicator: '203.0.113.7',
                riskScore: 87,
                hitCount: 42,
                lastSeenAt: new Date('2026-04-17T20:55:00Z'),
              },
            },
          ],
        }),
      },
    });

    it('GET /synapse/campaigns reads from Campaign table, maps status + severity', async () => {
      const fakePrisma = buildPrisma();
      const fleetApp = buildApp(['fleet:read'], {
        prisma: fakePrisma as unknown as Parameters<typeof buildApp>[1] extends infer T
          ? T extends { prisma?: infer P } ? P : never : never,
      });

      const res = await request(fleetApp).get('/synapse/campaigns').expect(200);

      expect(res.body.campaigns).toHaveLength(1);
      expect(res.body.campaigns[0]).toMatchObject({
        campaignId: 'camp-1',
        status: 'ACTIVE',
        severity: 'HIGH',
        confidence: 0.82,
        actorCount: 5,
        summary: 'Cross-tenant attack detected affecting 3 tenants',
      });
      expect(fakePrisma.campaign.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ tenantId: 'tenant-1' }),
        })
      );
    });

    it('GET /synapse/campaigns?status=DETECTED translates to DB MONITORING', async () => {
      const fakePrisma = buildPrisma();
      const fleetApp = buildApp(['fleet:read'], {
        prisma: fakePrisma as never,
      });

      await request(fleetApp).get('/synapse/campaigns?status=DETECTED').expect(200);

      expect(fakePrisma.campaign.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            tenantId: 'tenant-1',
            status: 'MONITORING',
          }),
        })
      );
    });

    it('GET /synapse/campaigns/:id/actors projects Threats as actors', async () => {
      const fakePrisma = buildPrisma();
      const fleetApp = buildApp(['fleet:read'], { prisma: fakePrisma as never });

      const res = await request(fleetApp)
        .get('/synapse/campaigns/camp-1/actors')
        .expect(200);

      expect(res.body).toMatchObject({
        campaignId: 'camp-1',
        actors: [
          expect.objectContaining({
            actorId: '203.0.113.7',
            riskScore: 87,
            ips: ['203.0.113.7'],
          }),
        ],
      });
    });

    it('GET /synapse/campaigns/:id/graph builds a 2-hop graph', async () => {
      const fakePrisma = buildPrisma();
      const fleetApp = buildApp(['fleet:read'], { prisma: fakePrisma as never });

      const res = await request(fleetApp)
        .get('/synapse/campaigns/camp-1/graph')
        .expect(200);

      expect(res.body.data.nodes).toHaveLength(2); // campaign + 1 threat
      expect(res.body.data.nodes[0]).toMatchObject({ id: 'camp-1', type: 'campaign' });
      expect(res.body.data.edges).toEqual([
        expect.objectContaining({
          source: 'camp-1',
          target: 'threat-1',
          type: 'primary_actor',
        }),
      ]);
    });

    it('returns 404 when campaign not found for tenant', async () => {
      const fakePrisma = {
        campaign: {
          findFirst: vi.fn().mockResolvedValue(null),
        },
      };
      const fleetApp = buildApp(['fleet:read'], { prisma: fakePrisma as never });

      await request(fleetApp).get('/synapse/campaigns/missing').expect(404);
    });

    it('returns 503 when prisma is not wired', async () => {
      const fleetApp = buildApp(['fleet:read']);

      await request(fleetApp).get('/synapse/campaigns').expect(503);
    });
  });
});
