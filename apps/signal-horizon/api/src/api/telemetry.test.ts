import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { Logger } from 'pino';
import { createHmac } from 'node:crypto';
import request from '../__tests__/test-request.js';
import { createTelemetryRouter } from './telemetry.js';
import type { PrismaClient } from '@prisma/client';
import type { ClickHouseService } from '../storage/clickhouse/index.js';

const mockConfig = vi.hoisted(() => ({
  telemetry: { jwtSecret: 'test-secret' as string | undefined },
}));

vi.mock('../config.js', () => ({
  config: mockConfig,
}));

// Ensure the mock intercepts config imports from nested modules
// (telemetry-jwt.ts imports config from ../../config.js relative to its location)
vi.mock('../../config.js', () => ({
  config: mockConfig,
}));

const createLogger = (): Logger => {
  const logger = {
    child: vi.fn(() => logger),
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
  } as Logger;
  return logger;
};

const payload = {
  event_type: 'request_processed',
  data: {
    method: 'GET',
    path: '/',
    status_code: 200,
    latency_ms: 12,
  },
};

const base64UrlEncode = (value: string | Buffer): string =>
  Buffer.from(value)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');

const createJwt = (overrides: Record<string, unknown> = {}): string => {
  const secret = mockConfig.telemetry.jwtSecret ?? 'test-secret';
  const now = Math.floor(Date.now() / 1000);
  const payloadData = {
    tenantId: 'tenant-1',
    sensorId: 'sensor-1',
    aud: 'signal-horizon',
    jti: 'jti-1',
    iat: now - 1,
    exp: now + 3600,
    ...overrides,
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payloadData));
  const signature = base64UrlEncode(
    createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest()
  );

  return `${headerB64}.${payloadB64}.${signature}`;
};

describe('Telemetry routes', () => {
  let app: Express;
  let clickhouse: ClickHouseService;
  let insertSpy: ReturnType<typeof vi.fn>;
  let prisma: PrismaClient;

  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-secret';

    insertSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: insertSpy,
    } as unknown as ClickHouseService;

    prisma = {
      tokenBlacklist: {
        findUnique: vi.fn().mockResolvedValue(null),
        findFirst: vi.fn().mockResolvedValue(null),
      },
    } as unknown as PrismaClient;

    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));
  });

  it('rejects requests when telemetry jwt secret is missing', async () => {
    mockConfig.telemetry.jwtSecret = undefined;

    const res = await request(app)
      .post('/_sensor/report')
      .send(payload)
      .expect(503);

    expect(res.body).toEqual({ error: 'telemetry_jwt_missing' });
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('rejects requests without a bearer token', async () => {
    const res = await request(app)
      .post('/_sensor/report')
      .send(payload)
      .expect(401);

    expect(res.body).toEqual({ error: 'unauthorized' });
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('rejects expired jwt tokens', async () => {
    const expired = Math.floor(Date.now() / 1000) - 10;
    const token = createJwt({ exp: expired, jti: 'expired-jti' });

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(payload)
      .expect(401);

    expect(res.body).toEqual({ error: 'unauthorized' });
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('accepts requests with a valid jwt', async () => {
    const token = createJwt({ jti: 'valid-jti' });

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(payload)
      .expect(202);

    expect(res.body).toMatchObject({ inserted: 1 });
    expect(insertSpy).toHaveBeenCalled();
  });

  it('prefers per-event request_id when provided', async () => {
    const token = createJwt({ jti: 'valid-jti-per-event-request-id' });
    const perEvent = {
      event_type: 'request_processed',
      data: {
        request_id: 'req_123',
        method: 'GET',
        path: '/health',
        status_code: 200,
        latency_ms: 1,
      },
    };

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    expect(insertSpy).toHaveBeenCalledTimes(1);
    const [rows] = insertSpy.mock.calls[0] ?? [];
    expect(rows[0]?.request_id).toBe('req_123');
  });

  it('ingests waf_block as WAF_BLOCK signal event with request_id', async () => {
    const token = createJwt({ jti: 'valid-jti-waf-block' });
    const perEvent = {
      event_type: 'waf_block',
      data: {
        request_id: 'req_abc',
        rule_id: '941100',
        severity: 'high',
        client_ip: '203.0.113.10',
        site: 'example.com',
        path: '/login',
      },
    };

    // Override clickhouse impl used by telemetry router for this test
    const signalSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: vi.fn(),
      insertSignalEvents: signalSpy,
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    expect(signalSpy).toHaveBeenCalledTimes(1);
    const [rows] = signalSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      request_id: 'req_abc',
      signal_type: 'WAF_BLOCK',
      source_ip: '203.0.113.10',
      severity: 'HIGH',
    });
  });

  it('ingests rate_limit_hit as RATE_LIMIT_HIT signal event', async () => {
    const token = createJwt({ jti: 'valid-jti-rate-limit-hit' });
    const perEvent = {
      event_type: 'rate_limit_hit',
      data: {
        request_id: 'req_rl_1',
        client_ip: '203.0.113.11',
        limit: 100,
        window_secs: 60,
        site: 'example.com',
      },
    };

    const signalSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: vi.fn(),
      insertSignalEvents: signalSpy,
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    const [rows] = signalSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      request_id: 'req_rl_1',
      signal_type: 'RATE_LIMIT_HIT',
      source_ip: '203.0.113.11',
      severity: 'MEDIUM',
    });
  });

  it('ingests config_reload into sensor_logs', async () => {
    const token = createJwt({ jti: 'valid-jti-config-reload' });
    const perEvent = {
      event_type: 'config_reload',
      data: {
        sites_loaded: 3,
        duration_ms: 120,
        success: true,
      },
    };

    const logSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: logSpy,
      insertSignalEvents: vi.fn(),
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const [rows] = logSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      message: 'config_reload',
      source: 'system',
      level: 'info',
    });
  });

  it('ingests service_health into sensor_logs', async () => {
    const token = createJwt({ jti: 'valid-jti-service-health' });
    const perEvent = {
      event_type: 'service_health',
      data: {
        uptime_secs: 3600,
        memory_mb: 512,
        active_connections: 12,
        requests_per_sec: 100.5,
      },
    };

    const logSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: logSpy,
      insertSignalEvents: vi.fn(),
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    const [rows] = logSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      message: 'service_health',
      source: 'system',
      level: 'info',
    });
  });

  it('ingests auth_coverage into sensor_logs', async () => {
    const token = createJwt({ jti: 'valid-jti-auth-coverage' });
    const perEvent = {
      event_type: 'auth_coverage',
      data: {
        request_id: 'req_auth_1',
        site: 'example.com',
        total_endpoints: 10,
        covered_endpoints: 7,
      },
    };

    const logSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: logSpy,
      insertSignalEvents: vi.fn(),
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const [rows] = logSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      request_id: 'req_auth_1',
      message: 'auth_coverage',
      source: 'system',
      level: 'info',
    });
    expect(typeof rows[0]?.fields).toBe('string');
  });

  it('ingests campaign_report into sensor_logs', async () => {
    const token = createJwt({ jti: 'valid-jti-campaign-report' });
    const perEvent = {
      event_type: 'campaign_report',
      data: {
        request_id: 'req_campaign_1',
        campaign_id: 'camp_1',
        status: 'running',
        counters: { ok: 12, blocked: 3 },
      },
    };

    const logSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: logSpy,
      insertSignalEvents: vi.fn(),
    } as unknown as ClickHouseService;
    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse, prisma }));

    await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(perEvent)
      .expect(202);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const [rows] = logSpy.mock.calls[0] ?? [];
    expect(rows[0]).toMatchObject({
      request_id: 'req_campaign_1',
      message: 'campaign_report',
      source: 'system',
      level: 'info',
    });
    expect(typeof rows[0]?.fields).toBe('string');
  });

  it('rejects payloads exceeding the event batch limit', async () => {
    const token = createJwt({ jti: 'oversized-batch' });
    const oversized = {
      events: Array.from({ length: 5001 }, () => ({})),
    };

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(oversized)
      .expect(400);

    expect(res.body.error).toBe('validation_failed');
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('rejects telemetry payloads with invalid event_type values', async () => {
    const token = createJwt({ jti: 'invalid-event-type' });
    const invalidPayload = {
      event_type: 123,
      data: {
        method: 'GET',
        path: '/',
        status_code: 200,
        latency_ms: 12,
      },
    };

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(invalidPayload)
      .expect(400);

    expect(res.body.error).toBe('validation_failed');
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('rejects telemetry payloads with overlong actor ip', async () => {
    const token = createJwt({ jti: 'invalid-actor-ip' });
    const invalidPayload = {
      event_type: 'request_processed',
      actor: {
        ip: '1'.repeat(51),
      },
      data: {
        method: 'GET',
        path: '/',
        status_code: 200,
        latency_ms: 12,
      },
    };

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(invalidPayload)
      .expect(400);

    expect(res.body.error).toBe('validation_failed');
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('rejects revoked jwt tokens', async () => {
    const token = createJwt({ jti: 'revoked-jti' });
    vi.mocked(prisma.tokenBlacklist.findFirst).mockResolvedValue({ jti: 'revoked-jti' } as never);

    const res = await request(app)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(payload)
      .expect(401);

    expect(res.body).toEqual({ error: 'token_revoked' });
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('audit logs external signal submissions', async () => {
    const signalPayload = {
      sensorId: 'test-sensor',
      timestamp: Date.now(),
      signal: {
        type: 'honeypot_hit',
        severity: 'critical',
      },
    };

    const logger = createLogger();
    const infoSpy = vi.fn();
    logger.info = infoSpy as Logger['info'];
    logger.child = vi.fn(() => logger) as Logger['child'];

    const signalSpy = vi.fn().mockResolvedValue(undefined);
    const clickhouseWithSignal = {
      isEnabled: () => true,
      insertHttpTransactions: vi.fn(),
      insertLogEntries: vi.fn(),
      insertSignalEvents: signalSpy,
    } as unknown as ClickHouseService;

    const appWithMockLogger = express();
    appWithMockLogger.use(express.json());
    appWithMockLogger.use(createTelemetryRouter(logger, { clickhouse: clickhouseWithSignal }));

    const token = createJwt({ jti: 'audit-jti', sensorId: 'jwt-sensor' });

    await request(appWithMockLogger)
      .post('/_sensor/report')
      .set('Authorization', `Bearer ${token}`)
      .send(signalPayload)
      .expect(202);

    expect(infoSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        audit: true,
        sensor_id: 'jwt-sensor',
        signal_type: 'honeypot_hit',
        severity: 'critical',
      }),
      expect.stringContaining('received')
    );

    expect(signalSpy).toHaveBeenCalledWith(
      expect.arrayContaining([
        expect.objectContaining({
          sensor_id: 'jwt-sensor',
          signal_type: 'honeypot_hit',
          severity: 'CRITICAL',
        }),
      ])
    );
  });
});
