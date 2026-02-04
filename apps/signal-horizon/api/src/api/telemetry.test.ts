import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { Logger } from 'pino';
import { createHmac } from 'node:crypto';
import request from '../__tests__/test-request.js';
import { createTelemetryRouter } from './telemetry.js';
import { revokeTelemetryToken } from './middleware/telemetry-jwt.js';
import type { ClickHouseService } from '../storage/clickhouse/index.js';

const mockConfig = vi.hoisted(() => ({
  telemetry: { jwtSecret: 'test-secret' as string | undefined },
}));

vi.mock('../config.js', () => ({
  config: mockConfig,
}));

const createLogger = (): Logger => {
  const logger = {
    child: vi.fn(() => logger),
    error: vi.fn(),
    warn: vi.fn(),
  } as unknown as Logger;
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

  beforeEach(() => {
    mockConfig.telemetry.jwtSecret = 'test-secret';

    insertSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: insertSpy,
    } as unknown as ClickHouseService;

    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse }));
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

  it('rejects revoked jwt tokens', async () => {
    const token = createJwt({ jti: 'revoked-jti' });
    revokeTelemetryToken('revoked-jti');

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
    (logger as any).info = infoSpy;
    (logger as any).child = vi.fn(() => logger);

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
