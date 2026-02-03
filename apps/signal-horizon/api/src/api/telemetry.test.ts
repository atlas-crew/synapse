import { describe, it, expect, beforeEach, vi } from 'vitest';
import express, { type Express } from 'express';
import type { Logger } from 'pino';
import request from '../__tests__/test-request.js';
import { createTelemetryRouter } from './telemetry.js';
import type { ClickHouseService } from '../storage/clickhouse/index.js';

const mockConfig = vi.hoisted(() => ({
  telemetry: { apiKey: 'test-key' as string | undefined },
  security: { apiKeyHeader: 'X-API-Key' },
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

describe('Telemetry routes', () => {
  let app: Express;
  let clickhouse: ClickHouseService;
  let insertSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockConfig.telemetry.apiKey = 'test-key';
    mockConfig.security.apiKeyHeader = 'X-API-Key';

    insertSpy = vi.fn().mockResolvedValue(undefined);
    clickhouse = {
      isEnabled: () => true,
      insertHttpTransactions: insertSpy,
    } as unknown as ClickHouseService;

    app = express();
    app.use(express.json());
    app.use(createTelemetryRouter(createLogger(), { clickhouse }));
  });

  it('rejects requests when telemetry key is missing', async () => {
    mockConfig.telemetry.apiKey = undefined;

    const res = await request(app)
      .post('/_sensor/report')
      .send(payload)
      .expect(503);

    expect(res.body).toEqual({ error: 'telemetry_key_missing' });
    expect(insertSpy).not.toHaveBeenCalled();
  });

  it('accepts requests with X-Admin-Key', async () => {
    const res = await request(app)
      .post('/_sensor/report')
      .set('X-Admin-Key', 'test-key')
      .send(payload)
      .expect(202);

    expect(res.body).toMatchObject({ inserted: 1 });
    expect(insertSpy).toHaveBeenCalled();
  });

  it('rejects requests with invalid api key', async () => {
    const res = await request(app)
      .post('/_sensor/report')
      .set('X-API-Key', 'wrong-key')
      .send(payload)
      .expect(401);

    expect(res.body).toEqual({ error: 'unauthorized' });
    expect(insertSpy).not.toHaveBeenCalled();
  });
});
