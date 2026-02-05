/**
 * Auth rate limiter tests
 *
 * Validates per-IP burst limits and failure-only limits for auth attempts.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from '../../../__tests__/test-request.js';
import { createAuthRateLimiters } from '../rate-limit.js';

const ENV_KEYS = [
  'AUTH_RATE_LIMIT_IP_PER_SEC',
  'AUTH_RATE_LIMIT_FAILURES_PER_MIN',
  'AUTH_RATE_LIMIT_KEY_PER_HOUR',
] as const;

const originalEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const key of ENV_KEYS) {
    originalEnv[key] = process.env[key];
  }
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    const value = originalEnv[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

function buildApp(status: number) {
  const app = express();
  const { ipBurst, ipFailures, keyFailures } = createAuthRateLimiters();
  app.use(ipBurst, ipFailures, keyFailures);
  app.get('/auth-check', (_req, res) => {
    res.status(status).json({ ok: status < 400 });
  });
  return app;
}

describe('auth rate limiters', () => {
  it('limits auth bursts per IP', async () => {
    process.env.AUTH_RATE_LIMIT_IP_PER_SEC = '2';
    process.env.AUTH_RATE_LIMIT_FAILURES_PER_MIN = '100';
    process.env.AUTH_RATE_LIMIT_KEY_PER_HOUR = '100';

    const app = buildApp(200);

    await request(app).get('/auth-check').expect(200);
    await request(app).get('/auth-check').expect(200);
    const res = await request(app).get('/auth-check').expect(429);

    expect(res.headers['retry-after']).toBeDefined();
  });

  it('limits failed auth attempts per IP', async () => {
    process.env.AUTH_RATE_LIMIT_IP_PER_SEC = '100';
    process.env.AUTH_RATE_LIMIT_FAILURES_PER_MIN = '2';
    process.env.AUTH_RATE_LIMIT_KEY_PER_HOUR = '100';

    const app = buildApp(401);

    await request(app).get('/auth-check').expect(401);
    await request(app).get('/auth-check').expect(401);
    const res = await request(app).get('/auth-check').expect(429);

    expect(res.headers['retry-after']).toBeDefined();
  });

  it('limits failed auth attempts per API key', async () => {
    process.env.AUTH_RATE_LIMIT_IP_PER_SEC = '100';
    process.env.AUTH_RATE_LIMIT_FAILURES_PER_MIN = '100';
    process.env.AUTH_RATE_LIMIT_KEY_PER_HOUR = '2';

    const app = buildApp(401);

    await request(app)
      .get('/auth-check')
      .set('authorization', 'Bearer test-token')
      .expect(401);
    await request(app)
      .get('/auth-check')
      .set('authorization', 'Bearer test-token')
      .expect(401);
    const res = await request(app)
      .get('/auth-check')
      .set('authorization', 'Bearer test-token')
      .expect(429);

    expect(res.headers['retry-after']).toBeDefined();
  });
});
