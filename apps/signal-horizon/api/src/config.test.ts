import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('Configuration parsing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('parses NODE_ENV case-insensitively', async () => {
    process.env.NODE_ENV = 'PRODUCTION';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    
    const { config } = await import('./config.js');
    expect(config.env).toBe('production');
    expect(config.isProd).toBe(true);
  });

  it('parses boolean flags case-insensitively', async () => {
    process.env.SENSOR_BRIDGE_ENABLED = 'YES';
    process.env.SYNAPSE_DIRECT_URL = 'http://localhost:6191';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    
    const { config } = await import('./config.js');
    expect(config.sensorBridge.enabled).toBe(true);
  });

  it('accepts various truthy values', async () => {
    process.env.CLICKHOUSE_ENABLED = '1';
    process.env.CLICKHOUSE_COMPRESSION = 'on';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    
    const { config } = await import('./config.js');
    expect(config.clickhouse.enabled).toBe(true);
    expect(config.clickhouse.compression).toBe(true);
  });

  it('parses LOG_LEVEL case-insensitively', async () => {
    process.env.LOG_LEVEL = 'DEBUG';
    process.env.DATABASE_URL = 'postgres://localhost:5432/db';
    
    const { config } = await import('./config.js');
    expect(config.logging.level).toBe('debug');
  });
});
