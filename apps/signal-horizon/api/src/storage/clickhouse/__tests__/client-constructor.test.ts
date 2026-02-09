import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Logger } from 'pino';

vi.mock('@clickhouse/client', () => {
  return {
    createClient: vi.fn(() => ({
      close: vi.fn().mockResolvedValue(undefined),
      ping: vi.fn().mockResolvedValue(undefined),
      insert: vi.fn().mockResolvedValue(undefined),
      query: vi.fn(),
    })),
  };
});

import { createClient } from '@clickhouse/client';
import { ClickHouseService } from '../client.js';

const createMockLogger = (): Logger =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
  } as unknown as Logger);

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ClickHouseService constructor', () => {
  it('sets wait_for_async_insert based on NODE_ENV', () => {
    const prev = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = 'production';
      new ClickHouseService(
        {
          host: 'localhost',
          port: 8123,
          database: 'test',
          username: 'test',
          password: 'test',
          compression: false,
          maxOpenConnections: 1,
        },
        createMockLogger(),
        true
      );

      const prodArgs = (createClient as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as any;
      expect(prodArgs.clickhouse_settings.wait_for_async_insert).toBe(0);

      (createClient as unknown as ReturnType<typeof vi.fn>).mockClear();

      process.env.NODE_ENV = 'test';
      new ClickHouseService(
        {
          host: 'localhost',
          port: 8123,
          database: 'test',
          username: 'test',
          password: 'test',
          compression: false,
          maxOpenConnections: 1,
        },
        createMockLogger(),
        true
      );

      const testArgs = (createClient as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as any;
      expect(testArgs.clickhouse_settings.wait_for_async_insert).toBe(1);
    } finally {
      process.env.NODE_ENV = prev;
    }
  });

  it('sets request_timeout to (queryTimeoutSec + 5) * 1000', () => {
    (createClient as unknown as ReturnType<typeof vi.fn>).mockClear();

    new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 1,
        queryTimeoutSec: 30,
      } as any,
      createMockLogger(),
      true
    );

    const args = (createClient as unknown as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as any;
    expect(args.request_timeout).toBe(35000);
  });

  it('clamps maxInFlightStreamQueries to [1, maxInFlightQueries]', () => {
    const svcLow = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 10,
        maxInFlightQueries: 4,
        maxInFlightStreamQueries: 0,
      },
      createMockLogger(),
      true
    );

    expect((svcLow as any).streamLimiter.getAvailable()).toBe(1);
    expect((svcLow as any).queryLimiter.getAvailable()).toBe(4);

    const svcHigh = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 10,
        maxInFlightQueries: 4,
        maxInFlightStreamQueries: 999,
      },
      createMockLogger(),
      true
    );

    expect((svcHigh as any).streamLimiter.getAvailable()).toBe(4);
  });

  it('uses maxInFlightQueries when provided (independent of maxOpenConnections)', () => {
    const svc = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 10,
        maxInFlightQueries: 3,
        maxInFlightStreamQueries: 1,
      },
      createMockLogger(),
      true
    );

    expect((svc as any).queryLimiter.getAvailable()).toBe(3);
  });

  it('ensures queryLimiter minimum is 1 when maxInFlightQueries is 0', () => {
    const svc = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 10,
        maxInFlightQueries: 0,
      } as any,
      createMockLogger(),
      true
    );

    expect((svc as any).queryLimiter.getAvailable()).toBe(1);
  });

  it('applies defaults when optional config is omitted', () => {
    const svc = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 7,
      },
      createMockLogger(),
      true
    );

    expect((svc as any).queryTimeoutSec).toBe(30);
    expect((svc as any).queueTimeoutMs).toBe(30000);
    expect((svc as any).maxRowsLimit).toBe(100000);
    expect((svc as any).queryLimiter.getAvailable()).toBe(7);
  });

  it('derives queueTimeoutMs from queryTimeoutSec when queueTimeoutSec is omitted', () => {
    const svc = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 1,
        queryTimeoutSec: 15,
      } as any,
      createMockLogger(),
      true
    );

    expect((svc as any).queueTimeoutMs).toBe(15000);
  });

  it('defaults maxInFlightStreamQueries to min(2, maxInFlightQueries)', () => {
    const svcA = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 10,
      } as any,
      createMockLogger(),
      true
    );
    expect((svcA as any).streamLimiter.getAvailable()).toBe(2);

    const svcB = new ClickHouseService(
      {
        host: 'localhost',
        port: 8123,
        database: 'test',
        username: 'test',
        password: 'test',
        compression: false,
        maxOpenConnections: 1,
      } as any,
      createMockLogger(),
      true
    );
    expect((svcB as any).streamLimiter.getAvailable()).toBe(1);
  });
});
