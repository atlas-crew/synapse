import { describe, it, expect, vi, afterEach } from 'vitest';
import { ClickHouseService } from '../client.js';
import { AsyncSemaphore } from '../../../lib/async-semaphore.js';
import { metrics } from '../../../services/metrics.js';
import type { Logger } from 'pino';

const createMockLogger = (): Logger =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    trace: vi.fn(),
  } as unknown as Logger);

const createTestService = (overrides: Partial<Record<string, unknown>> = {}) => {
  const logger = createMockLogger();
  const svc = new ClickHouseService(
    {
      host: 'localhost',
      port: 8123,
      database: 'test',
      username: 'test',
      password: 'test',
      compression: false,
      maxOpenConnections: 1,
      maxInFlightQueries: 1,
      queryTimeoutSec: 30,
      queueTimeoutSec: 1,
      maxRowsLimit: 1000,
      ...overrides,
    } as any,
    logger,
    false
  );

  // Enable and install a deterministic limiter without creating a real ClickHouse client.
  (svc as any).enabled = true;
  (svc as any).queryLimiter = new AsyncSemaphore(1);
  (svc as any).queueTimeoutMs = 1000;

  return svc;
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('ClickHouseService query telemetry/backpressure', () => {
  it('starts execution timer only after acquiring a permit', async () => {
    const execTimerSpy = vi.spyOn(metrics.clickhouseQueryDuration, 'startTimer');
    const waitTimerSpy = vi.spyOn(metrics.clickhouseQueryWaitDuration, 'startTimer');

    let resolveQuery1: ((value: any) => void) | undefined;

    const fakeClient = {
      query: vi
        .fn()
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              resolveQuery1 = resolve;
            })
        )
        .mockResolvedValueOnce({
          json: async () => [{ ok: 2 }],
        }),
    };

    const svc = createTestService();
    (svc as any).client = fakeClient;

    const p1 = svc.queryWithParams('SELECT 1', {});
    await Promise.resolve();

    const p2 = svc.queryWithParams('SELECT 2', {});
    await Promise.resolve();

    // Second call should be stuck waiting on the semaphore and must not start the exec timer yet.
    expect(waitTimerSpy).toHaveBeenCalled();
    expect(execTimerSpy).toHaveBeenCalledTimes(1);

    resolveQuery1?.({
      json: async () => [{ ok: 1 }],
    });

    await p1;
    await p2;

    expect(execTimerSpy).toHaveBeenCalledTimes(2);
  });

  it('times out waiting for a permit and does not leak capacity', async () => {
    vi.useFakeTimers();

    const errorIncSpy = vi.spyOn(metrics.clickhouseQueryErrors, 'inc');
    const inflightIncSpy = vi.spyOn(metrics.clickhouseQueriesInFlight, 'inc');

    let resolveQuery1: ((value: any) => void) | undefined;

    const fakeClient = {
      query: vi
        .fn()
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              resolveQuery1 = resolve;
            })
        ),
    };

    const svc = createTestService();
    (svc as any).client = fakeClient;

    const p1 = svc.queryWithParams('SELECT 1', {});
    await Promise.resolve();

    const p2 = svc.queryWithParams('SELECT 2', {});
    const p2Caught = p2.catch((e) => e);
    await Promise.resolve();

    // First query acquired a permit; second is queued and should not acquire.
    expect(inflightIncSpy).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(1000);
    const err = await p2Caught;
    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).toMatch(/permit wait timed out/i);
    expect(errorIncSpy).toHaveBeenCalled();

    // Unblock the first query so the test can finish cleanly.
    resolveQuery1?.({
      json: async () => [{ ok: 1 }],
    });
    await p1;

    // Capacity should not be leaked after the timeout.
    const release = await (svc as any).queryLimiter.acquire();
    release();
  });

  it('fails gracefully if close() happens while waiting for a permit', async () => {
    let resolveQuery1: ((value: any) => void) | undefined;

    const fakeClient = {
      query: vi
        .fn()
        .mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              resolveQuery1 = resolve;
            })
        ),
      close: vi.fn().mockResolvedValue(undefined),
    };

    const svc = createTestService();
    (svc as any).client = fakeClient;

    const p1 = svc.queryWithParams('SELECT 1', {});
    await Promise.resolve();

    const p2 = svc.queryWithParams('SELECT 2', {});
    const p2Caught = p2.catch((e) => e);
    await Promise.resolve();

    await svc.close();

    resolveQuery1?.({
      json: async () => [{ ok: 1 }],
    });
    await p1;

    const err = await p2Caught;
    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).toMatch(/not available|closed/i);
  });
});
