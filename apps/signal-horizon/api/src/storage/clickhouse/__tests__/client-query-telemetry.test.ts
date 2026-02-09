import { describe, it, expect, vi, afterEach } from 'vitest';
import { ClickHouseService } from '../client.js';
import { AsyncSemaphore } from '../../../lib/async-semaphore.js';
import { metrics } from '../../../services/metrics.js';
import type { Logger } from 'pino';

const waitForMicrotasks = async (predicate: () => boolean, maxTicks = 50) => {
  for (let i = 0; i < maxTicks; i += 1) {
    if (predicate()) return;
    // Yield to allow promise continuations to run.
    await Promise.resolve();
  }
  throw new Error('Timed out waiting for microtasks to settle');
};

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
      maxInFlightStreamQueries: 1,
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
  (svc as any).streamLimiter = new AsyncSemaphore(1);
  (svc as any).queueTimeoutMs = 1000;

  return svc;
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('ClickHouseService query telemetry/backpressure', () => {
  it('clears permit acquisition timeout on success (no timer leaks)', async () => {
    vi.useFakeTimers();
    const setSpy = vi.spyOn(globalThis, 'setTimeout');
    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        json: async () => [{ ok: 1 }],
      }),
    };

    const svc = createTestService();
    (svc as any).client = fakeClient;

    await svc.queryWithParams('SELECT 1', {});

    expect(setSpy).toHaveBeenCalled();
    const timeoutId = setSpy.mock.results[0]?.value;
    expect(clearSpy).toHaveBeenCalledWith(timeoutId);
  });

  it('releases permits in reverse (LIFO) order when query fails after acquiring both permits', async () => {
    const svc = createTestService();
    const releaseOrder: string[] = [];

    (svc as any).acquireQueryPermit = vi.fn().mockResolvedValue(() => {
      releaseOrder.push('query');
    });
    (svc as any).acquireStreamPermit = vi.fn().mockResolvedValue(() => {
      releaseOrder.push('stream');
    });

    const err = await (svc as any)
      .withQueryTelemetry(
        'queryStream',
        async () => {
          throw new Error('boom');
        },
        { acquireExtraPermit: () => (svc as any).acquireStreamPermit('queryStream') }
      )
      .catch((e: unknown) => e);

    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).toMatch(/boom/i);
    expect(releaseOrder).toEqual(['stream', 'query']);
  });

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
    await waitForMicrotasks(() => execTimerSpy.mock.calls.length === 1);

    const p2 = svc.queryWithParams('SELECT 2', {});
    await waitForMicrotasks(() => waitTimerSpy.mock.calls.length >= 2);

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
    const queueDepthDecSpy = vi.spyOn(metrics.clickhouseQueryQueueDepth, 'dec');

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
    expect(queueDepthDecSpy).toHaveBeenCalledWith({ op: 'queryWithParams', queue: 'query' });

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

  it('applies a separate stream limiter for queryStream', async () => {
    const execTimerSpy = vi.spyOn(metrics.clickhouseQueryDuration, 'startTimer');

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
          stream: async function* () {
            yield [];
          },
        }),
    };

    const svc = createTestService({ maxInFlightQueries: 2, maxInFlightStreamQueries: 1 });
    (svc as any).queryLimiter = new AsyncSemaphore(2);
    (svc as any).streamLimiter = new AsyncSemaphore(1);
    (svc as any).client = fakeClient;

    const p1 = svc.queryStream('SELECT 1', 100, async () => {});
    await waitForMicrotasks(() => execTimerSpy.mock.calls.length === 1);

    const p2 = svc.queryStream('SELECT 2', 100, async () => {});
    await waitForMicrotasks(() => execTimerSpy.mock.calls.length === 1);

    // Second stream call should be blocked on stream limiter; only one exec timer started so far.
    expect(execTimerSpy).toHaveBeenCalledTimes(1);

    resolveQuery1?.({
      stream: async function* () {
        yield [];
      },
    });

    await p1;
    await p2;
    expect(execTimerSpy).toHaveBeenCalledTimes(2);
  });

  it('times out waiting for stream permit and rolls back query permit', async () => {
    vi.useFakeTimers();

    const svc = createTestService({ maxInFlightQueries: 2, maxInFlightStreamQueries: 1 });
    const queryLimiter = new AsyncSemaphore(2);
    const streamLimiter = new AsyncSemaphore(1);
    (svc as any).queryLimiter = queryLimiter;
    (svc as any).streamLimiter = streamLimiter;
    (svc as any).queueTimeoutMs = 100;

    let resolveQuery1: ((value: any) => void) | undefined;
    const fakeClient = {
      query: vi.fn().mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveQuery1 = resolve;
          })
      ),
    };
    (svc as any).client = fakeClient;

    const p1 = svc.queryStream('SELECT 1', 100, async () => {});
    await waitForMicrotasks(() => streamLimiter.getAvailable() === 0);

    const p2 = svc.queryStream('SELECT 2', 100, async () => {});
    const p2Caught = p2.catch((e) => e);
    // Ensure p2 has acquired a query permit but is blocked on the stream permit.
    await waitForMicrotasks(() => queryLimiter.getAvailable() === 0);

    await vi.advanceTimersByTimeAsync(100);
    const err = await p2Caught;
    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).toMatch(/stream permit wait timed out/i);

    // p1 holds 1 query permit; p2 should have rolled back its query permit on stream timeout.
    expect(queryLimiter.getAvailable()).toBe(1);

    resolveQuery1?.({
      stream: async function* () {
        yield [];
      },
    });
    await p1;

    expect(queryLimiter.getAvailable()).toBe(2);
    expect(streamLimiter.getAvailable()).toBe(1);
  });

  it('propagates onBatch errors and releases permits for queryStream', async () => {
    const svc = createTestService({ maxInFlightQueries: 1, maxInFlightStreamQueries: 1 });
    const queryLimiter = new AsyncSemaphore(1);
    const streamLimiter = new AsyncSemaphore(1);
    (svc as any).queryLimiter = queryLimiter;
    (svc as any).streamLimiter = streamLimiter;

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        stream: async function* () {
          yield [
            { json: () => ({ n: 1 }) },
            { json: () => ({ n: 2 }) },
          ];
        },
      }),
    };
    (svc as any).client = fakeClient;

    const err = await svc
      .queryStream('SELECT 1', 2, async () => {
        throw new Error('boom');
      })
      .catch((e) => e);

    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).toMatch(/boom/i);
    expect(queryLimiter.getAvailable()).toBe(1);
    expect(streamLimiter.getAvailable()).toBe(1);
  });

  it('batches streamed rows and flushes a partial final batch', async () => {
    const svc = createTestService({ maxInFlightQueries: 1, maxInFlightStreamQueries: 1 });
    (svc as any).queryLimiter = new AsyncSemaphore(1);
    (svc as any).streamLimiter = new AsyncSemaphore(1);

    const fakeClient = {
      query: vi.fn().mockResolvedValue({
        stream: async function* () {
          yield [
            { json: () => ({ n: 1 }) },
            { json: () => ({ n: 2 }) },
            { json: () => ({ n: 3 }) },
            { json: () => ({ n: 4 }) },
            { json: () => ({ n: 5 }) },
          ];
        },
      }),
    };
    (svc as any).client = fakeClient;

    const batches: number[] = [];
    const total = await svc.queryStream('SELECT 1', 2, async (rows) => {
      batches.push(rows.length);
    });

    expect(total).toBe(5);
    expect(batches).toEqual([2, 2, 1]);
  });
});
