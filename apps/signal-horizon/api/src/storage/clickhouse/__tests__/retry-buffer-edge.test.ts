import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ClickHouseRetryBuffer } from '../retry-buffer.js';
import type { ClickHouseService, SignalEventRow } from '../client.js';
import type { Logger } from 'pino';
import type { BufferedItem, IRetryPersistentStore } from '../retry-buffer.js';

const createMockClickhouse = (): ClickHouseService =>
  ({
    isEnabled: vi.fn().mockReturnValue(true),
    insertSignalEvents: vi.fn().mockResolvedValue(undefined),
    insertCampaignEvent: vi.fn().mockResolvedValue(undefined),
    insertBlocklistEvents: vi.fn().mockResolvedValue(undefined),
    insertHttpTransactions: vi.fn().mockResolvedValue(undefined),
    insertLogEntries: vi.fn().mockResolvedValue(undefined),
    ping: vi.fn().mockResolvedValue(true),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as ClickHouseService);

const createMockLogger = (): Logger =>
  ({
    child: vi.fn().mockReturnThis(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger);

const createTestSignal = (overrides: Partial<SignalEventRow> = {}): SignalEventRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 'test-tenant',
  sensor_id: 'test-sensor',
  request_id: 'r1',
  signal_type: 'IP_THREAT',
  source_ip: '192.168.1.100',
  fingerprint: 'test-fingerprint',
  anon_fingerprint: 'test-anon-fingerprint'.padEnd(64, '0'),
  severity: 'HIGH',
  confidence: 0.95,
  event_count: 1,
  metadata: '{}',
  ...overrides,
});

const mkBufferedSignals = (count: number): BufferedItem[] =>
  Array.from({ length: count }).map((_, i) => ({
    type: 'signal' as const,
    data: [],
    attempts: 1,
    nextRetryAt: i,
    addedAt: i,
  }));

describe('ClickHouseRetryBuffer (edges)', () => {
  let clickhouse: ClickHouseService;
  let logger: Logger;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    clickhouse = createMockClickhouse();
    logger = createMockLogger();
  });

  afterEach(async () => {
    vi.useRealTimers();
  });

  it('start() loads from persistent store and caps to maxBufferSize', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue(mkBufferedSignals(200)),
      save: vi.fn(),
    };

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, { maxBufferSize: 100 }, store);
    await buffer.start();

    expect(buffer.getBufferSize()).toBe(100);
    expect(store.load).toHaveBeenCalled();
  });

  it('start() works without a persistent store', async () => {
    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, { retryIntervalMs: 100 });
    await expect(buffer.start()).resolves.toBeUndefined();
    expect(buffer.getBufferSize()).toBe(0);
    await buffer.stop();
  });

  it('start() merges loaded items with pre-existing buffered items', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue(mkBufferedSignals(2)),
      save: vi.fn(),
    };

    const buffer = new ClickHouseRetryBuffer(
      clickhouse,
      logger,
      { maxBufferSize: 10, retryIntervalMs: 100, initialDelayMs: 0 },
      store
    );

    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getBufferSize()).toBe(1);

    await buffer.start();
    expect(buffer.getBufferSize()).toBe(3);
  });

  it('start() is idempotent (does not create multiple intervals)', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue([]),
      save: vi.fn(),
    };

    const setIntervalSpy = vi.spyOn(globalThis, 'setInterval');

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, { retryIntervalMs: 100 }, store);
    await buffer.start();
    await buffer.start();

    expect(setIntervalSpy).toHaveBeenCalledTimes(1);
    expect(store.load).toHaveBeenCalledTimes(1);
  });

  it('stop() does not call persistent store when buffer is empty', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue([]),
      save: vi.fn(),
    };

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, { retryIntervalMs: 100 }, store);
    await buffer.stop();
    expect(store.save).not.toHaveBeenCalled();
  });

  it('start() handles persistent store load failure gracefully', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockRejectedValue(new Error('boom')),
      save: vi.fn(),
    };

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, { retryIntervalMs: 100 }, store);
    await expect(buffer.start()).resolves.toBeUndefined();
    expect((logger.error as unknown as ReturnType<typeof vi.fn>)).toHaveBeenCalled();
    await buffer.stop();
  });

  it('stop() handles persistent store save failure gracefully', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue([]),
      save: vi.fn().mockRejectedValue(new Error('boom')),
    };

    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const buffer = new ClickHouseRetryBuffer(
      clickhouse,
      logger,
      { retryIntervalMs: 100, initialDelayMs: 0, maxBufferSize: 100 },
      store
    );

    await buffer.insertSignalEvents([createTestSignal()]);
    await expect(buffer.stop()).resolves.toBeUndefined();
    expect((logger.error as unknown as ReturnType<typeof vi.fn>)).toHaveBeenCalled();
  });

  it('stop() saves to persistent store when buffer is non-empty', async () => {
    const store: IRetryPersistentStore = {
      load: vi.fn().mockResolvedValue([]),
      save: vi.fn().mockResolvedValue(undefined),
    };

    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const buffer = new ClickHouseRetryBuffer(
      clickhouse,
      logger,
      { retryIntervalMs: 100, initialDelayMs: 0, maxBufferSize: 100 },
      store
    );

    await buffer.start();
    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getBufferSize()).toBe(1);

    await buffer.stop();
    expect(store.save).toHaveBeenCalledTimes(1);
    expect((store.save as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]?.length).toBe(1);
  });

  it('stop() clears retry interval (no more retries after stop)', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.start();
    await buffer.insertSignalEvents([createTestSignal()]);
    expect((clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mock.calls.length).toBe(1);

    await buffer.stop();

    await vi.advanceTimersByTimeAsync(1000);
    expect((clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mock.calls.length).toBe(1);
  });

  it('clear() empties the buffer', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getBufferSize()).toBe(1);

    buffer.clear();
    expect(buffer.getBufferSize()).toBe(0);
  });

  it('DLQ payload included only when maxBufferSize < 1000', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('fail'));

    const loggerSmall = createMockLogger();
    const small = new ClickHouseRetryBuffer(
      clickhouse,
      loggerSmall,
      { maxBufferSize: 500, maxRetries: 1, initialDelayMs: 0, retryIntervalMs: 100 }
    );
    await small.insertSignalEvents([createTestSignal()]);
    await (small as any).processRetries();
    const smallArg = (loggerSmall.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => (c[0] as any)?.dlq === true
    )?.[0] as any;
    expect(Array.isArray(smallArg.payload)).toBe(true);

    const loggerLarge = createMockLogger();
    const large = new ClickHouseRetryBuffer(
      clickhouse,
      loggerLarge,
      { maxBufferSize: 5000, maxRetries: 1, initialDelayMs: 0, retryIntervalMs: 100 }
    );
    await large.insertSignalEvents([createTestSignal()]);
    await (large as any).processRetries();
    const largeArg = (loggerLarge.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => (c[0] as any)?.dlq === true
    )?.[0] as any;
    expect(largeArg.payload).toBeUndefined();
  });

  it('getStats().oldestItemAge matches elapsed time since first add', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error('fail')
    );

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    vi.setSystemTime(1000);
    await buffer.insertSignalEvents([createTestSignal()]);

    vi.setSystemTime(5000);
    expect(buffer.getStats().oldestItemAge).toBe(4000);
  });

  it('getStats().isProcessing toggles during processing', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error('fail'))
      .mockImplementationOnce(() => new Promise(() => {})); // hang on retry

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getStats().isProcessing).toBe(false);

    const p = (buffer as any).processRetries();
    expect(buffer.getStats().isProcessing).toBe(true);

    await vi.advanceTimersByTimeAsync(10000);
    await p;
    expect(buffer.getStats().isProcessing).toBe(false);
  });

  it('processRetries() enforces per-item timeout for hanging retry', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error('initial fail'))
      .mockImplementationOnce(() => new Promise(() => {})); // hang on retry

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getBufferSize()).toBe(1);

    const p = (buffer as any).processRetries();
    await vi.advanceTimersByTimeAsync(10000);
    await p;

    expect(buffer.getStats().failedRetries).toBe(1);
    expect(buffer.getBufferSize()).toBe(1);
  });

  it('processRetries() schedules exponential backoff delay values', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('fail'));

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 100,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);
    let item = (buffer as any).buffer[0] as BufferedItem;
    expect(item.attempts).toBe(1);
    expect(item.nextRetryAt).toBe(100);

    vi.setSystemTime(100);
    await (buffer as any).processRetries();
    item = (buffer as any).buffer[0] as BufferedItem;
    expect(item.attempts).toBe(2);
    expect(item.nextRetryAt).toBe(300); // now(100) + 100*2^(2-1)=200

    vi.setSystemTime(300);
    await (buffer as any).processRetries();
    item = (buffer as any).buffer[0] as BufferedItem;
    expect(item.attempts).toBe(3);
    expect(item.nextRetryAt).toBe(700); // now(300) + 100*2^(3-1)=400
  });

  it('processRetries() clamps backoff delay to maxDelayMs', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('fail'));

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 100,
      maxDelayMs: 250,
      maxRetries: 10,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);

    vi.setSystemTime(100);
    await (buffer as any).processRetries();

    vi.setSystemTime(300);
    await (buffer as any).processRetries();

    const item = (buffer as any).buffer[0] as BufferedItem;
    expect(item.attempts).toBe(3);
    expect(item.nextRetryAt).toBe(550); // now(300) + clamp(400, 250)
  });

  it('processRetries() reentrancy guard prevents overlapping processing', async () => {
    (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
      .mockRejectedValueOnce(new Error('initial fail'))
      .mockImplementationOnce(() => new Promise(() => {})); // hang on retry

    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      maxDelayMs: 1000,
      maxRetries: 5,
      retryBatchSize: 1,
      maxBufferSize: 100,
    });

    await buffer.insertSignalEvents([createTestSignal()]);
    expect(buffer.getBufferSize()).toBe(1);

    const p1 = (buffer as any).processRetries();
    const p2 = (buffer as any).processRetries();
    await p2;

    expect(buffer.getStats().totalAttempts).toBe(1);

    await vi.advanceTimersByTimeAsync(10000);
    await p1;
  });

  it('retryItem() dispatches to blocklist/transaction/log insert methods', async () => {
    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      retryBatchSize: 10,
      maxRetries: 5,
      maxDelayMs: 1000,
      maxBufferSize: 100,
    });

    const blocklistData = [
      {
        timestamp: new Date().toISOString(),
        tenant_id: 't1',
        request_id: 'r1',
        action: 'added',
        block_type: 'ip',
        indicator: '1.2.3.4',
        source: 'test',
        reason: 'test',
        campaign_id: 'c1',
        expires_at: null,
      },
    ];

    const txnData = [
      {
        timestamp: new Date().toISOString(),
        tenant_id: 't1',
        sensor_id: 's1',
        request_id: 'r1',
        site: 'example.com',
        method: 'GET',
        path: '/',
        status_code: 200,
        latency_ms: 1,
        waf_action: null,
      },
    ];

    const logData = [
      {
        timestamp: new Date().toISOString(),
        tenant_id: 't1',
        sensor_id: 's1',
        request_id: 'r1',
        log_id: 'l1',
        source: 'sensor',
        level: 'info',
        message: 'm',
        fields: null,
        method: null,
        path: null,
        status_code: null,
        latency_ms: null,
        client_ip: null,
        rule_id: null,
      },
    ];

    (buffer as any).buffer.push(
      { type: 'blocklist', data: blocklistData, attempts: 1, nextRetryAt: 0, addedAt: 0 },
      { type: 'transaction', data: txnData, attempts: 1, nextRetryAt: 0, addedAt: 0 },
      { type: 'log', data: logData, attempts: 1, nextRetryAt: 0, addedAt: 0 }
    );

    await (buffer as any).processRetries();

    expect(clickhouse.insertBlocklistEvents).toHaveBeenCalledWith(blocklistData);
    expect(clickhouse.insertHttpTransactions).toHaveBeenCalledWith(txnData);
    expect(clickhouse.insertLogEntries).toHaveBeenCalledWith(logData);
  });

  it('moves unknown buffered item types to DLQ (does not silently drop)', async () => {
    const buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 0,
      retryBatchSize: 10,
      maxRetries: 1,
      maxDelayMs: 1000,
      maxBufferSize: 10,
    });

    (buffer as any).buffer.push({
      type: 'unknown',
      data: [],
      attempts: 1,
      nextRetryAt: 0,
      addedAt: 0,
    });

    await (buffer as any).processRetries();

    expect(buffer.getBufferSize()).toBe(0);
    const dlqArg = (logger.error as unknown as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => (c[0] as any)?.dlq === true
    )?.[0] as any;
    expect(dlqArg?.itemType).toBe('unknown');
  });
});
