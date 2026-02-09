import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ClickHouseRetryBuffer } from '../retry-buffer.js';
import type {
  ClickHouseService,
  SignalEventRow,
  CampaignHistoryRow,
  BlocklistHistoryRow,
  HttpTransactionRow,
  LogEntryRow,
} from '../client.js';
import type { Logger } from 'pino';

// Mock ClickHouseService
const createMockClickhouse = (): ClickHouseService => ({
  isEnabled: vi.fn().mockReturnValue(true),
  insertSignalEvents: vi.fn().mockResolvedValue(undefined),
  insertCampaignEvent: vi.fn().mockResolvedValue(undefined),
  insertBlocklistEvents: vi.fn().mockResolvedValue(undefined),
  insertHttpTransactions: vi.fn().mockResolvedValue(undefined),
  insertLogEntries: vi.fn().mockResolvedValue(undefined),
  ping: vi.fn().mockResolvedValue(true),
  close: vi.fn().mockResolvedValue(undefined),
} as unknown as ClickHouseService);

// Mock Logger
const createMockLogger = (): Logger => ({
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

const createTestBlocklist = (overrides: Partial<BlocklistHistoryRow> = {}): BlocklistHistoryRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 'test-tenant',
  request_id: 'r1',
  action: 'added',
  block_type: 'ip',
  indicator: '1.2.3.4',
  source: 'test',
  reason: 'test',
  campaign_id: 'campaign-1',
  expires_at: null,
  ...overrides,
});

const createTestTxn = (overrides: Partial<HttpTransactionRow> = {}): HttpTransactionRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 'test-tenant',
  sensor_id: 'test-sensor',
  request_id: 'r1',
  site: 'example.com',
  method: 'GET',
  path: '/',
  status_code: 200,
  latency_ms: 1,
  waf_action: null,
  ...overrides,
});

const createTestLog = (overrides: Partial<LogEntryRow> = {}): LogEntryRow => ({
  timestamp: new Date().toISOString(),
  tenant_id: 'test-tenant',
  sensor_id: 'test-sensor',
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
  ...overrides,
});

describe('ClickHouseRetryBuffer', () => {
  let clickhouse: ClickHouseService;
  let logger: Logger;
  let buffer: ClickHouseRetryBuffer;

  beforeEach(() => {
    vi.useFakeTimers();
    clickhouse = createMockClickhouse();
    logger = createMockLogger();
    buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
      retryIntervalMs: 100,
      initialDelayMs: 100,
      maxDelayMs: 1000,
      maxRetries: 3,
      maxBufferSize: 100,
    });
  });

  afterEach(() => {
    buffer.stop();
    vi.useRealTimers();
  });

  describe('successful writes', () => {
    it('writes signals directly without buffering on success', async () => {
      const signals = [createTestSignal()];
      const result = await buffer.insertSignalEvents(signals);

      expect(result).toBe(true);
      expect(clickhouse.insertSignalEvents).toHaveBeenCalledWith(signals);
      expect(buffer.getStats().bufferedCount).toBe(0);
    });

    it('writes campaign events directly on success', async () => {
      const event: CampaignHistoryRow = {
        timestamp: new Date().toISOString(),
        campaign_id: 'campaign-1',
        tenant_id: 'test-tenant',
        request_id: 'r1',
        event_type: 'created',
        name: 'Test Campaign',
        status: 'active',
        severity: 'HIGH',
        is_cross_tenant: 0,
        tenants_affected: 1,
        confidence: 0.9,
        metadata: '{}',
      };

      const result = await buffer.insertCampaignEvent(event);

      expect(result).toBe(true);
      expect(clickhouse.insertCampaignEvent).toHaveBeenCalledWith(event);
    });

    it('writes campaign events even when campaign_id is empty', async () => {
      const event: CampaignHistoryRow = {
        timestamp: new Date().toISOString(),
        campaign_id: '',
        tenant_id: 'test-tenant',
        request_id: null,
        event_type: 'created',
        name: 'Test Campaign',
        status: 'active',
        severity: 'HIGH',
        is_cross_tenant: 0,
        tenants_affected: 1,
        confidence: 0.9,
        metadata: '{}',
      };

      const result = await buffer.insertCampaignEvent(event);
      expect(result).toBe(true);
      expect(clickhouse.insertCampaignEvent).toHaveBeenCalledWith(event);
    });

    it('writes blocklist events directly on success', async () => {
      const events = [createTestBlocklist()];
      const result = await buffer.insertBlocklistEvents(events);

      expect(result).toBe(true);
      expect(clickhouse.insertBlocklistEvents).toHaveBeenCalledWith(events);
      expect(buffer.getStats().bufferedCount).toBe(0);
    });

    it('writes HTTP transactions directly on success', async () => {
      const events = [createTestTxn()];
      const result = await buffer.insertHttpTransactions(events);

      expect(result).toBe(true);
      expect(clickhouse.insertHttpTransactions).toHaveBeenCalledWith(events);
      expect(buffer.getStats().bufferedCount).toBe(0);
    });

    it('writes log entries directly on success', async () => {
      const events = [createTestLog()];
      const result = await buffer.insertLogEntries(events);

      expect(result).toBe(true);
      expect(clickhouse.insertLogEntries).toHaveBeenCalledWith(events);
      expect(buffer.getStats().bufferedCount).toBe(0);
    });
  });

  describe('buffering on failure', () => {
    it('buffers signals when write fails', async () => {
      const error = new Error('Connection refused');
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(error);

      const signals = [createTestSignal()];
      const result = await buffer.insertSignalEvents(signals);

      expect(result).toBe(false);
      expect(buffer.getStats().bufferedCount).toBe(1);
    });

    it('buffers campaign events when write fails', async () => {
      (clickhouse.insertCampaignEvent as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Timeout')
      );

      const event: CampaignHistoryRow = {
        timestamp: new Date().toISOString(),
        campaign_id: 'campaign-1',
        tenant_id: 'test-tenant',
        request_id: 'r1',
        event_type: 'created',
        name: 'Test Campaign',
        status: 'active',
        severity: 'HIGH',
        is_cross_tenant: 0,
        tenants_affected: 1,
        confidence: 0.9,
        metadata: '{}',
      };

      const result = await buffer.insertCampaignEvent(event);

      expect(result).toBe(false);
      expect(buffer.getStats().bufferedCount).toBe(1);
    });

    it('buffers blocklist events when write fails', async () => {
      (clickhouse.insertBlocklistEvents as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Timeout')
      );

      const result = await buffer.insertBlocklistEvents([createTestBlocklist()]);
      expect(result).toBe(false);
      expect(buffer.getStats().bufferedCount).toBe(1);
    });

    it('buffers HTTP transactions when write fails', async () => {
      (clickhouse.insertHttpTransactions as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Timeout')
      );

      const result = await buffer.insertHttpTransactions([createTestTxn()]);
      expect(result).toBe(false);
      expect(buffer.getStats().bufferedCount).toBe(1);
    });

    it('buffers log entries when write fails', async () => {
      (clickhouse.insertLogEntries as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
        new Error('Timeout')
      );

      const result = await buffer.insertLogEntries([createTestLog()]);
      expect(result).toBe(false);
      expect(buffer.getStats().bufferedCount).toBe(1);
    });
  });

  describe('retry logic', () => {
    it('retries buffered items after delay', async () => {
      const error = new Error('Connection refused');
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(error)
        .mockResolvedValueOnce(undefined);

      buffer.start();

      const signals = [createTestSignal()];
      await buffer.insertSignalEvents(signals);

      expect(buffer.getStats().bufferedCount).toBe(1);

      // Advance past initial delay and retry interval
      await vi.advanceTimersByTimeAsync(200);

      expect(buffer.getStats().bufferedCount).toBe(0);
      expect(buffer.getStats().successfulRetries).toBe(1);
    });

    it('uses exponential backoff for retries', async () => {
      // Keep failing
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Connection refused')
      );

      buffer.start();

      const signals = [createTestSignal()];
      await buffer.insertSignalEvents(signals);

      // Item buffered with attempts=1, nextRetryAt=100ms
      // Retry interval is 100ms

      // First retry at 100ms (initial delay)
      await vi.advanceTimersByTimeAsync(110);
      expect(buffer.getStats().totalAttempts).toBe(1);
      expect(buffer.getStats().failedRetries).toBe(1);
      // nextRetryAt now = 100 + 200 = 300ms (100 * 2^1)

      // Second retry at 300ms
      await vi.advanceTimersByTimeAsync(210);
      // Item dropped after attempts=3 (maxRetries=3)
      expect(buffer.getStats().totalAttempts).toBe(2);
      expect(buffer.getStats().droppedItems).toBe(1);
    });

    it('drops items after max retries', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Connection refused')
      );

      buffer.start();

      const signals = [createTestSignal()];
      await buffer.insertSignalEvents(signals);

      // Run through all retries
      await vi.advanceTimersByTimeAsync(2000);

      expect(buffer.getStats().bufferedCount).toBe(0);
      expect(buffer.getStats().droppedItems).toBe(1);
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ dlq: true, reason: 'max_retries_exceeded' }),
        expect.any(String)
      );
    });

    it('removes processed items during a batch to avoid evicting new failures', async () => {
      let signalCallCount = 0;
      let campaignCallCount = 0;
      let resolveCampaignRetry: (() => void) | null = null;
      let signalRetryStarted: (() => void) | null = null;

      const signalRetryStartedPromise = new Promise<void>((resolve) => {
        signalRetryStarted = resolve;
      });

      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        signalCallCount += 1;
        if (signalCallCount === 1) {
          throw new Error('fail');
        }
        if (signalCallCount === 2) {
          signalRetryStarted?.();
          return;
        }
        throw new Error('fail');
      });

      (clickhouse.insertCampaignEvent as ReturnType<typeof vi.fn>).mockImplementation(async () => {
        campaignCallCount += 1;
        if (campaignCallCount === 1) {
          throw new Error('fail');
        }
        return new Promise<void>((resolve) => {
          resolveCampaignRetry = resolve;
        });
      });

      buffer = new ClickHouseRetryBuffer(clickhouse, logger, {
        maxBufferSize: 2,
        retryIntervalMs: 50,
        initialDelayMs: 0,
        retryBatchSize: 2,
      });

      buffer.start();

      await buffer.insertSignalEvents([createTestSignal({ source_ip: '1.1.1.1' })]);
      await buffer.insertCampaignEvent({
        timestamp: new Date().toISOString(),
        campaign_id: 'campaign-1',
        tenant_id: 'test-tenant',
        request_id: 'r1',
        event_type: 'created',
        name: 'Test Campaign',
        status: 'active',
        severity: 'HIGH',
        is_cross_tenant: 0,
        tenants_affected: 1,
        confidence: 0.9,
        metadata: '{}',
      });

      expect(buffer.getStats().bufferedCount).toBe(2);

      await vi.advanceTimersByTimeAsync(50);
      await signalRetryStartedPromise;
      await Promise.resolve();

      expect(buffer.getStats().bufferedCount).toBe(1);

      await buffer.insertSignalEvents([createTestSignal({ source_ip: '2.2.2.2' })]);

      expect(buffer.getStats().bufferedCount).toBe(2);
      expect(buffer.getStats().droppedItems).toBe(0);

      resolveCampaignRetry?.();
      await Promise.resolve();
    });
  });

  describe('buffer capacity', () => {
    it('evicts oldest items when buffer is full', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('Connection refused')
      );

      // Create buffer with small capacity
      const smallBuffer = new ClickHouseRetryBuffer(clickhouse, logger, {
        maxBufferSize: 3,
        retryIntervalMs: 10000, // Long interval so no retries during test
      });

      // Fill buffer
      await smallBuffer.insertSignalEvents([createTestSignal({ source_ip: '1.1.1.1' })]);
      await smallBuffer.insertSignalEvents([createTestSignal({ source_ip: '2.2.2.2' })]);
      await smallBuffer.insertSignalEvents([createTestSignal({ source_ip: '3.3.3.3' })]);

      expect(smallBuffer.getStats().bufferedCount).toBe(3);

      // Add one more - should evict oldest
      await smallBuffer.insertSignalEvents([createTestSignal({ source_ip: '4.4.4.4' })]);

      expect(smallBuffer.getStats().bufferedCount).toBe(3);
      expect(smallBuffer.getStats().droppedItems).toBe(1);
      expect(logger.error).toHaveBeenCalledWith(
        expect.objectContaining({ dlq: true, reason: 'buffer_overflow' }),
        expect.any(String)
      );

      smallBuffer.stop();
    });
  });

  describe('statistics', () => {
    it('tracks all statistics correctly', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined);

      buffer.start();

      await buffer.insertSignalEvents([createTestSignal()]);

      let stats = buffer.getStats();
      expect(stats.bufferedCount).toBe(1);
      expect(stats.totalAttempts).toBe(0);
      expect(stats.successfulRetries).toBe(0);
      expect(stats.failedRetries).toBe(0);

      // Advance to trigger retry
      await vi.advanceTimersByTimeAsync(200);

      stats = buffer.getStats();
      expect(stats.bufferedCount).toBe(0);
      expect(stats.totalAttempts).toBe(1);
      expect(stats.successfulRetries).toBe(1);
      expect(stats.failedRetries).toBe(0);
    });

    it('calculates buffer utilization', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>).mockRejectedValue(
        new Error('fail')
      );

      await buffer.insertSignalEvents([createTestSignal()]);
      await buffer.insertSignalEvents([createTestSignal()]);

      const stats = buffer.getStats();
      expect(stats.bufferUtilization).toBe(0.02); // 2/100
    });

    it('resets statistics on resetStats', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined);

      buffer.start();
      await buffer.insertSignalEvents([createTestSignal()]);
      await vi.advanceTimersByTimeAsync(200);

      expect(buffer.getStats().successfulRetries).toBe(1);

      buffer.resetStats();

      expect(buffer.getStats().successfulRetries).toBe(0);
      expect(buffer.getStats().totalAttempts).toBe(0);
    });
  });

  describe('flush', () => {
    it('flushes all pending items', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(undefined);

      await buffer.insertSignalEvents([createTestSignal()]);
      await buffer.insertSignalEvents([createTestSignal()]);

      expect(buffer.getStats().bufferedCount).toBe(2);

      const result = await buffer.flush();

      expect(result.succeeded).toBe(2);
      expect(result.failed).toBe(0);
      expect(buffer.getStats().bufferedCount).toBe(0);
    });

    it('reports failed items during flush', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined)
        .mockRejectedValueOnce(new Error('still failing'));

      await buffer.insertSignalEvents([createTestSignal()]);
      await buffer.insertSignalEvents([createTestSignal()]);

      const result = await buffer.flush();

      expect(result.succeeded).toBe(1);
      expect(result.failed).toBe(1);
    });

    it('times out flush and reports remaining items as failed (labs-ykn9)', async () => {
      vi.useRealTimers();

      const slowClickhouse = createMockClickhouse();
      const slowLogger = createMockLogger();
      const slowBuffer = new ClickHouseRetryBuffer(slowClickhouse, slowLogger, {
        retryIntervalMs: 100000, // Long interval so no background retries
      });

      // First call fails (to buffer), second call hangs forever (to simulate timeout)
      (slowClickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'))
        .mockImplementationOnce(() => new Promise(() => {})); // Never resolves

      await slowBuffer.insertSignalEvents([createTestSignal()]);
      await slowBuffer.insertSignalEvents([createTestSignal()]);

      expect(slowBuffer.getStats().bufferedCount).toBe(2);

      // Flush with a short timeout
      const result = await slowBuffer.flush(100);

      // One should hang (timed out), the buffer should be cleared
      expect(result.succeeded + result.failed).toBe(2);
      expect(result.failed).toBeGreaterThanOrEqual(1);
      expect(slowBuffer.getStats().bufferedCount).toBe(0);

      vi.useFakeTimers();
    });

    it('can start again after flush() and process retries', async () => {
      (clickhouse.insertSignalEvents as ReturnType<typeof vi.fn>)
        .mockRejectedValueOnce(new Error('fail-1')) // insert buffers
        .mockResolvedValueOnce(undefined) // flush succeeds
        .mockRejectedValueOnce(new Error('fail-2')) // insert buffers again after restart
        .mockResolvedValueOnce(undefined); // retry succeeds

      await buffer.start();
      await buffer.insertSignalEvents([createTestSignal({ request_id: 'r1' })]);
      expect(buffer.getBufferSize()).toBe(1);

      await buffer.flush();
      expect(buffer.getBufferSize()).toBe(0);

      await buffer.start();
      await buffer.insertSignalEvents([createTestSignal({ request_id: 'r2' })]);
      expect(buffer.getBufferSize()).toBe(1);

      await vi.advanceTimersByTimeAsync(200);
      await Promise.resolve();

      expect(buffer.getBufferSize()).toBe(0);
      expect(clickhouse.insertSignalEvents).toHaveBeenCalledTimes(4);
    });

    it('returns immediately when buffer is empty', async () => {
      expect(buffer.getStats().bufferedCount).toBe(0);

      const result = await buffer.flush();

      expect(result.succeeded).toBe(0);
      expect(result.failed).toBe(0);
    });
  });

  describe('isEnabled', () => {
    it('delegates to underlying ClickHouse service', () => {
      expect(buffer.isEnabled()).toBe(true);

      (clickhouse.isEnabled as ReturnType<typeof vi.fn>).mockReturnValue(false);
      expect(buffer.isEnabled()).toBe(false);
    });
  });

  describe('empty operations', () => {
    it('handles empty signal arrays', async () => {
      const result = await buffer.insertSignalEvents([]);
      expect(result).toBe(true);
      expect(clickhouse.insertSignalEvents).not.toHaveBeenCalled();
    });

    it('handles empty blocklist arrays', async () => {
      const result = await buffer.insertBlocklistEvents([]);
      expect(result).toBe(true);
      expect(clickhouse.insertBlocklistEvents).not.toHaveBeenCalled();
    });

    it('handles empty transaction arrays', async () => {
      const result = await buffer.insertHttpTransactions([]);
      expect(result).toBe(true);
      expect(clickhouse.insertHttpTransactions).not.toHaveBeenCalled();
    });

    it('handles empty log arrays', async () => {
      const result = await buffer.insertLogEntries([]);
      expect(result).toBe(true);
      expect(clickhouse.insertLogEntries).not.toHaveBeenCalled();
    });
  });
});
