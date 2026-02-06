/**
 * SynapseProxyService Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { Logger } from 'pino';
import {
  SynapseProxyService,
  SynapseProxyError,
  SensorError,
  validateSensorUrl,
  backoffDelay,
  type SynapseStatus,
  type EvalRequest,
} from './synapse-proxy.js';
import type { TunnelBroker, LegacyTunnelMessage } from '../websocket/tunnel-broker.js';

class MockTunnelBroker extends EventEmitter implements Partial<TunnelBroker> {
  getTunnelStatus = vi.fn();
  getActiveTunnels = vi.fn().mockReturnValue([]);
  sendToSensor = vi.fn();
}

const createLogger = (): Logger => ({
  child: vi.fn().mockReturnThis(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger);

const createStatusPayload = (): SynapseStatus => ({
  version: '1.0.0',
  uptime: 120,
  status: 'healthy',
  cpu: 10,
  memory: 20,
  disk: 30,
  requestsPerSecond: 5,
  blockedRequests: 1,
  rulesLoaded: 10,
  entitiesTracked: 5,
  actorsActive: 2,
});

describe('SynapseProxyService', () => {
  let broker: MockTunnelBroker;
  let service: SynapseProxyService;

  beforeEach(() => {
    vi.useFakeTimers();
    broker = new MockTunnelBroker();
    broker.getTunnelStatus.mockReturnValue({ tenantId: 'tenant-1' });
    service = new SynapseProxyService(broker as unknown as TunnelBroker, createLogger());
  });

  afterEach(async () => {
    await service.shutdown();
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('rejects invalid sensor IDs', async () => {
    await expect(
      service.proxyRequest('invalid id', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'INVALID_SENSOR_ID' });
  });

  it('blocks path traversal in endpoints', async () => {
    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/../_sensor/status')
    ).rejects.toMatchObject({ code: 'INVALID_ENDPOINT' });
  });

  it('blocks encoded path traversal in endpoints', async () => {
    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/%2e%2e/_sensor/status')
    ).rejects.toMatchObject({ code: 'INVALID_ENDPOINT' });
  });

  it('blocks null bytes in endpoints', async () => {
    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status\0/etc/passwd')
    ).rejects.toMatchObject({ code: 'INVALID_ENDPOINT' });
  });

  it('blocks absolute URLs in endpoints', async () => {
    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', 'http://evil.com/_sensor/status')
    ).rejects.toMatchObject({ code: 'INVALID_ENDPOINT' });
  });

  it('blocks non-allowlisted endpoints', async () => {
    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/unknown')
    ).rejects.toMatchObject({ code: 'ENDPOINT_NOT_ALLOWED' });
  });

  it('enforces tenant isolation', async () => {
    broker.getTunnelStatus.mockReturnValue({ tenantId: 'tenant-2' });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('resolves proxy requests from tunnel responses', async () => {
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 200,
            data: { ok: true },
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).resolves.toEqual({ ok: true });
  });

  it('forwards headers in proxy requests', async () => {
    const headers = { 'x-test': '1', 'x-trace': 'abc' };
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      expect(message.payload.headers).toEqual(headers);
      const response: LegacyTunnelMessage = {
        type: 'dashboard-response',
        sessionId: message.sessionId!,
        payload: { status: 200, data: { ok: true } },
        timestamp: new Date().toISOString(),
      };
      process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
      return true;
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status', 'GET', undefined, headers)
    ).resolves.toEqual({ ok: true });
  });

  it('caches status responses and clears cache by sensor', async () => {
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 200,
            data: createStatusPayload(),
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    const first = await service.getSensorStatus('sensor-1', 'tenant-1');
    const second = await service.getSensorStatus('sensor-1', 'tenant-1');

    expect(first).toEqual(second);
    expect(broker.sendToSensor).toHaveBeenCalledTimes(1);

    service.clearSensorCache('sensor-1');

    await service.getSensorStatus('sensor-1', 'tenant-1');
    expect(broker.sendToSensor).toHaveBeenCalledTimes(2);
  });

  it('fails when tunnel cannot send request (after retries)', async () => {
    broker.sendToSensor.mockReturnValue(false);

    const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

    // Advance through all retry backoff delays (3 retries)
    // Retry 0: ~1s, Retry 1: ~2s, Retry 2: ~4s
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(3000);
    await vi.advanceTimersByTimeAsync(6000);

    await expect(request).rejects.toMatchObject({ code: 'SEND_FAILED' });
  });

  it('handles sendToSensor exceptions without leaking pending requests', async () => {
    broker.sendToSensor.mockImplementation(() => {
      throw new Error('network down');
    });

    const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

    // Advance through all retry backoff delays
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(3000);
    await vi.advanceTimersByTimeAsync(6000);

    await expect(request).rejects.toMatchObject({ code: 'SEND_FAILED' });

    const stats = service.getStats();
    expect(stats.pendingRequests).toBe(0);
  });

  it('marks sensor errors as non-retryable', async () => {
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 500,
            error: 'Sensor failure',
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'SENSOR_ERROR' });
  });

  it('rejects HTTP errors from sensor responses', async () => {
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 404,
            data: { error: 'Not found' },
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'HTTP_ERROR', status: 404 });
  });

  it('rejects HTTP errors without sensor error field', async () => {
    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 503,
            data: { message: 'Service unavailable' },
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'HTTP_ERROR', status: 503 });
  });

  it('wraps sensor problem details in SensorError', async () => {
    const problem = {
      type: 'about:blank',
      title: 'Bad Request',
      status: 400,
      detail: 'Invalid filter',
    };

    broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
      if (message.type === 'dashboard-request' && message.sessionId) {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId,
          payload: {
            status: 400,
            data: problem,
          },
          timestamp: new Date().toISOString(),
        };
        broker.emit('tunnel:message', sensorId, response);
      }
      return true;
    });

    let caught: unknown;
    try {
      await service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');
    } catch (error) {
      caught = error;
    }

    expect(caught).toBeInstanceOf(SensorError);
    expect((caught as SensorError).sensorProblem).toEqual(problem);
    expect((caught as SensorError).sensorId).toBe('sensor-1');
  });

  it('rejects invalid endpoints before tunnel access', async () => {
    broker.getTunnelStatus.mockReturnValue(null);

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'TUNNEL_NOT_FOUND' });
  });

  it('reports structured error metadata', async () => {
    try {
      await service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/unknown');
    } catch (error) {
      const proxyError = error as SynapseProxyError;
      const serialized = proxyError.toJSON();
      expect(serialized.code).toBe('ENDPOINT_NOT_ALLOWED');
      expect(serialized.retryable).toBe(false);
    }
  });

  describe('Concurrency and Timeouts', () => {
    it('enforces concurrency limits', async () => {
      // Set up broker to never respond
      broker.sendToSensor.mockReturnValue(true);

      const requests: Promise<unknown>[] = [];
      // MAX_CONCURRENT_REQUESTS is 20
      for (let i = 0; i < 25; i++) {
        // Catch rejections to avoid unhandled errors on shutdown
        requests.push(service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status').catch(() => {}));
      }

      // Let the first 20 acquire the semaphore and call executeRequest
      await vi.advanceTimersByTimeAsync(0);

      const stats = service.getStats();
      expect(stats.concurrentRequestsAvailable).toBe(0);
      expect(stats.concurrentRequestsQueued).toBe(5);
      expect(stats.pendingRequests).toBe(20);
    });

    it('enforces request timeouts', async () => {
      broker.sendToSensor.mockReturnValue(true);

      const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

      // Let acquire() settle
      await vi.advanceTimersByTimeAsync(0);

      // Advance time by 30 seconds
      vi.advanceTimersByTime(30001);

      await expect(request).rejects.toMatchObject({ code: 'TIMEOUT' });
    });

    it('reports accurate statistics', async () => {
      broker.sendToSensor.mockReturnValue(true);
      
      // 1 successful request
      broker.sendToSensor.mockImplementationOnce((sensorId, message) => {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { ok: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');
      
      const stats = service.getStats();
      expect(stats.totalRequests).toBe(1);
      expect(stats.concurrentRequestsAvailable).toBe(20);
    });
  });

  describe('High-Level Methods', () => {
    const sensorId = 'sensor-1';
    const tenantId = 'tenant-1';

    it('getSensorStatus uses cache', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: createStatusPayload() },
          timestamp: new Date().toISOString(),
        };
        // Emit in next tick to avoid synchronous resolution
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.getSensorStatus(sensorId, tenantId);
      await service.getSensorStatus(sensorId, tenantId);

      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('getSensorConfigSection fetches correctly', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe('/_sensor/config/dlp');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { enabled: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const config = await service.getSensorConfigSection(sensorId, tenantId, 'dlp');
      expect(config).toEqual({ enabled: true });
    });

    it('updateSensorConfig forwards PUT body', async () => {
      const updatePayload = { enabled: false };
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.method).toBe('PUT');
        expect(message.payload.body).toEqual(updatePayload);
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { ok: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.updateSensorConfig(sensorId, tenantId, 'dlp', updatePayload);
    });

    it('updateSensorConfig invalidates cache', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { ok: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      // Populate cache
      await service.getSensorConfig(sensorId, tenantId);
      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);

      // Update config
      await service.updateSensorConfig(sensorId, tenantId, 'dlp', { enabled: false });
      
      // Request again, should hit broker
      await service.getSensorConfig(sensorId, tenantId);
      expect(broker.sendToSensor).toHaveBeenCalledTimes(3);
    });

    it('listEntities supports query parameters', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toContain('type=IP');
        expect(message.payload.endpoint).toContain('limit=10');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { entities: [], total: 0 } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.listEntities(sensorId, tenantId, { type: 'IP', limit: 10 });
    });

    it('listBlocks builds query parameters', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toContain('/_sensor/blocks?');
        expect(message.payload.endpoint).toContain('type=IP');
        expect(message.payload.endpoint).toContain('limit=5');
        expect(message.payload.endpoint).toContain('offset=10');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { blocks: [], total: 0 } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.listBlocks(sensorId, tenantId, { type: 'IP', limit: 5, offset: 10 });
    });

    it('getPayloadStats uses cache', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe('/_sensor/payload/stats');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: {
            status: 200,
            data: {
              success: true,
              data: {
                total_endpoints: 1,
                total_entities: 1,
                total_requests: 10,
                total_request_bytes: 100,
                total_response_bytes: 200,
                avg_request_size: 10,
                avg_response_size: 20,
                active_anomalies: 0,
              },
            },
          },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.getPayloadStats(sensorId, tenantId);
      await service.getPayloadStats(sensorId, tenantId);

      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('listProfiles caches responses', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe('/api/profiles');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: {
            status: 200,
            data: {
              success: true,
              data: {
                profiles: [],
                count: 0,
              },
            },
          },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.listProfiles(sensorId, tenantId);
      await service.listProfiles(sensorId, tenantId);

      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('getProfile encodes templates with slashes', async () => {
      const template = '/api/v1/users/:id';
      const encoded = encodeURIComponent(template);

      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe(`/api/profiles/${encoded}`);
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: {
            status: 200,
            data: {
              success: true,
              data: {
                template,
                sampleCount: 1,
                firstSeenMs: 1000,
                lastUpdatedMs: 2000,
                payloadSize: { mean: 1, variance: 0, stdDev: 0, count: 1 },
                expectedParams: [],
                contentTypes: [],
                statusCodes: [],
                endpointRisk: 0,
                requestRate: { currentRps: 0, windowMs: 60000 },
              },
            },
          },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      await service.getProfile(sensorId, tenantId, template);
    });

    it('evaluateRequest performs POST', async () => {
      const evalData: EvalRequest = {
        method: 'GET',
        path: '/',
        headers: {},
        clientIp: '1.1.1.1',
      };
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.method).toBe('POST');
        expect(message.payload.body).toEqual(evalData);
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { decision: 'allow' } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const result = await service.evaluateRequest(sensorId, tenantId, evalData);
      expect(result.decision).toBe('allow');
    });

    it('passes through binary response payloads', async () => {
      const binary = Buffer.from('binary-data');
      broker.sendToSensor.mockImplementation((_id, message) => {
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: binary },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const result = await service.proxyRequest<Buffer>(sensorId, tenantId, '/_sensor/status');
      expect(result).toEqual(binary);
    });
  });

  describe('Retry with Exponential Backoff', () => {
    it('retries retryable errors up to MAX_RETRIES times', async () => {
      let callCount = 0;
      broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
        callCount++;
        if (callCount <= 3) {
          // First 3 attempts: simulate timeout via no response
          // The timeout fires when we advance timers
          return true;
        }
        // 4th attempt: respond successfully
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { ok: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

      // Let the first executeRequest settle
      await vi.advanceTimersByTimeAsync(0);

      // Advance past the request timeout (30s) to trigger TIMEOUT on attempt 0
      await vi.advanceTimersByTimeAsync(30001);

      // Advance past backoff delay for retry 1 (~1s base + jitter)
      await vi.advanceTimersByTimeAsync(2000);

      // Advance past the request timeout for attempt 1
      await vi.advanceTimersByTimeAsync(30001);

      // Advance past backoff delay for retry 2 (~2s base + jitter)
      await vi.advanceTimersByTimeAsync(3000);

      // Advance past the request timeout for attempt 2
      await vi.advanceTimersByTimeAsync(30001);

      // Advance past backoff delay for retry 3 (~4s base + jitter)
      await vi.advanceTimersByTimeAsync(6000);

      // Attempt 3 should succeed (4th sendToSensor call)
      await vi.advanceTimersByTimeAsync(0);

      const result = await request;
      expect(result).toEqual({ ok: true });
      expect(callCount).toBe(4); // 1 initial + 3 retries
    });

    it('does not retry non-retryable errors', async () => {
      // SENSOR_ERROR is not retryable
      broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
        if (message.type === 'dashboard-request' && message.sessionId) {
          const response: LegacyTunnelMessage = {
            type: 'dashboard-response',
            sessionId: message.sessionId,
            payload: {
              status: 500,
              error: 'Sensor failure',
            },
            timestamp: new Date().toISOString(),
          };
          broker.emit('tunnel:message', sensorId, response);
        }
        return true;
      });

      await expect(
        service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
      ).rejects.toMatchObject({ code: 'SENSOR_ERROR' });

      // Should have only been called once (no retries)
      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('retries on SEND_FAILED then succeeds', async () => {
      let callCount = 0;
      broker.sendToSensor.mockImplementation((sensorId: string, message: LegacyTunnelMessage) => {
        callCount++;
        if (callCount === 1) {
          // First call fails
          return false;
        }
        // Second call succeeds
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { retried: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

      // Let first attempt settle and fail
      await vi.advanceTimersByTimeAsync(0);

      // Advance past backoff for first retry (~1s base + jitter)
      await vi.advanceTimersByTimeAsync(2000);

      // Let second attempt settle
      await vi.advanceTimersByTimeAsync(0);

      const result = await request;
      expect(result).toEqual({ retried: true });
      expect(callCount).toBe(2);
    });
  });

  describe('Lifecycle', () => {
    it('rejects pending requests on shutdown', async () => {
      broker.sendToSensor.mockReturnValue(true);

      const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

      // Let acquire() settle
      await vi.advanceTimersByTimeAsync(0);

      await service.shutdown();

      await expect(request).rejects.toMatchObject({ code: 'SHUTDOWN' });
    });

    it('rejects pending requests on sensor disconnect', async () => {
      broker.sendToSensor.mockReturnValue(true);

      const request = service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status');

      // Let acquire() settle
      await vi.advanceTimersByTimeAsync(0);

      broker.emit('tunnel:disconnected', 'sensor-1', 'tenant-1');

      await expect(request).rejects.toMatchObject({ code: 'SENSOR_DISCONNECTED' });
    });
  });
});

// ===========================================================================
// Standalone Unit Tests for SSRF URL Validation
// ===========================================================================

describe('validateSensorUrl', () => {
  it('accepts valid public http URLs', () => {
    expect(() => validateSensorUrl('http://sensor.example.com:6191')).not.toThrow();
    expect(() => validateSensorUrl('https://8.8.8.8:6191')).not.toThrow();
  });

  it('rejects non-http schemes', () => {
    expect(() => validateSensorUrl('ftp://sensor.example.com')).toThrow('only http and https');
    expect(() => validateSensorUrl('file:///etc/passwd')).toThrow('only http and https');
  });

  it('rejects localhost', () => {
    expect(() => validateSensorUrl('http://localhost:6191')).toThrow('blocked host');
  });

  it('rejects 0.0.0.0', () => {
    expect(() => validateSensorUrl('http://0.0.0.0:6191')).toThrow('blocked host');
  });

  it('rejects loopback IPs (127.x.x.x)', () => {
    expect(() => validateSensorUrl('http://127.0.0.1:6191')).toThrow('private or reserved');
    expect(() => validateSensorUrl('http://127.255.255.255:6191')).toThrow('private or reserved');
  });

  it('rejects private 10.x.x.x range', () => {
    expect(() => validateSensorUrl('http://10.0.0.1:6191')).toThrow('private or reserved');
    expect(() => validateSensorUrl('http://10.255.255.255:6191')).toThrow('private or reserved');
  });

  it('rejects private 172.16-31.x.x range', () => {
    expect(() => validateSensorUrl('http://172.16.0.1:6191')).toThrow('private or reserved');
    expect(() => validateSensorUrl('http://172.31.255.255:6191')).toThrow('private or reserved');
  });

  it('rejects private 192.168.x.x range', () => {
    expect(() => validateSensorUrl('http://192.168.1.1:6191')).toThrow('private or reserved');
  });

  it('rejects AWS metadata endpoint', () => {
    expect(() => validateSensorUrl('http://169.254.169.254/latest/meta-data')).toThrow();
  });

  it('rejects URLs with credentials', () => {
    expect(() => validateSensorUrl('http://user:pass@sensor.example.com:6191')).toThrow('credentials');
  });

  it('rejects ports outside valid range', () => {
    expect(() => validateSensorUrl('http://sensor.example.com:80')).toThrow('Invalid sensor port');
    expect(() => validateSensorUrl('http://sensor.example.com:0')).toThrow('Invalid sensor port');
  });

  it('rejects invalid URLs', () => {
    expect(() => validateSensorUrl('not a url')).toThrow('Invalid sensor URL');
  });
});

// ===========================================================================
// Standalone Unit Tests for Backoff Delay
// ===========================================================================

describe('backoffDelay', () => {
  it('returns increasing delays for increasing attempts', () => {
    const d0 = backoffDelay(0);
    const d1 = backoffDelay(1);
    const d2 = backoffDelay(2);

    // Base delays are 1000, 2000, 4000 plus up to 25% jitter
    expect(d0).toBeGreaterThanOrEqual(1000);
    expect(d0).toBeLessThanOrEqual(1250);

    expect(d1).toBeGreaterThanOrEqual(2000);
    expect(d1).toBeLessThanOrEqual(2500);

    expect(d2).toBeGreaterThanOrEqual(4000);
    expect(d2).toBeLessThanOrEqual(5000);
  });

  it('caps at 30 seconds', () => {
    const d10 = backoffDelay(10);
    // Max base is 30000 + up to 25% jitter = 37500
    expect(d10).toBeLessThanOrEqual(37500);
    expect(d10).toBeGreaterThanOrEqual(30000);
  });
});
