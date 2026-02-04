/**
 * SynapseProxyService Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'node:events';
import type { Logger } from 'pino';
import { SynapseProxyService, SynapseProxyError, SensorError, type SynapseStatus } from './synapse-proxy.js';
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

  it('fails when tunnel cannot send request', async () => {
    broker.sendToSensor.mockReturnValue(false);

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'SEND_FAILED' });
  });

  it('handles sendToSensor exceptions without leaking pending requests', async () => {
    broker.sendToSensor.mockImplementation(() => {
      throw new Error('network down');
    });

    await expect(
      service.proxyRequest('sensor-1', 'tenant-1', '/_sensor/status')
    ).rejects.toMatchObject({ code: 'SEND_FAILED' });

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

    it('getPayloadStats fetches and caches results', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe('/_sensor/payload/stats');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { ok: true } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const first = await service.getPayloadStats(sensorId, tenantId);
      const second = await service.getPayloadStats(sensorId, tenantId);

      expect(first).toEqual({ ok: true });
      expect(second).toEqual({ ok: true });
      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('listProfiles fetches and caches results', async () => {
      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe('/api/profiles');
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { profiles: [] } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const first = await service.listProfiles(sensorId, tenantId);
      const second = await service.listProfiles(sensorId, tenantId);

      expect(first).toEqual({ profiles: [] });
      expect(second).toEqual({ profiles: [] });
      expect(broker.sendToSensor).toHaveBeenCalledTimes(1);
    });

    it('getProfile encodes template path', async () => {
      const template = '/api/v1/users/{id}';
      const encoded = encodeURIComponent(template);

      broker.sendToSensor.mockImplementation((_id, message) => {
        expect(message.payload.endpoint).toBe(`/api/profiles/${encoded}`);
        const response: LegacyTunnelMessage = {
          type: 'dashboard-response',
          sessionId: message.sessionId!,
          payload: { status: 200, data: { template } },
          timestamp: new Date().toISOString(),
        };
        process.nextTick(() => broker.emit('tunnel:message', sensorId, response));
        return true;
      });

      const result = await service.getProfile(sensorId, tenantId, template);
      expect(result).toEqual({ template });
    });

    it('evaluateRequest performs POST', async () => {
      const evalData = { method: 'GET', path: '/', headers: {}, clientIp: '1.1.1.1' };
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

      const result = await service.evaluateRequest(sensorId, tenantId, evalData as any);
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
