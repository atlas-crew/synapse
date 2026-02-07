import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';

const mockFetch = vi.fn();

describe('useHunt.getRequestTimeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = mockFetch;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('calls /hunt/request/:requestId and returns parsed events', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        success: true,
        data: [
          {
            kind: 'http_transaction',
            timestamp: '2026-02-06T17:00:00.000Z',
            tenantId: 'tenant-1',
            sensorId: 'sensor-1',
            requestId: 'req_123',
            site: 'example.com',
            method: 'GET',
            path: '/health',
            statusCode: 200,
            latencyMs: 12,
            wafAction: null,
          },
        ],
        meta: {
          requestId: 'req_123',
          tenantId: 'tenant-1',
          count: 1,
        },
      }),
    });

    const { useHunt } = await import('./useHunt');
    const { result } = renderHook(() => useHunt());

    let res: Awaited<ReturnType<typeof result.current.getRequestTimeline>> | undefined;
    await act(async () => {
      res = await result.current.getRequestTimeline('req_123', { limit: 25 });
    });

    expect(mockFetch).toHaveBeenCalled();
    const [url, options] = mockFetch.mock.calls[0] as [string, RequestInit | undefined];
    expect(url).toContain('/api/v1/hunt/request/req_123?limit=25');
    expect(options?.credentials).toBe('include');
    expect((options?.headers as Record<string, string> | undefined)?.['X-API-Key']).toBeUndefined();

    expect(res?.meta).toMatchObject({ requestId: 'req_123', count: 1 });
    expect(res?.events[0]).toMatchObject({ kind: 'http_transaction', requestId: 'req_123' });
  });
});
