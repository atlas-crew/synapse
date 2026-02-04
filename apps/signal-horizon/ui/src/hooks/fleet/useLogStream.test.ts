import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useLogStream } from './useLogStream';

const mockFetch = vi.fn();

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  url: string;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  send(): void {}

  close(code = 1000, reason = 'cleanup'): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.(new CloseEvent('close', { code, reason }));
  }

  simulateClose(code = 1006, reason = 'abnormal'): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.(new CloseEvent('close', { code, reason }));
  }
}

let originalWebSocket: typeof WebSocket;
let originalFetch: typeof fetch;
let mockWebSocketInstances: MockWebSocket[] = [];

const flushPromises = () => new Promise<void>((resolve) => queueMicrotask(resolve));
const flushAllPromises = async () => {
  await flushPromises();
  await flushPromises();
};

describe('useLogStream reconnect', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    mockWebSocketInstances = [];

    originalWebSocket = globalThis.WebSocket;
    originalFetch = globalThis.fetch;

    const MockWebSocketConstructor = Object.assign(
      function (this: MockWebSocket, url: string) {
        const instance = new MockWebSocket(url);
        mockWebSocketInstances.push(instance);
        return instance;
      },
      {
        CONNECTING: 0 as const,
        OPEN: 1 as const,
        CLOSING: 2 as const,
        CLOSED: 3 as const,
      }
    ) as unknown as typeof WebSocket;

    globalThis.WebSocket = MockWebSocketConstructor;
    globalThis.fetch = mockFetch as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    globalThis.fetch = originalFetch;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('creates a new session on reconnect after abnormal close', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessionId: 'session-2', wsUrl: '/ws-2' }),
      });

    const { result } = renderHook(() =>
      useLogStream({ sensorId: 'sensor-1' })
    );

    await act(async () => {
      result.current.connect();
      await flushAllPromises();
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockWebSocketInstances).toHaveLength(1);

    await act(async () => {
      mockWebSocketInstances[0].simulateClose(4000, 'abnormal');
      await flushAllPromises();
    });

    await act(async () => {
      vi.advanceTimersByTime(3000);
      await flushAllPromises();
    });

    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockWebSocketInstances).toHaveLength(2);
    expect(mockWebSocketInstances[1].url).toContain('/ws-2');
  });
});
