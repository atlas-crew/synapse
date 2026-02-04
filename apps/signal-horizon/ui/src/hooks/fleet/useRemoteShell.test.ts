import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useRemoteShell } from './useRemoteShell';

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
  onerror: ((event: Event) => void) | null = null;
  lastCloseEvent: CloseEvent | null = null;
  private oncloseHandler: ((event: CloseEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  get onclose(): ((event: CloseEvent) => void) | null {
    return this.oncloseHandler;
  }

  set onclose(handler: ((event: CloseEvent) => void) | null) {
    this.oncloseHandler = (event) => {
      this.lastCloseEvent = event;
      handler?.(event);
    };
  }

  send(): void {}

  close(code = 1000, reason = 'cleanup'): void {
    this.readyState = MockWebSocket.CLOSED;
    this.oncloseHandler?.({ code, reason } as CloseEvent);
  }

  simulateClose(code = 1006, reason = 'abnormal'): void {
    this.readyState = MockWebSocket.CLOSED;
    this.oncloseHandler?.({ code, reason } as CloseEvent);
  }
}

let originalWebSocket: typeof WebSocket;
let originalFetch: typeof fetch;
let mockWebSocketInstances: MockWebSocket[] = [];

const flushPromises = () => new Promise<void>((resolve) => queueMicrotask(resolve));
const flushAllPromises = async (count = 4) => {
  for (let i = 0; i < count; i += 1) {
    await flushPromises();
  }
};

describe('useRemoteShell reconnect', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWebSocketInstances = [];

    originalWebSocket = globalThis.WebSocket;
    originalFetch = globalThis.fetch;

    const PlaceholderWebSocket = Object.assign(
      class {} as unknown as typeof WebSocket,
      {
        CONNECTING: 0 as const,
        OPEN: 1 as const,
        CLOSING: 2 as const,
        CLOSED: 3 as const,
      }
    );

    globalThis.WebSocket = PlaceholderWebSocket;
    globalThis.fetch = mockFetch as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    globalThis.fetch = originalFetch;
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

    const webSocketFactory = (url: string) => {
      const instance = new MockWebSocket(url);
      mockWebSocketInstances.push(instance);
      return instance as unknown as WebSocket;
    };

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onData: vi.fn(),
        webSocketFactory,
        reconnectOptions: { baseDelay: 10, maxDelay: 10 },
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockWebSocketInstances).toHaveLength(1);

    await act(async () => {
      mockWebSocketInstances[0].simulateClose(4000, 'abnormal');
    });

    await act(async () => {
      await flushAllPromises();
    });

    expect(mockWebSocketInstances[0].lastCloseEvent?.code).toBe(4000);
    expect(result.current.status).toBe('connecting');
    expect(result.current.isReconnecting).toBe(true);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      await flushAllPromises();
    });

    expect(mockWebSocketInstances).toHaveLength(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockWebSocketInstances[1].url).toContain('/ws-2');
  });

  it('reconnects after a clean close when not manually disconnected', async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sessionId: 'session-2', wsUrl: '/ws-2' }),
      });

    const webSocketFactory = (url: string) => {
      const instance = new MockWebSocket(url);
      mockWebSocketInstances.push(instance);
      return instance as unknown as WebSocket;
    };

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onData: vi.fn(),
        webSocketFactory,
        reconnectOptions: { baseDelay: 10, maxDelay: 10 },
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(mockWebSocketInstances).toHaveLength(1);

    await act(async () => {
      mockWebSocketInstances[0].simulateClose(1000, 'server shutdown');
    });

    await act(async () => {
      await flushAllPromises();
    });

    expect(result.current.status).toBe('connecting');
    expect(result.current.isReconnecting).toBe(true);

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      await flushAllPromises();
    });

    expect(mockWebSocketInstances).toHaveLength(2);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(mockWebSocketInstances[1].url).toContain('/ws-2');
  });

  it('retries session creation during reconnect until it succeeds', async () => {
    vi.useFakeTimers();

    try {
      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          text: async () => 'service unavailable',
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ sessionId: 'session-2', wsUrl: '/ws-2' }),
        });

      const webSocketFactory = (url: string) => {
        const instance = new MockWebSocket(url);
        mockWebSocketInstances.push(instance);
        return instance as unknown as WebSocket;
      };

      const { result } = renderHook(() =>
        useRemoteShell({
          sensorId: 'sensor-1',
          onData: vi.fn(),
          webSocketFactory,
          reconnectOptions: { baseDelay: 5, maxDelay: 5 },
        })
      );

      await act(async () => {
        result.current.connect();
      });

      await act(async () => {
        await flushAllPromises();
      });

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(mockWebSocketInstances).toHaveLength(1);

      await act(async () => {
        mockWebSocketInstances[0].simulateClose(4000, 'abnormal');
      });

      await act(async () => {
        await flushAllPromises();
      });

      expect(result.current.status).toBe('connecting');
      expect(result.current.isReconnecting).toBe(true);

      await act(async () => {
        vi.advanceTimersByTime(5);
        await flushAllPromises();
      });

      expect(mockFetch).toHaveBeenCalledTimes(2);
      expect(mockWebSocketInstances).toHaveLength(1);

      await act(async () => {
        vi.advanceTimersByTime(5);
        await flushAllPromises();
      });

      expect(mockFetch).toHaveBeenCalledTimes(3);
      expect(mockWebSocketInstances).toHaveLength(2);
      expect(mockWebSocketInstances[1].url).toContain('/ws-2');
    } finally {
      vi.useRealTimers();
    }
  });
});
