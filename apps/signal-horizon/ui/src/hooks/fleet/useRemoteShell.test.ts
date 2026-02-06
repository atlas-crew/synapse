import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

const terminalInstances: Array<{
  write: ReturnType<typeof vi.fn>;
  writeln: ReturnType<typeof vi.fn>;
  onData: ReturnType<typeof vi.fn>;
  loadAddon: ReturnType<typeof vi.fn>;
  open: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
}> = [];

vi.mock('@xterm/xterm', () => {
  const Terminal = vi.fn().mockImplementation(() => {
    const instance = {
      write: vi.fn(),
      writeln: vi.fn(),
      onData: vi.fn().mockReturnValue({ dispose: vi.fn() }),
      loadAddon: vi.fn(),
      open: vi.fn(),
      dispose: vi.fn(),
      focus: vi.fn(),
      options: {},
    };
    terminalInstances.push(instance);
    return instance;
  });
  return { Terminal };
});

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: vi.fn().mockImplementation(() => ({
    fit: vi.fn(),
    proposeDimensions: vi.fn().mockReturnValue({ cols: 80, rows: 24 }),
    dispose: vi.fn(),
  })),
}));

vi.mock('@xterm/addon-web-links', () => ({
  WebLinksAddon: vi.fn().mockImplementation(() => ({
    dispose: vi.fn(),
  })),
}));

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

  simulateMessage(data: string): void {
    this.onmessage?.({ data } as MessageEvent);
  }
}

let originalWebSocket: typeof WebSocket;
let originalFetch: typeof fetch;
let originalRaf: typeof requestAnimationFrame;
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
    terminalInstances.length = 0;

    originalWebSocket = globalThis.WebSocket;
    originalFetch = globalThis.fetch;
    originalRaf = globalThis.requestAnimationFrame;

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
    globalThis.requestAnimationFrame = ((cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    }) as typeof requestAnimationFrame;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    globalThis.fetch = originalFetch;
    globalThis.requestAnimationFrame = originalRaf;
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
    // labs-c4hh: URL is now a fixed tunnel endpoint (no session token in URL)
    expect(mockWebSocketInstances[1].url).toContain('/ws/tunnel/user');
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
    // labs-c4hh: URL is now a fixed tunnel endpoint (no session token in URL)
    expect(mockWebSocketInstances[1].url).toContain('/ws/tunnel/user');
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
      // labs-c4hh: URL is now a fixed tunnel endpoint (no session token in URL)
      expect(mockWebSocketInstances[1].url).toContain('/ws/tunnel/user');
    } finally {
      vi.useRealTimers();
    }
  });

  it('sets error when session creation fails', async () => {
    const onError = vi.fn();

    mockFetch.mockResolvedValueOnce({
      ok: false,
      text: async () => 'service unavailable',
    });

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onError,
        webSocketFactory: (url: string) => {
          const instance = new MockWebSocket(url);
          mockWebSocketInstances.push(instance);
          return instance as unknown as WebSocket;
        },
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    expect(result.current.status).toBe('error');
    expect(result.current.error).toBe('service unavailable');
    expect(onError).toHaveBeenCalledWith('service unavailable');
  });

  it('writes raw output when message is not JSON (after auth)', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
    });

    const webSocketFactory = (url: string) => {
      const instance = new MockWebSocket(url);
      mockWebSocketInstances.push(instance);
      return instance as unknown as WebSocket;
    };

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onError: vi.fn(),
        webSocketFactory,
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    const terminal = terminalInstances[0];
    expect(terminal).toBeDefined();

    // labs-c4hh: Authenticate first via first-message auth
    await act(async () => {
      mockWebSocketInstances[0].simulateMessage(JSON.stringify({ type: 'auth-success', sessionId: 'session-1' }));
      await flushAllPromises();
    });

    await act(async () => {
      mockWebSocketInstances[0].simulateMessage('raw-output');
      await flushAllPromises();
    });

    expect(terminal.write).toHaveBeenCalledWith('raw-output');
  });

  it('ignores raw output before auth is confirmed', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
    });

    const webSocketFactory = (url: string) => {
      const instance = new MockWebSocket(url);
      mockWebSocketInstances.push(instance);
      return instance as unknown as WebSocket;
    };

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onError: vi.fn(),
        webSocketFactory,
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    const terminal = terminalInstances[0];
    expect(terminal).toBeDefined();

    // Send raw output without authenticating first
    await act(async () => {
      mockWebSocketInstances[0].simulateMessage('raw-output');
      await flushAllPromises();
    });

    // Should NOT write to terminal before auth
    expect(terminal.write).not.toHaveBeenCalled();
  });

  it('drops output when payload exceeds buffer limit', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ sessionId: 'session-1', wsUrl: '/ws-1' }),
    });

    const webSocketFactory = (url: string) => {
      const instance = new MockWebSocket(url);
      mockWebSocketInstances.push(instance);
      return instance as unknown as WebSocket;
    };

    const { result } = renderHook(() =>
      useRemoteShell({
        sensorId: 'sensor-1',
        onError: vi.fn(),
        webSocketFactory,
      })
    );

    await act(async () => {
      result.current.connect();
    });

    await act(async () => {
      await flushAllPromises();
    });

    // labs-c4hh: Authenticate first
    await act(async () => {
      mockWebSocketInstances[0].simulateMessage(JSON.stringify({ type: 'auth-success', sessionId: 'session-1' }));
      await flushAllPromises();
    });

    const terminal = terminalInstances[0];
    const bigPayload = 'a'.repeat(1024 * 1024 + 1);
    const encoded = btoa(bigPayload);

    const message = JSON.stringify({
      type: 'shell-data',
      payload: { data: encoded },
    });

    await act(async () => {
      mockWebSocketInstances[0].simulateMessage(message);
      await flushAllPromises();
    });

    expect(terminal.write).not.toHaveBeenCalled();
  });
});
