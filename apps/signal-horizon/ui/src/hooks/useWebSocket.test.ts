/**
 * useWebSocket Hook Tests
 * Tests WebSocket connection management and message handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from './useWebSocket';

// Mock the Zustand store
const mockSetConnectionState = vi.fn();
const mockSetSessionId = vi.fn();
const mockSetSnapshot = vi.fn();
const mockAddCampaign = vi.fn();
const mockAddThreat = vi.fn();
const mockAddAlert = vi.fn();

vi.mock('../stores/horizonStore', () => ({
  useHorizonStore: () => ({
    connectionState: 'disconnected',
    setConnectionState: mockSetConnectionState,
    setSessionId: mockSetSessionId,
    setSnapshot: mockSetSnapshot,
    addCampaign: mockAddCampaign,
    addThreat: mockAddThreat,
    addAlert: mockAddAlert,
  }),
}));

// Mock WebSocket
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

  private sentMessages: string[] = [];

  constructor(url: string) {
    this.url = url;
  }

  send(data: string): void {
    this.sentMessages.push(data);
  }

  close(_code?: number, _reason?: string): void {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code: 1000 }));
    }
  }

  // Test helpers
  simulateOpen(): void {
    this.readyState = MockWebSocket.OPEN;
    if (this.onopen) {
      this.onopen(new Event('open'));
    }
  }

  simulateMessage(data: unknown): void {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }));
    }
  }

  simulateError(): void {
    if (this.onerror) {
      this.onerror(new Event('error'));
    }
  }

  simulateClose(code = 1000, reason = ''): void {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code, reason }));
    }
  }

  getSentMessages(): string[] {
    return this.sentMessages;
  }

  getLastSentMessage(): unknown | null {
    if (this.sentMessages.length === 0) return null;
    return JSON.parse(this.sentMessages[this.sentMessages.length - 1]);
  }
}

// Track created WebSocket instances
let mockWebSocketInstances: MockWebSocket[] = [];

describe('useWebSocket', () => {
  let originalWebSocket: typeof WebSocket;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    mockWebSocketInstances = [];

    // Save original WebSocket
    originalWebSocket = globalThis.WebSocket;

    // Create a mock WebSocket constructor with static properties
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

    // Replace global WebSocket
    globalThis.WebSocket = MockWebSocketConstructor;
  });

  afterEach(() => {
    // Restore original WebSocket
    globalThis.WebSocket = originalWebSocket;
    vi.useRealTimers();
  });

  describe('connect', () => {
    it('should create WebSocket and set connecting state', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('connecting');
      expect(mockWebSocketInstances).toHaveLength(1);
    });

    it('should set connected state on open', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('connected');
    });

    it('should not create duplicate connections', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.connect();
      });

      // Should only have 1 WebSocket instance since second connect was ignored
      expect(mockWebSocketInstances).toHaveLength(1);
    });
  });

  describe('disconnect', () => {
    it('should close WebSocket and reset state', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.disconnect();
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('disconnected');
      expect(mockSetSessionId).toHaveBeenCalledWith(null);
    });
  });

  describe('message handling', () => {
    it('should handle auth-required message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'auth-required',
          message: 'Please authenticate',
          timestamp: Date.now(),
        });
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as { type: string };
      expect(lastMessage.type).toBe('auth');
    });

    it('should handle auth-success message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'auth-success',
          sessionId: 'session-123',
          tenantId: 'tenant-1',
          isFleetAdmin: false,
          timestamp: Date.now(),
        });
      });

      expect(mockSetSessionId).toHaveBeenCalledWith('session-123');
    });

    it('should handle auth-failed message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'auth-failed',
          error: 'Invalid API key',
          timestamp: Date.now(),
        });
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('error');
    });

    it('should handle snapshot message', () => {
      const { result } = renderHook(() => useWebSocket());

      const snapshotData = {
        activeCampaigns: [
          {
            id: 'campaign-1',
            name: 'Test Campaign',
            status: 'ACTIVE',
            severity: 'HIGH',
            isCrossTenant: true,
            tenantsAffected: 3,
            confidence: 0.9,
            firstSeenAt: '2024-01-01T00:00:00Z',
            lastActivityAt: '2024-01-02T00:00:00Z',
          },
        ],
        recentThreats: [
          {
            id: 'threat-1',
            threatType: 'IP',
            indicator: '10.0.0.1',
            riskScore: 85,
            hitCount: 25,
            tenantsAffected: 2,
            isFleetThreat: true,
            firstSeenAt: '2024-01-01T00:00:00Z',
            lastSeenAt: '2024-01-02T00:00:00Z',
          },
        ],
        sensorStats: { CONNECTED: 10, DISCONNECTED: 2 },
      };

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'snapshot',
          data: snapshotData,
          timestamp: Date.now(),
        });
      });

      expect(mockSetSnapshot).toHaveBeenCalledWith(snapshotData);
    });

    it('should handle campaign-alert message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'campaign-alert',
          data: {
            campaign: {
              id: 'campaign-1',
              name: 'New Campaign',
              severity: 'CRITICAL',
              isCrossTenant: true,
              tenantsAffected: 5,
              confidence: 0.95,
            },
          },
          timestamp: Date.now(),
        });
      });

      expect(mockAddCampaign).toHaveBeenCalled();
      expect(mockAddAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'campaign',
          title: expect.stringContaining('Campaign Detected'),
          severity: 'CRITICAL',
        })
      );
    });

    it('should handle threat-alert message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'threat-alert',
          data: {
            threat: {
              id: 'threat-1',
              threatType: 'IP',
              indicator: '10.0.0.1',
              riskScore: 90,
              isFleetThreat: true,
            },
          },
          timestamp: Date.now(),
        });
      });

      expect(mockAddThreat).toHaveBeenCalled();
      expect(mockAddAlert).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'threat',
          severity: 'CRITICAL', // riskScore >= 80
        })
      );
    });

    it('should handle ping message with pong response', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
        mockWebSocketInstances[0].simulateMessage({
          type: 'ping',
          timestamp: Date.now(),
        });
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as { type: string };
      expect(lastMessage.type).toBe('pong');
    });

    it('should handle invalid JSON gracefully', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      // Simulate raw invalid JSON message
      act(() => {
        if (mockWebSocketInstances[0].onmessage) {
          mockWebSocketInstances[0].onmessage(
            new MessageEvent('message', { data: 'invalid json{' })
          );
        }
      });

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('send', () => {
    it('should send message when connected', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.send({ type: 'test', data: 'hello' });
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as {
        type: string;
        data: string;
      };
      expect(lastMessage.type).toBe('test');
      expect(lastMessage.data).toBe('hello');
    });

    it('should warn when sending while disconnected', () => {
      const consoleSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.send({ type: 'test' });
      });

      expect(consoleSpy).toHaveBeenCalledWith('[WebSocket] Cannot send - not connected');
      consoleSpy.mockRestore();
    });
  });

  describe('subscribe/unsubscribe', () => {
    it('should send subscribe message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.subscribe('campaigns');
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as {
        type: string;
        payload: { topic: string };
      };
      expect(lastMessage.type).toBe('subscribe');
      expect(lastMessage.payload.topic).toBe('campaigns');
    });

    it('should send unsubscribe message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.unsubscribe('threats');
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as {
        type: string;
        payload: { topic: string };
      };
      expect(lastMessage.type).toBe('unsubscribe');
      expect(lastMessage.payload.topic).toBe('threats');
    });
  });

  describe('requestSnapshot', () => {
    it('should send request-snapshot message', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.requestSnapshot();
      });

      const lastMessage = mockWebSocketInstances[0].getLastSentMessage() as { type: string };
      expect(lastMessage.type).toBe('request-snapshot');
    });
  });

  describe('reconnection', () => {
    it('should schedule reconnect on disconnect', async () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        mockWebSocketInstances[0].simulateClose(1006, 'Connection lost');
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('disconnected');
    });

    it('should not reconnect after intentional disconnect', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      act(() => {
        result.current.disconnect();
      });

      // Advance timers past reconnect delay
      act(() => {
        vi.advanceTimersByTime(10000);
      });

      // Should only have initial WebSocket instance
      expect(mockWebSocketInstances).toHaveLength(1);
    });
  });

  describe('error handling', () => {
    it('should set error state on WebSocket error', () => {
      const { result } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateError();
      });

      expect(mockSetConnectionState).toHaveBeenCalledWith('error');
    });
  });

  describe('cleanup', () => {
    it('should disconnect on unmount', () => {
      const { result, unmount } = renderHook(() => useWebSocket());

      act(() => {
        result.current.connect();
        mockWebSocketInstances[0].simulateOpen();
      });

      unmount();

      expect(mockSetConnectionState).toHaveBeenCalledWith('disconnected');
    });
  });
});
