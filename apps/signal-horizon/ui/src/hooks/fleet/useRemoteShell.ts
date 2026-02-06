/**
 * useRemoteShell Hook
 * Manages WebSocket connection for remote shell sessions to sensors
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { Terminal, type ITerminalOptions } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import type {
  ShellSession,
  ShellSessionStatus,
  ShellMessage,
  ShellServerMessage,
  ShellInitOptions,
  ShellReconnectOptions,
} from '../../types/shell';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY = import.meta.env.VITE_API_KEY || import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

/**
 * Fetch a short-lived WebSocket ticket from the API (labs-n6nf).
 * The ticket is used to authenticate the WebSocket connection since
 * httpOnly cookies cannot be passed in WS handshakes.
 */
async function fetchWsTicket(): Promise<string | null> {
  try {
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (API_KEY && API_KEY !== 'dev-dashboard-key') {
      headers['Authorization'] = `Bearer ${API_KEY}`;
    }
    const res = await fetch(`${API_URL}/api/v1/auth/ws-ticket`, {
      headers,
      credentials: 'include',
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.ticket ?? null;
  } catch {
    return null;
  }
}

/** Default reconnection options */
const DEFAULT_RECONNECT_OPTIONS: ShellReconnectOptions = {
  maxAttempts: 10,
  baseDelay: 1000,
  maxDelay: 30000,
};

/** Maximum session duration warning threshold (25 minutes) */
const SESSION_WARNING_THRESHOLD = 25 * 60 * 1000;

/** Maximum session duration (30 minutes) */
const MAX_SESSION_DURATION = 30 * 60 * 1000;

export interface UseRemoteShellOptions {
  /** Target sensor ID */
  sensorId: string;
  /** Callback when shell session exits */
  onExit?: (code: number) => void;
  /** Callback when an error occurs */
  onError?: (error: string) => void;
  /** Callback when session is about to timeout */
  onTimeoutWarning?: (remainingMs: number) => void;
  /** Callback when session is ready */
  onReady?: () => void;
  /** Custom reconnection options */
  reconnectOptions?: Partial<ShellReconnectOptions>;
  /** Auto-connect on mount */
  autoConnect?: boolean;
  /** Optional WebSocket factory (useful for deterministic tests) */
  webSocketFactory?: (url: string) => WebSocket;
  /** Terminal configuration options */
  terminalOptions?: ITerminalOptions;
}

export interface UseRemoteShellReturn {
  /** Current connection status */
  status: ShellSessionStatus;
  /** Connect to the shell */
  connect: (options?: ShellInitOptions) => void;
  /** Disconnect from the shell */
  disconnect: () => void;
  /** Resize the terminal */
  resize: (cols: number, rows: number) => void;
  /** Current session information */
  session: ShellSession | null;
  /** Whether reconnection is in progress */
  isReconnecting: boolean;
  /** Current reconnection attempt number */
  reconnectAttempt: number;
  /** Max reconnection attempts */
  maxReconnectAttempts: number;
  /** Error message if any */
  error: string | null;
  /** The xterm.js Terminal instance */
  terminal: Terminal | null;
  /** The FitAddon instance for resizing */
  fitAddon: FitAddon | null;
}

/**
 * Hook for managing remote shell WebSocket connections
 */
export function useRemoteShell(options: UseRemoteShellOptions): UseRemoteShellReturn {
  const {
    sensorId,
    onExit,
    onError,
    onTimeoutWarning,
    onReady,
    reconnectOptions = {},
    autoConnect = false,
    webSocketFactory,
    terminalOptions,
  } = options;

  const reconnectConfig: ShellReconnectOptions = {
    ...DEFAULT_RECONNECT_OPTIONS,
    ...reconnectOptions,
  };

  // State
  const [status, setStatus] = useState<ShellSessionStatus>('disconnected');
  const [session, setSession] = useState<ShellSession | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);

  // Refs
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sessionStartRef = useRef<Date | null>(null);
  const timeoutWarningRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const sessionTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isCleaningUpRef = useRef(false);
  const pendingInitOptionsRef = useRef<ShellInitOptions | null>(null);
  const manualCloseSocketRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const isReconnectingRef = useRef(false);
  const connectInternalRef = useRef<
    ((initOptions?: ShellInitOptions, isReconnectAttempt?: boolean) => void) | null
  >(null);

  // Terminal Refs (labs-ejau)
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  // Initialize Terminal once
  useEffect(() => {
    if (terminalRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: MAX_OUTPUT_LINES,
      tabStopWidth: 4,
      allowProposedApi: true,
      allowTransparency: false,
      convertEol: true,
      ...terminalOptions,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());

    terminalRef.current = term;
    fitAddonRef.current = fitAddon;

    // Handle user input: send to WebSocket
    term.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        // Send as base64
        const message: ShellMessage = {
          type: 'shell-data',
          sessionId: sessionIdRef.current, // Use ref to access current session ID
          payload: { data: btoa(data) },
        };
        wsRef.current.send(JSON.stringify(message));
      } else {
        console.warn('[RemoteShell] Cannot send - not connected');
      }
    });

    return () => {
      term.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, []); // Run once on mount

  // Keep track of current session ID in a ref for the terminal callback
  const sessionIdRef = useRef<string>('');
  useEffect(() => {
    sessionIdRef.current = session?.id || '';
  }, [session?.id]);

  // Update terminal onData to use the ref (re-bind if needed, or just use ref inside)
  // Actually, the closure in useEffect above captures the initial state. 
  // We need to use a mutable ref for session ID inside the onData callback.
  // The terminal instance is stable, but we need to ensure it sends the correct session ID.
  
  // Re-bind onData is not easily possible with xterm API (it returns IDisposable).
  // So we MUST use a ref for session ID inside the initial onData handler.
  // I updated the onData handler above to use `session?.id` which would be stale.
  // Let's fix the useEffect above to use `sessionIdRef`.

  // ... (Correcting the useEffect block in the actual replacement)

  const setReconnectState = useCallback((nextAttempt: number, nextIsReconnecting: boolean) => {
    reconnectAttemptRef.current = nextAttempt;
    isReconnectingRef.current = nextIsReconnecting;
    setReconnectAttempt(nextAttempt);
    setIsReconnecting(nextIsReconnecting);
  }, []);

  const resetReconnectState = useCallback(() => {
    setReconnectState(0, false);
  }, [setReconnectState]);

  /**
   * Clear all timers
   */
  const clearTimers = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (timeoutWarningRef.current) {
      clearTimeout(timeoutWarningRef.current);
      timeoutWarningRef.current = null;
    }
    if (sessionTimeoutRef.current) {
      clearTimeout(sessionTimeoutRef.current);
      sessionTimeoutRef.current = null;
    }
  }, []);

  /**
   * Clean up WebSocket connection and timers
   */
  const cleanup = useCallback(() => {
    isCleaningUpRef.current = true;
    clearTimers();
    authenticatedRef.current = false;

    if (wsRef.current) {
      manualCloseSocketRef.current = wsRef.current;
      wsRef.current.onopen = null;
      wsRef.current.onmessage = null;
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.close(1000, 'Cleanup');
      wsRef.current = null;
    }

    isCleaningUpRef.current = false;
  }, [clearTimers]);

  /**
   * Setup session timeout warnings
   */
  const setupSessionTimeouts = useCallback(() => {
    clearTimers();
    sessionStartRef.current = new Date();

    // Warning at 25 minutes
    timeoutWarningRef.current = setTimeout(() => {
      const remaining = MAX_SESSION_DURATION - SESSION_WARNING_THRESHOLD;
      onTimeoutWarning?.(remaining);
    }, SESSION_WARNING_THRESHOLD);

    // Force disconnect at 30 minutes
    sessionTimeoutRef.current = setTimeout(() => {
      setError('Session timeout - maximum duration reached');
      setStatus('error');
      cleanup();
      onError?.('Session timeout - maximum duration reached');
    }, MAX_SESSION_DURATION);
  }, [cleanup, clearTimers, onError, onTimeoutWarning]);

  // Output buffer for rate limiting
  const outputBufferRef = useRef<string[]>([]);
  const outputRafIdRef = useRef<number | null>(null);
  const MAX_WRITE_CHUNK_SIZE = 16384; // 16KB per frame
  const MAX_BUFFER_SIZE = 1024 * 1024; // 1MB max buffer
  /** Maximum pending output chunks to retain (labs-1gsa) */
  const MAX_OUTPUT_LINES = 5000;

  const processOutputBuffer = useCallback(() => {
    if (!terminalRef.current || outputBufferRef.current.length === 0) {
      outputRafIdRef.current = null;
      return;
    }

    const chunk = outputBufferRef.current.shift();
    if (chunk) {
      terminalRef.current.write(chunk);
    }

    // Continue processing if there's more data
    if (outputBufferRef.current.length > 0) {
      outputRafIdRef.current = requestAnimationFrame(processOutputBuffer);
    } else {
      outputRafIdRef.current = null;
    }
  }, []);

  const queueOutput = useCallback((data: string) => {
    // Check total buffer size to prevent memory exhaustion
    const currentSize = outputBufferRef.current.reduce((acc, str) => acc + str.length, 0);

    if (currentSize + data.length > MAX_BUFFER_SIZE) {
      console.warn('[RemoteShell] Output buffer full, dropping data');
      return;
    }

    // Chunk large updates
    for (let i = 0; i < data.length; i += MAX_WRITE_CHUNK_SIZE) {
      outputBufferRef.current.push(data.slice(i, i + MAX_WRITE_CHUNK_SIZE));
    }

    // labs-1gsa: Cap the pending output buffer to prevent unbounded memory growth
    if (outputBufferRef.current.length > MAX_OUTPUT_LINES) {
      outputBufferRef.current = outputBufferRef.current.slice(-MAX_OUTPUT_LINES);
    }

    if (outputRafIdRef.current === null) {
      outputRafIdRef.current = requestAnimationFrame(processOutputBuffer);
    }
  }, [processOutputBuffer]);

  // Track whether the WebSocket has been authenticated (labs-c4hh)
  const authenticatedRef = useRef(false);

  /**
   * Handle incoming WebSocket messages.
   * Messages are ignored until first-message auth is confirmed (labs-c4hh).
   */
  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const message: ShellServerMessage = JSON.parse(event.data as string);

        // labs-c4hh: Handle auth response before processing any other messages
        if (message.type === 'auth-success') {
          authenticatedRef.current = true;
          console.log('[RemoteShell] Auth confirmed');
          return;
        }

        if (message.type === 'auth-error') {
          const authError = (message as unknown as { error?: string }).error || 'Authentication failed';
          setError(authError);
          setStatus('error');
          resetReconnectState();
          onError?.(authError);
          return;
        }

        // Don't process data until authenticated
        if (!authenticatedRef.current) {
          console.warn('[RemoteShell] Ignoring message before auth:', message.type);
          return;
        }

        switch (message.type) {
          case 'shell-data':
            if (message.payload?.data) {
              try {
                const decoded = atob(message.payload.data);
                queueOutput(decoded);
              } catch {
                queueOutput(message.payload.data);
              }
            }
            break;

          case 'shell-ready':
            setStatus('connected');
            resetReconnectState();
            setupSessionTimeouts();
            onReady?.();
            break;

          case 'shell-exit':
            setStatus('disconnected');
            resetReconnectState();
            cleanup();
            onExit?.(message.payload?.code ?? 0);
            if (terminalRef.current) {
              const code = message.payload?.code ?? 0;
              terminalRef.current.writeln('');
              terminalRef.current.writeln(
                `\x1b[1;${code === 0 ? '32' : '31'}m[Shell exited with code ${code}]\x1b[0m`
              );
            }
            break;

          case 'shell-error':
            const errorMsg = message.payload?.error || 'Unknown shell error';
            setError(errorMsg);
            setStatus('error');
            resetReconnectState();
            onError?.(errorMsg);
            if (terminalRef.current) {
              terminalRef.current.writeln('');
              terminalRef.current.writeln(`\x1b[1;31m[Error: ${errorMsg}]\x1b[0m`);
            }
            break;

          case 'pong':
            // Heartbeat response - connection is alive
            break;

          default:
            console.log('[RemoteShell] Unknown message type:', message.type);
        }
      } catch (err) {
        // If parsing fails, treat as raw data (only if authenticated)
        if (authenticatedRef.current && typeof event.data === 'string') {
          queueOutput(event.data);
        }
      }
    },
    [cleanup, onError, onExit, onReady, queueOutput, resetReconnectState, setupSessionTimeouts]
  );

  /**
   * Schedule a reconnection attempt
   */
  const scheduleReconnect = useCallback(() => {
    if (isCleaningUpRef.current) return;

    const nextAttempt = reconnectAttemptRef.current + 1;
    if (nextAttempt > reconnectConfig.maxAttempts) {
      setError('Max reconnection attempts reached');
      setStatus('error');
      resetReconnectState();
      onError?.('Max reconnection attempts reached');
      return;
    }

    setError(null);
    setStatus('connecting');
    setReconnectState(nextAttempt, true);

    const delay = Math.min(
      reconnectConfig.baseDelay * Math.pow(2, nextAttempt - 1),
      reconnectConfig.maxDelay
    );

    console.log(`[RemoteShell] Reconnecting in ${delay}ms (attempt ${nextAttempt})`);

    reconnectTimeoutRef.current = setTimeout(() => {
      if (!isCleaningUpRef.current) {
        // Reconnect with the same init options
        connectInternalRef.current?.(pendingInitOptionsRef.current || undefined, true);
      }
    }, delay);
  }, [onError, reconnectConfig, resetReconnectState, setReconnectState]);

  const sessionUrlRef = useRef<string | null>(null);

  const createSession = useCallback(async () => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY && API_KEY !== 'dev-dashboard-key') {
      headers['Authorization'] = `Bearer ${API_KEY}`;
    }
    const response = await fetch(`${API_URL}/api/v1/tunnel/shell/${sensorId}`, {
      method: 'POST',
      headers,
      credentials: 'include', // labs-n6nf
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Failed to create shell session');
    }

    const data = await response.json();
    return {
      sessionId: data.sessionId as string,
      wsUrl: data.wsUrl as string,
    };
  }, [sensorId]);

  const createWebSocket = useCallback(
    (url: string) => {
      if (webSocketFactory) {
        return webSocketFactory(url);
      }
      return new WebSocket(url);
    },
    [webSocketFactory]
  );

  /**
   * Internal connect function
   */
  const connectInternal = useCallback(
    async (initOptions?: ShellInitOptions, isReconnectAttempt = false) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        return;
      }

      cleanup();
      setStatus('connecting');
      setError(null);

      // Store init options for potential reconnection
      if (initOptions) {
        pendingInitOptionsRef.current = initOptions;
      }

      let sessionId = session?.id || '';
      let wsPath = sessionUrlRef.current;

      if (!sessionId || !wsPath) {
        try {
          const sessionInfo = await createSession();
          sessionId = sessionInfo.sessionId;
          wsPath = sessionInfo.wsUrl;
          sessionUrlRef.current = wsPath;
          const newSession: ShellSession = {
            id: sessionId,
            sensorId,
            status: 'connecting',
            startedAt: new Date(),
          };
          setSession(newSession);
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : 'Failed to create session';
          if (isReconnectAttempt) {
            console.warn('[RemoteShell] Reconnect session failed:', errorMsg);
            scheduleReconnect();
            return;
          }
          setError(errorMsg);
          setStatus('error');
          onError?.(errorMsg);
          return;
        }
      }

      // labs-c4hh: Connect to the tunnel endpoint without session token in the URL.
      // The session token is sent as the first WebSocket message (first-message auth).
      const wsProtocol = API_URL.startsWith('https') ? 'wss' : 'ws';
      const wsHost = API_URL.replace(/^https?:\/\//, '');
      const wsUrl = `${wsProtocol}://${wsHost}/ws/tunnel/user`;

      try {
        authenticatedRef.current = false;
        const ws = createWebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          console.log('[RemoteShell] WebSocket connected, sending auth');
          // First message: authenticate with sessionId
          ws.send(JSON.stringify({ type: 'auth', sessionId }));

          // Then send initial resize
          const cols = initOptions?.cols ?? 80;
          const rows = initOptions?.rows ?? 24;
          ws.send(
            JSON.stringify({
              type: 'shell-resize',
              sessionId,
              payload: { cols, rows },
            })
          );
        };

        ws.onmessage = handleMessage;

        ws.onerror = (event) => {
          console.error('[RemoteShell] WebSocket error:', event);
          const errorMsg = 'WebSocket connection error';
          setError(errorMsg);
          setStatus('error');
          resetReconnectState();
          onError?.(errorMsg);
        };

        ws.onclose = (event) => {
          console.log('[RemoteShell] WebSocket closed:', event.code, event.reason);
          const wasManualClose = manualCloseSocketRef.current === ws;
          if (wasManualClose) {
            manualCloseSocketRef.current = null;
          }
          wsRef.current = null;

          if (!isCleaningUpRef.current) {
            setStatus('disconnected');

            if (wasManualClose) {
              resetReconnectState();
              return;
            }

            // Clear session so reconnect creates a fresh tunnel session
            setSession(null);
            sessionUrlRef.current = null;
            scheduleReconnect();
          }
        };
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : 'Failed to create WebSocket';
        setError(errorMsg);
        setStatus('error');
        resetReconnectState();
        onError?.(errorMsg);
      }
    },
    [
      cleanup,
      createSession,
      createWebSocket,
      handleMessage,
      onError,
      resetReconnectState,
      scheduleReconnect,
      sensorId,
      session?.id,
    ]
  );

  useEffect(() => {
    connectInternalRef.current = connectInternal;
  }, [connectInternal]);

  /**
   * Connect to the remote shell
   */
  const connect = useCallback(
    (initOptions?: ShellInitOptions) => {
      resetReconnectState();
      void connectInternal(initOptions);
    },
    [connectInternal, resetReconnectState]
  );

  /**
   * Disconnect from the remote shell
   */
  const disconnect = useCallback(() => {
    isCleaningUpRef.current = true;
    clearTimers();
    resetReconnectState();

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      manualCloseSocketRef.current = wsRef.current;
      wsRef.current.close(1000, 'Client disconnect');
    }

    cleanup();
    setStatus('disconnected');
    setSession(null);
    setError(null);
    sessionUrlRef.current = null;
    pendingInitOptionsRef.current = null;
    isCleaningUpRef.current = false;
  }, [cleanup, clearTimers, resetReconnectState]);

  /**
   * Send input to the shell (base64 encoded)
   */
  const sendInput = useCallback(
    (data: string) => {
      if (wsRef.current?.readyState !== WebSocket.OPEN) {
        console.warn('[RemoteShell] Cannot send - not connected');
        return;
      }

      const message: ShellMessage = {
        type: 'shell-data',
        sessionId: session?.id || '',
        payload: { data },
      };

      wsRef.current.send(JSON.stringify(message));
    },
    [session?.id]
  );

  /**
   * Send terminal resize event
   */
  const resize = useCallback(
    (cols: number, rows: number) => {
      if (wsRef.current?.readyState !== WebSocket.OPEN) {
        return;
      }

      const message: ShellMessage = {
        type: 'shell-resize',
        sessionId: session?.id || '',
        payload: { cols, rows },
      };

      wsRef.current.send(JSON.stringify(message));
    },
    [session?.id]
  );

  // Auto-connect on mount if enabled
  useEffect(() => {
    if (autoConnect) {
      connect();
    }
  }, [autoConnect, connect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    status,
    connect,
    disconnect,
    resize,
    session,
    isReconnecting,
    reconnectAttempt,
    maxReconnectAttempts: reconnectConfig.maxAttempts,
    error,
    terminal: terminalRef.current,
    fitAddon: fitAddonRef.current,
  };
}
