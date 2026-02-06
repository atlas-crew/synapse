/**
 * useLogStream Hook
 *
 * WebSocket-based hook for streaming logs from a sensor.
 * Manages connection state, filtering, and a rolling buffer of log entries.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  LogEntry,
  LogFilter,
  LogStreamState,
  LogStreamMessage,
} from '../../types/logs';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY =
  import.meta.env.VITE_API_KEY ||
  import.meta.env.VITE_HORIZON_API_KEY ||
  'dev-dashboard-key';

export interface UseLogStreamOptions {
  /** Sensor ID to stream logs from */
  sensorId: string;
  /** Maximum entries to keep in buffer (default: 5000) */
  maxEntries?: number;
  /** Initial filter to apply */
  initialFilter?: LogFilter;
}

export interface UseLogStreamReturn {
  /** Current log stream state */
  state: LogStreamState;
  /** Connect to the log stream */
  connect: () => void;
  /** Disconnect from the log stream */
  disconnect: () => void;
  /** Update the active filter */
  setFilter: (filter: LogFilter) => void;
  /** Toggle pause state */
  togglePause: () => void;
  /** Clear all buffered entries */
  clear: () => void;
  /** Export current entries as JSON file */
  exportLogs: () => void;
}

/**
 * Parse a raw log entry message into a LogEntry object
 */
function parseLogEntry(raw: LogStreamMessage): LogEntry | null {
  try {
    if (raw.type === 'log') {
      const entry = raw.entry;
      return {
        id: entry.id,
        timestamp: new Date(entry.timestamp),
        source: entry.source,
        level: entry.level,
        message: entry.message,
        fields: entry.fields,
        method: entry.method,
        path: entry.path,
        statusCode: entry.statusCode,
        latencyMs: entry.latencyMs,
        clientIp: entry.clientIp,
        ruleId: entry.ruleId,
      };
    }

    if (raw.type === 'entry' && raw.channel === 'logs') {
      const timestamp = raw.logTimestamp
        ? new Date(raw.logTimestamp)
        : new Date();
      return {
        id: `${raw.sessionId ?? 'log'}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        timestamp,
        source: raw.source,
        level: raw.level,
        message: raw.message,
        fields: raw.fields,
        method: raw.method,
        path: raw.path,
        statusCode: raw.statusCode,
        latencyMs: raw.latencyMs,
        clientIp: raw.clientIp,
        ruleId: raw.ruleId,
      };
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Check if a log entry matches the current filter
 */
function matchesFilter(entry: LogEntry, filter: LogFilter): boolean {
  // Check source filter
  if (filter.sources && filter.sources.length > 0) {
    if (!filter.sources.includes(entry.source)) {
      return false;
    }
  }

  // Check level filter
  if (filter.levels && filter.levels.length > 0) {
    if (!filter.levels.includes(entry.level)) {
      return false;
    }
  }

  // Check search filter
  if (filter.search && filter.search.trim()) {
    const searchLower = filter.search.toLowerCase();
    const messageMatch = entry.message.toLowerCase().includes(searchLower);
    const pathMatch = entry.path?.toLowerCase().includes(searchLower);
    const clientIpMatch = entry.clientIp?.includes(filter.search);
    const ruleIdMatch = entry.ruleId?.toLowerCase().includes(searchLower);

    if (!messageMatch && !pathMatch && !clientIpMatch && !ruleIdMatch) {
      return false;
    }
  }

  // Check since filter
  if (filter.since) {
    if (entry.timestamp < filter.since) {
      return false;
    }
  }

  return true;
}

export function useLogStream(options: UseLogStreamOptions): UseLogStreamReturn {
  const { sensorId, maxEntries = 5000, initialFilter = {} } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const filterDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isCleaningUpRef = useRef(false);
  const pausedBufferRef = useRef<LogEntry[]>([]);
  const sessionIdRef = useRef<string | null>(null);
  const sessionUrlRef = useRef<string | null>(null);
  const filterRef = useRef<LogFilter>(initialFilter);

  const [state, setState] = useState<LogStreamState>({
    connected: false,
    entries: [],
    filter: initialFilter,
    paused: false,
    dropped: 0,
  });

  const createSession = useCallback(async () => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY && API_KEY !== 'dev-dashboard-key') {
      headers['Authorization'] = `Bearer ${API_KEY}`;
    }
    const response = await fetch(`${API_URL}/api/v1/tunnel/logs/${sensorId}`, {
      method: 'POST',
      headers,
      credentials: 'include', // labs-n6nf
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Failed to create log session');
    }

    const data = await response.json();
    return {
      sessionId: data.sessionId as string,
      wsUrl: data.wsUrl as string,
    };
  }, [sensorId]);

  /**
   * Clean up WebSocket connection and timers
   */
  const cleanup = useCallback(() => {
    isCleaningUpRef.current = true;

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (filterDebounceRef.current) {
      clearTimeout(filterDebounceRef.current);
      filterDebounceRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.onopen = null;
      wsRef.current.onmessage = null;
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.close(1000, 'Cleanup');
      wsRef.current = null;
    }

    isCleaningUpRef.current = false;
  }, []);

  /**
   * Add entries to the buffer, maintaining max size
   */
  const addEntries = useCallback(
    (newEntries: LogEntry[]) => {
      setState((prev) => {
        if (prev.paused) {
          // Store in paused buffer instead
          pausedBufferRef.current = [...newEntries, ...pausedBufferRef.current].slice(0, maxEntries);
          return prev;
        }

        // Filter entries based on current filter
        const filteredEntries = newEntries.filter((entry) => matchesFilter(entry, prev.filter));

        if (filteredEntries.length === 0) {
          return prev;
        }

        // Prepend new entries (newest first)
        const combined = [...filteredEntries, ...prev.entries];
        const droppedCount = Math.max(0, combined.length - maxEntries);

        return {
          ...prev,
          entries: combined.slice(0, maxEntries),
          dropped: prev.dropped + droppedCount,
        };
      });
    },
    [maxEntries]
  );

  /**
   * Handle incoming WebSocket messages
   */
  const handleMessage = useCallback(
    (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data as string) as LogStreamMessage;

        if (data.type === 'log' || data.type === 'entry') {
          const entry = parseLogEntry(data);
          if (entry) {
            addEntries([entry]);
          }
        } else if (data.type === 'log-batch') {
          const entries = (data as { entries: Array<{ id: string; timestamp: string; source: LogEntry['source']; level: LogEntry['level']; message: string; fields?: Record<string, unknown>; method?: string; path?: string; statusCode?: number; latencyMs?: number; clientIp?: string; ruleId?: string }> }).entries
            .map((raw) => {
              try {
                return {
                  id: raw.id,
                  timestamp: new Date(raw.timestamp),
                  source: raw.source,
                  level: raw.level,
                  message: raw.message,
                  fields: raw.fields,
                  method: raw.method,
                  path: raw.path,
                  statusCode: raw.statusCode,
                  latencyMs: raw.latencyMs,
                  clientIp: raw.clientIp,
                  ruleId: raw.ruleId,
                } as LogEntry;
              } catch {
                return null;
              }
            })
            .filter((e): e is LogEntry => e !== null);

          if (entries.length > 0) {
            addEntries(entries);
          }
        } else if (data.type === 'backfill-complete') {
          // Optional: could surface a toast or mark backfill finished
        }
      } catch (err) {
        console.error('[useLogStream] Failed to parse message:', err);
      }
    },
    [addEntries]
  );

  /**
   * Connect to the log stream WebSocket
   */
  const connectInternal = useCallback(async () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    cleanup();

    let sessionId = sessionIdRef.current;
    let wsPath = sessionUrlRef.current;

    if (!sessionId || !wsPath) {
      try {
        const sessionInfo = await createSession();
        sessionId = sessionInfo.sessionId;
        wsPath = sessionInfo.wsUrl;
        sessionIdRef.current = sessionId;
        sessionUrlRef.current = wsPath;
      } catch (error) {
        console.error('[useLogStream] Failed to create session:', error);
        setState((prev) => ({ ...prev, connected: false }));
        return;
      }
    }

    const wsProtocol = API_URL.startsWith('https') ? 'wss' : 'ws';
    const wsHost = API_URL.replace(/^https?:\/\//, '');
    const wsUrl = wsPath.startsWith('ws')
      ? wsPath
      : `${wsProtocol}://${wsHost}${wsPath.startsWith('/') ? wsPath : `/${wsPath}`}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[useLogStream] Connected to log stream');
        setState((prev) => ({ ...prev, connected: true }));

        const activeFilter = filterRef.current;
        ws.send(
          JSON.stringify({
            type: 'subscribe',
            channel: 'logs',
            sessionId,
            sources: activeFilter.sources ?? [],
            filter: activeFilter,
            backfill: true,
            backfillLines: 200,
          })
        );
      };

      ws.onmessage = handleMessage;

      ws.onclose = (event) => {
        console.log('[useLogStream] Disconnected:', event.code, event.reason);
        setState((prev) => ({ ...prev, connected: false }));

        // Attempt reconnection unless intentionally cleaning up
        if (!isCleaningUpRef.current && event.code !== 1000) {
          // Clear session so reconnect creates a fresh tunnel session
          sessionIdRef.current = null;
          sessionUrlRef.current = null;
          reconnectTimeoutRef.current = setTimeout(() => {
            void connectInternal();
          }, 3000);
        }
      };

      ws.onerror = (error) => {
        console.error('[useLogStream] WebSocket error:', error);
        setState((prev) => ({ ...prev, connected: false }));
      };
    } catch (error) {
      console.error('[useLogStream] Failed to connect:', error);
      setState((prev) => ({ ...prev, connected: false }));
    }
  }, [cleanup, createSession, handleMessage]);

  const connect = useCallback(() => {
    void connectInternal();
  }, [connectInternal]);

  /**
   * Disconnect from the log stream
   */
  const disconnect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'unsubscribe',
          channel: 'logs',
          sessionId: sessionIdRef.current,
        })
      );
    }
    cleanup();
    setState((prev) => ({ ...prev, connected: false }));
    sessionIdRef.current = null;
    sessionUrlRef.current = null;
  }, [cleanup]);

  /**
   * Update the active filter with debouncing
   */
  const setFilter = useCallback(
    (filter: LogFilter) => {
      filterRef.current = filter;
      // Clear existing debounce timer
      if (filterDebounceRef.current) {
        clearTimeout(filterDebounceRef.current);
      }

      // Debounce filter changes
      filterDebounceRef.current = setTimeout(() => {
        setState((prev) => {
          // Re-filter existing entries with new filter
          const filteredEntries = prev.entries.filter((entry) => matchesFilter(entry, filter));

          return {
            ...prev,
            filter,
            entries: filteredEntries,
          };
        });

        // Notify server of filter change if connected
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(
            JSON.stringify({
              type: 'filter',
              channel: 'logs',
              sessionId: sessionIdRef.current,
              sources: filter.sources ?? [],
              filter,
            })
          );
        }
      }, 300);
    },
    []
  );

  /**
   * Toggle pause state
   */
  const togglePause = useCallback(() => {
    setState((prev) => {
      if (prev.paused) {
        // Resuming - merge paused buffer with current entries
        const merged = [...pausedBufferRef.current, ...prev.entries]
          .filter((entry) => matchesFilter(entry, prev.filter))
          .slice(0, maxEntries);
        pausedBufferRef.current = [];

        return {
          ...prev,
          paused: false,
          entries: merged,
        };
      } else {
        // Pausing
        return {
          ...prev,
          paused: true,
        };
      }
    });
  }, [maxEntries]);

  /**
   * Clear all buffered entries
   */
  const clear = useCallback(() => {
    setState((prev) => ({
      ...prev,
      entries: [],
      dropped: 0,
    }));
    pausedBufferRef.current = [];
  }, []);

  /**
   * Export current entries as JSON file
   */
  const exportLogs = useCallback(() => {
    const exportData = state.entries.map((entry) => ({
      ...entry,
      timestamp: entry.timestamp.toISOString(),
    }));

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json',
    });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `sensor-${sensorId}-logs-${timestamp}.json`;

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, [state.entries, sensorId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cleanup();
    };
  }, [cleanup]);

  return {
    state,
    connect,
    disconnect,
    setFilter,
    togglePause,
    clear,
    exportLogs,
  };
}
