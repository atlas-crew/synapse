import { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { Activity, WifiOff, AlertCircle } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { Spinner, Stack } from '@/ui';

export interface WebTerminalProps {
  sensorId: string;
  sessionId?: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Error) => void;
}

type ConnectionState = 'connecting' | 'connected' | 'disconnected' | 'error';

export function WebTerminal({
  sensorId,
  sessionId,
  onConnect,
  onDisconnect,
  onError,
}: WebTerminalProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [errorMessage, setErrorMessage] = useState('');
  const [reconnectAttempt, setReconnectAttempt] = useState(0);

  const cleanup = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }
    fitAddonRef.current = null;
  }, []);

  const connectWebSocket = useCallback(() => {
    if (!sessionId) {
      setErrorMessage('No session ID provided');
      setConnectionState('error');
      return;
    }

    setConnectionState('connecting');
    setErrorMessage('');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/tunnel/user/${sessionId}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnectionState('connected');
        setReconnectAttempt(0);
        onConnect?.();

        ws.send(JSON.stringify({
          type: 'connect',
          sensorId,
        }));
      };

      ws.onmessage = (event) => {
        if (xtermRef.current && typeof event.data === 'string') {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'shell-data' && msg.payload?.data) {
              xtermRef.current.write(msg.payload.data);
            }
          } catch {
            // Raw data, write directly
            xtermRef.current.write(event.data);
          }
        }
      };

      ws.onerror = () => {
        const err = new Error('WebSocket connection error');
        setErrorMessage(err.message);
        setConnectionState('error');
        onError?.(err);
      };

      ws.onclose = () => {
        setConnectionState('disconnected');
        onDisconnect?.();

        if (reconnectAttempt < 5) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempt), 30000);
          reconnectTimeoutRef.current = setTimeout(() => {
            setReconnectAttempt((prev) => prev + 1);
            connectWebSocket();
          }, delay);
        } else {
          setErrorMessage('Max reconnection attempts reached');
          setConnectionState('error');
        }
      };
    } catch (error) {
      const err = error instanceof Error ? error : new Error('Failed to create WebSocket');
      setErrorMessage(err.message);
      setConnectionState('error');
      onError?.(err);
    }
  }, [sessionId, sensorId, onConnect, onDisconnect, onError, reconnectAttempt]);

  // Initialize terminal
  useEffect(() => {
    if (!terminalRef.current) return;

    const terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1a1a1a',
        foreground: '#e5e5e5',
        cursor: '#ffffff',
        black: '#000000',
        red: '#ff6b6b',
        green: '#51cf66',
        yellow: '#ffd93d',
        blue: '#74c0fc',
        magenta: '#da77f2',
        cyan: '#4dabf7',
        white: '#e5e5e5',
        brightBlack: '#666666',
        brightRed: '#ff8787',
        brightGreen: '#69db7c',
        brightYellow: '#ffe066',
        brightBlue: '#91c9fc',
        brightMagenta: '#e599f7',
        brightCyan: '#66d9e8',
        brightWhite: '#ffffff',
      },
    });

    xtermRef.current = terminal;

    const fitAddon = new FitAddon();
    fitAddonRef.current = fitAddon;
    terminal.loadAddon(fitAddon);
    terminal.loadAddon(new WebLinksAddon());

    terminal.open(terminalRef.current);
    fitAddon.fit();

    terminal.onData((data) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({ type: 'input', data }));
      }
    });

    const handleResize = () => fitAddon.fit();
    window.addEventListener('resize', handleResize);

    terminal.writeln('\x1b[1;36mSignal Horizon Terminal\x1b[0m');
    terminal.writeln(`\x1b[1;90mSensor: ${sensorId}\x1b[0m`);
    terminal.writeln('');

    return () => {
      window.removeEventListener('resize', handleResize);
      cleanup();
    };
  }, [sensorId, cleanup]);

  // Connect when sessionId available
  useEffect(() => {
    if (sessionId) {
      connectWebSocket();
    }
    return () => cleanup();
  }, [sessionId, connectWebSocket, cleanup]);

  const getStatusIndicator = () => {
    switch (connectionState) {
      case 'connected':
        return (
          <div className="flex items-center gap-2 text-status-success">
            <Activity className="w-4 h-4" />
            <span className="text-sm font-medium">Connected</span>
          </div>
        );
      case 'connecting':
        return (
          <div className="flex items-center gap-2 text-ink-secondary">
            <Spinner size={16} color="#7F7F7F" />
            <span className="text-sm font-medium">Connecting...</span>
          </div>
        );
      case 'disconnected':
        return (
          <div className="flex items-center gap-2 text-status-warning">
            <WifiOff className="w-4 h-4" />
            <span className="text-sm font-medium">
              {reconnectAttempt > 0 ? `Reconnecting (${reconnectAttempt}/5)...` : 'Disconnected'}
            </span>
          </div>
        );
      case 'error':
        return (
          <div className="flex items-center gap-2 text-status-error">
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm font-medium">Error</span>
          </div>
        );
    }
  };

  return (
    <div className="flex flex-col h-full bg-surface-card border border-border-subtle overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-surface-raised border-b border-border-subtle">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-medium text-ink-primary">Terminal</h3>
          <span className="text-xs text-ink-secondary">
            Session: {sessionId || 'Not connected'}
          </span>
        </div>
        {getStatusIndicator()}
      </div>

      {/* Error Message */}
      {errorMessage && (
        <div className="px-4 py-2 bg-status-error/10 border-b border-status-error/20">
          <div className="flex items-center gap-2 text-status-error text-sm">
            <AlertCircle className="w-4 h-4" />
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      {/* Terminal Container */}
      <div className="flex-1 relative">
        <div
          ref={terminalRef}
          className="absolute inset-0 p-2"
          style={{ backgroundColor: '#1a1a1a' }}
          role="log"
          aria-label="Terminal session output"
          aria-live="polite"
        />

        {/* Overlays */}
        {connectionState === 'connecting' && (
          <div className="absolute inset-0 bg-surface-card/80 backdrop-blur-sm flex items-center justify-center">
            <Stack direction="column" align="center" style={{ gap: '12px' }}>
              <Spinner size={32} color="#7F7F7F" />
              <p className="text-sm text-ink-secondary">Establishing connection...</p>
            </Stack>
          </div>
        )}

        {connectionState === 'error' && (
          <div className="absolute inset-0 bg-surface-card/80 backdrop-blur-sm flex items-center justify-center">
            <Stack
              direction="column"
              align="center"
              style={{ gap: '12px' }}
              className="max-w-md text-center"
            >
              <AlertCircle className="w-8 h-8 text-status-error" />
              <p className="text-sm text-ink-primary font-medium">Connection Error</p>
              <p className="text-xs text-ink-secondary">{errorMessage}</p>
            </Stack>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 bg-surface-raised border-t border-border-subtle">
        <p className="text-xs text-ink-secondary">
          Use Ctrl+Shift+V to paste • Copy with selection
        </p>
      </div>
    </div>
  );
}
