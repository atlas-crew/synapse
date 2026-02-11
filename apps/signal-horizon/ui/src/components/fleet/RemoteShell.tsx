/**
 * RemoteShell Component
 * xterm.js-based terminal component for remote shell sessions to sensors
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { X, Activity, WifiOff, AlertCircle, Clock, RefreshCw } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { useRemoteShell } from '../../hooks/fleet/useRemoteShell';
import type { ShellSessionStatus } from '../../types/shell';
import { Spinner } from '@/ui';

/** Tokyo Night inspired terminal theme */
const TERMINAL_THEME = {
  background: '#1a1b26',
  foreground: '#a9b1d6',
  cursor: '#c0caf5',
  cursorAccent: '#1a1b26',
  selectionBackground: '#33467c',
  selectionForeground: '#c0caf5',
  selectionInactiveBackground: '#283457',
  black: '#15161e',
  red: '#f7768e',
  green: '#9ece6a',
  yellow: '#e0af68',
  blue: '#7aa2f7',
  magenta: '#bb9af7',
  cyan: '#7dcfff',
  white: '#c0caf5',
  brightBlack: '#414868',
  brightRed: '#f7768e',
  brightGreen: '#9ece6a',
  brightYellow: '#e0af68',
  brightBlue: '#7aa2f7',
  brightMagenta: '#bb9af7',
  brightCyan: '#7dcfff',
  brightWhite: '#c0caf5',
};

export interface RemoteShellProps {
  /** Target sensor ID */
  sensorId: string;
  /** Display name for the sensor */
  sensorName: string;
  /** Callback when shell is closed */
  onClose?: () => void;
  /** Additional CSS classes */
  className?: string;
  /** Initial terminal columns */
  initialCols?: number;
  /** Initial terminal rows */
  initialRows?: number;
}

/**
 * Remote Shell terminal component with xterm.js
 */
export function RemoteShell({
  sensorId,
  sensorName,
  onClose,
  className = '',
  initialCols = 80,
  initialRows = 24,
}: RemoteShellProps) {
  const terminalRef = useRef<HTMLDivElement>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);

  const [showTimeoutWarning, setShowTimeoutWarning] = useState(false);
	  const [remainingTime, setRemainingTime] = useState<number | null>(null);
	  const [exitCode, setExitCode] = useState<number | null>(null);

	  /**
	   * Handle shell exit
	   */
  const handleExit = useCallback((code: number) => {
    setExitCode(code);
  }, []);

  /**
   * Handle errors
   */
  const handleError = useCallback((_error: string) => {
    // Error is logged by hook to terminal
  }, []);

  /**
   * Handle timeout warning
   */
  const handleTimeoutWarning = useCallback((remainingMs: number) => {
    setShowTimeoutWarning(true);
    setRemainingTime(Math.floor(remainingMs / 1000 / 60)); // Convert to minutes
  }, []);

  /**
   * Handle shell ready
   */
  const handleReady = useCallback(() => {
    // Focus terminal when ready
    // We can't access terminal instance directly here easily unless we expose it from hook,
    // but the hook exposes it now!
  }, []);

  // Initialize remote shell hook
  const {
    status,
    connect,
    disconnect,
    resize,
    session,
    isReconnecting,
    reconnectAttempt,
    maxReconnectAttempts,
    error,
    terminal,
    fitAddon,
  } = useRemoteShell({
    sensorId,
    onExit: handleExit,
    onError: handleError,
    onTimeoutWarning: handleTimeoutWarning,
    onReady: handleReady,
    terminalOptions: {
      theme: TERMINAL_THEME,
      fontFamily: '"JetBrains Mono", "Fira Code", Menlo, Monaco, "Courier New", monospace',
      fontSize: 14,
      fontWeight: 'normal',
      fontWeightBold: 'bold',
    },
  });

  /**
   * Handle terminal resize
   */
  const handleResize = useCallback(() => {
    if (fitAddon) {
      fitAddon.fit();
      // We don't need to manually call resize() here if fitAddon handles it locally,
      // but we need to tell the server.
      // fitAddon.proposeDimensions() gives us the new cols/rows.
      const dims = fitAddon.proposeDimensions();
      if (dims) {
        resize(dims.cols, dims.rows);
      }
    }
  }, [fitAddon, resize]);

  // Attach terminal to DOM on mount/update
  useEffect(() => {
    if (!terminalRef.current || !terminal || !fitAddon) return;

    // Open terminal in container if not already opened
    // xterm.js doesn't expose an easy "isOpened" property, but checking element content is a proxy
    if (terminalRef.current.childElementCount === 0) {
      terminal.open(terminalRef.current);
      fitAddon.fit();
      
      // Initial banner
      terminal.writeln('\x1b[1;36mSignal Horizon Remote Shell\x1b[0m');
      terminal.writeln(`\x1b[90mSensor: ${sensorName} (${sensorId})\x1b[0m`);
      terminal.writeln('\x1b[90mPress Connect to establish session...\x1b[0m');
      terminal.writeln('');
    }

    // Setup resize observer
    const resizeObserver = new ResizeObserver(() => {
      handleResize();
    });
    resizeObserver.observe(terminalRef.current);
    resizeObserverRef.current = resizeObserver;

    return () => {
      resizeObserver.disconnect();
      // We do NOT dispose the terminal here, the hook handles its lifecycle.
      // But we might want to detach it? terminal.dispose() destroys it.
      // The hook disposes it on unmount.
    };
  }, [terminal, fitAddon, handleResize, sensorName, sensorId]);

  // Focus terminal when connected
  useEffect(() => {
    if (status === 'connected' && terminal) {
      terminal.focus();
      
      // Send initial resize
      handleResize();
    }
  }, [status, terminal, handleResize]);

  // Handle connect/disconnect state changes for UI feedback in terminal
  useEffect(() => {
    if (!terminal) return;

    if (status === 'connected') {
      terminal.writeln('\x1b[1;32m[Connected]\x1b[0m');
      terminal.writeln('');
    } else if (status === 'disconnected' && !isReconnecting) {
      terminal.writeln('');
      terminal.writeln('\x1b[1;33m[Disconnected]\x1b[0m');
    }
  }, [status, isReconnecting, terminal]);

  /**
   * Handle connect button click
   */
  const handleConnect = useCallback(() => {
    // Initial dimensions
    let cols = initialCols;
    let rows = initialRows;
    
    if (fitAddon) {
      const dims = fitAddon.proposeDimensions();
      if (dims) {
        cols = dims.cols;
        rows = dims.rows;
      }
    }
    
    connect({ cols, rows });

    if (terminal) {
      terminal.clear();
      terminal.writeln('\x1b[1;36mSignal Horizon Remote Shell\x1b[0m');
      terminal.writeln(`\x1b[90mSensor: ${sensorName} (${sensorId})\x1b[0m`);
      terminal.writeln('\x1b[90mConnecting...\x1b[0m');
      terminal.writeln('');
    }
  }, [connect, fitAddon, initialCols, initialRows, sensorId, sensorName, terminal]);

  /**
   * Handle disconnect button click
   */
  const handleDisconnect = useCallback(() => {
    disconnect();
    setShowTimeoutWarning(false);
    setRemainingTime(null);
    setExitCode(null);
  }, [disconnect]);

  /**
   * Handle close button click
   */
  const handleClose = useCallback(() => {
    disconnect();
    onClose?.();
  }, [disconnect, onClose]);

  /**
   * Render connection status indicator
   */
  const renderStatusIndicator = () => {
    const statusConfig: Record<
      ShellSessionStatus,
      { icon: React.ReactNode; text: string; className: string }
    > = {
      connected: {
        icon: <Activity className="w-4 h-4" />,
        text: 'Connected',
        className: 'text-status-success',
      },
      connecting: {
        icon: <Spinner size={16} color="#7F7F7F" />,
        text: isReconnecting
          ? `Reconnecting (${reconnectAttempt}/${maxReconnectAttempts})...`
          : 'Connecting...',
        className: 'text-ink-secondary',
      },
      disconnected: {
        icon: <WifiOff className="w-4 h-4" />,
        text: 'Disconnected',
        className: 'text-status-warning',
      },
      error: {
        icon: <AlertCircle className="w-4 h-4" />,
        text: 'Error',
        className: 'text-status-error',
      },
    };

    const config = statusConfig[status];

    return (
      <div className={`flex items-center gap-2 ${config.className}`}>
        {config.icon}
        <span className="text-sm font-medium">{config.text}</span>
      </div>
    );
  };

  return (
    <div
      className={`flex flex-col h-full bg-surface-card  border border-border-subtle overflow-hidden ${className}`}
    >
      {/* Header Bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-surface-raised border-b border-border-subtle">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-ink-primary">Remote Shell</h3>
          <span className="text-xs text-ink-secondary truncate max-w-[200px]" title={sensorName}>
            {sensorName}
          </span>
        </div>

        <div className="flex items-center gap-4">
          {renderStatusIndicator()}

          {/* Connection buttons */}
          <div className="flex items-center gap-2">
            {status === 'disconnected' || status === 'error' ? (
              <button
                onClick={handleConnect}
                className="px-3 py-1.5 text-xs font-medium bg-accent-primary text-white hover:bg-accent-primary/90 transition-colors"
              >
                Connect
              </button>
            ) : status === 'connected' ? (
              <button
                onClick={handleDisconnect}
                className="px-3 py-1.5 text-xs font-medium bg-status-error/10 text-status-error hover:bg-status-error/20 transition-colors"
              >
                Disconnect
              </button>
            ) : null}
          </div>

          {/* Close button */}
          {onClose && (
            <button
              onClick={handleClose}
              className="p-1 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              title="Close terminal"
              aria-label="Close terminal"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Timeout Warning */}
      {showTimeoutWarning && (
        <div className="px-4 py-2 bg-status-warning/10 border-b border-status-warning/20">
          <div className="flex items-center gap-2 text-status-warning text-sm">
            <Clock className="w-4 h-4" />
            <span>
              Session will timeout in {remainingTime} minute{remainingTime !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="px-4 py-2 bg-status-error/10 border-b border-status-error/20">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-status-error text-sm">
              <AlertCircle className="w-4 h-4" />
              <span>{error}</span>
            </div>
            {(status === 'error' || status === 'disconnected') && (
              <button
                onClick={handleConnect}
                className="flex items-center gap-1 px-2 py-1 text-xs text-status-error hover:bg-status-error/10 transition-colors"
              >
                <RefreshCw className="w-3 h-3" />
                Retry
              </button>
            )}
          </div>
        </div>
      )}

      {/* Terminal Container */}
      <div className="flex-1 relative min-h-0">
        <div
          ref={terminalRef}
          className="absolute inset-0 p-2"
          style={{ backgroundColor: TERMINAL_THEME.background }}
          role="log"
          aria-label="Remote shell terminal output"
          aria-live="polite"
        />

        {/* Connecting Overlay */}
        {status === 'connecting' && (
          <div className="absolute inset-0 bg-surface-card/80 backdrop-blur-sm flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <Spinner size={32} color="#0057B7" />
              <p className="text-sm text-ink-secondary">
                {isReconnecting
                  ? `Reconnecting to ${sensorName}... (attempt ${reconnectAttempt}/${maxReconnectAttempts})`
                  : `Establishing connection to ${sensorName}...`}
              </p>
            </div>
          </div>
        )}

        {/* Error Overlay */}
        {status === 'error' && !error && (
          <div className="absolute inset-0 bg-surface-card/80 backdrop-blur-sm flex items-center justify-center">
            <div className="flex flex-col items-center gap-3 max-w-md text-center">
              <AlertCircle className="w-8 h-8 text-status-error" />
              <p className="text-sm text-ink-primary font-medium">Connection Error</p>
              <p className="text-xs text-ink-secondary">
                Failed to connect to the sensor. Please check the sensor status and try again.
              </p>
              <button
                onClick={handleConnect}
                className="px-4 py-2 text-sm font-medium bg-accent-primary text-white hover:bg-accent-primary/90 transition-colors"
              >
                Retry Connection
              </button>
            </div>
          </div>
        )}

        {/* Exit Code Display */}
        {exitCode !== null && status === 'disconnected' && (
          <div className="absolute bottom-4 right-4 px-3 py-2 bg-surface-raised border border-border-subtle">
            <p className={`text-sm ${exitCode === 0 ? 'text-status-success' : 'text-status-error'}`}>
              Shell exited with code {exitCode}
            </p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between px-4 py-2 bg-surface-raised border-t border-border-subtle">
        <p className="text-xs text-ink-secondary">
          Ctrl+C: Interrupt | Ctrl+D: EOF | Ctrl+L: Clear
        </p>
        {session && (
          <p className="text-xs text-ink-muted">Session: {session.id.slice(0, 16)}...</p>
        )}
      </div>
    </div>
  );
}

export default RemoteShell;
