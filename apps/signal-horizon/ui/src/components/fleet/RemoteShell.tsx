/**
 * RemoteShell Component
 * xterm.js-based terminal component for remote shell sessions to sensors
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { X, Activity, WifiOff, Loader2, AlertCircle, Clock, RefreshCw } from 'lucide-react';
import '@xterm/xterm/css/xterm.css';
import { useRemoteShell } from '../../hooks/fleet/useRemoteShell';
import type { ShellSessionStatus } from '../../types/shell';

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
  const terminalInstance = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const resizeObserverRef = useRef<ResizeObserver | null>(null);

  const [showTimeoutWarning, setShowTimeoutWarning] = useState(false);
  const [remainingTime, setRemainingTime] = useState<number | null>(null);
  const [exitCode, setExitCode] = useState<number | null>(null);

  /**
   * Handle incoming data from the shell
   * Data arrives base64 encoded
   */
  const handleData = useCallback((data: string) => {
    if (!terminalInstance.current) return;

    try {
      // Decode base64 data
      const decoded = atob(data);
      terminalInstance.current.write(decoded);
    } catch {
      // If not valid base64, write raw data
      terminalInstance.current.write(data);
    }
  }, []);

  /**
   * Handle shell exit
   */
  const handleExit = useCallback((code: number) => {
    setExitCode(code);
    if (terminalInstance.current) {
      terminalInstance.current.writeln('');
      terminalInstance.current.writeln(
        `\x1b[1;${code === 0 ? '32' : '31'}m[Shell exited with code ${code}]\x1b[0m`
      );
    }
  }, []);

  /**
   * Handle errors
   */
  const handleError = useCallback((error: string) => {
    if (terminalInstance.current) {
      terminalInstance.current.writeln('');
      terminalInstance.current.writeln(`\x1b[1;31m[Error: ${error}]\x1b[0m`);
    }
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
    if (terminalInstance.current) {
      // Focus terminal when ready
      terminalInstance.current.focus();
    }
  }, []);

  // Initialize remote shell hook
  const {
    status,
    connect,
    disconnect,
    sendInput,
    resize,
    session,
    isReconnecting,
    reconnectAttempt,
    maxReconnectAttempts,
    error,
  } = useRemoteShell({
    sensorId,
    onData: handleData,
    onExit: handleExit,
    onError: handleError,
    onTimeoutWarning: handleTimeoutWarning,
    onReady: handleReady,
  });

  /**
   * Get terminal dimensions from container
   */
  const getTerminalDimensions = useCallback(() => {
    if (fitAddon.current && terminalInstance.current) {
      const dims = fitAddon.current.proposeDimensions();
      return dims ? { cols: dims.cols, rows: dims.rows } : { cols: initialCols, rows: initialRows };
    }
    return { cols: initialCols, rows: initialRows };
  }, [initialCols, initialRows]);

  /**
   * Handle terminal resize
   */
  const handleResize = useCallback(() => {
    if (fitAddon.current) {
      fitAddon.current.fit();
      const dims = getTerminalDimensions();
      resize(dims.cols, dims.rows);
    }
  }, [getTerminalDimensions, resize]);

  // Initialize terminal on mount
  useEffect(() => {
    if (!terminalRef.current) return;

    // Create terminal instance
    const terminal = new Terminal({
      theme: TERMINAL_THEME,
      fontFamily: '"JetBrains Mono", "Fira Code", Menlo, Monaco, "Courier New", monospace',
      fontSize: 14,
      fontWeight: 'normal',
      fontWeightBold: 'bold',
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10000,
      tabStopWidth: 4,
      allowProposedApi: true,
      allowTransparency: false,
      convertEol: true,
    });

    terminalInstance.current = terminal;

    // Load addons
    const fit = new FitAddon();
    fitAddon.current = fit;
    terminal.loadAddon(fit);

    const webLinks = new WebLinksAddon();
    terminal.loadAddon(webLinks);

    // Open terminal in container
    terminal.open(terminalRef.current);
    fit.fit();

    // Handle user input - encode as base64
    terminal.onData((data) => {
      sendInput(btoa(data));
    });

    // Write welcome message
    terminal.writeln('\x1b[1;36mSignal Horizon Remote Shell\x1b[0m');
    terminal.writeln(`\x1b[90mSensor: ${sensorName} (${sensorId})\x1b[0m`);
    terminal.writeln('\x1b[90mPress Connect to establish session...\x1b[0m');
    terminal.writeln('');

    // Setup resize observer
    const resizeObserver = new ResizeObserver(() => {
      handleResize();
    });
    resizeObserver.observe(terminalRef.current);
    resizeObserverRef.current = resizeObserver;

    // Cleanup on unmount
    return () => {
      resizeObserver.disconnect();
      terminal.dispose();
      terminalInstance.current = null;
      fitAddon.current = null;
    };
  }, [sensorId, sensorName, handleResize, sendInput]);

  // Handle connect/disconnect state changes
  useEffect(() => {
    if (!terminalInstance.current) return;

    if (status === 'connected') {
      terminalInstance.current.writeln('\x1b[1;32m[Connected]\x1b[0m');
      terminalInstance.current.writeln('');
    } else if (status === 'disconnected' && !isReconnecting) {
      terminalInstance.current.writeln('');
      terminalInstance.current.writeln('\x1b[1;33m[Disconnected]\x1b[0m');
    }
  }, [status, isReconnecting]);

  /**
   * Handle connect button click
   */
  const handleConnect = useCallback(() => {
    const dims = getTerminalDimensions();
    connect({ cols: dims.cols, rows: dims.rows });

    if (terminalInstance.current) {
      terminalInstance.current.clear();
      terminalInstance.current.writeln('\x1b[1;36mSignal Horizon Remote Shell\x1b[0m');
      terminalInstance.current.writeln(`\x1b[90mSensor: ${sensorName} (${sensorId})\x1b[0m`);
      terminalInstance.current.writeln('\x1b[90mConnecting...\x1b[0m');
      terminalInstance.current.writeln('');
    }
  }, [connect, getTerminalDimensions, sensorId, sensorName]);

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
        icon: <Loader2 className="w-4 h-4 animate-spin" />,
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
      className={`flex flex-col h-full bg-surface-card rounded-lg border border-border-subtle overflow-hidden ${className}`}
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
                className="px-3 py-1.5 text-xs font-medium bg-accent-primary text-white rounded hover:bg-accent-primary/90 transition-colors"
              >
                Connect
              </button>
            ) : status === 'connected' ? (
              <button
                onClick={handleDisconnect}
                className="px-3 py-1.5 text-xs font-medium bg-status-error/10 text-status-error rounded hover:bg-status-error/20 transition-colors"
              >
                Disconnect
              </button>
            ) : null}
          </div>

          {/* Close button */}
          {onClose && (
            <button
              onClick={handleClose}
              className="p-1 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle rounded transition-colors"
              title="Close terminal"
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
                className="flex items-center gap-1 px-2 py-1 text-xs text-status-error hover:bg-status-error/10 rounded transition-colors"
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
        />

        {/* Connecting Overlay */}
        {status === 'connecting' && (
          <div className="absolute inset-0 bg-surface-card/80 backdrop-blur-sm flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-accent-primary" />
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
                className="px-4 py-2 text-sm font-medium bg-accent-primary text-white rounded hover:bg-accent-primary/90 transition-colors"
              >
                Retry Connection
              </button>
            </div>
          </div>
        )}

        {/* Exit Code Display */}
        {exitCode !== null && status === 'disconnected' && (
          <div className="absolute bottom-4 right-4 px-3 py-2 bg-surface-raised border border-border-subtle rounded-lg">
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
