import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Maximize2,
  Minimize2,
  RefreshCw,
  ExternalLink,
  AlertCircle,
  Wifi,
  WifiOff,
} from 'lucide-react';
import clsx from 'clsx';
import { Spinner, Stack, colors } from '@/ui';

export interface EmbeddedDashboardProps {
  sensorId: string;
  sessionId?: string;
  tunnelMode?: boolean;
  height?: string | number;
  onLoad?: () => void;
  onError?: (error: Error) => void;
}

interface DashboardState {
  loading: boolean;
  error: Error | null;
  content: string | null;
  connected: boolean;
  fullscreen: boolean;
}

export function EmbeddedDashboard({
  sensorId,
  sessionId,
  tunnelMode = true,
  height = 600,
  onLoad,
  onError,
}: EmbeddedDashboardProps) {
  const [state, setState] = useState<DashboardState>({
    loading: true,
    error: null,
    content: null,
    connected: false,
    fullscreen: false,
  });

  const iframeRef = useRef<HTMLIFrameElement>(null);

  const fetchDashboardContent = useCallback(async () => {
    setState((prev) => ({ ...prev, loading: true, error: null }));

    try {
      const url = `/api/v1/tunnel/proxy/${sessionId || sensorId}`;
      const response = await fetch(url);

      if (!response.ok) {
        throw new Error(`Failed to fetch dashboard: ${response.statusText}`);
      }

      const html = await response.text();
      setState((prev) => ({
        ...prev,
        loading: false,
        content: html,
        connected: true,
        error: null,
      }));
      onLoad?.();
    } catch (error) {
      const err = error instanceof Error ? error : new Error('Unknown error');
      setState((prev) => ({
        ...prev,
        loading: false,
        error: err,
        connected: false,
      }));
      onError?.(err);
    }
  }, [sessionId, sensorId, onLoad, onError]);

  useEffect(() => {
    if (tunnelMode) {
      fetchDashboardContent();
    } else {
      setState((prev) => ({ ...prev, loading: false, connected: true }));
      onLoad?.();
    }
  }, [tunnelMode, fetchDashboardContent, onLoad]);

  const handleIframeLoad = () => {
    if (!tunnelMode) {
      setState((prev) => ({ ...prev, loading: false, connected: true }));
      onLoad?.();
    }
  };

  const handleIframeError = () => {
    const error = new Error('Failed to load dashboard in iframe');
    setState((prev) => ({
      ...prev,
      loading: false,
      error,
      connected: false,
    }));
    onError?.(error);
  };

  const toggleFullscreen = () => {
    setState((prev) => ({ ...prev, fullscreen: !prev.fullscreen }));
  };

  const handleRefresh = () => {
    if (tunnelMode) {
      fetchDashboardContent();
    } else if (iframeRef.current) {
      iframeRef.current.src = iframeRef.current.src;
    }
  };

  const handleRetry = () => {
    setState((prev) => ({ ...prev, error: null, loading: true }));
    if (tunnelMode) {
      fetchDashboardContent();
    } else if (iframeRef.current) {
      iframeRef.current.src = iframeRef.current.src;
    }
  };

  const handleOpenExternal = () => {
    const url = tunnelMode
      ? `/api/v1/tunnel/proxy/${sessionId || sensorId}`
      : iframeRef.current?.src;
    if (url) window.open(url, '_blank');
  };

  const normalizedHeight = typeof height === 'number' ? `${height}px` : height;

  return (
    <div
      className={clsx(
        'bg-surface-card border border-border-subtle overflow-hidden',
        state.fullscreen && 'z-50'
      )}
      style={state.fullscreen ? { position: 'fixed', inset: 0 } : undefined}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-surface-raised border-b border-border-subtle">
        <div className="space-y-0.5">
          <h3 className="text-sm font-medium text-ink-primary">Sensor Dashboard</h3>
          <p className="text-xs text-ink-secondary">
            {tunnelMode ? 'Tunnel Mode' : 'Direct Mode'} • Sensor {sensorId}
          </p>
        </div>

        <Stack direction="row" align="center" gap="sm">
          {/* Connection Status */}
          <Stack direction="row" align="center" gap="xsPlus" className="text-sm mr-2">
            {state.connected ? (
              <>
                <Wifi className="h-4 w-4 text-status-success" />
                <span className="text-ink-secondary">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="h-4 w-4 text-status-error" />
                <span className="text-ink-secondary">Disconnected</span>
              </>
            )}
          </Stack>

          {/* Action Buttons */}
          <button
            onClick={handleRefresh}
            disabled={state.loading}
            className="p-2 hover:bg-surface-subtle disabled:opacity-50"
            title="Refresh Dashboard"
          >
            {state.loading ? (
              <Spinner size={16} color={colors.gray.mid} />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
          </button>

          <button
            onClick={handleOpenExternal}
            className="p-2 hover:bg-surface-subtle"
            title="Open in New Tab"
          >
            <ExternalLink className="h-4 w-4" />
          </button>

          <button
            onClick={toggleFullscreen}
            className="p-2 hover:bg-surface-subtle"
            title={state.fullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
          >
            {state.fullscreen ? (
              <Minimize2 className="h-4 w-4" />
            ) : (
              <Maximize2 className="h-4 w-4" />
            )}
          </button>
        </Stack>
      </div>

      {/* Content */}
      <div className="p-0">
        {/* Error State */}
        {state.error && (
          <div className="p-6">
            <div className="bg-status-error/10 border border-status-error/20 p-4">
              <Stack direction="row" align="center" gap="sm" className="text-status-error">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span className="flex-1">{state.error.message}</span>
                <button
                  onClick={handleRetry}
                  className="px-3 py-1 text-sm border border-status-error/30 hover:bg-status-error/10"
                >
                  Retry
                </button>
              </Stack>
            </div>
          </div>
        )}

        {/* Loading State */}
        {state.loading && !state.error && (
          <div
            className="flex items-center justify-center bg-surface-subtle"
            style={{ height: normalizedHeight }}
          >
            <Stack direction="column" align="center" style={{ gap: '12px' }}>
              <Spinner size={32} color={colors.gray.mid} />
              <p className="text-sm text-ink-secondary">Loading dashboard...</p>
            </Stack>
          </div>
        )}

        {/* Dashboard Iframe */}
        {!state.loading && !state.error && (
          <div className="border-t border-border-subtle">
            <iframe
              ref={iframeRef}
              src={tunnelMode ? undefined : `/api/v1/sensors/${sensorId}/dashboard-url`}
              srcDoc={tunnelMode ? state.content ?? undefined : undefined}
              title={`Sensor ${sensorId} Dashboard`}
              className="w-full border-0"
              style={{
                height: state.fullscreen ? 'calc(100vh - 60px)' : normalizedHeight,
              }}
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
              onLoad={handleIframeLoad}
              onError={handleIframeError}
            />
          </div>
        )}
      </div>
    </div>
  );
}
