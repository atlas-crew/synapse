/**
 * ServiceControlPanel Component
 * Control panel for managing sensor service lifecycle (reload, restart, shutdown, drain/resume)
 */

import { memo, useState, useCallback, useEffect, useRef } from 'react';
import {
  RefreshCw,
  RotateCw,
  Power,
  Pause,
  Play,
  Activity,
  AlertTriangle,
  X,
  Clock,
  Wifi,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useServiceControl, type ServiceState, type ControlCommand, type ControlResult } from '../../hooks/fleet/useServiceControl';
import { Modal, Spinner, Stack } from '@/ui';

export interface ServiceControlPanelProps {
  /** Target sensor ID */
  sensorId: string;
  /** Display name for the sensor */
  sensorName: string;
  /** Additional CSS classes */
  className?: string;
  /** Compact layout for sidebars */
  compact?: boolean;
  /** Callback when a command completes */
  onCommandComplete?: (result: ControlResult) => void;
}

/** State badge configuration */
const stateConfig: Record<ServiceState, { label: string; icon: React.ReactNode; className: string }> = {
  running: {
    label: 'Running',
    icon: <Activity className="w-3.5 h-3.5" />,
    className: 'text-status-success bg-status-success/10 border-status-success/30',
  },
  draining: {
    label: 'Draining',
    icon: <Pause className="w-3.5 h-3.5" />,
    className: 'text-status-warning bg-status-warning/10 border-status-warning/30',
  },
  restarting: {
    label: 'Restarting',
    icon: <Spinner size={14} color="#0057B7" />,
    className: 'text-ac-blue bg-ac-blue/10 border-ac-blue/30',
  },
  shutting_down: {
    label: 'Shutting Down',
    icon: <Power className="w-3.5 h-3.5" />,
    className: 'text-status-error bg-status-error/10 border-status-error/30',
  },
};

/** Format uptime duration */
function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (hours < 24) return `${hours}h ${mins}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

/** Confirmation dialog component */
interface ConfirmationDialogProps {
  isOpen: boolean;
  title: string;
  message: string;
  warningMessage?: string;
  confirmText: string;
  requireTypedConfirmation?: string;
  onConfirm: () => void;
  onCancel: () => void;
  isExecuting?: boolean;
}

const ConfirmationDialog = memo(function ConfirmationDialog({
  isOpen,
  title,
  message,
  warningMessage,
  confirmText,
  requireTypedConfirmation,
  onConfirm,
  onCancel,
  isExecuting = false,
}: ConfirmationDialogProps) {
  const [typedValue, setTypedValue] = useState('');
  const [countdown, setCountdown] = useState(30);
  const inputRef = useRef<HTMLInputElement>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Reset state when dialog opens/closes
  useEffect(() => {
    if (isOpen) {
      setTypedValue('');
      setCountdown(30);
      // Focus input after dialog opens
      setTimeout(() => inputRef.current?.focus(), 100);

      // Start countdown timer
      countdownRef.current = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            onCancel();
            return 30;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
        countdownRef.current = null;
      }
    };
  }, [isOpen, onCancel]);

  // Handle keyboard shortcuts
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onCancel();
      } else if (e.key === 'Enter' && !requireTypedConfirmation) {
        onConfirm();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onConfirm, onCancel, requireTypedConfirmation]);

  if (!isOpen) return null;

  const isConfirmEnabled = !requireTypedConfirmation ||
    typedValue.toLowerCase() === requireTypedConfirmation.toLowerCase();

  return (
    <Modal open onClose={onCancel} size="520px" title={title}>
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-status-warning" />
          <p className="text-sm text-ink-secondary">{message}</p>
        </div>

        {warningMessage && (
          <div className="flex items-start gap-2 p-3 bg-status-warning/10 border border-status-warning/20">
            <AlertTriangle className="w-4 h-4 text-status-warning shrink-0 mt-0.5" />
            <p className="text-xs text-status-warning">{warningMessage}</p>
          </div>
        )}

        {requireTypedConfirmation && (
          <div className="space-y-2">
            <label className="block text-xs text-ink-muted">
              Type <span className="font-mono font-semibold text-ink-primary">{requireTypedConfirmation}</span> to confirm
            </label>
            <input
              ref={inputRef}
              type="text"
              value={typedValue}
              onChange={(e) => setTypedValue(e.target.value)}
              placeholder={requireTypedConfirmation}
              className="w-full px-3 py-2 text-sm bg-surface-inset border border-border-subtle text-ink-primary placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-accent-primary/50"
              disabled={isExecuting}
            />
          </div>
        )}

        <div className="flex items-center justify-center gap-1 text-xs text-ink-muted">
          <Clock className="w-3 h-3" />
          <span>Auto-cancel in {countdown}s</span>
        </div>
      </div>

      <Modal.Footer>
        <div className="flex items-center justify-end gap-2 w-full">
          <button
            onClick={onCancel}
            disabled={isExecuting}
            className="px-4 py-2 text-sm font-medium text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!isConfirmEnabled || isExecuting}
            className={clsx(
              'px-4 py-2 text-sm font-medium transition-colors flex items-center gap-2',
              'bg-status-error text-white hover:bg-status-error/90',
              'disabled:opacity-50 disabled:cursor-not-allowed'
            )}
          >
            {isExecuting && <Spinner size={14} color="#FFFFFF" />}
            {confirmText}
          </button>
        </div>
      </Modal.Footer>
    </Modal>
  );
});

/** Toast notification component */
interface ToastProps {
  message: string;
  type: 'success' | 'error' | 'info';
  onClose: () => void;
}

const Toast = memo(function Toast({ message, type, onClose }: ToastProps) {
  useEffect(() => {
    const timer = setTimeout(onClose, 4000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const typeConfig = {
    success: 'bg-status-success/10 border-status-success/30 text-status-success',
    error: 'bg-status-error/10 border-status-error/30 text-status-error',
    info: 'bg-ac-blue/10 border-ac-blue/30 text-ac-blue',
  };

  return (
    <div
      className={clsx(
        'fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-3 border shadow-lg',
        typeConfig[type]
      )}
    >
      <span className="text-sm font-medium">{message}</span>
      <button
        onClick={onClose}
        className="p-0.5 hover:bg-black/10 transition-colors"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  );
});

/**
 * Service Control Panel for managing sensor lifecycle
 */
export const ServiceControlPanel = memo(function ServiceControlPanel({
  sensorId,
  sensorName,
  className = '',
  compact = false,
  onCommandComplete,
}: ServiceControlPanelProps) {
  // Confirmation dialog state
  const [confirmDialog, setConfirmDialog] = useState<{
    command: ControlCommand;
    title: string;
    message: string;
    warningMessage?: string;
    confirmText: string;
    requireTypedConfirmation?: string;
  } | null>(null);

  // Toast state
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);

  // Service control hook
  const {
    state,
    activeConnections,
    uptime,
    isExecuting,
    executingCommand,
    error,
    isLoading,
    lastConfigReload,
    reload,
    restart,
    shutdown,
    drain,
    resume,
    refreshState,
    clearError,
  } = useServiceControl({
    sensorId,
    onCommandComplete: (result) => {
      // Show toast notification
      setToast({
        message: result.message,
        type: result.success ? 'success' : 'error',
      });
      onCommandComplete?.(result);
    },
    onError: (err) => {
      setToast({
        message: err.message,
        type: 'error',
      });
    },
  });

  // Get current state configuration
  const currentStateConfig = stateConfig[state];

  /**
   * Handle reload button click
   */
  const handleReload = useCallback(async () => {
    await reload();
  }, [reload]);

  /**
   * Handle restart button click - open confirmation dialog
   */
  const handleRestartClick = useCallback(() => {
    setConfirmDialog({
      command: 'restart',
      title: 'Confirm Graceful Restart',
      message: `Are you sure you want to restart the service on ${sensorName}? This will briefly interrupt active connections.`,
      warningMessage: 'Active connections will be gracefully terminated before restart.',
      confirmText: 'Restart Service',
    });
  }, [sensorName]);

  /**
   * Handle shutdown button click - open confirmation dialog with typed confirmation
   */
  const handleShutdownClick = useCallback(() => {
    setConfirmDialog({
      command: 'shutdown',
      title: 'Confirm Service Shutdown',
      message: `This will completely shut down the service on ${sensorName}. The sensor will become unavailable until manually restarted.`,
      warningMessage: 'This action will make the sensor unavailable. Manual intervention will be required to restart.',
      confirmText: 'Shutdown Service',
      requireTypedConfirmation: 'CONFIRM',
    });
  }, [sensorName]);

  /**
   * Handle drain button click
   */
  const handleDrain = useCallback(async () => {
    await drain();
  }, [drain]);

  /**
   * Handle resume button click
   */
  const handleResume = useCallback(async () => {
    await resume();
  }, [resume]);

  /**
   * Handle confirmation dialog confirm
   */
  const handleConfirm = useCallback(async () => {
    if (!confirmDialog) return;

    const { command } = confirmDialog;

    if (command === 'restart') {
      await restart(true);
    } else if (command === 'shutdown') {
      await shutdown(true);
    }

    setConfirmDialog(null);
  }, [confirmDialog, restart, shutdown]);

  /**
   * Handle confirmation dialog cancel
   */
  const handleCancelDialog = useCallback(() => {
    setConfirmDialog(null);
  }, []);

  /**
   * Handle toast close
   */
  const handleToastClose = useCallback(() => {
    setToast(null);
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Only handle if not in an input field
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      // Ctrl+R for reload (prevent browser refresh)
      if (e.ctrlKey && e.key === 'r') {
        e.preventDefault();
        if (!isExecuting && state === 'running') {
          handleReload();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isExecuting, state, handleReload]);

  // Clear error on unmount
  useEffect(() => {
    return () => {
      clearError();
    };
  }, [clearError]);

  // Loading state
  if (isLoading) {
    return (
      <div className={clsx('bg-surface-card border border-border-subtle', className)}>
        <div className="flex items-center justify-center p-6">
          <Spinner size={24} color="#7F7F7F" />
        </div>
      </div>
    );
  }

  return (
    <>
      <div
        className={clsx(
          'bg-surface-card border border-border-subtle overflow-hidden',
          className
        )}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-surface-raised border-b border-border-subtle">
          <h3 className="text-sm font-semibold text-ink-primary">Service Control</h3>
          <button
            onClick={refreshState}
            disabled={isExecuting}
            className="p-1.5 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle transition-colors disabled:opacity-50"
            title="Refresh status"
          >
            {isExecuting ? <Spinner size={16} color="#7F7F7F" /> : <RefreshCw className="w-4 h-4" />}
          </button>
        </div>

        {/* Status Section */}
        <div className={clsx('p-4 space-y-4', compact && 'p-3 space-y-3')}>
          {/* State Badge and Connections */}
          <Stack
            direction={compact ? 'column' : 'row'}
            align={compact ? 'flex-start' : 'center'}
            justify="space-between"
            gap="sm"
          >
            {/* State Badge */}
            <div
              className={clsx(
                'inline-flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium border',
                currentStateConfig.className
              )}
            >
              {currentStateConfig.icon}
              <span>{currentStateConfig.label}</span>
            </div>

            {/* Active Connections */}
            <div className="flex items-center gap-1.5 text-xs text-ink-secondary">
              <Wifi className="w-3.5 h-3.5" />
              <span>
                {activeConnections} connection{activeConnections !== 1 ? 's' : ''}
              </span>
            </div>
          </Stack>

          {/* Uptime and Last Reload */}
          <div className={clsx('grid gap-3', compact ? 'grid-cols-1' : 'grid-cols-2')}>
            <div className="flex items-center gap-2">
              <Clock className="w-4 h-4 text-ink-muted" />
              <div>
                <div className="text-xs text-ink-muted">Uptime</div>
                <div className="text-sm font-medium text-ink-primary">
                  {formatUptime(uptime)}
                </div>
              </div>
            </div>

            {lastConfigReload && (
              <div className="flex items-center gap-2">
                <RefreshCw className="w-4 h-4 text-ink-muted" />
                <div>
                  <div className="text-xs text-ink-muted">Last Config Reload</div>
                  <div className="text-sm font-medium text-ink-primary">
                    {lastConfigReload.toLocaleTimeString()}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Error Display */}
          {error && (
            <div className="flex items-start gap-2 p-3 bg-status-error/10 border border-status-error/20">
              <AlertTriangle className="w-4 h-4 text-status-error shrink-0 mt-0.5" />
              <div className="flex-1">
                <p className="text-xs text-status-error">{error.message}</p>
              </div>
              <button
                onClick={clearError}
                className="p-0.5 text-status-error hover:bg-status-error/10 transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}

          {/* Control Buttons */}
          <div className={clsx('grid gap-2', compact ? 'grid-cols-2' : 'grid-cols-4')}>
            {/* Reload Config */}
            <button
              onClick={handleReload}
              disabled={isExecuting || state === 'shutting_down'}
              className={clsx(
                'flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium transition-colors',
                'bg-ac-blue/10 text-ac-blue border border-ac-blue/30',
                'hover:bg-ac-blue/20 disabled:opacity-50 disabled:cursor-not-allowed'
              )}
              title="Reload configuration without restart (Ctrl+R)"
            >
              {executingCommand === 'reload' ? (
                <Spinner size={16} color="#0057B7" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              <span className={clsx(compact && 'hidden sm:inline')}>Reload</span>
            </button>

            {/* Drain / Resume Toggle */}
            {state === 'draining' ? (
              <button
                onClick={handleResume}
                disabled={isExecuting}
                className={clsx(
                  'flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium transition-colors',
                  'bg-status-success/10 text-status-success border border-status-success/30',
                  'hover:bg-status-success/20 disabled:opacity-50 disabled:cursor-not-allowed'
                )}
                title="Resume accepting connections"
              >
                {executingCommand === 'resume' ? (
                  <Spinner size={16} color="#00B140" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
                <span className={clsx(compact && 'hidden sm:inline')}>Resume</span>
              </button>
            ) : (
              <button
                onClick={handleDrain}
                disabled={isExecuting || state === 'shutting_down' || state === 'restarting'}
                className={clsx(
                  'flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium transition-colors',
                  'bg-status-warning/10 text-status-warning border border-status-warning/30',
                  'hover:bg-status-warning/20 disabled:opacity-50 disabled:cursor-not-allowed'
                )}
                title="Stop accepting new connections"
              >
                {executingCommand === 'drain' ? (
                  <Spinner size={16} color="#E35205" />
                ) : (
                  <Pause className="w-4 h-4" />
                )}
                <span className={clsx(compact && 'hidden sm:inline')}>Drain</span>
              </button>
            )}

            {/* Graceful Restart */}
            <button
              onClick={handleRestartClick}
              disabled={isExecuting || state === 'shutting_down'}
              className={clsx(
                'flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium transition-colors',
                'bg-ac-orange/10 text-ac-orange border border-ac-orange/30',
                'hover:bg-ac-orange/20 disabled:opacity-50 disabled:cursor-not-allowed'
              )}
              title="Graceful restart (requires confirmation)"
            >
              {executingCommand === 'restart' ? (
                <Spinner size={16} color="#E35205" />
              ) : (
                <RotateCw className="w-4 h-4" />
              )}
              <span className={clsx(compact && 'hidden sm:inline')}>Restart</span>
            </button>

            {/* Shutdown */}
            <button
              onClick={handleShutdownClick}
              disabled={isExecuting || state === 'shutting_down'}
              className={clsx(
                'flex items-center justify-center gap-2 px-3 py-2 text-xs font-medium transition-colors',
                'bg-status-error/10 text-status-error border border-status-error/30',
                'hover:bg-status-error/20 disabled:opacity-50 disabled:cursor-not-allowed'
              )}
              title="Shutdown service (requires confirmation)"
            >
              {executingCommand === 'shutdown' ? (
                <Spinner size={16} color="#EF3340" />
              ) : (
                <Power className="w-4 h-4" />
              )}
              <span className={clsx(compact && 'hidden sm:inline')}>Shutdown</span>
            </button>
          </div>

          {/* Connection count during drain */}
          {state === 'draining' && activeConnections > 0 && (
            <div className="flex items-center justify-center gap-2 py-2 px-3 bg-status-warning/5 border border-status-warning/20">
              <Spinner size={14} color="#E35205" />
              <span className="text-xs text-status-warning">
                Draining {activeConnections} active connection{activeConnections !== 1 ? 's' : ''}...
              </span>
            </div>
          )}
        </div>

        {/* Footer with keyboard shortcuts hint */}
        {!compact && (
          <div className="px-4 py-2 bg-surface-raised border-t border-border-subtle">
            <p className="text-xs text-ink-muted">
              Keyboard: Ctrl+R to reload configuration
            </p>
          </div>
        )}
      </div>

      {/* Confirmation Dialog */}
      {confirmDialog && (
        <ConfirmationDialog
          isOpen={true}
          title={confirmDialog.title}
          message={confirmDialog.message}
          warningMessage={confirmDialog.warningMessage}
          confirmText={confirmDialog.confirmText}
          requireTypedConfirmation={confirmDialog.requireTypedConfirmation}
          onConfirm={handleConfirm}
          onCancel={handleCancelDialog}
          isExecuting={isExecuting && (executingCommand === 'restart' || executingCommand === 'shutdown')}
        />
      )}

      {/* Toast Notification */}
      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onClose={handleToastClose}
        />
      )}
    </>
  );
});

export default ServiceControlPanel;
