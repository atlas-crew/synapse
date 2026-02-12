import { useState, useCallback, memo } from 'react';
import { RefreshCw, Play, RotateCw } from 'lucide-react';
import { clsx } from 'clsx';
import { Spinner, Stack } from '@/ui';

interface ServiceControlsProps {
  onAction: (action: 'test' | 'reload' | 'restart') => Promise<void>;
}

export const ServiceControls = memo(function ServiceControls({ onAction }: ServiceControlsProps) {
  const [status, setStatus] = useState<'idle' | 'running' | 'success' | 'error'>('idle');
  const [lastAction, setLastAction] = useState<string | null>(null);

  const handleAction = useCallback(async (action: 'test' | 'reload' | 'restart') => {
    setStatus('running');
    setLastAction(action);
    try {
      await onAction(action);
      setStatus('success');
      setTimeout(() => setStatus('idle'), 3000);
    } catch {
      setStatus('error');
    }
  }, [onAction]);

  return (
    <div className="flex items-center justify-between bg-surface-subtle p-4 border border-border-subtle">
      <Stack direction="row" align="center" gap="md">
        <div className={clsx(
          "w-2 h-2 ",
          status === 'running' ? "bg-ac-blue animate-pulse" :
          status === 'success' ? "bg-ac-green" :
          status === 'error' ? "bg-ac-red" :
          "bg-ink-muted"
        )} />
        <span className="text-sm font-medium text-ink-primary">
          {status === 'running' ? `${lastAction}ing...` : 
           status === 'success' ? `${lastAction}ed successfully` : 
           status === 'error' ? `${lastAction} failed` : 
           "Service Ready"}
        </span>
      </Stack>

      <div className="flex gap-2">
        <button
          onClick={() => handleAction('test')}
          disabled={status === 'running'}
          className="btn-outline h-8 px-3 text-xs"
        >
          <Stack direction="row" align="center" gap="sm">
            <Play className="w-3 h-3" />
            <span>Test Config</span>
          </Stack>
        </button>
        <button
          onClick={() => handleAction('reload')}
          disabled={status === 'running'}
          className="btn-primary h-8 px-3 text-xs"
        >
          <Stack direction="row" align="center" gap="sm">
            {status === 'running' && lastAction === 'reload' ? (
              <Spinner size={12} color="#0057B7" />
            ) : (
              <RefreshCw className="w-3 h-3" />
            )}
            <span>Reload</span>
          </Stack>
        </button>
        <button
          onClick={() => handleAction('restart')}
          disabled={status === 'running'}
          className="btn-outline h-8 px-3 text-xs text-ac-red border-ac-red/30 hover:bg-ac-red/5"
        >
          <Stack direction="row" align="center" gap="sm">
            <RotateCw className="w-3 h-3" />
            <span>Restart</span>
          </Stack>
        </button>
      </div>
    </div>
  );
});
