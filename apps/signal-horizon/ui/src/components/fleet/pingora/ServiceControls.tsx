import { useState, useCallback, memo } from 'react';
import { RefreshCw, Play, RotateCw } from 'lucide-react';
import { clsx } from 'clsx';
import { Spinner } from '@/ui';

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
      <div className="flex items-center gap-3">
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
      </div>

      <div className="flex gap-2">
        <button
          onClick={() => handleAction('test')}
          disabled={status === 'running'}
          className="btn-outline h-8 px-3 text-xs flex items-center gap-2"
        >
          <Play className="w-3 h-3" />
          Test Config
        </button>
        <button
          onClick={() => handleAction('reload')}
          disabled={status === 'running'}
          className="btn-primary h-8 px-3 text-xs flex items-center gap-2"
        >
          {status === 'running' && lastAction === 'reload' ? (
            <Spinner size={12} color="#0057B7" />
          ) : (
            <RefreshCw className="w-3 h-3" />
          )}
          Reload
        </button>
        <button
          onClick={() => handleAction('restart')}
          disabled={status === 'running'}
          className="btn-outline h-8 px-3 text-xs flex items-center gap-2 text-ac-red border-ac-red/30 hover:bg-ac-red/5"
        >
          <RotateCw className="w-3 h-3" />
          Restart
        </button>
      </div>
    </div>
  );
});
