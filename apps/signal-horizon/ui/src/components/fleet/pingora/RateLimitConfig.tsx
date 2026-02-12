import { memo } from 'react';
import { Activity } from 'lucide-react';
import { clsx } from 'clsx';
import { Stack } from '@/ui';

export interface RateLimitData {
  enabled: boolean;
  requests_per_second: number;
  burst: number;
}

interface RateLimitConfigProps {
  config: RateLimitData;
  onChange: (config: RateLimitData) => void;
}

export const RateLimitConfig = memo(function RateLimitConfig({ config, onChange }: RateLimitConfigProps) {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Stack direction="row" align="center" gap="sm">
          <Activity className={clsx("w-5 h-5", config.enabled ? "text-ac-blue" : "text-ink-muted")} aria-hidden="true" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Rate Limiting</h3>
            <p className="text-xs text-ink-secondary">Global request throttling</p>
          </div>
        </Stack>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
            aria-label="Enable Rate Limiting"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after: after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-blue"></div>
        </label>
      </div>

      {config.enabled && (
        <div className="grid grid-cols-2 gap-4 border-t border-border-subtle pt-6">
          <div className="space-y-1">
            <label htmlFor="rate-limit-rps" className="text-xs font-medium text-ink-secondary">Requests / Sec</label>
            <input
              id="rate-limit-rps"
              type="number"
              min="1"
              value={config.requests_per_second}
              onChange={(e) => onChange({ ...config, requests_per_second: parseInt(e.target.value) || 1 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-1">
            <label htmlFor="rate-limit-burst" className="text-xs font-medium text-ink-secondary">Burst Capacity</label>
            <input
              id="rate-limit-burst"
              type="number"
              min="1"
              value={config.burst}
              onChange={(e) => onChange({ ...config, burst: parseInt(e.target.value) || 1 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          
          <div className="col-span-2 p-3 bg-surface-subtle text-xs text-ink-muted">
            Allows <strong className="text-ink-primary">{config.requests_per_second} RPS</strong> sustained, 
            with spikes up to <strong className="text-ink-primary">{config.burst} requests</strong>.
          </div>
        </div>
      )}
    </div>
  );
});
