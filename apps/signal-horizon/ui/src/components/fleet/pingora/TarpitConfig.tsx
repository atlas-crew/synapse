import { useMemo } from 'react';
import { Timer, Hourglass, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';

export interface TarpitConfigData {
  enabled: boolean;
  base_delay_ms: number;
  max_delay_ms: number;
  progressive_multiplier: number;
  max_concurrent_tarpits: number;
  decay_threshold_ms: number;
}

interface TarpitConfigProps {
  config: TarpitConfigData;
  onChange: (config: TarpitConfigData) => void;
}

interface ValidationErrors {
  base_delay_ms?: string;
  max_delay_ms?: string;
  progressive_multiplier?: string;
}

function validateTarpitConfig(config: TarpitConfigData): ValidationErrors {
  const errors: ValidationErrors = {};

  if (config.base_delay_ms >= config.max_delay_ms) {
    errors.base_delay_ms = 'Base delay must be less than max delay';
    errors.max_delay_ms = 'Max delay must be greater than base delay';
  }

  if (config.progressive_multiplier <= 0) {
    errors.progressive_multiplier = 'Multiplier must be greater than 0';
  }

  if (config.progressive_multiplier < 1) {
    errors.progressive_multiplier = 'Multiplier should be >= 1 for progressive delay';
  }

  return errors;
}

export function TarpitConfig({ config, onChange }: TarpitConfigProps) {
  const validationErrors = useMemo(() => validateTarpitConfig(config), [config]);
  const hasErrors = Object.keys(validationErrors).length > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Hourglass className={clsx("w-5 h-5", config.enabled ? "text-ac-orange" : "text-ink-muted")} />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Tarpit (Slow-Drip Defense)</h3>
            <p className="text-xs text-ink-secondary">Progressive delays for suspicious actors</p>
          </div>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-orange"></div>
        </label>
      </div>

      {config.enabled && (
        <div className="space-y-4 border-t border-border-subtle pt-6">
          {hasErrors && (
            <div className="flex items-center gap-2 p-3 bg-status-error/10 border border-status-error/20 rounded-lg">
              <AlertTriangle className="w-4 h-4 text-status-error flex-shrink-0" />
              <span className="text-xs text-status-error">Configuration has validation errors</span>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Base Delay (ms)</label>
              <input
                type="number"
                min="100"
                max="10000"
                value={config.base_delay_ms}
                onChange={(e) => onChange({ ...config, base_delay_ms: parseInt(e.target.value) || 1000 })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.base_delay_ms
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.base_delay_ms && (
                <p className="text-xs text-status-error">{validationErrors.base_delay_ms}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Delay (ms)</label>
              <input
                type="number"
                min="1000"
                max="120000"
                value={config.max_delay_ms}
                onChange={(e) => onChange({ ...config, max_delay_ms: parseInt(e.target.value) || 30000 })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.max_delay_ms
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.max_delay_ms && (
                <p className="text-xs text-status-error">{validationErrors.max_delay_ms}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Progressive Multiplier</label>
              <input
                type="number"
                min="1.0"
                max="3.0"
                step="0.1"
                value={config.progressive_multiplier}
                onChange={(e) => onChange({ ...config, progressive_multiplier: parseFloat(e.target.value) || 1.5 })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.progressive_multiplier
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.progressive_multiplier && (
                <p className="text-xs text-status-error">{validationErrors.progressive_multiplier}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Concurrent</label>
              <input
                type="number"
                min="100"
                max="10000"
                value={config.max_concurrent_tarpits}
                onChange={(e) => onChange({ ...config, max_concurrent_tarpits: parseInt(e.target.value) || 1000 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1 col-span-2">
              <label className="text-xs font-medium text-ink-secondary">Decay Threshold (minutes)</label>
              <input
                type="number"
                min="1"
                max="60"
                value={Math.round(config.decay_threshold_ms / 60000)}
                onChange={(e) => onChange({ ...config, decay_threshold_ms: (parseInt(e.target.value) || 5) * 60000 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
          </div>

          <div className="p-3 bg-surface-subtle rounded text-xs text-ink-muted">
            <div className="flex items-center gap-1 mb-1">
              <Timer className="w-3 h-3" />
              <span className="font-medium">Delay Formula:</span>
            </div>
            <code className="text-ac-blue">
              delay = min({config.base_delay_ms}ms × {config.progressive_multiplier}^level, {config.max_delay_ms}ms)
            </code>
          </div>
        </div>
      )}
    </div>
  );
}
