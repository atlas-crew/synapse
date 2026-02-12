import { useMemo, memo } from 'react';
import { Timer, Hourglass } from 'lucide-react';
import { clsx } from 'clsx';
import { parseIntSafe, parseFloatSafe } from '../../../utils/parseNumeric';
import type { TarpitConfig as SharedTarpitConfig } from '@signal-horizon/shared/types';
import { Alert, Stack } from '@/ui';

/**
 * Tarpit config data used by the UI form.
 * Based on shared TarpitConfig type but only includes fields exposed in the form.
 */
export type TarpitConfigData = Pick<
  SharedTarpitConfig,
  'enabled' | 'base_delay_ms' | 'max_delay_ms' | 'progressive_multiplier' | 'max_concurrent_tarpits' | 'decay_threshold_ms'
>;

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

export const TarpitConfig = memo(function TarpitConfig({ config, onChange }: TarpitConfigProps) {
  const validationErrors = useMemo(() => validateTarpitConfig(config), [config]);
  const hasErrors = Object.keys(validationErrors).length > 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Stack direction="row" align="center" gap="sm">
          <Hourglass className={clsx("w-5 h-5", config.enabled ? "text-ac-orange" : "text-ink-muted")} aria-hidden="true" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Tarpit (Slow-Drip Defense)</h3>
            <p className="text-xs text-ink-secondary">Progressive delays for suspicious actors</p>
          </div>
        </Stack>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
            aria-label="Enable Tarpit"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after: after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-orange"></div>
        </label>
      </div>

      {config.enabled && (
        <div className="space-y-4 border-t border-border-subtle pt-6">
          {hasErrors && (
            <Alert status="error" title="Configuration Error" style={{ padding: '10px 12px' }}>
              Configuration has validation errors
            </Alert>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <label htmlFor="tarpit-base-delay" className="text-xs font-medium text-ink-secondary">Base Delay (ms)</label>
              <input
                id="tarpit-base-delay"
                type="number"
                min="100"
                max="10000"
                value={config.base_delay_ms}
                onChange={(e) => onChange({
                  ...config,
                  base_delay_ms: parseIntSafe(e.target.value, config.base_delay_ms),
                })}
                aria-invalid={!!validationErrors.base_delay_ms}
                aria-describedby={validationErrors.base_delay_ms ? 'tarpit-base-delay-error' : undefined}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border  text-sm focus:outline-none transition-colors",
                  validationErrors.base_delay_ms
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.base_delay_ms && (
                <p id="tarpit-base-delay-error" className="text-xs text-status-error" aria-live="polite">
                  {validationErrors.base_delay_ms}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <label htmlFor="tarpit-max-delay" className="text-xs font-medium text-ink-secondary">Max Delay (ms)</label>
              <input
                id="tarpit-max-delay"
                type="number"
                min="1000"
                max="120000"
                value={config.max_delay_ms}
                onChange={(e) => onChange({
                  ...config,
                  max_delay_ms: parseIntSafe(e.target.value, config.max_delay_ms),
                })}
                aria-invalid={!!validationErrors.max_delay_ms}
                aria-describedby={validationErrors.max_delay_ms ? 'tarpit-max-delay-error' : undefined}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border  text-sm focus:outline-none transition-colors",
                  validationErrors.max_delay_ms
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.max_delay_ms && (
                <p id="tarpit-max-delay-error" className="text-xs text-status-error" aria-live="polite">
                  {validationErrors.max_delay_ms}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <label htmlFor="tarpit-multiplier" className="text-xs font-medium text-ink-secondary">Progressive Multiplier</label>
              <input
                id="tarpit-multiplier"
                type="number"
                min="1.0"
                max="3.0"
                step="0.1"
                value={config.progressive_multiplier}
                onChange={(e) => onChange({
                  ...config,
                  progressive_multiplier: parseFloatSafe(e.target.value, config.progressive_multiplier),
                })}
                aria-invalid={!!validationErrors.progressive_multiplier}
                aria-describedby={validationErrors.progressive_multiplier ? 'tarpit-multiplier-error' : undefined}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border  text-sm focus:outline-none transition-colors",
                  validationErrors.progressive_multiplier
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.progressive_multiplier && (
                <p id="tarpit-multiplier-error" className="text-xs text-status-error" aria-live="polite">
                  {validationErrors.progressive_multiplier}
                </p>
              )}
            </div>
            <div className="space-y-1">
              <label htmlFor="tarpit-max-concurrent" className="text-xs font-medium text-ink-secondary">Max Concurrent</label>
              <input
                id="tarpit-max-concurrent"
                type="number"
                min="100"
                max="10000"
                value={config.max_concurrent_tarpits}
                onChange={(e) => onChange({
                  ...config,
                  max_concurrent_tarpits: parseIntSafe(e.target.value, config.max_concurrent_tarpits),
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1 col-span-2">
              <label htmlFor="tarpit-decay-threshold" className="text-xs font-medium text-ink-secondary">Decay Threshold (minutes)</label>
              <input
                id="tarpit-decay-threshold"
                type="number"
                min="1"
                max="60"
                value={Math.round(config.decay_threshold_ms / 60000)}
                onChange={(e) => onChange({
                  ...config,
                  decay_threshold_ms: parseIntSafe(e.target.value, Math.round(config.decay_threshold_ms / 60000)) * 60000,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
          </div>

          <div className="p-3 bg-surface-subtle text-xs text-ink-muted">
            <Stack direction="row" align="center" gap="xs" className="mb-1">
              <Timer className="w-3 h-3" aria-hidden="true" />
              <span className="font-medium">Delay Formula:</span>
            </Stack>
            <code className="text-ac-blue">
              delay = min({config.base_delay_ms}ms × {config.progressive_multiplier}^level, {config.max_delay_ms}ms)
            </code>
          </div>
        </div>
      )}
    </div>
  );
});
