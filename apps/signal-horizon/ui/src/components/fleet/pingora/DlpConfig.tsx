import { useMemo, useCallback } from 'react';
import { Eye, Zap, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
// Note: DEFAULT_* constants removed since parseIntSafe uses current value as fallback
import { parseIntSafe } from '../../../utils/parseNumeric';

export interface DlpConfigData {
  enabled: boolean;
  fast_mode: boolean;
  scan_text_only: boolean;
  max_scan_size: number;
  max_body_inspection_bytes: number;
  max_matches: number;
  custom_keywords: string[];
}

interface DlpConfigProps {
  config: DlpConfigData;
  onChange: (config: DlpConfigData) => void;
}

interface ValidationErrors {
  max_scan_size?: string;
  max_body_inspection_bytes?: string;
}

function validateDlpConfig(config: DlpConfigData): ValidationErrors {
  const errors: ValidationErrors = {};

  if (config.max_body_inspection_bytes > config.max_scan_size) {
    errors.max_body_inspection_bytes = 'Inspect bytes cannot exceed max scan size';
    errors.max_scan_size = 'Max scan size must be >= inspect bytes';
  }

  return errors;
}

export function DlpConfig({ config, onChange }: DlpConfigProps) {
  const validationErrors = useMemo(() => validateDlpConfig(config), [config]);
  const hasErrors = Object.keys(validationErrors).length > 0;

  const handleKeywordsChange = useCallback((value: string) => {
    const keywords = value.split(',').map(k => k.trim()).filter(k => k.length > 0);
    onChange({ ...config, custom_keywords: keywords });
  }, [config, onChange]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Eye className={clsx("w-5 h-5", config.enabled ? "text-ac-magenta" : "text-ink-muted")} />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">DLP Scanner</h3>
            <p className="text-xs text-ink-secondary">Data Loss Prevention - detect sensitive data</p>
          </div>
        </div>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-magenta"></div>
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

          {/* Mode toggles */}
          <div className="flex flex-wrap gap-4">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.fast_mode}
                onChange={(e) => onChange({ ...config, fast_mode: e.target.checked })}
                className="w-4 h-4 rounded border-border-subtle text-ac-blue focus:ring-ac-blue/20"
              />
              <div className="flex items-center gap-1">
                <Zap className="w-3 h-3 text-ac-orange" />
                <span className="text-xs text-ink-secondary">Fast Mode (critical patterns only)</span>
              </div>
            </label>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={config.scan_text_only}
                onChange={(e) => onChange({ ...config, scan_text_only: e.target.checked })}
                className="w-4 h-4 rounded border-border-subtle text-ac-blue focus:ring-ac-blue/20"
              />
              <span className="text-xs text-ink-secondary">Scan text content only</span>
            </label>
          </div>

          {/* Numeric inputs */}
          <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Scan Size (MB)</label>
              <input
                type="number"
                min="1"
                max="50"
                value={Math.round(config.max_scan_size / (1024 * 1024))}
                onChange={(e) => onChange({
                  ...config,
                  max_scan_size: parseIntSafe(e.target.value, Math.round(config.max_scan_size / (1024 * 1024))) * 1024 * 1024,
                })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.max_scan_size
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.max_scan_size && (
                <p className="text-xs text-status-error">{validationErrors.max_scan_size}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Inspect Bytes (KB)</label>
              <input
                type="number"
                min="1"
                max="64"
                value={Math.round(config.max_body_inspection_bytes / 1024)}
                onChange={(e) => onChange({
                  ...config,
                  max_body_inspection_bytes: parseIntSafe(e.target.value, Math.round(config.max_body_inspection_bytes / 1024)) * 1024,
                })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.max_body_inspection_bytes
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.max_body_inspection_bytes && (
                <p className="text-xs text-status-error">{validationErrors.max_body_inspection_bytes}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Matches</label>
              <input
                type="number"
                min="10"
                max="1000"
                value={config.max_matches}
                onChange={(e) => onChange({
                  ...config,
                  max_matches: parseIntSafe(e.target.value, config.max_matches),
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
          </div>

          {/* Custom keywords */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Custom Keywords (comma-separated)</label>
            <input
              type="text"
              value={config.custom_keywords.join(', ')}
              onChange={(e) => handleKeywordsChange(e.target.value)}
              placeholder="project-alpha, confidential, internal-only"
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm font-mono focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>

          <div className="p-3 bg-surface-subtle rounded text-xs text-ink-muted">
            Detects: Credit cards, SSN, API keys, AWS credentials, passwords, private keys, JWT, IBAN, medical records
          </div>
        </div>
      )}
    </div>
  );
}
