import { Eye, Zap } from 'lucide-react';
import { clsx } from 'clsx';

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

export function DlpConfig({ config, onChange }: DlpConfigProps) {
  const handleKeywordsChange = (value: string) => {
    const keywords = value.split(',').map(k => k.trim()).filter(k => k.length > 0);
    onChange({ ...config, custom_keywords: keywords });
  };

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
                onChange={(e) => onChange({ ...config, max_scan_size: (parseInt(e.target.value) || 5) * 1024 * 1024 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Inspect Bytes (KB)</label>
              <input
                type="number"
                min="1"
                max="64"
                value={Math.round(config.max_body_inspection_bytes / 1024)}
                onChange={(e) => onChange({ ...config, max_body_inspection_bytes: (parseInt(e.target.value) || 8) * 1024 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Matches</label>
              <input
                type="number"
                min="10"
                max="1000"
                value={config.max_matches}
                onChange={(e) => onChange({ ...config, max_matches: parseInt(e.target.value) || 100 })}
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
