import { useCallback, memo } from 'react';
import { Shield } from 'lucide-react';
import { clsx } from 'clsx';
import { Button, Stack, colors } from '@/ui';

export interface WafConfigData {
  enabled: boolean;
  threshold: number;
  rule_overrides: Record<string, { enabled: boolean; action: 'block' | 'log' | 'allow' }>;
}

interface WafConfigProps {
  config: WafConfigData;
  onChange: (config: WafConfigData) => void;
}

export const WafConfig = memo(function WafConfig({ config, onChange }: WafConfigProps) {
  const handleThresholdChange = useCallback((val: number) => {
    onChange({ ...config, threshold: Math.max(0, Math.min(1, val)) });
  }, [config, onChange]);

  const handleRuleOverride = useCallback((ruleId: string, override: any) => {
    const newOverrides = { ...config.rule_overrides };
    if (override === null) {
      delete newOverrides[ruleId];
    } else {
      newOverrides[ruleId] = override;
    }
    onChange({ ...config, rule_overrides: newOverrides });
  }, [config, onChange]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Stack direction="row" align="center" gap="sm">
          <Shield className={clsx("w-5 h-5", config.enabled ? "text-ac-green" : "text-ink-muted")} aria-hidden="true" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">WAF Protection</h3>
            <p className="text-xs text-ink-secondary">Web Application Firewall engine</p>
          </div>
        </Stack>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
            aria-label="Enable WAF Protection"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after: after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-green"></div>
        </label>
      </div>

      {config.enabled && (
        <div className="space-y-6 border-t border-border-subtle pt-6">
          {/* Sensitivity */}
          <div className="space-y-2">
            <div className="flex justify-between">
              <label htmlFor="waf-threshold" className="text-sm font-medium text-ink-primary">Sensitivity Threshold</label>
              <span id="waf-threshold-value" className="text-sm font-mono text-ink-secondary">{config.threshold.toFixed(2)}</span>
            </div>
            <input
              id="waf-threshold"
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={config.threshold}
              onChange={(e) => handleThresholdChange(parseFloat(e.target.value))}
              aria-valuemin={0}
              aria-valuemax={1}
              aria-valuenow={config.threshold}
              aria-valuetext={`${config.threshold.toFixed(2)} - ${config.threshold <= 0.3 ? 'Strict' : config.threshold <= 0.7 ? 'Balanced' : 'Permissive'}`}
              className="w-full h-2 bg-surface-subtle appearance-none cursor-pointer accent-ac-blue"
            />
            <div className="flex justify-between text-xs text-ink-muted" aria-hidden="true">
              <span>Strict (0.0)</span>
              <span>Balanced (0.5)</span>
              <span>Permissive (1.0)</span>
            </div>
          </div>

          {/* Rule Overrides */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-ink-primary">Rule Overrides</h4>
              <Button
                onClick={() => {
                  const id = prompt('Enter Rule ID (e.g., XSS-001)');
                  if (id) handleRuleOverride(id, { enabled: false, action: 'allow' });
                }}
                variant="ghost"
                size="sm"
                style={{ height: '24px', padding: 0, fontSize: '12px', color: colors.blue }}
              >
                + Add Override
              </Button>
            </div>
            
            {Object.keys(config.rule_overrides).length === 0 ? (
              <div className="text-center py-4 bg-surface-subtle border border-dashed border-border-subtle text-xs text-ink-muted">
                No active overrides. All global rules apply.
              </div>
            ) : (
              <div className="space-y-2">
                {Object.entries(config.rule_overrides).map(([id, override]) => (
                  <div key={id} className="flex items-center justify-between p-2 bg-surface-subtle border border-border-subtle text-sm">
                    <span className="font-mono text-xs">{id}</span>
                    <Stack direction="row" align="center" gap="smPlus">
                      <select
                        value={override.action}
                        onChange={(e) => handleRuleOverride(id, { ...override, action: e.target.value })}
                        className="bg-surface-base border border-border-subtle px-2 py-1 text-xs"
                      >
                        <option value="block">Block</option>
                        <option value="log">Log Only</option>
                        <option value="allow">Allow</option>
                      </select>
                      <Button
                        onClick={() => handleRuleOverride(id, null)}
                        variant="ghost"
                        size="sm"
                        style={{ height: '24px', padding: 0, fontSize: '12px', color: colors.red }}
                      >
                        Remove
                      </Button>
                    </Stack>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
});
