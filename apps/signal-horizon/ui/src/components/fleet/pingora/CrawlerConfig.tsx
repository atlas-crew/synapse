import { memo } from 'react';
import { Bot, Shield, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import {
  DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS,
  DEFAULT_CRAWLER_DNS_FAILURE_POLICY,
  DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY,
  DEFAULT_CRAWLER_DNS_TIMEOUT_MS,
  DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS,
} from './configDefaults';
import { Stack } from '@/ui';

export interface CrawlerConfigData {
  enabled: boolean;
  verify_legitimate_crawlers: boolean;
  block_bad_bots: boolean;
  dns_failure_policy: 'allow' | 'apply_risk_penalty' | 'block';
  dns_cache_ttl_secs: number;
  dns_timeout_ms: number;
  max_concurrent_dns_lookups: number;
  dns_failure_risk_penalty: number;
}

interface CrawlerConfigProps {
  config: CrawlerConfigData;
  onChange: (config: CrawlerConfigData) => void;
}

export const CrawlerConfig = memo(function CrawlerConfig({ config, onChange }: CrawlerConfigProps) {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Stack direction="row" align="center" gap="sm">
          <Bot className={clsx("w-5 h-5", config.enabled ? "text-ac-purple" : "text-ink-muted")} aria-hidden="true" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Crawler/Bot Detection</h3>
            <p className="text-xs text-ink-secondary">Verify legitimate crawlers, block bad bots</p>
          </div>
        </Stack>
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enabled}
            onChange={(e) => onChange({ ...config, enabled: e.target.checked })}
            className="sr-only peer"
            aria-label="Enable Crawler/Bot Detection"
          />
          <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after: after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-purple"></div>
        </label>
      </div>

      {config.enabled && (
        <div className="space-y-4 border-t border-border-subtle pt-6">
          {/* Feature toggles */}
          <div className="flex flex-wrap gap-4">
            <Stack direction="row" align="center" gap="sm">
              <input
                id="crawler-verify-legit"
                type="checkbox"
                checked={config.verify_legitimate_crawlers}
                onChange={(e) => onChange({ ...config, verify_legitimate_crawlers: e.target.checked })}
                className="w-4 h-4 border-border-subtle text-ac-blue focus:ring-ac-blue/20"
              />
              <Stack direction="row" align="center" gap="xs">
                <Shield className="w-3 h-3 text-ac-green" aria-hidden="true" />
                <label htmlFor="crawler-verify-legit" className="text-xs text-ink-secondary cursor-pointer">
                  Verify legitimate crawlers (DNS)
                </label>
              </Stack>
            </Stack>
            <Stack direction="row" align="center" gap="sm">
              <input
                id="crawler-block-bad-bots"
                type="checkbox"
                checked={config.block_bad_bots}
                onChange={(e) => onChange({ ...config, block_bad_bots: e.target.checked })}
                className="w-4 h-4 border-border-subtle text-ac-blue focus:ring-ac-blue/20"
              />
              <Stack direction="row" align="center" gap="xs">
                <AlertTriangle className="w-3 h-3 text-ac-red" aria-hidden="true" />
                <label htmlFor="crawler-block-bad-bots" className="text-xs text-ink-secondary cursor-pointer">
                  Block known bad bots
                </label>
              </Stack>
            </Stack>
          </div>

          {/* DNS Failure Policy */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">DNS Failure Policy</label>
            <select
              value={config.dns_failure_policy}
              onChange={(e) => onChange({
                ...config,
                dns_failure_policy: (e.target.value as any) || DEFAULT_CRAWLER_DNS_FAILURE_POLICY,
              })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            >
              <option value="apply_risk_penalty">Apply Risk Penalty (recommended)</option>
              <option value="allow">Allow (fail-open)</option>
              <option value="block">Block (fail-secure)</option>
            </select>
          </div>

          {/* Numeric settings */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">DNS Cache TTL (sec)</label>
              <input
                type="number"
                min="60"
                max="3600"
                value={config.dns_cache_ttl_secs}
                onChange={(e) => onChange({
                  ...config,
                  dns_cache_ttl_secs: parseInt(e.target.value) || DEFAULT_CRAWLER_DNS_CACHE_TTL_SECS,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">DNS Timeout (ms)</label>
              <input
                type="number"
                min="500"
                max="10000"
                value={config.dns_timeout_ms}
                onChange={(e) => onChange({
                  ...config,
                  dns_timeout_ms: parseInt(e.target.value) || DEFAULT_CRAWLER_DNS_TIMEOUT_MS,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Concurrent DNS</label>
              <input
                type="number"
                min="10"
                max="500"
                value={config.max_concurrent_dns_lookups}
                onChange={(e) => onChange({
                  ...config,
                  max_concurrent_dns_lookups: parseInt(e.target.value) || DEFAULT_CRAWLER_MAX_CONCURRENT_DNS_LOOKUPS,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Failure Risk Penalty</label>
              <input
                type="number"
                min="0"
                max="100"
                value={config.dns_failure_risk_penalty}
                onChange={(e) => onChange({
                  ...config,
                  dns_failure_risk_penalty: parseInt(e.target.value) || DEFAULT_CRAWLER_DNS_FAILURE_RISK_PENALTY,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
