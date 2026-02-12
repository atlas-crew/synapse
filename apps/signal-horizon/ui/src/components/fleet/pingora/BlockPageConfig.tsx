import { memo } from 'react';
import { FileWarning } from 'lucide-react';
import { Stack } from '@/ui';

export interface BlockPageConfigData {
  company_name?: string;
  support_email?: string;
  logo_url?: string;
  custom_css?: string;
  show_request_id: boolean;
  show_timestamp: boolean;
  show_client_ip: boolean;
  show_rule_id: boolean;
}

interface BlockPageConfigProps {
  config: BlockPageConfigData;
  onChange: (config: BlockPageConfigData) => void;
}

export const BlockPageConfig = memo(function BlockPageConfig({ config, onChange }: BlockPageConfigProps) {
  return (
    <div className="space-y-6">
      <Stack direction="row" align="center" gap="sm">
        <FileWarning className="w-5 h-5 text-ac-orange" aria-hidden="true" />
        <div>
          <h3 className="text-sm font-medium text-ink-primary">Block Page Branding</h3>
          <p className="text-xs text-ink-secondary">Customize the page shown to blocked users</p>
        </div>
      </Stack>

      <div className="space-y-4 border-t border-border-subtle pt-6">
        {/* Branding inputs */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Company Name</label>
            <input
              type="text"
              value={config.company_name || ''}
              onChange={(e) => onChange({ ...config, company_name: e.target.value || undefined })}
              placeholder="Your Company"
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Support Email</label>
            <input
              type="email"
              value={config.support_email || ''}
              onChange={(e) => onChange({ ...config, support_email: e.target.value || undefined })}
              placeholder="security@example.com"
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-xs font-medium text-ink-secondary">Logo URL</label>
          <input
            type="url"
            value={config.logo_url || ''}
            onChange={(e) => onChange({ ...config, logo_url: e.target.value || undefined })}
            placeholder="https://example.com/logo.png"
            className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm font-mono focus:border-ac-blue focus:outline-none transition-colors"
          />
        </div>

        {/* Display toggles */}
        <div className="space-y-2">
          <label className="text-xs font-medium text-ink-secondary">Display Options</label>
          <div className="flex flex-wrap gap-4">
            {[
              { key: 'show_request_id', label: 'Request ID' },
              { key: 'show_timestamp', label: 'Timestamp' },
              { key: 'show_client_ip', label: 'Client IP' },
              { key: 'show_rule_id', label: 'Rule ID (debug)' },
            ].map(({ key, label }) => (
              <Stack key={key} direction="row" align="center" gap="sm">
                <input
                  id={`block-page-${key}`}
                  type="checkbox"
                  checked={config[key as keyof BlockPageConfigData] as boolean}
                  onChange={(e) => onChange({ ...config, [key]: e.target.checked })}
                  className="w-4 h-4 border-border-subtle text-ac-blue focus:ring-ac-blue/20"
                />
                <label htmlFor={`block-page-${key}`} className="text-xs text-ink-secondary cursor-pointer">
                  {label}
                </label>
              </Stack>
            ))}
          </div>
        </div>

        {/* Custom CSS */}
        <div className="space-y-1">
          <label className="text-xs font-medium text-ink-secondary">Custom CSS</label>
          <textarea
            value={config.custom_css || ''}
            onChange={(e) => onChange({ ...config, custom_css: e.target.value || undefined })}
            placeholder=".block-page { background: #1a1a2e; }"
            rows={3}
            className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm font-mono focus:border-ac-blue focus:outline-none transition-colors resize-none"
          />
        </div>
      </div>
    </div>
  );
});
