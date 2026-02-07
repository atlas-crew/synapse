import { useCallback } from 'react';
import { motion } from 'framer-motion';
import { Globe } from 'lucide-react';
import { clsx } from 'clsx';
import type { Campaign } from '../../stores/horizonStore';

interface ActiveCampaignListProps {
  campaigns: Campaign[];
}

const severityBorderColors: Record<Campaign['severity'], string> = {
  CRITICAL: 'border-l-ac-red',
  HIGH: 'border-l-ac-orange',
  MEDIUM: 'border-l-ac-blue',
  LOW: 'border-l-ac-green',
};

const severityBadgeColors: Record<Campaign['severity'], string> = {
  LOW: 'text-ac-blue bg-ac-blue/10 border-ac-blue/30',
  MEDIUM: 'text-ac-orange bg-ac-orange/10 border-ac-orange/30',
  HIGH: 'text-ac-orange bg-ac-orange/20 border-ac-orange/40',
  CRITICAL: 'text-ac-red bg-ac-red/15 border-ac-red/40',
};

function formatRelativeTime(dateStr: string): string {
  const diffMs = Date.now() - new Date(dateStr).getTime();
  const diffMin = Math.floor(diffMs / 60_000);
  const diffHr = Math.floor(diffMin / 60);
  const diffDays = Math.floor(diffHr / 24);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  if (diffDays < 30) return `${diffDays}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export function ActiveCampaignList({ campaigns }: ActiveCampaignListProps) {
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (e.key === 'Enter') e.currentTarget.click();
    },
    [],
  );

  if (campaigns.length === 0) {
    return (
      <div className="text-center text-ink-muted py-8" role="status">
        No active campaigns detected
      </div>
    );
  }

  return (
    <div role="list" aria-label="Active attack campaigns" className="flex flex-col gap-2">
      {campaigns.map((campaign, index) => (
        <motion.div
          key={campaign.id}
          role="listitem"
          tabIndex={0}
          onKeyDown={handleKeyDown}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: index * 0.05 }}
          className={clsx(
            'border-l-2 border border-border-subtle bg-surface-inset px-4 py-3',
            'hover:bg-[#0A1A3A] hover:text-white hover:translate-x-1',
            'focus-visible:outline focus-visible:outline-2 focus-visible:outline-ac-blue',
            'transition-all duration-200 cursor-pointer',
            severityBorderColors[campaign.severity],
          )}
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-medium text-sm truncate">{campaign.name}</span>
              <span
                aria-label={`Severity: ${campaign.severity}`}
                className={clsx(
                  'inline-flex items-center px-2 py-0.5 text-xs border shrink-0',
                  severityBadgeColors[campaign.severity],
                )}
              >
                {campaign.severity}
              </span>
              {campaign.isCrossTenant && (
                <Globe
                  className="w-3.5 h-3.5 text-ink-secondary shrink-0"
                  aria-label="Cross-tenant campaign"
                />
              )}
            </div>

            <div className="flex items-center gap-4 text-xs text-ink-secondary shrink-0">
              <span title="Tenants affected">
                {campaign.tenantsAffected} {campaign.tenantsAffected === 1 ? 'tenant' : 'tenants'}
              </span>
              <span title="Confidence">{Math.round(campaign.confidence * 100)}%</span>
              <span
                className="text-ink-muted"
                title={new Date(campaign.lastActivityAt).toLocaleString()}
              >
                {formatRelativeTime(campaign.lastActivityAt)}
              </span>
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

export default ActiveCampaignList;
