import React from 'react';
import { motion } from 'framer-motion';
import { Globe, Shield, AlertTriangle, TrendingUp } from 'lucide-react';
import { clsx } from 'clsx';
import { useNavigate } from 'react-router-dom';
import type { Campaign } from '../../stores/horizonStore';
import { useRelativeTime } from '../../hooks/useRelativeTime';
import { EmptyState } from '../feedback/EmptyState';

interface ActiveCampaignListProps {
  campaigns: Campaign[];
}

const severityConfig = {
  CRITICAL: {
    border: 'border-ac-red',
    bg: 'bg-ac-red/10',
    text: 'text-ac-red',
    glow: 'shadow-[0_0_12px_rgba(239,51,64,0.2)]',
  },
  HIGH: {
    border: 'border-ac-orange',
    bg: 'bg-ac-orange/10',
    text: 'text-ac-orange',
    glow: 'shadow-[0_0_12px_rgba(227,82,5,0.2)]',
  },
  MEDIUM: {
    border: 'border-ac-blue',
    bg: 'bg-ac-blue/10',
    text: 'text-ac-blue',
    glow: 'shadow-[0_0_12px_rgba(0,87,183,0.2)]',
  },
  LOW: {
    border: 'border-ac-green',
    bg: 'bg-ac-green/10',
    text: 'text-ac-green',
    glow: 'shadow-[0_0_12px_rgba(0,177,64,0.2)]',
  },
};

export const ActiveCampaignList: React.FC<ActiveCampaignListProps> = ({ campaigns }) => {
  const navigate = useNavigate();

  if (campaigns.length === 0) {
    return (
      <div className="py-12 border border-dashed border-border-subtle bg-surface-subtle/30">
        <EmptyState
          title="No Active Campaigns"
          description="Monitoring fleet for coordinated threat activity."
          icon={Shield}
        />
      </div>
    );
  }

  return (
    <div className="space-y-3" role="list" aria-label="Active campaign list">
      {campaigns.map((campaign, index) => {
        const config = severityConfig[campaign.severity] || severityConfig.MEDIUM;
        const lastSeen = new Date(campaign.lastActivityAt).getTime();

        return (
          <motion.div
            key={campaign.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05 }}
            tabIndex={0}
            role="listitem"
            onKeyDown={(e) => {
              if (e.key === 'Enter') navigate(`/campaigns/${campaign.id}`);
            }}
            onClick={() => navigate(`/campaigns/${campaign.id}`)}
            className={clsx(
              'group flex flex-wrap items-center justify-between p-4 transition-all duration-200 cursor-pointer border-l-4 border-radius-0 outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ac-blue/50',
              'bg-surface-inset border-border-subtle',
              'hover:bg-[#0A1A3A] hover:text-white hover:translate-x-1 hover:border-l-4',
              campaign.severity === 'CRITICAL' && 'hover:border-ac-magenta',
              campaign.severity === 'HIGH' && 'hover:border-ac-orange',
              campaign.severity === 'MEDIUM' && 'hover:border-ac-blue',
              campaign.severity === 'LOW' && 'hover:border-ac-green'
            )}
          >
            <div className="flex-1 min-w-0 pr-4">
              <div className="flex items-center gap-3 mb-1">
                <h3 className="font-medium truncate group-hover:text-white">
                  {campaign.name}
                </h3>
                <span className={clsx(
                  'px-2 py-0.5 text-[10px] font-bold uppercase tracking-widest border',
                  config.text,
                  config.border,
                  config.bg
                )}>
                  {campaign.severity}
                </span>
                {campaign.isCrossTenant && (
                  <Globe className="w-3.5 h-3.5 text-ac-blue-tint" title="Cross-tenant campaign" />
                )}
              </div>
              <div className="flex items-center gap-4 text-[10px] text-ink-muted group-hover:text-white/60">
                <span>Confidence: {campaign.confidence}%</span>
                <span>Tenants: {campaign.tenantsAffected}</span>
                <span className="flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" />
                  Last Activity: <RelativeTime timestamp={lastSeen} />
                </span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-bold text-ink-primary group-hover:text-white uppercase tracking-tighter">
                  Status: {campaign.status}
                </div>
              </div>
              <div className="w-8 h-8 flex items-center justify-center border border-border-subtle group-hover:border-white/20">
                <span className="text-[10px] font-bold group-hover:text-[#D62598] transition-colors">&gt;</span>
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
};

// Internal component for relative time to avoid hook issues in loop
const RelativeTime: React.FC<{ timestamp: number }> = ({ timestamp }) => {
  const timeText = useRelativeTime(timestamp);
  return <span>{timeText || 'Just now'}</span>;
};

export default ActiveCampaignList;