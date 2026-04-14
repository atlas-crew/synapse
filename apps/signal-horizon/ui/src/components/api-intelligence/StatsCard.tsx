import { clsx } from 'clsx';
import type { LucideIcon } from 'lucide-react';
import { Panel } from '@/ui';

export interface StatsCardProps {
  label: string;
  value: string | number;
  sublabel: string;
  icon: LucideIcon;
  /**
   * Tailwind className applied to the icon badge. Despite the prop name,
   * this is NOT a <Panel> tone — it's a color class applied to the icon
   * square. The prop name is kept for backwards-compat with call-sites.
   */
  tone: string;
}

export function StatsCard({ label, value, sublabel, icon: Icon, tone }: StatsCardProps) {
  return (
    <Panel tone="default" padding="sm" spacing="none">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm text-ink-secondary mb-1">{label}</div>
          <div className="text-2xl font-bold text-ink-primary" aria-live="polite">
            {value}
          </div>
          <div className="text-xs text-ink-secondary mt-1">{sublabel}</div>
        </div>
        <div className={clsx('w-10 h-10 flex items-center justify-center bg-surface-subtle', tone)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </Panel>
  );
}
