import { clsx } from 'clsx';
import type { LucideIcon } from 'lucide-react';

export interface StatsCardProps {
  label: string;
  value: string | number;
  sublabel: string;
  icon: LucideIcon;
  tone: string;
}

export function StatsCard({ label, value, sublabel, icon: Icon, tone }: StatsCardProps) {
  return (
    <div className="card p-4 flex items-center justify-between">
      <div>
        <div className="text-sm text-ink-secondary mb-1">{label}</div>
        <div className="text-2xl font-bold text-ink-primary" aria-live="polite">{value}</div>
        <div className="text-xs text-ink-secondary mt-1">{sublabel}</div>
      </div>
      <div className={clsx("w-10 h-10  flex items-center justify-center bg-surface-subtle", tone)}>
        <Icon className="w-5 h-5" />
      </div>
    </div>
  );
}
