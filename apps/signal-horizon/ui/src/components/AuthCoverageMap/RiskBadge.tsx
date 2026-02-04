import React from 'react';
import { clsx } from 'clsx';

type RiskLevel = 'low' | 'medium' | 'high' | 'unknown';

interface Props {
  level: RiskLevel;
  className?: string;
}

const levelStyles: Record<RiskLevel, string> = {
  high: 'bg-danger/10 text-danger border-danger/30',
  medium: 'bg-warning/10 text-warning border-warning/30',
  low: 'bg-success/10 text-success border-success/30',
  unknown: 'bg-surface-subtle text-ink-muted border-border-subtle',
};

export const RiskBadge: React.FC<Props> = ({ level, className }) => {
  return (
    <span className={clsx(
      "inline-flex items-center px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
      levelStyles[level],
      className
    )}>
      {level === 'unknown' ? 'NO DATA' : level}
    </span>
  );
};