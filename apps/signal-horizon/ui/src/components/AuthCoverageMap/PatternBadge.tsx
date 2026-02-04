import React from 'react';
import { clsx } from 'clsx';

type AuthPattern = 'enforced' | 'none_observed' | 'public' | 'insufficient_data';

interface Props {
  pattern: AuthPattern;
}

const PATTERN_LABELS: Record<AuthPattern, string> = {
  enforced: 'Auth Enforced',
  none_observed: 'Auth Missing',
  public: 'Public Endpoint',
  insufficient_data: 'Learning...',
};

const patternStyles: Record<AuthPattern, string> = {
  enforced: 'bg-success/5 text-success',
  none_observed: 'bg-danger/5 text-danger',
  public: 'bg-warning/5 text-warning',
  insufficient_data: 'bg-surface-subtle text-ink-muted',
};

export const PatternBadge: React.FC<Props> = ({ pattern }) => {
  return (
    <span className={clsx(
      "inline-flex items-center px-3 py-1 text-[11px] font-medium tracking-wide",
      patternStyles[pattern]
    )}>
      {PATTERN_LABELS[pattern]}
    </span>
  );
};