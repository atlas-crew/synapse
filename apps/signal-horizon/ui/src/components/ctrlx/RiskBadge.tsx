import { memo } from 'react';

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface RiskBadgeProps {
  level: RiskLevel;
  className?: string;
}

const riskStyles: Record<RiskLevel, string> = {
  LOW: 'bg-risk-low/10 text-risk-low border-risk-low/30',
  MEDIUM: 'bg-risk-medium/10 text-risk-medium border-risk-medium/30',
  HIGH: 'bg-risk-high/10 text-risk-high border-risk-high/30',
  CRITICAL: 'bg-risk-critical/10 text-risk-critical border-risk-critical/30',
};

/**
 * RiskBadge - Colored badge for risk levels.
 * LOW=green, MEDIUM=yellow, HIGH=orange, CRITICAL=red.
 */
export const RiskBadge = memo(function RiskBadge({
  level,
  className = '',
}: RiskBadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center px-2 py-0.5 text-xs font-semibold uppercase border
        ${riskStyles[level]}
        ${className}
      `}
    >
      {level}
    </span>
  );
});

export default RiskBadge;
