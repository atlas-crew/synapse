import { memo } from 'react';
import { AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  showIcon?: boolean;
  className?: string;
}

const severityConfig: Record<SeverityLevel, { bg: string; text: string; border: string; Icon: typeof AlertCircle }> = {
  CRITICAL: {
    bg: 'bg-risk-critical/10',
    text: 'text-risk-critical',
    border: 'border-risk-critical/30',
    Icon: AlertCircle,
  },
  HIGH: {
    bg: 'bg-risk-high/10',
    text: 'text-risk-high',
    border: 'border-risk-high/30',
    Icon: AlertTriangle,
  },
  MEDIUM: {
    bg: 'bg-risk-medium/10',
    text: 'text-risk-medium',
    border: 'border-risk-medium/30',
    Icon: AlertTriangle,
  },
  LOW: {
    bg: 'bg-risk-low/10',
    text: 'text-risk-low',
    border: 'border-risk-low/30',
    Icon: CheckCircle,
  },
  INFO: {
    bg: 'bg-ctrlx-info/10',
    text: 'text-ctrlx-info',
    border: 'border-ctrlx-info/30',
    Icon: Info,
  },
};

/**
 * SeverityBadge - Colored badge for severity levels with optional icon.
 * CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=green, INFO=blue.
 */
export const SeverityBadge = memo(function SeverityBadge({
  severity,
  showIcon = false,
  className = '',
}: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const { Icon } = config;

  return (
    <span
      className={`
        inline-flex items-center gap-1 px-2 py-0.5 text-xs font-semibold uppercase border
        ${config.bg} ${config.text} ${config.border}
        ${className}
      `}
    >
      {showIcon && <Icon className="w-3 h-3" />}
      {severity}
    </span>
  );
});

export default SeverityBadge;
