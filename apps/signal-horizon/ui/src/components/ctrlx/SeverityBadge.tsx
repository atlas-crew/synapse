import { memo } from 'react';
import { AlertTriangle, AlertCircle, Info, CheckCircle } from 'lucide-react';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  showIcon?: boolean;
  className?: string;
}

// Signal Horizon Design System: Solid backgrounds for severity badges
// Critical=Magenta, Warning=Orange, Success=Green, Info=Blue outline
const severityConfig: Record<SeverityLevel, { bg: string; text: string; border: string; Icon: typeof AlertCircle }> = {
  CRITICAL: {
    bg: 'bg-ac-red',
    text: 'text-white',
    border: 'border-ac-red',
    Icon: AlertCircle,
  },
  HIGH: {
    bg: 'bg-ac-orange',
    text: 'text-white',
    border: 'border-ac-orange',
    Icon: AlertTriangle,
  },
  MEDIUM: {
    bg: 'bg-ac-orange/80',
    text: 'text-white',
    border: 'border-ac-orange/80',
    Icon: AlertTriangle,
  },
  LOW: {
    bg: 'bg-ac-green',
    text: 'text-white',
    border: 'border-ac-green',
    Icon: CheckCircle,
  },
  INFO: {
    bg: 'bg-transparent',
    text: 'text-ac-blue',
    border: 'border-ac-navy',
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
