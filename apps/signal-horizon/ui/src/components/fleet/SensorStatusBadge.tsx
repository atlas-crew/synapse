import { memo } from 'react';
import type { SensorStatus } from '../../types/fleet';

interface SensorStatusBadgeProps {
  status: SensorStatus;
  className?: string;
}

const statusConfig = {
  online: { label: 'Online', icon: '●', color: 'text-ac-green bg-ac-green/10 border-ac-green/30' },
  warning: { label: 'Warning', icon: '⚠', color: 'text-ac-orange bg-ac-orange/10 border-ac-orange/30' },
  offline: { label: 'Offline', icon: '○', color: 'text-ink-muted bg-surface-subtle border-border-subtle' },
};

export const SensorStatusBadge = memo(function SensorStatusBadge({
  status,
  className = '',
}: SensorStatusBadgeProps) {
  const config = statusConfig[status];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium border ${config.color} ${className}`}>
      <span>{config.icon}</span>
      <span>{config.label}</span>
    </span>
  );
});
