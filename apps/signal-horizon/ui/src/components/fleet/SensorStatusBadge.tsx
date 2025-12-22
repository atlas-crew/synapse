import { memo } from 'react';
import type { SensorStatus } from '../../types/fleet';

interface SensorStatusBadgeProps {
  status: SensorStatus;
  className?: string;
}

const statusConfig = {
  online: { label: 'Online', icon: '●', color: 'text-green-600 bg-green-50 border-green-200' },
  warning: { label: 'Warning', icon: '⚠', color: 'text-yellow-600 bg-yellow-50 border-yellow-200' },
  offline: { label: 'Offline', icon: '○', color: 'text-gray-600 bg-gray-50 border-gray-200' },
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
