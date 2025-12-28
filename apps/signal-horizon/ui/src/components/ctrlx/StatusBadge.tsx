import { memo } from 'react';

export type StatusType = 'online' | 'offline' | 'warning' | 'blocked' | 'pending' | 'unknown';

interface StatusBadgeProps {
  status: StatusType;
  label?: string;
  className?: string;
}

const statusConfig: Record<StatusType, { bg: string; text: string; dot: string; defaultLabel: string }> = {
  online: {
    bg: 'bg-ctrlx-success/10',
    text: 'text-ctrlx-success',
    dot: 'bg-ctrlx-success',
    defaultLabel: 'Online',
  },
  offline: {
    bg: 'bg-gray-100',
    text: 'text-gray-500',
    dot: 'bg-gray-400',
    defaultLabel: 'Offline',
  },
  warning: {
    bg: 'bg-ctrlx-warning/10',
    text: 'text-ctrlx-warning',
    dot: 'bg-ctrlx-warning',
    defaultLabel: 'Warning',
  },
  blocked: {
    bg: 'bg-ctrlx-danger/10',
    text: 'text-ctrlx-danger',
    dot: 'bg-ctrlx-danger',
    defaultLabel: 'Blocked',
  },
  pending: {
    bg: 'bg-ctrlx-info/10',
    text: 'text-ctrlx-info',
    dot: 'bg-ctrlx-info animate-pulse',
    defaultLabel: 'Pending',
  },
  unknown: {
    bg: 'bg-gray-100',
    text: 'text-gray-500',
    dot: 'bg-gray-400',
    defaultLabel: 'Unknown',
  },
};

/**
 * StatusBadge - Status indicator with colored dot and label.
 * Used for connection states, entity status, etc.
 */
export const StatusBadge = memo(function StatusBadge({
  status,
  label,
  className = '',
}: StatusBadgeProps) {
  const config = statusConfig[status];

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 px-2 py-0.5 text-xs font-medium
        ${config.bg} ${config.text}
        ${className}
      `}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      {label || config.defaultLabel}
    </span>
  );
});

export default StatusBadge;
