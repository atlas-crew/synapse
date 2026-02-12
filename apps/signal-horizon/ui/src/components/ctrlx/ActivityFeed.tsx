import { memo, type ReactNode } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { Stack } from '@/ui';

export interface ActivityItem {
  id: string;
  timestamp: Date;
  title: string;
  description?: string;
  icon?: ReactNode;
  badge?: ReactNode;
  status?: 'success' | 'warning' | 'error' | 'info';
}

interface ActivityFeedProps {
  items: ActivityItem[];
  maxItems?: number;
  emptyMessage?: string;
  className?: string;
}

const statusStyles = {
  success: 'border-l-ctrlx-success',
  warning: 'border-l-ctrlx-warning',
  error: 'border-l-ctrlx-danger',
  info: 'border-l-ctrlx-info',
};

/**
 * ActivityFeed - Time-ordered list of events with optional status indicators.
 * Used for threat activity, discovery events, etc.
 */
export const ActivityFeed = memo(function ActivityFeed({
  items,
  maxItems = 10,
  emptyMessage = 'No recent activity',
  className = '',
}: ActivityFeedProps) {
  const displayItems = items.slice(0, maxItems);

  if (displayItems.length === 0) {
    return (
      <div className={`text-center py-8 text-gray-500 ${className}`}>
        {emptyMessage}
      </div>
    );
  }

  return (
    <div className={`space-y-0 ${className}`}>
      {displayItems.map((item) => (
        <div
          key={item.id}
          className={`
            flex items-start gap-3 px-4 py-3 border-b border-gray-100 last:border-b-0
            hover:bg-gray-50 transition-colors
            ${item.status ? `border-l-2 ${statusStyles[item.status]}` : 'border-l-2 border-l-transparent'}
          `}
        >
          {/* Timestamp */}
          <div className="text-xs text-gray-400 min-w-[4rem] pt-0.5">
            {formatDistanceToNow(item.timestamp, { addSuffix: false })}
          </div>

          {/* Icon */}
          {item.icon && (
            <div className="text-gray-400 pt-0.5">{item.icon}</div>
          )}

          {/* Content */}
          <div className="flex-1 min-w-0">
            <Stack direction="row" align="center" gap="sm">
              <span className="text-sm font-medium text-navy-900 truncate">
                {item.title}
              </span>
              {item.badge}
            </Stack>
            {item.description && (
              <p className="text-xs text-gray-500 mt-0.5 truncate">
                {item.description}
              </p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
});

export default ActivityFeed;
