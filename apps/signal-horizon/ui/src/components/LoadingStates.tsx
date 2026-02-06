/**
 * Loading State Components
 * Skeleton screens and loading indicators for graceful loading states
 */

import { clsx } from 'clsx';

/**
 * Skeleton loading placeholder
 */
export function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={clsx(
        'animate-pulse bg-surface-inset border border-border-subtle',
        className
      )}
      aria-hidden="true"
      {...props}
    />
  );
}

/**
 * Card skeleton for dashboard cards
 */
export function CardSkeleton() {
  return (
    <div className="card p-4" aria-busy="true" aria-label="Loading card">
      <div className="flex items-center gap-3">
        <Skeleton className="w-10 h-10" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-6 w-20" />
          <Skeleton className="h-4 w-16" />
        </div>
      </div>
    </div>
  );
}

/**
 * Stats grid skeleton for the overview page
 */
export function StatsGridSkeleton() {
  return (
    <div
      className="grid grid-cols-4 gap-4"
      role="status"
      aria-label="Loading statistics"
    >
      {Array.from({ length: 4 }).map((_, i) => (
        <CardSkeleton key={i} />
      ))}
    </div>
  );
}

/**
 * Table skeleton for data tables
 */
export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="card" aria-busy="true" aria-label="Loading table data">
      <div className="card-header">
        <Skeleton className="h-5 w-32" />
      </div>
      <div className="overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              {Array.from({ length: 6 }).map((_, i) => (
                <th key={i}>
                  <Skeleton className="h-4 w-16" />
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: rows }).map((_, rowIdx) => (
              <tr key={rowIdx}>
                {Array.from({ length: 6 }).map((_, colIdx) => (
                  <td key={colIdx}>
                    <Skeleton className="h-4 w-full max-w-24" />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Campaign list skeleton
 */
export function CampaignListSkeleton() {
  return (
    <div className="card" aria-busy="true" aria-label="Loading campaigns">
      <div className="card-header flex items-center justify-between">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-4 w-16" />
      </div>
      <div className="card-body space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className="flex items-center justify-between p-3 bg-surface-inset"
          >
            <div className="flex items-center gap-3">
              <Skeleton className="w-2 h-2" />
              <div className="space-y-2">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-3 w-24" />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Skeleton className="h-5 w-16" />
              <Skeleton className="h-5 w-12" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Alert feed skeleton
 */
export function AlertFeedSkeleton() {
  return (
    <div className="card" aria-busy="true" aria-label="Loading alerts">
      <div className="card-header flex items-center justify-between">
        <Skeleton className="h-5 w-28" />
        <Skeleton className="h-4 w-4" />
      </div>
      <div className="card-body max-h-80 overflow-y-auto space-y-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="p-2 border-l-2 border-border-subtle bg-surface-inset">
            <Skeleton className="h-4 w-full mb-1" />
            <Skeleton className="h-3 w-3/4 mb-1" />
            <Skeleton className="h-3 w-16" />
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Loading spinner with optional message
 */
export function LoadingSpinner({
  message = 'Loading...',
  size = 'md',
}: {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
}) {
  const sizeClasses = {
    sm: 'w-4 h-4 border-2',
    md: 'w-8 h-8 border-2',
    lg: 'w-12 h-12 border-3',
  };

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center gap-3 py-8"
    >
      <div
        className={clsx(
          'border-border-subtle border-t-accent animate-spin',
          sizeClasses[size]
        )}
        aria-hidden="true"
      />
      <span className="text-ink-secondary text-sm" aria-hidden="true">{message}</span>
      <span className="sr-only">{message}</span>
    </div>
  );
}

/**
 * Empty state component
 */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div
      role="status"
      aria-label={title}
      className="flex flex-col items-center justify-center py-12 text-center"
    >
      <div className="p-4 bg-surface-subtle border border-border-subtle mb-4">
        <Icon className="w-8 h-8 text-ink-muted" aria-hidden="true" />
      </div>
      <h3 className="text-lg font-medium text-ink-primary mb-1">{title}</h3>
      <p className="text-ink-secondary max-w-sm">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/**
 * Sensor detail skeleton - matches sensor detail page layout
 */
export function SensorDetailSkeleton() {
  return (
    <div className="space-y-6 p-6" aria-busy="true" aria-label="Loading sensor details">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-32" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-32" />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-border-subtle pb-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-24" />
        ))}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="card p-4 space-y-2">
            <Skeleton className="h-4 w-20" />
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-3 w-24" />
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Config panel skeleton - matches config forms layout
 */
export function ConfigPanelSkeleton() {
  return (
    <div className="p-6 space-y-6" aria-busy="true" aria-label="Loading configuration">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Skeleton className="w-5 h-5" />
          <div className="space-y-1">
            <Skeleton className="h-5 w-32" />
            <Skeleton className="h-3 w-48" />
          </div>
        </div>
        <Skeleton className="w-11 h-6" />
      </div>
      <div className="border-t border-border-subtle pt-6 space-y-4">
        <div className="grid grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-10 w-full" />
            </div>
          ))}
        </div>
        <div className="grid grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="space-y-2">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-10 w-full" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/**
 * Fleet overview skeleton - matches fleet overview page layout
 */
export function FleetOverviewSkeleton() {
  return (
    <div className="space-y-6" aria-busy="true" aria-label="Loading fleet overview">
      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="card p-4 space-y-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-8 w-16" />
          </div>
        ))}
      </div>

      {/* Sensors List */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-8 w-24" />
        </div>
        <div className="divide-y divide-border-subtle">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="p-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Skeleton className="w-3 h-3" />
                <div className="space-y-1">
                  <Skeleton className="h-5 w-40" />
                  <Skeleton className="h-3 w-24" />
                </div>
              </div>
              <div className="flex items-center gap-4">
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-6 w-16" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/**
 * Rules list skeleton - matches rule distribution page layout
 */
export function RulesListSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading rules">
      <div className="flex items-center justify-between">
        <Skeleton className="h-6 w-32" />
        <div className="flex gap-2">
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-24" />
        </div>
      </div>
      <div className="card divide-y divide-border-subtle">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Skeleton className="w-4 h-4" />
              <div className="space-y-1">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-3 w-32" />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Skeleton className="h-6 w-16" />
              <Skeleton className="h-6 w-12" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Token list skeleton - matches onboarding page token list
 */
export function TokenListSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading tokens">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="p-4 bg-surface-card border border-border-subtle">
          <div className="flex items-center justify-between">
            <div className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-48" />
            </div>
            <div className="flex gap-2">
              <Skeleton className="h-8 w-20" />
              <Skeleton className="h-8 w-20" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Connection status banner
 */
export function ConnectionBanner({
  isConnected,
  isReconnecting,
  reconnectAttempt,
  maxReconnectAttempts,
}: {
  isConnected: boolean;
  isReconnecting: boolean;
  reconnectAttempt?: number;
  maxReconnectAttempts?: number;
}) {
  if (isConnected) return null;

  const hasExhaustedAttempts =
    reconnectAttempt != null &&
    maxReconnectAttempts != null &&
    reconnectAttempt >= maxReconnectAttempts;

  return (
    <div
      role="alert"
      aria-live="polite"
      className={clsx(
        'flex items-center justify-center gap-2 py-2 px-4 text-sm',
        isReconnecting && !hasExhaustedAttempts
          ? 'bg-ac-orange/15 text-ac-orange'
          : 'bg-ac-red/15 text-ac-red'
      )}
    >
      {isReconnecting && !hasExhaustedAttempts ? (
        <>
          <div className="w-3 h-3 border-2 border-ac-orange border-t-transparent animate-spin" />
          <span>
            Reconnecting to server...
            {reconnectAttempt != null && maxReconnectAttempts != null && (
              <span className="ml-1 opacity-80">
                (attempt {reconnectAttempt}/{maxReconnectAttempts})
              </span>
            )}
          </span>
        </>
      ) : hasExhaustedAttempts ? (
        <>
          <span className="w-2 h-2 bg-ac-red" />
          <span>Unable to reconnect after {maxReconnectAttempts} attempts. Please refresh the page.</span>
        </>
      ) : (
        <>
          <span className="w-2 h-2 bg-ac-red" />
          <span>Connection lost. Data may be stale.</span>
        </>
      )}
    </div>
  );
}
