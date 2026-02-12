import { memo } from 'react';
import { Stack } from '@/ui';

export type ProgressVariant = 'default' | 'success' | 'warning' | 'danger' | 'info';

interface ProgressBarProps {
  value: number; // 0-100
  max?: number;
  variant?: ProgressVariant;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const variantStyles: Record<ProgressVariant, string> = {
  default: 'bg-ctrlx-primary',
  success: 'bg-ctrlx-success',
  warning: 'bg-ctrlx-warning',
  danger: 'bg-ctrlx-danger',
  info: 'bg-ctrlx-info',
};

const sizeStyles: Record<'sm' | 'md' | 'lg', string> = {
  sm: 'h-1',
  md: 'h-2',
  lg: 'h-3',
};

/**
 * ProgressBar - Horizontal progress indicator with color variants.
 * Can auto-color based on thresholds (>80% = danger, >60% = warning).
 */
export const ProgressBar = memo(function ProgressBar({
  value,
  max = 100,
  variant = 'default',
  showLabel = false,
  size = 'md',
  className = '',
}: ProgressBarProps) {
  const percentage = Math.min(Math.max((value / max) * 100, 0), 100);

  // Auto-determine variant based on value if using default
  const computedVariant =
    variant === 'default'
      ? percentage >= 80
        ? 'danger'
        : percentage >= 60
          ? 'warning'
          : 'success'
      : variant;

  return (
    <Stack direction="row" align="center" gap="sm" className={className}>
      <div className={`flex-1 bg-gray-200 overflow-hidden ${sizeStyles[size]}`}>
        <div
          className={`h-full transition-all duration-300 ${variantStyles[computedVariant]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showLabel && (
        <span className="text-xs font-medium text-gray-600 min-w-[3rem] text-right">
          {Math.round(percentage)}%
        </span>
      )}
    </Stack>
  );
});

export default ProgressBar;
