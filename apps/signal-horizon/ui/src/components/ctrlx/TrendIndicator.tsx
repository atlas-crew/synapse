import { memo } from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';

export type TrendDirection = 'up' | 'down' | 'neutral';

interface TrendIndicatorProps {
  value: number;
  direction: TrendDirection;
  label?: string;
  className?: string;
}

/**
 * TrendIndicator - Shows trend with arrow icon and percentage.
 * Green for up, red for down, gray for neutral.
 */
export const TrendIndicator = memo(function TrendIndicator({
  value,
  direction,
  label,
  className = '',
}: TrendIndicatorProps) {
  const config = {
    up: {
      icon: TrendingUp,
      color: 'text-ctrlx-success',
      bgColor: 'bg-ctrlx-success/10',
    },
    down: {
      icon: TrendingDown,
      color: 'text-ctrlx-danger',
      bgColor: 'bg-ctrlx-danger/10',
    },
    neutral: {
      icon: Minus,
      color: 'text-gray-400',
      bgColor: 'bg-gray-100',
    },
  };

  const { icon: Icon, color, bgColor } = config[direction];
  const displayValue = Math.abs(value);

  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs font-medium ${color} ${bgColor} ${className}`}
    >
      <Icon className="w-3 h-3" />
      <span>{displayValue}%</span>
      {label && <span className="text-gray-500 ml-0.5">{label}</span>}
    </span>
  );
});

export default TrendIndicator;
