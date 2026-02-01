import { memo } from 'react';

export type TimeRange = '1H' | '6H' | '24H' | '7D' | '30D' | 'custom';

interface TimeRangeSelectorProps {
  value: TimeRange;
  onChange: (range: TimeRange) => void;
  options?: TimeRange[];
  className?: string;
}

const defaultOptions: TimeRange[] = ['1H', '6H', '24H', '7D', '30D'];

/**
 * TimeRangeSelector - Button group for selecting time ranges.
 * Matches Signal Horizon design system with theme-aware styling.
 */
export const TimeRangeSelector = memo(function TimeRangeSelector({
  value,
  onChange,
  options = defaultOptions,
  className = '',
}: TimeRangeSelectorProps) {
  return (
    <div className={`inline-flex bg-surface-subtle dark:bg-surface-card p-0.5 border border-border-subtle ${className}`}>
      {options.map((range) => (
        <button
          key={range}
          type="button"
          onClick={() => onChange(range)}
          className={`
            px-3 py-1.5 text-sm font-medium transition-colors
            ${
              value === range
                ? 'bg-white dark:bg-surface-hero text-ac-navy dark:text-white shadow-sm'
                : 'text-ink-secondary hover:text-ac-navy dark:hover:text-white hover:bg-surface-card dark:hover:bg-surface-subtle'
            }
          `}
        >
          {range}
        </button>
      ))}
    </div>
  );
});

export default TimeRangeSelector;
