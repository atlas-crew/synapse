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
 * Matches CtrlX design with light gray background and white active state.
 */
export const TimeRangeSelector = memo(function TimeRangeSelector({
  value,
  onChange,
  options = defaultOptions,
  className = '',
}: TimeRangeSelectorProps) {
  return (
    <div className={`inline-flex bg-gray-100 p-0.5 ${className}`}>
      {options.map((range) => (
        <button
          key={range}
          type="button"
          onClick={() => onChange(range)}
          className={`
            px-3 py-1.5 text-sm font-medium transition-colors
            ${
              value === range
                ? 'bg-white text-navy-900 shadow-sm'
                : 'text-gray-600 hover:text-navy-900 hover:bg-gray-200'
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
