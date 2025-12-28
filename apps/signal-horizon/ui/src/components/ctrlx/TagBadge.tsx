import { memo } from 'react';
import { X } from 'lucide-react';

interface TagBadgeProps {
  label: string;
  onRemove?: () => void;
  variant?: 'default' | 'outline';
  className?: string;
}

/**
 * TagBadge - Simple tag/chip component for labels and categories.
 * Gray background with optional remove button.
 */
export const TagBadge = memo(function TagBadge({
  label,
  onRemove,
  variant = 'default',
  className = '',
}: TagBadgeProps) {
  const variantStyles = {
    default: 'bg-gray-100 text-gray-700',
    outline: 'bg-white border border-gray-300 text-gray-700',
  };

  return (
    <span
      className={`
        inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium
        ${variantStyles[variant]}
        ${className}
      `}
    >
      {label}
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          className="ml-0.5 p-0.5 hover:bg-gray-200 rounded transition-colors"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </span>
  );
});

export default TagBadge;
