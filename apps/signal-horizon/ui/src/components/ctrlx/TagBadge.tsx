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
 * Theme-aware styling following Signal Horizon design system.
 */
export const TagBadge = memo(function TagBadge({
  label,
  onRemove,
  variant = 'default',
  className = '',
}: TagBadgeProps) {
  const variantStyles = {
    default: 'bg-surface-subtle dark:bg-surface-card text-ink-secondary border border-border-subtle',
    outline: 'bg-white dark:bg-transparent border border-border-subtle dark:border-border-strong text-ink-secondary',
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
          className="ml-0.5 p-0.5 hover:bg-surface-card dark:hover:bg-surface-subtle transition-colors"
        >
          <X className="w-3 h-3" />
        </button>
      )}
    </span>
  );
});

export default TagBadge;
