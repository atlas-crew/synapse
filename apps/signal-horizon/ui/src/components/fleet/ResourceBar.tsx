import { memo } from 'react';

interface ResourceBarProps {
  label: string;
  value: number;
  max?: number;
  showPercentage?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

function getColorClass(percentage: number): string {
  if (percentage >= 90) return 'bg-ac-red';
  if (percentage >= 75) return 'bg-ac-orange';
  return 'bg-ac-blue';
}

const sizeClasses = {
  sm: 'h-1.5',
  md: 'h-2.5',
  lg: 'h-4',
};

export const ResourceBar = memo(function ResourceBar({
  label,
  value,
  max = 100,
  showPercentage = true,
  size = 'md',
  className = '',
}: ResourceBarProps) {
  const percentage = Math.min((value / max) * 100, 100);
  const colorClass = getColorClass(percentage);

  return (
    <div className={className}>
      <div className="flex justify-between items-center mb-1">
        <span className="text-sm font-medium text-ink-secondary">{label}</span>
        {showPercentage && (
          <span className="text-sm text-ink-muted">{percentage.toFixed(1)}%</span>
        )}
      </div>
      <div className={`w-full bg-surface-subtle ${sizeClasses[size]}`}>
        <div
          className={`${colorClass} ${sizeClasses[size]} transition-all duration-300`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
});

interface ResourceBarGroupProps {
  cpu: number;
  memory: number;
  disk: number;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const ResourceBarGroup = memo(function ResourceBarGroup({
  cpu,
  memory,
  disk,
  size = 'md',
  className = '',
}: ResourceBarGroupProps) {
  return (
    <div className={`space-y-3 ${className}`}>
      <ResourceBar label="CPU" value={cpu} size={size} />
      <ResourceBar label="Memory" value={memory} size={size} />
      <ResourceBar label="Disk" value={disk} size={size} />
    </div>
  );
});
