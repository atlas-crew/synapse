import { memo } from 'react';
import { Globe2 } from 'lucide-react';
import { ProgressBar } from '../../ctrlx/ProgressBar';
import { Stack } from '@/ui';

interface RegionTraffic {
  code: string;
  name: string;
  percentage: number;
  requests: number;
  flag?: string;
}

interface TrafficByRegionListProps {
  data: RegionTraffic[];
  maxItems?: number;
  className?: string;
}

/**
 * TrafficByRegionList - Country list with flags, names, and percentage bars.
 */
export const TrafficByRegionList = memo(function TrafficByRegionList({
  data,
  maxItems = 8,
  className = '',
}: TrafficByRegionListProps) {
  const displayData = data.slice(0, maxItems);
  const maxPercentage = Math.max(...displayData.map((d) => d.percentage));

  return (
    <div className={`space-y-3 ${className}`}>
      {displayData.map((region) => (
        <Stack key={region.code} direction="row" align="center" gap="md">
          {/* Flag */}
          <span
            className="inline-flex h-6 w-6 items-center justify-center border border-border-subtle bg-surface-subtle"
            aria-label={region.name}
          >
            <Globe2 className="h-3.5 w-3.5 text-ac-blue" />
          </span>

          {/* Country name and percentage */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-medium text-navy-800 truncate">
                {region.name}
              </span>
              <span className="text-sm text-gray-500 ml-2">
                {region.percentage.toFixed(1)}%
              </span>
            </div>
            <ProgressBar
              value={region.percentage}
              max={maxPercentage}
              variant="info"
              size="sm"
            />
          </div>
        </Stack>
      ))}
    </div>
  );
});

// Demo data generator
export function generateRegionTrafficData(): RegionTraffic[] {
  return [
    { code: 'US', name: 'United States', percentage: 37.2, requests: 892000 },
    { code: 'GB', name: 'United Kingdom', percentage: 17.2, requests: 412000 },
    { code: 'DE', name: 'Germany', percentage: 12.4, requests: 297000 },
    { code: 'JP', name: 'Japan', percentage: 8.7, requests: 208000 },
    { code: 'FR', name: 'France', percentage: 6.3, requests: 151000 },
    { code: 'AU', name: 'Australia', percentage: 5.1, requests: 122000 },
    { code: 'CA', name: 'Canada', percentage: 4.8, requests: 115000 },
    { code: 'BR', name: 'Brazil', percentage: 3.2, requests: 77000 },
    { code: 'IN', name: 'India', percentage: 2.8, requests: 67000 },
    { code: 'SG', name: 'Singapore', percentage: 2.3, requests: 55000 },
  ];
}

export default TrafficByRegionList;
