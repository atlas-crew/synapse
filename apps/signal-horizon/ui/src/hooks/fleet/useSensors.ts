import { useQuery } from '@tanstack/react-query';
import type { SensorSummary } from '../../types/fleet';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';
import { fleetKeys, getQueryMode } from '../../lib/queryKeys';
import { ApiError } from '../../lib/api';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3100';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';

async function fetchSensors(): Promise<SensorSummary[]> {
  const response = await fetch(`${API_BASE}/api/v1/fleet/sensors`, {
    headers: {
      'Authorization': `Bearer ${API_KEY}`,
    },
  });
  if (!response.ok) {
    let serverMessage: string | undefined;
    try {
      const body = await response.json();
      serverMessage = body.error ?? body.message;
    } catch { /* no parseable body */ }
    throw new ApiError(
      response.status,
      serverMessage
        ? `Failed to fetch sensors (${response.status}: ${serverMessage})`
        : `Failed to fetch sensors (${response.status} ${response.statusText})`,
      serverMessage,
    );
  }
  const data = await response.json();
  return data.sensors || data;
}

/**
 * Hook to fetch sensors from the API or return demo data when demo mode is enabled.
 */
export function useSensors() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();
  const mode = getQueryMode(isDemoMode, scenario);

  return useQuery({
    queryKey: fleetKeys.sensors(mode),
    queryFn: () => {
      // Return demo data when demo mode is enabled
      if (isDemoMode) {
        const demoData = getDemoData(scenario);
        return demoData.fleet.sensors as SensorSummary[];
      }
      return fetchSensors();
    },
    // Disable polling in demo mode (static snapshot)
    refetchInterval: isDemoMode ? false : 5000,
    staleTime: isDemoMode ? Infinity : 4000,
  });
}
