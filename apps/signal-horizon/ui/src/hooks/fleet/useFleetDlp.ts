import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import type { SensorSummary } from '../../types/fleet';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

/**
 * Aggregate DLP (Data Loss Prevention) telemetry across the fleet.
 *
 * Each Synapse sensor exposes `/_sensor/dlp/stats` and `/_sensor/dlp/violations`
 * via the Horizon proxy. We fan out both endpoints per-sensor and combine:
 *   - stats: sum counters; keep the max pattern count (same on every sensor
 *     in practice but we don't rely on that invariant).
 *   - violations: concat all sensors' violations, tagging each with the
 *     sensor it came from so the UI can group/filter.
 *
 * Offline or permission-denied sensors return empty — the dashboard shows
 * partial data rather than failing. Matches the pattern used by
 * useFleetSites.
 */

export interface FleetDlpStats {
  totalScans: number;
  totalMatches: number;
  patternCount: number;
}

export interface FleetDlpViolation {
  timestamp: number;
  pattern_name: string;
  data_type: string;
  severity: string;
  masked_value: string;
  client_ip?: string;
  path: string;
  sensorId: string;
  sensorName: string;
}

export interface FleetDlpData {
  stats: FleetDlpStats;
  violations: FleetDlpViolation[];
}

async function fetchSensors(): Promise<SensorSummary[]> {
  const data = await apiFetch<{ sensors?: SensorSummary[] } | SensorSummary[]>(
    '/fleet/sensors',
  );
  return Array.isArray(data) ? data : data.sensors ?? [];
}

async function fetchStatsForSensor(sensor: SensorSummary): Promise<FleetDlpStats | null> {
  try {
    return await apiFetch<FleetDlpStats>(
      `/synapse/${encodeURIComponent(sensor.id)}/proxy/_sensor/dlp/stats`,
    );
  } catch {
    return null;
  }
}

async function fetchViolationsForSensor(
  sensor: SensorSummary,
): Promise<FleetDlpViolation[]> {
  try {
    const response = await apiFetch<{ violations?: Array<Omit<FleetDlpViolation, 'sensorId' | 'sensorName'>> }>(
      `/synapse/${encodeURIComponent(sensor.id)}/proxy/_sensor/dlp/violations`,
    );
    const raw = response.violations ?? [];
    return raw.map((v) => ({
      ...v,
      sensorId: sensor.id,
      sensorName: sensor.name ?? sensor.id,
    }));
  } catch {
    return [];
  }
}

export function useFleetDlp() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'dlp', isDemoMode ? `demo:${scenario}` : 'live'],
    queryFn: async (): Promise<FleetDlpData> => {
      if (isDemoMode) {
        const demo = getDemoData(scenario);
        const violations: FleetDlpViolation[] = (demo.fleet.dlp.violations ?? []).map(
          (v: any) => ({
            timestamp: v.timestamp,
            pattern_name: v.pattern_name,
            data_type: v.data_type,
            severity: v.severity,
            masked_value: v.masked_value,
            client_ip: v.client_ip,
            path: v.path,
            sensorId: v.sensorId ?? 'demo-sensor',
            sensorName: v.sensorName ?? 'Demo Sensor',
          }),
        );
        return {
          stats: demo.fleet.dlp.stats,
          violations,
        };
      }

      const sensors = await fetchSensors();
      const [statsResults, violationsResults] = await Promise.all([
        Promise.all(sensors.map(fetchStatsForSensor)),
        Promise.all(sensors.map(fetchViolationsForSensor)),
      ]);

      const stats: FleetDlpStats = statsResults.reduce<FleetDlpStats>(
        (acc, s) => {
          if (!s) return acc;
          return {
            totalScans: acc.totalScans + (s.totalScans ?? 0),
            totalMatches: acc.totalMatches + (s.totalMatches ?? 0),
            patternCount: Math.max(acc.patternCount, s.patternCount ?? 0),
          };
        },
        { totalScans: 0, totalMatches: 0, patternCount: 0 },
      );

      const violations = violationsResults
        .flat()
        .sort((a, b) => b.timestamp - a.timestamp);

      return { stats, violations };
    },
    refetchInterval: isDemoMode ? false : 10000,
    staleTime: isDemoMode ? Infinity : 5000,
  });
}
