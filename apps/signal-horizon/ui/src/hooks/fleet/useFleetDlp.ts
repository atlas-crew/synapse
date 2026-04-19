import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

/**
 * Aggregate DLP (Data Loss Prevention) telemetry across the fleet.
 *
 * Horizon now exposes fleet-native DLP endpoints backed by the latest
 * per-sensor payload snapshots. The API returns an aggregate plus a
 * per-sensor partial-results envelope so the dashboard can stay resilient
 * when some sensors have stale or missing snapshots.
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
  partial: {
    succeeded: number;
    failed: number;
    failedSensorIds: string[];
  };
}

type DemoDlpViolation = ReturnType<typeof getDemoData>['fleet']['dlp']['violations'][number];

interface FleetPartialAggregateResponse<TItem, TAggregate> {
  aggregate: TAggregate;
  results: Array<{
    sensorId: string;
    status: 'ok' | 'error';
    data?: TItem;
    error?: string;
  }>;
  summary: {
    succeeded: number;
    failed: number;
  };
  error?: {
    code: string;
    message: string;
  };
}

export function useFleetDlp() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'dlp', isDemoMode ? `demo:${scenario}` : 'live'],
    queryFn: async (): Promise<FleetDlpData> => {
      if (isDemoMode) {
        const demo = getDemoData(scenario);
        const violations: FleetDlpViolation[] = (demo.fleet.dlp.violations ?? []).map(
          (v: DemoDlpViolation) => ({
            timestamp: v.timestamp,
            pattern_name: v.pattern_name,
            data_type: v.data_type,
            severity: v.severity,
            masked_value: v.masked_value,
            client_ip: v.client_ip,
            path: v.path,
            sensorId:
              'sensorId' in v && typeof v.sensorId === 'string' ? v.sensorId : 'demo-sensor',
            sensorName:
              'sensorName' in v && typeof v.sensorName === 'string'
                ? v.sensorName
                : 'Demo Sensor',
          }),
        );
        return {
          stats: demo.fleet.dlp.stats,
          violations,
          partial: {
            succeeded: 1,
            failed: 0,
            failedSensorIds: [],
          },
        };
      }
      const [statsResponse, violationsResponse] = await Promise.all([
        apiFetch<FleetPartialAggregateResponse<FleetDlpStats, FleetDlpStats>>('/synapse/dlp/stats'),
        apiFetch<FleetPartialAggregateResponse<FleetDlpViolation[], FleetDlpViolation[]>>(
          '/synapse/dlp/violations'
        ),
      ]);

      const sensorIds = new Set([
        ...statsResponse.results.map((result) => result.sensorId),
        ...violationsResponse.results.map((result) => result.sensorId),
      ]);
      const failedSensorIds = Array.from(
        new Set(
          [...statsResponse.results, ...violationsResponse.results]
            .filter((result) => result.status === 'error')
            .map((result) => result.sensorId)
        )
      );

      return {
        stats: statsResponse.aggregate,
        violations: [...violationsResponse.aggregate].sort((a, b) => b.timestamp - a.timestamp),
        partial: {
          succeeded: sensorIds.size - failedSensorIds.length,
          failed: failedSensorIds.length,
          failedSensorIds,
        },
      };
    },
    refetchInterval: isDemoMode ? false : 10000,
    staleTime: isDemoMode ? Infinity : 5000,
  });
}
