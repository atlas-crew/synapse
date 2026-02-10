/**
 * useConnectivity Hook
 *
 * Wire-up for Management Connectivity endpoints:
 * - GET /api/v1/management/connectivity
 * - POST /api/v1/management/connectivity/test
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

import { apiFetch } from '../../lib/api';

export type ConnectivityState = 'CONNECTED' | 'DISCONNECTED' | 'RECONNECTING';

export interface ConnectivitySensor {
  id: string;
  name: string;
  connectionState: ConnectivityState;
  lastHeartbeat: string | null;
}

export interface ConnectivityStatusResponse {
  stats: {
    total: number;
    online: number;
    offline: number;
    reconnecting: number;
    recentlyActive: number;
  };
  sensors: Record<ConnectivityState, ConnectivitySensor[]>;
  timestamp: string;
}

export type ConnectivityTestType =
  | 'ping'
  | 'dns'
  | 'tls'
  | 'traceroute'
  | 'http1'
  | 'http2'
  | 'h2c'
  | 'tcp'
  | 'udp'
  | 'grpc'
  | 'mqtt'
  | 'redis'
  | 'smtp'
  | 'icap'
  | 'syslog';

export interface ConnectivityTestResult {
  testType: ConnectivityTestType;
  status: 'passed' | 'failed' | 'error';
  target: string;
  latencyMs: number | null;
  details: Record<string, unknown>;
  errorType?: string;
  error?: string;
  timestamp: string;
}

export interface ConnectivityTestResponse {
  result: ConnectivityTestResult;
  remote?: boolean;
  commandIds?: string[];
  request: {
    testType: ConnectivityTestType;
    target: string;
  };
  metadata: {
    timestamp: string;
    requestId?: string;
  };
}

async function fetchConnectivityStatus(): Promise<ConnectivityStatusResponse> {
  return apiFetch<ConnectivityStatusResponse>('/management/connectivity');
}

async function runConnectivityTest(params: {
  testType: ConnectivityTestType;
  target?: string;
  sensorIds?: string[];
}): Promise<ConnectivityTestResponse> {
  return apiFetch<ConnectivityTestResponse>('/management/connectivity/test', {
    method: 'POST',
    body: params,
  });
}

export function useConnectivity() {
  const queryClient = useQueryClient();

  const statusQuery = useQuery({
    queryKey: ['management', 'connectivity'],
    queryFn: fetchConnectivityStatus,
    refetchInterval: 30000,
  });

  const testMutation = useMutation({
    mutationFn: runConnectivityTest,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['management', 'connectivity'] });
    },
  });

  return {
    status: statusQuery.data || null,
    isLoadingStatus: statusQuery.isLoading,
    statusError: statusQuery.error as Error | null,
    refreshStatus: () => queryClient.invalidateQueries({ queryKey: ['management', 'connectivity'] }),

    runTest: testMutation.mutateAsync,
    isTesting: testMutation.isPending,
    testResult: testMutation.data || null,
    testError: testMutation.error as Error | null,
  };
}

export default useConnectivity;
