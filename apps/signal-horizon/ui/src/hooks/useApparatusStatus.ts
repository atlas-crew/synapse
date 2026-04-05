/**
 * Hook to fetch Apparatus integration status from the management API.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { apiFetch } from '../lib/api';
import { useDemoMode } from '../stores/demoModeStore';

export interface ApparatusStatus {
  state: 'disabled' | 'disconnected' | 'connecting' | 'connected' | 'error';
  url?: string;
  version?: string;
  lastHealthCheck?: string;
  lastError?: string;
}

interface IntegrationsResponse {
  apparatus: ApparatusStatus;
}

const DEMO_STATUS: ApparatusStatus = {
  state: 'connected',
  url: 'http://apparatus:8090',
  version: '0.9.1',
};

export function useApparatusStatus(pollingIntervalMs = 30_000) {
  const { isEnabled: isDemo } = useDemoMode();

  const [status, setStatus] = useState<ApparatusStatus>({ state: 'disabled' });
  const [isLoading, setIsLoading] = useState(!isDemo);
  const [error, setError] = useState<Error | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const data = await apiFetch<IntegrationsResponse>('/management/integrations');
      setStatus(data.apparatus);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isDemo) {
      setStatus({ ...DEMO_STATUS, lastHealthCheck: new Date().toISOString() });
      setIsLoading(false);
      return;
    }

    fetchStatus();
    intervalRef.current = setInterval(fetchStatus, pollingIntervalMs);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isDemo, fetchStatus, pollingIntervalMs]);

  return { status, isLoading, error, refetch: isDemo ? async () => {} : fetchStatus };
}
