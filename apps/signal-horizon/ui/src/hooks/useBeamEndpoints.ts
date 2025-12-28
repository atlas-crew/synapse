/**
 * useBeamEndpoints Hook
 * Fetches API endpoint catalog data from Signal Horizon API
 */

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import type { Endpoint, Service } from '../types/beam';

// ============================================================================
// API Response Types
// ============================================================================

interface EndpointsApiResponse {
  endpoints: ApiEndpoint[];
}

interface ApiEndpoint {
  id: string;
  method: string;
  pathTemplate: string;
  service: string;
  lastSeenAt: string;
  createdAt: string;
  sensor?: { id: string; name: string };
  _count?: { schemaChanges: number; ruleBindings: number };
}

interface EndpointDetailResponse {
  endpoint: ApiEndpoint & {
    schemaChanges: ApiSchemaChange[];
    ruleBindings: { rule: { id: string; name: string; enabled: boolean } }[];
  };
}

interface ApiSchemaChange {
  id: string;
  field: string;
  changeType: string;
  oldValue?: string;
  newValue?: string;
  detectedAt: string;
}

// ============================================================================
// Hook Configuration
// ============================================================================

export interface EndpointQueryParams {
  service?: string;
  method?: string;
  limit?: number;
}

export interface UseBeamEndpointsOptions {
  /** Polling interval in milliseconds (default: 60000 = 60s) */
  pollingInterval?: number;
  /** Whether to start fetching immediately (default: true) */
  autoFetch?: boolean;
  /** API base URL (default: /api/v1) */
  apiBaseUrl?: string;
  /** Query parameters for filtering */
  queryParams?: EndpointQueryParams;
}

export interface UseBeamEndpointsResult {
  endpoints: Endpoint[];
  services: Service[];
  isLoading: boolean;
  error: Error | null;
  refetch: () => Promise<void>;
  fetchEndpointById: (id: string) => Promise<Endpoint | null>;
  isConnected: boolean;
  lastUpdated: Date | null;
}

// ============================================================================
// Demo Data Generator
// ============================================================================

function generateDemoEndpoints(): Endpoint[] {
  const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] as const;
  const services = ['user-service', 'product-service', 'order-service', 'auth-service', 'payment-service'];
  const riskLevels = ['low', 'medium', 'high', 'critical'] as const;

  return Array.from({ length: 50 }, (_, i) => {
    const method = methods[Math.floor(Math.random() * methods.length)];
    const service = services[Math.floor(Math.random() * services.length)];
    const riskLevel = riskLevels[Math.floor(Math.random() * riskLevels.length)];

    return {
      id: `ep-${i + 1}`,
      method,
      path: `/api/v2/${service.split('-')[0]}/${i % 10 === 0 ? '{id}' : 'list'}`,
      pathTemplate: `/api/v2/${service.split('-')[0]}/${i % 10 === 0 ? ':id' : 'list'}`,
      service,
      riskLevel,
      sensitiveFields: riskLevel === 'high' || riskLevel === 'critical'
        ? ['password', 'ssn', 'credit_card']
        : [],
      protectionStatus: Math.random() > 0.2 ? 'protected' : 'unprotected',
      activeRules: [`rule-${Math.floor(Math.random() * 10) + 1}`],
      requestCount24h: Math.floor(Math.random() * 100000),
      lastSeen: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      firstSeen: new Date(Date.now() - Math.random() * 30 * 86400000).toISOString(),
    };
  });
}

function generateDemoServices(endpoints: Endpoint[]): Service[] {
  const serviceMap = new Map<string, { total: number; protected: number }>();

  endpoints.forEach(ep => {
    const current = serviceMap.get(ep.service) || { total: 0, protected: 0 };
    current.total++;
    if (ep.protectionStatus === 'protected') current.protected++;
    serviceMap.set(ep.service, current);
  });

  return Array.from(serviceMap.entries()).map(([name, counts]) => ({
    id: name,
    name,
    endpointCount: counts.total,
    protectedCount: counts.protected,
    coveragePercent: Math.round((counts.protected / counts.total) * 100),
  }));
}

// ============================================================================
// Hook Implementation
// ============================================================================

export function useBeamEndpoints(options: UseBeamEndpointsOptions = {}): UseBeamEndpointsResult {
  const {
    pollingInterval = 60000,
    autoFetch = true,
    apiBaseUrl = '/api/v1',
    queryParams = {},
  } = options;

  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const intervalRef = useRef<number | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // Derive services from endpoints
  const services = useMemo(() => generateDemoServices(endpoints), [endpoints]);

  const fetchData = useCallback(async () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsLoading(true);

    try {
      const params = new URLSearchParams();
      if (queryParams.service) params.set('service', queryParams.service);
      if (queryParams.method) params.set('method', queryParams.method);
      if (queryParams.limit) params.set('limit', queryParams.limit.toString());

      const url = `${apiBaseUrl}/beam/endpoints${params.toString() ? `?${params}` : ''}`;

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as EndpointsApiResponse;

      // Transform API response to UI types
      const transformedEndpoints: Endpoint[] = data.endpoints.map(ep => ({
        id: ep.id,
        method: ep.method as Endpoint['method'],
        path: ep.pathTemplate,
        pathTemplate: ep.pathTemplate,
        service: ep.service,
        riskLevel: 'medium', // Default, will be calculated server-side in future
        sensitiveFields: [],
        protectionStatus: (ep._count?.ruleBindings ?? 0) > 0 ? 'protected' : 'unprotected',
        activeRules: [],
        requestCount24h: 0, // Not provided by current API
        lastSeen: ep.lastSeenAt,
        firstSeen: ep.createdAt,
      }));

      setEndpoints(transformedEndpoints);
      setIsConnected(true);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      if ((err as Error).name === 'AbortError') return;

      console.warn('Failed to fetch beam endpoints, using demo data:', err);
      setError(err as Error);
      setIsConnected(false);

      if (endpoints.length === 0) {
        setEndpoints(generateDemoEndpoints());
      }
    } finally {
      setIsLoading(false);
    }
  }, [apiBaseUrl, queryParams, endpoints.length]);

  const fetchEndpointById = useCallback(async (id: string): Promise<Endpoint | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/beam/endpoints/${id}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        if (response.status === 404) return null;
        throw new Error(`API error: ${response.status}`);
      }

      const data = await response.json() as EndpointDetailResponse;
      const ep = data.endpoint;

      return {
        id: ep.id,
        method: ep.method as Endpoint['method'],
        path: ep.pathTemplate,
        pathTemplate: ep.pathTemplate,
        service: ep.service,
        riskLevel: 'medium',
        sensitiveFields: [],
        protectionStatus: ep.ruleBindings.length > 0 ? 'protected' : 'unprotected',
        activeRules: ep.ruleBindings.filter(rb => rb.rule.enabled).map(rb => rb.rule.id),
        requestCount24h: 0,
        lastSeen: ep.lastSeenAt,
        firstSeen: ep.createdAt,
      };
    } catch (err) {
      console.warn('Failed to fetch endpoint details:', err);
      return null;
    }
  }, [apiBaseUrl]);

  useEffect(() => {
    if (autoFetch) fetchData();
    return () => { abortControllerRef.current?.abort(); };
  }, [autoFetch, fetchData]);

  useEffect(() => {
    if (pollingInterval > 0) {
      intervalRef.current = window.setInterval(fetchData, pollingInterval);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [pollingInterval, fetchData]);

  return {
    endpoints,
    services,
    isLoading,
    error,
    refetch: fetchData,
    fetchEndpointById,
    isConnected,
    lastUpdated,
  };
}

export default useBeamEndpoints;
