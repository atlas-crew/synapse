/**
 * useBandwidth Hook
 * Fetches bandwidth statistics, timeline, and billing metrics from the API
 */

import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { useDemoMode } from '../../stores/demoModeStore';

// ============================================================================
// Types
// ============================================================================

export interface BandwidthDataPoint {
  timestamp: string;
  bytesIn: number;
  bytesOut: number;
  requestCount: number;
}

export interface FleetBandwidthStats {
  totalBytesIn: number;
  totalBytesOut: number;
  totalRequests: number;
  avgBytesPerRequest: number;
  peakBytesIn: number;
  peakBytesOut: number;
  sensorCount: number;
  respondedSensors: number;
  collectedAt: string;
}

export interface SensorBandwidthStats {
  sensorId: string;
  sensorName: string;
  region?: string;
  totalBytesIn: number;
  totalBytesOut: number;
  totalRequests: number;
  avgBytesPerRequest: number;
  maxRequestSize: number;
  maxResponseSize: number;
  collectedAt: string;
  isOnline: boolean;
}

export interface EndpointBandwidthStats {
  endpoint: string;
  methods: string[];
  bytesIn: number;
  bytesOut: number;
  requestCount: number;
  avgResponseSize: number;
  maxResponseSize: number;
  firstSeen: string;
  lastSeen: string;
}

export interface BandwidthTimeline {
  points: BandwidthDataPoint[];
  granularity: '1m' | '5m' | '1h';
  startTime: string;
  endTime: string;
  totalBytesIn: number;
  totalBytesOut: number;
}

export interface EndpointBillingBreakdown {
  endpoint: string;
  bytes: number;
  percentage: number;
  requestCount: number;
}

export interface SensorBillingBreakdown {
  sensorId: string;
  sensorName: string;
  bytes: number;
  percentage: number;
  requestCount: number;
}

export interface BillingMetrics {
  period: {
    start: string;
    end: string;
  };
  totalDataTransfer: number;
  ingressBytes: number;
  egressBytes: number;
  requestCount: number;
  estimatedCost: number;
  costPerGb: number;
  breakdown: EndpointBillingBreakdown[];
  sensorBreakdown: SensorBillingBreakdown[];
}

// ============================================================================
// API Response Types
// ============================================================================

interface ApiResponse<T> {
  success: boolean;
  data: T;
  error?: string;
}

// ============================================================================
// API Functions
// ============================================================================

async function fetchFleetBandwidth(): Promise<FleetBandwidthStats> {
  const response = await apiFetch<ApiResponse<FleetBandwidthStats>>('/fleet/bandwidth');
  if (!response.success) throw new Error(response.error || 'Failed to fetch bandwidth stats');
  return response.data;
}

async function fetchBandwidthTimeline(
  granularity: '1m' | '5m' | '1h',
  duration: number
): Promise<BandwidthTimeline> {
  const response = await apiFetch<ApiResponse<BandwidthTimeline>>(
    `/fleet/bandwidth/timeline?granularity=${granularity}&duration=${duration}`
  );
  if (!response.success) throw new Error(response.error || 'Failed to fetch timeline');
  return response.data;
}

async function fetchEndpointBandwidth(): Promise<EndpointBandwidthStats[]> {
  const response = await apiFetch<ApiResponse<EndpointBandwidthStats[]> & { count: number }>(
    '/fleet/bandwidth/endpoints'
  );
  if (!response.success) throw new Error(response.error || 'Failed to fetch endpoint stats');
  return response.data;
}

async function fetchBillingMetrics(
  start: Date,
  end: Date,
  costPerGb?: number
): Promise<BillingMetrics> {
  const params = new URLSearchParams({
    start: start.toISOString(),
    end: end.toISOString(),
  });
  if (costPerGb !== undefined) {
    params.set('costPerGb', costPerGb.toString());
  }
  const response = await apiFetch<ApiResponse<BillingMetrics>>(
    `/fleet/bandwidth/billing?${params.toString()}`
  );
  if (!response.success) throw new Error(response.error || 'Failed to fetch billing metrics');
  return response.data;
}

async function fetchSensorBandwidth(sensorId: string): Promise<SensorBandwidthStats> {
  const response = await apiFetch<ApiResponse<SensorBandwidthStats>>(
    `/fleet/bandwidth/sensors/${sensorId}`
  );
  if (!response.success) throw new Error(response.error || 'Failed to fetch sensor bandwidth');
  return response.data;
}

// ============================================================================
// Demo Data Generators
// ============================================================================

function generateDemoFleetStats(): FleetBandwidthStats {
  const baseBytes = 50 * 1024 * 1024 * 1024; // 50 GB
  const variation = Math.random() * 0.2 - 0.1;

  return {
    totalBytesIn: Math.round(baseBytes * 0.4 * (1 + variation)),
    totalBytesOut: Math.round(baseBytes * 0.6 * (1 + variation)),
    totalRequests: Math.round(1000000 * (1 + variation)),
    avgBytesPerRequest: Math.round(50 * 1024),
    peakBytesIn: Math.round(500 * 1024 * 1024),
    peakBytesOut: Math.round(800 * 1024 * 1024),
    sensorCount: 5,
    respondedSensors: 5,
    collectedAt: new Date().toISOString(),
  };
}

function generateDemoTimeline(
  granularity: '1m' | '5m' | '1h',
  duration: number
): BandwidthTimeline {
  const bucketSizeMs = granularity === '1m' ? 60000 : granularity === '5m' ? 300000 : 3600000;
  const now = Date.now();
  const startTime = now - duration * 60 * 1000;
  const points: BandwidthDataPoint[] = [];

  let totalBytesIn = 0;
  let totalBytesOut = 0;

  for (let t = startTime; t < now; t += bucketSizeMs) {
    const hour = new Date(t).getHours();
    const isBusinessHours = hour >= 9 && hour <= 17;
    const baseMultiplier = isBusinessHours ? 1.5 : 0.7;

    const bytesIn = Math.round(1024 * 1024 * baseMultiplier * (1 + Math.random() * 0.5));
    const bytesOut = Math.round(1.5 * 1024 * 1024 * baseMultiplier * (1 + Math.random() * 0.5));
    const requestCount = Math.round(1000 * baseMultiplier * (1 + Math.random() * 0.3));

    points.push({
      timestamp: new Date(t).toISOString(),
      bytesIn,
      bytesOut,
      requestCount,
    });

    totalBytesIn += bytesIn;
    totalBytesOut += bytesOut;
  }

  return {
    points,
    granularity,
    startTime: new Date(startTime).toISOString(),
    endTime: new Date(now).toISOString(),
    totalBytesIn,
    totalBytesOut,
  };
}

function generateDemoEndpointStats(): EndpointBandwidthStats[] {
  const endpoints = [
    '/api/v1/users',
    '/api/v1/products',
    '/api/v1/orders',
    '/api/v1/auth/login',
    '/api/v1/auth/refresh',
    '/api/v1/search',
    '/api/v1/analytics',
    '/api/v1/uploads',
    '/health',
    '/api/v1/notifications',
  ];

  const now = Date.now();
  return endpoints.map((endpoint, i) => {
    const requestCount = Math.round(100000 / (i + 1) + Math.random() * 10000);
    const avgResponseSize = Math.round(2048 * (1 + Math.random()));
    const bytesOut = requestCount * avgResponseSize;
    const bytesIn = Math.round(requestCount * 500);

    return {
      endpoint,
      methods: i < 3 ? ['GET', 'POST', 'PUT', 'DELETE'] : ['GET', 'POST'],
      bytesIn,
      bytesOut,
      requestCount,
      avgResponseSize,
      maxResponseSize: avgResponseSize * 10,
      firstSeen: new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString(),
      lastSeen: new Date(now - Math.random() * 60000).toISOString(),
    };
  });
}

function generateDemoBillingMetrics(start: Date, end: Date): BillingMetrics {
  const totalDataTransfer = 75 * 1024 * 1024 * 1024; // 75 GB
  const ingressBytes = Math.round(totalDataTransfer * 0.4);
  const egressBytes = Math.round(totalDataTransfer * 0.6);
  const costPerGb = 0.085;
  const estimatedCost = Math.round((totalDataTransfer / (1024 * 1024 * 1024)) * costPerGb * 100) / 100;

  const endpoints = generateDemoEndpointStats();
  const breakdown = endpoints.slice(0, 5).map((ep) => {
    const bytes = ep.bytesIn + ep.bytesOut;
    return {
      endpoint: ep.endpoint,
      bytes,
      percentage: Math.round((bytes / totalDataTransfer) * 10000) / 100,
      requestCount: ep.requestCount,
    };
  });

  const sensorBreakdown = [
    { sensorId: 'sensor-1', sensorName: 'prod-us-east-1', bytes: Math.round(totalDataTransfer * 0.35), percentage: 35, requestCount: 350000 },
    { sensorId: 'sensor-2', sensorName: 'prod-us-west-2', bytes: Math.round(totalDataTransfer * 0.28), percentage: 28, requestCount: 280000 },
    { sensorId: 'sensor-3', sensorName: 'prod-eu-west-1', bytes: Math.round(totalDataTransfer * 0.22), percentage: 22, requestCount: 220000 },
    { sensorId: 'sensor-4', sensorName: 'prod-ap-southeast-1', bytes: Math.round(totalDataTransfer * 0.10), percentage: 10, requestCount: 100000 },
    { sensorId: 'sensor-5', sensorName: 'staging-us-east-1', bytes: Math.round(totalDataTransfer * 0.05), percentage: 5, requestCount: 50000 },
  ];

  return {
    period: {
      start: start.toISOString(),
      end: end.toISOString(),
    },
    totalDataTransfer,
    ingressBytes,
    egressBytes,
    requestCount: 1000000,
    estimatedCost,
    costPerGb,
    breakdown,
    sensorBreakdown,
  };
}

// ============================================================================
// Hooks
// ============================================================================

/**
 * Hook to fetch fleet-wide bandwidth statistics
 */
export function useFleetBandwidth() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'bandwidth', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return generateDemoFleetStats();
      }
      return fetchFleetBandwidth();
    },
    refetchInterval: isDemoMode ? false : 30000,
    staleTime: isDemoMode ? Infinity : 25000,
  });
}

/**
 * Hook to fetch bandwidth timeline for visualization
 */
export function useBandwidthTimeline(
  granularity: '1m' | '5m' | '1h' = '5m',
  durationMinutes: number = 60
) {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'bandwidth', 'timeline', granularity, durationMinutes, isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return generateDemoTimeline(granularity, durationMinutes);
      }
      return fetchBandwidthTimeline(granularity, durationMinutes);
    },
    refetchInterval: isDemoMode ? false : 30000,
    staleTime: isDemoMode ? Infinity : 25000,
  });
}

/**
 * Hook to fetch per-endpoint bandwidth breakdown
 */
export function useEndpointBandwidth() {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'bandwidth', 'endpoints', isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return generateDemoEndpointStats();
      }
      return fetchEndpointBandwidth();
    },
    refetchInterval: isDemoMode ? false : 60000,
    staleTime: isDemoMode ? Infinity : 55000,
  });
}

/**
 * Hook to fetch billing metrics for a time period
 */
export function useBillingMetrics(
  start: Date,
  end: Date,
  costPerGb?: number
) {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'bandwidth', 'billing', start.toISOString(), end.toISOString(), costPerGb, isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return generateDemoBillingMetrics(start, end);
      }
      return fetchBillingMetrics(start, end, costPerGb);
    },
    refetchInterval: isDemoMode ? false : 60000,
    staleTime: isDemoMode ? Infinity : 55000,
  });
}

/**
 * Hook to fetch bandwidth for a specific sensor
 */
export function useSensorBandwidth(sensorId: string) {
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'bandwidth', 'sensor', sensorId, isDemoMode ? scenario : 'live'],
    queryFn: () => {
      if (isDemoMode) {
        return {
          sensorId,
          sensorName: `Sensor ${sensorId}`,
          region: 'us-east-1',
          totalBytesIn: Math.round(10 * 1024 * 1024 * 1024 * Math.random()),
          totalBytesOut: Math.round(15 * 1024 * 1024 * 1024 * Math.random()),
          totalRequests: Math.round(200000 * Math.random()),
          avgBytesPerRequest: Math.round(50 * 1024),
          maxRequestSize: Math.round(5 * 1024 * 1024),
          maxResponseSize: Math.round(10 * 1024 * 1024),
          collectedAt: new Date().toISOString(),
          isOnline: true,
        } as SensorBandwidthStats;
      }
      return fetchSensorBandwidth(sensorId);
    },
    refetchInterval: isDemoMode ? false : 30000,
    staleTime: isDemoMode ? Infinity : 25000,
    enabled: !!sensorId,
  });
}

/**
 * Combined hook for bandwidth dashboard
 * Fetches all bandwidth data in parallel
 */
export function useBandwidthDashboard(options?: {
  timelineGranularity?: '1m' | '5m' | '1h';
  timelineDuration?: number;
  billingStart?: Date;
  billingEnd?: Date;
}) {
  const {
    timelineGranularity = '5m',
    timelineDuration = 60,
    billingStart = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    billingEnd = new Date(),
  } = options || {};

  const fleetStats = useFleetBandwidth();
  const timeline = useBandwidthTimeline(timelineGranularity, timelineDuration);
  const endpoints = useEndpointBandwidth();
  const billing = useBillingMetrics(billingStart, billingEnd);

  return {
    fleetStats,
    timeline,
    endpoints,
    billing,
    isLoading: fleetStats.isLoading || timeline.isLoading || endpoints.isLoading || billing.isLoading,
    isError: fleetStats.isError || timeline.isError || endpoints.isError || billing.isError,
    error: fleetStats.error || timeline.error || endpoints.error || billing.error,
  };
}
