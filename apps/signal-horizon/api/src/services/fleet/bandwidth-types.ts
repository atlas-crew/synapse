/**
 * Bandwidth Billing Metrics Types
 * Types for fleet-wide bandwidth aggregation and billing calculations
 */

/**
 * Single data point in a bandwidth timeline
 */
export interface BandwidthDataPoint {
  /** Timestamp (ISO 8601) */
  timestamp: Date;
  /** Bytes received during this period */
  bytesIn: number;
  /** Bytes sent during this period */
  bytesOut: number;
  /** Request count during this period */
  requestCount: number;
}

/**
 * Fleet-wide aggregated bandwidth statistics
 */
export interface FleetBandwidthStats {
  /** Total bytes received across all sensors */
  totalBytesIn: number;
  /** Total bytes sent across all sensors */
  totalBytesOut: number;
  /** Total requests processed */
  totalRequests: number;
  /** Average bytes per request (in + out) */
  avgBytesPerRequest: number;
  /** Peak bytes received in a single period */
  peakBytesIn: number;
  /** Peak bytes sent in a single period */
  peakBytesOut: number;
  /** Number of sensors included in aggregation */
  sensorCount: number;
  /** Number of sensors that responded */
  respondedSensors: number;
  /** Time of collection */
  collectedAt: Date;
}

/**
 * Per-sensor bandwidth statistics
 */
export interface SensorBandwidthStats {
  /** Sensor identifier */
  sensorId: string;
  /** Sensor name for display */
  sensorName: string;
  /** Sensor region */
  region?: string;
  /** Total bytes received */
  totalBytesIn: number;
  /** Total bytes sent */
  totalBytesOut: number;
  /** Total requests processed */
  totalRequests: number;
  /** Average bytes per request */
  avgBytesPerRequest: number;
  /** Maximum request size observed */
  maxRequestSize: number;
  /** Maximum response size observed */
  maxResponseSize: number;
  /** Time of collection */
  collectedAt: Date;
  /** Whether the sensor responded */
  isOnline: boolean;
}

/**
 * Per-endpoint bandwidth breakdown
 */
export interface EndpointBandwidthStats {
  /** Endpoint path pattern */
  endpoint: string;
  /** HTTP methods observed */
  methods: string[];
  /** Bytes received for this endpoint */
  bytesIn: number;
  /** Bytes sent for this endpoint */
  bytesOut: number;
  /** Request count for this endpoint */
  requestCount: number;
  /** Average response size */
  avgResponseSize: number;
  /** Maximum response size */
  maxResponseSize: number;
  /** First seen timestamp */
  firstSeen: Date;
  /** Last seen timestamp */
  lastSeen: Date;
}

/**
 * Bandwidth timeline for visualization
 */
export interface BandwidthTimeline {
  /** Array of data points */
  points: BandwidthDataPoint[];
  /** Granularity of the timeline */
  granularity: '1m' | '5m' | '1h';
  /** Start of the time range */
  startTime: Date;
  /** End of the time range */
  endTime: Date;
  /** Total bytes in over the entire timeline */
  totalBytesIn: number;
  /** Total bytes out over the entire timeline */
  totalBytesOut: number;
}

/**
 * Billing metrics for a specific period
 */
export interface BillingMetrics {
  /** Billing period */
  period: {
    start: Date;
    end: Date;
  };
  /** Total data transfer (ingress + egress) in bytes */
  totalDataTransfer: number;
  /** Total ingress in bytes */
  ingressBytes: number;
  /** Total egress in bytes */
  egressBytes: number;
  /** Total request count */
  requestCount: number;
  /** Estimated cost based on $/GB rate */
  estimatedCost: number;
  /** Rate used for calculation ($/GB) */
  costPerGb: number;
  /** Breakdown by endpoint */
  breakdown: EndpointBillingBreakdown[];
  /** Breakdown by sensor */
  sensorBreakdown: SensorBillingBreakdown[];
}

/**
 * Per-endpoint billing breakdown
 */
export interface EndpointBillingBreakdown {
  /** Endpoint path */
  endpoint: string;
  /** Total bytes for this endpoint */
  bytes: number;
  /** Percentage of total */
  percentage: number;
  /** Request count */
  requestCount: number;
}

/**
 * Per-sensor billing breakdown
 */
export interface SensorBillingBreakdown {
  /** Sensor identifier */
  sensorId: string;
  /** Sensor name */
  sensorName: string;
  /** Total bytes for this sensor */
  bytes: number;
  /** Percentage of total */
  percentage: number;
  /** Request count */
  requestCount: number;
}

/**
 * Response from a single sensor's bandwidth query
 */
export interface SensorBandwidthResponse {
  sensorId: string;
  success: boolean;
  error?: string;
  data?: {
    totalBytes: number;
    totalBytesIn: number;
    totalBytesOut: number;
    avgBytesPerRequest: number;
    maxRequestSize: number;
    maxResponseSize: number;
    requestCount: number;
    timeline: Array<{
      timestamp: number;
      bytesIn: number;
      bytesOut: number;
      requestCount: number;
    }>;
    endpointStats: Array<{
      path: string;
      methods: string[];
      hitCount: number;
      firstSeen: number;
      lastSeen: number;
    }>;
  };
}

/**
 * Query parameters for bandwidth timeline
 */
export interface BandwidthTimelineQuery {
  tenantId: string;
  granularity?: '1m' | '5m' | '1h';
  /** Duration in minutes (default: 60) */
  durationMinutes?: number;
}

/**
 * Query parameters for billing metrics
 */
export interface BillingMetricsQuery {
  tenantId: string;
  start: Date;
  end: Date;
  /** Cost per GB in dollars (default: 0.085) */
  costPerGb?: number;
}
