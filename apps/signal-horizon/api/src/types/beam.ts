/**
 * Beam Analytics Types
 * Types for risk-server data aggregation and analytics display
 */

// ============================================================================
// Traffic Overview
// ============================================================================

export interface TrafficTimelinePoint {
  timestamp: string; // ISO 8601
  requests: number;
  blocked: number;
  bytesIn: number;
  bytesOut: number;
}

export interface TrafficOverview {
  totalRequests: number;
  totalBlocked: number;
  totalBandwidthIn: number;  // bytes
  totalBandwidthOut: number; // bytes
  blockRate: number;         // percentage
  timeline: TrafficTimelinePoint[];
}

// ============================================================================
// Bandwidth Analytics (from risk-server /_sensor/payload/bandwidth)
// ============================================================================

export interface BandwidthTimelineBucket {
  timestamp: string;
  bytesIn: number;
  bytesOut: number;
  requestCount: number;
}

export interface EndpointBandwidth {
  template: string;      // e.g., "/api/v2/users/{id}"
  method: string;        // HTTP method
  requests: number;
  avgRequestSize: number;
  avgResponseSize: number;
  totalBytes: number;
}

export interface BandwidthAnalytics {
  timeline: BandwidthTimelineBucket[];
  topEndpoints: EndpointBandwidth[];
  totalBytesIn: number;
  totalBytesOut: number;
  avgBytesPerRequest: number;
}

// ============================================================================
// Threat/Anomaly Data (from risk-server /_sensor/anomalies)
// ============================================================================

export interface ThreatEvent {
  id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;          // e.g., 'SQL_INJECTION', 'XSS', 'BOT_TRAFFIC'
  description: string;
  entityId?: string;
  sourceIp?: string;
  blocked: boolean;
}

export interface ThreatSummary {
  total: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  byType: Record<string, number>;
  recentEvents: ThreatEvent[];
}

// ============================================================================
// Sensor Status (from risk-server /_sensor/status)
// ============================================================================

export interface SensorMetrics {
  requestsTotal: number;
  blocksTotal: number;
  entitiesTracked: number;
  activeCampaigns: number;
  uptime: number;
  rps: number;
  latencyP50: number;
  latencyP95: number;
  latencyP99: number;
}

// ============================================================================
// Top Endpoints (from risk-server /_sensor/payload/top-endpoints)
// ============================================================================

export interface TopEndpoint {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  path: string;
  requests: number;
  avgLatency: number;
  errorRate: number;
  bandwidthIn: number;
  bandwidthOut: number;
}

// ============================================================================
// Response Time Distribution (Demo data - not available from risk-server)
// ============================================================================

export interface ResponseTimeBucket {
  range: string;     // e.g., "<25ms", "25-50ms"
  count: number;
  percentage: number;
}

// ============================================================================
// Traffic by Region (Demo data - not available from risk-server)
// ============================================================================

export interface RegionTraffic {
  countryCode: string;  // ISO 3166-1 alpha-2
  countryName: string;
  requests: number;
  percentage: number;
  blocked: number;
}

// ============================================================================
// Status Codes (Demo data - not available from risk-server)
// ============================================================================

export interface StatusCodeDistribution {
  code2xx: number;
  code3xx: number;
  code4xx: number;
  code5xx: number;
}

// ============================================================================
// Combined Analytics Response
// ============================================================================

export interface BeamAnalyticsResponse {
  // Real data from risk-server
  traffic: TrafficOverview;
  bandwidth: BandwidthAnalytics;
  threats: ThreatSummary;
  sensor: SensorMetrics;
  topEndpoints: TopEndpoint[];

  // Demo data (not available from risk-server yet)
  responseTimeDistribution: ResponseTimeBucket[];
  regionTraffic: RegionTraffic[];
  statusCodes: StatusCodeDistribution;

  // Metadata
  fetchedAt: string;
  dataSource: 'live' | 'demo' | 'mixed';
}

// ============================================================================
// API Error Response
// ============================================================================

export interface BeamApiError {
  error: string;
  message: string;
  statusCode: number;
  timestamp: string;
}
