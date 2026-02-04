import {
  AuthCoverageSummary,
  EndpointAuthStats,
  AuthPattern,
  RiskLevel,
  CoverageMapSummary,
} from '../schemas/auth-coverage.js';

export interface AuthCoverageAggregatorConfig {
  /** Whether to return demo data when no real data is available (default: true) */
  demoMode?: boolean;
}

interface EndpointAccumulator {
  endpoint: string;
  method: string;
  tenantId?: string;

  totalRequests: number;
  successCount: number;
  unauthorizedCount: number;
  forbiddenCount: number;
  otherErrorCount: number;

  requestsWithAuth: number;
  requestsWithoutAuth: number;

  firstSeen: number;
  lastSeen: number;
}

const MIN_REQUESTS_FOR_CLASSIFICATION = 100;
const DENIAL_RATE_THRESHOLD = 0.005; // 0.5%
const AUTH_RATE_THRESHOLD = 0.5; // 50%

const SENSITIVE_PATH_PATTERNS = [
  '/admin',
  '/internal',
  '/private',
  '/settings',
  '/config',
  '/users/',
  '/accounts/',
  '/billing',
  '/payment',
  '/export',
  '/download',
];

export class AuthCoverageAggregator {
  private endpoints: Map<string, EndpointAccumulator> = new Map();
  private config: Required<AuthCoverageAggregatorConfig>;

  constructor(config: AuthCoverageAggregatorConfig = {}) {
    this.config = {
      demoMode: config.demoMode ?? true,
    };
  }
  
  /**
   * Process incoming summary from a Synapse sensor
   */
  ingestSummary(summary: AuthCoverageSummary): void {
    for (const ep of summary.endpoints) {
      const key = summary.tenant_id
        ? `${summary.tenant_id}:${ep.endpoint}`
        : ep.endpoint;
      
      let acc = this.endpoints.get(key);
      
      if (!acc) {
        acc = {
          endpoint: ep.endpoint,
          method: ep.endpoint.split(' ')[0] || 'UNKNOWN',
          tenantId: summary.tenant_id,
          totalRequests: 0,
          successCount: 0,
          unauthorizedCount: 0,
          forbiddenCount: 0,
          otherErrorCount: 0,
          requestsWithAuth: 0,
          requestsWithoutAuth: 0,
          firstSeen: summary.timestamp,
          lastSeen: summary.timestamp,
        };
        this.endpoints.set(key, acc);
      }
      
      // Merge counts
      acc.totalRequests += ep.counts.total;
      acc.successCount += ep.counts.success;
      acc.unauthorizedCount += ep.counts.unauthorized;
      acc.forbiddenCount += ep.counts.forbidden;
      acc.otherErrorCount += ep.counts.other_error;
      acc.requestsWithAuth += ep.counts.with_auth;
      acc.requestsWithoutAuth += ep.counts.without_auth;
      acc.lastSeen = Math.max(acc.lastSeen, summary.timestamp);
      acc.firstSeen = Math.min(acc.firstSeen, summary.timestamp);
    }
  }
  
  /**
   * Compute auth pattern from observed data
   */
  private computeAuthPattern(acc: EndpointAccumulator): AuthPattern {
    if (acc.totalRequests < MIN_REQUESTS_FOR_CLASSIFICATION) {
      return 'insufficient_data';
    }
    
    const denialCount = acc.unauthorizedCount + acc.forbiddenCount;
    const denialRate = denialCount / acc.totalRequests;
    
    if (denialRate > DENIAL_RATE_THRESHOLD) {
      return 'enforced';
    }
    
    const authRate = acc.requestsWithAuth / acc.totalRequests;
    
    if (authRate > AUTH_RATE_THRESHOLD) {
      return 'none_observed';
    }
    
    return 'public';
  }
  
  /**
   * Check if endpoint path suggests sensitive data
   */
  private isSensitivePath(endpoint: string): boolean {
    const lowerEndpoint = endpoint.toLowerCase();
    return SENSITIVE_PATH_PATTERNS.some(p => lowerEndpoint.includes(p));
  }
  
  /**
   * Compute risk level from auth pattern
   */
  private computeRiskLevel(pattern: AuthPattern, acc: EndpointAccumulator): RiskLevel {
    switch (pattern) {
      case 'enforced':
        return 'low';
      
      case 'public':
        return this.isSensitivePath(acc.endpoint) ? 'medium' : 'low';
      
      case 'none_observed':
        return 'high';
      
      case 'insufficient_data':
        return 'unknown';
    }
  }
  
  /**
   * Convert accumulator to stats object
   */
  private toStats(acc: EndpointAccumulator): EndpointAuthStats {
    const denialCount = acc.unauthorizedCount + acc.forbiddenCount;
    const denialRate = acc.totalRequests > 0 ? denialCount / acc.totalRequests : 0;
    const authPattern = this.computeAuthPattern(acc);
    const riskLevel = this.computeRiskLevel(authPattern, acc);
    
    return {
      endpoint: acc.endpoint,
      method: acc.method,
      tenantId: acc.tenantId,
      totalRequests: acc.totalRequests,
      successCount: acc.successCount,
      unauthorizedCount: acc.unauthorizedCount,
      forbiddenCount: acc.forbiddenCount,
      otherErrorCount: acc.otherErrorCount,
      requestsWithAuth: acc.requestsWithAuth,
      requestsWithoutAuth: acc.requestsWithoutAuth,
      uniqueActors: 0, // Not tracked in summary model
      firstSeen: new Date(acc.firstSeen),
      lastSeen: new Date(acc.lastSeen),
      denialRate,
      authPattern,
      riskLevel,
    };
  }
  
  /**
   * Get stats for a single endpoint
   */
  getEndpointStats(key: string): EndpointAuthStats | null {
    const acc = this.endpoints.get(key);
    if (!acc) return null;
    return this.toStats(acc);
  }
  
  /**
   * Get all endpoint stats, optionally filtered by tenant
   * Returns demo data if no real data available and demoMode enabled
   */
  getAllEndpointStats(tenantId?: string): EndpointAuthStats[] {
    const stats = Array.from(this.endpoints.values())
      .filter(acc => !tenantId || acc.tenantId === tenantId)
      .map(acc => this.toStats(acc));

    // Fallback to demo data if no real data and demo mode enabled
    if (stats.length === 0 && this.config.demoMode) {
      return this.getDemoEndpoints();
    }

    return stats;
  }
  
  /**
   * Get endpoints filtered by risk level
   */
  getEndpointsByRisk(riskLevel: RiskLevel, tenantId?: string): EndpointAuthStats[] {
    return this.getAllEndpointStats(tenantId)
      .filter(stats => stats.riskLevel === riskLevel);
  }
  
  /**
   * Get high-risk endpoints (gaps in auth coverage)
   */
  getAuthGaps(tenantId?: string): EndpointAuthStats[] {
    return this.getAllEndpointStats(tenantId)
      .filter(stats => stats.riskLevel === 'high' || stats.riskLevel === 'medium')
      .sort((a, b) => {
        if (a.riskLevel !== b.riskLevel) {
          return a.riskLevel === 'high' ? -1 : 1;
        }
        return b.totalRequests - a.totalRequests;
      });
  }
  
  /**
   * Get coverage summary
   * Returns demo summary if no real data available and demoMode enabled
   */
  getSummary(tenantId?: string): CoverageMapSummary {
    const allStats = this.getAllEndpointStats(tenantId);

    // If we got demo data fallback from getAllEndpointStats, use it
    return {
      totalEndpoints: allStats.length,
      highRiskCount: allStats.filter(s => s.riskLevel === 'high').length,
      mediumRiskCount: allStats.filter(s => s.riskLevel === 'medium').length,
      lowRiskCount: allStats.filter(s => s.riskLevel === 'low').length,
      unknownCount: allStats.filter(s => s.riskLevel === 'unknown').length,
      lastUpdated: new Date(),
    };
  }
  
  /**
   * Export for persistence
   */
  export(): Record<string, EndpointAccumulator> {
    const result: Record<string, EndpointAccumulator> = {};
    for (const [key, acc] of this.endpoints) {
      result[key] = { ...acc };
    }
    return result;
  }
  
  /**
   * Import from persistence
   */
  import(data: Record<string, EndpointAccumulator>): void {
    this.endpoints.clear();
    for (const [key, acc] of Object.entries(data)) {
      this.endpoints.set(key, { ...acc });
    }
  }
  
  /**
   * Clear all data (for testing)
   */
  clear(): void {
    this.endpoints.clear();
  }

  /**
   * Generate realistic demo endpoints (for documentation/screenshots)
   */
  private getDemoEndpoints(): EndpointAuthStats[] {
    const demoEndpoints = [
      {
        endpoint: 'POST /admin/users',
        method: 'POST',
        riskLevel: 'high' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 2400,
        unauthorizedCount: 5,
        forbiddenCount: 5,
        requestsWithAuth: 450,
      },
      {
        endpoint: 'GET /admin/settings',
        method: 'GET',
        riskLevel: 'high' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 5600,
        unauthorizedCount: 80,
        forbiddenCount: 40,
        requestsWithAuth: 800,
      },
      {
        endpoint: 'GET /internal/metrics',
        method: 'GET',
        riskLevel: 'high' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 8900,
        unauthorizedCount: 250,
        forbiddenCount: 100,
        requestsWithAuth: 1200,
      },
      {
        endpoint: 'POST /api/v1/accounts',
        method: 'POST',
        riskLevel: 'medium' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 3400,
        unauthorizedCount: 150,
        forbiddenCount: 80,
        requestsWithAuth: 2100,
      },
      {
        endpoint: 'GET /api/v1/users/:id/profile',
        method: 'GET',
        riskLevel: 'medium' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 6200,
        unauthorizedCount: 200,
        forbiddenCount: 150,
        requestsWithAuth: 4200,
      },
      {
        endpoint: 'POST /api/v1/billing/invoice',
        method: 'POST',
        riskLevel: 'medium' as RiskLevel,
        authPattern: 'optional' as AuthPattern,
        totalRequests: 2800,
        unauthorizedCount: 120,
        forbiddenCount: 60,
        requestsWithAuth: 1800,
      },
      {
        endpoint: 'GET /api/v1/public/health',
        method: 'GET',
        riskLevel: 'low' as RiskLevel,
        authPattern: 'none' as AuthPattern,
        totalRequests: 24000,
        unauthorizedCount: 5,
        forbiddenCount: 5,
        requestsWithAuth: 100,
      },
      {
        endpoint: 'GET /api/v1/threats/list',
        method: 'GET',
        riskLevel: 'low' as RiskLevel,
        authPattern: 'required' as AuthPattern,
        totalRequests: 15600,
        unauthorizedCount: 80,
        forbiddenCount: 80,
        requestsWithAuth: 15200,
      },
      {
        endpoint: 'POST /api/v1/auth/login',
        method: 'POST',
        riskLevel: 'low' as RiskLevel,
        authPattern: 'none' as AuthPattern,
        totalRequests: 42000,
        unauthorizedCount: 300,
        forbiddenCount: 100,
        requestsWithAuth: 5000,
      },
      {
        endpoint: 'PUT /api/v1/settings/profile',
        method: 'PUT',
        riskLevel: 'low' as RiskLevel,
        authPattern: 'required' as AuthPattern,
        totalRequests: 3200,
        unauthorizedCount: 50,
        forbiddenCount: 40,
        requestsWithAuth: 3100,
      },
    ];

    return demoEndpoints.map(ep => ({
      endpoint: ep.endpoint,
      method: ep.method,
      totalRequests: ep.totalRequests,
      successCount: Math.round(ep.totalRequests * 0.95),
      unauthorizedCount: ep.unauthorizedCount,
      forbiddenCount: ep.forbiddenCount,
      otherErrorCount: Math.round(ep.totalRequests * 0.02),
      requestsWithAuth: ep.requestsWithAuth,
      requestsWithoutAuth: ep.totalRequests - ep.requestsWithAuth,
      uniqueActors: Math.round(Math.random() * 100) + 10,
      firstSeen: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      lastSeen: new Date(),
      denialRate: (ep.unauthorizedCount + ep.forbiddenCount) / ep.totalRequests,
      authRate: ep.requestsWithAuth / ep.totalRequests,
      authPattern: ep.authPattern,
      riskLevel: ep.riskLevel,
      tenantId: undefined,
    } as EndpointAuthStats));
  }
}
