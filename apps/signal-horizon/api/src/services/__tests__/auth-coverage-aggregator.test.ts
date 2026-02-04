import { describe, it, expect, beforeEach } from 'vitest';
import { AuthCoverageAggregator } from '../auth-coverage-aggregator.js';
import { AuthCoverageSummary } from '../../schemas/auth-coverage.js';

describe('AuthCoverageAggregator', () => {
  let aggregator: AuthCoverageAggregator;

  beforeEach(() => {
    aggregator = new AuthCoverageAggregator();
  });

  const mockSummary: AuthCoverageSummary = {
    timestamp: Date.now(),
    sensor_id: 'test-sensor',
    tenant_id: 'tenant-1',
    endpoints: [
      {
        endpoint: 'GET /api/users',
        counts: {
          total: 100,
          success: 90,
          unauthorized: 5,
          forbidden: 5,
          other_error: 0,
          with_auth: 95,
          without_auth: 5,
        },
      },
    ],
  };

  it('should ingest and merge summaries', () => {
    aggregator.ingestSummary(mockSummary);
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/users');
    expect(stats).toBeDefined();
    expect(stats?.totalRequests).toBe(100);
    expect(stats?.authPattern).toBe('enforced'); // 10% denial rate > 0.5%
  });

  it('should handle multiple sensors for same tenant', () => {
    aggregator.ingestSummary(mockSummary);
    aggregator.ingestSummary({
      ...mockSummary,
      sensor_id: 'test-sensor-2',
    });
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/users');
    expect(stats?.totalRequests).toBe(200);
  });

  it('should classify as none_observed when auth is present but no denials', () => {
    aggregator.ingestSummary({
      timestamp: Date.now(),
      sensor_id: 'sensor-1',
      tenant_id: 'tenant-1',
      endpoints: [
        {
          endpoint: 'GET /api/users',
          counts: {
            total: 200,
            success: 200,
            unauthorized: 0,
            forbidden: 0,
            other_error: 0,
            with_auth: 150, // 75% auth rate > 50%
            without_auth: 50,
          },
        },
      ],
    });
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/users');
    expect(stats?.authPattern).toBe('none_observed');
    expect(stats?.riskLevel).toBe('high');
  });

  it('should classify as public when no auth and no denials', () => {
    aggregator.ingestSummary({
      timestamp: Date.now(),
      sensor_id: 'sensor-1',
      tenant_id: 'tenant-1',
      endpoints: [
        {
          endpoint: 'GET /api/public',
          counts: {
            total: 200,
            success: 200,
            unauthorized: 0,
            forbidden: 0,
            other_error: 0,
            with_auth: 10, // 5% auth rate < 50%
            without_auth: 190,
          },
        },
      ],
    });
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/public');
    expect(stats?.authPattern).toBe('public');
    expect(stats?.riskLevel).toBe('low');
  });

  it('should classify sensitive public paths as medium risk', () => {
    aggregator.ingestSummary({
      timestamp: Date.now(),
      sensor_id: 'sensor-1',
      tenant_id: 'tenant-1',
      endpoints: [
        {
          endpoint: 'GET /api/admin/config',
          counts: {
            total: 200,
            success: 200,
            unauthorized: 0,
            forbidden: 0,
            other_error: 0,
            with_auth: 10,
            without_auth: 190,
          },
        },
      ],
    });
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/admin/config');
    expect(stats?.authPattern).toBe('public');
    expect(stats?.riskLevel).toBe('medium');
  });

  it('should report insufficient_data for low volume', () => {
    aggregator.ingestSummary({
      timestamp: Date.now(),
      sensor_id: 'sensor-1',
      tenant_id: 'tenant-1',
      endpoints: [
        {
          endpoint: 'GET /api/rare',
          counts: {
            total: 10,
            success: 10,
            unauthorized: 0,
            forbidden: 0,
            other_error: 0,
            with_auth: 0,
            without_auth: 10,
          },
        },
      ],
    });
    const stats = aggregator.getEndpointStats('tenant-1:GET /api/rare');
    expect(stats?.authPattern).toBe('insufficient_data');
    expect(stats?.riskLevel).toBe('unknown');
  });

  it('should identify auth gaps', () => {
    // High risk gap
    aggregator.ingestSummary({
      timestamp: Date.now(),
      sensor_id: 'sensor-1',
      tenant_id: 'tenant-1',
      endpoints: [
        {
          endpoint: 'GET /api/vulnerable',
          counts: {
            total: 200,
            success: 200,
            unauthorized: 0,
            forbidden: 0,
            other_error: 0,
            with_auth: 150,
            without_auth: 50,
          },
        },
      ],
    });
    
    const gaps = aggregator.getAuthGaps('tenant-1');
    expect(gaps.length).toBe(1);
    expect(gaps[0].endpoint).toBe('GET /api/vulnerable');
    expect(gaps[0].riskLevel).toBe('high');
  });
});
