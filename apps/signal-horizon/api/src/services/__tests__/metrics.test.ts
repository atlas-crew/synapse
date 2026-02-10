/**
 * MetricsService Tests
 * Validates Prometheus metric registration: names, types, labels, and naming conventions.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MetricsService } from '../metrics.js';

describe('MetricsService', () => {
  let metricsService: MetricsService;

  beforeEach(() => {
    metricsService = new MetricsService();
  });

  // =========================================================================
  // Expected metric definitions for validation
  // =========================================================================

  const expectedCounters = [
    { property: 'fleetCommandsSent', name: 'horizon_fleet_commands_sent_total' },
    { property: 'fleetCommandsSucceeded', name: 'horizon_fleet_commands_succeeded_total' },
    { property: 'fleetCommandsFailed', name: 'horizon_fleet_commands_failed_total' },
    { property: 'sensorHeartbeatsTotal', name: 'horizon_sensor_heartbeats_total' },
    { property: 'signalsIngestedTotal', name: 'horizon_signals_ingested_total' },
    { property: 'clickhouseInsertSuccess', name: 'horizon_clickhouse_insert_success_total' },
    { property: 'clickhouseInsertFailed', name: 'horizon_clickhouse_insert_failed_total' },
    { property: 'clickhouseQueryErrors', name: 'horizon_clickhouse_query_errors_total' },
    { property: 'clickhouseRawQueriesTotal', name: 'horizon_clickhouse_raw_queries_total' },
    { property: 'signalsDroppedTotal', name: 'horizon_signals_dropped_total' },
    { property: 'nonceStoreEvictionsTotal', name: 'horizon_nonce_store_evictions_total' },
    { property: 'authBlacklistDbErrors', name: 'horizon_auth_blacklist_db_errors_total' },
  ];

  const expectedGauges = [
    { property: 'sensorsOnlineGauge', name: 'horizon_sensors_online_count' },
    { property: 'clickhouseRetryBufferCount', name: 'horizon_clickhouse_retry_buffer_items' },
    { property: 'clickhouseQueryQueueDepth', name: 'horizon_clickhouse_query_queue_depth' },
    { property: 'clickhouseQueriesInFlight', name: 'horizon_clickhouse_queries_in_flight' },
  ];

  const expectedHistograms = [
    { property: 'fleetCommandDuration', name: 'horizon_fleet_command_duration_seconds' },
    { property: 'signalIngestionDuration', name: 'horizon_signal_ingestion_duration_seconds' },
    { property: 'clickhouseQueryWaitDuration', name: 'horizon_clickhouse_query_wait_seconds' },
    { property: 'clickhouseQueryDuration', name: 'horizon_clickhouse_query_duration_seconds' },
  ];

  // =========================================================================
  // Counter existence and naming
  // =========================================================================

  describe('counters', () => {
    it.each(expectedCounters)(
      'should register counter $name',
      ({ property, name }) => {
        const counter = (metricsService as any)[property];
        expect(counter).toBeDefined();
        // prom-client stores the metric name in a private field accessible via `name`
        // The Prometheus text output contains the metric name
        expect((counter as any).name).toBe(name);
      }
    );

    it('should have correct names for all expected counters', () => {
      for (const { property, name } of expectedCounters) {
        const counter = (metricsService as any)[property];
        expect(counter, `Counter ${property} should exist`).toBeDefined();
        expect((counter as any).name).toBe(name);
      }
    });
  });

  // =========================================================================
  // Gauge existence and naming
  // =========================================================================

  describe('gauges', () => {
    it.each(expectedGauges)(
      'should register gauge $name',
      ({ property, name }) => {
        const gauge = (metricsService as any)[property];
        expect(gauge).toBeDefined();
        expect((gauge as any).name).toBe(name);
      }
    );

    it('should have correct names for all expected gauges', () => {
      for (const { property, name } of expectedGauges) {
        const gauge = (metricsService as any)[property];
        expect(gauge, `Gauge ${property} should exist`).toBeDefined();
        expect((gauge as any).name).toBe(name);
      }
    });
  });

  // =========================================================================
  // Histogram existence and naming
  // =========================================================================

  describe('histograms', () => {
    it.each(expectedHistograms)(
      'should register histogram $name',
      ({ property, name }) => {
        const histogram = (metricsService as any)[property];
        expect(histogram).toBeDefined();
        expect((histogram as any).name).toBe(name);
      }
    );

    it('should have correct names for all expected histograms', () => {
      for (const { property, name } of expectedHistograms) {
        const histogram = (metricsService as any)[property];
        expect(histogram, `Histogram ${property} should exist`).toBeDefined();
        expect((histogram as any).name).toBe(name);
      }
    });
  });

  // =========================================================================
  // Label names
  // =========================================================================

  describe('label names', () => {
    const metricsWithLabels = [
      { property: 'fleetCommandsSent', labels: ['type', 'tenant_id'] },
      { property: 'fleetCommandsSucceeded', labels: ['type', 'tenant_id'] },
      { property: 'fleetCommandsFailed', labels: ['type', 'tenant_id', 'error_type'] },
      { property: 'fleetCommandDuration', labels: ['type', 'tenant_id'] },
      { property: 'sensorHeartbeatsTotal', labels: ['sensor_id', 'tenant_id'] },
      { property: 'sensorsOnlineGauge', labels: ['tenant_id', 'region'] },
      { property: 'signalsIngestedTotal', labels: ['type', 'tenant_id', 'severity'] },
      { property: 'clickhouseInsertSuccess', labels: ['table'] },
      { property: 'clickhouseInsertFailed', labels: ['table'] },
      { property: 'clickhouseRetryBufferCount', labels: ['type'] },
      { property: 'clickhouseQueryQueueDepth', labels: ['op', 'queue'] },
      { property: 'clickhouseQueryWaitDuration', labels: ['op'] },
      { property: 'clickhouseQueryDuration', labels: ['op'] },
      { property: 'clickhouseQueryErrors', labels: ['op'] },
      { property: 'clickhouseQueriesInFlight', labels: ['op'] },
      { property: 'signalsDroppedTotal', labels: ['reason'] },
      { property: 'nonceStoreEvictionsTotal', labels: ['reason'] },
      { property: 'authBlacklistDbErrors', labels: ['source'] },
    ];

    it.each(metricsWithLabels)(
      'should have correct label names for $property',
      ({ property, labels }) => {
        const metric = (metricsService as any)[property];
        expect(metric).toBeDefined();
        expect((metric as any).labelNames).toEqual(labels);
      }
    );
  });

  // =========================================================================
  // Naming convention
  // =========================================================================

  describe('naming convention', () => {
    it('all custom metric names should use horizon_ prefix', () => {
      const allMetrics = [
        ...expectedCounters,
        ...expectedGauges,
        ...expectedHistograms,
      ];

      for (const { name } of allMetrics) {
        expect(name).toMatch(/^horizon_/);
      }
    });

    it('counter names should end with _total', () => {
      for (const { name } of expectedCounters) {
        expect(name).toMatch(/_total$/);
      }
    });

    it('histogram duration names should end with _seconds', () => {
      const durationHistograms = expectedHistograms.filter(
        (h) => h.name.includes('duration') || h.name.includes('wait')
      );
      for (const { name } of durationHistograms) {
        expect(name).toMatch(/_seconds$/);
      }
    });
  });

  // =========================================================================
  // No duplicate metric names
  // =========================================================================

  describe('uniqueness', () => {
    it('should not register any duplicate metric names', () => {
      const allMetrics = [
        ...expectedCounters,
        ...expectedGauges,
        ...expectedHistograms,
      ];

      const names = allMetrics.map((m) => m.name);
      const uniqueNames = new Set(names);
      expect(uniqueNames.size).toBe(names.length);
    });
  });

  // =========================================================================
  // Prometheus output
  // =========================================================================

  describe('getMetrics', () => {
    it('should return Prometheus-formatted metrics string', async () => {
      const output = await metricsService.getMetrics();
      expect(typeof output).toBe('string');
      // All custom metrics should appear in the output
      for (const { name } of expectedCounters) {
        expect(output).toContain(name);
      }
      for (const { name } of expectedGauges) {
        expect(output).toContain(name);
      }
      for (const { name } of expectedHistograms) {
        expect(output).toContain(name);
      }
    });

    it('should return correct content type', () => {
      const contentType = metricsService.getContentType();
      expect(contentType).toContain('text/plain');
    });
  });
});
