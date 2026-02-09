/**
 * Metrics Service
 * Prometheus metrics export for Signal Horizon Hub (P1-OBSERVABILITY-002)
 */

import client from 'prom-client';

export class MetricsService {
  private register: client.Registry;
  
  // Fleet Command Metrics
  public fleetCommandsSent: client.Counter;
  public fleetCommandsSucceeded: client.Counter;
  public fleetCommandsFailed: client.Counter;
  public fleetCommandDuration: client.Histogram;
  
  // Sensor Metrics
  public sensorHeartbeatsTotal: client.Counter;
  public sensorsOnlineGauge: client.Gauge;
  
  // Signal Metrics
  public signalsIngestedTotal: client.Counter;
  public signalIngestionDuration: client.Histogram;
  
  // Storage Metrics
  public clickhouseInsertSuccess: client.Counter;
  public clickhouseInsertFailed: client.Counter;
  public clickhouseRetryBufferCount: client.Gauge;
  public clickhouseQueryQueueDepth: client.Gauge;
  public clickhouseQueryWaitDuration: client.Histogram;
  public clickhouseQueryDuration: client.Histogram;
  public clickhouseQueryErrors: client.Counter;
  public clickhouseQueriesInFlight: client.Gauge;
  public clickhouseRawQueriesTotal: client.Counter;
  // Backpressure Metrics
  public signalsDroppedTotal: client.Counter;
  public nonceStoreEvictionsTotal: client.Counter;

  // Auth Metrics
  public authBlacklistDbErrors: client.Counter;
  
  constructor() {
    this.register = new client.Registry();
    
    // Collect default metrics (CPU, memory, event loop lag, etc.)
    client.collectDefaultMetrics({ register: this.register, prefix: 'horizon_' });
    
    this.fleetCommandsSent = new client.Counter({
      name: 'horizon_fleet_commands_sent_total',
      help: 'Total number of fleet commands sent',
      labelNames: ['type', 'tenant_id'],
      registers: [this.register],
    });
    
    this.fleetCommandsSucceeded = new client.Counter({
      name: 'horizon_fleet_commands_succeeded_total',
      help: 'Total number of successfully executed fleet commands',
      labelNames: ['type', 'tenant_id'],
      registers: [this.register],
    });
    
    this.fleetCommandsFailed = new client.Counter({
      name: 'horizon_fleet_commands_failed_total',
      help: 'Total number of failed fleet commands',
      labelNames: ['type', 'tenant_id', 'error_type'],
      registers: [this.register],
    });
    
    this.fleetCommandDuration = new client.Histogram({
      name: 'horizon_fleet_command_duration_seconds',
      help: 'Duration of fleet command execution from sent to ack',
      labelNames: ['type', 'tenant_id'],
      buckets: [0.1, 0.5, 1, 2, 5, 10, 30],
      registers: [this.register],
    });
    
    this.sensorHeartbeatsTotal = new client.Counter({
      name: 'horizon_sensor_heartbeats_total',
      help: 'Total number of sensor heartbeats received',
      labelNames: ['sensor_id', 'tenant_id'],
      registers: [this.register],
    });
    
    this.sensorsOnlineGauge = new client.Gauge({
      name: 'horizon_sensors_online_count',
      help: 'Number of sensors currently connected and healthy',
      labelNames: ['tenant_id', 'region'],
      registers: [this.register],
    });
    
    this.signalsIngestedTotal = new client.Counter({
      name: 'horizon_signals_ingested_total',
      help: 'Total number of threat signals ingested',
      labelNames: ['type', 'tenant_id', 'severity'],
      registers: [this.register],
    });
    
    this.signalIngestionDuration = new client.Histogram({
      name: 'horizon_signal_ingestion_duration_seconds',
      help: 'Duration of signal ingestion batch processing',
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 5],
      registers: [this.register],
    });
    
    this.clickhouseInsertSuccess = new client.Counter({
      name: 'horizon_clickhouse_insert_success_total',
      help: 'Total number of successful ClickHouse inserts',
      labelNames: ['table'],
      registers: [this.register],
    });
    
    this.clickhouseInsertFailed = new client.Counter({
      name: 'horizon_clickhouse_insert_failed_total',
      help: 'Total number of failed ClickHouse inserts',
      labelNames: ['table'],
      registers: [this.register],
    });

    this.clickhouseRetryBufferCount = new client.Gauge({
      name: 'horizon_clickhouse_retry_buffer_items',
      help: 'Number of items currently in the ClickHouse retry buffer',
      labelNames: ['type'],
      registers: [this.register],
    });

    this.clickhouseQueryQueueDepth = new client.Gauge({
      name: 'horizon_clickhouse_query_queue_depth',
      // NOTE: split by queue so streaming ops (long-lived) don't hide point-query backpressure.
      help: 'Number of ClickHouse ops waiting for a permit (queue=query|stream)',
      labelNames: ['op', 'queue'],
      registers: [this.register],
    });

    this.clickhouseQueryWaitDuration = new client.Histogram({
      name: 'horizon_clickhouse_query_wait_seconds',
      help: 'Time spent waiting for a ClickHouse query permit (backpressure)',
      labelNames: ['op'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
      registers: [this.register],
    });

    this.clickhouseQueryDuration = new client.Histogram({
      name: 'horizon_clickhouse_query_duration_seconds',
      help: 'Duration of ClickHouse queries',
      labelNames: ['op'],
      buckets: [0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30],
      registers: [this.register],
    });

    this.clickhouseQueryErrors = new client.Counter({
      name: 'horizon_clickhouse_query_errors_total',
      help: 'Total number of ClickHouse query errors',
      labelNames: ['op'],
      registers: [this.register],
    });

    this.clickhouseQueriesInFlight = new client.Gauge({
      name: 'horizon_clickhouse_queries_in_flight',
      help: 'Number of ClickHouse queries currently in flight (after limiter)',
      labelNames: ['op'],
      registers: [this.register],
    });

    this.clickhouseRawQueriesTotal = new client.Counter({
      name: 'horizon_clickhouse_raw_queries_total',
      help: 'Total number of raw ClickHouse query() calls (deprecated; prefer queryWithParams())',
      registers: [this.register],
    });

    this.signalsDroppedTotal = new client.Counter({
      name: 'horizon_signals_dropped_total',
      help: 'Total number of signals dropped due to backpressure',
      labelNames: ['reason'],
      registers: [this.register],
    });

    this.nonceStoreEvictionsTotal = new client.Counter({
      name: 'horizon_nonce_store_evictions_total',
      help: 'Total number of nonces evicted from the in-memory store',
      labelNames: ['reason'],
      registers: [this.register],
    });

    this.authBlacklistDbErrors = new client.Counter({
      name: 'horizon_auth_blacklist_db_errors_total',
      help: 'Total number of blacklist DB errors during auth checks',
      labelNames: ['source'],
      registers: [this.register],
    });
  }
  
  /**
   * Get metrics in Prometheus format
   */
  async getMetrics(): Promise<string> {
    return this.register.metrics();
  }
  
  /**
   * Get metrics content type
   */
  getContentType(): string {
    return this.register.contentType;
  }
}

// Export singleton instance
export const metrics = new MetricsService();
