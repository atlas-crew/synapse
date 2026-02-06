/**
 * Fleet Aggregator Service
 * Real-time aggregation of sensor heartbeats into fleet-wide metrics
 */

import type { Logger } from 'pino';
import { EventEmitter } from 'node:events';
import { metrics } from '../metrics.js';
import type {
  SensorMetricsSnapshot,
  FleetMetrics,
  RegionMetrics,
  SensorAlert,
  SensorHeartbeat,
} from './types.js';

export interface FleetAggregatorConfig {
  /**
   * How long to keep sensor metrics in memory (milliseconds)
   * Default: 5 minutes
   */
  metricsRetentionMs?: number;

  /**
   * Heartbeat timeout threshold (milliseconds)
   * Sensors are considered offline if no heartbeat within this time
   * Default: 60000 (60 seconds = 2 missed heartbeats at 30s interval)
   */
  heartbeatTimeoutMs?: number;

  /**
   * CPU threshold for alerts (percentage)
   * Default: 80
   */
  cpuAlertThreshold?: number;

  /**
   * Memory threshold for alerts (percentage)
   * Default: 85
   */
  memoryAlertThreshold?: number;

  /**
   * Disk threshold for alerts (percentage)
   * Default: 90
   */
  diskAlertThreshold?: number;
}

/**
 * FleetAggregator Events:
 * - 'metrics-updated': Emitted when fleet metrics are updated
 * - 'sensor-online': Emitted when a sensor comes online
 * - 'sensor-offline': Emitted when a sensor goes offline
 * - 'sensor-alert': Emitted when a sensor requires attention
 */
export class FleetAggregator extends EventEmitter {
  private logger: Logger;
  private config: Required<FleetAggregatorConfig>;
  private sensorMetrics: Map<string, SensorMetricsSnapshot> = new Map();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(logger: Logger, config: FleetAggregatorConfig = {}) {
    super();
    this.logger = logger.child({ service: 'fleet-aggregator' });
    this.config = {
      metricsRetentionMs: config.metricsRetentionMs ?? 5 * 60 * 1000, // 5 minutes
      heartbeatTimeoutMs: config.heartbeatTimeoutMs ?? 60000, // 60 seconds
      cpuAlertThreshold: config.cpuAlertThreshold ?? 80,
      memoryAlertThreshold: config.memoryAlertThreshold ?? 85,
      diskAlertThreshold: config.diskAlertThreshold ?? 90,
    };

    // Start cleanup timer to remove stale metrics
    this.startCleanup();
  }

  /**
   * Update sensor metrics from incoming heartbeat
   */
  updateSensorMetrics(sensorId: string, heartbeat: SensorHeartbeat): void {
    const wasOnline = this.sensorMetrics.has(sensorId) && this.isOnline(this.sensorMetrics.get(sensorId)!);

    const snapshot: SensorMetricsSnapshot = {
      sensorId: heartbeat.sensorId,
      tenantId: heartbeat.tenantId,
      hostname: heartbeat.metadata?.hostname as string | undefined,
      region: heartbeat.region,
      rps: heartbeat.metrics.rps,
      latency: heartbeat.metrics.latency,
      cpu: heartbeat.metrics.cpu,
      memory: heartbeat.metrics.memory,
      disk: heartbeat.metrics.disk,
      health: heartbeat.health,
      lastHeartbeat: heartbeat.timestamp,
      requestsTotal: heartbeat.requestsTotal,
      configHash: heartbeat.configHash,
      rulesHash: heartbeat.rulesHash,
    };

    this.sensorMetrics.set(sensorId, snapshot);

    // Increment metrics (P1-OBSERVABILITY-002)
    metrics.sensorHeartbeatsTotal.inc({ sensor_id: sensorId, tenant_id: heartbeat.tenantId });

    // Emit sensor online event if coming back online
    if (!wasOnline) {
      this.logger.info({ sensorId, tenantId: heartbeat.tenantId }, 'Sensor came online');
      this.emit('sensor-online', { sensorId, tenantId: heartbeat.tenantId });
      
      // Update online count gauge
      metrics.sensorsOnlineGauge.inc({ tenant_id: heartbeat.tenantId, region: heartbeat.region });
    }

    // Check for alerts
    this.checkSensorAlerts(snapshot);

    // Emit metrics updated event
    this.emit('metrics-updated', this.getFleetMetrics());
  }

  /**
   * Compute fleet-wide metrics
   */
  getFleetMetrics(): FleetMetrics {
    const now = new Date();
    const onlineSensors: SensorMetricsSnapshot[] = [];
    const offlineSensors: SensorMetricsSnapshot[] = [];

    for (const sensor of this.sensorMetrics.values()) {
      if (this.isOnline(sensor)) {
        onlineSensors.push(sensor);
      } else {
        offlineSensors.push(sensor);
      }
    }

    const totalSensors = this.sensorMetrics.size;
    const onlineCount = onlineSensors.length;

    // Calculate totals and averages
    let totalRps = 0;
    let weightedLatency = 0;
    let totalRequests = 0;
    let totalCpu = 0;
    let totalMemory = 0;
    let totalDisk = 0;

    for (const sensor of onlineSensors) {
      totalRps += sensor.rps;
      weightedLatency += sensor.latency * sensor.rps;
      totalRequests += sensor.rps;
      totalCpu += sensor.cpu;
      totalMemory += sensor.memory;
      totalDisk += sensor.disk;
    }

    // Weighted average latency (weight by RPS)
    const avgLatency = totalRequests > 0 ? weightedLatency / totalRequests : 0;

    // Simple averages for resources
    const avgCpu = onlineCount > 0 ? totalCpu / onlineCount : 0;
    const avgMemory = onlineCount > 0 ? totalMemory / onlineCount : 0;
    const avgDisk = onlineCount > 0 ? totalDisk / onlineCount : 0;

    // Health score: (healthy sensors / total sensors) * 100
    const healthScore = totalSensors > 0 ? (onlineCount / totalSensors) * 100 : 0;

    return {
      totalSensors,
      onlineSensors: onlineCount,
      offlineSensors: offlineSensors.length,
      totalRps,
      avgLatency: Math.round(avgLatency * 100) / 100, // Round to 2 decimals
      healthScore: Math.round(healthScore * 100) / 100,
      avgCpu: Math.round(avgCpu * 100) / 100,
      avgMemory: Math.round(avgMemory * 100) / 100,
      avgDisk: Math.round(avgDisk * 100) / 100,
      timestamp: now,
    };
  }

  /**
   * Get metrics for a specific region
   */
  getRegionMetrics(region: string): RegionMetrics {
    const regionSensors = Array.from(this.sensorMetrics.values()).filter(
      (s) => s.region === region
    );

    const onlineSensors = regionSensors.filter((s) => this.isOnline(s));

    let totalRps = 0;
    let weightedLatency = 0;
    let totalRequests = 0;

    for (const sensor of onlineSensors) {
      totalRps += sensor.rps;
      weightedLatency += sensor.latency * sensor.rps;
      totalRequests += sensor.rps;
    }

    const avgLatency = totalRequests > 0 ? weightedLatency / totalRequests : 0;
    const healthScore = regionSensors.length > 0 ? (onlineSensors.length / regionSensors.length) * 100 : 0;

    return {
      region,
      sensors: regionSensors.length,
      onlineSensors: onlineSensors.length,
      totalRps,
      avgLatency: Math.round(avgLatency * 100) / 100,
      healthScore: Math.round(healthScore * 100) / 100,
    };
  }

  /**
   * Get sensors requiring attention (degraded, high resource usage)
   */
  getSensorsRequiringAttention(): SensorAlert[] {
    const alerts: SensorAlert[] = [];

    for (const sensor of this.sensorMetrics.values()) {
      // Offline sensors
      if (!this.isOnline(sensor)) {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'offline',
          severity: 'critical',
          message: 'Sensor is offline (no heartbeat)',
        });
        continue;
      }

      // Degraded health
      if (sensor.health === 'degraded') {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'degraded',
          severity: 'warning',
          message: 'Sensor health is degraded',
        });
      } else if (sensor.health === 'critical') {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'degraded',
          severity: 'critical',
          message: 'Sensor health is critical',
        });
      }

      // High CPU
      if (sensor.cpu >= this.config.cpuAlertThreshold) {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'high_cpu',
          severity: sensor.cpu >= 95 ? 'critical' : 'warning',
          message: `CPU usage is ${sensor.cpu}%`,
          value: sensor.cpu,
          threshold: this.config.cpuAlertThreshold,
        });
      }

      // High memory
      if (sensor.memory >= this.config.memoryAlertThreshold) {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'high_memory',
          severity: sensor.memory >= 95 ? 'critical' : 'warning',
          message: `Memory usage is ${sensor.memory}%`,
          value: sensor.memory,
          threshold: this.config.memoryAlertThreshold,
        });
      }

      // High disk
      if (sensor.disk >= this.config.diskAlertThreshold) {
        alerts.push({
          sensorId: sensor.sensorId,
          tenantId: sensor.tenantId,
          alertType: 'high_disk',
          severity: sensor.disk >= 98 ? 'critical' : 'warning',
          message: `Disk usage is ${sensor.disk}%`,
          value: sensor.disk,
          threshold: this.config.diskAlertThreshold,
        });
      }
    }

    return alerts;
  }

  /**
   * Get current sensor metrics snapshot
   */
  getSensorMetrics(sensorId: string): SensorMetricsSnapshot | null {
    return this.sensorMetrics.get(sensorId) ?? null;
  }

  /**
   * Get all sensor metrics
   */
  getAllSensorMetrics(): SensorMetricsSnapshot[] {
    return Array.from(this.sensorMetrics.values());
  }

  /**
   * Remove sensor from tracking
   */
  removeSensor(sensorId: string): void {
    const sensor = this.sensorMetrics.get(sensorId);
    if (sensor) {
      this.sensorMetrics.delete(sensorId);
      this.logger.info({ sensorId }, 'Sensor removed from fleet aggregator');
      this.emit('sensor-offline', { sensorId, tenantId: sensor.tenantId });
    }
  }

  /**
   * Check if sensor is online (heartbeat within threshold)
   */
  private isOnline(sensor: SensorMetricsSnapshot): boolean {
    const now = Date.now();
    const lastHeartbeat = sensor.lastHeartbeat.getTime();
    return now - lastHeartbeat <= this.config.heartbeatTimeoutMs;
  }

  /**
   * Check for sensor alerts and emit events
   */
  private checkSensorAlerts(sensor: SensorMetricsSnapshot): void {
    const alerts: SensorAlert[] = [];

    // Check health status
    if (sensor.health === 'critical') {
      alerts.push({
        sensorId: sensor.sensorId,
        tenantId: sensor.tenantId,
        alertType: 'degraded',
        severity: 'critical',
        message: 'Sensor health is critical',
      });
    } else if (sensor.health === 'degraded') {
      alerts.push({
        sensorId: sensor.sensorId,
        tenantId: sensor.tenantId,
        alertType: 'degraded',
        severity: 'warning',
        message: 'Sensor health is degraded',
      });
    }

    // Check resource thresholds
    if (sensor.cpu >= this.config.cpuAlertThreshold) {
      alerts.push({
        sensorId: sensor.sensorId,
        tenantId: sensor.tenantId,
        alertType: 'high_cpu',
        severity: sensor.cpu >= 95 ? 'critical' : 'warning',
        message: `CPU usage is ${sensor.cpu}%`,
        value: sensor.cpu,
        threshold: this.config.cpuAlertThreshold,
      });
    }

    if (sensor.memory >= this.config.memoryAlertThreshold) {
      alerts.push({
        sensorId: sensor.sensorId,
        tenantId: sensor.tenantId,
        alertType: 'high_memory',
        severity: sensor.memory >= 95 ? 'critical' : 'warning',
        message: `Memory usage is ${sensor.memory}%`,
        value: sensor.memory,
        threshold: this.config.memoryAlertThreshold,
      });
    }

    if (sensor.disk >= this.config.diskAlertThreshold) {
      alerts.push({
        sensorId: sensor.sensorId,
        tenantId: sensor.tenantId,
        alertType: 'high_disk',
        severity: sensor.disk >= 98 ? 'critical' : 'warning',
        message: `Disk usage is ${sensor.disk}%`,
        value: sensor.disk,
        threshold: this.config.diskAlertThreshold,
      });
    }

    // Emit alerts
    for (const alert of alerts) {
      this.emit('sensor-alert', alert);
    }
  }

  /**
   * Start cleanup timer to remove stale metrics
   */
  private startCleanup(): void {
    // Run cleanup every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanupStaleMetrics();
    }, 60000);
  }

  /**
   * Remove metrics for sensors that have been offline too long
   */
  private cleanupStaleMetrics(): void {
    const now = Date.now();
    const retentionThreshold = now - this.config.metricsRetentionMs;
    let removedCount = 0;

    for (const [sensorId, sensor] of this.sensorMetrics.entries()) {
      if (sensor.lastHeartbeat.getTime() < retentionThreshold) {
        const tenantId = sensor.tenantId;
        const region = sensor.region;
        
        this.sensorMetrics.delete(sensorId);
        removedCount++;
        this.logger.info({ sensorId, tenantId }, 'Removed stale sensor metrics');
        this.emit('sensor-offline', { sensorId, tenantId });
        
        // Update online count gauge
        metrics.sensorsOnlineGauge.dec({ tenant_id: tenantId, region });
      }
    }

    if (removedCount > 0) {
      this.logger.info({ removedCount }, 'Cleaned up stale sensor metrics');
    }
  }

  /**
   * Stop the aggregator and cleanup resources
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.sensorMetrics.clear();
    this.removeAllListeners();
    this.logger.info('Fleet aggregator stopped');
  }
}
