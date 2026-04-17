/**
 * Fleet Operations Demo Data Generator
 *
 * Generates fleet-related demo data including sensors, metrics,
 * health data, connectivity, rules, onboarding tokens, and API keys.
 */

import type { DemoScenario } from '../../../stores/demoModeStore';

// ============================================================================
// Types
// ============================================================================

export interface FleetSensor {
  id: string;
  name: string;
  status: 'online' | 'warning' | 'offline';
  cpu: number;
  memory: number;
  rps: number;
  latencyMs: number;
  version: string;
  region: string;
}

export interface FleetMetrics {
  totalSensors: number;
  onlineCount: number;
  warningCount: number;
  offlineCount: number;
  totalRps: number;
  avgLatencyMs: number;
}

export interface RegionDistribution {
  region: string;
  online: number;
  warning: number;
  offline: number;
  total: number;
}

export interface FleetAlert {
  id: string;
  sensorName: string;
  type: string;
  error: string;
  createdAt: string;
}

export interface FleetOverview {
  summary: {
    totalSensors: number;
    onlineCount: number;
    warningCount: number;
    offlineCount: number;
    healthScore: number;
  };
  fleetMetrics: {
    totalRps: number;
    avgLatency: number;
    avgCpu: number;
    avgMemory: number;
  };
  regionDistribution: RegionDistribution[];
  recentAlerts: FleetAlert[];
}

export interface FleetIncident {
  id: string;
  sensorId: string;
  type: string;
  message: string;
  timestamp: string;
}

export interface FleetHealthData {
  overallScore: number;
  criticalAlerts: number;
  warningAlerts: number;
  recentIncidents: FleetIncident[];
}

export interface ConnectivitySensor {
  sensorId: string;
  sensorName: string;
  status: 'online' | 'offline' | 'degraded';
  latency: number;
  lastHeartbeat: string;
  reconnects: number;
  packetLoss: number;
}

export interface CloudEndpoint {
  name: string;
  url: string;
  status: 'healthy' | 'degraded' | 'down';
  latency: number;
}

export interface ConnectivityData {
  stats: {
    total: number;
    online: number;
    offline: number;
    degraded: number;
    avgLatency: number;
    uptime: number;
  };
  sensors: ConnectivitySensor[];
  cloudEndpoints: CloudEndpoint[];
}

export interface FleetRule {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
  category: string;
  createdAt: string;
}

export interface RuleSyncStatus {
  sensorId: string;
  totalRules: number;
  syncedRules: number;
  pendingRules: number;
  failedRules: number;
  lastSync: string;
}

export interface FleetRulesData {
  rules: FleetRule[];
  syncStatus: RuleSyncStatus[];
}

export interface OnboardingToken {
  id: string;
  name: string;
  tokenPrefix: string;
  status: 'active' | 'expired' | 'revoked';
  maxUses: number;
  usedCount: number;
  remainingUses: number;
  region: string;
  expiresAt: string;
  createdAt: string;
  createdBy: string;
}

export interface PendingSensor {
  id: string;
  name: string;
  hostname: string;
  region: string;
  version: string;
  os: string;
  architecture: string;
  publicIp: string;
  privateIp: string;
  registrationMethod: 'token' | 'api-key' | 'manual';
  createdAt: string;
  lastHeartbeat: string;
}

export interface OnboardingData {
  tokens: OnboardingToken[];
  pendingSensors: PendingSensor[];
}

export interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  sensorId: string | null;
  sensor: string | null;
  status: 'active' | 'expired' | 'revoked';
  permissions: string[];
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string | null;
}

export interface ApiKeysData {
  keys: ApiKey[];
}

export interface DlpViolation {
  timestamp: number;
  pattern_name: string;
  data_type: string;
  severity: string;
  masked_value: string;
  client_ip?: string;
  path: string;
}

export interface DlpStats {
  totalScans: number;
  totalMatches: number;
  patternCount: number;
}

export interface DlpData {
  stats: DlpStats;
  violations: DlpViolation[];
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    type: 'ip' | 'actor' | 'token' | 'asn' | 'campaign' | 'other';
    details?: Record<string, string | number>;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    label: string;
  };
}

export interface CampaignGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ConfigTemplate {
  id: string;
  name: string;
  description?: string;
  environment: 'production' | 'staging' | 'dev';
  version: string;
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface SyncStatus {
  totalSensors: number;
  syncedSensors: number;
  outOfSyncSensors: number;
  errorSensors: number;
  syncPercentage: number;
}

/**
 * A single multi-site entry for the /fleet/sites demo.
 *
 * Shape mirrors the UI's `FleetSite` output (hooks/fleet/useFleetSites)
 * so the hook can short-circuit in demo mode without a transform.
 * `raw` carries a Synapse-shaped payload that drives the edit drawer
 * exactly as a real fetch would — editing a demo site round-trips
 * through the same buildPayload() logic as a real one.
 */
export interface FleetSiteDemo {
  sensorId: string;
  sensorName: string;
  hostname: string;
  upstreams: string[];
  tlsEnabled: boolean;
  wafEnabled: boolean;
  rateLimitRps?: number;
  accessDefault?: string;
  raw: Record<string, unknown>;
}

export interface FleetData {
  sensors: FleetSensor[];
  metrics: FleetMetrics;
  overview: FleetOverview;
  health: FleetHealthData;
  connectivity: ConnectivityData;
  rules: FleetRulesData;
  onboarding: OnboardingData;
  apiKeys: ApiKeysData;
  dlp: DlpData;
  sites: FleetSiteDemo[];
  campaignGraphs: Record<string, CampaignGraphData>;
  configTemplates: ConfigTemplate[];
  syncStatus: SyncStatus;
}

// ============================================================================
// Constants
// ============================================================================

const REGIONS = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'eu-west-1',
  'eu-west-2',
  'eu-central-1',
  'ap-northeast-1',
  'ap-southeast-1',
  'ap-southeast-2',
];

const SENSOR_VERSIONS = ['2.4.1', '2.4.0', '2.3.8', '2.3.7'];

const RULE_CATEGORIES = [
  'injection',
  'authentication',
  'rate-limiting',
  'bot-detection',
  'custom',
  'compliance',
];

const ALERT_TYPES = [
  'high_cpu',
  'high_memory',
  'connection_lost',
  'version_mismatch',
  'rule_sync_failed',
  'certificate_expiring',
];

const ALERT_ERRORS: Record<string, string[]> = {
  high_cpu: [
    'CPU usage exceeded 90% for 5 minutes',
    'CPU spike detected during peak traffic',
    'Sustained high CPU affecting response times',
  ],
  high_memory: [
    'Memory usage exceeded 85% threshold',
    'Memory leak suspected in rule engine',
    'Garbage collection taking too long',
  ],
  connection_lost: [
    'Lost connection to control plane',
    'WebSocket connection timeout',
    'Network interface went down',
  ],
  version_mismatch: [
    'Sensor version outdated by 2+ minor versions',
    'Critical security patch available',
    'Incompatible rule format detected',
  ],
  rule_sync_failed: [
    'Failed to sync rules after 3 retries',
    'Rule validation failed on sensor',
    'Timeout during rule deployment',
  ],
  certificate_expiring: [
    'TLS certificate expires in 7 days',
    'Client certificate renewal required',
    'CA certificate rotation needed',
  ],
};

const INCIDENT_TYPES = [
  'connectivity',
  'performance',
  'security',
  'configuration',
  'resource',
];

const OS_TYPES = ['Linux', 'Windows Server', 'FreeBSD'];
const ARCHITECTURES = ['x86_64', 'arm64', 'aarch64'];

const CLOUD_ENDPOINTS = [
  { name: 'Control Plane', url: 'https://api.atlascrew.io/v1' },
  { name: 'Metrics Collector', url: 'https://metrics.atlascrew.io' },
  { name: 'Rule Distribution', url: 'https://rules.atlascrew.io' },
  { name: 'Telemetry', url: 'https://telemetry.atlascrew.io' },
  { name: 'Update Server', url: 'https://updates.atlascrew.io' },
];

const RULE_DEFINITIONS = [
  { name: 'SQL Injection Protection', description: 'Blocks SQL injection attempts in query parameters', category: 'injection', severity: 'critical' as const },
  { name: 'XSS Prevention', description: 'Prevents cross-site scripting attacks', category: 'injection', severity: 'high' as const },
  { name: 'Rate Limiting - API', description: 'Enforces rate limits on API endpoints', category: 'rate-limiting', severity: 'medium' as const },
  { name: 'Bot Detection - Automation', description: 'Detects automated bot traffic', category: 'bot-detection', severity: 'medium' as const },
  { name: 'Credential Stuffing Prevention', description: 'Blocks credential stuffing attacks', category: 'authentication', severity: 'critical' as const },
  { name: 'Path Traversal Protection', description: 'Prevents directory traversal attempts', category: 'injection', severity: 'high' as const },
  { name: 'JWT Validation', description: 'Validates JWT tokens and detects tampering', category: 'authentication', severity: 'high' as const },
  { name: 'DDoS Layer 7 Protection', description: 'Mitigates application-layer DDoS', category: 'rate-limiting', severity: 'critical' as const },
  { name: 'Command Injection Block', description: 'Blocks OS command injection attempts', category: 'injection', severity: 'critical' as const },
  { name: 'Scanner Detection', description: 'Identifies vulnerability scanner traffic', category: 'bot-detection', severity: 'medium' as const },
  { name: 'LDAP Injection Protection', description: 'Prevents LDAP injection attacks', category: 'injection', severity: 'high' as const },
  { name: 'XXE Prevention', description: 'Blocks XML external entity attacks', category: 'injection', severity: 'critical' as const },
  { name: 'SSRF Protection', description: 'Prevents server-side request forgery', category: 'injection', severity: 'high' as const },
  { name: 'GraphQL Depth Limit', description: 'Limits query depth in GraphQL requests', category: 'rate-limiting', severity: 'medium' as const },
  { name: 'Sensitive Data Masking', description: 'Masks sensitive data in responses', category: 'compliance', severity: 'high' as const },
  { name: 'PCI Compliance Rules', description: 'Enforces PCI-DSS compliance requirements', category: 'compliance', severity: 'critical' as const },
  { name: 'GDPR Data Protection', description: 'Ensures GDPR data handling compliance', category: 'compliance', severity: 'high' as const },
  { name: 'Headless Browser Detection', description: 'Detects headless browser automation', category: 'bot-detection', severity: 'low' as const },
  { name: 'API Key Validation', description: 'Validates API key format and permissions', category: 'authentication', severity: 'medium' as const },
  { name: 'Custom Business Logic', description: 'Application-specific protection rules', category: 'custom', severity: 'medium' as const },
];

// ============================================================================
// Helpers
// ============================================================================

function generateId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 9)}`;
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function generateTimestamp(hoursAgo: number): string {
  const date = new Date();
  date.setHours(date.getHours() - hoursAgo);
  date.setMinutes(Math.floor(Math.random() * 60));
  return date.toISOString();
}

function generateFutureTimestamp(daysAhead: number): string {
  const date = new Date();
  date.setDate(date.getDate() + daysAhead);
  return date.toISOString();
}

function randomInRange(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomFloat(min: number, max: number, decimals: number = 1): number {
  const value = Math.random() * (max - min) + min;
  return Number(value.toFixed(decimals));
}

function pickRandom<T>(array: T[]): T {
  return array[Math.floor(Math.random() * array.length)];
}

function generateIp(isPrivate: boolean = false): string {
  if (isPrivate) {
    return `10.${randomInRange(0, 255)}.${randomInRange(0, 255)}.${randomInRange(1, 254)}`;
  }
  return `${randomInRange(1, 223)}.${randomInRange(0, 255)}.${randomInRange(0, 255)}.${randomInRange(1, 254)}`;
}

// ============================================================================
// Sensor Generation
// ============================================================================

function generateSensors(scenario: DemoScenario): FleetSensor[] {
  const sensorCount = randomInRange(40, 60);
  const sensors: FleetSensor[] = [];

  // Status distribution based on scenario (warning%, offline%)
  // Online is implicit: 100 - warning - offline
  let warningPercent: number;
  let offlinePercent: number;

  switch (scenario) {
    case 'high-threat':
      warningPercent = 15;
      offlinePercent = 10;
      break;
    case 'quiet':
      warningPercent = 7;
      offlinePercent = 3;
      break;
    case 'normal':
    default:
      warningPercent = 12;
      offlinePercent = 8;
      break;
  }

  // Distribute sensors across regions
  const sensorsPerRegion = Math.ceil(sensorCount / REGIONS.length);

  for (let i = 0; i < sensorCount; i++) {
    const regionIndex = Math.floor(i / sensorsPerRegion) % REGIONS.length;
    const region = REGIONS[regionIndex];
    const regionAbbrev = region.replace(/-/g, '');
    const sensorNum = String(i + 1).padStart(3, '0');

    // Determine status based on percentages
    const rand = Math.random() * 100;
    let status: 'online' | 'warning' | 'offline';
    if (rand < offlinePercent) {
      status = 'offline';
    } else if (rand < offlinePercent + warningPercent) {
      status = 'warning';
    } else {
      status = 'online';
    }

    // Generate metrics based on scenario and status
    let cpu: number;
    let memory: number;
    let rps: number;
    let latencyMs: number;

    if (status === 'offline') {
      cpu = 0;
      memory = 0;
      rps = 0;
      latencyMs = 0;
    } else if (status === 'warning') {
      // Warning sensors have elevated metrics
      cpu = randomInRange(70, 95);
      memory = randomInRange(65, 90);
      rps = randomInRange(5000, 10000);
      latencyMs = randomInRange(80, 150);
    } else {
      // Online sensors vary by scenario
      if (scenario === 'high-threat') {
        cpu = randomInRange(50, 85);
        memory = randomInRange(45, 80);
        rps = randomInRange(2000, 10000);
        latencyMs = randomInRange(30, 100);
      } else if (scenario === 'quiet') {
        cpu = randomInRange(20, 45);
        memory = randomInRange(30, 55);
        rps = randomInRange(100, 2000);
        latencyMs = randomInRange(10, 40);
      } else {
        cpu = randomInRange(35, 70);
        memory = randomInRange(40, 70);
        rps = randomInRange(500, 5000);
        latencyMs = randomInRange(20, 80);
      }
    }

    sensors.push({
      id: generateUUID(),
      name: `sensor-${regionAbbrev.substring(0, 6)}-${sensorNum}`,
      status,
      cpu,
      memory,
      rps,
      latencyMs,
      version: pickRandom(SENSOR_VERSIONS),
      region,
    });
  }

  return sensors;
}

// ============================================================================
// Metrics Generation
// ============================================================================

function generateFleetMetrics(sensors: FleetSensor[]): FleetMetrics {
  const onlineSensors = sensors.filter((s) => s.status !== 'offline');

  return {
    totalSensors: sensors.length,
    onlineCount: sensors.filter((s) => s.status === 'online').length,
    warningCount: sensors.filter((s) => s.status === 'warning').length,
    offlineCount: sensors.filter((s) => s.status === 'offline').length,
    totalRps: onlineSensors.reduce((sum, s) => sum + s.rps, 0),
    avgLatencyMs:
      onlineSensors.length > 0
        ? Math.round(
            onlineSensors.reduce((sum, s) => sum + s.latencyMs, 0) / onlineSensors.length
          )
        : 0,
  };
}

// ============================================================================
// Overview Generation
// ============================================================================

function generateFleetOverview(
  sensors: FleetSensor[],
  metrics: FleetMetrics,
  scenario: DemoScenario
): FleetOverview {
  // Calculate region distribution
  const regionMap = new Map<string, { online: number; warning: number; offline: number }>();

  for (const region of REGIONS) {
    regionMap.set(region, { online: 0, warning: 0, offline: 0 });
  }

  for (const sensor of sensors) {
    const regionData = regionMap.get(sensor.region);
    if (regionData) {
      if (sensor.status === 'online') regionData.online++;
      else if (sensor.status === 'warning') regionData.warning++;
      else regionData.offline++;
    }
  }

  const regionDistribution: RegionDistribution[] = Array.from(regionMap.entries())
    .filter(([_, data]) => data.online + data.warning + data.offline > 0)
    .map(([region, data]) => ({
      region,
      online: data.online,
      warning: data.warning,
      offline: data.offline,
      total: data.online + data.warning + data.offline,
    }));

  // Calculate health score
  let healthScore: number;
  const onlineRatio = metrics.onlineCount / metrics.totalSensors;
  const warningPenalty = (metrics.warningCount / metrics.totalSensors) * 15;
  const offlinePenalty = (metrics.offlineCount / metrics.totalSensors) * 30;

  healthScore = Math.round(Math.max(0, Math.min(100, onlineRatio * 100 - warningPenalty - offlinePenalty)));

  // Generate recent alerts
  const alertCount = scenario === 'high-threat' ? randomInRange(5, 10) : scenario === 'quiet' ? randomInRange(0, 2) : randomInRange(2, 5);
  const recentAlerts: FleetAlert[] = [];

  const problematicSensors = sensors.filter((s) => s.status !== 'online');
  for (let i = 0; i < alertCount; i++) {
    const sensor = problematicSensors.length > 0 ? pickRandom(problematicSensors) : pickRandom(sensors);
    const alertType = pickRandom(ALERT_TYPES);
    const errors = ALERT_ERRORS[alertType] || ['Unknown error'];

    recentAlerts.push({
      id: generateId(),
      sensorName: sensor.name,
      type: alertType,
      error: pickRandom(errors),
      createdAt: generateTimestamp(Math.random() * 24),
    });
  }

  // Sort alerts by time (newest first)
  recentAlerts.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  // Calculate aggregate metrics
  const onlineSensors = sensors.filter((s) => s.status !== 'offline');
  const avgCpu = onlineSensors.length > 0
    ? Math.round(onlineSensors.reduce((sum, s) => sum + s.cpu, 0) / onlineSensors.length)
    : 0;
  const avgMemory = onlineSensors.length > 0
    ? Math.round(onlineSensors.reduce((sum, s) => sum + s.memory, 0) / onlineSensors.length)
    : 0;

  return {
    summary: {
      totalSensors: metrics.totalSensors,
      onlineCount: metrics.onlineCount,
      warningCount: metrics.warningCount,
      offlineCount: metrics.offlineCount,
      healthScore,
    },
    fleetMetrics: {
      totalRps: metrics.totalRps,
      avgLatency: metrics.avgLatencyMs,
      avgCpu,
      avgMemory,
    },
    regionDistribution,
    recentAlerts,
  };
}

// ============================================================================
// Health Data Generation
// ============================================================================

function generateHealthData(
  sensors: FleetSensor[],
  scenario: DemoScenario
): FleetHealthData {
  // Calculate overall score
  let overallScore: number;
  switch (scenario) {
    case 'high-threat':
      overallScore = randomInRange(65, 78);
      break;
    case 'quiet':
      overallScore = randomInRange(88, 95);
      break;
    case 'normal':
    default:
      overallScore = randomInRange(78, 88);
      break;
  }

  // Alert counts based on scenario
  let criticalAlerts: number;
  let warningAlerts: number;

  switch (scenario) {
    case 'high-threat':
      criticalAlerts = randomInRange(3, 8);
      warningAlerts = randomInRange(8, 15);
      break;
    case 'quiet':
      criticalAlerts = 0;
      warningAlerts = randomInRange(0, 2);
      break;
    case 'normal':
    default:
      criticalAlerts = randomInRange(0, 2);
      warningAlerts = randomInRange(3, 7);
      break;
  }

  // Generate recent incidents
  const incidentCount = scenario === 'high-threat' ? randomInRange(5, 10) : scenario === 'quiet' ? randomInRange(0, 2) : randomInRange(2, 5);
  const recentIncidents: FleetIncident[] = [];

  const incidentMessages: Record<string, string[]> = {
    connectivity: [
      'Connection to control plane lost',
      'WebSocket reconnection attempts exceeded',
      'DNS resolution failure',
    ],
    performance: [
      'High latency detected on sensor',
      'Response time exceeded SLA threshold',
      'Processing queue backlog detected',
    ],
    security: [
      'Certificate validation failed',
      'Unauthorized access attempt blocked',
      'Anomalous traffic pattern detected',
    ],
    configuration: [
      'Rule deployment failed',
      'Configuration mismatch detected',
      'Version update required',
    ],
    resource: [
      'Memory threshold exceeded',
      'CPU utilization critical',
      'Disk space running low',
    ],
  };

  for (let i = 0; i < incidentCount; i++) {
    const sensor = pickRandom(sensors);
    const type = pickRandom(INCIDENT_TYPES);
    const messages = incidentMessages[type] || ['Unknown incident'];

    recentIncidents.push({
      id: generateUUID(),
      sensorId: sensor.id,
      type,
      message: pickRandom(messages),
      timestamp: generateTimestamp(Math.random() * 48),
    });
  }

  // Sort incidents by time (newest first)
  recentIncidents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return {
    overallScore,
    criticalAlerts,
    warningAlerts,
    recentIncidents,
  };
}

// ============================================================================
// Connectivity Data Generation
// ============================================================================

function generateConnectivityData(
  sensors: FleetSensor[],
  scenario: DemoScenario
): ConnectivityData {
  // Map sensors to connectivity data
  const connectivitySensors: ConnectivitySensor[] = sensors.map((sensor) => {
    let connStatus: 'online' | 'offline' | 'degraded';
    if (sensor.status === 'offline') {
      connStatus = 'offline';
    } else if (sensor.status === 'warning') {
      connStatus = Math.random() > 0.5 ? 'degraded' : 'online';
    } else {
      connStatus = 'online';
    }

    // Generate reconnects and packet loss based on status
    let reconnects: number;
    let packetLoss: number;

    if (connStatus === 'offline') {
      reconnects = randomInRange(10, 50);
      packetLoss = 100;
    } else if (connStatus === 'degraded') {
      reconnects = randomInRange(3, 15);
      packetLoss = randomFloat(2, 15);
    } else {
      reconnects = randomInRange(0, 3);
      packetLoss = randomFloat(0, 1);
    }

    return {
      sensorId: sensor.id,
      sensorName: sensor.name,
      status: connStatus,
      latency: sensor.latencyMs || randomInRange(10, 150),
      lastHeartbeat: sensor.status === 'offline'
        ? generateTimestamp(randomInRange(1, 24))
        : generateTimestamp(randomFloat(0, 0.1)),
      reconnects,
      packetLoss,
    };
  });

  // Calculate stats
  const onlineCount = connectivitySensors.filter((s) => s.status === 'online').length;
  const offlineCount = connectivitySensors.filter((s) => s.status === 'offline').length;
  const degradedCount = connectivitySensors.filter((s) => s.status === 'degraded').length;
  const activeSensors = connectivitySensors.filter((s) => s.status !== 'offline');
  const avgLatency = activeSensors.length > 0
    ? Math.round(activeSensors.reduce((sum, s) => sum + s.latency, 0) / activeSensors.length)
    : 0;

  // Calculate uptime based on scenario
  let uptime: number;
  switch (scenario) {
    case 'high-threat':
      uptime = randomFloat(96.5, 98.5);
      break;
    case 'quiet':
      uptime = randomFloat(99.5, 99.99);
      break;
    case 'normal':
    default:
      uptime = randomFloat(98.5, 99.5);
      break;
  }

  // Generate cloud endpoints with status based on scenario
  const cloudEndpoints: CloudEndpoint[] = CLOUD_ENDPOINTS.map((endpoint) => {
    let status: 'healthy' | 'degraded' | 'down';
    let latency: number;

    if (scenario === 'high-threat' && Math.random() < 0.15) {
      status = Math.random() < 0.3 ? 'down' : 'degraded';
      latency = status === 'down' ? 0 : randomInRange(200, 500);
    } else if (scenario === 'normal' && Math.random() < 0.05) {
      status = 'degraded';
      latency = randomInRange(150, 300);
    } else {
      status = 'healthy';
      latency = randomInRange(20, 80);
    }

    return {
      name: endpoint.name,
      url: endpoint.url,
      status,
      latency,
    };
  });

  return {
    stats: {
      total: sensors.length,
      online: onlineCount,
      offline: offlineCount,
      degraded: degradedCount,
      avgLatency,
      uptime,
    },
    sensors: connectivitySensors,
    cloudEndpoints,
  };
}

// ============================================================================
// Rules Generation
// ============================================================================

function generateRulesData(
  sensors: FleetSensor[],
  scenario: DemoScenario
): FleetRulesData {
  // Generate rules (50-100 based on scenario)
  const ruleCount = scenario === 'high-threat' ? randomInRange(80, 100) : scenario === 'quiet' ? randomInRange(50, 65) : randomInRange(60, 80);

  const rules: FleetRule[] = [];

  // Use predefined rules first, then generate additional ones
  for (let i = 0; i < ruleCount; i++) {
    if (i < RULE_DEFINITIONS.length) {
      const def = RULE_DEFINITIONS[i];
      rules.push({
        id: generateUUID(),
        name: def.name,
        description: def.description,
        severity: def.severity,
        enabled: Math.random() > 0.1, // 90% enabled
        category: def.category,
        createdAt: generateTimestamp(randomInRange(24, 720)), // 1-30 days ago
      });
    } else {
      // Generate additional custom rules
      const category = pickRandom(RULE_CATEGORIES);
      const severity = pickRandom(['critical', 'high', 'medium', 'low']) as FleetRule['severity'];
      const ruleNum = i + 1;

      rules.push({
        id: generateUUID(),
        name: `Custom Rule ${ruleNum}`,
        description: `Custom ${category} protection rule #${ruleNum}`,
        severity,
        enabled: Math.random() > 0.15, // 85% enabled
        category,
        createdAt: generateTimestamp(randomInRange(24, 720)),
      });
    }
  }

  // Generate sync status for each sensor
  const syncStatus: RuleSyncStatus[] = sensors.map((sensor) => {
    const totalRules = rules.filter((r) => r.enabled).length;
    let syncedRules: number;
    let pendingRules: number;
    let failedRules: number;

    if (sensor.status === 'offline') {
      syncedRules = Math.floor(totalRules * randomFloat(0.5, 0.8));
      pendingRules = totalRules - syncedRules;
      failedRules = 0;
    } else if (sensor.status === 'warning') {
      const syncRatio = randomFloat(0.85, 0.95);
      syncedRules = Math.floor(totalRules * syncRatio);
      failedRules = randomInRange(1, 5);
      pendingRules = totalRules - syncedRules - failedRules;
    } else {
      const syncRatio = scenario === 'high-threat' ? randomFloat(0.92, 0.98) : randomFloat(0.97, 1.0);
      syncedRules = Math.floor(totalRules * syncRatio);
      failedRules = scenario === 'high-threat' ? randomInRange(0, 2) : 0;
      pendingRules = Math.max(0, totalRules - syncedRules - failedRules);
    }

    return {
      sensorId: sensor.id,
      totalRules,
      syncedRules,
      pendingRules: Math.max(0, pendingRules),
      failedRules,
      lastSync: sensor.status === 'offline'
        ? generateTimestamp(randomInRange(1, 24))
        : generateTimestamp(randomFloat(0, 0.5)),
    };
  });

  return {
    rules,
    syncStatus,
  };
}

// ============================================================================
// Onboarding Data Generation
// ============================================================================

function generateOnboardingData(scenario: DemoScenario): OnboardingData {
  // Generate tokens (5-15 based on scenario)
  const tokenCount = scenario === 'high-threat' ? randomInRange(8, 15) : scenario === 'quiet' ? randomInRange(3, 6) : randomInRange(5, 10);

  const tokens: OnboardingToken[] = [];
  const users = ['admin@company.com', 'devops@company.com', 'security@company.com', 'platform@company.com'];

  for (let i = 0; i < tokenCount; i++) {
    const maxUses = pickRandom([5, 10, 25, 50, 100]);
    const usedCount = randomInRange(0, maxUses);
    const daysAgo = randomInRange(1, 30);
    const expiresInDays = randomInRange(-5, 30); // Some may be expired

    let status: OnboardingToken['status'];
    if (expiresInDays < 0) {
      status = 'expired';
    } else if (Math.random() < 0.1) {
      status = 'revoked';
    } else {
      status = 'active';
    }

    tokens.push({
      id: generateUUID(),
      name: `Onboarding Token ${i + 1}`,
      tokenPrefix: `txob_${Math.random().toString(36).substring(2, 10)}`,
      status,
      maxUses,
      usedCount,
      remainingUses: Math.max(0, maxUses - usedCount),
      region: pickRandom(REGIONS),
      expiresAt: expiresInDays < 0
        ? generateTimestamp(Math.abs(expiresInDays) * 24)
        : generateFutureTimestamp(expiresInDays),
      createdAt: generateTimestamp(daysAgo * 24),
      createdBy: pickRandom(users),
    });
  }

  // Generate pending sensors (0-8 based on scenario)
  const pendingCount = scenario === 'high-threat' ? randomInRange(3, 8) : scenario === 'quiet' ? randomInRange(0, 2) : randomInRange(1, 5);

  const pendingSensors: PendingSensor[] = [];

  for (let i = 0; i < pendingCount; i++) {
    const region = pickRandom(REGIONS);
    const regionAbbrev = region.replace(/-/g, '').substring(0, 6);

    pendingSensors.push({
      id: generateUUID(),
      name: `pending-${regionAbbrev}-${String(i + 1).padStart(3, '0')}`,
      hostname: `sensor-${i + 1}.${region}.internal`,
      region,
      version: pickRandom(SENSOR_VERSIONS),
      os: pickRandom(OS_TYPES),
      architecture: pickRandom(ARCHITECTURES),
      publicIp: generateIp(false),
      privateIp: generateIp(true),
      registrationMethod: pickRandom(['token', 'api-key', 'manual']),
      createdAt: generateTimestamp(randomInRange(1, 72)),
      lastHeartbeat: generateTimestamp(randomFloat(0, 1)),
    });
  }

  return {
    tokens,
    pendingSensors,
  };
}

// ============================================================================
// API Keys Generation
// ============================================================================

function generateApiKeysData(sensors: FleetSensor[], scenario: DemoScenario): ApiKeysData {
  // Generate API keys (10-30 based on scenario)
  const keyCount = scenario === 'high-threat' ? randomInRange(20, 30) : scenario === 'quiet' ? randomInRange(8, 15) : randomInRange(12, 20);

  const permissionSets = [
    ['read:sensors', 'read:metrics'],
    ['read:sensors', 'read:metrics', 'write:rules'],
    ['read:sensors', 'read:metrics', 'read:rules', 'write:rules', 'manage:sensors'],
    ['read:*', 'write:*'],
    ['admin:*'],
  ];

  const keys: ApiKey[] = [];

  for (let i = 0; i < keyCount; i++) {
    const daysAgo = randomInRange(1, 90);
    const expiresInDays = randomInRange(-10, 365);
    const hasSensor = Math.random() > 0.3;
    const sensor = hasSensor ? pickRandom(sensors) : null;

    let status: ApiKey['status'];
    if (expiresInDays < 0) {
      status = 'expired';
    } else if (Math.random() < 0.08) {
      status = 'revoked';
    } else {
      status = 'active';
    }

    keys.push({
      id: generateUUID(),
      name: `API Key ${i + 1}`,
      keyPrefix: `txk_${Math.random().toString(36).substring(2, 10)}`,
      sensorId: sensor?.id || null,
      sensor: sensor?.name || null,
      status,
      permissions: pickRandom(permissionSets),
      createdAt: generateTimestamp(daysAgo * 24),
      expiresAt: expiresInDays < 0
        ? generateTimestamp(Math.abs(expiresInDays) * 24)
        : generateFutureTimestamp(expiresInDays),
      lastUsedAt: status === 'active' && Math.random() > 0.2
        ? generateTimestamp(randomFloat(0, 48))
        : null,
    });
  }

  return { keys };
}

// ============================================================================
// DLP Generation
// ============================================================================

function generateDlpData(scenario: DemoScenario): DlpData {
  const totalScans = scenario === 'high-threat' ? 842100 : scenario === 'quiet' ? 12400 : 452300;
  const totalMatches = scenario === 'high-threat' ? 1242 : scenario === 'quiet' ? 3 : 156;
  const patternCount = 25;

  const patterns = [
    { name: 'Visa Card', type: 'credit_card', severity: 'critical' },
    { name: 'MasterCard', type: 'credit_card', severity: 'critical' },
    { name: 'SSN (formatted)', type: 'ssn', severity: 'critical' },
    { name: 'Email Address', type: 'email', severity: 'medium' },
    { name: 'AWS Secret Key', type: 'aws_key', severity: 'critical' },
    { name: 'GitHub Token', type: 'api_key', severity: 'critical' },
    { name: 'Stripe API Key', type: 'api_key', severity: 'critical' },
    { name: 'Password in JSON', type: 'password', severity: 'critical' },
    { name: 'Custom Keyword', type: 'custom', severity: 'high' },
  ];

  const paths = [
    '/api/v1/users/profile',
    '/api/v1/payments/checkout',
    '/api/v1/admin/config',
    '/api/v1/auth/login',
    '/api/v1/debug/dump',
  ];

  const violations: DlpViolation[] = Array.from({ length: totalMatches > 20 ? 20 : totalMatches }, (_, i) => {
    const pattern = pickRandom(patterns);
    return {
      timestamp: Date.now() - i * 1000 * 60 * 5, // Every 5 minutes
      pattern_name: pattern.name,
      data_type: pattern.type,
      severity: pattern.severity,
      masked_value: pattern.type === 'credit_card' ? '****-****-****-4242' : '********',
      client_ip: generateIp(false),
      path: pickRandom(paths),
    };
  });

  return {
    stats: { totalScans, totalMatches, patternCount },
    violations,
  };
}

// ============================================================================
// Campaign Graph Generation
// ============================================================================

function generateCampaignGraphsData(_scenario: DemoScenario): Record<string, CampaignGraphData> {
  const graphs: Record<string, CampaignGraphData> = {};
  
  // Generate a couple of demo graphs
  const campaignIds = ['camp-001', 'camp-002'];
  
  for (const id of campaignIds) {
    const nodes: GraphNode[] = [
      { data: { id: 'campaign', label: id === 'camp-001' ? 'Dark Phoenix' : 'SQLi Wave', type: 'campaign' } },
    ];
    const edges: GraphEdge[] = [];

    // Add 3-5 actor nodes
    for (let i = 1; i <= 3; i++) {
      const actorId = `fp-${id}-${i}`;
      nodes.push({ data: { id: actorId, label: `FP-${Math.random().toString(36).substring(2, 6)}`, type: 'actor' } });
      edges.push({ data: { id: `e-c-${actorId}`, source: 'campaign', target: actorId, label: 'attributed' } });

      // Link each actor to 2-3 IPs
      for (let j = 1; j <= 2; j++) {
        const ipId = `ip-${id}-${i}-${j}`;
        nodes.push({ data: { id: ipId, label: generateIp(false), type: 'ip', details: { 'Risk Score': randomInRange(60, 95) } } });
        edges.push({ data: { id: `e-a-${ipId}`, source: actorId, target: ipId, label: 'uses' } });
      }
    }

    graphs[id] = { nodes, edges };
  }

  return graphs;
}

// ============================================================================
// Configuration Generation
// ============================================================================

function generateConfigTemplatesData(scenario: DemoScenario): ConfigTemplate[] {
  const templates: ConfigTemplate[] = [
    {
      id: 'tpl-prod-standard',
      name: 'Production Standard',
      description: 'Standard WAF and rate limit settings for production sites',
      environment: 'production',
      version: '1.2.4',
      isActive: true,
      createdAt: generateTimestamp(720),
      updatedAt: generateTimestamp(24),
    },
    {
      id: 'tpl-staging-v2',
      name: 'Staging v2 Testing',
      description: 'Experimental schema validation settings for v2 rollout',
      environment: 'staging',
      version: '2.0.0-rc1',
      isActive: true,
      createdAt: generateTimestamp(168),
      updatedAt: generateTimestamp(48),
    },
    {
      id: 'tpl-dev-permissive',
      name: 'Developer Permissive',
      description: 'Relaxed security settings for local development environments',
      environment: 'dev',
      version: '0.9.5',
      isActive: true,
      createdAt: generateTimestamp(240),
      updatedAt: generateTimestamp(120),
    },
  ];

  if (scenario === 'high-threat') {
    templates.push({
      id: 'tpl-incident-hardened',
      name: 'Incident Response Hardened',
      description: 'Aggressive blocking and detailed logging for active attacks',
      environment: 'production',
      version: '1.0.0',
      isActive: false,
      createdAt: generateTimestamp(2),
      updatedAt: generateTimestamp(1),
    });
  }

  return templates;
}

function generateSyncStatusData(sensors: FleetSensor[]): SyncStatus {
  const totalSensors = sensors.length;
  const offlineCount = sensors.filter(s => s.status === 'offline').length;
  const warningCount = sensors.filter(s => s.status === 'warning').length;
  
  const syncedSensors = totalSensors - offlineCount - warningCount;
  const outOfSyncSensors = warningCount;
  const errorSensors = 0; // Simulated
  const syncPercentage = totalSensors > 0 ? (syncedSensors / totalSensors) * 100 : 100;

  return {
    totalSensors,
    syncedSensors,
    outOfSyncSensors,
    errorSensors,
    syncPercentage,
  };
}

// ============================================================================
// Main Export
// ============================================================================

// ============================================================================
// Fleet Sites Generator
// ============================================================================

// A compact pool of realistic-looking hostnames. Each online sensor
// gets a small rotating slice so the demo looks populated without
// being overwhelming — ~2-4 sites per sensor gives a ~60-150 site
// table for the standard ~40-50 sensor demo fleet.
const SITE_HOSTNAME_PREFIXES = [
  'api', 'auth', 'cdn', 'www', 'app', 'admin', 'status', 'ingest',
  'metrics', 'docs', 'assets', 'ws',
] as const;

const SITE_HOSTNAME_DOMAINS = [
  'synapse.demo',
  'acme-api.io',
  'edge.example.com',
  'ingest.sample.com',
] as const;

// Upstream port pools by service type. Using real-world default ports
// makes the data feel authentic to anyone who's deployed a service.
const UPSTREAM_PORTS = {
  http: [8080, 8081, 8082, 3000, 3100, 5000],
  api: [4000, 4001, 5555, 6000, 6001, 7000],
  tls: [443, 8443],
} as const;

function generateSitesData(
  sensors: FleetSensor[],
  scenario: DemoScenario,
): FleetSiteDemo[] {
  const sites: FleetSiteDemo[] = [];

  // Only online/warning sensors serve sites — an offline sensor can't
  // proxy anything. warning-state sensors are degraded but usually
  // still serve their sites (just with elevated latency/error rates).
  const eligibleSensors = sensors.filter((s) => s.status !== 'offline');

  // Distribute hostname prefixes round-robin across sensors so the
  // table has natural variety without duplicate hostnames on the
  // same sensor.
  let prefixIdx = 0;

  for (const sensor of eligibleSensors) {
    // Sites per sensor varies by scenario: high-threat fleets tend to
    // be busier, quiet ones simpler. 1-4 sites per sensor feels right.
    const perSensor =
      scenario === 'high-threat' ? randomInRange(2, 4)
      : scenario === 'quiet' ? randomInRange(1, 2)
      : randomInRange(1, 3);

    for (let i = 0; i < perSensor; i++) {
      const prefix = SITE_HOSTNAME_PREFIXES[prefixIdx % SITE_HOSTNAME_PREFIXES.length];
      const domain = SITE_HOSTNAME_DOMAINS[prefixIdx % SITE_HOSTNAME_DOMAINS.length];
      prefixIdx++;
      const hostname = `${prefix}.${domain}`;

      // Upstreams: 1-2 backends in realistic host:port form. Load-
      // balanced pairs are common enough (blue/green, a/b) to be
      // worth showing in the demo.
      const upstreamCount = Math.random() < 0.3 ? 2 : 1;
      const portPool = prefix === 'api' || prefix === 'ingest'
        ? UPSTREAM_PORTS.api
        : UPSTREAM_PORTS.http;
      const upstreams: string[] = [];
      const upstreamObjects: Array<{ host: string; port: number }> = [];
      for (let u = 0; u < upstreamCount; u++) {
        const host = `10.${sensor.region.startsWith('us') ? 0 : 1}.${upstreamCount > 1 ? u : 0}.${50 + (prefixIdx % 200)}`;
        const port = portPool[Math.floor(Math.random() * portPool.length)];
        upstreams.push(`${host}:${port}`);
        upstreamObjects.push({ host, port });
      }

      // Config distribution rules (matches real-world deployments):
      //  - ~80% WAF enabled (default-on protection)
      //  - ~40% have TLS configured (most production sites)
      //  - ~30% have per-site rate limits set
      //  - ~10% have access control (allow/deny CIDR rules)
      const wafEnabled = Math.random() < 0.8;
      const hasTls = Math.random() < 0.4;
      const hasRateLimit = Math.random() < 0.3;
      const hasAccessControl = Math.random() < 0.1;

      const rateLimitRps = hasRateLimit
        ? [100, 500, 1000, 2500, 5000, 10000][Math.floor(Math.random() * 6)]
        : undefined;
      const accessDefault = hasAccessControl
        ? Math.random() < 0.7 ? 'allow' : 'deny'
        : undefined;

      // `raw` mirrors the Synapse /sites/:hostname response shape so
      // the edit drawer's buildPayload() reads the same fields it
      // would against a real sensor. Keeps the demo path faithful to
      // the real API contract.
      const raw: Record<string, unknown> = {
        hostname,
        upstreams: upstreamObjects,
        tls: hasTls
          ? {
              cert_path: `/etc/synapse/certs/${hostname}.crt`,
              key_path: `/etc/synapse/certs/${hostname}.key`,
              min_version: '1.3',
            }
          : null,
        waf: {
          enabled: wafEnabled,
          threshold: wafEnabled ? [50, 60, 70, 80][Math.floor(Math.random() * 4)] : null,
          rule_overrides: {},
        },
        rate_limit: hasRateLimit
          ? { enabled: true, rps: rateLimitRps, burst: null }
          : null,
        access_control: hasAccessControl
          ? {
              allow: accessDefault === 'deny' ? ['10.0.0.0/8', '192.168.0.0/16'] : [],
              deny: accessDefault === 'allow' ? ['203.0.113.0/24'] : [],
              default_action: accessDefault,
            }
          : null,
        headers: null,
        shadow_mirror: null,
      };

      sites.push({
        sensorId: sensor.id,
        sensorName: sensor.name,
        hostname,
        upstreams,
        tlsEnabled: hasTls,
        wafEnabled,
        rateLimitRps,
        accessDefault,
        raw,
      });
    }
  }

  return sites;
}

export function generateFleetData(scenario: DemoScenario): FleetData {
  // Generate sensors first (used by other generators)
  const sensors = generateSensors(scenario);

  // Generate metrics from sensors
  const metrics = generateFleetMetrics(sensors);

  // Generate all other data
  const overview = generateFleetOverview(sensors, metrics, scenario);
  const health = generateHealthData(sensors, scenario);
  const connectivity = generateConnectivityData(sensors, scenario);
  const rules = generateRulesData(sensors, scenario);
  const onboarding = generateOnboardingData(scenario);
  const apiKeys = generateApiKeysData(sensors, scenario);
  const dlp = generateDlpData(scenario);
  const sites = generateSitesData(sensors, scenario);
  const campaignGraphs = generateCampaignGraphsData(scenario);
  const configTemplates = generateConfigTemplatesData(scenario);
  const syncStatus = generateSyncStatusData(sensors);

  return {
    sensors,
    metrics,
    overview,
    health,
    connectivity,
    rules,
    onboarding,
    apiKeys,
    dlp,
    sites,
    campaignGraphs,
    configTemplates,
    syncStatus,
  };
}

export default generateFleetData;
