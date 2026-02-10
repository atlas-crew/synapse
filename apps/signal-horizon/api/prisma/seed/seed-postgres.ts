import {
  PrismaClient,
  Prisma,
  TenantTier,
  SharingPreference,
  UserRole,
  ConnectionState,
  RegistrationMethod,
  ApprovalStatus,
  SignalType,
  Severity,
  ThreatType,
  BlockType,
  BlockSource,
  PropagationStatus,
  CampaignStatus,
  WarRoomStatus,
  Priority,
} from '@prisma/client';
import type { SeedOptions } from './args.js';
import { Rng } from './rng.js';
import { randomHex, randomIp, scryptHash, sha256Hex, slugify, clamp } from './util.js';

export interface SeedSummary {
  tenants: Array<{
    tenantId: string;
    tenantName: string;
    adminEmail: string;
    adminPassword: string;
    dashboardApiKey: string;
    sensors: string[];
    sensorBridge?: {
      sensorId: string;
      sensorName: string;
      apiKey: string;
    };
  }>;
}

const REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'eu-central-1', 'ap-southeast-1'] as const;
const SENSOR_VERSIONS = ['1.2.0', '1.2.4', '1.3.0', '1.3.2'] as const;
const OS_STRINGS = ['Ubuntu 22.04.3 LTS', 'Debian 12', 'Amazon Linux 2023', 'Rocky Linux 9.4'] as const;
const INSTANCE_TYPES = ['c6i.xlarge', 'c6i.2xlarge', 'm6i.xlarge', 'c5.xlarge', 'c7i.xlarge'] as const;

const ENDPOINT_METHODS = ['GET', 'POST', 'PUT', 'DELETE'] as const;
const ENDPOINT_PATHS = [
  '/api/v1/auth/login',
  '/api/v1/auth/refresh',
  '/api/v1/users/profile',
  '/api/v1/users/{id}',
  '/api/v1/users/{id}/roles',
  '/api/v1/orders',
  '/api/v1/orders/{id}',
  '/api/v1/orders/{id}/checkout',
  '/api/v1/catalog',
  '/api/v1/catalog/search',
  '/api/v1/admin/purge-cache',
  '/api/v1/admin/audit-export',
  '/api/v1/billing/payment-methods',
  '/api/v1/billing/invoices',
  '/internal/health',
  '/internal/metrics',
] as const;

const API_INTELLIGENCE_VIOLATION_TYPES = [
  'type_mismatch',
  'missing_required_field',
  'extra_field',
  'format_error',
  'constraint_violation',
  'invalid_enum_value',
] as const;

function violationMessageForType(v: (typeof API_INTELLIGENCE_VIOLATION_TYPES)[number]): string {
  switch (v) {
    case 'type_mismatch':
      return 'Field had an unexpected type (seeded schema mismatch).';
    case 'missing_required_field':
      return 'Request missing required field (seeded schema mismatch).';
    case 'extra_field':
      return 'Request contained an unexpected field (seeded schema mismatch).';
    case 'format_error':
      return 'Field did not match required format (seeded schema mismatch).';
    case 'constraint_violation':
      return 'Value violated schema constraint (seeded schema mismatch).';
    case 'invalid_enum_value':
      return 'Value not in allowed enum set (seeded schema mismatch).';
  }
}

function tenantSeedName(i: number): { name: string; tier: TenantTier; sharing: SharingPreference } {
  const presets = [
    { name: 'Acme Corporation', tier: TenantTier.PLATINUM, sharing: SharingPreference.CONTRIBUTE_AND_RECEIVE },
    { name: 'Globex Industries', tier: TenantTier.ENTERPRISE, sharing: SharingPreference.CONTRIBUTE_AND_RECEIVE },
    { name: 'Initech LLC', tier: TenantTier.STANDARD, sharing: SharingPreference.RECEIVE_ONLY },
    { name: 'Umbrella Holdings', tier: TenantTier.STANDARD, sharing: SharingPreference.CONTRIBUTE_AND_RECEIVE },
    { name: 'Stark Logistics', tier: TenantTier.ENTERPRISE, sharing: SharingPreference.CONTRIBUTE_ONLY },
    { name: 'Wayne Retail', tier: TenantTier.FREE, sharing: SharingPreference.RECEIVE_ONLY },
  ] as const;
  if (i < presets.length) return presets[i];
  return { name: `Tenant ${i + 1}`, tier: TenantTier.STANDARD, sharing: SharingPreference.CONTRIBUTE_AND_RECEIVE };
}

function signalSeverityForType(type: SignalType): Severity {
  switch (type) {
    case SignalType.CREDENTIAL_STUFFING:
    case SignalType.IMPOSSIBLE_TRAVEL:
      return Severity.CRITICAL;
    case SignalType.IP_THREAT:
    case SignalType.FINGERPRINT_THREAT:
      return Severity.HIGH;
    case SignalType.SCHEMA_VIOLATION:
      return Severity.MEDIUM;
    default:
      return Severity.LOW;
  }
}

function buildPolicyConfig(rng: Rng, mode: 'standard' | 'strict' | 'dev'): Prisma.InputJsonValue {
  const base = mode === 'strict' ? 0.25 : mode === 'dev' ? 0.75 : 0.5;
  return {
    waf: {
      enabled: true,
      threshold: base,
      overrides: {
        'rule-sqli-001': { enabled: true, action: mode === 'dev' ? 'log' : 'block' },
        'rule-xss-001': { enabled: true, action: 'block' },
      },
    },
    rateLimit: {
      enabled: mode !== 'dev',
      rps: mode === 'strict' ? 80 : 120,
      burst: mode === 'strict' ? 20 : 60,
    },
    anomaly: {
      impossibleTravel: true,
      minConfidence: clamp(0.6 + rng.float() * 0.2, 0.5, 0.95),
    },
  } satisfies Record<string, unknown>;
}

function playbookSteps(rng: Rng): Prisma.InputJsonValue {
  return [
    { kind: 'note', text: 'Triage: identify impacted endpoints and tenants', timeoutSec: 300 },
    { kind: 'query', name: 'recent signals', query: { lastHours: 6, types: ['CREDENTIAL_STUFFING', 'IP_THREAT'] } },
    { kind: 'action', name: 'block top IPs', mode: rng.bool(0.7) ? 'auto' : 'manual' },
    { kind: 'notify', channel: 'soc', template: 'war-room-update-v1' },
  ] satisfies Array<Record<string, unknown>>;
}

export async function seedPostgres(prisma: PrismaClient, opts: SeedOptions): Promise<SeedSummary> {
  const rng = new Rng(opts.seed);
  const now = Date.now();

  const summary: SeedSummary = { tenants: [] };

  // Compatibility: allow sensor-bridge to work with defaults from config.ts
  // SENSOR_BRIDGE_SENSOR_ID defaults to 'synapse-pingora-1'
  // SENSOR_BRIDGE_SENSOR_NAME defaults to 'Synapse Pingora WAF'
  const BRIDGE_SENSOR_ID = 'synapse-pingora-1';
  const BRIDGE_SENSOR_NAME = 'Synapse Pingora WAF';
  const BRIDGE_SENSOR_API_KEY = 'sk-sensor-bridge-dev';
  const BRIDGE_SENSOR_FINGERPRINT = sha256Hex(`${BRIDGE_SENSOR_ID}:${BRIDGE_SENSOR_API_KEY}`).slice(0, 32);
  // Compatibility: UI defaults assume this API key value exists.
  const DEFAULT_DASHBOARD_API_KEY = 'dev-dashboard-key';

  const tenantScopedIp = (tenantIndex: number): string => {
    // Enforce uniqueness across tenants to avoid Threat @@unique collisions on IP indicators.
    // 185.228.<tenant-slice>.<host>
    const c = (tenantIndex * 17 + 13) % 250;
    const d = rng.int(1, 254);
    return `185.228.${c}.${d}`;
  };

  // Global templates
  const globalConfig = { telemetry: { enabled: true }, ingest: { batchSize: 100 } };
  // Idempotent seed: allow `--wipe=false` runs without tripping unique ids.
  await prisma.configTemplate.upsert({
    where: { id: 'cfg-global-production-base' },
    update: {
      tenantId: null,
      name: 'Global: Production Base',
      description: 'Baseline config template for all tenants',
      environment: 'production',
      config: globalConfig as Prisma.InputJsonValue,
      hash: sha256Hex(JSON.stringify(globalConfig)),
      version: '1.0.0',
      isActive: true,
    },
    create: {
      id: 'cfg-global-production-base',
      tenantId: null,
      name: 'Global: Production Base',
      description: 'Baseline config template for all tenants',
      environment: 'production',
      config: globalConfig as Prisma.InputJsonValue,
      hash: sha256Hex(JSON.stringify(globalConfig)),
      version: '1.0.0',
      isActive: true,
    },
  });

  // Releases (Phase 2C)
  const release = await prisma.release.upsert({
    where: { version: '1.3.2' },
    update: {
      changelog: 'Seeded release for rollout testing.\n- Fix: heartbeat jitter\n- Perf: request routing cache',
      binaryUrl: 'https://example.invalid/synapse/1.3.2.bin',
      sha256: sha256Hex('synapse-1.3.2-binary'),
      size: 48_102_400,
      createdBy: 'seed',
    },
    create: {
      version: '1.3.2',
      changelog: 'Seeded release for rollout testing.\n- Fix: heartbeat jitter\n- Perf: request routing cache',
      binaryUrl: 'https://example.invalid/synapse/1.3.2.bin',
      sha256: sha256Hex('synapse-1.3.2-binary'),
      size: 48_102_400,
      createdBy: 'seed',
    },
  });

  for (let t = 0; t < opts.tenants; t++) {
    const preset = tenantSeedName(t);
    const slug = slugify(preset.name);
    const tenantId = `tenant-${slug}`;
    const anonymizationSalt = `salt-${sha256Hex(`${opts.seed}:${tenantId}`).slice(0, 16)}`;

    // Idempotent seed: if tenant exists and caller asked for wipe=false, skip deep seeding
    // rather than failing on unique ids. Use `db:reseed` for a full deterministic rebuild.
    if (!opts.wipe) {
      const existing = await prisma.tenant.findUnique({
        where: { id: tenantId },
        select: { id: true, name: true },
      });
      if (existing) {
        const sensorRows = await prisma.sensor.findMany({
          where: { tenantId },
          select: { id: true },
          orderBy: { id: 'asc' },
        });
        summary.tenants.push({
          tenantId: existing.id,
          tenantName: existing.name,
          adminEmail: `admin+${slug}@signal-horizon.dev`,
          adminPassword: `dev-${slug}-admin`,
          dashboardApiKey: t === 0 ? DEFAULT_DASHBOARD_API_KEY : 'existing',
          sensors: sensorRows.map((s) => s.id),
          ...(t === 0
            ? {
                sensorBridge: {
                  sensorId: BRIDGE_SENSOR_ID,
                  sensorName: BRIDGE_SENSOR_NAME,
                  apiKey: BRIDGE_SENSOR_API_KEY,
                },
              }
            : {}),
        });
        continue;
      }
    }

    const tenant = await prisma.tenant.create({
      data: {
        id: tenantId,
        name: preset.name,
        tier: preset.tier,
        sharingPreference: preset.sharing,
        anonymizationSalt,
        preferenceVersion: '1.0',
      },
    });

    // Users
    const adminPassword = `dev-${slug}-admin`;
    const adminEmail = `admin+${slug}@signal-horizon.dev`;
    const adminId = `user-${slug}-admin`;
    const operatorId = `user-${slug}-operator`;
    const viewerId = `user-${slug}-viewer`;

    const pwSalt = sha256Hex(`${opts.seed}:${tenantId}:pw`).slice(0, 32);
    const [adminHash, operatorHash, viewerHash] = await Promise.all([
      scryptHash(adminPassword, pwSalt),
      scryptHash(`dev-${slug}-operator`, pwSalt),
      scryptHash(`dev-${slug}-viewer`, pwSalt),
    ]);

    await prisma.user.createMany({
      data: [
        { id: adminId, email: adminEmail, passwordHash: adminHash, name: `${preset.name} Admin` },
        { id: operatorId, email: `operator+${slug}@signal-horizon.dev`, passwordHash: operatorHash, name: `${preset.name} Operator` },
        { id: viewerId, email: `viewer+${slug}@signal-horizon.dev`, passwordHash: viewerHash, name: `${preset.name} Viewer` },
      ],
    });

    await prisma.tenantMember.createMany({
      data: [
        { tenantId, userId: adminId, role: UserRole.ADMIN },
        { tenantId, userId: operatorId, role: UserRole.OPERATOR },
        { tenantId, userId: viewerId, role: UserRole.VIEWER },
      ],
    });

    // Consent
    await prisma.tenantConsent.create({
      data: {
        tenantId,
        consentType: 'BLOCKLIST_SHARING',
        grantedBy: adminId,
        version: '1.0',
        acknowledged: true,
        ipAddress: '127.0.0.1',
        userAgent: 'seed',
      },
    });

    // Dashboard API key (store hash; return raw to operator)
    const dashboardApiKey = t === 0 ? DEFAULT_DASHBOARD_API_KEY : `dev-dashboard-${slug}-${randomHex(rng, 8)}`;
    const dashboardKeyHash = sha256Hex(dashboardApiKey);
    const existingByHash = await prisma.apiKey.findUnique({
      where: { keyHash: dashboardKeyHash },
      select: { id: true, tenantId: true },
    });
    if (existingByHash && existingByHash.tenantId !== tenantId) {
      // Don't steal a shared key from another tenant in non-wipe runs.
      // In dev, prefer wipe=true; this is just a safety guard.
      // Fall back to a unique per-tenant key.
      const fallbackKey = `dev-dashboard-${slug}-${randomHex(rng, 8)}`;
      await prisma.apiKey.upsert({
        where: { tenantId_name: { tenantId, name: 'Development Dashboard' } },
        update: {
          keyHash: sha256Hex(fallbackKey),
          scopes: [
            'admin',
            'fleet:admin',
            'fleet:read',
            'fleet:write',
            'dashboard:read',
            'dashboard:write',
            'signal:write',
            'config:read',
            'config:write',
            'policy:read',
            'policy:write',
            'hunt:read',
            'auth-coverage:read',
            'releases:read',
            'releases:write',
            'beam:read',
            'beam:write',
          ],
          rateLimit: 25_000,
          isRevoked: false,
        },
        create: {
          tenantId,
          keyHash: sha256Hex(fallbackKey),
          name: 'Development Dashboard',
          scopes: [
            'admin',
            'fleet:admin',
            'fleet:read',
            'fleet:write',
            'dashboard:read',
            'dashboard:write',
            'signal:write',
            'config:read',
            'config:write',
            'policy:read',
            'policy:write',
            'hunt:read',
            'auth-coverage:read',
            'releases:read',
            'releases:write',
            'beam:read',
            'beam:write',
          ],
          rateLimit: 25_000,
          isRevoked: false,
        },
      });
    } else {
      await prisma.apiKey.upsert({
        where: { tenantId_name: { tenantId, name: 'Development Dashboard' } },
        update: {
          keyHash: dashboardKeyHash,
          scopes: [
            'admin',
            'fleet:admin',
            'fleet:read',
            'fleet:write',
            'dashboard:read',
            'dashboard:write',
            'signal:write',
            'config:read',
            'config:write',
            'policy:read',
            'policy:write',
            'hunt:read',
            'auth-coverage:read',
            'releases:read',
            'releases:write',
            'beam:read',
            'beam:write',
          ],
          rateLimit: 25_000,
          isRevoked: false,
        },
        create: {
          tenantId,
          keyHash: dashboardKeyHash,
          name: 'Development Dashboard',
          scopes: [
            'admin',
            'fleet:admin',
            'fleet:read',
            'fleet:write',
            'dashboard:read',
            'dashboard:write',
            'signal:write',
            'config:read',
            'config:write',
            'policy:read',
            'policy:write',
            'hunt:read',
            'auth-coverage:read',
            'releases:read',
            'releases:write',
            'beam:read',
            'beam:write',
          ],
          rateLimit: 25_000,
          isRevoked: false,
        },
      });
    }

    // Registration token
    const rawToken = `rt_${slug}_${randomHex(rng, 12)}`;
    const regToken = await prisma.registrationToken.create({
      data: {
        tenantId,
        tokenHash: sha256Hex(rawToken),
        tokenPrefix: rawToken.slice(0, 16),
        name: 'Seed Enrollment Token',
        region: rng.pick(REGIONS),
        maxUses: 50,
        expiresAt: new Date(now + 1000 * 60 * 60 * 24 * 30),
        revoked: false,
        createdBy: adminId,
        metadata: { purpose: 'seed', raw_token_hint: rawToken.slice(0, 8) } as Prisma.InputJsonValue,
      },
    });

    // Templates
    const tenantConfig = { telemetry: { enabled: true }, waf: { enabled: true }, tenant: { id: tenantId } };
    await prisma.configTemplate.create({
      data: {
        tenantId,
        name: 'Tenant: Production',
        description: 'Tenant-scoped production config',
        environment: 'production',
        config: tenantConfig as Prisma.InputJsonValue,
        hash: sha256Hex(JSON.stringify(tenantConfig)),
        version: '1.0.0',
        isActive: true,
      },
    });

    await prisma.policyTemplate.createMany({
      data: [
        {
          tenantId,
          name: 'Standard Policy',
          description: 'Balanced protection',
          severity: 'standard',
          config: buildPolicyConfig(rng, 'standard'),
          metadata: { seeded: true } as Prisma.InputJsonValue,
          isDefault: true,
          isActive: true,
          version: '1.0.0',
        },
        {
          tenantId,
          name: 'Strict Policy',
          description: 'Aggressive blocking and tighter rate limits',
          severity: 'strict',
          config: buildPolicyConfig(rng, 'strict'),
          metadata: { seeded: true } as Prisma.InputJsonValue,
          isDefault: false,
          isActive: true,
          version: '1.0.0',
        },
        {
          tenantId,
          name: 'Dev Policy',
          description: 'Observe-only profile for development',
          severity: 'dev',
          config: buildPolicyConfig(rng, 'dev'),
          metadata: { seeded: true } as Prisma.InputJsonValue,
          isDefault: false,
          isActive: true,
          version: '1.0.0',
        },
      ],
    });

    // Sensors
    const sensors: string[] = [];

    // Seed a stable bridge sensor for tenant 0 (Acme) so the sensor-bridge can auth
    // without a registration token (it matches by sensorName).
    if (t === 0) {
      const region = rng.pick(REGIONS);
      await prisma.sensor.create({
        data: {
          id: BRIDGE_SENSOR_ID,
          tenantId,
          name: BRIDGE_SENSOR_NAME,
          hostname: 'synapse-pingora',
          region,
          version: '1.0.0-bridge',
          connectionState: ConnectionState.CONNECTED,
          lastHeartbeat: new Date(now - rng.int(5_000, 60_000)),
          lastSignalAt: new Date(now - rng.int(10_000, 120_000)),
          signalsReported: rng.int(50_000, 250_000),
          blocksApplied: rng.int(500, 12_000),
          ipAddress: tenantScopedIp(t),
          publicIp: tenantScopedIp(t),
          privateIp: `10.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(2, 254)}`,
          os: rng.pick(OS_STRINGS),
          kernel: `5.15.0-${rng.int(60, 130)}-generic`,
          architecture: 'x86_64',
          instanceType: rng.pick(INSTANCE_TYPES),
          uptime: rng.int(3600, 86400 * 30),
          tunnelActive: false,
          registrationMethod: RegistrationMethod.MANUAL,
          approvalStatus: ApprovalStatus.APPROVED,
          approvedAt: new Date(now - rng.int(60_000, 86_400_000)),
          approvedBy: adminId,
          fingerprint: BRIDGE_SENSOR_FINGERPRINT,
          metadata: { tags: ['bridge', 'primary'], seeded: true } as Prisma.InputJsonValue,
        },
      });

      // Stable API key for bridge upgrades + auth message
      await prisma.sensorApiKey.create({
        data: {
          name: 'Sensor Bridge Key',
          keyHash: sha256Hex(BRIDGE_SENSOR_API_KEY),
          keyPrefix: BRIDGE_SENSOR_API_KEY.slice(0, 8),
          sensorId: BRIDGE_SENSOR_ID,
          status: 'ACTIVE',
          permissions: ['signal:write', 'blocklist:read', 'beam:write'],
          createdBy: adminId,
        },
      });

      // Basic config/sync state so fleet pages look realistic
      await prisma.sensorPingoraConfig.create({
        data: {
          sensorId: BRIDGE_SENSOR_ID,
          wafEnabled: true,
          wafThreshold: 0.5,
          wafOverrides: { 'rule-sqli-001': { enabled: true, action: 'block' } } as Prisma.InputJsonValue,
          rateLimitEnabled: true,
          rps: 120,
          burst: 60,
          allowList: ['127.0.0.1/32'],
          denyList: [],
          fullConfig: { version: 1, seeded: true } as Prisma.InputJsonValue,
          version: 1,
        },
      });

      await prisma.sensorSyncState.create({
        data: {
          sensorId: BRIDGE_SENSOR_ID,
          expectedConfigHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:cfg:expected`),
          expectedRulesHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:rules:expected`),
          expectedBlocklistHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:blocklist:expected`),
          actualConfigHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:cfg:expected`),
          actualRulesHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:rules:expected`),
          actualBlocklistHash: sha256Hex(`${tenantId}:${BRIDGE_SENSOR_ID}:blocklist:expected`),
          lastSyncAttempt: new Date(now - rng.int(60_000, 600_000)),
          lastSyncSuccess: new Date(now - rng.int(60_000, 600_000)),
          syncErrors: [],
        },
      });

      sensors.push(BRIDGE_SENSOR_ID);
    }

    for (let s = 0; s < opts.sensorsPerTenant; s++) {
      const sensorId = `sensor-${slug}-${String(s + 1).padStart(2, '0')}`;
      sensors.push(sensorId);
      const region = rng.pick(REGIONS);
      const cs =
        s === 0 ? ConnectionState.CONNECTED : s === 1 ? ConnectionState.DISCONNECTED : rng.pick([ConnectionState.CONNECTED, ConnectionState.RECONNECTING]);
      const hb = cs === ConnectionState.DISCONNECTED ? null : new Date(now - rng.int(5_000, 60_000));
      const lastSignalAt = cs === ConnectionState.DISCONNECTED ? null : new Date(now - rng.int(10_000, 120_000));

      await prisma.sensor.create({
        data: {
          id: sensorId,
          tenantId,
          name: `${slug}-sensor-${s + 1}`,
          hostname: `${slug}-host-${s + 1}`,
          region,
          version: rng.pick(SENSOR_VERSIONS),
          connectionState: cs,
          lastHeartbeat: hb,
          lastSignalAt,
          signalsReported: cs === ConnectionState.DISCONNECTED ? rng.int(0, 2000) : rng.int(12_000, 95_000),
          blocksApplied: rng.int(0, 3200),
          ipAddress: tenantScopedIp(t),
          publicIp: tenantScopedIp(t),
          privateIp: `10.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(2, 254)}`,
          os: rng.pick(OS_STRINGS),
          kernel: `5.15.0-${rng.int(60, 130)}-generic`,
          architecture: 'x86_64',
          instanceType: rng.pick(INSTANCE_TYPES),
          uptime: rng.int(3600, 86400 * 30),
          tunnelActive: rng.bool(0.08),
          registrationMethod: s === 0 ? RegistrationMethod.MANUAL : RegistrationMethod.TOKEN,
          registrationTokenId: s === 0 ? null : regToken.id,
          approvalStatus: ApprovalStatus.APPROVED,
          approvedAt: new Date(now - rng.int(60_000, 86_400_000)),
          approvedBy: adminId,
          fingerprint: sha256Hex(`${tenantId}:${sensorId}`).slice(0, 32),
          metadata: { tags: s === 0 ? ['primary'] : ['edge'], seeded: true } as Prisma.InputJsonValue,
        },
      });

      // Per-sensor API key
      const sk = `sk_${slug}_${sensorId}_${randomHex(rng, 10)}`;
      await prisma.sensorApiKey.create({
        data: {
          name: 'Seed Sensor Key',
          keyHash: sha256Hex(sk),
          keyPrefix: sk.slice(0, 8),
          sensorId,
          status: 'ACTIVE',
          permissions: ['signal:write', 'blocklist:read', 'beam:write'],
          createdBy: adminId,
        },
      });

      // Pingora config
      await prisma.sensorPingoraConfig.create({
        data: {
          sensorId,
          wafEnabled: true,
          wafThreshold: clamp(0.35 + rng.float() * 0.3, 0.2, 0.95),
          wafOverrides: { 'rule-sqli-001': { enabled: true, action: 'block' } } as Prisma.InputJsonValue,
          rateLimitEnabled: true,
          rps: rng.int(60, 180),
          burst: rng.int(20, 100),
          allowList: ['127.0.0.1/32'],
          denyList: [],
          fullConfig: { version: 1, seeded: true } as Prisma.InputJsonValue,
          version: 1,
        },
      });

      // Sync state
      const expectedConfigHash = sha256Hex(`${tenantId}:${sensorId}:cfg:expected`);
      const expectedRulesHash = sha256Hex(`${tenantId}:${sensorId}:rules:expected`);
      const expectedBlocklistHash = sha256Hex(`${tenantId}:${sensorId}:blocklist:expected`);
      const isInSync = cs === ConnectionState.CONNECTED && rng.bool(0.7);
      await prisma.sensorSyncState.create({
        data: {
          sensorId,
          expectedConfigHash,
          expectedRulesHash,
          expectedBlocklistHash,
          actualConfigHash: isInSync ? expectedConfigHash : sha256Hex(`${tenantId}:${sensorId}:cfg:actual`),
          actualRulesHash: isInSync ? expectedRulesHash : sha256Hex(`${tenantId}:${sensorId}:rules:actual`),
          actualBlocklistHash: isInSync ? expectedBlocklistHash : sha256Hex(`${tenantId}:${sensorId}:blocklist:actual`),
          lastSyncAttempt: new Date(now - rng.int(60_000, 600_000)),
          lastSyncSuccess: isInSync ? new Date(now - rng.int(60_000, 600_000)) : null,
          syncErrors: isInSync ? [] : ['hash_mismatch:rules'],
        },
      });

      // Commands
      const cmdTypes = ['push_config', 'push_rules', 'restart', 'update'] as const;
      for (let c = 0; c < rng.int(2, 6); c++) {
        const queuedAt = new Date(now - rng.int(60_000, 7 * 86_400_000));
        const status = rng.pick(['pending', 'sent', 'success', 'failed']);
        const sentAt = status === 'pending' ? null : new Date(queuedAt.getTime() + rng.int(5_000, 60_000));
        const completedAt = status === 'success' || status === 'failed' ? new Date((sentAt ?? queuedAt).getTime() + rng.int(5_000, 90_000)) : null;
        await prisma.fleetCommand.create({
          data: {
            sensorId,
            commandType: rng.pick(cmdTypes),
            payload: { seeded: true, nonce: randomHex(rng, 4) } as Prisma.InputJsonValue,
            status,
            result: status === 'success' ? ({ ok: true } as Prisma.InputJsonValue) : null,
            error: status === 'failed' ? 'remote_error:timeout' : null,
            queuedAt,
            sentAt,
            completedAt,
            attempts: status === 'failed' ? rng.int(1, 3) : rng.int(0, 2),
            timeoutAt: new Date(queuedAt.getTime() + 120_000),
          },
        });
      }

      // Alerts
      if (cs === ConnectionState.DISCONNECTED) {
        await prisma.fleetAlert.create({
          data: {
            tenantId,
            sensorId,
            alertType: 'sensor_offline',
            severity: 'critical',
            title: 'Sensor Offline',
            message: `Sensor ${sensorId} missed heartbeats.`,
            metadata: { region, seeded: true } as Prisma.InputJsonValue,
            acknowledged: rng.bool(0.3),
          },
        });
      } else if (rng.bool(0.18)) {
        await prisma.fleetAlert.create({
          data: {
            tenantId,
            sensorId,
            alertType: 'high_cpu',
            severity: 'warning',
            title: 'High CPU Usage',
            message: `Sensor ${sensorId} CPU sustained at ${rng.int(80, 97)}%.`,
            metadata: { cpu: rng.int(80, 97), seeded: true } as Prisma.InputJsonValue,
          },
        });
      }
    }

    // Scheduled deployment (restart recovery)
    await prisma.scheduledDeployment.create({
      data: {
        tenantId,
        sensorIds: sensors.slice(0, Math.min(5, sensors.length)),
        rules: [{ id: 'rule-sqli-001', action: 'block' }] as unknown as Prisma.InputJsonValue,
        scheduledAt: new Date(now + rng.int(10_000, 120_000)),
        status: 'PENDING',
      },
    });

    // Rule sync state (fleet UI)
    for (const sensorId of sensors.slice(0, Math.min(12, sensors.length))) {
      for (const ruleId of ['rule-sqli-001', 'rule-xss-001', 'rule-rate-001']) {
        await prisma.ruleSyncState.upsert({
          where: { sensorId_ruleId: { sensorId, ruleId } },
          update: {},
          create: {
            sensorId,
            ruleId,
            status: rng.pick(['pending', 'synced', 'failed']),
            syncedAt: rng.bool(0.7) ? new Date(now - rng.int(60_000, 3 * 3600_000)) : null,
            error: rng.bool(0.15) ? 'seed:sync_failed' : null,
          },
        });
      }
    }

    // Diagnostic + update history for one sensor
    if (sensors[0]) {
      await prisma.diagnosticBundle.create({
        data: {
          sensorId: sensors[0],
          status: rng.pick(['pending', 'completed']),
          includes: ['waf', 'syslog', 'config'],
          downloadUrl: null,
          expiresAt: new Date(now + 7 * 86_400_000),
          notes: 'Seeded diagnostic bundle',
        },
      });

      await prisma.sensorUpdate.create({
        data: {
          sensorId: sensors[0],
          fromVersion: '1.2.4',
          toVersion: '1.3.2',
          status: rng.pick(['scheduled', 'in_progress', 'completed']),
          scheduledFor: new Date(now + rng.int(60_000, 6 * 3600_000)),
          rollbackAvailable: true,
          logs: 'seed: update prepared',
        },
      });

      await prisma.tunnelSession.create({
        data: {
          sensorId: sensors[0],
          tenantId,
          userId: adminId,
          type: 'shell',
          status: rng.pick(['pending', 'connected', 'disconnected']),
          lastActivity: new Date(now - rng.int(10_000, 300_000)),
          expiresAt: new Date(now + 30 * 60_000),
        },
      });

      const dlpPatterns = [
        { name: 'Visa Card', type: 'credit_card', severity: 'critical', masked: '****-****-****-4242' },
        { name: 'SSN (formatted)', type: 'ssn', severity: 'critical', masked: '***-**-6789' },
        { name: 'AWS Secret Key', type: 'aws_key', severity: 'critical', masked: 'AKIA****************' },
        { name: 'GitHub Token', type: 'api_key', severity: 'critical', masked: 'ghp_************************' },
        { name: 'Email Address', type: 'email', severity: 'medium', masked: 'u***@example.com' },
      ] as const;
      const dlpPaths = [
        '/api/v1/users/profile',
        '/api/v1/payments/checkout',
        '/api/v1/admin/audit-export',
        '/api/v1/auth/login',
        '/api/v1/debug/dump',
      ] as const;

      // Seed per-sensor payload stats so Fleet Health can render CPU/memory/RPS/latency.
      for (let i = 0; i < sensors.length; i++) {
        const sensorId = sensors[i]!;
        const cpu = clamp(10 + rng.float() * 85, 0, 100);
        const memory = clamp(18 + rng.float() * 80, 0, 100);
        const rps = Math.round(clamp(20 + rng.float() * 1200, 0, 5000));
        const latencyMs = Math.round(clamp(8 + rng.float() * 180, 1, 2000));

        const stats: Record<string, unknown> = {
          cpu,
          memory,
          rps,
          latencyMs,
          seeded: true,
        };

        // Only the stable bridge sensor (tenant 0) gets DLP violations for the DLP dashboard.
        if (t === 0 && sensorId === BRIDGE_SENSOR_ID) {
          const totalScans = rng.int(25_000, 900_000);
          const totalMatches = rng.int(18, 240);
          const violationsCount = Math.min(20, Math.max(0, Math.min(totalMatches, rng.int(8, 18))));

          const violations = Array.from({ length: violationsCount }, (_v, j) => {
            const p = rng.pick(dlpPatterns);
            return {
              timestamp: now - j * 5 * 60_000 - rng.int(0, 60_000),
              pattern_name: p.name,
              data_type: p.type,
              severity: p.severity,
              masked_value: p.masked,
              client_ip: tenantScopedIp(t),
              path: rng.pick(dlpPaths),
            };
          });

          stats.dlp = {
            totalScans,
            totalMatches,
            patternCount: 25,
            violations,
          };
        }

        await prisma.sensorPayloadSnapshot.create({
          data: {
            tenantId,
            sensorId,
            capturedAt: new Date(now - rng.int(10_000, 120_000) - i * 1_000),
            stats: stats as Prisma.InputJsonValue,
            bandwidth: { in_mbps: rng.int(10, 900), out_mbps: rng.int(10, 900) } as Prisma.InputJsonValue,
            endpoints: { discovered: opts.endpointsPerSensor } as Prisma.InputJsonValue,
            anomalies: { impossible_travel: rng.int(0, 4) } as Prisma.InputJsonValue,
          },
        });
      }
    }

    // Beam endpoints + schema changes
    const endpointsBySensor = new Map<
      string,
      Array<{ method: string; path: string; pathTemplate: string; service: string; hasSchema: boolean }>
    >();
    for (const sensorId of sensors) {
      const chosen = [...ENDPOINT_PATHS];
      rng.shuffleInPlace(chosen);
      const epCount = Math.min(opts.endpointsPerSensor, chosen.length);
      for (let e = 0; e < epCount; e++) {
        const method = rng.pick(ENDPOINT_METHODS);
        const pathTemplate = chosen[e];
        const svc = pathTemplate.includes('/admin') ? 'admin-service' : pathTemplate.includes('/auth') ? 'auth-service' : 'api-gateway';
        const hasSchema = rng.bool(0.7);
        const firstSeenAt = new Date(now - rng.int(0, opts.recentDays * 86_400_000));
        const lastSeenAt = new Date(
          clamp(firstSeenAt.getTime() + rng.int(30_000, opts.recentDays * 86_400_000), firstSeenAt.getTime(), now)
        );
        const requestSchema = hasSchema
          ? ({
              type: 'object',
              properties: { example: { type: 'string' } },
              required: ['example'],
            } as Prisma.InputJsonValue)
          : null;
        const responseSchema = hasSchema
          ? ({
              type: 'object',
              properties: { ok: { type: 'boolean' } },
            } as Prisma.InputJsonValue)
          : null;

        const schemaHash = hasSchema ? sha256Hex(JSON.stringify({ requestSchema, responseSchema })) : null;
        const path = pathTemplate.replace('{id}', String(rng.int(1, 9999)));

        const ep = await prisma.endpoint.create({
          data: {
            tenantId,
            sensorId,
            method,
            path,
            pathTemplate,
            service: svc,
            firstSeenAt,
            lastSeenAt,
            requestCount: rng.int(1000, 250_000),
            hasSchema,
            schemaVersion: hasSchema ? `v${rng.int(1, 6)}` : null,
            schemaHash,
            requestSchema: requestSchema ?? undefined,
            responseSchema: responseSchema ?? undefined,
            avgLatencyMs: clamp(15 + rng.float() * 220, 5, 600),
            p95LatencyMs: clamp(40 + rng.float() * 450, 10, 1600),
            p99LatencyMs: clamp(70 + rng.float() * 800, 20, 3000),
            errorRate: clamp(rng.float() * 0.06, 0, 0.25),
            riskLevel: pathTemplate.includes('/admin') ? 'high' : pathTemplate.includes('/billing') ? 'critical' : rng.pick(['low', 'medium']),
            authRequired: !pathTemplate.startsWith('/internal') && rng.bool(0.85),
            sensitiveData: pathTemplate.includes('/billing') || pathTemplate.includes('/users/'),
            metadata: { seeded: true } as Prisma.InputJsonValue,
          },
        });

        const arr = endpointsBySensor.get(sensorId) ?? [];
        arr.push({ method, path, pathTemplate, service: svc, hasSchema });
        endpointsBySensor.set(sensorId, arr);

        if (hasSchema && rng.bool(0.25)) {
          await prisma.endpointSchemaChange.create({
            data: {
              tenantId,
              endpointId: ep.id,
              changeType: 'field_added',
              field: 'client.version',
              oldValue: null,
              newValue: 'string',
              riskLevel: rng.pick(['low', 'medium', 'high']),
              previousHash: schemaHash,
              currentHash: sha256Hex(`${schemaHash}:change:${randomHex(rng, 4)}`),
              detectedAt: new Date(now - rng.int(60_000, 12 * 3600_000)),
            },
          });
        }
      }
    }

    // Rules + deployments + bindings
    const sensorTargets = sensors.slice();
    for (let r = 0; r < opts.rulesPerTenant; r++) {
      const ruleName = r === 0 ? 'SQLi Protection' : r === 1 ? 'Credential Stuffing' : `Custom Rule ${r + 1}`;
      const rule = await prisma.customerRule.create({
        data: {
          tenantId,
          name: ruleName,
          description: 'Seeded rule for API protection testing',
          category: r < 2 ? 'security' : 'custom',
          severity: r === 0 ? 'high' : r === 1 ? 'critical' : rng.pick(['low', 'medium', 'high']),
          action: r === 1 ? 'challenge' : 'block',
          patterns:
            r === 0
              ? ({ kind: 'regex', field: 'body', value: '(?i)(union select|sleep\\()' } as Prisma.InputJsonValue)
              : ({ kind: 'rate', field: 'ip', threshold: rng.int(30, 120), windowSec: 60 } as Prisma.InputJsonValue),
          exclusions: { ips: ['127.0.0.1'] } as Prisma.InputJsonValue,
          sensitivity: rng.int(25, 85),
          enabled: rng.bool(0.9),
          status: rng.pick(['draft', 'deployed', 'deployed', 'deployed', 'failed']),
          rolloutStrategy: rng.pick(['immediate', 'canary', 'rolling']),
          rolloutConfig: { batchSize: rng.int(3, 10), delaySec: rng.int(10, 120) } as Prisma.InputJsonValue,
          totalSensors: sensors.length,
          deployedSensors: rng.int(0, sensors.length),
          failedSensors: rng.int(0, Math.max(1, Math.floor(sensors.length * 0.2))),
          triggers24h: rng.int(0, 2200),
          lastTriggered: rng.bool(0.7) ? new Date(now - rng.int(60_000, 86_400_000)) : null,
          deployedAt: rng.bool(0.7) ? new Date(now - rng.int(60_000, 14 * 86_400_000)) : null,
          createdBy: adminId,
        },
      });

      // Deployments
      rng.shuffleInPlace(sensorTargets);
      const targetCount = rng.int(Math.max(1, Math.floor(sensors.length * 0.4)), sensors.length);
      for (let i = 0; i < targetCount; i++) {
        const sensorId = sensorTargets[i];
        const status = rng.pick(['pending', 'running', 'success', 'failed']);
        const queuedAt = new Date(now - rng.int(60_000, 7 * 86_400_000));
        const startedAt = status === 'pending' ? null : new Date(queuedAt.getTime() + rng.int(2_000, 40_000));
        const completedAt = status === 'success' || status === 'failed' ? new Date((startedAt ?? queuedAt).getTime() + rng.int(3_000, 60_000)) : null;
        await prisma.ruleDeployment.create({
          data: {
            ruleId: rule.id,
            tenantId,
            sensorId,
            status,
            error: status === 'failed' ? 'deploy_error:agent_unreachable' : null,
            attempts: status === 'failed' ? rng.int(1, 4) : rng.int(0, 2),
            queuedAt,
            startedAt,
            completedAt,
          },
        });
      }

      // Bind to a few endpoints (include)
      const eps = await prisma.endpoint.findMany({ where: { tenantId }, take: 10, orderBy: { lastSeenAt: 'desc' } });
      for (const ep of eps.slice(0, rng.int(2, Math.min(6, eps.length)))) {
        await prisma.ruleEndpointBinding.create({
          data: {
            tenantId,
            ruleId: rule.id,
            endpointId: ep.id,
            bindingType: 'include',
          },
        });
      }
    }

    // War room + playbooks
    const warRoom = await prisma.warRoom.create({
      data: {
        tenantId,
        name: 'Incident: Credential Stuffing',
        description: 'Seeded incident workspace',
        status: WarRoomStatus.ACTIVE,
        priority: Priority.HIGH,
        leaderId: adminId,
      },
    });

    const playbook = await prisma.playbook.create({
      data: {
        tenantId,
        name: 'Credential Stuffing Response',
        description: 'Seeded playbook',
        triggerType: 'SIGNAL_TYPE',
        triggerValue: String(SignalType.CREDENTIAL_STUFFING),
        isActive: true,
        steps: playbookSteps(rng),
      },
    });

    await prisma.playbookRun.create({
      data: {
        tenantId,
        warRoomId: warRoom.id,
        playbookId: playbook.id,
        status: rng.pick(['RUNNING', 'COMPLETED']),
        currentStep: rng.int(0, 3),
        stepResults: [{ step: 0, ok: true }] as unknown as Prisma.InputJsonValue,
        startedAt: new Date(now - rng.int(60_000, 6 * 3600_000)),
        completedAt: rng.bool(0.6) ? new Date(now - rng.int(10_000, 60_000)) : null,
        startedBy: adminId,
      },
    });

    await prisma.warRoomActivity.createMany({
      data: [
        {
          tenantId,
          warRoomId: warRoom.id,
          actorType: 'USER',
          actorId: adminId,
          actorName: `${preset.name} Admin`,
          actionType: 'MESSAGE',
          description: 'Investigating elevated 401/403 rates on /api/v1/auth/login',
          metadata: { seeded: true } as Prisma.InputJsonValue,
        },
        {
          tenantId,
          warRoomId: warRoom.id,
          actorType: 'HORIZON_BOT',
          actorId: 'horizon-bot',
          actorName: 'Horizon Bot',
          actionType: 'ALERT_TRIGGERED',
          description: 'Correlation indicates multi-region credential stuffing pattern',
          metadata: { confidence: 0.92 } as Prisma.InputJsonValue,
        },
      ],
    });

    // Signals + threats + campaigns
    const signals: Prisma.SignalCreateManyInput[] = [];
    const types = [
      SignalType.IP_THREAT,
      SignalType.BOT_SIGNATURE,
      SignalType.CREDENTIAL_STUFFING,
      SignalType.RATE_ANOMALY,
      SignalType.SCHEMA_VIOLATION,
      SignalType.IMPOSSIBLE_TRAVEL,
      SignalType.TEMPLATE_DISCOVERY,
      SignalType.FINGERPRINT_THREAT,
    ] as const;
    for (const sensorId of sensors) {
      const seededEndpoints = endpointsBySensor.get(sensorId) ?? [];
      for (let i = 0; i < opts.signalsPerSensor; i++) {
        // Bias toward API intelligence so dashboards aren't empty in seeded/dev environments.
        const type = rng.bool(0.35)
          ? rng.pick([SignalType.SCHEMA_VIOLATION, SignalType.TEMPLATE_DISCOVERY] as const)
          : rng.pick(types);
        const fp = `fp_${sha256Hex(`${tenantId}:${sensorId}:${i}`).slice(0, 16)}`;
        const anonFp = sha256Hex(`${fp}:${anonymizationSalt}`);
        const ts = new Date(now - rng.int(0, opts.recentDays * 86_400_000));
        const sourceIp = tenantScopedIp(t);
        const confidence = clamp(0.55 + rng.float() * 0.45, 0, 1);
        const sev = signalSeverityForType(type);

        // API Intelligence pages query these keys specifically (`metadata.endpoint`, `metadata.method`, etc).
        const pickedEndpoint = seededEndpoints.length > 0 ? rng.pick(seededEndpoints) : null;
        const endpoint = pickedEndpoint?.pathTemplate ?? rng.pick(ENDPOINT_PATHS);
        const method = pickedEndpoint?.method ?? rng.pick(ENDPOINT_METHODS);
        const baseMeta: Record<string, unknown> = {
          endpoint,
          method,
          // Keep legacy key used elsewhere in seed/demo payloads.
          path: endpoint,
          user_agent: rng.pick(['python-requests/2.31.0', 'curl/8.6.0', 'Mozilla/5.0', 'okhttp/4.12.0']),
          ja3: `ja3:${sha256Hex(`${fp}:ja3`).slice(0, 32)}`,
          request_id: `req_${randomHex(rng, 8)}`,
        };

        if (type === SignalType.TEMPLATE_DISCOVERY) {
          baseMeta.templatePattern = pickedEndpoint?.pathTemplate ?? endpoint;
          baseMeta.discoveryConfidence = clamp(0.6 + rng.float() * 0.4, 0, 1);
          baseMeta.parameterTypes = String(baseMeta.templatePattern).includes('{id}')
            ? ({ id: rng.pick(['uuid', 'int', 'string']) } as Record<string, string>)
            : {};
        }

        if (type === SignalType.SCHEMA_VIOLATION) {
          const violationType = rng.pick(API_INTELLIGENCE_VIOLATION_TYPES);
          baseMeta.violationType = violationType;
          baseMeta.violationPath = rng.pick([
            '$.body.example',
            '$.query.limit',
            '$.headers.x-client-id',
            '$.body.items[0].price',
          ]);
          baseMeta.violationMessage = violationMessageForType(violationType);
        }
        signals.push({
          tenantId,
          sensorId,
          signalType: type,
          sourceIp,
          fingerprint: fp,
          anonFingerprint: anonFp,
          severity: sev,
          confidence,
          eventCount: rng.int(1, 120),
          createdAt: ts,
          metadata: baseMeta as Prisma.InputJsonValue,
        });
      }
    }
    await prisma.signal.createMany({ data: signals });

    // Build threats from a sample of signals
    const recentSignals = await prisma.signal.findMany({
      where: { tenantId },
      select: { id: true, sourceIp: true, anonFingerprint: true, fingerprint: true, createdAt: true },
      take: Math.min(2500, sensors.length * 600),
      orderBy: { createdAt: 'desc' },
    });

    const ipIndicators = new Map<string, string[]>(); // indicator -> signalIds
    const fpIndicators = new Map<string, string[]>();
    for (const s of recentSignals) {
      if (s.sourceIp) {
        const arr = ipIndicators.get(s.sourceIp) ?? [];
        arr.push(s.id);
        ipIndicators.set(s.sourceIp, arr);
      }
      if (s.fingerprint) {
        const arr = fpIndicators.get(s.fingerprint) ?? [];
        arr.push(s.id);
        fpIndicators.set(s.fingerprint, arr);
      }
    }

    const ipThreats = [...ipIndicators.entries()].slice(0, 40);
    const fpThreats = [...fpIndicators.entries()].slice(0, 25);
    for (const [ip, sigIds] of ipThreats) {
      await prisma.threat.upsert({
        where: { threatType_indicator: { threatType: ThreatType.IP, indicator: ip } },
        update: {},
        create: {
          tenantId,
          threatType: ThreatType.IP,
          indicator: ip,
          anonIndicator: sha256Hex(`${ip}:${anonymizationSalt}`),
          riskScore: clamp(55 + rng.float() * 45, 0, 100),
          fleetRiskScore: null,
          firstSeenAt: new Date(now - opts.recentDays * 86_400_000),
          lastSeenAt: new Date(now - rng.int(0, 6 * 3600_000)),
          hitCount: sigIds.length,
          tenantsAffected: 1,
          isFleetThreat: false,
          metadata: { asn: `AS${rng.int(1000, 65000)}`, country: rng.pick(['US', 'NL', 'DE', 'BR', 'SG', 'GB']) } as Prisma.InputJsonValue,
        },
      });
    }
    for (const [fp, sigIds] of fpThreats) {
      await prisma.threat.upsert({
        where: { threatType_indicator: { threatType: ThreatType.FINGERPRINT, indicator: fp } },
        update: {},
        create: {
          tenantId,
          threatType: ThreatType.FINGERPRINT,
          indicator: fp,
          anonIndicator: sha256Hex(`${fp}:${anonymizationSalt}`),
          riskScore: clamp(45 + rng.float() * 50, 0, 100),
          fleetRiskScore: null,
          firstSeenAt: new Date(now - opts.recentDays * 86_400_000),
          lastSeenAt: new Date(now - rng.int(0, 6 * 3600_000)),
          hitCount: sigIds.length,
          tenantsAffected: 1,
          isFleetThreat: false,
          metadata: { family: rng.pick(['headless-chrome', 'automation', 'unknown']), note: 'seeded' } as Prisma.InputJsonValue,
        },
      });
    }

    // Link threats to signals (junction)
    const threats = await prisma.threat.findMany({ where: { tenantId }, take: 60, orderBy: { riskScore: 'desc' } });
    for (const threat of threats) {
      const sigIds = threat.threatType === ThreatType.IP ? ipIndicators.get(threat.indicator) : fpIndicators.get(threat.indicator);
      if (!sigIds || sigIds.length === 0) continue;
      const pick = sigIds.slice(0, Math.min(sigIds.length, 20));
      for (const sid of pick) {
        await prisma.threatSignal.upsert({
          where: { threatId_signalId: { threatId: threat.id, signalId: sid } },
          update: {},
          create: { threatId: threat.id, signalId: sid },
        });
      }
    }

    // Blocklist entries for top threats
    for (const threat of threats.slice(0, 10)) {
      const indicator =
        threat.threatType === ThreatType.IP
          ? threat.indicator
          : threat.threatType === ThreatType.FINGERPRINT
            ? threat.indicator
            : threat.indicator;
      const blockType = threat.threatType === ThreatType.IP ? BlockType.IP : BlockType.FINGERPRINT;
      await prisma.blocklistEntry.upsert({
        where: { blockType_indicator_tenantId: { blockType, indicator, tenantId } },
        update: {},
        create: {
          tenantId,
          threatId: threat.id,
          blockType,
          indicator,
          source: rng.pick([BlockSource.AUTOMATIC, BlockSource.MANUAL, BlockSource.WAR_ROOM]),
          reason: 'Seeded block based on elevated risk score',
          expiresAt: rng.bool(0.5) ? new Date(now + rng.int(1, 14) * 86_400_000) : null,
          propagationStatus: rng.pick([PropagationStatus.PENDING, PropagationStatus.IN_PROGRESS, PropagationStatus.COMPLETED]),
          sensorsNotified: rng.int(0, sensors.length),
        },
      });
    }

    // Campaign
    const campaign = await prisma.campaign.create({
      data: {
        tenantId,
        name: 'Operation Dark Phoenix',
        description: 'Coordinated credential stuffing campaign targeting authentication endpoints.',
        status: CampaignStatus.ACTIVE,
        severity: Severity.CRITICAL,
        isCrossTenant: preset.sharing === SharingPreference.CONTRIBUTE_AND_RECEIVE && rng.bool(0.4),
        tenantsAffected: rng.int(1, 4),
        confidence: clamp(0.75 + rng.float() * 0.24, 0, 1),
        correlationSignals: { ja3_match: 0.95, endpoint: '/api/v1/auth/login' } as Prisma.InputJsonValue,
        firstSeenAt: new Date(now - rng.int(6 * 3600_000, 4 * 86_400_000)),
        lastActivityAt: new Date(now - rng.int(60_000, 3 * 3600_000)),
        metadata: { seeded: true } as Prisma.InputJsonValue,
      },
    });
    for (const threat of threats.slice(0, 8)) {
      await prisma.campaignThreat.create({
        data: {
          campaignId: campaign.id,
          threatId: threat.id,
          role: rng.pick(['primary_actor', 'infrastructure', 'botnet']),
        },
      });
    }
    await prisma.warRoomCampaign.create({
      data: { warRoomId: warRoom.id, campaignId: campaign.id, linkedBy: adminId },
    });

    // Beam block decisions (decisions stream)
    const topEndpoints = await prisma.endpoint.findMany({ where: { tenantId }, take: 12, orderBy: { requestCount: 'desc' } });
    for (let b = 0; b < 20; b++) {
      const sensorId = rng.pick(sensors);
      const ep = rng.pick(topEndpoints);
      const blockId = `block_${randomHex(rng, 12)}`;
      await prisma.blockDecision.create({
        data: {
          tenantId,
          sensorId,
          blockId,
          entityId: `actor_${randomHex(rng, 6)}`,
          sourceIp: tenantScopedIp(t),
          mode: rng.pick(['BLOCK', 'CHALLENGE', 'LOG']),
          ruleId: null,
          ruleName: rng.pick(['SQLi Protection', 'Credential Stuffing', 'Schema Violation']),
          reason: 'Seeded enforcement decision',
          riskScore: rng.int(60, 99),
          requestMethod: ep.method,
          requestPath: ep.pathTemplate,
          requestHeaders: { 'user-agent': 'seed', 'x-request-id': `req_${randomHex(rng, 8)}` } as Prisma.InputJsonValue,
          entityState: { total_requests: rng.int(50, 4000), violations: rng.int(1, 90) } as Prisma.InputJsonValue,
          matchedRules: ['rule-sqli-001', 'rule-rate-001'] as unknown as Prisma.InputJsonValue,
          decidedAt: new Date(now - rng.int(60_000, 3 * 86_400_000)),
        },
      });
    }

    // Intel snapshots (SOC widgets)
    for (let i = 0; i < 20; i++) {
      const actorId = `actor-${slug}-${1000 + i}`;
      const firstSeenAt = new Date(now - rng.int(2 * 86_400_000, 30 * 86_400_000));
      const lastSeenAt = new Date(now - rng.int(10_000, 6 * 3600_000));
      const ips = [randomIp(rng), randomIp(rng)];
      const fingerprints = [`ja3:${sha256Hex(`${actorId}:ja3`).slice(0, 32)}`, `ua:${sha256Hex(`${actorId}:ua`).slice(0, 20)}`];
      const sessionIds = [`sess_${randomHex(rng, 6)}`, `sess_${randomHex(rng, 6)}`];
      const riskScore = clamp(35 + rng.float() * 65, 0, 100);
      await prisma.sensorIntelActor.create({
        data: {
          tenantId,
          sensorId: sensors[0] ?? `sensor-${slug}-01`,
          actorId,
          riskScore,
          isBlocked: riskScore > 88,
          firstSeenAt,
          lastSeenAt,
          ips: ips as unknown as Prisma.InputJsonValue,
          fingerprints: fingerprints as unknown as Prisma.InputJsonValue,
          sessionIds: sessionIds as unknown as Prisma.InputJsonValue,
          raw: { actorId, riskScore, ips, fingerprints, sessionIds, seeded: true } as Prisma.InputJsonValue,
        },
      });
    }

    for (let i = 0; i < 30; i++) {
      const sessionId = `sess-${slug}-${100 + i}`;
      const isSuspicious = i % 6 === 0;
      // Ensure a handful of sessions are "active" (lastActivity within 30m) so KPI cards aren't all zero.
      const lastActivitySkewMs = i < 6
        ? rng.int(10_000, 20 * 60_000)
        : rng.int(10_000, 4 * 3600_000);
      await prisma.sensorIntelSession.create({
        data: {
          tenantId,
          sensorId: sensors[0] ?? `sensor-${slug}-01`,
          sessionId,
          actorId: isSuspicious ? `actor-${slug}-1000` : null,
          requestCount: rng.int(25, 2400),
          isSuspicious,
          lastActivityAt: new Date(now - lastActivitySkewMs),
          boundIp: tenantScopedIp(t),
          boundJa4: `ja4:${sha256Hex(`${sessionId}:ja4`).slice(0, 24)}`,
          hijackAlerts: isSuspicious ? ([{ type: 'ip_drift', confidence: 0.88, ts: now - 120_000 }] as unknown as Prisma.InputJsonValue) : null,
          raw: { sessionId, isSuspicious, seeded: true } as Prisma.InputJsonValue,
        },
      });
    }

    await prisma.sensorIntelCampaign.create({
      data: {
        tenantId,
        sensorId: sensors[0] ?? `sensor-${slug}-01`,
        campaignId: `cmp-${slug}-credstuff`,
        status: 'ACTIVE',
        riskScore: 92.5,
        confidence: 0.88,
        actorCount: 15,
        attackTypes: ['credential_stuffing', 'brute_force'] as unknown as Prisma.InputJsonValue,
        firstSeenAt: new Date(now - 12 * 3600_000),
        lastActivityAt: new Date(now - 7 * 60_000),
        raw: { name: 'Credential Cascade', seeded: true } as Prisma.InputJsonValue,
      },
    });

    // Audit logs
    const actions = ['USER_LOGIN', 'RULE_CREATED', 'CONFIG_UPDATED', 'SENSOR_RESTART', 'EXPORT_REPORT'] as const;
    const logs: Prisma.AuditLogCreateManyInput[] = [];
    for (let i = 0; i < 80; i++) {
      logs.push({
        tenantId,
        userId: rng.pick([adminId, operatorId, viewerId]),
        action: rng.pick(actions),
        resource: rng.pick(['sensor', 'rule', 'campaign', 'blocklist']),
        resourceId: rng.bool(0.7) ? rng.pick(sensors) : null,
        details: { seeded: true, ip: '127.0.0.1' } as Prisma.InputJsonValue,
        ipAddress: '127.0.0.1',
        userAgent: 'seed',
        createdAt: new Date(now - rng.int(0, 14 * 86_400_000)),
      });
    }
    await prisma.auditLog.createMany({ data: logs });

    await prisma.securityAuditLog.createMany({
      data: [
        {
          action: 'PLAYBOOK_CREATED',
          resourceType: 'playbook',
          resourceId: playbook.id,
          userId: adminId,
          tenantId,
          ipAddress: '127.0.0.1',
          userAgent: 'seed',
          result: 'SUCCESS',
          details: JSON.stringify({ seeded: true }),
        },
        {
          action: 'SENSOR_COMMAND',
          resourceType: 'sensor_command',
          resourceId: 'fleet_command',
          userId: operatorId,
          tenantId,
          ipAddress: '127.0.0.1',
          userAgent: 'seed',
          result: 'SUCCESS',
          details: JSON.stringify({ seeded: true }),
        },
      ],
    });

    // Rollout (one per tenant, to populate progress table)
    const rollout = await prisma.rollout.create({
      data: {
        releaseId: release.id,
        strategy: rng.pick(['canary', 'rolling']),
        status: rng.pick(['pending', 'in_progress', 'completed']),
        targetTags: ['primary', 'edge'],
        batchSize: rng.int(5, 12),
        batchDelay: rng.int(30, 120),
        startedAt: rng.bool(0.7) ? new Date(now - rng.int(60_000, 5 * 86_400_000)) : null,
        completedAt: null,
      },
    });
    for (const sensorId of sensors.slice(0, Math.min(12, sensors.length))) {
      await prisma.rolloutProgress.create({
        data: {
          rolloutId: rollout.id,
          sensorId,
          status: rng.pick(['pending', 'downloading', 'ready', 'activated', 'failed']),
          error: rng.bool(0.1) ? 'seed:download_failed' : null,
        },
      });
    }

    summary.tenants.push({
      tenantId: tenant.id,
      tenantName: tenant.name,
      adminEmail,
      adminPassword,
      dashboardApiKey,
      sensors,
      ...(t === 0
        ? {
            sensorBridge: {
              sensorId: BRIDGE_SENSOR_ID,
              sensorName: BRIDGE_SENSOR_NAME,
              apiKey: BRIDGE_SENSOR_API_KEY,
            },
          }
        : {}),
    });
  }

  // Fleet-wide threats + campaigns to exercise cross-tenant views
  const fleetIps = ['203.0.113.10', '203.0.113.11', '203.0.113.12', '198.51.100.20'];
  for (const ip of fleetIps) {
    await prisma.threat.upsert({
      where: { threatType_indicator: { threatType: ThreatType.IP, indicator: ip } },
      update: { isFleetThreat: true, fleetRiskScore: 92.0 },
      create: {
        tenantId: null,
        threatType: ThreatType.IP,
        indicator: ip,
        anonIndicator: sha256Hex(`fleet:${ip}`),
        riskScore: 92.0,
        fleetRiskScore: 92.0,
        firstSeenAt: new Date(now - 30 * 86_400_000),
        lastSeenAt: new Date(now - 2 * 3600_000),
        hitCount: 120_000,
        tenantsAffected: clamp(2 + Math.floor(rng.float() * 8), 2, 25),
        isFleetThreat: true,
        metadata: { feed: 'seed', country: 'US', asn: 'AS15169' } as Prisma.InputJsonValue,
      },
    });
    // Prisma can't upsert composite uniques containing nullable fields (tenantId=null),
    // so do a best-effort check + create.
    const existingFleetBlock = await prisma.blocklistEntry.findFirst({
      where: { tenantId: null, blockType: BlockType.IP, indicator: ip },
      select: { id: true },
    });
    if (!existingFleetBlock) {
      await prisma.blocklistEntry.create({
        data: {
          tenantId: null,
          threatId: null,
          blockType: BlockType.IP,
          indicator: ip,
          source: BlockSource.EXTERNAL_FEED,
          reason: 'Seeded fleet feed block',
          expiresAt: new Date(now + 14 * 86_400_000),
          propagationStatus: PropagationStatus.COMPLETED,
          sensorsNotified: 0,
        },
      });
    }
  }

  // Prisma can't upsert composite uniques containing nullable fields reliably; do a best-effort check + create.
  const fleetCampaignName = 'Fleet: Silver Siphon';
  const existingFleetCampaign = await prisma.campaign.findFirst({
    where: { tenantId: null, name: fleetCampaignName },
    select: { id: true },
  });
  if (!existingFleetCampaign) {
    await prisma.campaign.create({
      data: {
        tenantId: null,
        name: fleetCampaignName,
        description: 'Seeded cross-tenant campaign for fleet views',
        status: CampaignStatus.MONITORING,
        severity: Severity.HIGH,
        isCrossTenant: true,
        tenantsAffected: 5,
        confidence: 0.82,
        correlationSignals: { anon_fp_cluster: true } as Prisma.InputJsonValue,
        firstSeenAt: new Date(now - 7 * 86_400_000),
        lastActivityAt: new Date(now - 40 * 60_000),
        metadata: { seeded: true } as Prisma.InputJsonValue,
      },
    });
  }

  return summary;
}
