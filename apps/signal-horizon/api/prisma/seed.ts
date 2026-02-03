/**
 * Signal Horizon - Development Seed Data
 * Creates sample tenants, sensors, campaigns for development/testing
 */

import { PrismaClient, TenantTier, SharingPreference, Severity } from '@prisma/client';
import { randomUUID } from 'crypto';

const prisma = new PrismaClient();

async function hashApiKey(apiKey: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  console.log('Seeding Signal Horizon database...');

  // Create tenants
  const tenants = await Promise.all([
    prisma.tenant.create({
      data: {
        id: 'tenant-acme',
        name: 'Acme Corporation',
        tier: TenantTier.ENTERPRISE,
        sharingPreference: SharingPreference.CONTRIBUTE_AND_RECEIVE,
      },
    }),
    prisma.tenant.create({
      data: {
        id: 'tenant-globex',
        name: 'Globex Industries',
        tier: TenantTier.STANDARD,
        sharingPreference: SharingPreference.CONTRIBUTE_AND_RECEIVE,
      },
    }),
    prisma.tenant.create({
      data: {
        id: 'tenant-initech',
        name: 'Initech LLC',
        tier: TenantTier.STANDARD,
        sharingPreference: SharingPreference.RECEIVE_ONLY,
      },
    }),
  ]);

  console.log(`Created ${tenants.length} tenants`);

  // Create API keys for each tenant (sensor keys)
  const apiKeys = [
    { tenant: 'tenant-acme', key: 'sk-acme-dev-12345', name: 'Acme Development' },
    { tenant: 'tenant-globex', key: 'sk-globex-dev-67890', name: 'Globex Development' },
    { tenant: 'tenant-initech', key: 'sk-initech-dev-54321', name: 'Initech Development' },
  ];

  for (const { tenant, key, name } of apiKeys) {
    await prisma.apiKey.create({
      data: {
        tenantId: tenant,
        keyHash: await hashApiKey(key),
        name,
        scopes: ['signal:write', 'blocklist:read'],
        rateLimit: 5000,
      },
    });
    console.log(`Created API key for ${tenant}: ${key}`);
  }

  // Create development dashboard key (fleet admin - can see all tenants)
  await prisma.apiKey.create({
    data: {
      tenantId: 'tenant-acme', // Associated with Acme but has fleet:admin
      keyHash: await hashApiKey('dev-dashboard-key'),
      name: 'Development Dashboard',
      scopes: [
        'admin',
        'dashboard:read', 'dashboard:write',
        'fleet:admin', 'fleet:read', 'fleet:write',
        'sensor:diag', 'sensor:files', 'sensor:admin', 'sensor:control',
        'config:read', 'config:write',
        'policy:read', 'policy:write',
        'releases:read', 'releases:write',
        'signal:write',
      ],
      rateLimit: 1000,
    },
  });
  console.log('Created dev dashboard key: dev-dashboard-key');

  // Create sensors with predictable IDs for testing
  const sensors = await Promise.all([
    prisma.sensor.create({
      data: {
        id: 'synapse-pingora-1',  // Sensor bridge sensor
        tenantId: 'tenant-acme',
        name: 'Synapse Pingora WAF',
        version: '0.1.0',
        connectionState: 'DISCONNECTED',
        region: 'local',
      },
    }),
    prisma.sensor.create({
      data: {
        id: 'sensor-acme-1',  // Predictable ID for tunnel testing
        tenantId: 'tenant-acme',
        name: 'acme-sensor-prod-1',
        version: '1.0.0',
        connectionState: 'DISCONNECTED',
      },
    }),
    prisma.sensor.create({
      data: {
        id: 'sensor-acme-2',
        tenantId: 'tenant-acme',
        name: 'acme-sensor-prod-2',
        version: '1.0.0',
        connectionState: 'DISCONNECTED',
      },
    }),
    prisma.sensor.create({
      data: {
        id: 'sensor-globex-1',
        tenantId: 'tenant-globex',
        name: 'globex-sensor-1',
        version: '1.0.0',
        connectionState: 'DISCONNECTED',
      },
    }),
    prisma.sensor.create({
      data: {
        id: 'sensor-initech-1',
        tenantId: 'tenant-initech',
        name: 'initech-sensor-1',
        version: '0.9.0',
        connectionState: 'DISCONNECTED',
      },
    }),
  ]);

  console.log(`Created ${sensors.length} sensors`);

  // Create a sample cross-tenant campaign
  const campaign = await prisma.campaign.create({
    data: {
      name: 'Operation Dark Phoenix',
      description: 'Coordinated credential stuffing campaign targeting multiple customers',
      status: 'ACTIVE',
      severity: Severity.HIGH,
      isCrossTenant: true,
      tenantsAffected: 2,
      confidence: 0.92,
      correlationSignals: {
        fingerprintMatch: 0.98,
        timingMatch: 0.89,
        tenantCount: 2,
      },
      firstSeenAt: new Date(Date.now() - 3600000), // 1 hour ago
      lastActivityAt: new Date(),
      metadata: {
        anonFingerprint: 'a1b2c3d4e5f6...',
        attackVector: 'credential_stuffing',
        estimatedBotCount: 150,
      },
    },
  });

  console.log(`Created campaign: ${campaign.name}`);

  // Create sample threats
  const threats = await Promise.all([
    prisma.threat.create({
      data: {
        threatType: 'IP',
        indicator: '192.168.1.100',
        anonIndicator: await hashApiKey('192.168.1.100'),
        riskScore: 85.5,
        fleetRiskScore: 78.2,
        firstSeenAt: new Date(Date.now() - 7200000),
        lastSeenAt: new Date(),
        hitCount: 1523,
        tenantsAffected: 2,
        isFleetThreat: true,
        metadata: { asn: 'AS12345', country: 'RU' },
      },
    }),
    prisma.threat.create({
      data: {
        threatType: 'FINGERPRINT',
        indicator: 'fp-dark-phoenix-001',
        anonIndicator: await hashApiKey('fp-dark-phoenix-001'),
        riskScore: 92.3,
        fleetRiskScore: 88.1,
        firstSeenAt: new Date(Date.now() - 3600000),
        lastSeenAt: new Date(),
        hitCount: 3421,
        tenantsAffected: 2,
        isFleetThreat: true,
        metadata: {
          tlsFingerprint: 'ja3:xxx',
          httpFingerprint: 'http2:yyy',
        },
      },
    }),
    prisma.threat.create({
      data: {
        tenantId: 'tenant-acme',
        threatType: 'IP',
        indicator: '10.0.0.50',
        riskScore: 45.0,
        firstSeenAt: new Date(Date.now() - 1800000),
        lastSeenAt: new Date(),
        hitCount: 89,
        tenantsAffected: 1,
        isFleetThreat: false,
        metadata: { asn: 'AS98765', country: 'US' },
      },
    }),
  ]);

  console.log(`Created ${threats.length} threats`);

  // Create blocklist entries
  await prisma.blocklistEntry.createMany({
    data: [
      {
        blockType: 'IP',
        indicator: '192.168.1.100',
        source: 'FLEET_INTEL',
        reason: 'Campaign: Operation Dark Phoenix',
        propagationStatus: 'COMPLETED',
        propagatedAt: new Date(),
        sensorsNotified: 4,
      },
      {
        blockType: 'FINGERPRINT',
        indicator: await hashApiKey('fp-dark-phoenix-001'),
        source: 'FLEET_INTEL',
        reason: 'Campaign: Operation Dark Phoenix',
        propagationStatus: 'COMPLETED',
        propagatedAt: new Date(),
        sensorsNotified: 4,
      },
      {
        tenantId: 'tenant-acme',
        blockType: 'IP',
        indicator: '10.0.0.50',
        source: 'MANUAL',
        reason: 'Suspicious activity - manual block',
        propagationStatus: 'COMPLETED',
        propagatedAt: new Date(),
        sensorsNotified: 2,
      },
    ],
  });

  console.log('Created blocklist entries');

  // Create a war room
  const warRoom = await prisma.warRoom.create({
    data: {
      tenantId: 'tenant-acme',
      name: 'Dark Phoenix Response',
      description: 'Incident response for Operation Dark Phoenix campaign',
      status: 'ACTIVE',
      priority: 'HIGH',
      leaderId: 'user-security-lead',
    },
  });

  // Add war room activities
  await prisma.warRoomActivity.createMany({
    data: [
      {
        warRoomId: warRoom.id,
        tenantId: 'tenant-acme',
        actorType: 'SYSTEM',
        actorId: 'horizon-bot',
        actorName: '@horizon-bot',
        actionType: 'ALERT_TRIGGERED',
        description: 'Cross-tenant campaign detected: Operation Dark Phoenix',
        metadata: { campaignId: campaign.id },
      },
      {
        warRoomId: warRoom.id,
        tenantId: 'tenant-acme',
        actorType: 'HORIZON_BOT',
        actorId: 'horizon-bot',
        actorName: '@horizon-bot',
        actionType: 'BLOCK_CREATED',
        description: 'Auto-blocked IP 192.168.1.100 (fleet-wide)',
        metadata: { blockType: 'IP', indicator: '192.168.1.100' },
      },
      {
        warRoomId: warRoom.id,
        tenantId: 'tenant-acme',
        actorType: 'USER',
        actorId: 'user-security-lead',
        actorName: 'Security Lead',
        actionType: 'MESSAGE',
        description: 'Confirmed attack pattern matches known APT group tactics',
      },
    ],
  });

  console.log(`Created war room: ${warRoom.name} with activities`);

  // Link campaign to war room
  await prisma.warRoomCampaign.create({
    data: {
      warRoomId: warRoom.id,
      campaignId: campaign.id,
      linkedBy: 'horizon-bot',
    },
  });

  // ===========================================================================
  // Create Mock Signals for Threat Hunting Demo
  // ===========================================================================
  console.log('Creating mock signals for hunting demo...');
  
  const now = Date.now();
  const mockSignals = [];

  // 1. IP Threat Signals (matching example 'ip:185.228.*')
  for (let i = 0; i < 15; i++) {
    mockSignals.push({
      tenantId: 'tenant-acme',
      sensorId: 'sensor-acme-1',
      signalType: 'IP_THREAT',
      sourceIp: `185.228.101.${10 + i}`,
      severity: 'CRITICAL',
      confidence: 0.95,
      eventCount: Math.floor(Math.random() * 50) + 1,
      metadata: { asn: '12345', isp: 'BadActor ISP', country: 'RU' },
      createdAt: new Date(now - Math.random() * 86400000), // Last 24h
    });
  }

  // 2. Fingerprint Signals (matching example 'fingerprint:"curl"')
  for (let i = 0; i < 10; i++) {
    mockSignals.push({
      tenantId: 'tenant-globex',
      sensorId: 'sensor-globex-1',
      signalType: 'BOT_SIGNATURE',
      sourceIp: `45.33.22.${i}`,
      anonFingerprint: 'curl/7.68.0', // Raw string for demo matching
      severity: 'MEDIUM',
      confidence: 0.80,
      eventCount: 1,
      metadata: { userAgent: 'curl/7.68.0', ja3: 'e7d705a3286e19ea42f55823' },
      createdAt: new Date(now - Math.random() * 86400000),
    });
  }

  // 3. API Discovery Signals (matching example 'endpoint:/api/auth/*')
  for (let i = 0; i < 8; i++) {
    mockSignals.push({
      tenantId: 'tenant-initech',
      sensorId: 'sensor-initech-1',
      signalType: 'TEMPLATE_DISCOVERY',
      sourceIp: `10.0.0.${50 + i}`,
      severity: 'LOW',
      confidence: 0.60,
      eventCount: 12,
      metadata: { method: 'POST', path: '/api/auth/login', risk: 'low' },
      createdAt: new Date(now - Math.random() * 86400000),
    });
  }

  // Bulk insert signals
  // Note: createMany is faster but create allows relations if needed (we use createMany here)
  await prisma.signal.createMany({
    data: mockSignals as any, // Cast to any to avoid strict enum typing issues in seed
  });

  console.log(`Created ${mockSignals.length} mock signals`);

  console.log('Seed completed successfully!');
  console.log('\n=== TEST CREDENTIALS ===');
  console.log('\nSensor IDs (use for tunnel testing):');
  console.log('  sensor-acme-1     (tenant-acme)');
  console.log('  sensor-acme-2     (tenant-acme)');
  console.log('  sensor-globex-1   (tenant-globex)');
  console.log('  sensor-initech-1  (tenant-initech)');
  console.log('\nAPI Keys:');
  console.log('  Sensor Keys:');
  console.log('    Acme:    sk-acme-dev-12345');
  console.log('    Globex:  sk-globex-dev-67890');
  console.log('    Initech: sk-initech-dev-54321');
  console.log('  Dashboard Key (fleet admin):');
  console.log('    dev-dashboard-key');
  console.log('\n=== TUNNEL TEST COMMAND ===');
  console.log('TUNNEL_ENABLED=true TUNNEL_SENSOR_ID=sensor-acme-1 TUNNEL_API_KEY=sk-acme-dev-12345 pnpm dev');
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
