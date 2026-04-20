const { PrismaClient } = require('@prisma/client');

/**
 * Procedural database wipe script for the Edge Protection dev environment.
 * Deletes all data in dependency-safe order using Prisma.
 */
async function main() {
  const prisma = new PrismaClient();
  const dryRun = process.argv.includes('--dry-run');

  console.log('🛡️ Edge Protection - Database Wipe Utility');
  console.log('-----------------------------------------');

  if (dryRun) {
    console.log('🔍 DRY RUN: Simulating data deletion...\n');
  } else {
    console.log('⚠️  WARNING: This will delete ALL data from the database.\n');
  }

  const tables = [
    'rolloutProgress', 'rollout', 'release',
    'ruleEndpointBinding', 'ruleDeployment', 'customerRule', 'endpointSchemaChange', 'endpoint', 'blockDecision',
    'tunnelSession', 'fleetAlert', 'sensorUpdate', 'diagnosticBundle', 'sensorApiKey', 'scheduledDeployment',
    'sensorPayloadSnapshot', 'sensorIntelProfile', 'sensorIntelCampaign', 'sensorIntelSession', 'sensorIntelActor',
    'sensorPingoraConfig', 'ruleSyncState', 'fleetCommand', 'sensorSyncState',
    'policyTemplate', 'configTemplate',
    'playbookRun', 'playbook', 'warRoomCampaign', 'warRoomActivity', 'warRoom',
    'campaignThreat', 'threatSignal', 'blocklistEntry', 'campaign', 'threat', 'signal',
    'securityAuditLog', 'auditLog', 'idempotencyRequest', 'tenantConsent', 'tokenBlacklist',
    'refreshToken', 'userSession', 'tenantMember', 'apiKey', 'sensor', 'registrationToken',
    'tenant', 'user'
  ];

  try {
    for (const table of tables) {
      if (prisma[table]) {
        const count = dryRun ? '?' : (await prisma[table].deleteMany({})).count;
        console.log(`✅ ${dryRun ? 'Found' : 'Deleted'} records in: ${table} (${count})`);
      } else {
        console.warn(`⚠️  Table not found in Prisma client: ${table}`);
      }
    }
    console.log('\n✨ Database wipe complete.');
  } catch (error) {
    console.error('\n❌ Wipe failed:', error.message);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();
