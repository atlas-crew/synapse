-- CreateEnum
CREATE TYPE "RegistrationMethod" AS ENUM ('MANUAL', 'AGENT_SCRIPT', 'AUTO_DISCOVERY');

-- CreateEnum
CREATE TYPE "ApprovalStatus" AS ENUM ('PENDING', 'APPROVED', 'REJECTED');

-- CreateEnum
CREATE TYPE "KeyStatus" AS ENUM ('ACTIVE', 'EXPIRED', 'REVOKED');

-- AlterTable
ALTER TABLE "sensors" ADD COLUMN     "approvalStatus" "ApprovalStatus" NOT NULL DEFAULT 'APPROVED',
ADD COLUMN     "approvedAt" TIMESTAMP(3),
ADD COLUMN     "approvedBy" TEXT,
ADD COLUMN     "architecture" TEXT,
ADD COLUMN     "instanceType" TEXT,
ADD COLUMN     "kernel" TEXT,
ADD COLUMN     "lastBoot" TIMESTAMP(3),
ADD COLUMN     "os" TEXT,
ADD COLUMN     "privateIp" TEXT,
ADD COLUMN     "publicIp" TEXT,
ADD COLUMN     "registrationMethod" "RegistrationMethod" NOT NULL DEFAULT 'MANUAL',
ADD COLUMN     "registrationToken" TEXT,
ADD COLUMN     "tunnelActive" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "tunnelSessionId" TEXT,
ADD COLUMN     "uptime" INTEGER;

-- CreateTable
CREATE TABLE "sensor_api_keys" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "keyHash" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "status" "KeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "permissions" TEXT[],
    "createdBy" TEXT,

    CONSTRAINT "sensor_api_keys_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "diagnostic_bundles" (
    "id" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    "status" TEXT NOT NULL DEFAULT 'pending',
    "includes" TEXT[],
    "downloadUrl" TEXT,
    "expiresAt" TIMESTAMP(3),
    "notes" TEXT,

    CONSTRAINT "diagnostic_bundles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sensor_updates" (
    "id" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "fromVersion" TEXT NOT NULL,
    "toVersion" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'scheduled',
    "scheduledFor" TIMESTAMP(3),
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "rollbackAvailable" BOOLEAN NOT NULL DEFAULT true,
    "logs" TEXT,

    CONSTRAINT "sensor_updates_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fleet_alerts" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT,
    "alertType" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "acknowledged" BOOLEAN NOT NULL DEFAULT false,
    "acknowledgedAt" TIMESTAMP(3),
    "acknowledgedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),

    CONSTRAINT "fleet_alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "registration_tokens" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "name" TEXT,
    "region" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "usedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdBy" TEXT,

    CONSTRAINT "registration_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "sensor_api_keys_sensorId_idx" ON "sensor_api_keys"("sensorId");

-- CreateIndex
CREATE INDEX "sensor_api_keys_keyHash_idx" ON "sensor_api_keys"("keyHash");

-- CreateIndex
CREATE INDEX "diagnostic_bundles_sensorId_idx" ON "diagnostic_bundles"("sensorId");

-- CreateIndex
CREATE INDEX "sensor_updates_sensorId_idx" ON "sensor_updates"("sensorId");

-- CreateIndex
CREATE INDEX "fleet_alerts_tenantId_idx" ON "fleet_alerts"("tenantId");

-- CreateIndex
CREATE INDEX "fleet_alerts_sensorId_idx" ON "fleet_alerts"("sensorId");

-- CreateIndex
CREATE INDEX "fleet_alerts_alertType_idx" ON "fleet_alerts"("alertType");

-- CreateIndex
CREATE INDEX "fleet_alerts_acknowledged_idx" ON "fleet_alerts"("acknowledged");

-- CreateIndex
CREATE UNIQUE INDEX "registration_tokens_token_key" ON "registration_tokens"("token");

-- CreateIndex
CREATE INDEX "registration_tokens_tenantId_idx" ON "registration_tokens"("tenantId");

-- CreateIndex
CREATE INDEX "registration_tokens_token_idx" ON "registration_tokens"("token");

-- AddForeignKey
ALTER TABLE "sensor_api_keys" ADD CONSTRAINT "sensor_api_keys_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "diagnostic_bundles" ADD CONSTRAINT "diagnostic_bundles_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_updates" ADD CONSTRAINT "sensor_updates_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;
