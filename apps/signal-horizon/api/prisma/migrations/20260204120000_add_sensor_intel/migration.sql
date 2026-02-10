-- CreateTable
CREATE TABLE "sensor_intel_actor" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "actorId" TEXT NOT NULL,
    "riskScore" DOUBLE PRECISION NOT NULL,
    "isBlocked" BOOLEAN NOT NULL DEFAULT false,
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "ips" JSONB,
    "fingerprints" JSONB,
    "sessionIds" JSONB,
    "raw" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sensor_intel_actor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sensor_intel_session" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "actorId" TEXT,
    "requestCount" INTEGER NOT NULL,
    "isSuspicious" BOOLEAN NOT NULL,
    "lastActivityAt" TIMESTAMP(3) NOT NULL,
    "boundIp" TEXT,
    "boundJa4" TEXT,
    "hijackAlerts" JSONB,
    "raw" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sensor_intel_session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sensor_intel_campaign" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "campaignId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "riskScore" DOUBLE PRECISION NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "actorCount" INTEGER NOT NULL,
    "attackTypes" JSONB,
    "firstSeenAt" TIMESTAMP(3) NOT NULL,
    "lastActivityAt" TIMESTAMP(3) NOT NULL,
    "raw" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "sensor_intel_campaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sensor_intel_profile" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "template" TEXT NOT NULL,
    "method" TEXT,
    "profile" JSONB NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sensor_intel_profile_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sensor_payload_snapshot" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL,
    "stats" JSONB NOT NULL,
    "bandwidth" JSONB,
    "endpoints" JSONB,
    "anomalies" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sensor_payload_snapshot_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "sensor_intel_actor_tenantId_sensorId_actorId_key" ON "sensor_intel_actor"("tenantId", "sensorId", "actorId");

-- CreateIndex
CREATE INDEX "sensor_intel_actor_tenantId_lastSeenAt_idx" ON "sensor_intel_actor"("tenantId", "lastSeenAt" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "sensor_intel_session_tenantId_sensorId_sessionId_key" ON "sensor_intel_session"("tenantId", "sensorId", "sessionId");

-- CreateIndex
CREATE INDEX "sensor_intel_session_tenantId_lastActivityAt_idx" ON "sensor_intel_session"("tenantId", "lastActivityAt" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "sensor_intel_campaign_tenantId_sensorId_campaignId_key" ON "sensor_intel_campaign"("tenantId", "sensorId", "campaignId");

-- CreateIndex
CREATE UNIQUE INDEX "sensor_intel_profile_tenantId_sensorId_template_method_key" ON "sensor_intel_profile"("tenantId", "sensorId", "template", "method");

-- CreateIndex
CREATE INDEX "sensor_payload_snapshot_tenantId_capturedAt_idx" ON "sensor_payload_snapshot"("tenantId", "capturedAt" DESC);

-- AddForeignKey
ALTER TABLE "sensor_intel_actor" ADD CONSTRAINT "sensor_intel_actor_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_actor" ADD CONSTRAINT "sensor_intel_actor_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_session" ADD CONSTRAINT "sensor_intel_session_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_session" ADD CONSTRAINT "sensor_intel_session_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_campaign" ADD CONSTRAINT "sensor_intel_campaign_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_campaign" ADD CONSTRAINT "sensor_intel_campaign_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_profile" ADD CONSTRAINT "sensor_intel_profile_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_intel_profile" ADD CONSTRAINT "sensor_intel_profile_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_payload_snapshot" ADD CONSTRAINT "sensor_payload_snapshot_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_payload_snapshot" ADD CONSTRAINT "sensor_payload_snapshot_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;
