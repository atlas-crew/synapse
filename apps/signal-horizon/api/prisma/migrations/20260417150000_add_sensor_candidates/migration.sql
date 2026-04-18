-- CreateTable
CREATE TABLE "sensor_candidates" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "registrationTokenId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "hostname" TEXT,
    "os" TEXT,
    "kernel" TEXT,
    "architecture" TEXT,
    "ipAddress" TEXT,
    "version" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "claimedSensorId" TEXT,
    "announceCount" INTEGER NOT NULL DEFAULT 1,
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sensor_candidates_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "sensor_candidates_registrationTokenId_fingerprint_key" ON "sensor_candidates"("registrationTokenId", "fingerprint");

-- CreateIndex
CREATE INDEX "sensor_candidates_tenantId_lastSeenAt_idx" ON "sensor_candidates"("tenantId", "lastSeenAt");

-- CreateIndex
CREATE INDEX "sensor_candidates_registrationTokenId_idx" ON "sensor_candidates"("registrationTokenId");

-- AddForeignKey
ALTER TABLE "sensor_candidates" ADD CONSTRAINT "sensor_candidates_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sensor_candidates" ADD CONSTRAINT "sensor_candidates_registrationTokenId_fkey" FOREIGN KEY ("registrationTokenId") REFERENCES "registration_tokens"("id") ON DELETE CASCADE ON UPDATE CASCADE;
