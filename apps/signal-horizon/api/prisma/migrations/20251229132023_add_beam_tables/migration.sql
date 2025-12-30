-- CreateTable
CREATE TABLE "beam_endpoints" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "pathTemplate" TEXT NOT NULL,
    "service" TEXT NOT NULL DEFAULT 'default',
    "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMP(3) NOT NULL,
    "requestCount" INTEGER NOT NULL DEFAULT 1,
    "hasSchema" BOOLEAN NOT NULL DEFAULT false,
    "schemaVersion" TEXT,
    "schemaHash" TEXT,
    "requestSchema" JSONB,
    "responseSchema" JSONB,
    "avgLatencyMs" DOUBLE PRECISION,
    "p95LatencyMs" DOUBLE PRECISION,
    "p99LatencyMs" DOUBLE PRECISION,
    "errorRate" DOUBLE PRECISION,
    "riskLevel" TEXT NOT NULL DEFAULT 'low',
    "authRequired" BOOLEAN NOT NULL DEFAULT false,
    "sensitiveData" BOOLEAN NOT NULL DEFAULT false,
    "metadata" JSONB,

    CONSTRAINT "beam_endpoints_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "beam_schema_changes" (
    "id" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "changeType" TEXT NOT NULL,
    "field" TEXT NOT NULL,
    "oldValue" TEXT,
    "newValue" TEXT,
    "riskLevel" TEXT NOT NULL DEFAULT 'low',
    "previousHash" TEXT,
    "currentHash" TEXT,
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "beam_schema_changes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "beam_rules" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "category" TEXT NOT NULL DEFAULT 'custom',
    "severity" TEXT NOT NULL DEFAULT 'medium',
    "action" TEXT NOT NULL DEFAULT 'block',
    "patterns" JSONB NOT NULL,
    "exclusions" JSONB,
    "sensitivity" INTEGER NOT NULL DEFAULT 50,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "status" TEXT NOT NULL DEFAULT 'draft',
    "rolloutStrategy" TEXT NOT NULL DEFAULT 'immediate',
    "rolloutConfig" JSONB,
    "totalSensors" INTEGER NOT NULL DEFAULT 0,
    "deployedSensors" INTEGER NOT NULL DEFAULT 0,
    "failedSensors" INTEGER NOT NULL DEFAULT 0,
    "triggers24h" INTEGER NOT NULL DEFAULT 0,
    "lastTriggered" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "deployedAt" TIMESTAMP(3),
    "createdBy" TEXT,

    CONSTRAINT "beam_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "beam_rule_deployments" (
    "id" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "error" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "queuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "beam_rule_deployments_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "beam_rule_endpoint_bindings" (
    "id" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "endpointId" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "bindingType" TEXT NOT NULL DEFAULT 'include',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "beam_rule_endpoint_bindings_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "beam_block_decisions" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "sensorId" TEXT NOT NULL,
    "blockId" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "sourceIp" TEXT NOT NULL,
    "mode" TEXT NOT NULL,
    "ruleId" TEXT,
    "ruleName" TEXT,
    "reason" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "requestMethod" TEXT NOT NULL,
    "requestPath" TEXT NOT NULL,
    "requestHeaders" JSONB,
    "entityState" JSONB NOT NULL,
    "matchedRules" JSONB NOT NULL,
    "decidedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "beam_block_decisions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "beam_endpoints_tenantId_idx" ON "beam_endpoints"("tenantId");

-- CreateIndex
CREATE INDEX "beam_endpoints_lastSeenAt_idx" ON "beam_endpoints"("lastSeenAt");

-- CreateIndex
CREATE INDEX "beam_endpoints_service_idx" ON "beam_endpoints"("service");

-- CreateIndex
CREATE UNIQUE INDEX "beam_endpoints_tenantId_sensorId_method_pathTemplate_key" ON "beam_endpoints"("tenantId", "sensorId", "method", "pathTemplate");

-- CreateIndex
CREATE INDEX "beam_schema_changes_tenantId_detectedAt_idx" ON "beam_schema_changes"("tenantId", "detectedAt");

-- CreateIndex
CREATE INDEX "beam_schema_changes_endpointId_idx" ON "beam_schema_changes"("endpointId");

-- CreateIndex
CREATE INDEX "beam_rules_tenantId_status_idx" ON "beam_rules"("tenantId", "status");

-- CreateIndex
CREATE INDEX "beam_rules_tenantId_enabled_idx" ON "beam_rules"("tenantId", "enabled");

-- CreateIndex
CREATE INDEX "beam_rule_deployments_ruleId_status_idx" ON "beam_rule_deployments"("ruleId", "status");

-- CreateIndex
CREATE INDEX "beam_rule_deployments_sensorId_idx" ON "beam_rule_deployments"("sensorId");

-- CreateIndex
CREATE UNIQUE INDEX "beam_rule_deployments_ruleId_sensorId_key" ON "beam_rule_deployments"("ruleId", "sensorId");

-- CreateIndex
CREATE UNIQUE INDEX "beam_rule_endpoint_bindings_ruleId_endpointId_key" ON "beam_rule_endpoint_bindings"("ruleId", "endpointId");

-- CreateIndex
CREATE UNIQUE INDEX "beam_block_decisions_blockId_key" ON "beam_block_decisions"("blockId");

-- CreateIndex
CREATE INDEX "beam_block_decisions_tenantId_decidedAt_idx" ON "beam_block_decisions"("tenantId", "decidedAt");

-- CreateIndex
CREATE INDEX "beam_block_decisions_entityId_idx" ON "beam_block_decisions"("entityId");

-- CreateIndex
CREATE INDEX "beam_block_decisions_sourceIp_idx" ON "beam_block_decisions"("sourceIp");

-- CreateIndex
CREATE INDEX "signals_severity_idx" ON "signals"("severity");

-- CreateIndex
CREATE INDEX "signals_severity_createdAt_idx" ON "signals"("severity", "createdAt");

-- CreateIndex
CREATE INDEX "signals_tenantId_severity_createdAt_idx" ON "signals"("tenantId", "severity", "createdAt");

-- AddForeignKey
ALTER TABLE "beam_endpoints" ADD CONSTRAINT "beam_endpoints_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_endpoints" ADD CONSTRAINT "beam_endpoints_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_schema_changes" ADD CONSTRAINT "beam_schema_changes_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "beam_endpoints"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_rules" ADD CONSTRAINT "beam_rules_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_rule_deployments" ADD CONSTRAINT "beam_rule_deployments_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "beam_rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_rule_deployments" ADD CONSTRAINT "beam_rule_deployments_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_rule_endpoint_bindings" ADD CONSTRAINT "beam_rule_endpoint_bindings_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "beam_rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_rule_endpoint_bindings" ADD CONSTRAINT "beam_rule_endpoint_bindings_endpointId_fkey" FOREIGN KEY ("endpointId") REFERENCES "beam_endpoints"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_block_decisions" ADD CONSTRAINT "beam_block_decisions_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "beam_block_decisions" ADD CONSTRAINT "beam_block_decisions_sensorId_fkey" FOREIGN KEY ("sensorId") REFERENCES "sensors"("id") ON DELETE CASCADE ON UPDATE CASCADE;
