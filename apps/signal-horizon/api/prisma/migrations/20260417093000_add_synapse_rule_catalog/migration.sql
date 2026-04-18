-- CreateTable
CREATE TABLE "synapse_rules" (
    "ruleId" INTEGER NOT NULL,
    "name" TEXT,
    "description" TEXT NOT NULL,
    "classification" TEXT,
    "state" TEXT,
    "risk" DOUBLE PRECISION,
    "contributingScore" DOUBLE PRECISION,
    "blocking" BOOLEAN,
    "beta" BOOLEAN,
    "tagName" TEXT,
    "rawDefinition" JSONB NOT NULL,
    "catalogVersion" TEXT NOT NULL,
    "catalogHash" TEXT NOT NULL,
    "importedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "synapse_rules_pkey" PRIMARY KEY ("ruleId")
);

-- CreateIndex
CREATE INDEX "synapse_rules_classification_idx" ON "synapse_rules"("classification");

-- CreateIndex
CREATE INDEX "synapse_rules_state_idx" ON "synapse_rules"("state");

-- CreateIndex
CREATE INDEX "synapse_rules_catalogVersion_idx" ON "synapse_rules"("catalogVersion");

-- CreateTable
CREATE TABLE "synapse_rule_overrides" (
    "id" TEXT NOT NULL,
    "tenantId" TEXT NOT NULL,
    "synapseRuleId" INTEGER NOT NULL,
    "enabled" BOOLEAN,
    "blockingOverride" BOOLEAN,
    "sensitivityOverride" INTEGER,
    "riskOverride" DOUBLE PRECISION,
    "notes" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdBy" TEXT,

    CONSTRAINT "synapse_rule_overrides_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "synapse_rule_overrides_tenantId_synapseRuleId_key" ON "synapse_rule_overrides"("tenantId", "synapseRuleId");

-- CreateIndex
CREATE INDEX "synapse_rule_overrides_tenantId_idx" ON "synapse_rule_overrides"("tenantId");

-- CreateIndex
CREATE INDEX "synapse_rule_overrides_synapseRuleId_idx" ON "synapse_rule_overrides"("synapseRuleId");

-- AddForeignKey
ALTER TABLE "synapse_rule_overrides" ADD CONSTRAINT "synapse_rule_overrides_tenantId_fkey" FOREIGN KEY ("tenantId") REFERENCES "tenants"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "synapse_rule_overrides" ADD CONSTRAINT "synapse_rule_overrides_synapseRuleId_fkey" FOREIGN KEY ("synapseRuleId") REFERENCES "synapse_rules"("ruleId") ON DELETE CASCADE ON UPDATE CASCADE;
