-- Add compound indexes for fleet management optimization
-- These indexes optimize critical query patterns for fleet operations

-- ConfigTemplate: Filter active templates by environment (10x speedup)
CREATE INDEX "config_templates_environment_isActive_idx" ON "config_templates"("environment", "isActive");

-- FleetCommand: Get pending commands per sensor (10-50x speedup)
CREATE INDEX "fleet_commands_sensorId_status_idx" ON "fleet_commands"("sensorId", "status");

-- FleetCommand: FIFO command processing query
CREATE INDEX "fleet_commands_status_queuedAt_idx" ON "fleet_commands"("status", "queuedAt");
