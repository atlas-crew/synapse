#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

/**
 * Validate the set of Synapse WAF fleet configs. Verifies:
 *   1. Each config parses as YAML-ish.
 *   2. Required top-level sections are present.
 *   3. No port collisions across configs (listen + admin_listen).
 *   4. Each config declares a unique sensor_id (if horizon block exists).
 *
 * Uses a minimal line-based YAML reader to avoid adding a dependency.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const SYNAPSE_DIR = path.join(REPO_ROOT, 'apps/synapse-pingora');

const REQUIRED_TOP_LEVEL = ['server', 'upstreams', 'rate_limit', 'logging', 'detection'];

function readPorts(src) {
  const listen = src.match(/^\s*listen:\s*"?([^"\n]+)"?/m);
  const admin = src.match(/^\s*admin_listen:\s*"?([^"\n]+)"?/m);
  return {
    listen: listen ? listen[1].trim() : null,
    admin: admin ? admin[1].trim() : null,
  };
}

function readSensorId(src) {
  const m = src.match(/^\s*sensor_id:\s*"?([^"\n]+)"?/m);
  return m ? m[1].trim() : null;
}

function readTopLevelSections(src) {
  const found = new Set();
  src.split('\n').forEach((line) => {
    const m = line.match(/^([a-z_]+):/);
    if (m) found.add(m[1]);
  });
  return found;
}

function main() {
  if (!fs.existsSync(SYNAPSE_DIR)) {
    console.error(`Synapse directory not found: ${SYNAPSE_DIR}`);
    process.exit(2);
  }

  const configs = fs
    .readdirSync(SYNAPSE_DIR)
    .filter((f) => /^config\.horizon(\.\d+)?\.yaml$/.test(f));

  if (configs.length === 0) {
    console.log('No config.horizon*.yaml files found.');
    return;
  }

  const summaries = [];
  const issues = [];
  const portMap = new Map();
  const sensorIdMap = new Map();

  for (const file of configs) {
    const abs = path.join(SYNAPSE_DIR, file);
    const src = fs.readFileSync(abs, 'utf8');

    const sections = readTopLevelSections(src);
    for (const req of REQUIRED_TOP_LEVEL) {
      if (!sections.has(req)) issues.push(`${file}: missing required section '${req}'`);
    }

    const ports = readPorts(src);
    if (!ports.listen) issues.push(`${file}: missing server.listen`);
    if (!ports.admin) issues.push(`${file}: missing server.admin_listen`);

    for (const [kind, val] of Object.entries(ports)) {
      if (!val) continue;
      if (portMap.has(val)) {
        issues.push(`Port collision on ${val}: ${portMap.get(val)} and ${file} (${kind})`);
      } else {
        portMap.set(val, `${file} (${kind})`);
      }
    }

    const sensorId = readSensorId(src);
    if (sensorId) {
      if (sensorIdMap.has(sensorId)) {
        issues.push(`sensor_id collision '${sensorId}': ${sensorIdMap.get(sensorId)} and ${file}`);
      } else {
        sensorIdMap.set(sensorId, file);
      }
    }

    summaries.push({ file, ports, sensorId: sensorId || '(none)' });
  }

  console.log('Fleet configs:');
  summaries.forEach((s) =>
    console.log(`  ${s.file.padEnd(28)} listen=${(s.ports.listen || '?').padEnd(18)} admin=${(s.ports.admin || '?').padEnd(18)} sensor_id=${s.sensorId}`)
  );

  if (issues.length === 0) {
    console.log(`\nAll ${configs.length} configs valid.`);
    return;
  }

  console.log(`\nFound ${issues.length} issue(s):`);
  issues.forEach((i) => console.log(`  - ${i}`));
  process.exit(1);
}

main();
