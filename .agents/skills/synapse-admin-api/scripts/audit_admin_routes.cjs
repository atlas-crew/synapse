#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

/**
 * Scan apps/synapse-pingora/src/admin_server.rs for `.route("/path",
 * <method>(handler))` entries and flag any whose handler function does not
 * appear nested under one of the `require_*` scope guards.
 *
 * Heuristic only — this won't catch every case (macro-generated routers,
 * dynamically composed routers), but it is strong enough to surface the
 * common mistake of forgetting to wrap a new handler.
 */

const ADMIN_SERVER = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'apps',
  'synapse-pingora',
  'src',
  'admin_server.rs'
);

const ROUTE_RE = /\.route\(\s*"[^"]+"\s*,\s*\w+\(([a-zA-Z0-9_]+)\)/;
const SCOPE_GUARDS = [
  'require_auth',
  'require_ws_auth',
  'require_admin_read',
  'require_admin_write',
  'require_config_write',
  'require_service_manage',
  'require_sensor_read',
  'require_sensor_write',
];

function main() {
  if (!fs.existsSync(ADMIN_SERVER)) {
    console.error(`admin_server.rs not found: ${ADMIN_SERVER}`);
    process.exit(2);
  }

  const src = fs.readFileSync(ADMIN_SERVER, 'utf8');
  const lines = src.split('\n');

  const handlers = new Set();
  lines.forEach((line) => {
    const m = line.match(ROUTE_RE);
    if (m) handlers.add(m[1]);
  });

  const guardedHandlers = new Set();
  for (const guard of SCOPE_GUARDS) {
    const guardRe = new RegExp(`${guard}[\\s\\S]{0,2000}?\\.route\\(\\s*"[^"]+"\\s*,\\s*\\w+\\(([a-zA-Z0-9_]+)\\)`, 'g');
    let m;
    while ((m = guardRe.exec(src)) !== null) {
      guardedHandlers.add(m[1]);
    }
  }

  const ungated = [...handlers].filter((h) => !guardedHandlers.has(h));

  if (ungated.length === 0) {
    console.log(`All ${handlers.size} mounted handlers appear under a scope guard.`);
    return;
  }

  console.log('Handlers not obviously gated by a scope guard:');
  ungated.sort().forEach((h) => console.log(`  ${h}`));
  console.log(
    `\n${ungated.length} handler(s) to review. Some may be intentional (root, health, public metrics) — confirm manually.`
  );
  process.exit(1);
}

main();
