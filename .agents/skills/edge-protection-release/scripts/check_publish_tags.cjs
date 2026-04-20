#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

/**
 * Verify that all Synapse Fleet package.json files agree on a version
 * before cutting a release. Walks the set of packages published together
 * and flags any mismatches.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

const PACKAGES = [
  'apps/signal-horizon/api/package.json',
  'apps/signal-horizon/ui/package.json',
  'apps/signal-horizon/shared/package.json',
  'packages/synapse-api/package.json',
  'packages/signal-ui/package.json',
];

function main() {
  const versions = [];
  for (const rel of PACKAGES) {
    const abs = path.join(REPO_ROOT, rel);
    if (!fs.existsSync(abs)) {
      console.log(`  (missing)  ${rel}`);
      continue;
    }
    const pkg = JSON.parse(fs.readFileSync(abs, 'utf8'));
    versions.push({ rel, name: pkg.name, version: pkg.version });
  }

  console.log('Fleet package versions:');
  versions.forEach((v) => console.log(`  ${v.version.padEnd(12)}  ${v.name}  (${v.rel})`));

  const uniq = new Set(versions.map((v) => v.version));
  if (uniq.size === 1) {
    console.log(`\nAll ${versions.length} packages aligned at ${[...uniq][0]}.`);
    return;
  }

  console.log(`\nVersion mismatch across ${uniq.size} distinct versions. Sync before tagging.`);
  process.exit(1);
}

main();
