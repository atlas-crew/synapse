#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Verify that the compiled console-next assets committed under
 * apps/synapse-pingora/assets/console-next/ match what the current
 * apps/synapse-console-ui/ build would produce.
 *
 * When apps/synapse-console-ui/dist/ exists, compares file lists and
 * SHA-256 hashes against the shipped copy. Otherwise reports that a
 * fresh build is needed.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const SRC_DIST = path.join(REPO_ROOT, 'apps/synapse-console-ui/dist');
const SHIPPED = path.join(REPO_ROOT, 'apps/synapse-pingora/assets/console-next');

function walk(dir, base = dir, out = new Map()) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir)) {
    const abs = path.join(dir, entry);
    const stat = fs.statSync(abs);
    if (stat.isDirectory()) {
      walk(abs, base, out);
    } else {
      const rel = path.relative(base, abs);
      const hash = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex').slice(0, 12);
      out.set(rel, hash);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(SHIPPED)) {
    console.error(`Shipped console-next directory not found: ${SHIPPED}`);
    process.exit(2);
  }

  const shipped = walk(SHIPPED);

  if (!fs.existsSync(SRC_DIST)) {
    console.log(`No fresh build at ${path.relative(REPO_ROOT, SRC_DIST)}.`);
    console.log(`Shipped bundle has ${shipped.size} files. Run 'pnpm --filter synapse-console-ui build' to compare.`);
    return;
  }

  const built = walk(SRC_DIST);

  const onlyInShipped = [...shipped.keys()].filter((k) => !built.has(k));
  const onlyInBuilt = [...built.keys()].filter((k) => !shipped.has(k));
  const mismatched = [...shipped.keys()].filter((k) => built.has(k) && shipped.get(k) !== built.get(k));

  if (onlyInShipped.length === 0 && onlyInBuilt.length === 0 && mismatched.length === 0) {
    console.log(`Console-next is in sync (${shipped.size} files match).`);
    return;
  }

  if (onlyInShipped.length) {
    console.log(`Only in shipped (stale, remove?): ${onlyInShipped.length}`);
    onlyInShipped.forEach((f) => console.log(`  - ${f}`));
  }
  if (onlyInBuilt.length) {
    console.log(`Only in fresh build (missing from ship): ${onlyInBuilt.length}`);
    onlyInBuilt.forEach((f) => console.log(`  + ${f}`));
  }
  if (mismatched.length) {
    console.log(`Content mismatch: ${mismatched.length}`);
    mismatched.forEach((f) => console.log(`  ~ ${f}`));
  }
  process.exit(1);
}

main();
