#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

/**
 * Find Vitest tests under apps/signal-horizon/api that mock PrismaClient or
 * @prisma/client — both violate the "real Prisma, not mocks" rule.
 *
 * Prints each hit with file:line so they can be reviewed.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');
const API_SRC = path.join(REPO_ROOT, 'apps/signal-horizon/api/src');

const PATTERNS = [
  { re: /vi\.mock\(\s*['"]@prisma\/client['"]/, name: "vi.mock('@prisma/client')" },
  { re: /vi\.mock\([^)]*PrismaClient/, name: 'vi.mock(... PrismaClient ...)' },
  { re: /new\s+PrismaClient\s*\(\s*\)\s*as\s+any/, name: 'new PrismaClient() as any' },
  { re: /mockDeep<\s*PrismaClient\s*>/, name: 'mockDeep<PrismaClient>' },
];

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir)) {
    const abs = path.join(dir, entry);
    const stat = fs.statSync(abs);
    if (stat.isDirectory()) {
      walk(abs, out);
    } else if (entry.endsWith('.test.ts') || entry.endsWith('.test.tsx')) {
      out.push(abs);
    }
  }
  return out;
}

function main() {
  if (!fs.existsSync(API_SRC)) {
    console.error(`API src directory not found: ${API_SRC}`);
    process.exit(2);
  }

  const files = walk(API_SRC);
  const hits = [];

  for (const file of files) {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    lines.forEach((line, i) => {
      for (const p of PATTERNS) {
        if (p.re.test(line)) {
          hits.push({ file: path.relative(REPO_ROOT, file), line: i + 1, pattern: p.name, text: line.trim() });
        }
      }
    });
  }

  if (hits.length === 0) {
    console.log(`No Prisma mocks found across ${files.length} test files.`);
    return;
  }

  console.log('Prisma mocks to review (policy: real Prisma in API tests):\n');
  hits.forEach((h) => {
    console.log(`  ${h.file}:${h.line}  [${h.pattern}]`);
    console.log(`    ${h.text}`);
  });
  console.log(`\n${hits.length} location(s) across ${new Set(hits.map((h) => h.file)).size} file(s).`);
  process.exit(1);
}

main();
