#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

/**
 * Scan apps/signal-horizon/api/src/api/routes/*.ts for handlers that call
 * Prisma directly without a tenantId filter. Multi-tenant rows must always
 * be filtered by tenantId; a missing filter is a cross-tenant data leak.
 */

const ROUTES_DIR = path.resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'apps',
  'signal-horizon',
  'api',
  'src',
  'api',
  'routes'
);

const PRISMA_CALLS = /\bprisma\.([a-zA-Z]+)\.(findMany|findFirst|findUnique|update|updateMany|delete|deleteMany|count|aggregate)\b/;
const TENANT_FILTER = /tenantId\s*:/;

function scanFile(filePath) {
  const src = fs.readFileSync(filePath, 'utf8');
  const lines = src.split('\n');
  const findings = [];

  lines.forEach((line, i) => {
    const match = line.match(PRISMA_CALLS);
    if (!match) return;

    const window = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
    if (!TENANT_FILTER.test(window)) {
      findings.push({
        file: path.relative(process.cwd(), filePath),
        line: i + 1,
        model: match[1],
        op: match[2],
        text: line.trim(),
      });
    }
  });

  return findings;
}

function main() {
  if (!fs.existsSync(ROUTES_DIR)) {
    console.error(`Routes directory not found: ${ROUTES_DIR}`);
    process.exit(2);
  }

  const files = fs
    .readdirSync(ROUTES_DIR)
    .filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .map((f) => path.join(ROUTES_DIR, f));

  const allFindings = files.flatMap(scanFile);

  if (allFindings.length === 0) {
    console.log('No un-scoped Prisma calls detected in route handlers.');
    return;
  }

  console.log('Route-level Prisma calls with no nearby tenantId filter:');
  console.log('(review each — some may intentionally be unscoped, e.g. auth bootstrap)\n');
  allFindings.forEach((f) => {
    console.log(`  ${f.file}:${f.line}  prisma.${f.model}.${f.op}`);
    console.log(`    ${f.text}`);
  });
  console.log(`\n${allFindings.length} site(s) to review.`);
  process.exit(allFindings.length > 0 ? 1 : 0);
}

main();
