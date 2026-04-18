/**
 * Synapse Rule Catalog Loader.
 *
 * Imports the authoritative WAF ruleset (currently 248 rules) from Synapse's
 * `production_rules.json` into Horizon's `SynapseRule` table. Catalog is the
 * immutable vendor ruleset; tenants layer tuning on top via TenantRuleOverride.
 *
 * The loader is pure — it takes a parsed record array (or a file path) and
 * a PrismaClient. The CLI wrapper at prisma/sync-synapse-rules.ts handles
 * env/arg parsing and client lifecycle.
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { Logger } from 'pino';
import type { PrismaClient, Prisma } from '@prisma/client';

export interface SynapseRuleRecord {
  id: number;
  name?: string | null;
  description: string;
  classification?: string | null;
  state?: string | null;
  risk?: number | null;
  contributing_score?: number | null;
  blocking?: boolean | null;
  beta?: boolean | null;
  tag_name?: string | null;
  matches?: unknown;
  // Any additional fields land in rawDefinition verbatim.
  [key: string]: unknown;
}

export interface SyncOptions {
  /** Version label recorded on each row. Defaults to short catalog hash. */
  catalogVersion?: string;
  /** If true, delete SynapseRule rows whose ids are absent from input. Default true. */
  prune?: boolean;
}

export interface SyncResult {
  catalogHash: string;
  catalogVersion: string;
  totalInput: number;
  inserted: number;
  updated: number;
  deleted: number;
  deletedIds: number[];
  skipped: number;
  warnings: string[];
}

/** SHA-256 of a canonical form: rules sorted by id, keys sorted per rule. */
export function computeCatalogHash(records: SynapseRuleRecord[]): string {
  const sorted = [...records].sort((a, b) => a.id - b.id).map(canonicalize);
  const hash = createHash('sha256');
  hash.update(JSON.stringify(sorted));
  return hash.digest('hex');
}

/** Parse raw JSON text into an array of rule records. Throws on shape errors. */
export function parseSynapseRules(raw: string): SynapseRuleRecord[] {
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error('Expected top-level JSON array of Synapse rule records');
  }
  return parsed as SynapseRuleRecord[];
}

export async function readSynapseRulesFile(path: string): Promise<SynapseRuleRecord[]> {
  const raw = await readFile(path, 'utf8');
  return parseSynapseRules(raw);
}

/**
 * Upsert the catalog into the database. Returns counts and any warnings.
 *
 * Runs inside a transaction so a partial failure leaves the catalog at its
 * prior consistent state.
 */
export async function syncSynapseRules(
  prisma: PrismaClient,
  records: SynapseRuleRecord[],
  options: SyncOptions = {},
  logger?: Logger
): Promise<SyncResult> {
  const warnings: string[] = [];
  const valid: SynapseRuleRecord[] = [];
  const seenIds = new Set<number>();

  for (const record of records) {
    if (!isValidRecord(record, warnings)) continue;
    if (seenIds.has(record.id)) {
      warnings.push(`duplicate rule id ${record.id} — keeping first occurrence`);
      continue;
    }
    seenIds.add(record.id);
    valid.push(record);
  }

  const catalogHash = computeCatalogHash(valid);
  const catalogVersion = options.catalogVersion ?? catalogHash.slice(0, 12);
  const prune = options.prune ?? true;

  const existing = await prisma.synapseRule.findMany({ select: { ruleId: true } });
  const existingIds = new Set(existing.map((r) => r.ruleId));
  const incomingIds = new Set(valid.map((r) => r.id));
  const deletedIds = prune
    ? Array.from(existingIds).filter((id) => !incomingIds.has(id))
    : [];

  let inserted = 0;
  let updated = 0;

  await prisma.$transaction(async (tx) => {
    for (const record of valid) {
      const data: Prisma.SynapseRuleUncheckedCreateInput = {
        ruleId: record.id,
        name: nullableString(record.name),
        description: record.description,
        classification: nullableString(record.classification),
        state: nullableString(record.state),
        risk: nullableNumber(record.risk),
        contributingScore: nullableNumber(record.contributing_score),
        blocking: nullableBoolean(record.blocking),
        beta: nullableBoolean(record.beta),
        tagName: nullableString(record.tag_name),
        rawDefinition: record as unknown as Prisma.InputJsonValue,
        catalogVersion,
        catalogHash,
      };

      const result = await tx.synapseRule.upsert({
        where: { ruleId: record.id },
        create: data,
        update: {
          ...data,
          ruleId: undefined,
        },
      });
      if (existingIds.has(result.ruleId)) updated++;
      else inserted++;
    }

    if (deletedIds.length > 0) {
      await tx.synapseRule.deleteMany({ where: { ruleId: { in: deletedIds } } });
    }
  });

  const result: SyncResult = {
    catalogHash,
    catalogVersion,
    totalInput: records.length,
    inserted,
    updated,
    deleted: deletedIds.length,
    deletedIds,
    skipped: records.length - valid.length,
    warnings,
  };

  logger?.info(result, 'Synapse rule catalog synced');
  return result;
}

function isValidRecord(record: unknown, warnings: string[]): record is SynapseRuleRecord {
  if (!record || typeof record !== 'object') {
    warnings.push('rejected non-object rule entry');
    return false;
  }
  const r = record as Record<string, unknown>;
  if (typeof r.id !== 'number' || !Number.isFinite(r.id) || !Number.isInteger(r.id)) {
    warnings.push(`rejected rule with non-integer id: ${JSON.stringify(r.id)}`);
    return false;
  }
  if (typeof r.description !== 'string') {
    warnings.push(`rejected rule ${r.id}: missing/non-string description`);
    return false;
  }
  return true;
}

function nullableString(v: unknown): string | null {
  return typeof v === 'string' ? v : null;
}

function nullableNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function nullableBoolean(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b));
    const out: Record<string, unknown> = {};
    for (const [k, v] of entries) out[k] = canonicalize(v);
    return out;
  }
  return value;
}
