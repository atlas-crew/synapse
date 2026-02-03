import { Router } from 'express';
import fs from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from '../../lib/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const router: ReturnType<typeof Router> = Router();

// Resilient path resolution:
// In dev: ../../../../docs
// In prod: ./docs (copied during build to dist/docs)
const getDocsRoot = () => {
  const prodPath = path.resolve(__dirname, '../../docs'); // From dist/api/routes/docs.js to dist/docs
  const devPath = path.resolve(__dirname, '../../../../docs');
  
  if (existsSync(prodPath)) return prodPath;
  return devPath;
};

const DOCS_ROOT = getDocsRoot();

// Patterns to exclude from user-facing documentation
const INTERNAL_PATTERNS = [
  /^api(\/|:|$)/i,
  /^project(\/|:|$)/i,
  /^architecture(\/|:|$)/i,
  /^archive(\/|:|$)/i,
  /(?:^|[:/])CLAUDE\.md$/i, // Filter out CLAUDE.md context files (exact filename match)
  /gap_analysis/i,
  /beam_backend_summary/i,
  /beam_api_examples/i,
  /ui-development/i,
  /protocols/i,
  /brand/i,
  /openapi/i,
  /swagger/i,
  /README/i,
  /fleet-api/i,
  /hunt-api/i,
  /sensor-protocol/i,
  /database-schema/i,
];

interface DocItem {
  id: string;
  title: string;
  category: string;
  path: string;
}

/**
 * Recursively list markdown files in the docs directory
 */
async function listDocs(dir: string, baseDir: string = DOCS_ROOT): Promise<DocItem[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const docs: DocItem[] = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(baseDir, fullPath);

    if (entry.isDirectory()) {
      // Skip internal directories early
      const id = relativePath.replace(/\//g, ':');
      if (INTERNAL_PATTERNS.some(p => p.test(id))) continue;

      const subDocs = await listDocs(fullPath, baseDir);
      docs.push(...subDocs);
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      const id = relativePath.replace(/\.md$/, '').replace(/\//g, ':');
      
      // Skip internal files
      if (INTERNAL_PATTERNS.some(p => p.test(id))) continue;

      const category = path.dirname(relativePath) === '.' ? 'General' : path.dirname(relativePath);
      
      // Basic title extraction from filename
      const title = entry.name
        .replace(/\.md$/, '')
        .split(/[-_]/)
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');

      docs.push({
        id,
        title,
        category: category.charAt(0).toUpperCase() + category.slice(1),
        path: relativePath
      });
    }
  }

  return docs;
}

/**
 * GET /api/v1/docs
 * List all available documentation files
 */
router.get('/', async (_req, res) => {
  try {
    const docs = await listDocs(DOCS_ROOT);
    res.json(docs);
  } catch (error) {
    logger.error({ error }, 'Failed to list documentation');
    res.status(500).json({ error: 'Failed to list documentation' });
  }
});

/**
 * GET /api/v1/docs/:id
 * Get the content of a specific documentation file
 */
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const relativePath = id.replace(/:/g, path.sep) + '.md';
    const fullPath = path.join(DOCS_ROOT, relativePath);

    // Security check: ensure the path is within DOCS_ROOT
    if (!fullPath.startsWith(DOCS_ROOT)) {
      res.status(403).json({ error: 'Access denied' });
      return;
    }

    const content = await fs.readFile(fullPath, 'utf-8');
    res.json({ id, content });
  } catch (error) {
    logger.error({ error, id: req.params.id }, 'Failed to read documentation file');
    res.status(404).json({ error: 'Documentation not found' });
  }
});

export default router;
