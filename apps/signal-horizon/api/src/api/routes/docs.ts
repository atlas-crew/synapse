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
// In dev: prefer app-local docs for predictable support UX.
// In prod: ./site (copied during build to dist/site)
const getSiteRoot = () => {
  const prodPath = path.resolve(__dirname, '../../site'); // From dist/api/routes/docs.js to dist/site
  // Dev: app-local docs live at apps/signal-horizon/site (sibling of api/)
  // Prefer these over apps/signal-horizon/api/docs so Support & Docs shows product docs.
  const devAppSiteFromApiCwd = path.resolve(process.cwd(), '../site');
  const devAppSiteFromRepoCwd = path.resolve(process.cwd(), 'apps/signal-horizon/site');
  const devAppSiteFromSrc = path.resolve(__dirname, '../../../../../site');
  const cwdSitePath = path.resolve(process.cwd(), 'site');
  const cwdDocsPath = path.resolve(process.cwd(), 'docs');
  // Repo root docs (when cwd is apps/signal-horizon/api)
  const repoDocsPath = path.resolve(process.cwd(), '../../../docs');
  const legacyDevPath = path.resolve(__dirname, '../../../../site');

  if (existsSync(prodPath)) return prodPath;
  if (existsSync(devAppSiteFromApiCwd)) return devAppSiteFromApiCwd;
  if (existsSync(devAppSiteFromSrc)) return devAppSiteFromSrc;
  if (existsSync(devAppSiteFromRepoCwd)) return devAppSiteFromRepoCwd;
  if (existsSync(cwdSitePath)) return cwdSitePath;
  if (existsSync(cwdDocsPath)) return cwdDocsPath;
  if (existsSync(repoDocsPath)) return repoDocsPath;
  return legacyDevPath;
};

const SITE_ROOT = getSiteRoot();

// Only filter out CLAUDE.md context files (exact filename match)
const INTERNAL_PATTERNS = [
  /(?:^|[:/])CLAUDE\.md$/i,
];

interface DocItem {
  id: string;
  title: string;
  category: string;
  path: string;
  mtime?: string;
}

/**
 * Recursively list markdown files in the docs directory
 */
async function listDocs(dir: string, baseDir: string = SITE_ROOT): Promise<DocItem[]> {
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

      const stats = await fs.stat(fullPath);

      docs.push({
        id,
        title,
        category: category.charAt(0).toUpperCase() + category.slice(1),
        path: relativePath,
        mtime: stats.mtime.toISOString(),
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
    const docs = await listDocs(SITE_ROOT);
    res.json(docs);
  } catch (error) {
    logger.error({ error }, 'Failed to list documentation');
    res.status(500).json({ error: 'Failed to list documentation' });
  }
});

/**
 * GET /api/v1/docs/search
 * Search through documentation content
 */
router.get('/search', async (req, res) => {
  try {
    const query = typeof req.query.q === 'string' ? req.query.q.slice(0, 200) : '';
    if (!query || query.length < 2) {
      res.json([]);
      return;
    }

    const resolvedRoot = path.resolve(SITE_ROOT);
    const docs = await listDocs(SITE_ROOT);
    const searchResults: Array<DocItem & { snippet: string }> = [];
    const lowerQuery = query.toLowerCase();

    for (const doc of docs) {
      const relativePath = doc.id.replace(/:/g, path.sep) + '.md';
      const resolvedPath = path.resolve(SITE_ROOT, relativePath);

      // SH-001: Path traversal guard (defense-in-depth, mirrors /:id endpoint)
      if (!resolvedPath.startsWith(resolvedRoot + path.sep)) {
        logger.warn({ docId: doc.id, path: resolvedPath }, 'Path traversal attempt in search');
        continue;
      }

      const content = await fs.readFile(resolvedPath, 'utf-8');
      const lowerContent = content.toLowerCase();
      const lowerTitle = doc.title.toLowerCase();

      if (lowerTitle.includes(lowerQuery) || lowerContent.includes(lowerQuery)) {
        // Simple snippet extraction
        let snippet = '';
        const index = lowerContent.indexOf(lowerQuery);
        
        if (index !== -1) {
          const start = Math.max(0, index - 40);
          const end = Math.min(content.length, index + lowerQuery.length + 40);
          snippet = content.substring(start, end).replace(/\n/g, ' ').trim();
          if (start > 0) snippet = '...' + snippet;
          if (end < content.length) snippet = snippet + '...';
        } else {
          // If match was only in title, show the beginning of the file
          snippet = content.substring(0, 80).replace(/\n/g, ' ').trim() + '...';
        }

        searchResults.push({
          ...doc,
          snippet
        });
      }
    }

    res.json(searchResults);
  } catch (error) {
    logger.error({ error, query: req.query.q }, 'Failed to search documentation');
    res.status(500).json({ error: 'Failed to search documentation' });
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

    // SH-001: Use path.resolve() for canonicalization to prevent path traversal
    // path.join resolves '..' internally but startsWith on non-canonical paths
    // can have edge cases. path.resolve + separator suffix ensures safety.
    const resolvedRoot = path.resolve(SITE_ROOT);
    const resolvedPath = path.resolve(SITE_ROOT, relativePath);

    if (!resolvedPath.startsWith(resolvedRoot + path.sep)) {
      res.status(403).json({ error: 'Access denied' });
      return;
    }

    const content = await fs.readFile(resolvedPath, 'utf-8');
    const stats = await fs.stat(resolvedPath);
    res.json({ id, content, mtime: stats.mtime.toISOString() });
  } catch (error) {
    logger.error({ error, id: req.params.id }, 'Failed to read documentation file');
    res.status(404).json({ error: 'Documentation not found' });
  }
});

export default router;
