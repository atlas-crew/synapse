import { mkdirSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

async function loadChromium() {
  try {
    const mod = await import('playwright');
    const chromium = mod.chromium ?? mod.default?.chromium ?? mod['module.exports']?.chromium;
    if (chromium) return chromium;
  } catch {}

  // Monorepo may have Playwright in the pnpm store but not as a dependency of this app.
  const pnpmStore = join(process.cwd(), 'node_modules/.pnpm');
  if (!existsSync(pnpmStore)) {
    throw new Error('Playwright not installed (no node_modules/.pnpm)');
  }

  const entry = readdirSync(pnpmStore).find((name) => name.startsWith('playwright@'));
  if (!entry) throw new Error('Playwright not installed (no playwright@* in node_modules/.pnpm)');

  const playwrightIndex = join(pnpmStore, entry, 'node_modules/playwright/index.js');
  const mod = await import(pathToFileURL(playwrightIndex));
  const chromium = mod.chromium ?? mod.default?.chromium ?? mod['module.exports']?.chromium;
  if (!chromium) throw new Error(`Playwright loaded but chromium export missing: ${playwrightIndex}`);
  return chromium;
}

const BASE_URL = process.env.BASE_URL || 'http://localhost:5180';
const API_URL = process.env.API_URL || 'http://localhost:3100';
const API_KEY = process.env.API_KEY || 'dev-dashboard-key';
const SOC_SENSOR_ID = process.env.SOC_SENSOR_ID || 'synapse-pingora-1';

function slug(input) {
  return input.replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'root';
}

async function apiJson(path, init = {}) {
  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${API_KEY}`,
      ...(init.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`API ${res.status} ${path}`);
  return res.json();
}

async function resolveIds() {
  const ids = {
    campaignId: null,
    actorId: null,
    sessionId: null,
    warRoomId: null,
    fleetSensorId: null,
  };

  try {
    const campaigns = await apiJson(`/api/v1/synapse/${SOC_SENSOR_ID}/campaigns`);
    ids.campaignId = campaigns?.campaigns?.[0]?.campaignId || null;
  } catch {}

  try {
    if (ids.campaignId) {
      const actors = await apiJson(
        `/api/v1/synapse/${SOC_SENSOR_ID}/campaigns/${ids.campaignId}/actors`
      );
      ids.actorId = actors?.actors?.[0]?.actorId || null;
    }
  } catch {}

  try {
    const sessions = await apiJson(`/api/v1/synapse/${SOC_SENSOR_ID}/sessions?limit=50`);
    ids.sessionId = sessions?.sessions?.[0]?.sessionId || null;
  } catch {}

  try {
    const warRooms = await apiJson(`/api/v1/warrooms?limit=1&offset=0`);
    ids.warRoomId = warRooms?.warRooms?.[0]?.id || null;
  } catch {}

  try {
    const sensors = await apiJson(`/api/v1/fleet/sensors?limit=1&offset=0`);
    ids.fleetSensorId = sensors?.sensors?.[0]?.id || null;
  } catch {}

  return ids;
}

const STATIC_PATHS = [
  '/',
  '/live-map',
  '/campaigns',
  '/actors',
  '/sessions',
  '/search',
  '/warroom',
  '/hunting',
  '/hunting/request',
  '/intel',
  '/api-intelligence',
  '/auth-coverage',
  '/dlp',
  '/fleet/forecast',
  '/support',
  '/settings/admin',

  '/fleet',
  '/fleet/health',
  '/fleet/updates',
  '/fleet/rules',
  '/fleet/config',
  '/fleet/connectivity',
  '/fleet/keys',
  '/fleet/onboarding',
  '/fleet/releases',
  '/fleet/bandwidth',

  '/beam',
  '/beam/analytics',
  '/beam/analytics/traffic',
  '/beam/analytics/response-times',
  '/beam/analytics/errors',
  '/beam/catalog',
  '/beam/catalog/services',
  '/beam/catalog/schema-changes',
  '/beam/rules',
  '/beam/rules/templates',
  '/beam/rules/custom',
  '/beam/threats',
  '/beam/threats/blocked',
  '/beam/threats/patterns',
];

async function main() {
  const outDir = join(process.cwd(), 'apps/signal-horizon/ui/tmp/site-scan');
  const shotsDir = join(outDir, 'screens');
  mkdirSync(shotsDir, { recursive: true });

  const ids = await resolveIds();
  const dynamic = [];
  if (ids.campaignId) dynamic.push(`/campaigns/${ids.campaignId}`);
  if (ids.actorId) dynamic.push(`/actors/${ids.actorId}`);
  if (ids.sessionId) dynamic.push(`/sessions/${ids.sessionId}`);
  if (ids.warRoomId) dynamic.push(`/warroom/${ids.warRoomId}`);
  if (ids.fleetSensorId) {
    dynamic.push(`/fleet/sensors/${ids.fleetSensorId}`);
    dynamic.push(`/fleet/sensors/${ids.fleetSensorId}/config`);
  }

  const paths = [...STATIC_PATHS, ...dynamic];

  const chromium = await loadChromium();
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  // Ensure demo mode stays off.
  await page.addInitScript(() => {
    try {
      localStorage.setItem('beam-demo-mode', JSON.stringify({ state: { isEnabled: false, scenario: 'normal' }, version: 0 }));
    } catch {}
  });

  const events = [];
  let currentPath = '';
  let currentNavStart = 0;

  page.on('console', (msg) => {
    const type = msg.type();
    if (type !== 'error' && type !== 'warning') return;
    events.push({
      path: currentPath,
      kind: 'console',
      level: type,
      text: msg.text(),
      tMs: Date.now() - currentNavStart,
    });
  });

  page.on('pageerror', (err) => {
    events.push({
      path: currentPath,
      kind: 'pageerror',
      text: String(err?.message || err),
      tMs: Date.now() - currentNavStart,
    });
  });

  page.on('requestfailed', (req) => {
    const url = req.url();
    if (!url.includes('localhost:3100')) return;
    events.push({
      path: currentPath,
      kind: 'requestfailed',
      method: req.method(),
      url,
      failure: req.failure()?.errorText,
      tMs: Date.now() - currentNavStart,
    });
  });

  page.on('response', (res) => {
    const url = res.url();
    if (!url.includes('localhost:3100')) return;
    const status = res.status();
    if (status < 400) return;
    events.push({
      path: currentPath,
      kind: 'http',
      method: res.request().method(),
      url,
      status,
      tMs: Date.now() - currentNavStart,
    });
  });

  const results = [];

  for (let i = 0; i < paths.length; i++) {
    currentPath = paths[i];
    currentNavStart = Date.now();
    const url = `${BASE_URL}${currentPath}`;

    const routeEventsStart = events.length;
    let ok = true;
    let note = '';

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45000 });
      await page.waitForTimeout(1500);

      const boundary = page.locator('[role="alert"] >> text=Something went wrong');
      if ((await boundary.count()) > 0) {
        ok = false;
        note = 'ErrorBoundary';
      }

      // Light interaction smoke: exercises POST flows that nav-only misses.
      // Keep selectors resilient (text-based) so this stays low-maintenance.
      if (ok && currentPath === '/hunting') {
        const runBtn = page.getByRole('heading', { name: 'Query Examples' }).locator('..').locator('..').getByRole('button', { name: /Run/i }).first();
        if ((await runBtn.count()) > 0) {
          await runBtn.click({ timeout: 5000 });
          await page.waitForTimeout(2000);
        }
      }

      if (ok && currentPath === '/fleet/connectivity') {
        const runTestBtn = page.getByRole('button', { name: 'Run Test' }).first();
        if ((await runTestBtn.count()) > 0) {
          await runTestBtn.click({ timeout: 5000 });
          await page.waitForTimeout(1500);
        }
      }
    } catch (err) {
      ok = false;
      note = `nav-error: ${String(err?.message || err).slice(0, 120)}`;
    }

    const routeEvents = events.slice(routeEventsStart).filter((e) => e.path === currentPath);
    const hasConsoleError = routeEvents.some((e) => e.kind === 'console' && e.level === 'error');
    const hasHttpError = routeEvents.some((e) => e.kind === 'http' && e.status >= 400);

    if (hasConsoleError || hasHttpError) ok = false;

    if (!ok) {
      try {
        await page.screenshot({ path: join(shotsDir, `${String(i).padStart(2, '0')}-${slug(currentPath)}.png`), fullPage: true });
      } catch {}
    }

    results.push({
      path: currentPath,
      ok,
      note,
      events: routeEvents,
    });
  }

  await browser.close();

  const fail = results.filter((r) => !r.ok);
  const stats = {
    routes: results.length,
    ok: results.length - fail.length,
    fail: fail.length,
  };
  const md = [
    `# Signal Horizon UI Site Scan`,
    ``,
    `base: ${BASE_URL}`,
    `api: ${API_URL}`,
    `sensor: ${SOC_SENSOR_ID}`,
    ``,
    `routes: ${stats.routes}`,
    `failures: ${stats.fail}`,
    ``,
    `## Failures`,
    ...fail.map((r) => `- ${r.path}${r.note ? ` (${r.note})` : ''}`),
    ``,
    `## Notes`,
    `- Captures console warnings/errors + API 4xx/5xx during nav.`,
    `- Screenshots only on failure.`,
    ``,
  ].join('\n');

  writeFileSync(join(outDir, 'report.md'), md, 'utf8');
  writeFileSync(
    join(outDir, 'report.json'),
    JSON.stringify({ ids, stats, failures: fail.map((r) => ({ route: r.path, note: r.note })), results }, null, 2),
    'utf8'
  );

  if (fail.length > 0) process.exitCode = 2;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
